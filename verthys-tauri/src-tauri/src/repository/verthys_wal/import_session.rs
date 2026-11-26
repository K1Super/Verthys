//! 导入会话状态与生命周期

use std::collections::{HashMap, HashSet};

use crate::repository::container_layout;

use super::wal_io::write_snapshot_file;
use super::wal_recovery::{apply_settlement, load};
use super::wal_writer::WalWriter;

/// 导入会话状态（贯穿整个导入生命周期，由 AppState 持有）
///
/// 绑定一个 WAL 写入句柄 + 已提交条目键集合（续传幂等）+ 批次计数器。
/// 通过 AppState::lock_import_session() 访问，单 verthys 同一时刻仅一个活跃会话。
pub struct ImportSession {
    /// WAL 写入句柄（append-only，持文件句柄）
    pub writer: WalWriter,
    /// 导入会话 ID（uuid 风格，贯穿整个导入生命周期）
    pub import_id: String,
    /// 绑定的 verthys 路径
    pub verthys_path: String,
    /// 下一个批次 ID（从 1 递增）
    pub next_batch_id: u64,
    /// 已 committed 的非内容条目键集合（生产者据此跳过，保证幂等）
    pub committed_keys: HashSet<String>,
    /// 已 committed 条目键 → 记录 ID 映射（按记录 ID 释放去重锁的权威依据）
    pub committed_ids: HashMap<String, u64>,
    /// 累计已 committed 记录数（检查点）
    pub total_committed: u64,
    /// 累计因条目键去重跳过的记录数（进度反馈用，不入 WAL）
    pub total_skipped: u64,
    /// 外置块键 → 记录 ID 映射（本会话已上传块，重试幂等复用）
    pub chunk_ids_by_key: HashMap<String, u64>,
    /// 本会话已成功上传的外置块记录 ID 集合（meta 引用的权威判定集）
    pub issued_chunk_ids: HashSet<u64>,
    /// 外置块台账（块记录 ID → 拥有者 meta ID，0 = 未被引用）
    ///
    /// 创建会话时从台账文件加载（缺失即空），随块上传/meta 入库在写者
    /// 线程内维护并落盘；孤儿块 GC 依据该映射判定可回收对象。
    pub chunk_ledger: crate::repository::verthys_chunks::ChunkLedger,
    /// 本会话内台账是否曾落盘失败
    ///
    /// 仅供诊断与日志：会话成功结束时无条件重试落盘，失败即拒绝结束并保留
    /// WAL，因此该标志不参与任何分支判定。
    pub ledger_dirty: bool,
}

impl ImportSession {
    /// 创建新会话：初始化 WAL + 从既有快照恢复 committed_keys（续传去重）
    /// 并加载外置块台账（缺失即空，损坏则向上传播失败）。
    ///
    /// 建会话前必须完成台账结算：把上一会话已提交记录的块归属写回台账，
    /// 冻结无法证明归属的历史条目。结算落盘失败即会话创建失败——绝不允许
    /// 在「台账可能把已被引用的块判成孤儿」的状态下开始新一轮写入。
    pub fn new(verthys_path: &str, import_id: &str) -> Result<Self, String> {
        // 先加载既有 WAL 快照（若存在遗留 WAL，恢复 committed_keys 实现续传去重）
        let snapshot = load(verthys_path)?;
        let committed_keys = snapshot.committed_keys.clone();
        let committed_ids = snapshot.committed_ids.clone();
        let total_committed = snapshot.committed_keys.len() as u64;

        // 加载外置块台账（在截断 WAL 之前：台账损坏时直接失败，避免已截断
        // WAL 却未能建立会话的半成品状态）
        let mut chunk_ledger = crate::repository::verthys_chunks::load_chunk_ledger(verthys_path)?;

        // 台账结算（必须在截断 WAL 之前）：此时快照仍能读到上一会话的全部
        // 归属声明；一旦 WAL 被截断，未结算的归属将永久失去证明来源
        let settlement = apply_settlement(&snapshot, &mut chunk_ledger);
        if settlement.changed() {
            crate::repository::verthys_chunks::save_chunk_ledger(verthys_path, &chunk_ledger)?;
            log::info!(
                "[import_session] 台账结算完成: 归属改写={} 冻结={}",
                settlement.settled,
                settlement.frozen
            );
        }

        // 创建/截断 WAL（新会话起始；遗留 pending 记录已被快照忽略，仅 committed 进入去重集合）
        let writer = WalWriter::create(verthys_path, import_id)?;

        // 基线固化（删除墓碑持久化不变量）：create() 截断了 WAL，落在旧 WAL 中的
        // 删除墓碑条目随之消失，而快照文件仍是压缩时点的旧集合。若不在此处把
        // 「快照基线 + WAL 增量重放」后的权威去重集合写回快照，会话结束（无论
        // 成功压缩还是失败保留）后再次载入会从陈旧快照复活已删除哈希——表现为
        // 照片删除后重新导入被静默全部跳过（去重锁未释放）。
        // 不变量：快照文件恒为「当前 WAL 首条目之前全部历史」的合并结果。
        // 载入结果 snapshot 即该合并结果（hashes / committed_ids / 计数均已收敛）。
        write_snapshot_file(&container_layout::wal_file_for(verthys_path), &snapshot)?;

        Ok(ImportSession {
            writer,
            import_id: import_id.to_string(),
            verthys_path: verthys_path.to_string(),
            next_batch_id: 1,
            committed_keys,
            committed_ids,
            total_committed,
            total_skipped: 0,
            chunk_ids_by_key: HashMap::new(),
            issued_chunk_ids: HashSet::new(),
            chunk_ledger,
            ledger_dirty: false,
        })
    }

    /// 检查条目键是否已 committed（会话内/WAL 续传幂等）
    pub fn is_committed(&self, entry_key: &str) -> bool {
        self.committed_keys.contains(entry_key)
    }

    /// 标记一条记录为已 committed（更新幂等集合 + 计数 + ID 映射）
    ///
    /// 同一批次可携带共用条目键的多条记录（照片 meta 与其预览共用键）：
    /// ID 映射必须保留首条索引记录，删除流程按索引记录 ID 反查条目键才能
    /// 命中；后写记录覆盖会让续传幂等锁永久残留，删除后重新导入被静默跳过。
    pub fn mark_committed(&mut self, entry_key: &str, verthys_id: u64) {
        if self.committed_keys.insert(entry_key.to_string()) {
            self.total_committed += 1;
        }
        if verthys_id != 0 {
            self.committed_ids
                .entry(entry_key.to_string())
                .or_insert(verthys_id);
        }
    }

    /// 标记一条记录因条目键幂等跳过（仅累计计数，不入 WAL）
    pub fn mark_skipped(&mut self) {
        self.total_skipped += 1;
    }

    /// 分配下一个批次 ID
    pub fn allocate_batch_id(&mut self) -> u64 {
        let id = self.next_batch_id;
        self.next_batch_id += 1;
        id
    }

    /// 查询已上传外置块（同块键复用记录 ID，批次重试幂等）
    pub fn lookup_chunk(&self, chunk_key: &str) -> Option<u64> {
        self.chunk_ids_by_key.get(chunk_key).copied()
    }

    /// 记账已上传外置块（幂等映射 + 发放集合两处同步）
    pub fn remember_chunk(&mut self, chunk_key: &str, id: u64) {
        self.chunk_ids_by_key.insert(chunk_key.to_string(), id);
        self.issued_chunk_ids.insert(id);
    }

    /// 校验外置块引用全部在本会话已成功上传
    ///
    /// 权威判定依据是「本会话经单写者成功落库的块 ID 集合」：块上传与
    /// meta 写入同走一条 FIFO，上传成功即集合记账，未记账的引用必然是
    /// 前端越序或伪造，直接拒绝该记录。
    pub fn chunk_refs_known(&self, ids: &[u64]) -> bool {
        ids.iter().all(|id| self.issued_chunk_ids.contains(id))
    }

    /// 删除照片后释放续传幂等锁（内存集合即时生效）
    ///
    /// 持久化由 WAL 删除墓碑承担（跨会话恢复时移除）；本方法仅同步
    /// 本会话内存集合与累计计数。返回 true 表示确实移除了已记账条目键。
    pub fn forget_committed(&mut self, entry_key: &str) -> bool {
        self.committed_ids.remove(entry_key);
        if self.committed_keys.remove(entry_key) {
            self.total_committed = self.total_committed.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// 按记录 ID 查询条目键（删除流程在 meta 不可解密时仍可释放去重锁）
    pub fn key_for_id(&self, verthys_id: u64) -> Option<&str> {
        self.committed_ids
            .iter()
            .find(|(_, id)| **id == verthys_id)
            .map(|(key, _)| key.as_str())
    }
}
