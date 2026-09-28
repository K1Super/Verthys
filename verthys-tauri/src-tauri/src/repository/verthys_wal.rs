//! repository/verthys_wal.rs — 照片导入 Write-Ahead Log（断点续传持久层）
//!
//! 异步批处理流水线 — 断点续传：前置 WAL + 检查点
//!
//! =============================================================================
//! 设计目标
//! =============================================================================
//! 在每条加密记录进入缓存缓冲器**之前**，先将 {hash, status} 写入本地 WAL，
//! 批量刷新成功后标记为 committed。崩溃/关闭后重启，扫描 WAL 即可：
//!   - 已 committed 的哈希 → 已落盘（v2 add_record 即时 fsync），续传时直接跳过
//!   - pending 但未 committed → 未落盘，续传时重新加密入库（哈希未变，幂等）
//! 重做量不超过一个批次（检查点粒度）。
//!
//! =============================================================================
//! 持久化格式（JSON-lines，append-only）
//! =============================================================================
//! 每行一个 JSON 对象，以 `\n` 分隔。条目类型：
//!   {"kind":"begin","import_id":"<uuid>","ts":<unix_ms>}
//!   {"kind":"pending","import_id":"<uuid>","batch_id":<n>,"hash":"<blake3 hex>","name":"<file>","idx":<i>}
//!   {"kind":"committed","import_id":"<uuid>","batch_id":<n>,"hash":"<blake3 hex>","verthys_id":<lid>,"name":"<file>","chunk_ids":<[lid]|缺省>}
//!   {"kind":"checkpoint","import_id":"<uuid>","batch_id":<n>,"committed_count":<x>}
//!   {"kind":"end","import_id":"<uuid>","success":<bool>}
//!
//! `chunk_ids` 为显式声明的外置块引用集合（缺省表示历史条目、引用不可推断）；
//! 崩溃恢复据此把块归属结算进台账，防止已提交记录引用的块被当作孤儿回收。
//!
//! 每条 append 后立即 sync_all（fsync）+ 刷新到磁盘，保证崩溃不丢失已提交记录。
//!
//! =============================================================================
//! 恢复语义
//! =============================================================================
//! - load(): 全量重放 WAL，构建 committed 哈希集合 + 最后检查点。
//! - 已 committed 哈希进入 `committed_hashes`，续传时生产者据此去重（幂等）。
//! - pending 未 committed：不入 committed_hashes，续传时重新处理（哈希未变 → 重新加密入库）。
//! - compact(): 导入成功结束后，将 committed 哈希合并写入一个 begin/checkpoint/end
//!   原子替换文件，缩减 WAL 体积；失败/中断保留原 WAL 供下次续传。
//!
//! =============================================================================
//! 安全边界
//! =============================================================================
//! - 仅记录哈希（BLAKE3 hex）与文件名，不含密钥、不含明文、不含密文。
//! - WAL 文件位于容器附属数据目录（受 VerthysFileLock 独占锁保护，防并发写）。
//! - 所有 IO 失败向上传播为 Err（持久层不吞异常），由控制器决定降级策略。
//!
//! =============================================================================
//! 附属目录与旧布局迁移
//! =============================================================================
//! - 权威写路径：附属数据目录内 import.wal（快照同目录，后缀 .snapshot）。
//! - 旧布局 <verthys_path>.import.wal（及快照）仅作只读回退：读取入口先尝试
//!   原子搬迁，搬迁失败时本次读取沿用旧位置（数据连续性优先），下次访问重试。
//! - 会话创建（截断 WAL）后旧布局文件被 best-effort 回收；去重集合已在建会话
//!   前载入内存，回收不丢失语义。
//!
//! 依赖方向：repository → util（单向，禁止引用 controller/service/entry）

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::repository::container_layout;

/// WAL 单条记录类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum WalEntry {
    /// 导入会话开始
    #[serde(rename = "begin")]
    Begin { import_id: String, ts: u64 },
    /// 记录已加密，待入库（写入缓存缓冲器之前）
    #[serde(rename = "pending")]
    Pending {
        import_id: String,
        batch_id: u64,
        hash: String,
        name: String,
        idx: u64,
    },
    /// 记录已入库并落盘（缓存刷新 + worker add_record 完成）
    ///
    /// `chunk_ids` 承载本条记录引用的外置块记录 ID：
    ///   - `Some([...])`：本条目显式声明引用集合（空集合表示无外置块）；
    ///   - `None`：字段缺省的历史条目，引用集合不可推断。
    #[serde(rename = "committed")]
    Committed {
        import_id: String,
        batch_id: u64,
        hash: String,
        verthys_id: u64,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_ids: Option<Vec<u64>>,
    },
    /// 检查点：标记某批次完整提交
    #[serde(rename = "checkpoint")]
    Checkpoint {
        import_id: String,
        batch_id: u64,
        committed_count: u64,
    },
    /// 删除墓碑：照片删除后释放去重锁（删除后可重新导入）
    #[serde(rename = "removed")]
    Removed {
        hashes: Vec<String>,
        /// 写入时刻（Unix 毫秒）
        at: u64,
    },
    /// 导入会话结束
    #[serde(rename = "end")]
    End { import_id: String, success: bool },
}

/// WAL 恢复后的快照
#[derive(Debug, Clone, Default)]
pub struct WalSnapshot {
    /// 所有已 committed 的内容哈希（BLAKE3 hex）— 续传去重依据
    pub committed_hashes: HashSet<String>,
    /// 最后一个检查点已提交计数
    pub last_committed_count: u64,
    /// 最后一个检查点的批次 ID
    pub last_batch_id: u64,
    /// 当前活跃的 import_id（若 WAL 未 end）
    pub active_import_id: Option<String>,
    /// 已 committed 的 {hash → verthys_id} 映射（供调试/审计）
    pub committed_ids: std::collections::HashMap<String, u64>,
    /// 已 committed 条目显式声明的外置块归属：{块记录 ID → 拥有者记录 ID}
    ///
    /// 仅由携带引用集合的条目累积；删除墓碑会撤销对应拥有者的声明。
    pub committed_chunk_owners: HashMap<u64, u64>,
    /// WAL 中是否存在引用集合不可推断的历史 committed 条目
    ///
    /// 为真时，台账中仍为孤儿候选的条目无法证明归属，结算路径须将其冻结，
    /// 宁可永久保留也不得回收。
    pub has_unsettleable_commits: bool,
}

/// 解析 WAL 数据位置：附属目录优先，旧布局命中时先尝试原子迁移。
///
/// 迁移失败（重命名被占用、权限异常等）不中断调用方：返回旧路径作为本次
/// 数据位置（数据连续性优先），后续访问自动重试迁移；任何情况下都不会把
/// 同一份数据同时写到两处。
fn resolve_wal_path(verthys_path: &str) -> PathBuf {
    let primary = container_layout::wal_file_for(verthys_path);
    if primary.exists() {
        return primary;
    }
    let legacy = container_layout::legacy_wal_file_for(verthys_path);
    if !legacy.exists() {
        return primary;
    }
    match container_layout::migrate_legacy_file(&legacy, &primary) {
        Ok(()) => {
            let snapshot = container_layout::legacy_wal_snapshot_file_for(verthys_path);
            if snapshot.exists() {
                let snap_primary = container_layout::wal_snapshot_file_for(verthys_path);
                if let Err(e) = container_layout::migrate_legacy_file(&snapshot, &snap_primary) {
                    log::warn!("[wal] 旧布局快照迁移失败（快照缺失按全量重放等价处理）: {}", e);
                }
            }
            log::info!("[wal] 旧布局 WAL 已收口至附属数据目录");
            primary
        }
        Err(e) => {
            log::warn!(
                "[wal] 旧布局 WAL 迁移失败（本次沿用原位置，下次访问重试）: {}",
                e
            );
            legacy
        }
    }
}

/// 回收旧布局 WAL 相关文件（best-effort）。
///
/// 仅在会话创建（WAL 已截断）之后调用：此刻旧 WAL 承载的去重集合已在建会话
/// 前载入内存，回收不丢失语义；残留文件在下次访问或显式删除时再被清理。
fn discard_legacy_wal_files(verthys_path: &str) {
    for path in [
        container_layout::legacy_wal_file_for(verthys_path),
        container_layout::legacy_wal_snapshot_file_for(verthys_path),
    ] {
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        let tmp = PathBuf::from(format!("{}.tmp", path.to_string_lossy()));
        if tmp.exists() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

/// 删除既有文件；不存在视为成功，其余错误上抛。
fn remove_file_if_exists(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| format!("{}删除失败: {}", label, e))?;
    }
    Ok(())
}

/// 快照文件路径（WAL 同目录附加后缀）
fn snapshot_path_for(wal_path: &Path) -> PathBuf {
    let mut p = wal_path.to_path_buf();
    let mut name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(".snapshot");
    p.set_file_name(name);
    p
}

/// 快照文件内容：compacted committed 集合的持久化镜像
///
/// 快照承载「压缩时点的去重集合 + ID 映射」，WAL 只保留快照之后的
/// 增量条目；恢复 = 快照基线 + WAL 增量重放，加载成本 O(1) + O(增量)。
#[derive(Serialize, Deserialize, Default)]
struct WalSetSnapshot {
    committed_hashes: Vec<String>,
    committed_ids: Vec<(String, u64)>,
}

/// 原子写出快照文件（compacted committed 集合镜像，tmp+rename）
fn write_snapshot_file(wal_path: &Path, snapshot: &WalSnapshot) -> Result<(), String> {
    let snap_path = snapshot_path_for(wal_path);
    let mut tmp = snap_path.clone();
    let mut name = tmp
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(".tmp");
    tmp.set_file_name(name);

    let payload = WalSetSnapshot {
        committed_hashes: snapshot.committed_hashes.iter().cloned().collect(),
        committed_ids: snapshot
            .committed_ids
            .iter()
            .map(|(hash, id)| (hash.clone(), *id))
            .collect(),
    };
    let json = serde_json::to_string(&payload).map_err(|e| format!("WAL 快照序列化失败: {}", e))?;
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| format!("WAL 快照临时文件创建失败: {}", e))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("WAL 快照写入失败: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("WAL 快照 fsync 失败: {}", e))?;
    }
    std::fs::rename(&tmp, &snap_path).map_err(|e| format!("WAL 快照 rename 失败: {}", e))?;
    Ok(())
}

/// WAL 写入句柄（持有打开的文件句柄，append-only）
pub struct WalWriter {
    file: File,
    path: PathBuf,
}

impl WalWriter {
    /// 创建/截断 WAL 文件并写入 begin 条目（新导入会话起始）
    /// 若存在遗留 WAL（未 end 的旧会话），调用方应先 load() 恢复再决定是否覆盖。
    ///
    /// 全部写路径固定为附属数据目录；截断成功后旧布局 WAL 与快照被 best-effort
    /// 回收（其去重集合已由调用方在此之前载入）。
    pub fn create(verthys_path: &str, import_id: &str) -> Result<Self, String> {
        container_layout::ensure_sidecar_dir(verthys_path)?;
        let path = container_layout::wal_file_for(verthys_path);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| format!("WAL 创建失败: {}", e))?;

        let mut writer = WalWriter { file, path };
        writer.append(&WalEntry::Begin {
            import_id: import_id.to_string(),
            ts: now_ms(),
        })?;
        writer.flush_sync()?;
        discard_legacy_wal_files(verthys_path);
        Ok(writer)
    }

    /// 追加一条记录并立即 fsync 落盘
    pub fn append(&mut self, entry: &WalEntry) -> Result<(), String> {
        let line = serde_json::to_string(entry).map_err(|e| format!("WAL 序列化失败: {}", e))?;
        writeln!(self.file, "{}", line).map_err(|e| format!("WAL 写入失败: {}", e))?;
        self.flush_sync()
    }

    /// 批量追加多条记录，末尾一次 fsync（减少 fsync 次数，但仍保证落盘）
    pub fn append_batch(&mut self, entries: &[WalEntry]) -> Result<(), String> {
        for entry in entries {
            let line =
                serde_json::to_string(entry).map_err(|e| format!("WAL 序列化失败: {}", e))?;
            writeln!(self.file, "{}", line).map_err(|e| format!("WAL 写入失败: {}", e))?;
        }
        self.flush_sync()
    }

    /// 追加一条记录但不落盘（写入缓冲，由后续 flush_sync 统一刷盘）。
    ///
    /// 仅限无需单独崩溃保证的条目使用：pending 在恢复重放中本就被忽略，
    /// 逐条 fsync 是纯浪费。批量场景下多条 deferred 追加依赖批次内后续
    /// committed / checkpoint 条目的 fsync 一并落盘，且批次末尾恒有
    /// checkpoint 兜底，批次边界处 pending 必已持久。
    pub fn append_deferred(&mut self, entry: &WalEntry) -> Result<(), String> {
        let line = serde_json::to_string(entry).map_err(|e| format!("WAL 序列化失败: {}", e))?;
        writeln!(self.file, "{}", line).map_err(|e| format!("WAL 写入失败: {}", e))
    }

    /// 写入 end 条目并关闭（success=true 时触发 compact）
    pub fn finish(self, import_id: &str, success: bool) -> Result<(), String> {
        let mut writer = self;
        writer.append(&WalEntry::End {
            import_id: import_id.to_string(),
            success,
        })?;
        // success=true：保留 WAL 供下次去重（committed_hashes 仍需可恢复），
        // 但通过 compact 缩减体积。failure：原样保留供续传。
        if success {
            writer.compact(import_id)?;
        }
        Ok(())
    }

    /// 压缩 WAL：去重集合全量固化到快照文件，WAL 仅保留会话骨架
    /// （begin + checkpoint + end）。
    ///
    /// 恢复成本与存活记录数解耦：快照文件承载哈希全集（O(1) 基线载入），
    /// WAL 只保留快照之后的增量条目。原子替换：先写临时文件再 rename，
    /// 保证压缩过程崩溃不损坏原 WAL；快照最后写入，快照缺失窗口退化为
    /// 全量重放旧 WAL，语义等价。
    fn compact(&self, import_id: &str) -> Result<(), String> {
        let snapshot = load_from_path(&self.path)?;

        let tmp_path = {
            let mut p = self.path.clone();
            let mut name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
            name.push(".tmp");
            p.set_file_name(name);
            p
        };

        {
            let mut tmp = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| format!("WAL 压缩临时文件创建失败: {}", e))?;

            let begin = serde_json::to_string(&WalEntry::Begin {
                import_id: import_id.to_string(),
                ts: now_ms(),
            })
            .map_err(|e| format!("WAL 序列化失败: {}", e))?;
            writeln!(tmp, "{}", begin).map_err(|e| format!("WAL 写入失败: {}", e))?;

            // 骨架检查点：计数与快照全集一致（哈希本体由快照承载，不重复落 WAL）
            let ckpt = serde_json::to_string(&WalEntry::Checkpoint {
                import_id: import_id.to_string(),
                batch_id: snapshot.last_batch_id,
                committed_count: snapshot.committed_hashes.len() as u64,
            })
            .map_err(|e| format!("WAL 序列化失败: {}", e))?;
            writeln!(tmp, "{}", ckpt).map_err(|e| format!("WAL 写入失败: {}", e))?;

            let end = serde_json::to_string(&WalEntry::End {
                import_id: import_id.to_string(),
                success: true,
            })
            .map_err(|e| format!("WAL 序列化失败: {}", e))?;
            writeln!(tmp, "{}", end).map_err(|e| format!("WAL 写入失败: {}", e))?;

            tmp.sync_all()
                .map_err(|e| format!("WAL 压缩 fsync 失败: {}", e))?;
        }

        // 原子替换
        std::fs::rename(&tmp_path, &self.path)
            .map_err(|e| format!("WAL 压缩 rename 失败: {}", e))?;

        // 快照后写：WAL 已收敛为最小骨架，快照承载全量去重集合
        write_snapshot_file(&self.path, &snapshot)?;
        Ok(())
    }

    /// 刷新缓冲并 fsync 到物理磁盘
    pub fn flush_sync(&mut self) -> Result<(), String> {
        self.file
            .flush()
            .map_err(|e| format!("WAL flush 失败: {}", e))?;
        self.file
            .sync_all()
            .map_err(|e| format!("WAL fsync 失败: {}", e))?;
        Ok(())
    }
}

/// 从指定 WAL 文件路径加载快照（快照文件基线 + WAL 增量重放）
fn load_from_path(path: &Path) -> Result<WalSnapshot, String> {
    let mut snapshot = WalSnapshot::default();

    // 1. 快照文件基线（compacted committed 集合，O(1) 载入）
    let snap_path = snapshot_path_for(path);
    if snap_path.exists() {
        let text =
            std::fs::read_to_string(&snap_path).map_err(|e| format!("WAL 快照读取失败: {}", e))?;
        let base: WalSetSnapshot =
            serde_json::from_str(&text).map_err(|e| format!("WAL 快照解析失败: {}", e))?;
        for hash in base.committed_hashes {
            snapshot.committed_hashes.insert(hash);
        }
        for (hash, id) in base.committed_ids {
            snapshot.committed_ids.insert(hash, id);
        }
        snapshot.last_committed_count = snapshot.committed_hashes.len() as u64;
    }

    // 2. 增量重放（快照之后追加的 WAL 条目；无 WAL 则仅快照有效）
    if !path.exists() {
        return Ok(snapshot);
    }

    let file = File::open(path).map_err(|e| format!("WAL 打开失败: {}", e))?;
    let reader = BufReader::new(file);

    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("WAL 读取失败 (行 {}): {}", line_no + 1, e))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: WalEntry = serde_json::from_str(line)
            .map_err(|e| format!("WAL 反序列化失败 (行 {}): {}", line_no + 1, e))?;

        match entry {
            WalEntry::Begin { import_id, .. } => {
                // 仅标记活跃会话，不清空已累积的去重集合：WAL 每次会话创建前
                // 会被截断，重放到的 Begin 必为当前历史的起点；存在快照基线时
                // （上次压缩的哈希全集）基线必须跨会话保留，清空会永久丢失
                // 既有照片的去重键，导致重新入库产生重复记录。
                snapshot.active_import_id = Some(import_id);
                snapshot.last_committed_count = 0;
                snapshot.last_batch_id = 0;
            }
            WalEntry::Pending { .. } => {
                // pending 不进入 committed_hashes，续传时重新处理
            }
            WalEntry::Committed {
                hash,
                verthys_id,
                import_id,
                chunk_ids,
                ..
            } => {
                snapshot.committed_hashes.insert(hash.clone());
                snapshot.committed_ids.insert(hash, verthys_id);
                match chunk_ids {
                    Some(ids) => {
                        for chunk_id in ids {
                            snapshot.committed_chunk_owners.insert(chunk_id, verthys_id);
                        }
                    }
                    // 历史条目未携带引用集合：归属无从推断，标记为不可结算，
                    // 由结算路径对台账孤儿候选执行冻结
                    None => snapshot.has_unsettleable_commits = true,
                }
                snapshot.active_import_id = Some(import_id);
            }
            WalEntry::Checkpoint {
                batch_id,
                committed_count,
                import_id,
            } => {
                snapshot.last_batch_id = batch_id;
                snapshot.last_committed_count = committed_count;
                snapshot.active_import_id = Some(import_id);
            }
            WalEntry::Removed { hashes, .. } => {
                // 删除墓碑：从去重集合移除（删除后可重新导入语义），并撤销
                // 该记录声明过的块归属，避免把已删除记录的块结算成有效归属
                for hash in &hashes {
                    if let Some(owner_id) = snapshot.committed_ids.remove(hash) {
                        snapshot
                            .committed_chunk_owners
                            .retain(|_, owner| *owner != owner_id);
                    }
                    snapshot.committed_hashes.remove(hash);
                }
            }
            WalEntry::End { .. } => {
                // 会话结束：保留已构建的 committed_hashes 供下次去重
                snapshot.active_import_id = None;
            }
        }
    }

    Ok(snapshot)
}

/// 加载给定 verthys 路径对应的 WAL 快照（恢复入口）
pub fn load(verthys_path: &str) -> Result<WalSnapshot, String> {
    let path = resolve_wal_path(verthys_path);
    load_from_path(&path)
}

/// 台账结算统计（用于日志与断言，不参与分支判定）
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SettlementOutcome {
    /// 本次真正改写归属的块记录数
    pub settled: u64,
    /// 本次被冻结（归属不可证明）的块记录数
    pub frozen: u64,
}

impl SettlementOutcome {
    /// 是否产生了台账变更；无变更时调用方无需重写台账文件
    pub fn changed(&self) -> bool {
        self.settled > 0 || self.frozen > 0
    }
}

/// 把 WAL 快照中的块归属声明应用到台账（纯内存变换，不落盘）
///
/// 两条规则：
///   1. 显式声明过引用集合的条目：把其块记录的归属改写为对应记录 ID；
///   2. 存在引用集合不可推断的历史条目时：台账中仍为孤儿候选的条目一律冻结
///      —— 它们可能被已提交记录引用，只是无从证明，宁可永久保留也不误删。
fn apply_settlement(
    snapshot: &WalSnapshot,
    ledger: &mut crate::repository::verthys_chunks::ChunkLedger,
) -> SettlementOutcome {
    let mut outcome = SettlementOutcome::default();

    for (chunk_id, owner_id) in &snapshot.committed_chunk_owners {
        if ledger.owner_of(*chunk_id) != Some(*owner_id) {
            ledger.set_owner(*chunk_id, *owner_id);
            outcome.settled += 1;
        }
    }

    if snapshot.has_unsettleable_commits {
        for chunk_id in ledger.garbage_ids() {
            ledger.set_owner(
                chunk_id,
                crate::repository::verthys_chunks::UNVERIFIABLE_OWNER,
            );
            outcome.frozen += 1;
        }
    }

    outcome
}

/// 结算块归属并落盘（孤儿回收前的守卫入口）
///
/// 存在这样的崩溃窗口：记录已提交，而台账尚未把块归属从「孤儿候选」改写
/// 为拥有者；此时直接按台账回收，会删掉仍被已提交记录引用的块。本函数以
/// WAL 中的归属声明为权威重建台账，对无法证明归属的历史条目执行冻结，
/// 保证回收面绝不扩大。
///
/// 台账落盘失败向上传播为 Err：调用方必须放弃本次回收（保守不删）。
pub fn settle_chunk_owners(verthys_path: &str) -> Result<SettlementOutcome, String> {
    let snapshot = load(verthys_path)?;
    let mut ledger = crate::repository::verthys_chunks::load_chunk_ledger(verthys_path)?;
    let outcome = apply_settlement(&snapshot, &mut ledger);
    if outcome.changed() {
        crate::repository::verthys_chunks::save_chunk_ledger(verthys_path, &ledger)?;
    }
    Ok(outcome)
}

/// 删除 WAL 文件（导入彻底完成且无需续传去重时调用）
///
/// 新布局与旧布局两处 WAL 及其临时文件一并清理（总清）；快照保留
/// （去重基线仍由快照承载），与既有语义一致。
pub fn remove(verthys_path: &str) -> Result<(), String> {
    let primary = container_layout::wal_file_for(verthys_path);
    remove_file_if_exists(&primary, "WAL")?;
    remove_file_if_exists(
        &PathBuf::from(format!("{}.tmp", primary.to_string_lossy())),
        "WAL 临时文件",
    )?;

    let legacy = container_layout::legacy_wal_file_for(verthys_path);
    remove_file_if_exists(&legacy, "旧布局 WAL")?;
    remove_file_if_exists(
        &PathBuf::from(format!("{}.tmp", legacy.to_string_lossy())),
        "旧布局 WAL 临时文件",
    )?;
    Ok(())
}

/// 判断 WAL 文件是否存在（新布局与旧布局任一命中，用于决定是否触发恢复流程）
pub fn exists(verthys_path: &str) -> bool {
    container_layout::wal_file_for(verthys_path).exists()
        || container_layout::legacy_wal_file_for(verthys_path).exists()
}

/// 追加删除墓碑（照片删除后释放去重锁，删除后可重新导入）。
///
/// 以 append 模式写入既有 WAL（含 fsync）；WAL 不存在时为无操作
/// （去重集合本为空，无可释放）。墓碑独立于导入会话：恢复重放时
/// 与条目位置无关地从 committed 集合移除哈希，且下一次会话创建在
/// 截断 WAL 前先完成重放，移除效果在截断后由内存集合继续承载。
pub fn append_removed(verthys_path: &str, hashes: &[String]) -> Result<(), String> {
    if hashes.is_empty() {
        return Ok(());
    }
    let path = resolve_wal_path(verthys_path);
    if !path.exists() {
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(|e| format!("WAL 追加打开失败: {}", e))?;
    let entry = WalEntry::Removed {
        hashes: hashes.to_vec(),
        at: now_ms(),
    };
    let line = serde_json::to_string(&entry).map_err(|e| format!("WAL 序列化失败: {}", e))?;
    writeln!(file, "{}", line).map_err(|e| format!("WAL 写入失败: {}", e))?;
    file.flush().map_err(|e| format!("WAL flush 失败: {}", e))?;
    file.sync_all()
        .map_err(|e| format!("WAL fsync 失败: {}", e))?;
    Ok(())
}

/// 删除 WAL 与快照文件（开发用重置入口：清空续传去重状态）
///
/// 新布局与旧布局两处一并清理，尾部回收空目录（仅当目录内无其他附属数据）。
pub fn remove_all(verthys_path: &str) -> Result<(), String> {
    let primary = container_layout::wal_file_for(verthys_path);
    remove_file_if_exists(&primary, "WAL")?;
    remove_file_if_exists(
        &PathBuf::from(format!("{}.tmp", primary.to_string_lossy())),
        "WAL 临时文件",
    )?;
    let snap = snapshot_path_for(&primary);
    remove_file_if_exists(&snap, "WAL 快照")?;
    remove_file_if_exists(
        &PathBuf::from(format!("{}.tmp", snap.to_string_lossy())),
        "WAL 快照临时文件",
    )?;

    let legacy = container_layout::legacy_wal_file_for(verthys_path);
    remove_file_if_exists(&legacy, "旧布局 WAL")?;
    remove_file_if_exists(
        &PathBuf::from(format!("{}.tmp", legacy.to_string_lossy())),
        "旧布局 WAL 临时文件",
    )?;
    let legacy_snap = container_layout::legacy_wal_snapshot_file_for(verthys_path);
    remove_file_if_exists(&legacy_snap, "旧布局 WAL 快照")?;
    remove_file_if_exists(
        &PathBuf::from(format!("{}.tmp", legacy_snap.to_string_lossy())),
        "旧布局 WAL 快照临时文件",
    )?;

    let _ =
        container_layout::remove_dir_if_empty(&container_layout::sidecar_dir_for(verthys_path));
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// 导入会话状态（贯穿整个导入生命周期，由 AppState 持有）
///
/// 绑定一个 WAL 写入句柄 + 已提交哈希集合（去重）+ 批次计数器。
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
    /// 已 committed 的内容哈希集合（生产者据此去重，保证幂等）
    pub committed_hashes: HashSet<String>,
    /// 累计已 committed 记录数（检查点）
    pub total_committed: u64,
    /// 累计因哈希去重跳过的记录数（进度反馈用，不入 WAL）
    pub total_skipped: u64,
    /// 外置块哈希 → 记录 ID 映射（本会话已上传块，重试幂等去重）
    pub chunk_ids_by_hash: HashMap<String, u64>,
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
    /// 创建新会话：初始化 WAL + 从既有快照恢复 committed_hashes（续传去重）
    /// 并加载外置块台账（缺失即空，损坏则向上传播失败）。
    ///
    /// 建会话前必须完成台账结算：把上一会话已提交记录的块归属写回台账，
    /// 冻结无法证明归属的历史条目。结算落盘失败即会话创建失败——绝不允许
    /// 在「台账可能把已被引用的块判成孤儿」的状态下开始新一轮写入。
    pub fn new(verthys_path: &str, import_id: &str) -> Result<Self, String> {
        // 先加载既有 WAL 快照（若存在遗留 WAL，恢复 committed_hashes 实现续传去重）
        let snapshot = load(verthys_path)?;
        let committed_hashes = snapshot.committed_hashes.clone();
        let total_committed = snapshot.committed_hashes.len() as u64;

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
            committed_hashes,
            total_committed,
            total_skipped: 0,
            chunk_ids_by_hash: HashMap::new(),
            issued_chunk_ids: HashSet::new(),
            chunk_ledger,
            ledger_dirty: false,
        })
    }

    /// 检查哈希是否已 committed（去重）
    pub fn is_committed(&self, hash: &str) -> bool {
        self.committed_hashes.contains(hash)
    }

    /// 标记一条记录为已 committed（更新去重集合 + 计数）
    pub fn mark_committed(&mut self, hash: &str) {
        if self.committed_hashes.insert(hash.to_string()) {
            self.total_committed += 1;
        }
    }

    /// 标记一条记录因哈希去重跳过（仅累计计数，不入 WAL）
    pub fn mark_skipped(&mut self) {
        self.total_skipped += 1;
    }

    /// 分配下一个批次 ID
    pub fn allocate_batch_id(&mut self) -> u64 {
        let id = self.next_batch_id;
        self.next_batch_id += 1;
        id
    }

    /// 查询已上传外置块（同哈希复用记录 ID，批次重试幂等）
    pub fn lookup_chunk(&self, hash: &str) -> Option<u64> {
        self.chunk_ids_by_hash.get(hash).copied()
    }

    /// 记账已上传外置块（幂等去重映射 + 发放集合两处同步）
    pub fn remember_chunk(&mut self, hash: &str, id: u64) {
        self.chunk_ids_by_hash.insert(hash.to_string(), id);
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

    /// 删除照片后释放去重锁（内存集合即时生效）
    ///
    /// 持久化由 WAL 删除墓碑承担（跨会话恢复时移除）；本方法仅同步
    /// 本会话内存集合与累计计数。返回 true 表示确实移除了已记账哈希。
    pub fn forget_committed(&mut self, hash: &str) -> bool {
        if self.committed_hashes.remove(hash) {
            self.total_committed = self.total_committed.saturating_sub(1);
            true
        } else {
            false
        }
    }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_verthys_path(dir: &Path) -> String {
        dir.join("test.verthys").to_string_lossy().to_string()
    }

    /// 台账落盘临时文件路径；把该路径占为目录即可令落盘确定性失败
    fn ledger_tmp_path(verthys_path: &str) -> PathBuf {
        let mut p = container_layout::chunk_ledger_file_for(verthys_path);
        let mut name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
        name.push(".tmp");
        p.set_file_name(name);
        p
    }

    /// 新布局 WAL 路径（测试直读写用；先确保附属目录存在）
    fn wal_file(verthys_path: &str) -> PathBuf {
        let _ = container_layout::ensure_sidecar_dir(verthys_path);
        container_layout::wal_file_for(verthys_path)
    }

    /// 手写 WAL 文本（用于构造携带/缺省引用集合的历史条目）
    fn write_wal_text(verthys_path: &str, text: &str) {
        std::fs::write(wal_file(verthys_path), text).unwrap();
    }

    #[test]
    fn test_wal_create_append_commit() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut writer = WalWriter::create(&verthys_path, "imp-1").unwrap();
        writer
            .append(&WalEntry::Pending {
                import_id: "imp-1".into(),
                batch_id: 1,
                hash: "abc".into(),
                name: "a.jpg".into(),
                idx: 0,
            })
            .unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-1".into(),
                batch_id: 1,
                hash: "abc".into(),
                verthys_id: 42,
                name: "a.jpg".into(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        writer.finish("imp-1", true).unwrap();

        let snap = load(&verthys_path).unwrap();
        assert!(snap.committed_hashes.contains("abc"));
        assert_eq!(snap.committed_ids.get("abc"), Some(&42));
        assert!(snap.active_import_id.is_none(), "end 后应无活跃会话");
    }

    #[test]
    fn test_wal_crash_recovery_pending_not_committed() {
        // 模拟崩溃：写入 pending 但未 committed，未 end
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut writer = WalWriter::create(&verthys_path, "imp-2").unwrap();
        writer
            .append(&WalEntry::Pending {
                import_id: "imp-2".into(),
                batch_id: 1,
                hash: "dup".into(),
                name: "b.jpg".into(),
                idx: 0,
            })
            .unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-2".into(),
                batch_id: 1,
                hash: "ok".into(),
                verthys_id: 7,
                name: "c.jpg".into(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        // 不调用 finish，模拟崩溃
        drop(writer);

        let snap = load(&verthys_path).unwrap();
        assert!(snap.committed_hashes.contains("ok"));
        assert!(
            !snap.committed_hashes.contains("dup"),
            "pending 未 committed 不应进入去重集合"
        );
        assert!(snap.active_import_id.is_some(), "未 end 应保留活跃会话");
    }

    #[test]
    fn test_wal_dedup_idempotent() {
        // 续传场景：已 committed 的哈希在去重集合中，重新导入应跳过
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut writer = WalWriter::create(&verthys_path, "imp-3").unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-3".into(),
                batch_id: 1,
                hash: "h1".into(),
                verthys_id: 1,
                name: "x".into(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        writer.finish("imp-3", true).unwrap();

        let snap = load(&verthys_path).unwrap();
        assert!(snap.committed_hashes.contains("h1"));
    }

    #[test]
    fn test_wal_compact_preserves_committed() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut writer = WalWriter::create(&verthys_path, "imp-4").unwrap();
        for i in 0..50 {
            writer
                .append(&WalEntry::Pending {
                    import_id: "imp-4".into(),
                    batch_id: 1,
                    hash: format!("h{}", i),
                    name: format!("f{}", i),
                    idx: i,
                })
                .unwrap();
            writer
                .append(&WalEntry::Committed {
                    import_id: "imp-4".into(),
                    batch_id: 1,
                    hash: format!("h{}", i),
                    verthys_id: 100 + i,
                    name: format!("f{}", i),
                    chunk_ids: Some(Vec::new()),
                })
                .unwrap();
        }
        writer.finish("imp-4", true).unwrap();

        // compact 后重新加载，所有 committed 哈希应保留
        let snap = load(&verthys_path).unwrap();
        for i in 0..50 {
            assert!(
                snap.committed_hashes.contains(&format!("h{}", i)),
                "compact 后哈希 h{} 应保留",
                i
            );
        }
    }

    #[test]
    fn test_wal_load_nonexistent() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());
        let snap = load(&verthys_path).unwrap();
        assert!(snap.committed_hashes.is_empty());
    }

    #[test]
    fn test_wal_append_deferred_batched_flush() {
        // 批量 pending 走 deferred 追加 + 一次 flush_sync：行完整可重放，
        // 且 pending 语义不变（不进入 committed 集合）
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut writer = WalWriter::create(&verthys_path, "imp-d").unwrap();
        writer
            .append_deferred(&WalEntry::Pending {
                import_id: "imp-d".into(),
                batch_id: 1,
                hash: "p1".into(),
                name: "a.jpg".into(),
                idx: 0,
            })
            .unwrap();
        writer
            .append_deferred(&WalEntry::Pending {
                import_id: "imp-d".into(),
                batch_id: 1,
                hash: "p2".into(),
                name: "b.jpg".into(),
                idx: 1,
            })
            .unwrap();
        writer.flush_sync().unwrap();
        drop(writer);

        let text = std::fs::read_to_string(wal_file(&verthys_path)).unwrap();
        assert_eq!(text.lines().count(), 3, "begin + 2 条 pending 应全部落盘");

        let snap = load(&verthys_path).unwrap();
        assert!(!snap.committed_hashes.contains("p1"));
        assert!(!snap.committed_hashes.contains("p2"));
    }

    #[test]
    fn test_wal_removed_tombstone_releases_dedup() {
        // 删除墓碑：恢复重放后哈希从去重集合移除（删除后可重新导入）
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut writer = WalWriter::create(&verthys_path, "imp-r").unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-r".into(),
                batch_id: 1,
                hash: "h1".into(),
                verthys_id: 5,
                name: "a.jpg".into(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        writer.finish("imp-r", true).unwrap();

        append_removed(&verthys_path, &["h1".to_string()]).unwrap();

        let snap = load(&verthys_path).unwrap();
        assert!(!snap.committed_hashes.contains("h1"), "墓碑应释放去重锁");
        assert!(!snap.committed_ids.contains_key("h1"));
    }

    #[test]
    fn test_append_removed_noop_without_wal() {
        // WAL 不存在：墓碑为无操作（去重集合本就为空），且不创建 WAL 文件
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());
        append_removed(&verthys_path, &["h1".to_string()]).unwrap();
        assert!(!exists(&verthys_path), "无 WAL 时不得创建文件");
    }

    #[test]
    fn test_snapshot_survives_wal_absence() {
        // 快照文件独立承载 committed 集合：WAL 文件缺失时仍可恢复去重
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut writer = WalWriter::create(&verthys_path, "imp-s").unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-s".into(),
                batch_id: 1,
                hash: "hs".into(),
                verthys_id: 9,
                name: "s.jpg".into(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        writer.finish("imp-s", true).unwrap();

        // WAL 文件被移除（模拟外部清理/损坏），快照仍提供去重集合
        std::fs::remove_file(wal_file(&verthys_path)).unwrap();
        let snap = load(&verthys_path).unwrap();
        assert!(snap.committed_hashes.contains("hs"));
        assert_eq!(snap.committed_ids.get("hs"), Some(&9));
    }

    #[test]
    fn test_import_session_loads_existing_chunk_ledger() {
        // 预写台账文件后新建会话：会话字段应载入既有映射（且不触碰台账文件本身）
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut ledger = crate::repository::verthys_chunks::ChunkLedger::default();
        ledger.set_owner(101, 0);
        ledger.set_owner(202, 77);
        crate::repository::verthys_chunks::save_chunk_ledger(&verthys_path, &ledger).unwrap();

        let session = ImportSession::new(&verthys_path, "imp-ledger").unwrap();
        assert_eq!(session.chunk_ledger.garbage_ids(), vec![101]);

        // 台账文件应保持原样（会话 new 只读台账，不重写）：两条映射均可在
        // 重载后的台账中命中移除，且仅有 101 是 owner==0 的孤儿候选
        let mut reloaded =
            crate::repository::verthys_chunks::load_chunk_ledger(&verthys_path).unwrap();
        assert_eq!(reloaded.garbage_ids(), vec![101]);
        assert!(reloaded.remove(&101));
        assert!(reloaded.remove(&202));
    }

    #[test]
    fn test_import_session_forget_committed() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut session = ImportSession::new(&verthys_path, "imp-f").unwrap();
        session.mark_committed("h1");
        session.mark_committed("h2");
        assert_eq!(session.total_committed, 2);

        assert!(session.forget_committed("h1"));
        assert!(!session.forget_committed("h1"), "重复释放不重复计数");
        assert_eq!(session.total_committed, 1);
        assert!(!session.is_committed("h1"));
        assert!(session.is_committed("h2"));
    }

    #[test]
    fn test_snapshot_baseline_survives_new_session() {
        // 回归：新会话 WAL 重放时 Begin 不得清空快照基线，
        // 否则上一会话压缩固化到快照的去重键将全部丢失，
        // 重启后重新导入同一批照片会产生重复记录
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        // 会话 A：入库 2 张并成功结束（compact 生成快照 + 最小 WAL）
        let mut writer = WalWriter::create(&verthys_path, "imp-a").unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-a".into(),
                batch_id: 1,
                hash: "h1".into(),
                verthys_id: 1,
                name: String::new(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-a".into(),
                batch_id: 1,
                hash: "h2".into(),
                verthys_id: 2,
                name: String::new(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        writer
            .append(&WalEntry::Checkpoint {
                import_id: "imp-a".into(),
                batch_id: 1,
                committed_count: 2,
            })
            .unwrap();
        writer.finish("imp-a", true).unwrap();

        // 会话 B：截断 WAL 写新 begin + 新记录，随后模拟崩溃（无 end）
        let mut writer = WalWriter::create(&verthys_path, "imp-b").unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-b".into(),
                batch_id: 1,
                hash: "h3".into(),
                verthys_id: 3,
                name: String::new(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        writer
            .append(&WalEntry::Checkpoint {
                import_id: "imp-b".into(),
                batch_id: 1,
                committed_count: 3,
            })
            .unwrap();
        drop(writer);

        let snap = load(&verthys_path).unwrap();
        assert!(
            snap.committed_hashes.contains("h1"),
            "快照基线哈希 h1 跨会话必须保留"
        );
        assert!(snap.committed_hashes.contains("h2"));
        assert!(snap.committed_hashes.contains("h3"));
        assert_eq!(snap.committed_hashes.len(), 3);
    }

    #[test]
    fn test_compact_wal_is_minimal_skeleton() {
        // compact 后 WAL 仅保留会话骨架（begin/checkpoint/end），
        // 哈希全集由快照承载；重放成本与存活记录数解耦
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut writer = WalWriter::create(&verthys_path, "imp-m").unwrap();
        for i in 0..50 {
            writer
                .append(&WalEntry::Committed {
                    import_id: "imp-m".into(),
                    batch_id: 1,
                    hash: format!("h{}", i),
                    verthys_id: 100 + i,
                    name: String::new(),
                    chunk_ids: Some(Vec::new()),
                })
                .unwrap();
        }
        writer
            .append(&WalEntry::Checkpoint {
                import_id: "imp-m".into(),
                batch_id: 1,
                committed_count: 50,
            })
            .unwrap();
        writer.finish("imp-m", true).unwrap();

        let wal_text = std::fs::read_to_string(wal_file(&verthys_path)).unwrap();
        let line_count = wal_text.lines().count();
        assert!(
            line_count < 10,
            "compact 后 WAL 应为会话骨架，实际 {} 行",
            line_count
        );

        let snap = load(&verthys_path).unwrap();
        assert_eq!(snap.committed_hashes.len(), 50, "快照承载全部 50 个哈希");
        assert!(snap.committed_hashes.contains("h49"));
    }

    #[test]
    fn test_tombstone_after_compact_releases_snapshot_hash() {
        // 墓碑追加在 compact 之后的 WAL 尾部，重放必须能移除快照基线内的哈希
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut writer = WalWriter::create(&verthys_path, "imp-t").unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-t".into(),
                batch_id: 1,
                hash: "keep".into(),
                verthys_id: 1,
                name: String::new(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-t".into(),
                batch_id: 1,
                hash: "gone".into(),
                verthys_id: 2,
                name: String::new(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        writer
            .append(&WalEntry::Checkpoint {
                import_id: "imp-t".into(),
                batch_id: 1,
                committed_count: 2,
            })
            .unwrap();
        writer.finish("imp-t", true).unwrap();

        append_removed(&verthys_path, &["gone".to_string()]).unwrap();

        let snap = load(&verthys_path).unwrap();
        assert!(snap.committed_hashes.contains("keep"));
        assert!(
            !snap.committed_hashes.contains("gone"),
            "墓碑须移除快照基线内的哈希"
        );
    }

    #[test]
    fn test_tombstone_survives_session_creation_and_ends() {
        // 回归（去重锁复活缺陷）：删除墓碑仅落在 WAL 尾部；会话创建会截断
        // WAL，若未把「快照基线 + WAL 重放」后的权威集合固化为新基线，墓碑
        // 随截断消失，失败结束（不 compact）后下次载入即复活已删除哈希，
        // 表现为删除后重新导入同一文件被静默全部跳过。
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        // 会话 A：入库 2 条并成功结束（compact 固化快照 + 最小骨架 WAL）
        let mut writer = WalWriter::create(&verthys_path, "imp-a").unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-a".into(),
                batch_id: 1,
                hash: "keep".into(),
                verthys_id: 1,
                name: String::new(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        writer
            .append(&WalEntry::Committed {
                import_id: "imp-a".into(),
                batch_id: 1,
                hash: "gone".into(),
                verthys_id: 2,
                name: String::new(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        writer
            .append(&WalEntry::Checkpoint {
                import_id: "imp-a".into(),
                batch_id: 1,
                committed_count: 2,
            })
            .unwrap();
        writer.finish("imp-a", true).unwrap();

        // 删除墓碑：释放 gone 的去重锁
        append_removed(&verthys_path, &["gone".to_string()]).unwrap();
        assert!(!load(&verthys_path).unwrap().committed_hashes.contains("gone"));

        // 会话 B：创建（截断 WAL）→ 以失败结束（不 compact，原样保留 WAL）
        let session = ImportSession::new(&verthys_path, "imp-b").unwrap();
        assert!(
            !session.is_committed("gone"),
            "会话内集合须等于墓碑后的权威集合"
        );
        assert!(session.is_committed("keep"));
        session.writer.finish("imp-b", false).unwrap();

        let snap = load(&verthys_path).unwrap();
        assert!(snap.committed_hashes.contains("keep"));
        assert!(
            !snap.committed_hashes.contains("gone"),
            "墓碑必须跨会话创建持久化（失败结束路径）"
        );

        // 会话 C：再次创建 → 以成功结束（compact 重写快照）
        let mut session = ImportSession::new(&verthys_path, "imp-c").unwrap();
        session.mark_committed("fresh");
        session
            .writer
            .append(&WalEntry::Committed {
                import_id: "imp-c".into(),
                batch_id: 1,
                hash: "fresh".into(),
                verthys_id: 3,
                name: String::new(),
                chunk_ids: Some(Vec::new()),
            })
            .unwrap();
        session.writer.finish("imp-c", true).unwrap();

        let snap = load(&verthys_path).unwrap();
        assert!(snap.committed_hashes.contains("keep"));
        assert!(snap.committed_hashes.contains("fresh"));
        assert!(
            !snap.committed_hashes.contains("gone"),
            "墓碑必须跨会话创建持久化（成功压缩路径）"
        );
    }

    #[test]
    fn test_committed_chunk_ids_accumulate_and_legacy_marked() {
        // 显式声明引用集合的条目累积归属；字段缺省的历史条目标记为不可结算
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());
        write_wal_text(
            &verthys_path,
            concat!(
                "{\"kind\":\"begin\",\"import_id\":\"imp-x\",\"ts\":1}\n",
                "{\"kind\":\"committed\",\"import_id\":\"imp-x\",\"batch_id\":1,",
                "\"hash\":\"legacy\",\"verthys_id\":11,\"name\":\"a.jpg\"}\n",
                "{\"kind\":\"committed\",\"import_id\":\"imp-x\",\"batch_id\":1,",
                "\"hash\":\"fresh\",\"verthys_id\":22,\"name\":\"b.jpg\",\"chunk_ids\":[7,8]}\n"
            ),
        );

        let snap = load(&verthys_path).unwrap();
        assert_eq!(snap.committed_chunk_owners.get(&7), Some(&22));
        assert_eq!(snap.committed_chunk_owners.get(&8), Some(&22));
        assert!(snap.has_unsettleable_commits, "历史条目应标记为不可结算");
    }

    #[test]
    fn test_settle_chunk_owners_applies_and_freezes() {
        // 已被声明的块归属改写为记录 ID；无法证明归属的孤儿候选冻结
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut ledger = crate::repository::verthys_chunks::ChunkLedger::default();
        ledger.set_owner(7, 0);
        ledger.set_owner(9, 0);
        crate::repository::verthys_chunks::save_chunk_ledger(&verthys_path, &ledger).unwrap();

        write_wal_text(
            &verthys_path,
            concat!(
                "{\"kind\":\"begin\",\"import_id\":\"imp-y\",\"ts\":1}\n",
                "{\"kind\":\"committed\",\"import_id\":\"imp-y\",\"batch_id\":1,",
                "\"hash\":\"legacy\",\"verthys_id\":11,\"name\":\"a.jpg\"}\n",
                "{\"kind\":\"committed\",\"import_id\":\"imp-y\",\"batch_id\":1,",
                "\"hash\":\"fresh\",\"verthys_id\":33,\"name\":\"b.jpg\",\"chunk_ids\":[7]}\n"
            ),
        );

        let outcome = settle_chunk_owners(&verthys_path).unwrap();
        assert_eq!(outcome.settled, 1, "块 7 的归属应被改写");
        assert_eq!(outcome.frozen, 1, "块 9 应被冻结");

        let reloaded = crate::repository::verthys_chunks::load_chunk_ledger(&verthys_path).unwrap();
        assert_eq!(reloaded.owner_of(7), Some(33));
        assert_eq!(
            reloaded.owner_of(9),
            Some(crate::repository::verthys_chunks::UNVERIFIABLE_OWNER)
        );
        assert!(reloaded.garbage_ids().is_empty(), "结算后不得再有回收候选");

        let again = settle_chunk_owners(&verthys_path).unwrap();
        assert!(!again.changed(), "重复结算应为无变更");
    }

    #[test]
    fn test_settle_chunk_owners_failure_propagates() {
        // 台账落盘通道被占时结算必须失败，不得静默跳过
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut ledger = crate::repository::verthys_chunks::ChunkLedger::default();
        ledger.set_owner(7, 0);
        crate::repository::verthys_chunks::save_chunk_ledger(&verthys_path, &ledger).unwrap();

        write_wal_text(
            &verthys_path,
            concat!(
                "{\"kind\":\"begin\",\"import_id\":\"imp-z\",\"ts\":1}\n",
                "{\"kind\":\"committed\",\"import_id\":\"imp-z\",\"batch_id\":1,",
                "\"hash\":\"fresh\",\"verthys_id\":44,\"name\":\"c.jpg\",\"chunk_ids\":[7]}\n"
            ),
        );

        let tmp_dir = ledger_tmp_path(&verthys_path);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        assert!(
            settle_chunk_owners(&verthys_path).is_err(),
            "落盘失败必须向上传播"
        );
        std::fs::remove_dir_all(&tmp_dir).unwrap();
    }

    #[test]
    fn test_import_session_settles_before_wal_truncation() {
        // 建会话先结算并落盘，随后才截断 WAL；归属不会因截断而失去证明
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut ledger = crate::repository::verthys_chunks::ChunkLedger::default();
        ledger.set_owner(7, 0);
        crate::repository::verthys_chunks::save_chunk_ledger(&verthys_path, &ledger).unwrap();

        write_wal_text(
            &verthys_path,
            concat!(
                "{\"kind\":\"begin\",\"import_id\":\"imp-s1\",\"ts\":1}\n",
                "{\"kind\":\"committed\",\"import_id\":\"imp-s1\",\"batch_id\":1,",
                "\"hash\":\"h\",\"verthys_id\":55,\"name\":\"d.jpg\",\"chunk_ids\":[7]}\n"
            ),
        );

        let session = ImportSession::new(&verthys_path, "imp-s2").unwrap();
        assert_eq!(session.chunk_ledger.owner_of(7), Some(55));
        drop(session);

        let reloaded = crate::repository::verthys_chunks::load_chunk_ledger(&verthys_path).unwrap();
        assert_eq!(reloaded.owner_of(7), Some(55), "结算结果必须落盘");
    }

    #[test]
    fn test_import_session_refuses_when_settlement_persist_fails() {
        // 结算落盘失败时会话创建失败，且不得截断 WAL（归属声明不可丢）
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut ledger = crate::repository::verthys_chunks::ChunkLedger::default();
        ledger.set_owner(7, 0);
        crate::repository::verthys_chunks::save_chunk_ledger(&verthys_path, &ledger).unwrap();

        write_wal_text(
            &verthys_path,
            concat!(
                "{\"kind\":\"begin\",\"import_id\":\"imp-s3\",\"ts\":1}\n",
                "{\"kind\":\"committed\",\"import_id\":\"imp-s3\",\"batch_id\":1,",
                "\"hash\":\"h\",\"verthys_id\":66,\"name\":\"e.jpg\",\"chunk_ids\":[7]}\n"
            ),
        );

        let tmp_dir = ledger_tmp_path(&verthys_path);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        assert!(ImportSession::new(&verthys_path, "imp-s4").is_err());
        std::fs::remove_dir_all(&tmp_dir).unwrap();

        let wal_after = std::fs::read_to_string(wal_file(&verthys_path)).unwrap();
        assert!(
            wal_after.contains("imp-s3"),
            "会话创建失败时 WAL 必须保持原样（含归属声明）"
        );
    }

    #[test]
    fn test_legacy_wal_and_snapshot_migrated_on_read() {
        // 旧布局 WAL + 快照在首次读取时被原子搬迁到附属目录
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let legacy_wal = container_layout::legacy_wal_file_for(&verthys_path);
        std::fs::write(
            &legacy_wal,
            "{\"kind\":\"begin\",\"import_id\":\"imp-l\",\"ts\":1}\n",
        )
        .unwrap();
        let mut baseline = WalSnapshot::default();
        baseline.committed_hashes.insert("hl".to_string());
        baseline.committed_ids.insert("hl".to_string(), 11);
        write_snapshot_file(&legacy_wal, &baseline).unwrap();

        let snap = load(&verthys_path).unwrap();
        assert!(snap.committed_hashes.contains("hl"));
        assert_eq!(snap.committed_ids.get("hl"), Some(&11));

        assert!(!legacy_wal.exists(), "旧布局 WAL 必须被搬走");
        assert!(
            !container_layout::legacy_wal_snapshot_file_for(&verthys_path).exists(),
            "旧布局快照必须被搬走"
        );
        assert!(container_layout::wal_file_for(&verthys_path).exists());
        assert!(container_layout::wal_snapshot_file_for(&verthys_path).exists());
    }

    #[test]
    fn test_create_recycles_legacy_after_truncate() {
        // 会话创建截断 WAL 后，旧布局 WAL 与快照被回收（去重集合已载入内存）
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());
        let legacy_wal = container_layout::legacy_wal_file_for(&verthys_path);
        let legacy_snap = container_layout::legacy_wal_snapshot_file_for(&verthys_path);
        std::fs::write(&legacy_wal, "stale").unwrap();
        std::fs::write(&legacy_snap, "stale").unwrap();

        let _writer = WalWriter::create(&verthys_path, "imp-c").unwrap();

        assert!(!legacy_wal.exists(), "旧布局 WAL 必须被回收");
        assert!(!legacy_snap.exists(), "旧布局快照必须被回收");
        assert!(container_layout::wal_file_for(&verthys_path).exists());
    }
}
