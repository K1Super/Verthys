/*
 * repository/verthys_chunks.rs — 照片导入外置块台账（ChunkLedger）
 *
 * 职责：持久化「外置块记录 ID → 拥有者 meta 记录 ID」的映射，支撑
 * 崩溃后孤儿块回收（GC）。大文件照片先以外置块（独立记录）上传，随后
 * meta 记录携带 chunk id 引用这些块；若上传后、meta 入库前崩溃，块记录
 * 残留且无任何 meta 引用，即为孤儿。
 *
 * 语义：
 *   - 块上传成功（process_append_chunks）：set_owner(id, 0)，0 表示
 *     「已上传但尚未被任何 meta 引用」，即崩溃孤儿候选；
 *   - meta 入库成功（process_append_pending）：set_owner(chunk_id, verthys_id)，
 *     绑定到 meta 记录，不再视作孤儿；
 *   - GC（verthys_gc_orphan_chunks）：owner==0 的块记录可安全删除。
 *
 * 约束（硬性）：
 *   - 台账仅存纯数字 ID 映射，不含密钥、不含明文、不含密文、不含哈希；
 *   - 台账只由导入单写者线程（state::import_writer）读写；GC 命令仅在场
 *     无活跃导入会话时接触台账文件，避免与写者内存视图并发冲突；
 *   - 台账落盘失败不破坏已入库数据：GC 退化为保守语义（不删）。
 *
 * 附属目录布局：
 *   - 权威写路径：附属数据目录内 import.chunks.json（受 VerthysFileLock 保护）。
 *
 * 依赖方向：repository → util（单向，禁止引用 controller/service/entry）。
 */

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::repository::container_layout;

/// 「无法证明归属」的台账占位值。
///
/// 孤儿回收只删除归属为 0 的条目；当历史条目既未被 meta 引用、又缺少
/// 可结算的引用记录时，回填本值将其冻结：既不参与回收，也不冒充真实归属。
/// 记录 ID 自 1 起单调分配且永不复用，本值不会与真实归属冲突。
pub const UNVERIFIABLE_OWNER: u64 = u64::MAX;

/// 外置块记录 ID → 拥有者 meta 记录 ID 映射（0 = 未被引用，孤儿候选）
///
/// chunk 记录 lid（键）→ owner meta lid（值）。owner 为 0 表示块已上传
/// 但尚未被任何 meta 引用。仅由导入单写者线程持有与修改。
#[derive(Default)]
pub struct ChunkLedger {
    /// 块记录 ID → 拥有者记录 ID（0 = 未被引用）
    entries: HashMap<u64, u64>,
}

impl ChunkLedger {
    /// 设置块记录的拥有者（覆盖既有值；owner 传 0 表示标记为孤儿候选）
    ///
    /// 并发约束：仅可被导入单写者线程调用；GC 路径在无活跃会话时操作
    /// 单独加载的台账副本，不与本实例并发。
    pub fn set_owner(&mut self, chunk_id: u64, owner_id: u64) {
        self.entries.insert(chunk_id, owner_id);
    }

    /// 移除块记录条目，返回是否确实移除了该 ID
    pub fn remove(&mut self, chunk_id: &u64) -> bool {
        self.entries.remove(chunk_id).is_some()
    }

    /// 查询块记录的当前归属；未登记返回 None
    ///
    /// 结算路径据此判断归属是否真的发生变化，避免无变更时重写台账文件。
    pub fn owner_of(&self, chunk_id: u64) -> Option<u64> {
        self.entries.get(&chunk_id).copied()
    }

    /// 返回 owner==0（未被任何 meta 引用）的块记录 ID，升序
    ///
    /// 冻结条目（`UNVERIFIABLE_OWNER`）不在此列：它们归属不可证明，
    /// 任何情况下都不得进入回收候选。
    pub fn garbage_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, owner)| **owner == 0)
            .map(|(chunk_id, _)| *chunk_id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// 按拥有者记录 ID 反查其全部外置块记录 ID（升序，单次遍历）。
    ///
    /// 删除照片/文件时，前端只需提交索引记录 ID；外置块（含瘦身布局的
    /// 缩略图/块集）由台账在此展开。避免为删除逐条解密 meta 取得块引用，
    /// 也保证级联删除不依赖前端缓存是否已解密。
    pub fn chunk_ids_for_owners(&self, owners: &HashSet<u64>) -> Vec<u64> {
        if owners.is_empty() {
            return Vec::new();
        }
        let mut ids: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, owner)| owners.contains(owner))
            .map(|(chunk_id, _)| *chunk_id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// 批量移除条目，返回实际移除数量（删除级联后的台账收敛）。
    pub fn remove_many(&mut self, ids: &[u64]) -> usize {
        let mut removed = 0usize;
        for id in ids {
            if self.entries.remove(id).is_some() {
                removed += 1;
            }
        }
        removed
    }
}

/// 台账文件在磁盘上的 JSON 表示（entries 以键值对数组序列化）
///
/// 排序后写出以保证字节级确定性，便于变更最小化与人工比对。
#[derive(Serialize, Deserialize, Default)]
struct ChunkLedgerFile {
    entries: Vec<(u64, u64)>,
}

/// 台账追加日志单条变更（JSON Lines；c=块 ID，o=拥有者 ID）
///
/// 追加日志把每次块上传/meta 认领的落盘成本降为 O(变更数 + fsync)，
/// 避免大会话中反复重写整份台账导致的 O(n²) 磁盘写放大。
#[derive(Serialize, Deserialize)]
struct ChunkLedgerChange {
    c: u64,
    o: u64,
}

/// 把追加日志重放到内存台账。
///
/// 崩溃可能截断最后一行：仅当最后一行无换行且解析失败时按撕裂写忽略，
/// 其余损坏一律向上传播，保持「台账不可信就拒绝 GC」的保守语义。
fn apply_journal_file(path: &Path, ledger: &mut ChunkLedger) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("块台账日志读取失败: {}", e))?;
    let lines: Vec<&str> = text.lines().collect();
    let ends_with_newline = text.ends_with('\n');
    for (idx, line) in lines.iter().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<ChunkLedgerChange>(line) {
            Ok(change) => {
                ledger.entries.insert(change.c, change.o);
            }
            Err(e) => {
                let is_last = idx + 1 == lines.len();
                if is_last && !ends_with_newline {
                    log::warn!("[chunk_ledger] 忽略截断的日志尾行: {}", e);
                    break;
                }
                return Err(format!("块台账日志解析失败: {}", e));
            }
        }
    }
    Ok(())
}

/// 解析既有台账文件（调用方保证文件存在）
///
/// 解析失败（JSON 损坏、字段类型不符）向上传播为 Err，不静默吞掉：
/// 损坏台账意味着 GC 判定依据不可信，宁可失败也不误删。
fn parse_ledger_file(path: &Path) -> Result<ChunkLedger, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("块台账读取失败: {}", e))?;
    let file: ChunkLedgerFile =
        serde_json::from_str(&text).map_err(|e| format!("块台账解析失败: {}", e))?;
    let mut ledger = ChunkLedger::default();
    for (chunk_id, owner_id) in file.entries {
        ledger.entries.insert(chunk_id, owner_id);
    }
    Ok(ledger)
}

/// 从磁盘加载台账；文件不存在时返回空台账
pub fn load_chunk_ledger(verthys_path: &str) -> Result<ChunkLedger, String> {
    let primary = container_layout::chunk_ledger_file_for(verthys_path);
    let mut ledger = if primary.exists() {
        parse_ledger_file(&primary)?
    } else {
        ChunkLedger::default()
    };

    let journal = container_layout::chunk_ledger_journal_file_for(verthys_path);
    apply_journal_file(&journal, &mut ledger)?;
    Ok(ledger)
}

/// 追加台账变更（块上传 owner=0 / meta 认领 owner>0）。
///
/// **不逐批 fsync**：日志写入系统页缓存即返回。日志是孤儿回收的辅助账，
/// 不是数据权威；进程/断电丢失尾部只会让未落账的块保守地不被回收，
/// 已提交记录引用的块由 WAL 结算重新绑定，不会误删。会话结束的全量快照
/// （`save_chunk_ledger`）负责真正持久化并清理日志，稳态文件数量有界。
///
/// 不逐批刷盘同时消除了导入热路径上「每批块一次 FlushFileBuffers」的
/// 分钟级磁盘停顿风险（慢盘/实时扫描下是首要卡顿来源）。
pub fn append_chunk_ledger_entries(
    verthys_path: &str,
    entries: &[(u64, u64)],
) -> Result<(), String> {
    if entries.is_empty() {
        return Ok(());
    }
    container_layout::ensure_sidecar_dir(verthys_path)?;
    let journal = container_layout::chunk_ledger_journal_file_for(verthys_path);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&journal)
        .map_err(|e| format!("块台账日志打开失败: {}", e))?;
    let mut buf = String::with_capacity(entries.len() * 24);
    for (chunk_id, owner_id) in entries {
        let change = ChunkLedgerChange {
            c: *chunk_id,
            o: *owner_id,
        };
        let line = serde_json::to_string(&change)
            .map_err(|e| format!("块台账日志序列化失败: {}", e))?;
        buf.push_str(&line);
        buf.push('\n');
    }
    file.write_all(buf.as_bytes())
        .map_err(|e| format!("块台账日志写入失败: {}", e))?;
    Ok(())
}

/// 原子写出台账（tmp 文件 + write_all + sync_all + rename，沿用 WAL 的
/// `.tmp` 命名套路）
///
/// 写失败向上传播为 Err：调用方据此决定是否中断（写者路径）或退化为
/// 保守 GC（不删）。rename 在 Windows 上目标不存在时原子替换。
/// 目录保障失败同样上抛。
pub fn save_chunk_ledger(verthys_path: &str, ledger: &ChunkLedger) -> Result<(), String> {
    container_layout::ensure_sidecar_dir(verthys_path)?;
    let path = container_layout::chunk_ledger_file_for(verthys_path);
    let mut tmp = path.clone();
    let mut name = tmp
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(".tmp");
    tmp.set_file_name(name);

    let mut entries: Vec<(u64, u64)> = ledger.entries.iter().map(|(k, v)| (*k, *v)).collect();
    entries.sort_unstable();
    let payload = ChunkLedgerFile { entries };
    let json = serde_json::to_string(&payload).map_err(|e| format!("块台账序列化失败: {}", e))?;
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| format!("块台账临时文件创建失败: {}", e))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("块台账写入失败: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("块台账 fsync 失败: {}", e))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("块台账 rename 失败: {}", e))?;

    /* 快照已持久，日志可安全删除；删除失败时保留日志也无害——
     * 重放是幂等的，下次压缩仍会清理。 */
    let journal = container_layout::chunk_ledger_journal_file_for(verthys_path);
    if let Err(e) = std::fs::remove_file(&journal) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!("[chunk_ledger] 快照后清理日志失败（保留，重放幂等）: {}", e);
        }
    }
    Ok(())
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_verthys_path(dir: &std::path::Path) -> String {
        dir.join("test.verthys").to_string_lossy().to_string()
    }

    #[test]
    fn test_load_nonexistent_is_empty() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());
        let ledger = load_chunk_ledger(&verthys_path).unwrap();
        assert!(ledger.entries.is_empty());
        assert!(ledger.garbage_ids().is_empty());
    }

    #[test]
    fn test_roundtrip_preserves_entries_including_zero_owner() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut ledger = ChunkLedger::default();
        ledger.set_owner(10, 0);
        ledger.set_owner(20, 99);
        ledger.set_owner(30, 88);
        save_chunk_ledger(&verthys_path, &ledger).unwrap();

        let loaded = load_chunk_ledger(&verthys_path).unwrap();
        assert_eq!(loaded.entries.len(), 3);
        assert_eq!(loaded.entries.get(&10), Some(&0));
        assert_eq!(loaded.entries.get(&20), Some(&99));
        assert_eq!(loaded.entries.get(&30), Some(&88));
    }

    #[test]
    fn test_garbage_ids_only_zero_owner_sorted() {
        let mut ledger = ChunkLedger::default();
        ledger.set_owner(5, 0);
        ledger.set_owner(1, 0);
        ledger.set_owner(7, 42);
        ledger.set_owner(3, 0);
        ledger.set_owner(9, 0);

        assert_eq!(ledger.garbage_ids(), vec![1, 3, 5, 9]);
    }

    #[test]
    fn test_frozen_owner_excluded_from_garbage() {
        // 冻结条目（归属不可证明）不得进入回收候选；归属查询按原值返回
        let mut ledger = ChunkLedger::default();
        ledger.set_owner(1, 0);
        ledger.set_owner(2, UNVERIFIABLE_OWNER);
        ledger.set_owner(3, 42);

        assert_eq!(ledger.garbage_ids(), vec![1]);
        assert_eq!(ledger.owner_of(2), Some(UNVERIFIABLE_OWNER));
        assert_eq!(ledger.owner_of(3), Some(42));
        assert_eq!(ledger.owner_of(999), None);
    }

    #[test]
    fn test_remove_semantics() {
        let mut ledger = ChunkLedger::default();
        ledger.set_owner(11, 0);
        ledger.set_owner(12, 7);

        assert!(ledger.remove(&11));
        assert!(!ledger.remove(&11), "重复删除应返回 false");
        assert!(!ledger.remove(&999));
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.entries.get(&12), Some(&7));
    }

    #[test]
    fn test_chunk_ids_for_owners_expands_delete_cascade() {
        // 删除索引记录时按台账反查其全部外置块（含瘦身缩略图/块集）
        let mut ledger = ChunkLedger::default();
        ledger.set_owner(101, 11);
        ledger.set_owner(102, 11);
        ledger.set_owner(103, 12);
        ledger.set_owner(104, 0);

        let owners: HashSet<u64> = [11u64, 12u64].into_iter().collect();
        assert_eq!(ledger.chunk_ids_for_owners(&owners), vec![101, 102, 103]);
        assert!(ledger.chunk_ids_for_owners(&HashSet::new()).is_empty());

        let removed = ledger.remove_many(&[101, 102, 103, 999]);
        assert_eq!(removed, 3);
        assert_eq!(ledger.owner_of(104), Some(0), "孤儿候选不得被误删");
    }

    #[test]
    fn test_save_then_load_consistent_and_sorted_file() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut ledger = ChunkLedger::default();
        ledger.set_owner(3, 0);
        ledger.set_owner(1, 0);
        ledger.set_owner(2, 55);
        save_chunk_ledger(&verthys_path, &ledger).unwrap();

        // 文件内 entries 升序且结构自洽
        let text = std::fs::read_to_string(container_layout::chunk_ledger_file_for(&verthys_path))
            .unwrap();
        assert!(text.starts_with('{'));
        assert!(text.contains("\"entries\""));
        // 首个键值对应为 (1, 0)
        assert!(text.contains("[1,0]"), "排序后首个条目应为 (1,0): {}", text);

        let loaded = load_chunk_ledger(&verthys_path).unwrap();
        assert_eq!(loaded.entries, ledger.entries);
    }

    #[test]
    fn test_save_leaves_no_tmp_residue() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut ledger = ChunkLedger::default();
        ledger.set_owner(1, 0);
        save_chunk_ledger(&verthys_path, &ledger).unwrap();

        let tmp = std::path::PathBuf::from(format!(
            "{}.tmp",
            container_layout::chunk_ledger_file_for(&verthys_path).to_string_lossy()
        ));
        assert!(!tmp.exists(), "不得遗留台账临时文件");
    }

    #[test]
    fn test_journal_replayed_without_snapshot() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        append_chunk_ledger_entries(&verthys_path, &[(10, 0), (20, 99), (10, 88)]).unwrap();

        let loaded = load_chunk_ledger(&verthys_path).unwrap();
        // 后写覆盖先写（重放顺序即追加顺序）
        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.owner_of(10), Some(88));
        assert_eq!(loaded.owner_of(20), Some(99));
    }

    #[test]
    fn test_journal_torn_tail_ignored() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        append_chunk_ledger_entries(&verthys_path, &[(1, 0)]).unwrap();
        let journal = container_layout::chunk_ledger_journal_file_for(&verthys_path);
        // 崩溃窗口：最后一行无换行且被截断
        let mut text = std::fs::read_to_string(&journal).unwrap();
        text.push_str("{\"c\":2,\"o");
        std::fs::write(&journal, text).unwrap();

        let loaded = load_chunk_ledger(&verthys_path).unwrap();
        assert_eq!(loaded.owner_of(1), Some(0), "完整行必须生效");
        assert_eq!(loaded.owner_of(2), None, "截断尾行不得生效");
    }

    #[test]
    fn test_journal_mid_file_corruption_rejected() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let journal = container_layout::chunk_ledger_journal_file_for(&verthys_path);
        std::fs::create_dir_all(journal.parent().unwrap()).unwrap();
        // 中间行损坏且后续仍有完整行：不得按撕裂尾行宽容，必须失败
        std::fs::write(&journal, b"{\"c\":1,\"o\":0}\nnot-json\n{\"c\":3,\"o\":5}\n").unwrap();

        assert!(load_chunk_ledger(&verthys_path).is_err());
    }

    #[test]
    fn test_save_compacts_and_removes_journal() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        append_chunk_ledger_entries(&verthys_path, &[(1, 0), (2, 0)]).unwrap();
        append_chunk_ledger_entries(&verthys_path, &[(2, 55)]).unwrap();

        let mut ledger = load_chunk_ledger(&verthys_path).unwrap();
        ledger.set_owner(3, 77);
        save_chunk_ledger(&verthys_path, &ledger).unwrap();

        let journal = container_layout::chunk_ledger_journal_file_for(&verthys_path);
        assert!(!journal.exists(), "快照落盘后日志必须被清理");

        // 快照已包含全部重放结果，重新加载不依赖日志
        let loaded = load_chunk_ledger(&verthys_path).unwrap();
        assert_eq!(loaded.owner_of(1), Some(0));
        assert_eq!(loaded.owner_of(2), Some(55));
        assert_eq!(loaded.owner_of(3), Some(77));
    }

    #[test]
    fn test_journal_idempotent_replay_after_snapshot() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut ledger = ChunkLedger::default();
        ledger.set_owner(1, 0);
        ledger.set_owner(2, 55);
        save_chunk_ledger(&verthys_path, &ledger).unwrap();

        // 模拟「快照写入成功但日志清理失败」：重复重放不得产生冲突或新增
        append_chunk_ledger_entries(&verthys_path, &[(1, 0), (2, 55)]).unwrap();
        let loaded = load_chunk_ledger(&verthys_path).unwrap();
        assert_eq!(loaded.entries, ledger.entries);
    }
}
