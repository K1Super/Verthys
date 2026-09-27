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
 * 依赖方向：repository → util（单向，禁止引用 controller/service/entry）。
 */

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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

    /// 返回所有 owner==0（未被任何 meta 引用）的块记录 ID，升序
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
}

/// 台账文件在磁盘上的 JSON 表示（entries 以键值对数组序列化）
///
/// 排序后写出以保证字节级确定性，便于变更最小化与人工比对。
#[derive(Serialize, Deserialize, Default)]
struct ChunkLedgerFile {
    entries: Vec<(u64, u64)>,
}

/// 计算给定 verthys 路径对应的台账文件路径（WAL 同目录）
///
/// 文件名为 `<verthys>.import.chunks.json`，与 WAL（`.import.wal`）同套
/// 命名，均位于 verthys 文件同目录（受 VerthysFileLock 独占锁保护）。
pub fn chunk_ledger_path_for(verthys_path: &str) -> PathBuf {
    let mut p = PathBuf::from(verthys_path);
    let mut name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(".import.chunks.json");
    p.set_file_name(name);
    p
}

/// 从磁盘加载台账；文件不存在时返回空台账
///
/// 解析失败（JSON 损坏、字段类型不符）向上传播为 Err，不静默吞掉：
/// 损坏台账意味着 GC 判定依据不可信，宁可失败也不误删。
pub fn load_chunk_ledger(verthys_path: &str) -> Result<ChunkLedger, String> {
    let path = chunk_ledger_path_for(verthys_path);
    if !path.exists() {
        return Ok(ChunkLedger::default());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("块台账读取失败: {}", e))?;
    let file: ChunkLedgerFile =
        serde_json::from_str(&text).map_err(|e| format!("块台账解析失败: {}", e))?;
    let mut ledger = ChunkLedger::default();
    for (chunk_id, owner_id) in file.entries {
        ledger.entries.insert(chunk_id, owner_id);
    }
    Ok(ledger)
}

/// 原子写出台账（tmp 文件 + write_all + sync_all + rename，沿用 WAL 的
/// `.tmp` 命名套路）
///
/// 写失败向上传播为 Err：调用方据此决定是否中断（写者路径）或退化为
/// 保守 GC（不删）。rename 在 Windows 上目标不存在时原子替换。
pub fn save_chunk_ledger(verthys_path: &str, ledger: &ChunkLedger) -> Result<(), String> {
    let path = chunk_ledger_path_for(verthys_path);
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
    fn test_save_then_load_consistent_and_sorted_file() {
        let dir = tempdir().unwrap();
        let verthys_path = make_verthys_path(dir.path());

        let mut ledger = ChunkLedger::default();
        ledger.set_owner(3, 0);
        ledger.set_owner(1, 0);
        ledger.set_owner(2, 55);
        save_chunk_ledger(&verthys_path, &ledger).unwrap();

        // 文件内 entries 升序且结构自洽
        let text = std::fs::read_to_string(chunk_ledger_path_for(&verthys_path)).unwrap();
        assert!(text.starts_with('{'));
        assert!(text.contains("\"entries\""));
        // 首个键值对应为 (1, 0)
        assert!(text.contains("[1,0]"), "排序后首个条目应为 (1,0): {}", text);

        let loaded = load_chunk_ledger(&verthys_path).unwrap();
        assert_eq!(loaded.entries, ledger.entries);
    }
}
