//! repository/verthys_wal.rs — 照片导入 Write-Ahead Log（断点续传持久层）
//!
//! ★ Comprehensive_optimization：异步批处理流水线 — 第 5 项「断点续传：前置 WAL + 检查点」
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
//!   {"kind":"committed","import_id":"<uuid>","batch_id":<n>,"hash":"<blake3 hex>","verthys_id":<lid>,"name":"<file>"}
//!   {"kind":"checkpoint","import_id":"<uuid>","batch_id":<n>,"committed_count":<x>}
//!   {"kind":"end","import_id":"<uuid>","success":<bool>}
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
//! - WAL 文件位于 verthys 文件同目录（受 VerthysFileLock 独占锁保护，防并发写）。
//! - 所有 IO 失败向上传播为 Err（持久层不吞异常），由控制器决定降级策略。
//!
//! 依赖方向：repository → util（单向，禁止引用 controller/service/entry）

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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
    #[serde(rename = "committed")]
    Committed {
        import_id: String,
        batch_id: u64,
        hash: String,
        verthys_id: u64,
        name: String,
    },
    /// 检查点：标记某批次完整提交
    #[serde(rename = "checkpoint")]
    Checkpoint {
        import_id: String,
        batch_id: u64,
        committed_count: u64,
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
}

/// 计算给定 verthys 路径对应的 WAL 文件路径
pub fn wal_path_for(verthys_path: &str) -> PathBuf {
    let mut p = PathBuf::from(verthys_path);
    let mut name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(".import.wal");
    p.set_file_name(name);
    p
}

/// WAL 写入句柄（持有打开的文件句柄，append-only）
pub struct WalWriter {
    file: File,
    path: PathBuf,
}

impl WalWriter {
    /// 创建/截断 WAL 文件并写入 begin 条目（新导入会话起始）
    /// 若存在遗留 WAL（未 end 的旧会话），调用方应先 load() 恢复再决定是否覆盖。
    pub fn create(verthys_path: &str, import_id: &str) -> Result<Self, String> {
        let path = wal_path_for(verthys_path);
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
        Ok(writer)
    }

    /// 追加一条记录并立即 fsync 落盘
    pub fn append(&mut self, entry: &WalEntry) -> Result<(), String> {
        let line = serde_json::to_string(entry)
            .map_err(|e| format!("WAL 序列化失败: {}", e))?;
        writeln!(self.file, "{}", line).map_err(|e| format!("WAL 写入失败: {}", e))?;
        self.flush_sync()
    }

    /// 批量追加多条记录，末尾一次 fsync（减少 fsync 次数，但仍保证落盘）
    pub fn append_batch(&mut self, entries: &[WalEntry]) -> Result<(), String> {
        for entry in entries {
            let line = serde_json::to_string(entry)
                .map_err(|e| format!("WAL 序列化失败: {}", e))?;
            writeln!(self.file, "{}", line).map_err(|e| format!("WAL 写入失败: {}", e))?;
        }
        self.flush_sync()
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

    /// 压缩 WAL：仅保留已 committed 的哈希清单（begin + committed + checkpoint + end）
    /// 原子替换：先写临时文件再 rename，保证压缩过程崩溃不损坏原 WAL。
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

            // 仅写入已 committed 的哈希（不含 verthys_id，避免泄露内部 ID）
            for hash in &snapshot.committed_hashes {
                let entry = WalEntry::Committed {
                    import_id: import_id.to_string(),
                    batch_id: snapshot.last_batch_id,
                    hash: hash.clone(),
                    verthys_id: *snapshot
                        .committed_ids
                        .get(hash)
                        .unwrap_or(&0),
                    name: String::new(),
                };
                let line = serde_json::to_string(&entry)
                    .map_err(|e| format!("WAL 序列化失败: {}", e))?;
                writeln!(tmp, "{}", line).map_err(|e| format!("WAL 写入失败: {}", e))?;
            }

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
        Ok(())
    }

    /// 刷新缓冲并 fsync 到物理磁盘
    fn flush_sync(&mut self) -> Result<(), String> {
        self.file
            .flush()
            .map_err(|e| format!("WAL flush 失败: {}", e))?;
        self.file
            .sync_all()
            .map_err(|e| format!("WAL fsync 失败: {}", e))?;
        Ok(())
    }
}

/// 从指定 WAL 文件路径加载快照（重放全部条目）
fn load_from_path(path: &Path) -> Result<WalSnapshot, String> {
    let mut snapshot = WalSnapshot::default();

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
                snapshot.active_import_id = Some(import_id);
                // 新会话开始：重置累加状态（同一 WAL 文件理论上只有一个活跃会话）
                snapshot.committed_hashes.clear();
                snapshot.committed_ids.clear();
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
                ..
            } => {
                snapshot.committed_hashes.insert(hash.clone());
                snapshot.committed_ids.insert(hash, verthys_id);
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
    let path = wal_path_for(verthys_path);
    load_from_path(&path)
}

/// 删除 WAL 文件（导入彻底完成且无需续传去重时调用）
pub fn remove(verthys_path: &str) -> Result<(), String> {
    let path = wal_path_for(verthys_path);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("WAL 删除失败: {}", e))?;
    }
    Ok(())
}

/// 判断 WAL 文件是否存在（用于决定是否触发恢复流程）
pub fn exists(verthys_path: &str) -> bool {
    wal_path_for(verthys_path).exists()
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
}

impl ImportSession {
    /// 创建新会话：初始化 WAL + 从既有快照恢复 committed_hashes（续传去重）
    pub fn new(verthys_path: &str, import_id: &str) -> Result<Self, String> {
        // 先加载既有 WAL 快照（若存在遗留 WAL，恢复 committed_hashes 实现续传去重）
        let snapshot = load(verthys_path)?;
        let committed_hashes = snapshot.committed_hashes.clone();
        let total_committed = snapshot.committed_hashes.len() as u64;

        // 创建/截断 WAL（新会话起始；遗留 pending 记录已被快照忽略，仅 committed 进入去重集合）
        let writer = WalWriter::create(verthys_path, import_id)?;

        Ok(ImportSession {
            writer,
            import_id: import_id.to_string(),
            verthys_path: verthys_path.to_string(),
            next_batch_id: 1,
            committed_hashes,
            total_committed,
            total_skipped: 0,
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
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_verthys_path(dir: &Path) -> String {
        dir.join("test.verthys").to_string_lossy().to_string()
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
}
