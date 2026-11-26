//! WAL 写入句柄与压缩

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use crate::repository::container_layout;

use super::wal_io::{now_ms, write_snapshot_file};
use super::wal_recovery::load_from_path;
use super::wal_types::WalEntry;

/// WAL 写入句柄（持有打开的文件句柄，append-only）
pub struct WalWriter {
    file: File,
    path: PathBuf,
}

impl WalWriter {
    /// 创建/截断 WAL 文件并写入 begin 条目（新导入会话起始）
    /// 若存在遗留 WAL（未 end 的旧会话），调用方应先 load() 恢复再决定是否覆盖。
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
        // success=true：保留 WAL 供下次去重（committed_keys 仍需可恢复），
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
                committed_count: snapshot.committed_keys.len() as u64,
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
