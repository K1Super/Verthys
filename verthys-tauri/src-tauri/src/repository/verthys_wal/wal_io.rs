//! WAL 文件与快照文件的路径解析、读写与清理

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::repository::container_layout;

use super::wal_types::{WalSetSnapshot, WalSnapshot};

/// 解析 WAL 数据位置（附属目录）。
pub(super) fn resolve_wal_path(verthys_path: &str) -> PathBuf {
    container_layout::wal_file_for(verthys_path)
}

/// 删除既有文件；不存在视为成功，其余错误上抛。
pub(super) fn remove_file_if_exists(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| format!("{}删除失败: {}", label, e))?;
    }
    Ok(())
}

/// 快照文件路径（WAL 同目录附加后缀）
pub(super) fn snapshot_path_for(wal_path: &Path) -> PathBuf {
    let mut p = wal_path.to_path_buf();
    let mut name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(".snapshot");
    p.set_file_name(name);
    p
}

/// 原子写出快照文件（compacted committed 集合镜像，tmp+rename）
pub(super) fn write_snapshot_file(wal_path: &Path, snapshot: &WalSnapshot) -> Result<(), String> {
    let snap_path = snapshot_path_for(wal_path);
    let mut tmp = snap_path.clone();
    let mut name = tmp
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(".tmp");
    tmp.set_file_name(name);

    let payload = WalSetSnapshot {
        committed_keys: snapshot.committed_keys.iter().cloned().collect(),
        committed_ids: snapshot
            .committed_ids
            .iter()
            .map(|(key, id)| (key.clone(), *id))
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

/// 删除 WAL 文件（导入彻底完成且无需续传去重时调用）
///
/// WAL 及其临时文件清理；快照保留（去重基线仍由快照承载）。
pub fn remove(verthys_path: &str) -> Result<(), String> {
    let primary = container_layout::wal_file_for(verthys_path);
    remove_file_if_exists(&primary, "WAL")?;
    remove_file_if_exists(
        &PathBuf::from(format!("{}.tmp", primary.to_string_lossy())),
        "WAL 临时文件",
    )?;
    Ok(())
}

/// 判断 WAL 文件是否存在（用于决定是否触发恢复流程）
pub fn exists(verthys_path: &str) -> bool {
    container_layout::wal_file_for(verthys_path).exists()
}

/// 当前时刻（Unix 毫秒）
pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
