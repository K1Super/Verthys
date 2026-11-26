/*
 * repository/recent_paths.rs — 最近使用的容器路径（锚点扫描范围）
 *
 * 为什么需要记录：
 *   锚点扫描不能只依赖“上次打开的容器”一个位置。应用打开或创建的每个容器
 *   都会登记锚点，记录最近路径可以让维护入口自动覆盖这些位置，而不要求用户
 *   再次手动选择目录。
 *
 * 数据：app_config_dir/.verthys_recent_paths（版本化 JSON，最多 16 条）
 * 纪律：大小写与分隔符归一后去重，最新在前；只保存路径，不保存密钥或
 *       容器内容；写入采用临时文件 + 原子替换。
 */

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::repository::anchor_scan_store::path_key;
use crate::repository::verthys_state::last_path_pointer_file;
use crate::util::path::normalize_path;

/// 最近容器路径上限：覆盖常见多库切换，同时限制扫描范围。
pub const MAX_RECENT_PATHS: usize = 16;

const RECENT_VERSION: u32 = 1;
const RECENT_FILE: &str = ".verthys_recent_paths";
const RECENT_TMP_FILE: &str = ".verthys_recent_paths.tmp";

#[derive(Serialize, Deserialize, Default)]
struct RecentFile {
    version: u32,
    #[serde(default)]
    paths: Vec<String>,
}

fn recent_file(config_dir: &Path) -> PathBuf {
    config_dir.join(RECENT_FILE)
}

fn read_raw(config_dir: &Path) -> Result<Vec<String>, String> {
    let path = recent_file(config_dir);
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("读取最近容器路径失败: {}", e)),
    };
    let file: RecentFile =
        serde_json::from_str(&content).map_err(|e| format!("解析最近容器路径失败: {}", e))?;
    if file.version != RECENT_VERSION {
        return Err(format!("最近容器路径版本不受支持: {}", file.version));
    }
    Ok(sanitize_paths(file.paths))
}

/// 从状态路径指针播种：老用户首次启用最近路径登记时不会从零开始。
pub fn seed_from_last(config_dir: &Path) -> Vec<String> {
    let pointer = last_path_pointer_file(config_dir);
    let Ok(content) = fs::read_to_string(pointer) else {
        return Vec::new();
    };
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    vec![normalize_path(trimmed)]
}

/// 读取最近容器路径；文件为空时用状态路径指针播种。
pub fn load(config_dir: &Path) -> Result<Vec<String>, String> {
    let raw = read_raw(config_dir)?;
    if raw.is_empty() {
        Ok(seed_from_last(config_dir))
    } else {
        Ok(raw)
    }
}

/// 登记一个容器路径；返回是否实际写入。
///
/// 调用方为状态文件写入路径：失败只记录告警，不影响状态落盘。
pub fn record(config_dir: &Path, path: &str) -> Result<bool, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    let normalized = normalize_path(trimmed);
    let key = path_key(&normalized);
    /* 历史路径不是安全状态：文件损坏或不可读时以状态路径指针重新播种，
     * 避免一次损坏让后续扫描永久失去其他历史容器。 */
    let raw = read_raw(config_dir).unwrap_or_default();
    let mut list = if raw.is_empty() {
        seed_from_last(config_dir)
    } else {
        raw.clone()
    };
    list.retain(|item| path_key(item) != key);
    list.insert(0, normalized);
    list.truncate(MAX_RECENT_PATHS);
    if list == raw {
        return Ok(false);
    }
    write(config_dir, &list)?;
    Ok(true)
}

fn sanitize_paths(paths: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in paths {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = normalize_path(trimmed);
        if seen.insert(path_key(&normalized)) {
            out.push(normalized);
            if out.len() >= MAX_RECENT_PATHS {
                break;
            }
        }
    }
    out
}

fn write(config_dir: &Path, paths: &[String]) -> Result<(), String> {
    fs::create_dir_all(config_dir).map_err(|e| format!("创建最近路径目录失败: {}", e))?;
    let content = serde_json::to_string_pretty(&RecentFile {
        version: RECENT_VERSION,
        paths: paths.to_vec(),
    })
    .map_err(|e| format!("序列化最近容器路径失败: {}", e))?;
    let tmp = config_dir.join(RECENT_TMP_FILE);
    fs::write(&tmp, content).map_err(|e| format!("写入最近容器路径临时文件失败: {}", e))?;
    fs::rename(&tmp, recent_file(config_dir)).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("提交最近容器路径失败: {}", e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_last_pointer(dir: &Path, path: &str) {
        fs::write(last_path_pointer_file(dir), path).expect("write pointer");
    }

    #[test]
    fn load_seeds_from_last_path_pointer() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_last_pointer(dir.path(), r"D:\Vaults\Vault.verthys");
        let paths = load(dir.path()).expect("load");
        assert_eq!(paths, vec![r"D:/Vaults/Vault.verthys".to_string()]);
    }

    #[test]
    fn record_keeps_newest_first_and_deduplicates() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_last_pointer(dir.path(), r"D:\Vaults\A.verthys");
        assert!(record(dir.path(), r"D:\Vaults\B.verthys").expect("record b"));
        assert!(record(dir.path(), r"D:\Vaults\A.verthys").expect("record a"));
        let paths = load(dir.path()).expect("load");
        assert_eq!(
            paths,
            vec![
                r"D:/Vaults/A.verthys".to_string(),
                r"D:/Vaults/B.verthys".to_string()
            ]
        );
        assert!(!record(dir.path(), r"D:\Vaults\A.verthys").expect("record duplicate"));
    }

    #[test]
    fn record_caps_recent_paths() {
        let dir = tempfile::tempdir().expect("temp dir");
        for index in 0..(MAX_RECENT_PATHS + 4) {
            record(dir.path(), &format!(r"D:\Vaults\{}.verthys", index)).expect("record");
        }
        let paths = load(dir.path()).expect("load");
        assert_eq!(paths.len(), MAX_RECENT_PATHS);
        assert!(paths[0].ends_with(&format!(r"/{}.verthys", MAX_RECENT_PATHS + 3)));
    }

    #[test]
    fn corrupt_recent_file_returns_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(recent_file(dir.path()), b"not-json").expect("write");
        assert!(load(dir.path()).is_err());
    }
}
