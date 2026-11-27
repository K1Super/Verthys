/*
 * repository/anchor_scan_store.rs — 回退锚点扫描证据持久化
 *
 * 为什么需要独立存储：
 *   扫描证据必须跨进程、跨扫描轮次保留。只保存在 UI 内存会让“再次扫描”
 *   抹掉其他位置的历史证据，用户无法判断某个锚点是“容器已不存在”还是
 *   “本次没扫到”。本模块按位置保存最近一次成功快照，供上层合并展示。
 *
 * 落盘位置：app_config_dir/.rollback_anchor_scan.json
 * 写入纪律：临时文件 + 原子替换；文件损坏返回 Err，由调用方决定降级，
 *           仓储层不静默吞掉。
 *
 * 安全边界：只保存 UUID 与容器路径，不保存密钥、指纹或容器内容；
 *           路径不进入审计与日志。
 */

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 证据文件版本；版本不匹配按不可用处理，由调用方重建。
///
/// v2：只保留自定义位置与磁盘根；当前/最近容器探针不再持久化。
/// v3：全盘扫描改为 8 层覆盖边界并跳过 AppData；旧证据的截断标记不再适用。
pub const STORE_VERSION: u32 = 3;

const STORE_FILE: &str = ".rollback_anchor_scan.json";
const STORE_TMP_FILE: &str = ".rollback_anchor_scan.json.tmp";

/// 单个 UUID 在一个位置下的路径证据
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StoredScanEntry {
    pub uuid: String,
    pub paths: Vec<String>,
    /// 路径数超过单锚点展示上限，列表不完整；不影响位置遍历完整性。
    #[serde(default)]
    pub capped: bool,
}

/// 单个扫描位置（文件或目录）的最近快照
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StoredScanRoot {
    pub path: String,
    /// "file" / "dir"
    pub kind: String,
    /// "container" / "recent" / "custom" / "volume"
    pub source: String,
    pub available: bool,
    /// 最近一次完整扫描成功的时间（Unix 秒）；0 表示尚未完整成功
    pub last_success_at: u64,
    /// 最近一次尝试扫描的时间（Unix 秒）
    pub last_attempt_at: u64,
    pub files_seen: u64,
    pub matched_count: u64,
    pub permission_errors: u64,
    pub other_errors: u64,
    pub truncated: bool,
    #[serde(default)]
    pub entries: Vec<StoredScanEntry>,
}

impl StoredScanRoot {
    pub fn new(path: &str, kind: &str, source: &str) -> Self {
        Self {
            path: path.to_string(),
            kind: kind.to_string(),
            source: source.to_string(),
            available: true,
            last_success_at: 0,
            last_attempt_at: 0,
            files_seen: 0,
            matched_count: 0,
            permission_errors: 0,
            other_errors: 0,
            truncated: false,
            entries: Vec::new(),
        }
    }
}

/// 扫描证据总库
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanStore {
    pub version: u32,
    /// 最近一次扫描尝试完成时间
    #[serde(default)]
    pub last_pass_at: u64,
    /// 最近一次扫描是否不完整
    #[serde(default)]
    pub last_pass_partial: bool,
    /// 最近一次扫描是否因为预算/错误而截断
    #[serde(default)]
    pub last_pass_truncated: bool,
    #[serde(default)]
    pub last_pass_files_seen: u64,
    #[serde(default)]
    pub last_pass_matched: u64,
    #[serde(default)]
    pub last_pass_permission_errors: u64,
    #[serde(default)]
    pub last_pass_other_errors: u64,
    /// 最近一次扫描时的当前容器路径（比较键）；切换容器后缓存必须失效
    #[serde(default)]
    pub last_pass_container_path: String,
    /// 最近一次扫描因预算未尝试的位置（路径比较键），供快照视图标记
    #[serde(default)]
    pub last_pass_deferred: Vec<String>,
    #[serde(default)]
    pub roots: Vec<StoredScanRoot>,
}

impl Default for ScanStore {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            last_pass_at: 0,
            last_pass_partial: false,
            last_pass_truncated: false,
            last_pass_files_seen: 0,
            last_pass_matched: 0,
            last_pass_permission_errors: 0,
            last_pass_other_errors: 0,
            last_pass_container_path: String::new(),
            last_pass_deferred: Vec::new(),
            roots: Vec::new(),
        }
    }
}

/// 证据文件路径
pub fn store_file(config_dir: &Path) -> PathBuf {
    config_dir.join(STORE_FILE)
}

/// 读取证据库。
///
/// 文件不存在返回空库；读取或解析失败返回 Err，由调用方决定是否按空库重建。
pub fn load(config_dir: &Path) -> Result<ScanStore, String> {
    let path = store_file(config_dir);
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ScanStore::default()),
        Err(e) => return Err(format!("读取扫描证据失败: {}", e)),
    };
    let mut store: ScanStore =
        serde_json::from_str(&content).map_err(|e| format!("解析扫描证据失败: {}", e))?;
    if store.version != STORE_VERSION {
        return Err(format!("扫描证据版本不受支持: {}", store.version));
    }
    store.roots.retain(|root| !root.path.trim().is_empty());
    Ok(store)
}

/// 原子写入证据库（临时文件 + rename）。
pub fn save(config_dir: &Path, store: &ScanStore) -> Result<(), String> {
    fs::create_dir_all(config_dir).map_err(|e| format!("创建扫描证据目录失败: {}", e))?;
    let path = store_file(config_dir);
    let tmp = config_dir.join(STORE_TMP_FILE);
    let content =
        serde_json::to_string_pretty(store).map_err(|e| format!("序列化扫描证据失败: {}", e))?;
    fs::write(&tmp, content).map_err(|e| format!("写入扫描证据临时文件失败: {}", e))?;
    fs::rename(&tmp, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("提交扫描证据失败: {}", e)
    })
}

/// 路径比较键：统一分隔符、去除末尾分隔符、大小写不敏感。
pub fn path_key(path: &str) -> String {
    let mut normalized = path.trim().replace('/', "\\");
    while normalized.len() > 1 && normalized.ends_with('\\') {
        let bytes = normalized.as_bytes();
        let is_drive_root = normalized.len() == 3 && bytes[1] == b':';
        let is_prefixed_drive_root = (normalized.starts_with(r"\\?\")
            || normalized.starts_with(r"\\.\"))
            && normalized.len() == 7
            && bytes[5] == b':';
        if is_drive_root || is_prefixed_drive_root {
            break;
        }
        normalized.pop();
    }
    normalized.to_lowercase()
}

/// 按路径查找位置索引（大小写与分隔符不敏感）。
pub fn find_index(store: &ScanStore, path: &str) -> Option<usize> {
    let key = path_key(path);
    store
        .roots
        .iter()
        .position(|root| path_key(&root.path) == key)
}

/// 取得位置的可变引用；不存在时追加。
/// 已存在的位置保留其原有 source，由调用方按优先级决定是否提升。
pub fn get_or_insert<'a>(
    store: &'a mut ScanStore,
    path: &str,
    kind: &str,
    source: &str,
) -> &'a mut StoredScanRoot {
    if let Some(index) = find_index(store, path) {
        let root = &mut store.roots[index];
        // 扫描目标使用原生分隔符；命中既有路径时同步为当前展示写法。
        root.path = path.to_string();
        root.kind = kind.to_string();
        return root;
    }
    store.roots.push(StoredScanRoot::new(path, kind, source));
    store.roots.last_mut().expect("追加后必然存在")
}

/// 移除自定义位置；非自定义位置不受影响。
pub fn remove_custom(store: &mut ScanStore, path: &str) -> bool {
    let key = path_key(path);
    let before = store.roots.len();
    store
        .roots
        .retain(|root| !(root.source == "custom" && path_key(&root.path) == key));
    store.roots.len() != before
}

/// 清理非持久化来源与已不存在的磁盘根。
///
/// 自定义位置始终保留（由用户显式管理）；当前/最近探针与已移除磁盘的
/// 历史根不得残留，否则容器改名或移动后会展示不可用的旧路径。
pub fn retain_current_roots(
    store: &mut ScanStore,
    volume_keys: &std::collections::HashSet<String>,
) {
    if volume_keys.is_empty() {
        /* 磁盘枚举失败时不能把已有磁盘证据当成失效数据清空；保留等待下轮。 */
        store
            .roots
            .retain(|root| matches!(root.source.as_str(), "custom" | "volume"));
        return;
    }
    store.roots.retain(|root| match root.source.as_str() {
        "custom" => true,
        "volume" => volume_keys.contains(&path_key(&root.path)),
        _ => false,
    });
}

/// 位置数量上限保护：优先淘汰最久未尝试的非自定义位置。
pub fn prune(store: &mut ScanStore, max_roots: usize) {
    if store.roots.len() <= max_roots {
        return;
    }
    let needed = store.roots.len() - max_roots;
    let mut removable: Vec<usize> = store
        .roots
        .iter()
        .enumerate()
        .filter(|(_, root)| root.source != "custom")
        .map(|(index, _)| index)
        .collect();
    removable.sort_by_key(|&index| {
        (
            store.roots[index].last_attempt_at,
            store.roots[index].path.clone(),
        )
    });
    let remove_set: std::collections::HashSet<usize> = removable.into_iter().take(needed).collect();
    let mut index = 0usize;
    store.roots.retain(|_| {
        let keep = !remove_set.contains(&index);
        index += 1;
        keep
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_key_normalizes_separators_case_and_trailing_slash() {
        assert_eq!(
            path_key("D:/Vaults/Vault.verthys"),
            path_key(r"D:\Vaults\Vault.verthys")
        );
        assert_eq!(path_key(r"D:\Vaults\"), r"d:\vaults");
        assert_eq!(path_key(r"D:\"), r"d:\");
        assert_eq!(path_key(r"\\?\D:\"), r"\\?\d:\");
        assert_eq!(
            path_key("  D:/Vaults/Vault.verthys  "),
            r"d:\vaults\vault.verthys"
        );
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut store = ScanStore::default();
        store.roots.push(StoredScanRoot::new(
            r"D:\Vaults\Vault.verthys",
            "file",
            "container",
        ));
        store.roots[0].entries.push(StoredScanEntry {
            uuid: "0123456789abcdef0123456789abcdef".into(),
            paths: vec![r"D:\Vaults\Vault.verthys".into()],
            capped: false,
        });
        store.last_pass_at = 100;

        save(dir.path(), &store).expect("save");
        let loaded = load(dir.path()).expect("load");
        assert_eq!(loaded.last_pass_at, 100);
        assert_eq!(loaded.roots.len(), 1);
        assert_eq!(loaded.roots[0].entries[0].paths.len(), 1);
    }

    #[test]
    fn corrupt_store_returns_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(store_file(dir.path()), b"not-json").expect("write");
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn missing_store_is_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = load(dir.path()).expect("load");
        assert!(store.roots.is_empty());
    }

    #[test]
    fn get_or_insert_matches_case_insensitively() {
        let mut store = ScanStore::default();
        store
            .roots
            .push(StoredScanRoot::new(r"D:\Vaults", "dir", "custom"));
        let root = get_or_insert(&mut store, "d:/vaults/", "dir", "recent");
        assert_eq!(root.source, "custom");
        assert_eq!(store.roots.len(), 1);
    }

    #[test]
    fn remove_custom_never_touches_other_sources() {
        let mut store = ScanStore::default();
        store
            .roots
            .push(StoredScanRoot::new(r"D:\Vaults", "dir", "custom"));
        store
            .roots
            .push(StoredScanRoot::new(r"D:\Vaults", "dir", "recent"));
        assert!(remove_custom(&mut store, r"D:\Vaults"));
        assert_eq!(store.roots.len(), 1);
        assert_eq!(store.roots[0].source, "recent");
        assert!(!remove_custom(&mut store, r"D:\Vaults"));
        assert_eq!(store.roots.len(), 1);
    }

    #[test]
    fn prune_keeps_custom_roots() {
        let mut store = ScanStore::default();
        for index in 0..5 {
            let mut root = StoredScanRoot::new(&format!(r"D:\vol{}", index), "dir", "volume");
            root.last_attempt_at = index;
            store.roots.push(root);
        }
        store
            .roots
            .push(StoredScanRoot::new(r"D:\custom", "dir", "custom"));
        prune(&mut store, 3);
        assert_eq!(store.roots.len(), 3);
        assert!(store.roots.iter().any(|root| root.source == "custom"));
    }

    #[test]
    fn retain_current_roots_drops_stale_probe_and_absent_volume() {
        let mut store = ScanStore::default();
        store.roots.push(StoredScanRoot::new(
            r"C:\Vaults\old.verthys",
            "file",
            "recent",
        ));
        store
            .roots
            .push(StoredScanRoot::new(r"C:\Vaults", "dir", "container"));
        store
            .roots
            .push(StoredScanRoot::new(r"C:\", "dir", "volume"));
        store
            .roots
            .push(StoredScanRoot::new(r"E:\", "dir", "volume"));
        store
            .roots
            .push(StoredScanRoot::new(r"E:\Custom", "dir", "custom"));

        let volumes: std::collections::HashSet<String> = [path_key(r"C:\")].into_iter().collect();
        retain_current_roots(&mut store, &volumes);

        assert_eq!(store.roots.len(), 2);
        assert!(store
            .roots
            .iter()
            .any(|root| root.source == "volume" && root.path == r"C:\"));
        assert!(store
            .roots
            .iter()
            .any(|root| root.source == "custom" && root.path == r"E:\Custom"));
    }

    #[test]
    fn retain_current_roots_keeps_volume_evidence_when_enumeration_is_empty() {
        let mut store = ScanStore::default();
        store
            .roots
            .push(StoredScanRoot::new(r"C:\", "dir", "volume"));
        store.roots.push(StoredScanRoot::new(
            r"C:\Vaults\old.verthys",
            "file",
            "recent",
        ));
        retain_current_roots(&mut store, &std::collections::HashSet::new());
        assert_eq!(store.roots.len(), 1);
        assert_eq!(store.roots[0].source, "volume");
    }

    #[test]
    fn old_store_version_is_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(store_file(dir.path()), br#"{"version":1,"roots":[]}"#).expect("write");
        assert!(load(dir.path()).is_err());
    }
}
