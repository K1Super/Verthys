/*
 * repository/container_layout.rs — 容器附属数据目录命名契约（单一权威定义）
 *
 * 职责：
 *   定义并派生容器附属数据（sidecar）的落盘路径，杜绝该命名规则在仓储、
 *   安全命令、控制层与 C 层之间重复实现造成的漂移。
 *
 * 命名契约：
 *   附属数据目录 = 容器路径末组件追加 ".d"
 *   目录内文件（短名，身份由目录名承载）：
 *     state.json / preset.json / import.wal / import.wal.snapshot /
 *     import.chunks.json / idx_cache / container.lock
 *
 * 跨语言一致性约束：
 *   idx_cache 与 container.lock 由 C 层生成，其路径构造必须与本模块命中同一文件；
 *   修改任一命名常量必须同步 C 层实现与其契约测试，否则温缓存与锁诊断会落到不同位置。
 *   分隔符纪律：派生路径只允许在容器路径之后追加，不改写原字符——Win32 对
 *   `\\?\` / `\\.\` 前缀路径不做正斜杠归一，改写输入会导致容器附属文件不可达。
 *
 * 线程与幂等：
 *   本模块全部为无状态纯函数；仅 ensure_sidecar_dir / migrate_legacy_file /
 *   cleanup_container_sidecars 触达文件系统，三者均按幂等设计，可安全重入。
 *
 * 依赖边界：仅依赖 util::path（仓储层不得反向引用上层模块）。
 */

use std::path::{Path, PathBuf};

use crate::util::path::MAX_PATH;

/// 附属数据目录后缀（追加在完整容器路径之后）
pub const SIDECAR_DIR_SUFFIX: &str = ".d";

/// 目录内文件名：容器状态
pub const FILE_STATE: &str = "state.json";
/// 目录内文件名：安全预设受信配置
pub const FILE_PRESET: &str = "preset.json";
/// 目录内文件名：导入 WAL
pub const FILE_WAL: &str = "import.wal";
/// 目录内文件名：WAL 去重快照
pub const FILE_WAL_SNAPSHOT: &str = "import.wal.snapshot";
/// 目录内文件名：块归属台账
pub const FILE_CHUNK_LEDGER: &str = "import.chunks.json";
/// 目录内文件名：温启动缓存（C 层读写，命名必须与 C 层一致）
pub const FILE_IDX_CACHE: &str = "idx_cache";
/// 目录内文件名：锁持有者诊断旁路（C 层读写，命名必须与 C 层一致）
pub const FILE_CONTAINER_LOCK: &str = "container.lock";

/// 目录内全部文件名（有界清理的删除白名单）
const KNOWN_FILE_NAMES: &[&str] = &[
    FILE_STATE,
    FILE_PRESET,
    FILE_WAL,
    FILE_WAL_SNAPSHOT,
    FILE_CHUNK_LEDGER,
    FILE_IDX_CACHE,
    FILE_CONTAINER_LOCK,
];

/// 派生路径相对容器路径的最长增量（目录后缀 + 分隔符 + 最长文件名）
const MAX_DERIVED_EXTRA: usize = 2 + 1 + 19;

/// 旧布局后缀：容器状态（仅用于只读回退与一次性迁移）
pub const LEGACY_STATE_SUFFIX: &str = ".state";
/// 旧布局后缀：安全预设
pub const LEGACY_PRESET_SUFFIX: &str = ".preset.json";
/// 旧布局后缀：导入 WAL
pub const LEGACY_WAL_SUFFIX: &str = ".import.wal";
/// 旧布局后缀：WAL 去重快照
pub const LEGACY_WAL_SNAPSHOT_SUFFIX: &str = ".import.wal.snapshot";
/// 旧布局后缀：块归属台账
pub const LEGACY_CHUNK_LEDGER_SUFFIX: &str = ".import.chunks.json";
/// 旧布局后缀：温启动缓存
pub const LEGACY_IDX_CACHE_SUFFIX: &str = ".idx_cache";
/// 旧布局后缀：锁诊断旁路
pub const LEGACY_CONTAINER_LOCK_SUFFIX: &str = ".lock";

/// 全部旧布局后缀（清理与迁移的遍历清单）
const LEGACY_SUFFIXES: &[&str] = &[
    LEGACY_STATE_SUFFIX,
    LEGACY_PRESET_SUFFIX,
    LEGACY_WAL_SUFFIX,
    LEGACY_WAL_SNAPSHOT_SUFFIX,
    LEGACY_CHUNK_LEDGER_SUFFIX,
    LEGACY_IDX_CACHE_SUFFIX,
    LEGACY_CONTAINER_LOCK_SUFFIX,
];

/// 有界清理结果（观测用，不参与控制流判定）
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    /// 已删除的附属文件数量（含新布局与旧布局）
    pub removed_files: u32,
    /// 附属目录是否被回收（目录清空后才回收）
    pub removed_dir: bool,
    /// 是否因目录内存在未知文件而保留目录本体
    pub kept_unknown_files: bool,
}

/* ------------------------------------------------------------------ *
 * 路径派生                                                            *
 * ------------------------------------------------------------------ */

/// 在容器路径的最后一个组件之后追加后缀。
///
/// 分隔符与输入保持同一体系，`\\?\` / `\\.\` 长路径前缀原样保留：
/// Win32 对带前缀的路径不做正斜杠归一，混用会导致打开失败，因此
/// 派生路径不得改写输入路径的任何字符，只允许追加。
fn append_to_last_component(verthys_path: &str, suffix: &str) -> PathBuf {
    let mut path = PathBuf::from(verthys_path);
    match path.file_name().map(|s| s.to_os_string()) {
        Some(mut name) => {
            name.push(suffix);
            path.set_file_name(name);
            path
        }
        None => PathBuf::from(format!("{}{}", verthys_path, suffix)),
    }
}

/// 附属数据目录（容器路径末组件追加 `.d`，分隔符随输入原样保留）
pub fn sidecar_dir_for(verthys_path: &str) -> PathBuf {
    append_to_last_component(verthys_path, SIDECAR_DIR_SUFFIX)
}

/// 目录内文件路径构造（附属目录 + 平台原生分隔符 + 文件名）
fn sidecar_file_for(verthys_path: &str, file_name: &str) -> PathBuf {
    sidecar_dir_for(verthys_path).join(file_name)
}

/// 容器状态文件（附属目录内 state.json）
pub fn state_file_for(verthys_path: &str) -> PathBuf {
    sidecar_file_for(verthys_path, FILE_STATE)
}

/// 安全预设受信文件（附属目录内 preset.json）
pub fn preset_file_for(verthys_path: &str) -> PathBuf {
    sidecar_file_for(verthys_path, FILE_PRESET)
}

/// 导入 WAL（附属目录内 import.wal）
pub fn wal_file_for(verthys_path: &str) -> PathBuf {
    sidecar_file_for(verthys_path, FILE_WAL)
}

/// WAL 去重快照（附属目录内 import.wal.snapshot）
pub fn wal_snapshot_file_for(verthys_path: &str) -> PathBuf {
    sidecar_file_for(verthys_path, FILE_WAL_SNAPSHOT)
}

/// 块归属台账（附属目录内 import.chunks.json）
pub fn chunk_ledger_file_for(verthys_path: &str) -> PathBuf {
    sidecar_file_for(verthys_path, FILE_CHUNK_LEDGER)
}

/// 温启动缓存（附属目录内 idx_cache；构造规则必须与 C 层命中同一文件）
pub fn idx_cache_file_for(verthys_path: &str) -> PathBuf {
    sidecar_file_for(verthys_path, FILE_IDX_CACHE)
}

/// 锁诊断旁路（附属目录内 container.lock；构造规则必须与 C 层命中同一文件）
pub fn lock_file_for(verthys_path: &str) -> PathBuf {
    sidecar_file_for(verthys_path, FILE_CONTAINER_LOCK)
}

/// 旧布局文件路径构造：`<容器路径><后缀>`（纯追加，保持旧版行为）
fn legacy_file_for(verthys_path: &str, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{}", verthys_path, suffix))
}

/// 旧布局状态文件：`<容器>.state`
pub fn legacy_state_file_for(verthys_path: &str) -> PathBuf {
    legacy_file_for(verthys_path, LEGACY_STATE_SUFFIX)
}

/// 旧布局预设文件：`<容器>.preset.json`
pub fn legacy_preset_file_for(verthys_path: &str) -> PathBuf {
    legacy_file_for(verthys_path, LEGACY_PRESET_SUFFIX)
}

/// 旧布局 WAL：`<容器>.import.wal`
pub fn legacy_wal_file_for(verthys_path: &str) -> PathBuf {
    legacy_file_for(verthys_path, LEGACY_WAL_SUFFIX)
}

/// 旧布局 WAL 快照：`<容器>.import.wal.snapshot`
pub fn legacy_wal_snapshot_file_for(verthys_path: &str) -> PathBuf {
    legacy_file_for(verthys_path, LEGACY_WAL_SNAPSHOT_SUFFIX)
}

/// 旧布局台账：`<容器>.import.chunks.json`
pub fn legacy_chunk_ledger_file_for(verthys_path: &str) -> PathBuf {
    legacy_file_for(verthys_path, LEGACY_CHUNK_LEDGER_SUFFIX)
}

/// 旧布局温缓存：`<容器>.idx_cache`
pub fn legacy_idx_cache_file_for(verthys_path: &str) -> PathBuf {
    legacy_file_for(verthys_path, LEGACY_IDX_CACHE_SUFFIX)
}

/// 旧布局锁诊断旁路：`<容器>.lock`
pub fn legacy_lock_file_for(verthys_path: &str) -> PathBuf {
    legacy_file_for(verthys_path, LEGACY_CONTAINER_LOCK_SUFFIX)
}

/* ------------------------------------------------------------------ *
 * 目录保障 / 迁移 / 有界清理                                          *
 * ------------------------------------------------------------------ */

/// 确保附属数据目录存在。
///
/// 语义：
///   - 目录不存在：创建（父目录即容器所在目录，须已存在）；
///   - 目录已存在且为目录：复用（幂等）；
///   - 路径被同名文件占用：返回明确错误，由调用方决定拒绝或降级；
///   - 派生路径超出 MAX_PATH：返回明确错误（长路径前缀 `\\?\` / `\\.\` 不受限）。
///
/// 长度口径：按容器路径的 UTF-8 字节数 + {@link MAX_DERIVED_EXTRA} 判定，
/// 与 {@code util::path::validate_path_input} 的字节口径一致（含多字节字符时偏保守）。
///
/// 返回：附属数据目录路径。
pub fn ensure_sidecar_dir(verthys_path: &str) -> Result<PathBuf, String> {
    let dir = sidecar_dir_for(verthys_path);
    let has_long_path_prefix =
        verthys_path.starts_with(r"\\?\") || verthys_path.starts_with(r"\\.\");
    if !has_long_path_prefix && verthys_path.len() + MAX_DERIVED_EXTRA > MAX_PATH {
        return Err(format!(
            "附属数据目录路径过长（超过 {} 字符），请缩短容器路径后重试",
            MAX_PATH
        ));
    }
    match std::fs::create_dir(&dir) {
        Ok(()) => Ok(dir),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if dir.is_dir() {
                Ok(dir)
            } else {
                Err("附属数据目录被同名文件占用".to_string())
            }
        }
        Err(e) => Err(format!("创建附属数据目录失败: {}", e)),
    }
}

/// 将旧布局文件原子迁移到新布局。
///
/// 幂等语义：
///   - 旧文件不存在 → Ok（无需迁移）；
///   - 目标已存在 → 旧文件为被取代的遗留副本，best-effort 删除后 Ok；
///   - 其余情况：确保目录存在后 rename；失败返回 Err 且不改动旧文件
///     （调用方保持读取旧位置，下次访问自动重试）。
///
/// 并发：同目录 rename 为原子操作；并发调用下的失败方按"已迁移"语义重读目标路径。
pub fn migrate_legacy_file(legacy: &Path, primary: &Path) -> Result<(), String> {
    if !legacy.exists() {
        return Ok(());
    }
    if let Some(parent) = primary.parent() {
        // 相对路径（父组件为空）无需建目录：目标与旧文件同处当前目录
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("创建附属数据目录失败 [{}]: {}", parent.display(), e))?;
        }
    }
    if primary.exists() {
        let _ = std::fs::remove_file(legacy);
        return Ok(());
    }
    std::fs::rename(legacy, primary).map_err(|e| {
        format!(
            "附属文件迁移失败 [{}] → [{}]: {}",
            legacy.display(),
            primary.display(),
            e
        )
    })
}

/// 目录为空时回收目录本体；非空或其他异常返回 false。
pub fn remove_dir_if_empty(dir: &Path) -> bool {
    std::fs::remove_dir(dir).is_ok()
}

/// 判断目录项是否为已知附属文件或其临时文件。
///
/// 临时文件判定：以已知文件名 + "." 为前缀且以 ".tmp" 结尾，
/// 覆盖 `state.json.tmp` 与 `preset.json.<pid>.<seq>.tmp` 两类命名。
fn is_known_sidecar_entry(name: &str) -> bool {
    if KNOWN_FILE_NAMES.contains(&name) {
        return true;
    }
    if !name.ends_with(".tmp") {
        return false;
    }
    KNOWN_FILE_NAMES
        .iter()
        .any(|known| name.starts_with(&format!("{}.", known)))
}

/// 有界清理容器附属数据（创建回滚与残留回收共用）。
///
/// 删除范围严格限定：
///   1. 附属目录内：已知附属文件及其 `.tmp` 临时文件；
///   2. 容器同级：已知旧布局文件及其 `.tmp` 临时文件；
///   3. 清理后目录若为空则回收目录本体。
///
/// 安全边界：目录内存在未知文件时只删已知文件、保留目录本体，绝不递归删除
/// 未知内容（防误删用户数据）。全部删除为 best-effort，失败不中断流程。
pub fn cleanup_container_sidecars(verthys_path: &str) -> CleanupReport {
    let mut report = CleanupReport::default();
    let dir = sidecar_dir_for(verthys_path);

    if dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if is_known_sidecar_entry(&name) {
                    if std::fs::remove_file(entry.path()).is_ok() {
                        report.removed_files += 1;
                    }
                } else {
                    report.kept_unknown_files = true;
                }
            }
        }
        if !report.kept_unknown_files && remove_dir_if_empty(&dir) {
            report.removed_dir = true;
        }
    }

    // 旧布局残留：仅删除"容器文件名 + 已知后缀"派生的文件与其 .tmp 临时文件，
    // 其余同名前缀文件一律不动（避免误删用户自建备份）。
    let container_path = Path::new(verthys_path);
    if let Some(container_name) = container_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
    {
        let container_name = format!("{}.", container_name);
        if let Some(parent) = container_path.parent() {
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if !name.starts_with(&container_name) {
                        continue;
                    }
                    let rest = &name[container_name.len()..];
                    let matched = LEGACY_SUFFIXES.iter().any(|suffix| {
                        rest == &suffix[1..]
                            || (rest.starts_with(&format!("{}.", &suffix[1..]))
                                && rest.ends_with(".tmp"))
                    });
                    if matched && std::fs::remove_file(entry.path()).is_ok() {
                        report.removed_files += 1;
                    }
                }
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn container_in(dir: &Path, name: &str) -> String {
        dir.join(name).to_string_lossy().replace('\\', "/")
    }

    /// 归一化为正斜杠：派生路径保留输入分隔符体系，断言前先归一
    fn norm(p: &Path) -> String {
        p.to_string_lossy().replace('\\', "/")
    }

    #[test]
    fn test_sidecar_dir_and_file_mapping() {
        let p = "D:/data/Vault.verthys";
        assert_eq!(norm(&sidecar_dir_for(p)), "D:/data/Vault.verthys.d");
        assert_eq!(norm(&state_file_for(p)), "D:/data/Vault.verthys.d/state.json");
        assert_eq!(
            norm(&preset_file_for(p)),
            "D:/data/Vault.verthys.d/preset.json"
        );
        assert_eq!(norm(&wal_file_for(p)), "D:/data/Vault.verthys.d/import.wal");
        assert_eq!(
            norm(&wal_snapshot_file_for(p)),
            "D:/data/Vault.verthys.d/import.wal.snapshot"
        );
        assert_eq!(
            norm(&chunk_ledger_file_for(p)),
            "D:/data/Vault.verthys.d/import.chunks.json"
        );
        assert_eq!(norm(&idx_cache_file_for(p)), "D:/data/Vault.verthys.d/idx_cache");
        assert_eq!(
            norm(&lock_file_for(p)),
            "D:/data/Vault.verthys.d/container.lock"
        );
    }

    #[test]
    fn test_legacy_mapping() {
        let p = "D:/data/Vault.verthys";
        assert_eq!(norm(&legacy_state_file_for(p)), "D:/data/Vault.verthys.state");
        assert_eq!(
            norm(&legacy_preset_file_for(p)),
            "D:/data/Vault.verthys.preset.json"
        );
        assert_eq!(
            norm(&legacy_wal_file_for(p)),
            "D:/data/Vault.verthys.import.wal"
        );
        assert_eq!(
            norm(&legacy_wal_snapshot_file_for(p)),
            "D:/data/Vault.verthys.import.wal.snapshot"
        );
        assert_eq!(
            norm(&legacy_chunk_ledger_file_for(p)),
            "D:/data/Vault.verthys.import.chunks.json"
        );
        assert_eq!(
            norm(&legacy_idx_cache_file_for(p)),
            "D:/data/Vault.verthys.idx_cache"
        );
        assert_eq!(norm(&legacy_lock_file_for(p)), "D:/data/Vault.verthys.lock");
    }

    #[test]
    fn test_backslash_path_keeps_native_separator() {
        let p = r"D:\data\Vault.verthys";
        // 原生分隔符保留：反斜杠输入不得被改写成正斜杠（长路径前缀纪律同源）
        assert_eq!(
            sidecar_dir_for(p).to_string_lossy(),
            r"D:\data\Vault.verthys.d"
        );
        assert_eq!(
            state_file_for(p).to_string_lossy(),
            r"D:\data\Vault.verthys.d\state.json"
        );
        assert_eq!(norm(&state_file_for(p)), "D:/data/Vault.verthys.d/state.json");
    }

    #[test]
    fn test_long_path_prefix_preserved() {
        let p = r"\\?\D:\very-long\Vault.verthys";
        let dir = sidecar_dir_for(p).to_string_lossy().to_string();
        assert!(dir.starts_with(r"\\?\"), "长路径前缀必须保留: {}", dir);
        assert!(
            !dir[r"\\?\".len()..].contains('/'),
            "前缀之后不得混入正斜杠: {}",
            dir
        );
        assert!(dir.ends_with(r"Vault.verthys.d"), "{}", dir);

        let file = state_file_for(p).to_string_lossy().to_string();
        assert!(file.starts_with(r"\\?\"), "{}", file);
        assert!(
            !file[r"\\?\".len()..].contains('/'),
            "前缀之后不得混入正斜杠: {}",
            file
        );
        assert!(file.ends_with(r"Vault.verthys.d\state.json"), "{}", file);
    }

    #[test]
    fn test_ensure_sidecar_dir_idempotent() {
        let dir = tempdir().unwrap();
        let p = container_in(dir.path(), "Vault.verthys");
        let first = ensure_sidecar_dir(&p).expect("首次创建应成功");
        assert!(first.is_dir());
        let second = ensure_sidecar_dir(&p).expect("重复调用应幂等成功");
        assert_eq!(first, second);
    }

    #[test]
    fn test_ensure_sidecar_dir_rejects_file_occupation() {
        let dir = tempdir().unwrap();
        let p = container_in(dir.path(), "Vault.verthys");
        std::fs::write(sidecar_dir_for(&p), b"occupied").unwrap();
        let result = ensure_sidecar_dir(&p);
        assert!(result.is_err(), "同名文件占用时必须明确拒绝");
    }

    #[test]
    fn test_ensure_sidecar_dir_rejects_overlong_path() {
        let long_name = "a".repeat(240);
        let p = format!("C:/{} Vault.verthys", long_name);
        let result = ensure_sidecar_dir(&p);
        assert!(result.is_err(), "派生路径超长必须明确拒绝");
        assert!(
            result.unwrap_err().contains("路径过长"),
            "超长拒绝必须给出明确原因"
        );
    }

    #[test]
    fn test_ensure_sidecar_dir_skips_length_limit_for_long_path_prefix() {
        // 长路径前缀（\\?\）不受 MAX_PATH 限制：错误必须来自创建失败而非长度门
        let long_name = "a".repeat(300);
        let p = format!(r"\\?\Z:\{}\Vault.verthys", long_name);
        let err = ensure_sidecar_dir(&p).unwrap_err();
        assert!(
            !err.contains("路径过长"),
            "带长路径前缀时不得命中 MAX_PATH 门: {}",
            err
        );
    }

    #[test]
    fn test_ensure_sidecar_dir_length_boundary() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_string_lossy().replace('\\', "/");
        let allowed = MAX_PATH - MAX_DERIVED_EXTRA;
        let pad = allowed - base.len() - 1 - ".verthys".len();

        // 恰好等于阈值：必须放行（进入创建阶段）
        let p_ok = format!("{}/{}.verthys", base, "a".repeat(pad));
        assert_eq!(p_ok.len(), allowed);
        assert!(ensure_sidecar_dir(&p_ok).is_ok(), "阈值内路径必须放行");

        // 超出 1 字节：必须命中长度门
        let p_over = format!("{}/{}.verthys", base, "a".repeat(pad + 1));
        assert_eq!(p_over.len(), allowed + 1);
        let err = ensure_sidecar_dir(&p_over).unwrap_err();
        assert!(err.contains("路径过长"), "越界必须给出长度原因: {}", err);
    }

    #[test]
    fn test_migrate_legacy_missing_source_is_ok() {
        let dir = tempdir().unwrap();
        let p = container_in(dir.path(), "Vault.verthys");
        let legacy = legacy_state_file_for(&p);
        let primary = state_file_for(&p);
        migrate_legacy_file(&legacy, &primary).expect("源缺失应视为无需迁移");
        assert!(!primary.exists());
    }

    #[test]
    fn test_migrate_legacy_moves_file_and_creates_dir() {
        let dir = tempdir().unwrap();
        let p = container_in(dir.path(), "Vault.verthys");
        let legacy = legacy_state_file_for(&p);
        let primary = state_file_for(&p);
        std::fs::write(&legacy, b"payload").unwrap();
        migrate_legacy_file(&legacy, &primary).expect("迁移应成功");
        assert!(!legacy.exists(), "旧文件必须被搬走");
        assert_eq!(std::fs::read(&primary).unwrap(), b"payload");
    }

    #[test]
    fn test_migrate_legacy_superseded_copy_removed() {
        let dir = tempdir().unwrap();
        let p = container_in(dir.path(), "Vault.verthys");
        let legacy = legacy_state_file_for(&p);
        let primary = state_file_for(&p);
        ensure_sidecar_dir(&p).unwrap();
        std::fs::write(&primary, b"new").unwrap();
        std::fs::write(&legacy, b"old").unwrap();
        migrate_legacy_file(&legacy, &primary).expect("已迁移场景应成功");
        assert!(!legacy.exists(), "被取代的旧副本必须回收");
        assert_eq!(std::fs::read(&primary).unwrap(), b"new");
    }

    #[test]
    fn test_cleanup_removes_known_and_keeps_unknown() {
        let dir = tempdir().unwrap();
        let p = container_in(dir.path(), "Vault.verthys");
        let sidecar = sidecar_dir_for(&p);
        std::fs::create_dir_all(&sidecar).unwrap();
        std::fs::write(sidecar.join(FILE_STATE), b"s").unwrap();
        std::fs::write(sidecar.join("state.json.tmp"), b"t").unwrap();
        std::fs::write(sidecar.join("preset.json.123.0.tmp"), b"t").unwrap();
        std::fs::write(sidecar.join(FILE_IDX_CACHE), b"c").unwrap();
        std::fs::write(sidecar.join("user_note.txt"), b"keep").unwrap();
        let legacy = legacy_preset_file_for(&p);
        std::fs::write(&legacy, b"lp").unwrap();

        let report = cleanup_container_sidecars(&p);

        assert!(report.kept_unknown_files, "存在未知文件时必须记录");
        assert!(sidecar.is_dir(), "含未知文件时目录本体必须保留");
        assert!(sidecar.join("user_note.txt").exists());
        assert!(!sidecar.join(FILE_STATE).exists());
        assert!(!sidecar.join(FILE_IDX_CACHE).exists());
        assert!(!legacy.exists(), "旧布局附属文件必须一并回收");
        assert!(report.removed_files >= 4);
    }

    #[test]
    fn test_cleanup_recovers_empty_dir() {
        let dir = tempdir().unwrap();
        let p = container_in(dir.path(), "Vault.verthys");
        let sidecar = sidecar_dir_for(&p);
        std::fs::create_dir_all(&sidecar).unwrap();
        std::fs::write(sidecar.join(FILE_CONTAINER_LOCK), b"pid").unwrap();

        let report = cleanup_container_sidecars(&p);

        assert!(report.removed_dir, "已知文件清空后必须回收目录");
        assert!(!sidecar.exists());
        assert!(!report.kept_unknown_files);
    }

    #[test]
    fn test_cleanup_never_touches_unrelated_tmp_files() {
        let dir = tempdir().unwrap();
        let p = container_in(dir.path(), "Vault.verthys");
        let unrelated = dir.path().join("notes.tmp");
        std::fs::write(&unrelated, b"keep").unwrap();
        let foreign = dir.path().join("Vault.verthys.backup.data");
        std::fs::write(&foreign, b"keep").unwrap();

        let _ = cleanup_container_sidecars(&p);

        assert!(unrelated.exists(), "无关 tmp 文件不得被删除");
        assert!(foreign.exists(), "非已知后缀的容器前缀文件不得被删除");
    }
}