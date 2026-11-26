/*
 * 用户授权路径守卫
 *
 * 职责边界：系统关键目录前缀表与比较归一化、关键目录判定，以及写入目标
 * 解析（字符级校验 + canonicalize + 关键目录拒绝）。读取、统计、写入与
 * 磁盘查询共用同一条路径校验链。
 */

use crate::controller::api_error::ErrorCode;
use crate::util::path::sanitize_path;
use std::path::PathBuf;

/// 系统关键目录前缀列表（canonicalize 后规范化为小写 + 正斜杠比较）。
///
/// 用户对话框选择的文件跳过白名单，但仍须拒绝系统关键目录，
/// 防止应用读取/覆盖系统敏感文件（如 C:\Windows\System32\config\SAM）。
#[cfg(windows)]
const SYSTEM_CRITICAL_PREFIXES: &[&str] = &[
    "c:/windows",
    "c:/program files",
    "c:/program files (x86)",
    "c:/programdata",
    "c:/system volume information",
    "c:/$recycle.bin",
    "c:/boot",
    "c:/recovery",
    "c:/drivers",
    "c:/intel",
    "c:/perflogs",
];

#[cfg(not(windows))]
const SYSTEM_CRITICAL_PREFIXES: &[&str] = &[
    "/etc",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/root",
    "/var/log",
];

/// 比较形态归一化：小写 + 正斜杠，并剥离 Windows verbatim/device 前缀。
///
/// `std::fs::canonicalize` 在 Windows 上返回 `\\?\C:\...` 形式的 verbatim
/// 路径；设备路径为 `\\.\C:\...`；UNC verbatim 为 `\\?\UNC\server\share`。
/// 不剥离这些前缀时，前缀表永远无法命中，系统目录保护会整体失效。
fn normalize_compare_path(raw: &str) -> String {
    let lowered = raw.to_lowercase().replace('\\', "/");
    let mut rest = lowered.as_str();
    if let Some(stripped) = rest.strip_prefix("//?/") {
        rest = stripped;
    } else if let Some(stripped) = rest.strip_prefix("//./") {
        rest = stripped;
    }
    let normalized = match rest.strip_prefix("unc/") {
        Some(unc) => format!("//{}", unc),
        None => rest.to_string(),
    };
    normalized.trim_end_matches('/').to_string()
}

/// 系统关键目录前缀（静态表 + 环境变量推导）。
///
/// 静态表固定为 C 盘常见路径；实际系统盘或 Program Files 位置可能不同，
/// 因此以 SystemRoot / ProgramFiles / ProgramFiles(x86) / ProgramData
/// 环境变量补充，避免非 C 盘安装时保护失效。
fn critical_path_prefixes() -> &'static [String] {
    static CACHE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let mut prefixes: Vec<String> = SYSTEM_CRITICAL_PREFIXES
            .iter()
            .map(|prefix| (*prefix).to_string())
            .collect();
        #[cfg(windows)]
        for key in [
            "SystemRoot",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramData",
        ] {
            if let Ok(value) = std::env::var(key) {
                if !value.trim().is_empty() {
                    prefixes.push(value);
                }
            }
        }
        prefixes
            .iter()
            .map(|prefix| normalize_compare_path(prefix))
            .filter(|prefix| !prefix.is_empty())
            .collect()
    })
}

/// 检测 canonicalize 后的路径是否位于系统关键目录内。
///
/// 用于 read_user_file / write_user_file 命令的安全兜底：
/// 用户对话框选择的文件跳过白名单，但仍拒绝系统关键目录。
///
/// 比较方式：路径与前缀均归一化为小写 + 正斜杠并剥离 verbatim 前缀，
/// trim 尾部分隔符后精确匹配或前缀匹配（path 以 base/ 开头）。
pub(crate) fn is_system_critical_path(canonical: &std::path::Path) -> bool {
    let path_str = normalize_compare_path(&canonical.to_string_lossy());

    for prefix in critical_path_prefixes() {
        if path_str == *prefix || path_str.starts_with(&format!("{}/", prefix)) {
            return true;
        }
    }
    false
}

/// 解析用户授权写入目标为规范化绝对路径（原子写入与流式写入共用）。
///
/// 校验链：
///   1. validate_path_input 字符级校验（防路径注入、目录遍历、保留设备名）；
///   2. canonicalize：文件已存在直接解析，不存在则解析父目录并拼接文件名；
///   3. 系统关键目录拒绝（防止覆盖 C:\Windows 等系统文件）。
///
/// `log_tag` 仅用于日志前缀区分调用方，不参与任何语义。
pub(in super::super) fn resolve_user_file_target(
    path: &str,
    log_tag: &str,
) -> Result<PathBuf, String> {
    // 1. 字符级校验
    crate::util::path::validate_path_input(path).map_err(|e| {
        log::warn!(
            "[{}] 路径校验失败: {} | {}",
            log_tag,
            sanitize_path(path),
            e
        );
        ErrorCode::InvalidPath.default_message().to_string()
    })?;

    // 2. 解析目标路径：若文件已存在直接 canonicalize；否则 canonicalize 父目录 + 拼接文件名
    let path_obj = std::path::Path::new(path);
    let canonical = match std::fs::canonicalize(path) {
        // 文件已存在 → canonicalize 成功
        Ok(c) => c,
        // 文件不存在 → canonicalize 父目录 + 拼接文件名
        Err(_) => {
            let parent = path_obj.parent().ok_or_else(|| {
                log::warn!("[{}] 无法解析父目录 | {}", log_tag, sanitize_path(path));
                ErrorCode::InvalidPath.default_message().to_string()
            })?;
            let parent_str = parent.to_str().ok_or_else(|| {
                log::warn!(
                    "[{}] 父目录路径含非 UTF-8 字符 | {}",
                    log_tag,
                    sanitize_path(path)
                );
                ErrorCode::InvalidPath.default_message().to_string()
            })?;
            let parent_canonical = std::fs::canonicalize(parent_str).map_err(|e| {
                log::warn!(
                    "[{}] 父目录解析失败: {} | {}",
                    log_tag,
                    sanitize_path(path),
                    e
                );
                ErrorCode::InvalidPath.default_message().to_string()
            })?;
            let file_name = path_obj.file_name().ok_or_else(|| {
                log::warn!("[{}] 无效文件名 | {}", log_tag, sanitize_path(path));
                ErrorCode::InvalidPath.default_message().to_string()
            })?;
            parent_canonical.join(file_name)
        }
    };

    // 3. 系统关键目录拒绝
    if is_system_critical_path(&canonical) {
        log::warn!(
            "[{}] 拒绝写入系统关键目录: {}",
            log_tag,
            sanitize_path(path)
        );
        return Err(ErrorCode::PermissionDenied.default_message().to_string());
    }

    Ok(canonical)
}
