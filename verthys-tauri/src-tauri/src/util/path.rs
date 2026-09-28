/*
 * util/path.rs — 路径处理工具
 *
 *
 *
 * 架构定位：工具层（util）纯函数模块
 *   - 不依赖任何上层模块（controller / service / repository）
 *   - 不持有状态、不执行需要权限的 I/O（canonicalize_strict 除外，需 FS 读）
 *   - 仅对外暴露路径标准化、脱敏、校验接口
 *
 * 输入硬校验：
 *   validate_path_input 拒绝空字节/控制字符/超 MAX_PATH/相对路径/../~，
 *   不通过返回 Err，调用方据此返回 INVALID_PATH 不执行 FS 操作。
 *
 * 白名单基目录：
 *   is_within_whitelist 校验 canonicalize 后的路径是否以白名单基目录为前缀，
 *   阻断目录遍历攻击。
 *
 * canonicalize 全解析：
 *   canonicalize_strict 解析符号链接 + 规范化路径，返回绝对路径。
 *
 * CI 红线：本文件不得包含任何 println!/eprintln!/log::* 调用。
 */

use std::path::{Path, PathBuf};

/// 路径标准化：反斜杠转正斜杠（跨平台适配）。
///
/// 例外：`\\?\` / `\\.\` 前缀路径原样返回——Win32 对带前缀的路径不执行
/// 正斜杠归一，改写会让该路径失效（容器附属数据派生依赖同一纪律）。
pub fn normalize_path(path: &str) -> String {
    if path.starts_with(r"\\?\") || path.starts_with(r"\\.\") {
        return path.to_string();
    }
    path.replace('\\', "/")
}

/// 日志脱敏：隐藏用户路径中的用户名等敏感信息
///
/// 同时覆盖正斜杠与原生反斜杠两种写法（含 `\\?\` 前缀路径的原始形态）。
pub fn sanitize_path(path: &str) -> String {
    let mut sanitized = normalize_path(path);
    for key in ["USERPROFILE", "HOME"] {
        let Ok(home) = std::env::var(key) else {
            continue;
        };
        if home.is_empty() {
            continue;
        }
        let normalized_home = normalize_path(&home);
        if sanitized.contains(&normalized_home) {
            sanitized = sanitized.replace(&normalized_home, "<USER_HOME>");
        } else if sanitized.contains(&home) {
            sanitized = sanitized.replace(&home, "<USER_HOME>");
        }
    }
    sanitized
}

// ===== 路径输入硬校验 =====

/// Windows MAX_PATH 限制（260 字符，含终止符）
///
/// 长路径需 `\\?\` 前缀，本常量用于校验未带前缀的路径长度。
/// 超过 MAX_PATH 的路径直接拒绝。
pub const MAX_PATH: usize = 260;

/// 路径输入校验错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathValidationError {
    /// 路径为空
    Empty,
    /// 包含空字节
    ContainsNull,
    /// 包含控制字符（0x00-0x1F）
    ContainsControlChar,
    /// 路径过长（超过 MAX_PATH）
    TooLong,
    /// 相对路径（未以盘符/根目录开头）
    RelativePath,
    /// 包含 `..` 目录遍历
    ContainsParentDir,
    /// 包含 `~` 家目录展开符
    ContainsHomeTilde,
    /// Windows 保留设备名（CON/PRN/AUX/NUL/COM*/LPT*）
    ReservedDeviceName,
}

impl std::fmt::Display for PathValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathValidationError::Empty => write!(f, "路径为空"),
            PathValidationError::ContainsNull => write!(f, "路径包含空字节"),
            PathValidationError::ContainsControlChar => write!(f, "路径包含控制字符"),
            PathValidationError::TooLong => write!(f, "路径过长（超过 {} 字符）", MAX_PATH),
            PathValidationError::RelativePath => write!(f, "相对路径不允许"),
            PathValidationError::ContainsParentDir => write!(f, "路径包含 .. 目录遍历"),
            PathValidationError::ContainsHomeTilde => write!(f, "路径包含 ~ 家目录展开符"),
            PathValidationError::ReservedDeviceName => write!(f, "Windows 保留设备名"),
        }
    }
}

impl std::error::Error for PathValidationError {}

/// 路径输入硬校验
///
/// 在任何 FS 操作之前调用，拒绝以下非法路径：
///   - 空字符串
///   - 包含空字节（\0）
///   - 包含控制字符（0x00-0x1F）
///   - 超过 MAX_PATH（260 字符，未带 \\?\ 前缀时）
///   - 相对路径（未以盘符 X: 或根目录 \ 开头）
///   - 包含 `..`（目录遍历攻击）
///   - 包含 `~`（家目录展开符，应由应用层解析而非依赖 shell）
///   - Windows 保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9）
///
/// 校验通过返回 Ok(())，否则返回 Err(PathValidationError)。
/// 调用方应据此返回 INVALID_PATH 错误码，不执行任何 FS 操作。
///
/// CI 红线：本函数不执行任何 I/O，仅做字符级校验。
pub fn validate_path_input(path: &str) -> Result<(), PathValidationError> {
    // 1. 空路径
    if path.is_empty() {
        return Err(PathValidationError::Empty);
    }

    // 2. 空字节
    if path.contains('\0') {
        return Err(PathValidationError::ContainsNull);
    }

    // 3. 控制字符（0x00-0x1F）
    if path.bytes().any(|b| b < 0x20) {
        return Err(PathValidationError::ContainsControlChar);
    }

    // 4. 长度校验（带 \\?\ 前缀的长路径允许超过 MAX_PATH）
    let has_long_path_prefix = path.starts_with(r"\\?\") || path.starts_with(r"\\.\");
    if !has_long_path_prefix && path.len() > MAX_PATH {
        return Err(PathValidationError::TooLong);
    }

    // 5. 相对路径校验
    //    Windows: 必须以盘符（X:\）或 UNC（\\）开头
    //    Unix: 必须以 / 开头
    let is_absolute = if cfg!(windows) {
        // 盘符路径：X:\ 或 X:/
        let bytes = path.as_bytes();
        bytes.len() >= 3
            && ((bytes[0] as char).is_ascii_alphabetic())
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
    } else {
        path.starts_with('/')
    };
    if !is_absolute && !has_long_path_prefix {
        return Err(PathValidationError::RelativePath);
    }

    // 6. 目录遍历 `..`
    //    检查路径组件中是否包含 `..`（两种分隔符都参与分割：`\\?\` 前缀路径
    //    保持原生反斜杠，不能被跳过）
    let normalized = normalize_path(path);
    for component in normalized.split(['/', '\\']) {
        if component == ".." {
            return Err(PathValidationError::ContainsParentDir);
        }
    }

    // 7. 家目录展开符 `~`
    //    路径中任何位置出现 `~` 都拒绝（应由应用层解析 HOME 环境变量）
    if normalized.contains('~') {
        return Err(PathValidationError::ContainsHomeTilde);
    }

    // 8. Windows 保留设备名
    if cfg!(windows) && is_reserved_device_name(path) {
        return Err(PathValidationError::ReservedDeviceName);
    }

    Ok(())
}

/// 检测 Windows 保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9）
fn is_reserved_device_name(path: &str) -> bool {
    // 提取路径最后一段的文件名（两种分隔符都参与分割，兼容 `\\?\` 前缀路径）
    let normalized = normalize_path(path);
    let filename = normalized.rsplit(['/', '\\']).next().unwrap_or("");
    // 去除扩展名
    let stem = filename.split('.').next().unwrap_or("");
    let stem_upper = stem.to_uppercase();

    // 检查简单保留名
    if matches!(stem_upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }

    // 检查 COM1-9
    if let Some(suffix) = stem_upper.strip_prefix("COM") {
        if !suffix.is_empty() && suffix.len() <= 2 && suffix.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }

    // 检查 LPT1-9
    if let Some(suffix) = stem_upper.strip_prefix("LPT") {
        if !suffix.is_empty() && suffix.len() <= 2 && suffix.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }

    false
}

// ===== canonicalize 全解析 + 白名单校验 =====

/// canonicalize 全解析
///
/// 调用 std::fs::canonicalize 解析符号链接 + 规范化路径，
/// 返回绝对路径（Windows 上带 `\\?\` 前缀）。
///
/// 与直接调用 std::fs::canonicalize 的区别：
///   - 先调 validate_path_input 做字符级校验，拒绝非法路径
///   - 失败返回结构化错误（PathValidationError 或 IO 错误）
///   - 不直接 panic，所有错误经 Result 传播
///
/// 注意：本函数执行 FS 读操作（解析符号链接），但不写任何文件。
pub fn canonicalize_strict(path: &str) -> Result<PathBuf, String> {
    // 1. 字符级校验（不执行 FS 操作）
    validate_path_input(path).map_err(|e| format!("路径校验失败: {}", e))?;

    // 2. canonicalize 解析符号链接
    let canonical = std::fs::canonicalize(path).map_err(|e| format!("路径解析失败: {}", e))?;

    Ok(canonical)
}

/// 白名单前缀校验
///
/// 校验 canonicalize 后的路径是否以白名单中的任一基目录为前缀。
/// 用于阻断目录遍历攻击（如 /etc/passwd 不在白名单内则拒绝）。
///
/// 参数：
///   - path: 待校验的路径（应先经 canonicalize_strict 解析）
///   - whitelist: 白名单基目录集合（canonicalize 后的绝对路径）
///
/// 返回：
///   - true: 路径在白名单内（安全）
///   - false: 路径不在白名单内（拒绝）
///
/// CI 红线：本函数不执行任何 I/O，仅做字符串前缀比较。
///
/// 比较口径：两侧统一进入「比较形式」——分隔符归一为正斜杠、剥离 `\\?\`
/// 长路径前缀（该前缀不改变路径语义，仅关闭 Win32 路径解析）、去掉尾部分隔符。
/// 仅用于字符串比较，不参与任何文件系统调用；`\\.\` 设备命名空间不剥离（保守拒绝）。
/// 大小写不做折叠（与 canonicalize 返回值口径一致）。
pub fn is_within_whitelist(path: &Path, whitelist: &[PathBuf]) -> bool {
    fn comparison_form(p: &Path) -> String {
        let raw = p.to_string_lossy().replace('\\', "/");
        let stripped = raw.strip_prefix("//?/").unwrap_or(&raw);
        stripped.trim_end_matches('/').to_string()
    }

    let path_str = comparison_form(path);
    for base in whitelist {
        let base_str = comparison_form(base);
        // 精确匹配或为子路径（path 以 base/ 开头）
        if path_str == base_str || path_str.starts_with(&format!("{}/", base_str)) {
            return true;
        }
    }
    false
}

/// 便捷函数：canonicalize + 白名单校验一步完成
///
/// 调用方提供原始路径与白名单基目录（未 canonicalize），
/// 本函数先校验路径合法性，再 canonicalize 路径与白名单，
/// 最后做前缀比较。
///
/// 返回：
///   - Ok(canonical_path): 路径合法且在白名单内
///   - Err(msg): 路径非法或不在白名单内
///
/// 注意：本函数已迁移至 util::sandbox::resolve_and_validate，
/// 此处保留作为薄包装，便于现有调用方平滑迁移。
pub fn resolve_and_validate(path: &str, whitelist: &[&str]) -> Result<PathBuf, String> {
    crate::util::sandbox::resolve_and_validate(path, whitelist)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_path_input_empty() {
        assert_eq!(validate_path_input(""), Err(PathValidationError::Empty));
    }

    #[test]
    fn test_validate_path_input_null_byte() {
        assert_eq!(
            validate_path_input("C:\\path\0evil"),
            Err(PathValidationError::ContainsNull)
        );
    }

    #[test]
    fn test_validate_path_input_control_char() {
        assert_eq!(
            validate_path_input("C:\\path\x01evil"),
            Err(PathValidationError::ContainsControlChar)
        );
    }

    #[test]
    fn test_validate_path_input_parent_dir() {
        assert_eq!(
            validate_path_input("C:\\data\\..\\evil"),
            Err(PathValidationError::ContainsParentDir)
        );
    }

    #[test]
    fn test_validate_path_input_tilde() {
        assert_eq!(
            validate_path_input("C:\\~user\\data"),
            Err(PathValidationError::ContainsHomeTilde)
        );
    }

    #[test]
    fn test_validate_path_input_relative() {
        assert_eq!(
            validate_path_input("relative/path"),
            Err(PathValidationError::RelativePath)
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_validate_path_input_absolute_ok() {
        assert!(validate_path_input("C:\\Users\\test\\data").is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn test_validate_path_input_reserved_device() {
        assert_eq!(
            validate_path_input("C:\\data\\CON.txt"),
            Err(PathValidationError::ReservedDeviceName)
        );
        assert_eq!(
            validate_path_input("C:\\data\\PRN"),
            Err(PathValidationError::ReservedDeviceName)
        );
    }

    #[test]
    fn test_is_within_whitelist() {
        let whitelist = vec![PathBuf::from("C:\\Users\\test\\data")];
        assert!(is_within_whitelist(
            &PathBuf::from("C:\\Users\\test\\data\\file.txt"),
            &whitelist
        ));
        assert!(!is_within_whitelist(
            &PathBuf::from("C:\\Windows\\evil"),
            &whitelist
        ));
    }

    #[test]
    fn test_is_within_whitelist_handles_canonicalized_forms() {
        // canonicalize 结果可能带 \\?\ 前缀并保留反斜杠，必须与原生白名单可比较
        let whitelist = vec![PathBuf::from(r"\\?\C:\Users\test\data")];
        assert!(is_within_whitelist(
            &PathBuf::from(r"\\?\C:\Users\test\data\file.txt"),
            &whitelist
        ));
        assert!(is_within_whitelist(
            &PathBuf::from(r"C:\Users\test\data\file.txt"),
            &whitelist
        ));
        // 驱动器根尾部分隔符（D:\ → D:）不得破坏前缀匹配
        let root = vec![PathBuf::from(r"D:\")];
        assert!(is_within_whitelist(&PathBuf::from(r"D:\"), &root));
        assert!(is_within_whitelist(
            &PathBuf::from(r"\\?\D:\data\file.txt"),
            &root
        ));
        // 相似前缀不得误判通过
        assert!(!is_within_whitelist(
            &PathBuf::from(r"C:\Users\test\data_evil\x"),
            &whitelist
        ));
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("C:\\Users\\test"), "C:/Users/test");
    }

    #[test]
    fn test_normalize_path_preserves_long_path_prefix() {
        // 长路径前缀路径不得被改写（Win32 对其不做正斜杠归一）
        let prefixed = r"\\?\D:\data\Vault.verthys";
        assert_eq!(normalize_path(prefixed), prefixed);
        let device = r"\\.\C:\data\Vault.verthys";
        assert_eq!(normalize_path(device), device);
        assert_eq!(normalize_path(r"D:\data\Vault.verthys"), "D:/data/Vault.verthys");
    }

    #[test]
    #[cfg(windows)]
    fn test_validate_path_input_rejects_parent_dir_in_long_path() {
        assert_eq!(
            validate_path_input(r"\\?\D:\data\..\evil\Vault.verthys"),
            Err(PathValidationError::ContainsParentDir)
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_validate_path_input_reserved_device_in_long_path() {
        assert_eq!(
            validate_path_input(r"\\?\D:\data\CON.txt"),
            Err(PathValidationError::ReservedDeviceName)
        );
    }

    #[test]
    fn test_sanitize_path_redacts_long_path_form() {
        let Ok(home) = std::env::var("USERPROFILE") else {
            return; // 无用户目录环境时跳过（CI 沙箱不强制）
        };
        if home.is_empty() {
            return;
        }
        let prefixed = format!(r"\\?\{}\Vault.verthys", home);
        let sanitized = sanitize_path(&prefixed);
        assert!(
            sanitized.contains("<USER_HOME>"),
            "带前缀路径中的用户目录必须被脱敏: {}",
            sanitized
        );
        let native = format!(r"{}\Vault.verthys", home);
        assert!(sanitize_path(&native).contains("<USER_HOME>"));
    }
}
