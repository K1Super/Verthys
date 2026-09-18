/*
 * util/sandbox.rs — 路径沙箱白名单校验模块
 *
 *    "" 第 3.1 项 / 第 6.1 项 / 第 3.8 项
 *
 * 架构定位：工具层（util）路径安全模块
 *   - 不依赖任何上层模块（controller / service / repository）
 *   - 依赖 util::path（validate_path_input / canonicalize_strict / is_within_whitelist）
 *   - 提供 PathSandbox 白名单容器 + resolve_and_validate 高层接口
 *
 * 第 3.1 项 — 白名单基目录集合：
 *   定义安全基目录集合（用户数据/应用配置/管理员指定卷），
 *   所有文件操作必须 canonicalize 后以白名单为前缀，阻断目录遍历。
 *
 * 第 6.1 项 — canonicalize 全解析：
 *   resolve_and_validate 内部调用 canonicalize_strict 解析符号链接 + 规范化路径。
 *
 * 第 3.8 项 — 输入硬校验：
 *   resolve_and_validate 先调 validate_path_input 拒绝非法路径，再做 FS 操作。
 *
 * 设计原则：
 *   - 失败即拒绝：路径校验失败立即返回 Err，不执行任何 FS 操作
 *   - 白名单最小化：仅允许必要的基目录，默认拒绝所有其他路径
 *   - canonicalize 优先：先解析符号链接再比较前缀，防止 symlink bypass
 *   - 白名单基目录自身也 canonicalize：避免白名单路径被 symlink 绕过
 *
 * CI 红线：
 *   - 本文件不得包含任何 println!/eprintln!/log::* 调用
 *   - 白名单基目录在应用启动时确定，运行时不可修改（防注入）
 *   - 所有错误经 Result 传播，不静默降级
 */

use std::path::{Path, PathBuf};

use crate::util::path::{is_within_whitelist, validate_path_input, PathValidationError};

// ===== PathSandbox 白名单容器 =====

/// 路径沙箱白名单容器
///
/// 持有一组 canonicalize 后的安全基目录。
/// 所有文件操作路径必须经 validate 后才允许执行。
///
/// 生命周期：
///   - 应用启动时从配置/环境变量构造 PathSandbox
///   - 注入至 AppState 或 Context，随应用生命周期存活
///   - 运行时不可修改（防注入攻击）
///
/// 使用示例：
///   ```rust,ignore
///   let sandbox = PathSandbox::new()
///       .add_base("C:/Users/test/AppData/Local/Verthys")
///       .add_base("D:/VerthysData");
///
///   let validated = sandbox.validate("C:/Users/test/AppData/Local/Verthys/verthys.verthys")?;
///   ```
#[derive(Debug, Clone)]
pub struct PathSandbox {
    /// canonicalize 后的白名单基目录集合
    bases: Vec<PathBuf>,
}

impl PathSandbox {
    /// 创建空白名单
    pub fn new() -> Self {
        PathSandbox { bases: Vec::new() }
    }

    /// 添加白名单基目录
    ///
    /// 基目录会被 canonicalize 后存储。
    /// 不存在的目录跳过（首次运行时用户数据目录可能未创建）。
    pub fn add_base(mut self, base: impl AsRef<Path>) -> Self {
        if let Ok(canon) = std::fs::canonicalize(base.as_ref()) {
            self.bases.push(canon);
        }
        self
    }

    /// 添加白名单基目录（不 canonicalize，调用方保证已规范化）
    ///
    /// 用于白名单基目录尚不存在但路径已知的场景。
    /// 调用方需确保路径为绝对路径且无符号链接。
    pub fn add_base_raw(mut self, base: impl AsRef<Path>) -> Self {
        let path = base.as_ref().to_path_buf();
        if path.is_absolute() {
            self.bases.push(path);
        }
        self
    }

    /// 校验路径是否在白名单内
    ///
    /// 流程：
    ///   1. validate_path_input 字符级校验
    ///   2. canonicalize 解析符号链接
    ///   3. is_within_whitelist 前缀比较
    ///
    /// 返回：
    ///   - Ok(canonical_path): 路径合法且在白名单内
    ///   - Err(SandboxError): 路径非法或不在白名单内
    pub fn validate(&self, path: &str) -> Result<PathBuf, SandboxError> {
        // 1. 字符级校验
        validate_path_input(path).map_err(SandboxError::InvalidPath)?;

        // 2. canonicalize 目标路径
        let canonical = std::fs::canonicalize(path).map_err(|e| SandboxError::ResolveFailed(e.to_string()))?;

        // 3. 白名单前缀校验
        if !is_within_whitelist(&canonical, &self.bases) {
            return Err(SandboxError::NotInWhitelist);
        }

        Ok(canonical)
    }

    /// 获取白名单基目录数量
    pub fn base_count(&self) -> usize {
        self.bases.len()
    }

    /// 获取白名单基目录引用（只读）
    pub fn bases(&self) -> &[PathBuf] {
        &self.bases
    }
}

impl Default for PathSandbox {
    fn default() -> Self {
        Self::new()
    }
}

// ===== SandboxError 错误类型 =====

/// 沙箱校验错误
#[derive(Debug, Clone)]
pub enum SandboxError {
    /// 路径输入非法（字符级校验失败）
    InvalidPath(PathValidationError),
    /// 路径解析失败（canonicalize 失败，如文件不存在）
    ResolveFailed(String),
    /// 路径不在白名单内
    NotInWhitelist,
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::InvalidPath(e) => write!(f, "路径校验失败: {}", e),
            SandboxError::ResolveFailed(msg) => write!(f, "路径解析失败: {}", msg),
            SandboxError::NotInWhitelist => write!(f, "路径不在白名单基目录内"),
        }
    }
}

impl std::error::Error for SandboxError {}

// ===== 便捷函数：一次性校验 =====

/// 一次性校验路径合法性 + 白名单前缀
///
/// 等价于 PathSandbox::validate 但无需构造 PathSandbox 实例。
/// 适用于单次校验场景。频繁校验建议复用 PathSandbox 实例。
///
/// 参数：
///   - path: 待校验的路径（原始字符串）
///   - whitelist: 白名单基目录集合（字符串切片）
///
/// 返回：
///   - Ok(canonical_path): 路径合法且在白名单内
///   - Err(msg): 路径非法或不在白名单内
pub fn resolve_and_validate(path: &str, whitelist: &[&str]) -> Result<PathBuf, String> {
    // 1. 字符级校验
    validate_path_input(path).map_err(|e| format!("路径校验失败: {}", e))?;

    // 2. canonicalize 目标路径
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| format!("路径解析失败: {}", e))?;

    // 3. canonicalize 白名单基目录
    let mut canonical_whitelist = Vec::with_capacity(whitelist.len());
    for base in whitelist {
        // 白名单基目录可能不存在（首次运行时用户数据目录未创建），
        // 此时跳过该基目录的 canonicalize
        if let Ok(canon_base) = std::fs::canonicalize(base) {
            canonical_whitelist.push(canon_base);
        }
    }

    // 4. 前缀校验
    if !is_within_whitelist(&canonical, &canonical_whitelist) {
        return Err("路径不在白名单基目录内".into());
    }

    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_empty() {
        let sandbox = PathSandbox::new();
        assert_eq!(sandbox.base_count(), 0);
    }

    #[test]
    fn test_sandbox_add_base_raw() {
        let sandbox = PathSandbox::new()
            .add_base_raw("C:/Users/test/data")
            .add_base_raw("D:/VerthysData");
        assert_eq!(sandbox.base_count(), 2);
    }

    #[test]
    fn test_resolve_and_validate_rejects_relative() {
        let result = resolve_and_validate("relative/path", &["C:/safe"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("路径校验失败"));
    }

    #[test]
    fn test_resolve_and_validate_rejects_parent_dir() {
        let result = resolve_and_validate("C:/safe/../../../etc/passwd", &["C:/safe"]);
        assert!(result.is_err());
    }
}
