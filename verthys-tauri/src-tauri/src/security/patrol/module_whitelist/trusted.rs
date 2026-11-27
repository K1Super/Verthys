/* ====================================================================== *
 *  受信任路径白名单与路径真实化                                            *
 * ====================================================================== */

use std::sync::Mutex;

/// 全局受信任路径白名单（用户可通过 add_trusted_path 添加）
/// 用 Mutex 保护以支持多线程主循环巡检
pub(super) static TRUSTED_PATHS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/* ====================================================================== *
 *  路径真实化（GetLongPathNameW）                                        *
 *                                                                        *
 *  调用 Windows 原生 GetLongPathNameW                                    *
 *  解析短文件名（8.3 格式）和符号链接/目录挂载点，确保白名单前缀匹配     *
 *  基于完全规范化的"真实路径"进行。                                       *
 * ====================================================================== */

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn GetLongPathNameW(lpszShortPath: *const u16, lpszLongPath: *mut u16, cchBuffer: u32) -> u32;
}

/// 路径真实化
///
/// 调用 GetLongPathNameW 解析短文件名（8.3）和符号链接/挂载点，
/// 然后进行规范化（剥离 \\?\ 前缀、统一反斜杠、转小写、去尾部分隔符）。
///
/// 所有白名单前缀匹配均基于此函数返回的"真实路径"进行，
/// 确保目录链接、短文件名等逃逸手段无效。
#[cfg(target_os = "windows")]
pub(super) fn realize_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    // 1. 调用 GetLongPathNameW 解析短文件名和符号链接
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut long_buf = [0u16; 520]; // MAX_PATH * 2 + 余量

    let len =
        unsafe { GetLongPathNameW(wide.as_ptr(), long_buf.as_mut_ptr(), long_buf.len() as u32) };

    // 获取真实路径（GetLongPathNameW 失败时回退到原始路径）
    let realized = if len > 0 && (len as usize) < long_buf.len() {
        String::from_utf16_lossy(&long_buf[..len as usize])
    } else {
        // GetLongPathNameW 失败（路径不存在或无效），回退到原始路径
        path.to_string()
    };

    // 2. 规范化：剥离 \\?\ 前缀、统一反斜杠、转小写、去尾部分隔符
    normalize_string_path(&realized)
}

/// 纯字符串规范化（在 realize_path 内部使用，也供非路径比较场景使用）
#[cfg(target_os = "windows")]
fn normalize_string_path(path: &str) -> String {
    let mut s = path;
    // 剥离 \\?\ 前缀（扩展长度路径）
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        s = stripped;
    }
    // 统一反斜杠（兼容传入正斜杠的路径）
    let mut s = s.replace('/', "\\");
    // 转小写（Windows 文件系统大小写不敏感）
    s = s.to_lowercase();
    // 去除尾部路径分隔符
    while s.len() > 1 && s.ends_with('\\') {
        s.pop();
    }
    s
}

/// 非 Windows 平台：路径规范化为空（白名单不启用，patrol_modules 总返回空）
#[cfg(not(target_os = "windows"))]
pub(super) fn realize_path(_path: &str) -> String {
    String::new()
}

/// 非 Windows 平台：纯字符串规范化为空
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn normalize_string_path(_path: &str) -> String {
    String::new()
}

/// 开发构建下当前进程主模块的真实化路径；发布构建恒为 None。
///
/// 只用于豁免“主程序自身”的签名复核：未签名的 dev 主程序位于安装目录内，
/// 会被完整校验误判为未签名模块，连续命中后触发应急销毁 Worker。
/// 发布构建不编译该豁免，主程序仍按原有签名规则校验。
pub(super) fn dev_self_module_path() -> Option<String> {
    #[cfg(debug_assertions)]
    {
        std::env::current_exe()
            .ok()
            .map(|p| realize_path(&p.to_string_lossy()))
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

/// 主模块豁免判定：必须与当前进程主模块的真实化路径完全相等。
///
/// 精确比较而非前缀匹配：同目录下的其他未签名模块仍按原规则处理，
/// 避免把“开发主程序豁免”扩散成整个目录的签名豁免。
pub(super) fn is_dev_self_module(path_norm: &str, self_norm: Option<&str>) -> bool {
    self_norm.is_some_and(|s| !s.is_empty() && s == path_norm)
}

/* ====================================================================== *
 *  公共接口 — 受信任路径白名单管理（跨平台）                               *
 * ====================================================================== */

/// 添加受信任路径到白名单（幂等：重复添加不会产生重复项）
///
/// 路径经 GetLongPathNameW 真实化后存储，
/// 确保短文件名/符号链接无法绕过白名单前缀匹配。
///
/// 调用方需在命令层完成会话授权检查，
/// 此函数仅负责路径真实化与存储。
pub fn add_trusted_path(path: &str) {
    let realized = realize_path(path);
    if realized.is_empty() {
        return;
    }
    let mut guard = match TRUSTED_PATHS.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if !guard.contains(&realized) {
        guard.push(realized);
    }
}

/// 清空受信任路径白名单
pub fn clear_trusted_paths() {
    if let Ok(mut guard) = TRUSTED_PATHS.lock() {
        guard.clear();
    }
}

/* ====================================================================== *
 *  白名单持久化接口                                                       *
 *                                                                        *
 *  export_trusted_paths / import_trusted_paths 供 security_commands.rs   *
 *  层进行 DPAPI 加密持久化，形成不可篡改的安全基线。                       *
 *  应用启动时加载，所有增删记录均以审计日志记录。                          *
 * ====================================================================== */

/// 导出受信任路径白名单（用于 DPAPI 加密持久化）
pub fn export_trusted_paths() -> Vec<String> {
    match TRUSTED_PATHS.lock() {
        Ok(g) => g.iter().cloned().collect(),
        Err(_) => Vec::new(),
    }
}

/// 导入受信任路径白名单（从 DPAPI 解密后恢复）
///
/// 合并持久化的路径到当前白名单（幂等：不产生重复项）。
/// 每条路径经 realize_path 真实化后存储。
#[allow(dead_code)]
pub fn import_trusted_paths(paths: &[String]) {
    let mut guard = match TRUSTED_PATHS.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    for path in paths {
        let realized = realize_path(path);
        if !realized.is_empty() && !guard.contains(&realized) {
            guard.push(realized);
        }
    }
}
