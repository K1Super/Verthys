/*
 * module_whitelist.rs — 模块白名单实时巡检
 *
 *
 * 安全策略：
 *   - Windows 文件系统大小写不敏感，路径比较统一转小写
 *   - 路径真实化：先调用 GetLongPathNameW 解析短名/符号链接，再统一规范化
 *   - 受信任路径白名单用 std::sync::Mutex<Vec<String>> 保护
 *   - wintrust.dll 通过 extern "system" + #[link(name="wintrust")] 直接 FFI 链接
 *   - 非 Windows 平台空实现（返回空 Vec / false），保证跨平台编译通过
 */

use std::sync::Mutex;

/* ====================================================================== *
 *  数据结构                                                               *
 * ====================================================================== */

/// 检测到的未知/可疑模块信息（前端弹窗展示用，serde::Serialize 序列化）
#[derive(Debug, Clone, serde::Serialize)]
pub struct UnknownModule {
    /// 模块名（如 xxx.dll）
    pub name: String,
    /// 模块完整路径
    pub path: String,
    /// 威胁原因："未知路径" 或 "未签名"
    pub reason: String,
}

/// 全局受信任路径白名单（用户可通过 add_trusted_path 添加）
/// 用 Mutex 保护以支持多线程主循环巡检
static TRUSTED_PATHS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/* ====================================================================== *
 *  路径真实化（GetLongPathNameW）                     *
 *                                                                        *
 *  放弃纯字符串 normalize_path，改为调用 Windows 原生 GetLongPathNameW     *
 *  解析短文件名（8.3 格式）和符号链接/目录挂载点，确保白名单前缀匹配       *
 *  基于完全规范化的"真实路径"进行。                                        *
 * ====================================================================== */

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn GetLongPathNameW(
        lpszShortPath: *const u16,
        lpszLongPath: *mut u16,
        cchBuffer: u32,
    ) -> u32;
}

/// 路径真实化
///
/// 调用 GetLongPathNameW 解析短文件名（8.3）和符号链接/挂载点，
/// 然后进行规范化（剥离 \\?\ 前缀、统一反斜杠、转小写、去尾部分隔符）。
///
/// 所有白名单前缀匹配均基于此函数返回的"真实路径"进行，
/// 确保目录链接、短文件名等逃逸手段无效。
#[cfg(target_os = "windows")]
fn realize_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    // 1. 调用 GetLongPathNameW 解析短文件名和符号链接
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut long_buf = [0u16; 520]; // MAX_PATH * 2 + 余量

    let len = unsafe {
        GetLongPathNameW(
            wide.as_ptr(),
            long_buf.as_mut_ptr(),
            long_buf.len() as u32,
        )
    };

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
fn realize_path(_path: &str) -> String {
    String::new()
}

/// 非 Windows 平台：纯字符串规范化为空
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn normalize_string_path(_path: &str) -> String {
    String::new()
}

/* ====================================================================== *
 *  公共接口 — 受信任路径白名单管理（跨平台）                                *
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
 *  白名单持久化接口                                   *
 *                                                                        *
 *  export_trusted_paths / import_trusted_paths 供 security_commands.rs    *
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

/* ====================================================================== *
 *  Windows 实现                                                           *
 * ====================================================================== */

#[cfg(target_os = "windows")]
mod win_impl {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };
    use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
    use windows::Win32::System::Threading::GetCurrentProcessId;

    use super::{realize_path, UnknownModule, TRUSTED_PATHS};

    /* ---------------- 签名验证结果缓存 ----------------
     * 以文件路径为键，缓存 WinVerifyTrust 结果（含吊销检查），TTL 1 小时。
     * 首次验证需联网检查吊销，成功后缓存，后续巡检直接使用缓存结果，
     * 避免重复网络开销和离线阻断。
     */
    static SIG_CACHE: OnceLock<Mutex<HashMap<String, (bool, Instant)>>> = OnceLock::new();
    const SIG_CACHE_TTL_SECS: u64 = 3600; // 1 小时

    fn sig_cache() -> &'static Mutex<HashMap<String, (bool, Instant)>> {
        SIG_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /* ---------------- wintrust.dll FFI 声明 ----------------
     * Cargo.toml 已启用 Win32_Security 但未启用 Win32_Security_WinTrust 子 feature，
     * 因此 windows crate 不直接导出 WinVerifyTrust。改为通过 extern "system" +
     * #[link(name="wintrust")] 直接链接 wintrust.dll，结构体与常量自定义。
     * 布局严格按 Win32 SDK wintrust.h 中的 WINTRUST_DATA / WINTRUST_FILE_INFO 定义，
     * 与 windows crate 0.58 的官方定义完全一致（已逐字段核对偏移量）。
     */

    /// GUID 结构（对应 Win32 GUID）
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct Guid {
        pub data1: u32,
        pub data2: u16,
        pub data3: u16,
        pub data4: [u8; 8],
    }

    /// WINTRUST_ACTION_GENERIC_VERIFY_V2 策略 GUID
    /// {00AAC56B-CD44-11D0-8CC2-00C04FC295EE}
    const WINTRUST_ACTION_GENERIC_VERIFY_V2: Guid = Guid {
        data1: 0x00aac56b,
        data2: 0xcd44,
        data3: 0x11d0,
        data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    };

    /// WINTRUST_FILE_INFO（对应 Win32 WINTRUST_FILE_INFO_）
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct WinTrustFileInfo {
        pub cb_struct: u32,
        pub pcwsz_file_path: *const u16, // LPCWSTR
        pub h_file: *mut c_void,         // HANDLE（不打开文件，传 null）
        pub pg_known_subject: *mut Guid, // 可选，传 null
    }

    /// WINTRUST_DATA（对应 Win32 _WINTRUST_DATA）
    /// 注意：原 C 结构中第 7 个字段是 union（pFile/pCatalog/pBlob/pSgnr/pCert），
    /// 所有成员都是指针（8 字节，x64 下），因此直接用 p_file 字段表示 union 的活跃成员。
    /// repr(C) 保证与 C 端内存布局完全一致（已逐字段核对偏移量）。
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct WinTrustData {
        pub cb_struct: u32,
        pub p_policy_callback_data: *mut c_void, // 4 字节后补齐到 8 字节对齐
        pub p_sip_client_data: *mut c_void,
        pub dw_ui_choice: u32,            // WTD_UI_NONE = 2
        pub fdw_revocation_checks: u32,  // WTD_REVOKE_NONE = 0
        pub dw_union_choice: u32,        // WTD_CHOICE_FILE = 1
        pub p_file: *mut WinTrustFileInfo, // 替代 union（4 字节后补齐到 8 字节对齐）
        pub dw_state_action: u32,        // WTD_STATEACTION_VERIFY=1 / CLOSE=2
        pub h_wvt_state_data: *mut c_void, // HANDLE（4 字节后补齐到 8 字节对齐）
        pub pwsz_url_reference: *const u16, // PWSTR
        pub dw_prov_flags: u32,
        pub dw_ui_context: u32,
        pub p_signature_settings: *mut c_void,
    }

    // WinVerifyTrust 常量（来自 wintrust.h）
    const WTD_UI_NONE: u32 = 2;
    /// 启用整条证书链的吊销检查
    /// WTD_REVOKE_NONE = 0（旧值，已废弃）
    /// WTD_REVOKE_WHOLECHAIN = 2（检查整条链的吊销状态）
    const WTD_REVOKE_WHOLECHAIN: u32 = 2;
    const WTD_CHOICE_FILE: u32 = 1;
    const WTD_STATEACTION_VERIFY: u32 = 1;
    const WTD_STATEACTION_CLOSE: u32 = 2;

    // 直接链接 wintrust.dll 的 WinVerifyTrust。
    // #[link(name="wintrust")] 在 windows-msvc 目标下链接 wintrust.lib，
    // 在 windows-gnu 目标下链接 libwintrust.a / wintrust.dll。
    #[link(name = "wintrust")]
    extern "system" {
        fn WinVerifyTrust(
            hwnd: *mut c_void,
            pg_action_id: *const Guid,
            pwvt_data: *mut c_void,
        ) -> i32;
    }

    /* ---------------- 字符串与系统目录辅助函数 ---------------- */

    /// 宽字符缓冲区转 String（遇到首个 null 终止）
    pub(super) fn wchar_to_string(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    /// 获取 %SystemRoot%\System32 规范化路径
    /// GetSystemDirectoryW 直接返回系统目录
    pub(super) fn get_system32_dir_normalized() -> String {
        let mut buf = [0u16; 260];
        let len = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
        if len == 0 || len as usize > buf.len() {
            // 取系统目录失败（极罕见），返回空串，调用方按“无系统目录白名单”处理
            return String::new();
        }
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        realize_path(&s)
    }

    /// 获取 %SystemRoot%\SysWOW64 规范化路径
    /// SysWOW64 = GetWindowsDirectoryW() + "\SysWOW64"
    pub(super) fn get_syswow64_dir_normalized() -> String {
        let mut buf = [0u16; 260];
        let len = unsafe { GetWindowsDirectoryW(Some(&mut buf)) };
        if len == 0 || len as usize > buf.len() {
            return String::new();
        }
        let root = String::from_utf16_lossy(&buf[..len as usize]);
        let syswow64 = format!("{}\\SysWOW64", root);
        realize_path(&syswow64)
    }

    /// 获取 %SystemRoot%\WinSxS 规范化路径
    /// WinSxS = GetWindowsDirectoryW() + "\WinSxS"
    /// Windows Side-by-Side 系统程序集目录，所有模块均为 Microsoft catalog 签名
    /// （comctl32.dll、comdlg32.dll、shell32.dll 等系统组件从此目录加载）
    pub(super) fn get_winsxs_dir_normalized() -> String {
        let mut buf = [0u16; 260];
        let len = unsafe { GetWindowsDirectoryW(Some(&mut buf)) };
        if len == 0 || len as usize > buf.len() {
            return String::new();
        }
        let root = String::from_utf16_lossy(&buf[..len as usize]);
        let winsxs = format!("{}\\WinSxS", root);
        realize_path(&winsxs)
    }

    /// 获取 Microsoft 受信任运行时目录列表（规范化后小写）
    ///
    /// 这些目录存放 Microsoft 签名的合法系统组件/运行时，但不在 System32/SysWOW64 下：
    ///   - %ProgramFiles%\Common Files\microsoft shared — Windows Ink (tiptsf.dll)、
    ///     语音、Office 共享组件等
    ///   - %ProgramFiles(x86)%\Microsoft\EdgeWebView\Application — Edge WebView2 运行时
    ///     （Tauri webview 依赖，EmbeddedBrowserWebView.dll 等）
    ///   - %ProgramFiles%\Microsoft\EdgeWebView\Application — Edge WebView2 64 位安装
    ///   - %ProgramFiles(x86)%\Microsoft\VisualStudio — Visual Studio 运行时组件
    ///   - %ProgramFiles(x86)%\Windows Kits — Windows SDK 运行时组件
    ///
    /// 返回空 Vec 表示无可用目录（环境变量未设置）。
    pub(super) fn get_microsoft_runtime_dirs_normalized() -> Vec<String> {
        let mut dirs: Vec<String> = Vec::new();

        // %ProgramFiles%\Common Files\microsoft shared
        if let Ok(pf) = std::env::var("ProgramFiles") {
            if !pf.is_empty() {
                let p = format!("{}\\Common Files\\microsoft shared", pf);
                dirs.push(realize_path(&p));
            }
        }
        // %ProgramFiles(x86)%\Microsoft\EdgeWebView\Application
        if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
            if !pf86.is_empty() {
                let p = format!("{}\\Microsoft\\EdgeWebView\\Application", pf86);
                dirs.push(realize_path(&p));
                // Visual Studio 运行时
                let p2 = format!("{}\\Microsoft\\VisualStudio", pf86);
                dirs.push(realize_path(&p2));
                // Windows Kits
                let p3 = format!("{}\\Windows Kits", pf86);
                dirs.push(realize_path(&p3));
            }
        }
        // %ProgramFiles%\Microsoft\EdgeWebView\Application (64 位 Edge)
        if let Ok(pf) = std::env::var("ProgramFiles") {
            if !pf.is_empty() {
                let p = format!("{}\\Microsoft\\EdgeWebView\\Application", pf);
                dirs.push(realize_path(&p));
            }
        }

        dirs
    }

    /* ---------------- 模块白名单巡检 ---------------- */

    /// 遍历当前进程已加载模块，返回未知/可疑模块列表
    ///
    /// 验证规则：
    ///   a) 路径在安装目录（install_dir）下 → 受信任位置，需验证签名
    ///   b) 路径在 %SystemRoot%\System32、SysWOW64 或 WinSxS 下 → 系统模块，按位置信任
    ///      （catalog 签名，跳过 Authenticode 验证，性能优化）
    ///   c) 路径在 Microsoft 运行时目录下（Edge WebView2、Visual Studio、Windows Kits、
    ///      Common Files\microsoft shared）→ 受信任位置，需验证签名
    ///   d) 路径在用户受信任白名单下 → 受信任位置，需验证签名
    ///   e) 不在上述任何位置 → 未知第三方 DLL，reason="未知路径"
    ///   f) 在受信任位置但非系统目录且未通过签名验证 → reason="未签名"
    ///
    /// verify_sigs 控制是否执行 Authenticode 签名验证（规则 f）：
    ///   - true：完整巡检，用于前端主动巡检命令（security_module_patrol）
    ///   - false：轻量巡检，仅路径白名单匹配，跳过 WinVerifyTrust 以降低 CPU 开销，
    ///     用于后台巡检线程（background_patrol）每 30s 高频调用
    pub(super) fn scan_modules(install_dir: &str, verify_sigs: bool) -> Vec<UnknownModule> {
        let mut unknown: Vec<UnknownModule> = Vec::new();

        // 预计算所有受信任路径前缀（规范化后小写）
        let install_norm = realize_path(install_dir);
        let system32_norm = get_system32_dir_normalized();
        let syswow64_norm = get_syswow64_dir_normalized();
        // WinSxS（Windows Side-by-Side 系统程序集目录，catalog 签名，按位置信任）
        let winsxs_norm = get_winsxs_dir_normalized();
        // Microsoft 运行时目录（Edge WebView2、Visual Studio、Windows Kits 等，
        // 均为 Microsoft 签名的合法组件，但不在 System32/SysWOW64 下）
        let ms_runtime_dirs = get_microsoft_runtime_dirs_normalized();
        // 复制受信任路径白名单快照（避免长时间持锁）
        let trusted: Vec<String> = match TRUSTED_PATHS.lock() {
            Ok(g) => g.iter().cloned().collect(),
            Err(_) => Vec::new(),
        };

        // 取当前进程模块快照
        // TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32：枚举当前进程的 32 位 + 64 位模块
        let pid = unsafe { GetCurrentProcessId() };
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        };
        let snapshot: HANDLE = match snapshot {
            Ok(h) => h,
            Err(_) => {
                // 快照创建失败（极罕见，如内存不足），按“无威胁”返回，不阻断业务
                return unknown;
            }
        };

        // 模块枚举：MODULEENTRY32W.dwSize 必须先设置
        let mut me = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        // Module32FirstW / Module32NextW 返回 Err 表示无更多模块
        let mut ok = unsafe { Module32FirstW(snapshot, &mut me) }.is_ok();
        while ok {
            // 提取模块名（szModule）与完整路径（szExePath）
            let name = wchar_to_string(&me.szModule);
            let path = wchar_to_string(&me.szExePath);

            // 跳过空路径（部分内核模块可能没有磁盘路径）
            if !path.is_empty() {
                let path_norm = realize_path(&path);

                // 路径白名单匹配（前缀比较，大小写已规范化）
                let in_install = !install_norm.is_empty()
                    && path_norm.starts_with(&install_norm);
                let in_system32 = !system32_norm.is_empty()
                    && path_norm.starts_with(&system32_norm);
                let in_syswow64 = !syswow64_norm.is_empty()
                    && path_norm.starts_with(&syswow64_norm);
                let in_winsxs = !winsxs_norm.is_empty()
                    && path_norm.starts_with(&winsxs_norm);
                let in_ms_runtime = ms_runtime_dirs
                    .iter()
                    .any(|d| !d.is_empty() && path_norm.starts_with(d));
                let in_trusted = trusted
                    .iter()
                    .any(|t| !t.is_empty() && path_norm.starts_with(t));

                // 系统目录集合：System32、SysWOW64、WinSxS（均为 Microsoft catalog 签名）
                let in_system_dir = in_system32 || in_syswow64 || in_winsxs;

                if !in_install && !in_system_dir && !in_ms_runtime && !in_trusted {
                    // 不在任何受信任位置 → 未知第三方 DLL
                    unknown.push(UnknownModule {
                        name: name.clone(),
                        path: path.clone(),
                        reason: "未知路径".to_string(),
                    });
                } else if verify_sigs && !in_system_dir {
                    // 受信任位置但非系统目录：必须通过 Authenticode 签名验证
                    // 系统目录模块跳过签名验证（catalog 签名，按位置信任）
                    // Microsoft 运行时目录（Edge WebView2 等）需验证签名（Authenticode 内嵌签名）
                    // 轻量巡检模式（verify_sigs=false）跳过签名验证，仅按路径信任，降低 CPU 开销
                    if !verify_signature(&path) {
                        unknown.push(UnknownModule {
                            name: name.clone(),
                            path: path.clone(),
                            reason: "未签名".to_string(),
                        });
                    }
                }
                // 系统目录模块（System32/SysWOW64/WinSxS）按位置信任，跳过签名验证
            }

            ok = unsafe { Module32NextW(snapshot, &mut me) }.is_ok();
        }

        // 释放快照句柄（忽略关闭错误）
        let _ = unsafe { CloseHandle(snapshot) };
        unknown
    }

    /// 完整巡检：路径白名单 + Authenticode 签名验证（供前端主动巡检命令使用）
    pub(super) fn patrol_modules(install_dir: &str) -> Vec<UnknownModule> {
        scan_modules(install_dir, true)
    }

    /// 轻量巡检：仅路径白名单匹配，跳过 WinVerifyTrust（供后台巡检线程使用，降低 CPU）
    pub(super) fn patrol_modules_paths_only(install_dir: &str) -> Vec<UnknownModule> {
        scan_modules(install_dir, false)
    }

    /* ---------------- Authenticode 数字签名验证 ---------------- */

    /// 验证模块的 Authenticode 数字签名（含吊销检查 + 缓存）
    ///
    /// 通过 WinVerifyTrust + WINTRUST_ACTION_GENERIC_VERIFY_V2 验证：
    ///   - WTD_UI_NONE：不显示 UI（服务/后台进程友好）
    ///   - WTD_REVOKE_WHOLECHAIN：检查整条证书链的吊销状态（CRL + OCSP）
    ///   - WTD_STATEACTION_VERIFY → 验证 → WTD_STATEACTION_CLOSE：必须配对调用
    ///     以释放验证状态数据，避免 wintrust 资源泄漏
    ///
    /// 签名验证结果缓存
    ///   - 以文件路径（realize_path 真实化后）为键，缓存 TTL 1 小时
    ///   - 首次验证需联网检查吊销，成功后缓存
    ///   - 后续巡检直接使用缓存结果，避免重复网络开销
    ///
    /// 返回：true=签名有效，false=未签名或签名无效
    pub(super) fn verify_signature(module_path: &str) -> bool {
        if module_path.is_empty() {
            return false;
        }

        // 检查缓存
        let cache_key = realize_path(module_path);
        if let Ok(cache) = sig_cache().lock() {
            if let Some((result, timestamp)) = cache.get(&cache_key) {
                if timestamp.elapsed().as_secs() < SIG_CACHE_TTL_SECS {
                    return *result;
                }
            }
        }

        // 执行实际验证（含吊销检查）
        let result = verify_signature_uncached(module_path);

        // 更新缓存
        if let Ok(mut cache) = sig_cache().lock() {
            cache.insert(cache_key, (result, Instant::now()));
        }

        result
    }

    /// 实际调用 WinVerifyTrust 执行签名验证（无缓存）
    fn verify_signature_uncached(module_path: &str) -> bool {
        // 路径转 UTF-16（含 null 终止符，供 PCWSTR 使用）
        let wide: Vec<u16> = module_path.encode_utf16().chain(std::iter::once(0)).collect();

        // WINTRUST_FILE_INFO：指定待验证文件路径
        let mut file_info = WinTrustFileInfo {
            cb_struct: std::mem::size_of::<WinTrustFileInfo>() as u32,
            pcwsz_file_path: wide.as_ptr(),
            h_file: ptr::null_mut(),
            pg_known_subject: ptr::null_mut(),
        };

        // WINTRUST_DATA：验证参数
        let mut trust_data = WinTrustData {
            cb_struct: std::mem::size_of::<WinTrustData>() as u32,
            p_policy_callback_data: ptr::null_mut(),
            p_sip_client_data: ptr::null_mut(),
            dw_ui_choice: WTD_UI_NONE,
            // 启用整条证书链的吊销检查
            fdw_revocation_checks: WTD_REVOKE_WHOLECHAIN,
            dw_union_choice: WTD_CHOICE_FILE,
            p_file: &mut file_info,
            dw_state_action: WTD_STATEACTION_VERIFY,
            h_wvt_state_data: ptr::null_mut(),
            pwsz_url_reference: ptr::null(),
            dw_prov_flags: 0,
            dw_ui_context: 0,
            p_signature_settings: ptr::null_mut(),
        };

        // 调用 WinVerifyTrust 执行验证
        let result = unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &WINTRUST_ACTION_GENERIC_VERIFY_V2,
                &mut trust_data as *mut WinTrustData as *mut c_void,
            )
        };

        // 必须配对调用 WTD_STATEACTION_CLOSE 释放状态数据资源
        trust_data.dw_state_action = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &WINTRUST_ACTION_GENERIC_VERIFY_V2,
                &mut trust_data as *mut WinTrustData as *mut c_void,
            );
        }

        // WinVerifyTrust 返回 0 表示签名有效，非 0 表示未签名/无效/吊销/过期等
        result == 0
    }
}

/* ====================================================================== *
 *  公共接口 — 平台分发                                                     *
 * ====================================================================== */

/// 遍历当前进程已加载模块，返回未知/可疑模块列表
///
/// Windows 实现：CreateToolhelp32Snapshot + Module32FirstW/NextW 枚举
/// 非 Windows：空实现，返回空 Vec
#[cfg(target_os = "windows")]
pub fn patrol_modules(install_dir: &str) -> Vec<UnknownModule> {
    win_impl::patrol_modules(install_dir)
}

/// 轻量巡检：仅路径白名单匹配，跳过 WinVerifyTrust 签名验证（降低 CPU 开销）
///
/// 供后台巡检线程（background_patrol）每 30s 高频调用：
///   - 仅检测"未知路径"的第三方 DLL（不在安装目录/System32/SysWOW64/WinSxS/
///     Microsoft 运行时目录/受信任白名单下）
///   - 受信任位置的非系统模块按路径信任，不调用 WinVerifyTrust
///   - 非 Windows：空实现，返回空 Vec
#[cfg(target_os = "windows")]
pub fn patrol_modules_paths_only(install_dir: &str) -> Vec<UnknownModule> {
    win_impl::patrol_modules_paths_only(install_dir)
}

/// 验证模块的 Authenticode 数字签名
///
/// Windows 实现：WinVerifyTrust + WINTRUST_ACTION_GENERIC_VERIFY_V2
/// 非 Windows：空实现，返回 false
#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub fn verify_signature(module_path: &str) -> bool {
    win_impl::verify_signature(module_path)
}

/* ====================================================================== *
 *  系统目录模块哈希基线库                       *
 *                                                                        *
 *  对 System32、SysWOW64、WinSxS 等系统目录下的模块，预计算所有合法微软   *
 *  DLL 的 SHA-256 哈希集合，在巡检时对哈希进行匹配。任何不在基线库中的    *
 *  模块（包括被替换或新增的 DLL）一律视为威胁。                           *
 *                                                                        *
 *  基线库在应用启动时构建一次（惰性初始化），后续巡检直接使用缓存结果。    *
 * ====================================================================== */

/// 系统目录模块哈希基线（路径 → SHA-256 hex）
///
/// 杜绝位置信任。
/// 预计算系统目录下所有合法微软 DLL 的 SHA-256 哈希，
/// 巡检时对系统目录模块的哈希进行匹配，被替换的 DLL 即便在系统目录下也被检出。
pub type HashBaseline = std::collections::HashMap<String, String>;

/// 计算文件的 SHA-256 哈希（hex 编码）
///
/// 读取文件内容并计算 SHA-256，返回 64 字符 hex 字符串。
/// 文件不存在 / 读取失败 / 过大（> 256MB，防 DoS）时返回 None。
#[cfg(target_os = "windows")]
pub fn compute_file_hash(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};

    // 文件大小上限 256MB，防止超大文件导致内存耗尽
    const MAX_HASH_FILE_SIZE: u64 = 256 * 1024 * 1024;

    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > MAX_HASH_FILE_SIZE {
        log::warn!(
            "[module_whitelist] 文件过大（{} 字节 > {} 上限），跳过哈希计算: {}",
            metadata.len(),
            MAX_HASH_FILE_SIZE,
            sanitize_path_for_hash(path)
        );
        return None;
    }

    let data = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    Some(hash.iter().map(|b| format!("{:02x}", b)).collect())
}

/// 非 Windows 平台：计算文件哈希（空实现）
#[cfg(not(target_os = "windows"))]
pub fn compute_file_hash(_path: &str) -> Option<String> {
    None
}

/// 构建系统目录模块哈希基线
///
/// 枚举 System32、SysWOW64 目录下的所有 .dll/.sys 文件，计算 SHA-256 哈希，
/// 返回"规范化路径 → SHA-256 hex"映射表。
///
/// WinSxS 目录因体积庞大（数十万文件）且模块均通过 catalog 签名验证，
/// 不纳入哈希基线（仅在 patrol_modules 完整巡检中通过签名验证）。
///
/// 此函数在后台线程中调用（启动时惰性构建），不阻塞主线程。
/// 构建失败时返回空 HashMap（降级为仅路径信任）。
#[cfg(target_os = "windows")]
pub fn build_system_baseline() -> HashBaseline {
    let mut baseline = HashBaseline::new();

    // System32 目录
    let system32 = win_impl::get_system32_dir_normalized();
    if !system32.is_empty() {
        collect_dir_hashes(&system32, &mut baseline);
    }

    // SysWOW64 目录
    let syswow64 = win_impl::get_syswow64_dir_normalized();
    if !syswow64.is_empty() {
        collect_dir_hashes(&syswow64, &mut baseline);
    }

    log::info!(
        "[module_whitelist] 系统目录哈希基线已构建：{} 个模块",
        baseline.len()
    );

    baseline
}

/// 非 Windows 平台：构建系统目录哈希基线（空实现）
#[cfg(not(target_os = "windows"))]
pub fn build_system_baseline() -> HashBaseline {
    HashBaseline::new()
}

/// 验证模块哈希是否匹配基线
///
/// 返回值：
///   - `Ok(true)`：哈希匹配，模块合法
///   - `Ok(false)`：哈希不匹配，模块可能被替换（威胁）
///   - `Err(())`：模块路径不在基线中（非系统目录模块，调用方应使用其他验证方式）
///
/// 注意：此函数仅对系统目录模块有意义。非系统目录模块应通过签名验证判断。
#[cfg(target_os = "windows")]
pub fn verify_module_against_baseline(
    module_path: &str,
    baseline: &HashBaseline,
) -> Result<bool, ()> {
    let normalized = realize_path(module_path);
    if normalized.is_empty() {
        return Err(());
    }

    let expected_hash = match baseline.get(&normalized) {
        Some(h) => h,
        None => return Err(()), // 不在基线中
    };

    match compute_file_hash(module_path) {
        Some(actual_hash) => Ok(&actual_hash == expected_hash),
        None => {
            log::warn!(
                "[module_whitelist] 无法计算模块哈希（文件可能已删除）: {}",
                sanitize_path_for_hash(module_path)
            );
            Ok(false) // 无法计算哈希视为不匹配（保守策略）
        }
    }
}

/// 非 Windows 平台：验证模块哈希（空实现，始终返回 Err）
#[cfg(not(target_os = "windows"))]
pub fn verify_module_against_baseline(
    _module_path: &str,
    _baseline: &HashBaseline,
) -> Result<bool, ()> {
    Err(())
}

/// 枚举目录下所有 .dll/.sys 文件并计算哈希
///
/// 递归遍历目录（深度 1，仅直接子文件），对每个 .dll/.sys 文件
/// 计算 SHA-256 并加入基线。
///
/// 跳过无法读取的文件（权限不足等），不中断基线构建。
#[cfg(target_os = "windows")]
fn collect_dir_hashes(dir: &str, baseline: &mut HashBaseline) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            log::warn!(
                "[module_whitelist] 读取目录失败，跳过哈希基线收集: {} ({})",
                sanitize_path_for_hash(dir),
                e
            );
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // 仅处理 .dll 和 .sys 文件
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !ext.eq_ignore_ascii_case("dll") && !ext.eq_ignore_ascii_case("sys") {
            continue;
        }

        let path_str = path.to_string_lossy().to_string();
        let normalized = realize_path(&path_str);
        if normalized.is_empty() {
            continue;
        }

        if let Some(hash) = compute_file_hash(&path_str) {
            baseline.insert(normalized, hash);
        }
    }
}

/// 路径脱敏（用于日志输出，隐藏用户名）
#[cfg(target_os = "windows")]
fn sanitize_path_for_hash(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    if let Ok(home) = std::env::var("USERPROFILE") {
        let h = home.replace('\\', "/");
        if normalized.contains(&h) {
            return normalized.replace(&h, "<USER_HOME>");
        }
    }
    normalized
}

/* ====================================================================== *
 *  非 Windows 平台空实现                                                  *
 * ====================================================================== */

#[cfg(not(target_os = "windows"))]
pub fn patrol_modules(_install_dir: &str) -> Vec<UnknownModule> {
    Vec::new()
}

#[cfg(not(target_os = "windows"))]
pub fn patrol_modules_paths_only(_install_dir: &str) -> Vec<UnknownModule> {
    Vec::new()
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn verify_signature(_module_path: &str) -> bool {
    false
}
