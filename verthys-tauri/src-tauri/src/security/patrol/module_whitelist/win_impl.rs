/* ====================================================================== *
 *  Windows 实现（Authenticode 签名验证 + 模块枚举）                       *
 * ====================================================================== */

use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
use windows::Win32::System::Threading::GetCurrentProcessId;

use super::trusted::{dev_self_module_path, is_dev_self_module, realize_path, TRUSTED_PATHS};
use super::types::{SignatureStatus, UnknownModule};

/* ---------------- 签名验证结果缓存 ----------------
 * 以文件路径为键，缓存 WinVerifyTrust 结论（含吊销检查），TTL 1 小时。
 * 首次验证需联网检查吊销，成功后缓存，后续巡检直接使用缓存结果，
 * 避免重复网络开销和离线阻断。
 */
static SIG_CACHE: OnceLock<Mutex<HashMap<String, (SignatureStatus, Instant)>>> = OnceLock::new();
const SIG_CACHE_TTL_SECS: u64 = 3600; // 1 小时

fn sig_cache() -> &'static Mutex<HashMap<String, (SignatureStatus, Instant)>> {
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
    pub dw_ui_choice: u32,              // WTD_UI_NONE = 2
    pub fdw_revocation_checks: u32,     // WTD_REVOKE_NONE = 0
    pub dw_union_choice: u32,           // WTD_CHOICE_FILE = 1
    pub p_file: *mut WinTrustFileInfo,  // 替代 union（4 字节后补齐到 8 字节对齐）
    pub dw_state_action: u32,           // WTD_STATEACTION_VERIFY=1 / CLOSE=2
    pub h_wvt_state_data: *mut c_void,  // HANDLE（4 字节后补齐到 8 字节对齐）
    pub pwsz_url_reference: *const u16, // PWSTR
    pub dw_prov_flags: u32,
    pub dw_ui_context: u32,
    pub p_signature_settings: *mut c_void,
}

// WinVerifyTrust 常量（来自 wintrust.h）
const WTD_UI_NONE: u32 = 2;
/// 不检查吊销（仅验证签名链本身；用于离线时区分“签名无效”与“吊销不可达”）
const WTD_REVOKE_NONE: u32 = 0;
/// 启用整条证书链的吊销检查
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
    fn WinVerifyTrust(hwnd: *mut c_void, pg_action_id: *const Guid, pwvt_data: *mut c_void) -> i32;
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
    // 开发主程序自身豁免（发布构建为 None）
    let dev_self = dev_self_module_path();
    // 取当前进程模块快照
    // TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32：枚举当前进程的 32 位 + 64 位模块
    let pid = unsafe { GetCurrentProcessId() };
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
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
            let in_install = !install_norm.is_empty() && path_norm.starts_with(&install_norm);
            let in_system32 = !system32_norm.is_empty() && path_norm.starts_with(&system32_norm);
            let in_syswow64 = !syswow64_norm.is_empty() && path_norm.starts_with(&syswow64_norm);
            let in_winsxs = !winsxs_norm.is_empty() && path_norm.starts_with(&winsxs_norm);
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
            } else if verify_sigs
                && !in_system_dir
                && !is_dev_self_module(&path_norm, dev_self.as_deref())
            {
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

/// 枚举受信位置（非系统目录）的已加载模块清单
///
/// 与 scan_modules 的签名验证集合保持同一口径：安装目录、Microsoft
/// 运行时目录、用户受信白名单下的模块纳入返回；系统目录模块
/// （catalog 签名，按位置信任 + 哈希基线校验）与未知路径模块不返回
/// （未知路径已由轻量巡检的路径白名单直接检出）。
pub(super) fn trusted_signable_module_paths(install_dir: &str) -> Vec<(String, String)> {
    let mut result: Vec<(String, String)> = Vec::new();

    let install_norm = realize_path(install_dir);
    let system32_norm = get_system32_dir_normalized();
    let syswow64_norm = get_syswow64_dir_normalized();
    let winsxs_norm = get_winsxs_dir_normalized();
    let ms_runtime_dirs = get_microsoft_runtime_dirs_normalized();
    let trusted: Vec<String> = match TRUSTED_PATHS.lock() {
        Ok(g) => g.iter().cloned().collect(),
        Err(_) => Vec::new(),
    };
    // 开发主程序自身豁免：未签名 dev 主程序不进入完整校验候选，
    // 避免后台抽样把自身误判为“签名失效”并升级应急。发布构建为 None。
    let dev_self = dev_self_module_path();

    let pid = unsafe { GetCurrentProcessId() };
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    let snapshot: HANDLE = match snapshot {
        Ok(h) => h,
        Err(_) => return result,
    };

    let mut me = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    let mut ok = unsafe { Module32FirstW(snapshot, &mut me) }.is_ok();
    while ok {
        let name = wchar_to_string(&me.szModule);
        let path = wchar_to_string(&me.szExePath);

        if !path.is_empty() && !name.is_empty() {
            let path_norm = realize_path(&path);
            let in_system_dir = (!system32_norm.is_empty()
                && path_norm.starts_with(&system32_norm))
                || (!syswow64_norm.is_empty() && path_norm.starts_with(&syswow64_norm))
                || (!winsxs_norm.is_empty() && path_norm.starts_with(&winsxs_norm));
            let in_trusted = (!install_norm.is_empty() && path_norm.starts_with(&install_norm))
                || ms_runtime_dirs
                    .iter()
                    .any(|d| !d.is_empty() && path_norm.starts_with(d))
                || trusted
                    .iter()
                    .any(|t| !t.is_empty() && path_norm.starts_with(t));

            if !in_system_dir && in_trusted && !is_dev_self_module(&path_norm, dev_self.as_deref())
            {
                result.push((name, path));
            }
        }

        ok = unsafe { Module32NextW(snapshot, &mut me) }.is_ok();
    }

    let _ = unsafe { CloseHandle(snapshot) };
    result
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
    signature_status(module_path).is_signed()
}

/// 签名核验结论（含吊销状态未知的容忍态），结果缓存 1 小时。
///
/// 判定顺序：先做整链吊销检查；失败时再在“不检查吊销”的模式下复核一次。
/// 第二次通过说明签名链本身有效、只是吊销状态不可达（离线/CRL 不可用），
/// 归为 `ValidRevocationUnknown`，避免离线环境把合法模块误判为未签名。
pub(super) fn signature_status(module_path: &str) -> SignatureStatus {
    if module_path.is_empty() {
        return SignatureStatus::Invalid;
    }

    // 检查缓存
    let cache_key = realize_path(module_path);
    if let Ok(cache) = sig_cache().lock() {
        if let Some((status, timestamp)) = cache.get(&cache_key) {
            if timestamp.elapsed().as_secs() < SIG_CACHE_TTL_SECS {
                return *status;
            }
        }
    }

    let status = if verify_signature_uncached(module_path, true) {
        SignatureStatus::Valid
    } else if verify_signature_uncached(module_path, false) {
        SignatureStatus::ValidRevocationUnknown
    } else {
        SignatureStatus::Invalid
    };

    // 更新缓存
    if let Ok(mut cache) = sig_cache().lock() {
        cache.insert(cache_key, (status, Instant::now()));
    }

    status
}

/// 实际调用 WinVerifyTrust 执行签名验证（无缓存）
///
/// revoke=true 时检查整条证书链的吊销状态；false 时跳过吊销检查，
/// 仅验证签名链与文件摘要。
fn verify_signature_uncached(module_path: &str, revoke: bool) -> bool {
    // 路径转 UTF-16（含 null 终止符，供 PCWSTR 使用）
    let wide: Vec<u16> = module_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

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
        // 按调用方策略决定是否检查整条证书链的吊销状态
        fdw_revocation_checks: if revoke {
            WTD_REVOKE_WHOLECHAIN
        } else {
            WTD_REVOKE_NONE
        },
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
