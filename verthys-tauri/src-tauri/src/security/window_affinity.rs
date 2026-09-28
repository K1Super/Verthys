/*
 * security/window_affinity.rs — 窗口显示亲和性原语
 *
 * 职责：
 *   - 读写窗口显示亲和性原始取值（SetWindowDisplayAffinity / GetWindowDisplayAffinity）
 *   - 运行时 OS 版本检测与能力降级判定
 *
 * 为什么提供原始取值接口而不是布尔接口：
 *   保护回滚必须还原变更前的**实际取值**，而取值存在"捕获排除 / 仅监视器 / 无"
 *   三种可能。布尔接口只能表达目标值的反面，会把"仅监视器"错误还原为"无保护"，
 *   因此回滚以原始取值为准，布尔语义只允许作为对外包装。
 *
 * 能力降级：
 *   WDA_EXCLUDEFROMCAPTURE (0x11) 仅在 Windows 10 2004 (build 19041) 及以上可用；
 *   旧版系统调用会失败，从而制造"以为已保护、实际未保护"的假象，因此按版本
 *   降级为 WDA_MONITOR（捕获结果中呈现为空白矩形，内容仍不可见）。
 *   版本经 RtlGetVersion 获取（不受 manifest 兼容性影响），结果进程内只检测一次。
 */

use std::sync::OnceLock;

/// 无保护
pub const WDA_NONE: u32 = 0x00;
/// 仅监视器：旧系统降级模式，捕获结果中呈现为空白矩形
pub const WDA_MONITOR: u32 = 0x01;
/// 完全排除捕获：窗口在捕获结果中不出现
pub const WDA_EXCLUDEFROMCAPTURE: u32 = 0x11;

/// OS 版本信息（仅保留能力判定所需字段）
#[derive(Debug, Clone, Copy)]
struct OsVersionInfo {
    major: u32,
    build: u32,
}

/// 通过 RtlGetVersion 获取真实 OS 版本
///
/// GetVersionExW 受 manifest 兼容性影响可能返回错误版本，
/// RtlGetVersion 直接从内核获取，不受 manifest 影响。
#[cfg(target_os = "windows")]
fn get_os_version() -> Option<OsVersionInfo> {
    #[repr(C)]
    #[allow(non_snake_case)]
    struct OsVersionInfoExW {
        dwOSVersionInfoSize: u32,
        dwMajorVersion: u32,
        dwMinorVersion: u32,
        dwBuildNumber: u32,
        dwPlatformId: u32,
        szCSDVersion: [u16; 128],
        wServicePackMajor: u16,
        wServicePackMinor: u16,
        wSuiteMask: u16,
        wProductType: u8,
        wReserved: u8,
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn RtlGetVersion(lpVersionInformation: *mut OsVersionInfoExW) -> i32;
    }

    unsafe {
        let mut info: OsVersionInfoExW = std::mem::zeroed();
        info.dwOSVersionInfoSize = std::mem::size_of::<OsVersionInfoExW>() as u32;
        let status = RtlGetVersion(&mut info);
        if status == 0 {
            Some(OsVersionInfo {
                major: info.dwMajorVersion,
                build: info.dwBuildNumber,
            })
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn get_os_version() -> Option<OsVersionInfo> {
    None
}

/// 缓存的 OS 版本（首次调用时检测，后续直接返回缓存）
static OS_VERSION: OnceLock<Option<OsVersionInfo>> = OnceLock::new();

fn cached_os_version() -> Option<OsVersionInfo> {
    *OS_VERSION.get_or_init(get_os_version)
}

/// 检测当前系统是否支持完全排除捕获
///
/// 版本不可得时按不支持处理：宁可降级为仅监视器，也不制造"设置成功"的假象。
pub fn supports_exclude_from_capture() -> bool {
    match cached_os_version() {
        Some(ver) => ver.major >= 10 && ver.build >= 19041,
        None => false,
    }
}

/// 能力判定到保护取值的纯函数（供测试直接断言，不依赖运行环境）
pub fn protection_value_for(exclude_from_capture_supported: bool) -> u32 {
    if exclude_from_capture_supported {
        WDA_EXCLUDEFROMCAPTURE
    } else {
        WDA_MONITOR
    }
}

/// 当前系统应使用的保护取值
pub fn protection_value() -> u32 {
    protection_value_for(supports_exclude_from_capture())
}

/// 设置窗口显示亲和性原始取值
#[cfg(target_os = "windows")]
pub fn set_raw_affinity(hwnd: isize, value: u32) -> Result<(), String> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        SetWindowDisplayAffinity, WINDOW_DISPLAY_AFFINITY,
    };

    unsafe {
        let hwnd = HWND(hwnd as *mut _);
        SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(value))
            .map_err(|e| format!("SetWindowDisplayAffinity(0x{:X}) 失败: {}", value, e))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn set_raw_affinity(_hwnd: isize, _value: u32) -> Result<(), String> {
    Err("窗口显示亲和性: 非 Windows 平台不支持".into())
}

/// 读取窗口显示亲和性原始取值
#[cfg(target_os = "windows")]
pub fn get_raw_affinity(hwnd: isize) -> Result<u32, String> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::GetWindowDisplayAffinity;

    let mut value: u32 = 0;
    unsafe {
        let hwnd = HWND(hwnd as *mut _);
        GetWindowDisplayAffinity(hwnd, &mut value)
            .map_err(|e| format!("GetWindowDisplayAffinity 失败: {}", e))?;
    }
    Ok(value)
}

#[cfg(not(target_os = "windows"))]
pub fn get_raw_affinity(_hwnd: isize) -> Result<u32, String> {
    Err("窗口显示亲和性: 非 Windows 平台不支持".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_value_for_uses_exclude_when_supported() {
        assert_eq!(protection_value_for(true), WDA_EXCLUDEFROMCAPTURE);
    }

    #[test]
    fn test_protection_value_for_degrades_to_monitor() {
        assert_eq!(protection_value_for(false), WDA_MONITOR);
    }

    #[test]
    fn test_constants_match_system_definition() {
        // 与 Windows SDK 定义一致：取值错位会让回读校验永远失败
        assert_eq!(WDA_NONE, 0x00);
        assert_eq!(WDA_MONITOR, 0x01);
        assert_eq!(WDA_EXCLUDEFROMCAPTURE, 0x11);
    }

    #[test]
    fn test_protection_value_is_never_none() {
        // 保护取值不允许等于无保护：避免"设置成功但未保护"的静默假象
        assert_ne!(protection_value(), WDA_NONE);
    }
}