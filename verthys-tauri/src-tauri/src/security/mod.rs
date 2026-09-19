/*
 * security/mod.rs — Windows 安全 API 封装
 *
 * 子模块：
 *   - session_guard:    智能会话自动锁屏（mpsc 通道 + RAII 窗口 + 看门狗）
 *   - file_lock:        独占锁与防并发 + 私有目录 ACL 隔离
 *   - usb_guard:        移动存储安全强化（DPAPI 持久化 + 加盐哈希 + 影子休眠）
 *   - module_whitelist: 模块白名单实时巡检（路径真实化 + 吊销检查 + 缓存）
 *   - cleanup:          程序痕迹、缓存与卸载残留防护（移除 Gutmann + TRIM）
 *   - brute_force:      登录暴力拦截（DPAPI 持久化 + 不可逆计数 + 速率限制）
 *   - background_patrol:后台模块巡检线程（动态频率 + 看门狗 + 独立熔断）
 *   - clipboard_guard:  剪贴板保护升级（延迟清空 + 外部写入检测 + 统一入口）
 *
 * 重写要点：
 *   1. 废弃 clear_clipboard 中的"写入随机数据再清空"模式
 *      - 直接调用 EmptyClipboard 清空剪贴板
 *      - 移除无意义的随机数据写入步骤
 *      - 清空后广播 WM_DESTROYCLIPBOARD 通知系统清除云剪贴板缓存
 *      - 清空操作保持 CLIPBOARD_LOCK 串行化
 *   2. 统一剪贴板操作入口，消除功能重复
 *      - clear_clipboard() 委托到 clipboard_guard::clear() 统一入口
 *      - 所有剪贴板相关操作均通过 clipboard_guard 模块暴露
 *   3. 增加运行时 OS 版本检测，对 SetWindowDisplayAffinity 进行降级处理
 *      - 使用 RtlGetVersion 获取真实版本（不受 manifest 影响）
 *      - Windows 10 build 19041+ 支持 WDA_EXCLUDEFROMCAPTURE
 *      - 旧版降级为 WDA_MONITOR（仅排除屏幕录制）
 *   4. 封装窗口隐私状态机，防止误操作
 *      - WindowPrivacyGuard 持有窗口句柄和当前保护状态
 *      - 提供 enable() / disable() 方法，确保状态转换原子性
 *      - 禁止直接使用 set_window_privacy 自由切换
 *   5. 将安全敏感操作的审计日志统一纳入结构化体系
 *      - 所有剪贴板清空、窗口保护切换操作均产生审计日志
 *      - 记录时间戳、操作类型、结果状态
 */

pub mod session_guard;
pub mod file_lock;
pub mod usb_guard;
pub mod module_whitelist;
pub mod cleanup;
pub mod brute_force;
pub mod background_patrol;
pub mod clipboard_guard;

/* ====================================================================== *
 *  统一剪贴板清空入口                                *
 *                                                                        *
 *  clear_clipboard() 委托到 clipboard_guard::clear() 统一入口。           *
 *  移除了旧版"写入随机数据再清空"的自相矛盾逻辑。                         *
 *  向后兼容：保持 () -> bool 签名供现有调用方使用。                       *
 * ====================================================================== */

/// 清空剪贴板（向后兼容接口）
///
/// 统一剪贴板清空入口：
///   - 废弃"写入随机数据再清空"模式，改为直接清空并广播
///   - 统一通过 clipboard_guard::clear() 实现
///   - 清空后广播 WM_DESTROYCLIPBOARD，强制系统清除云剪贴板缓存
///
/// 返回 true 表示清空成功，false 表示失败。
pub fn clear_clipboard() -> bool {
    match clipboard_guard::clear() {
        Ok(()) => {
            log::info!(
                "[security] 第 5 项：剪贴板已清空（EmptyClipboard + WM_DESTROYCLIPBOARD 广播）"
            );
            true
        }
        Err(e) => {
            log::warn!("[security] 剪贴板清空失败: {}", e);
            false
        }
    }
}

/* ====================================================================== *
 *  运行时 OS 版本检测                                *
 *                                                                        *
 *  WDA_EXCLUDEFROMCAPTURE (0x11) 仅在 Windows 10 2004 (build 19041)      *
 *  及以上版本可用。旧版系统调用会返回错误，误以为截屏保护已启用。         *
 *                                                                        *
 *  使用 RtlGetVersion 获取真实版本（不受 manifest 兼容性影响）。          *
 *  结果通过 OnceLock 缓存，进程生命周期内仅检测一次。                     *
 * ====================================================================== */

use std::sync::OnceLock;

/// OS 版本信息
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

/// 缓存的 OS 版本
static OS_VERSION: OnceLock<Option<OsVersionInfo>> = OnceLock::new();

/// 获取缓存的 OS 版本（首次调用时检测，后续直接返回缓存）
fn cached_os_version() -> Option<OsVersionInfo> {
    *OS_VERSION.get_or_init(get_os_version)
}

/// 检测 OS 是否支持 WDA_EXCLUDEFROMCAPTURE
///
/// WDA_EXCLUDEFROMCAPTURE (0x11) 仅在 Windows 10 2004 (build 19041) 及以上可用。
/// 旧版系统调用 SetWindowDisplayAffinity 会返回错误，
/// 误以为截屏保护已启用，形成安全假象。
fn os_supports_exclude_from_capture() -> bool {
    if let Some(ver) = cached_os_version() {
        ver.major >= 10 && ver.build >= 19041
    } else {
        false
    }
}

/* ====================================================================== *
 *  WindowPrivacyGuard 窗口隐私状态机                 *
 *                                                                        *
 *  封装窗口隐私保护状态，防止误操作：                                     *
 *  - 持有窗口句柄和当前保护状态                                           *
 *  - 提供 enable() / disable() 方法                                       *
 *  - 内部记录状态并确保状态转换的原子性                                   *
 *  - 禁止直接使用 set_window_privacy 自由切换                             *
 * ====================================================================== */

/// 窗口隐私保护状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PrivacyState {
    /// 未启用防截屏（WDA_NONE）
    Unprotected,
    /// 已启用排除截屏捕获（WDA_EXCLUDEFROMCAPTURE，Windows 10 2004+）
    ExcludedFromCapture,
    /// 已启用排除屏幕录制（WDA_MONITOR，旧版降级模式）
    MonitorOnly,
}

/// WindowPrivacyGuard — 窗口隐私保护状态机
///
/// 封装窗口隐私状态，防止误操作
///
/// 使用方式：
/// ```ignore
/// let mut guard = WindowPrivacyGuard::new(hwnd);
/// guard.enable().ok();  // 启用防截屏
/// guard.disable().ok(); // 禁用防截屏
/// ```
///
/// 状态转换：
///   Unprotected → ExcludedFromCapture（OS 支持 19041+）
///   Unprotected → MonitorOnly（OS 不支持，降级）
///   ExcludedFromCapture → Unprotected
///   MonitorOnly → Unprotected
pub struct WindowPrivacyGuard {
    hwnd: isize,
    state: PrivacyState,
    os_supports_exclude: bool,
}

impl WindowPrivacyGuard {
    #![allow(dead_code)]
    /// 创建窗口隐私守卫
    ///
    /// 创建时检测 OS 版本，确定可用能力。
    pub fn new(hwnd: isize) -> Self {
        let os_supports = os_supports_exclude_from_capture();
        if !os_supports {
            log::warn!(
                "[window_privacy] 第 3 项：当前 OS 不支持 WDA_EXCLUDEFROMCAPTURE，\
                 将降级为 WDA_MONITOR"
            );
        }
        WindowPrivacyGuard {
            hwnd,
            state: PrivacyState::Unprotected,
            os_supports_exclude: os_supports,
        }
    }

    /// 启用窗口隐私保护
    ///
    /// 根据 OS 版本选择最佳保护模式
    /// - Windows 10 2004+ (build 19041)：使用 WDA_EXCLUDEFROMCAPTURE
    /// - 旧版系统：降级为 WDA_MONITOR
    ///
    /// 状态转换原子性 — 仅在 Unprotected 状态下可启用
    pub fn enable(&mut self) -> Result<PrivacyState, String> {
        if self.state != PrivacyState::Unprotected {
            // 已启用保护，返回当前状态（幂等操作）
            return Ok(self.state);
        }

        let (affinity, new_state) = if self.os_supports_exclude {
            // WDA_EXCLUDEFROMCAPTURE = 0x11 — 完全排除截屏捕获
            (0x11u32, PrivacyState::ExcludedFromCapture)
        } else {
            // WDA_MONITOR = 0x01 — 降级模式，仅排除屏幕录制但允许截图
            (0x01u32, PrivacyState::MonitorOnly)
        };

        if set_window_display_affinity(self.hwnd, affinity) {
            self.state = new_state;
            log::info!(
                "[window_privacy] 第 5 项：窗口隐私保护已启用 \
                 (HWND=0x{:X}, mode={:?})",
                self.hwnd,
                new_state
            );
            Ok(new_state)
        } else {
            Err(format!(
                "SetWindowDisplayAffinity(0x{:X}) 失败 (HWND=0x{:X})",
                affinity,
                self.hwnd
            ))
        }
    }

    /// 禁用窗口隐私保护
    ///
    /// 状态转换原子性 — 仅在非 Unprotected 状态下可禁用
    /// 使用 WDA_NONE (0x00) 重置窗口 DisplayAffinity
    pub fn disable(&mut self) -> Result<(), String> {
        if self.state == PrivacyState::Unprotected {
            return Ok(()); // 已未保护，幂等
        }

        if set_window_display_affinity(self.hwnd, 0x00) {
            let old_state = self.state;
            self.state = PrivacyState::Unprotected;
            log::info!(
                "[window_privacy] 第 5 项：窗口隐私保护已禁用 \
                 (HWND=0x{:X}, previous={:?})",
                self.hwnd,
                old_state
            );
            Ok(())
        } else {
            Err(format!(
                "SetWindowDisplayAffinity(WDA_NONE) 失败 (HWND=0x{:X})",
                self.hwnd
            ))
        }
    }

    /// 查询当前保护状态
    pub fn state(&self) -> PrivacyState {
        self.state
    }

    /// 查询 OS 是否支持 WDA_EXCLUDEFROMCAPTURE
    #[allow(dead_code)]
    pub fn os_supports_exclude_from_capture(&self) -> bool {
        self.os_supports_exclude
    }
}

/* ====================================================================== *
 *  底层 SetWindowDisplayAffinity 封装                                     *
 *                                                                        *
 *  根据 OS 版本选择 affinity 值                      *
 *  推荐使用 WindowPrivacyGuard 状态机替代直接调用    *
 * ====================================================================== */

/// 设置窗口显示亲和性
///
/// 此函数为底层封装，推荐使用 WindowPrivacyGuard 状态机替代。
/// 保留向后兼容性供现有调用方使用。
///
/// 若 enabled=true 但 OS 不支持 WDA_EXCLUDEFROMCAPTURE，
/// 自动降级为 WDA_MONITOR。
pub fn set_window_privacy(hwnd: isize, enabled: bool) -> bool {
    if enabled {
        let affinity = if os_supports_exclude_from_capture() {
            0x11u32 // WDA_EXCLUDEFROMCAPTURE
        } else {
            0x01u32 // WDA_MONITOR (降级)
        };
        set_window_display_affinity(hwnd, affinity)
    } else {
        set_window_display_affinity(hwnd, 0x00) // WDA_NONE
    }
}

/// 底层 SetWindowDisplayAffinity 调用
#[cfg(target_os = "windows")]
fn set_window_display_affinity(hwnd: isize, affinity: u32) -> bool {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WINDOW_DISPLAY_AFFINITY};

    unsafe {
        let hwnd = HWND(hwnd as *mut _);
        SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(affinity)).is_ok()
    }
}

#[cfg(not(target_os = "windows"))]
fn set_window_display_affinity(_hwnd: isize, _affinity: u32) -> bool {
    false
}
