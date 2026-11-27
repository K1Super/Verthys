/*
 * Win32 常量、会话事件与后端抽象
 *
 * 集中定义窗口消息 / WTS 会话 / 电源广播常量、GUID 布局、事件类型、
 * 窗口实例数据与 SessionGuardBackend trait，供各平台后端共享。
 */

use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};

/* ---------- Windows 消息常量 ---------- */
pub(super) const WM_WTSESSION_CHANGE: u32 = 0x0319;
pub(super) const WM_POWERBROADCAST: u32 = 0x0218;
pub(super) const WM_DESTROY: u32 = 0x0002;
/// WM_QUIT = 0x0012：PostQuitMessage 投递，消息循环检测到后退出
pub(super) const WM_QUIT: u32 = 0x0012;

/* WTS 会话通知代码 */
pub(super) const WTS_SESSION_LOCK: u32 = 0x7;
pub(super) const WTS_SESSION_UNLOCK: u32 = 0x8;
pub(super) const WTS_SESSION_LOGOFF: u32 = 0x6;
pub(super) const WTS_REMOTE_DISCONNECT: u32 = 0x4;
pub(super) const WTS_CONSOLE_DISCONNECT: u32 = 0x2;

/* 电源广播事件 */
pub(super) const PBT_APMSUSPEND: u32 = 0x0004;
/// 电源设置变更广播（wParam），lParam 指向 POWERBROADCAST_SETTING
pub(super) const PBT_POWERSETTINGCHANGE: u32 = 0x8011;

/// GUID_CONSOLE_DISPLAY_STATE = {6FE69556-704A-47A0-8F24-C28D936FDA47}
/// （显示器开/关状态设置，crate 未导出故本地定义；Data[0]: 0=关 1=开）
#[cfg(target_os = "windows")]
pub(super) const GUID_CONSOLE_DISPLAY_STATE: Guid = Guid {
    data1: 0x6fe6_9556,
    data2: 0x704a,
    data3: 0x47a0,
    data4: [0x8f, 0x24, 0xc2, 0x8d, 0x93, 0x6f, 0xda, 0x47],
};

/// Win32 GUID 布局（FFI 使用；与 SDK GUID 内存布局一致）
#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

/* NOTIFY_FOR_THIS_SESSION = 0 */
pub(super) const NOTIFY_FOR_THIS_SESSION: u32 = 0;

/* GWLP_USERDATA = -21：窗口用户数据槽，存储实例数据指针 */
#[cfg(target_os = "windows")]
pub(super) const GWLP_USERDATA: i32 = -21;

/// 看门狗检查间隔（秒）。工作线程的 recv_timeout 使用此值。
pub(super) const WATCHDOG_CHECK_SECS: u64 = 5;

/// 最大重启尝试次数，防止无限重启循环
pub(super) const MAX_RESTART_ATTEMPTS: u32 = 3;

/* ==================================================================== *
 *  mpsc 消息通道事件类型                            *
 *                                                                        *
 *  窗口过程仅发送事件到通道，工作线程接收后执行用户回调。                  *
 *  不依赖全局裸指针，避免 UAF 风险。                                     *
 * ==================================================================== */

/// 会话锁定原因（外部锁定事件载荷）
///
/// 与前端 `applyExternalLock(reason)` 的字符串约定对齐：
/// session-lock / logoff / disconnect / suspend / display-off。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLockReason {
    SessionLock,
    Logoff,
    Disconnect,
    Suspend,
    DisplayOff,
}

impl SessionLockReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionLockReason::SessionLock => "session-lock",
            SessionLockReason::Logoff => "logoff",
            SessionLockReason::Disconnect => "disconnect",
            SessionLockReason::Suspend => "suspend",
            SessionLockReason::DisplayOff => "display-off",
        }
    }
}

/// 会话事件（通过 mpsc 通道传递）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionEvent {
    /// 系统锁屏 / 注销 / 会话断开（携带具体原因）
    Lock(SessionLockReason),
    /// 系统解锁
    Unlock,
    /// 电源挂起（恒触发锁定；原因在回调内固定为 Suspend）
    PowerSuspend,
    /// 显示器关闭（高安全模式下触发锁定；源自
    /// GUID_CONSOLE_DISPLAY_STATE 电源设置广播）
    DisplayOff,
    /// 关闭信号（stop 时发送，工作线程退出）
    Shutdown,
}

/* ==================================================================== *
 *  窗口实例数据                            *
 *                                                                        *
 *  每个窗口实例拥有独立的 WindowInstanceData，通过 GWLP_USERDATA 存储      *
 *  在窗口上。包含事件发送器和高安全模式标志。                              *
 *  不依赖任何全局静态变量，允许多实例。                                    *
 * ==================================================================== */

/// 窗口实例数据（存储在 GWLP_USERDATA 上）
///
/// high_security 为 Arc<AtomicBool>，
/// 由 SessionGuard 和窗口过程共享，不使用全局变量。
pub(super) struct WindowInstanceData {
    /// 事件发送器（Mutex 包装以满足 Sync 要求）
    pub(super) event_tx: Mutex<mpsc::Sender<SessionEvent>>,
    /// 高安全模式标志（实例级，非全局）
    pub(super) high_security: Arc<AtomicBool>,
}

/* ==================================================================== *
 *  平台抽象层                                        *
 *                                                                        *
 *  定义 SessionGuardBackend trait，Windows 实现基于隐藏窗口，             *
 *  非 Windows 平台返回错误但不阻止应用启动。                              *
 * ==================================================================== */

/// 会话守卫后端 trait（平台抽象）
pub(super) trait SessionGuardBackend: Send {
    /// 启动会话监听
    fn start(&mut self) -> Result<(), String>;
    /// 停止会话监听
    fn stop(&mut self);
    /// 设置高安全模式
    fn set_high_security(&self, enabled: bool);
    /// 查询是否正在运行
    fn is_running(&self) -> bool;
}
