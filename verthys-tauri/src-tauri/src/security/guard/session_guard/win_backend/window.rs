/*
 * 隐藏窗口、窗口过程与消息循环
 *
 * 窗口类通过 std::sync::Once 仅注册一次，允许多实例；实例数据经
 * GWLP_USERDATA 挂载，窗口过程只向 mpsc 通道投递事件并立即返回；
 * 消息循环使用 PeekMessageW 非阻塞轮询，配合 stop_flag 自主退出。
 */

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::super::types::{
    Guid, SessionEvent, SessionLockReason, WindowInstanceData, GUID_CONSOLE_DISPLAY_STATE,
    GWLP_USERDATA, NOTIFY_FOR_THIS_SESSION, PBT_APMSUSPEND, PBT_POWERSETTINGCHANGE, WM_DESTROY,
    WM_POWERBROADCAST, WM_QUIT, WM_WTSESSION_CHANGE, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT,
    WTS_SESSION_LOCK, WTS_SESSION_LOGOFF, WTS_SESSION_UNLOCK,
};

/* ---------- Windows 原始 FFI 声明 ---------- */
#[link(name = "user32")]
extern "system" {
    fn CreateWindowExW(
        dwExStyle: u32,
        lpClassName: *const u16,
        lpWindowName: *const u16,
        dwStyle: u32,
        x: i32,
        y: i32,
        nWidth: i32,
        nHeight: i32,
        hWndParent: isize,
        hMenu: isize,
        hInstance: isize,
        lpParam: *const u8,
    ) -> isize;

    fn DefWindowProcW(hWnd: isize, Msg: u32, wParam: usize, lParam: isize) -> isize;

    fn DestroyWindow(hWnd: isize) -> i32;

    fn PeekMessageW(
        lpMsg: *mut Msg,
        hWnd: isize,
        wMsgFilterMin: u32,
        wMsgFilterMax: u32,
        wRemoveMsg: u32,
    ) -> i32;

    fn TranslateMessage(lpMsg: *const Msg) -> i32;

    fn DispatchMessageW(lpMsg: *const Msg) -> isize;

    fn PostQuitMessage(nExitCode: i32);

    fn RegisterClassExW(lpWndClass: *const WndClassExW) -> u16;

    fn GetWindowLongPtrW(hWnd: isize, nIndex: i32) -> isize;

    fn SetWindowLongPtrW(hWnd: isize, nIndex: i32, dwNewLong: isize) -> isize;
}

/// PM_REMOVE 常量
const PM_REMOVE: u32 = 0x0001;

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
    fn GetModuleHandleW(lpModuleName: *const u16) -> isize;
    fn LoadLibraryW(lpLibFileName: *const u16) -> isize;
    fn GetProcAddress(hModule: isize, lpProcName: *const u8) -> *const u8;
}

/* ---------- 电源设置通知 FFI（user32） ----------
 * RegisterPowerSettingNotification 返回 HPOWERNOTIFY 句柄（非零成功），
 * 须与 UnregisterPowerSettingNotification 配对，防止句柄泄漏。
 */
#[link(name = "user32")]
extern "system" {
    fn RegisterPowerSettingNotification(
        hwnd: isize,
        powersettingguid: *const Guid,
        flags: u32,
    ) -> isize;
    pub(super) fn UnregisterPowerSettingNotification(handle: isize) -> i32;
}

/// POWERBROADCAST_SETTING（WM_POWERBROADCAST + PBT_POWERSETTINGCHANGE
/// 时 lParam 指向的结构：GUID + 数据长度 + 柔性数组首字节）
#[repr(C)]
struct PowerBroadcastSetting {
    power_setting: Guid,
    data_length: u32,
    data: [u8; 1],
}

/* ---------- FFI 结构体 ---------- */
#[repr(C)]
#[derive(Default)]
#[allow(non_snake_case)]
struct WndClassExW {
    cbSize: u32,
    style: u32,
    lpfnWndProc: Option<unsafe extern "system" fn(isize, u32, usize, isize) -> isize>,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: isize,
    hIcon: isize,
    hCursor: isize,
    hbrBackground: isize,
    lpszMenuName: *const u16,
    lpszClassName: *const u16,
    hIconSm: isize,
}

#[repr(C)]
#[derive(Default)]
struct Msg {
    hwnd: isize,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt_x: i32,
    pt_y: i32,
}

/* ---------- 辅助函数 ---------- */

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    if v.last() != Some(&0) {
        v.push(0);
    }
    v
}

/* ---------- WTS API 动态加载 ---------- */
#[allow(non_camel_case_types)]
type WTSRegisterSessionNotification_t = unsafe extern "system" fn(isize, u32) -> i32;

#[allow(non_camel_case_types)]
pub(super) type WTSUnRegisterSessionNotification_t = unsafe extern "system" fn(isize) -> i32;

fn load_wts_api() -> (
    Option<WTSRegisterSessionNotification_t>,
    Option<WTSUnRegisterSessionNotification_t>,
) {
    unsafe {
        let wide = to_wide("wtsapi32.dll");
        let lib = LoadLibraryW(wide.as_ptr());
        if lib == 0 {
            return (None, None);
        }

        let reg_name = b"WTSRegisterSessionNotification\0";
        let reg_proc = GetProcAddress(lib, reg_name.as_ptr());
        let reg: Option<WTSRegisterSessionNotification_t> = if reg_proc.is_null() {
            None
        } else {
            Some(std::mem::transmute::<
                *const u8,
                WTSRegisterSessionNotification_t,
            >(reg_proc))
        };

        let unreg_name = b"WTSUnRegisterSessionNotification\0";
        let unreg_proc = GetProcAddress(lib, unreg_name.as_ptr());
        let unreg: Option<WTSUnRegisterSessionNotification_t> = if unreg_proc.is_null() {
            None
        } else {
            Some(std::mem::transmute::<
                *const u8,
                WTSUnRegisterSessionNotification_t,
            >(unreg_proc))
        };

        (reg, unreg)
    }
}

/* ==================================================================== *
 *  窗口类注册（Once，仅注册一次，允许多实例）       *
 * ==================================================================== */

static CLASS_REGISTERED: std::sync::Once = std::sync::Once::new();

/// 注册窗口类（进程级仅一次）
///
/// 使用 std::sync::Once 保证窗口类仅注册一次，允许多个 SessionGuard 实例。
/// 不在 Drop 中 UnregisterClassW：类随进程退出自动清理，
/// 避免"类残留"和"多次注册"的竞态问题。
fn register_window_class_once() {
    CLASS_REGISTERED.call_once(|| unsafe {
        let class_name = to_wide("VerthysSecGuard");
        let hinst = GetModuleHandleW(std::ptr::null());

        let wc = WndClassExW {
            cbSize: std::mem::size_of::<WndClassExW>() as u32,
            lpfnWndProc: Some(window_proc),
            hInstance: hinst,
            lpszClassName: class_name.as_ptr(),
            ..Default::default()
        };

        let atom = RegisterClassExW(&wc);
        if atom == 0 {
            let err = GetLastError();
            log::error!(
                "[session_guard] RegisterClassExW 失败: GetLastError={}",
                err
            );
        } else {
            log::debug!("[session_guard] 窗口类已注册 (atom={})", atom);
        }
    });
}

/* ==================================================================== *
 *  窗口过程                     *
 *                                                                        *
 *  仅发送事件到 mpsc 通道，立即返回。                                    *
 *  不调用任何剪贴板 API、不执行用户回调、不阻塞消息循环。                *
 *  实例数据通过 GWLP_USERDATA 获取（非全局变量）。                       *
 * ==================================================================== */

unsafe extern "system" fn window_proc(
    hwnd: isize,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    // 从 GWLP_USERDATA 获取实例数据（非全局变量）
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const WindowInstanceData;
    if ptr.is_null() {
        // 窗口创建期间 GWLP_USERDATA 尚未设置，走默认处理
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    let data = &*ptr;

    match msg {
        WM_WTSESSION_CHANGE => {
            let code = wparam as u32;
            let event = match code {
                WTS_SESSION_LOCK => Some(SessionEvent::Lock(SessionLockReason::SessionLock)),
                WTS_SESSION_LOGOFF => Some(SessionEvent::Lock(SessionLockReason::Logoff)),
                WTS_REMOTE_DISCONNECT | WTS_CONSOLE_DISCONNECT => {
                    Some(SessionEvent::Lock(SessionLockReason::Disconnect))
                }
                WTS_SESSION_UNLOCK => Some(SessionEvent::Unlock),
                _ => None,
            };
            if let Some(ev) = event {
                // 仅发送事件到通道，不执行回调
                if let Ok(tx) = data.event_tx.lock() {
                    let _ = tx.send(ev);
                }
            }
            0
        }
        WM_POWERBROADCAST => {
            // 从实例数据读取高安全标志（非全局变量）：
            // 挂起与显示器关闭两项硬化事件均仅在高安全模式下触发锁定
            if data.high_security.load(Ordering::SeqCst) {
                match wparam as u32 {
                    PBT_APMSUSPEND => {
                        if let Ok(tx) = data.event_tx.lock() {
                            let _ = tx.send(SessionEvent::PowerSuspend);
                        }
                    }
                    // lParam 为 POWERBROADCAST_SETTING 指针，仅在
                    // 本消息处理期间有效；逐字段判别后立即转事件
                    PBT_POWERSETTINGCHANGE if lparam != 0 => {
                        let setting = lparam as *const PowerBroadcastSetting;
                        let s = unsafe { &*setting };
                        if s.power_setting == GUID_CONSOLE_DISPLAY_STATE
                            && s.data_length >= 1
                            && s.data[0] == 0
                        {
                            // 显示器关闭（Data[0]=0）
                            if let Ok(tx) = data.event_tx.lock() {
                                let _ = tx.send(SessionEvent::DisplayOff);
                            }
                        }
                    }
                    _ => {}
                }
            }
            1 /* TRUE — 确认电源广播 */
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/* ==================================================================== *
 *  窗口创建 + 消息循环                                                   *
 * ==================================================================== */

/// 创建隐藏窗口并注册 WTS 会话通知 + 显示器电源设置通知
///
/// 窗口类通过 Once 仅注册一次。
/// 实例数据通过 GWLP_USERDATA 存储在窗口上。
///
/// 返回 (HWND, WTS 注销函数, HPOWERNOTIFY 句柄)。显示器电源设置
/// 通知注册失败不视为致命（退化为仅监听系统挂起）。
pub(super) fn create_guard_window(
    instance_data: &Arc<WindowInstanceData>,
) -> Result<(isize, WTSUnRegisterSessionNotification_t, isize), String> {
    unsafe {
        register_window_class_once();

        let class_name = to_wide("VerthysSecGuard");
        let hinst = GetModuleHandleW(std::ptr::null());

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            hinst,
            std::ptr::null(),
        );

        if hwnd == 0 {
            return Err(format!(
                "CreateWindowExW 失败: GetLastError={}",
                GetLastError()
            ));
        }

        // 设置实例数据到 GWLP_USERDATA
        let ptr = Arc::as_ptr(instance_data) as isize;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, ptr);

        // 注册 WTS 会话通知
        let (reg, unreg) = load_wts_api();
        let reg_fn = reg.ok_or("无法加载 WTSRegisterSessionNotification")?;
        let unreg_fn = unreg.ok_or("无法加载 WTSUnRegisterSessionNotification")?;

        if reg_fn(hwnd, NOTIFY_FOR_THIS_SESSION) == 0 {
            let err = GetLastError();
            let _ = DestroyWindow(hwnd);
            return Err(format!(
                "WTSRegisterSessionNotification 失败: GetLastError={}",
                err
            ));
        }

        // 注册显示器开/关状态通知（display-off 锁定的信号源）。
        // 注册失败仅告警降级：系统挂起监听不受影响。
        let power_notify = RegisterPowerSettingNotification(
            hwnd,
            &GUID_CONSOLE_DISPLAY_STATE,
            NOTIFY_FOR_THIS_SESSION,
        );
        if power_notify == 0 {
            log::warn!(
                "[session_guard] 显示器电源设置通知注册失败 (GetLastError={})，\
                 display-off 锁定降级为仅监听系统挂起",
                GetLastError()
            );
        }

        Ok((hwnd, unreg_fn, power_notify))
    }
}

/// 消息循环线程主函数
///
/// 使用 PeekMessageW 非阻塞轮询，配合 stop_flag 实现线程自主退出。
/// 检测到 WM_QUIT（窗口被外部销毁）时退出，由看门狗重启。
pub(super) fn run_message_loop(hwnd: isize, stop_flag: Arc<AtomicBool>) {
    unsafe {
        loop {
            let mut msg: Msg = Default::default();
            let has_msg = PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE);
            if has_msg != 0 {
                // 检测 WM_QUIT（窗口被外部销毁）
                if msg.message == WM_QUIT {
                    log::warn!("[session_guard] 收到 WM_QUIT，窗口可能已被外部销毁，消息循环退出");
                    break;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            } else if stop_flag.load(Ordering::SeqCst) {
                // 主动停止：销毁窗口并退出
                if hwnd != 0 {
                    let _ = DestroyWindow(hwnd);
                }
                break;
            } else {
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}
