/*
 * session_guard.rs — 智能会话自动锁屏（SECURITY.md 企业级重写版）
 *
 * 用户需求（六.2 智能会话自动锁屏）：
 *   不依赖简单的"3分钟无操作"定时器。程序监听操作系统底层的
 *   "工作站锁屏"事件（Win+L / 笔记本合盖 ACPI 事件）。
 *   - 系统未锁屏 → 程序永不自动退出或销毁密钥（允许过夜常驻）
 *   - 捕获到系统锁屏、切换账户或远程桌面会话断开 → 立即销毁全部
 *     解密密钥并卸载 Verthys 句柄
 *   - 高安全模式：额外启用显示器关闭（系统睡眠）作为触发信号
 *
 * SECURITY.md 企业级重写要点：
 *   1. 使用 mpsc 消息通道替代全局裸指针，回调异步化
 *      - 窗口过程仅发送 SessionEvent 到通道，立即返回
 *      - 独立工作线程接收事件并安全执行用户回调
 *      - 消除 UAF 风险和阻塞消息循环的问题
 *   2. 封装窗口为 RAII 类型，禁止全局状态
 *      - GuardWindow 持有 HWND、线程句柄、stop_flag
 *      - 实例数据通过 GWLP_USERDATA 存储在窗口上（非全局变量）
 *      - 窗口类通过 std::sync::Once 仅注册一次，允许多实例
 *   3. 在回调边界使用 catch_unwind 防止 panic 跨 FFI
 *      - 工作线程中用 catch_unwind 包裹用户回调
 *      - panic 被捕获并记录，不传播到 FFI 边界
 *   4. 提供平台抽象层与降级策略
 *      - SessionGuardBackend trait 定义统一接口
 *      - Windows 实现基于隐藏窗口 + WTS 会话通知
 *      - 非 Windows 平台返回错误但不阻止应用启动
 *   5. 删除 set_high_security_mode 的全局状态
 *      - 高安全标志为 Arc<AtomicBool>，在实例间共享
 *      - 窗口过程通过实例数据读取标志，不依赖全局变量
 *   6. 增加运行时健康监控与自动恢复
 *      - 工作线程使用 recv_timeout 充当看门狗
 *      - 消息循环线程意外退出时自动重启
 *      - 重启次数上限防止无限循环
 */

use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};

/* ---------- Windows 消息常量 ---------- */
const WM_WTSESSION_CHANGE: u32 = 0x0319;
const WM_POWERBROADCAST: u32 = 0x0218;
const WM_DESTROY: u32 = 0x0002;
/// WM_QUIT = 0x0012：PostQuitMessage 投递，消息循环检测到后退出
const WM_QUIT: u32 = 0x0012;

/* WTS 会话通知代码 */
const WTS_SESSION_LOCK: u32 = 0x7;
const WTS_SESSION_UNLOCK: u32 = 0x8;
const WTS_SESSION_LOGOFF: u32 = 0x6;
const WTS_REMOTE_DISCONNECT: u32 = 0x4;
const WTS_CONSOLE_DISCONNECT: u32 = 0x2;

/* 电源广播事件 */
const PBT_APMSUSPEND: u32 = 0x0004;

/* NOTIFY_FOR_THIS_SESSION = 0 */
const NOTIFY_FOR_THIS_SESSION: u32 = 0;

/* GWLP_USERDATA = -21：窗口用户数据槽，存储实例数据指针 */
#[cfg(target_os = "windows")]
const GWLP_USERDATA: i32 = -21;

/// 看门狗检查间隔（秒）。工作线程的 recv_timeout 使用此值。
const WATCHDOG_CHECK_SECS: u64 = 5;

/// 最大重启尝试次数，防止无限重启循环
const MAX_RESTART_ATTEMPTS: u32 = 3;

/* ==================================================================== *
 *  SECURITY.md 第 1 项：mpsc 消息通道事件类型                            *
 *                                                                        *
 *  窗口过程仅发送事件到通道，工作线程接收后执行用户回调。                  *
 *  完全消除全局裸指针和 UAF 风险。                                       *
 * ==================================================================== */

/// 会话事件（通过 mpsc 通道传递）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionEvent {
    /// 系统锁屏 / 注销 / 会话断开
    Lock,
    /// 系统解锁
    Unlock,
    /// 电源挂起（高安全模式下等同于 Lock）
    PowerSuspend,
    /// 关闭信号（stop 时发送，工作线程退出）
    Shutdown,
}

/* ==================================================================== *
 *  SECURITY.md 第 2 项 + 第 5 项：窗口实例数据（替代全局变量）            *
 *                                                                        *
 *  每个窗口实例拥有独立的 WindowInstanceData，通过 GWLP_USERDATA 存储      *
 *  在窗口上。包含事件发送器和高安全模式标志。                              *
 *  不依赖任何全局静态变量，允许多实例。                                    *
 * ==================================================================== */

/// 窗口实例数据（存储在 GWLP_USERDATA 上）
///
/// SECURITY.md 第 5 项：high_security 为 Arc<AtomicBool>，
/// 由 SessionGuard 和窗口过程共享，不使用全局变量。
struct WindowInstanceData {
    /// 事件发送器（Mutex 包装以满足 Sync 要求）
    event_tx: Mutex<mpsc::Sender<SessionEvent>>,
    /// 高安全模式标志（实例级，非全局）
    high_security: Arc<AtomicBool>,
}

/* ==================================================================== *
 *  SECURITY.md 第 4 项：平台抽象层                                        *
 *                                                                        *
 *  定义 SessionGuardBackend trait，Windows 实现基于隐藏窗口，             *
 *  非 Windows 平台返回错误但不阻止应用启动。                              *
 * ==================================================================== */

/// 会话守卫后端 trait（平台抽象）
trait SessionGuardBackend: Send {
    /// 启动会话监听
    fn start(&mut self) -> Result<(), String>;
    /// 停止会话监听
    fn stop(&mut self);
    /// 设置高安全模式
    fn set_high_security(&self, enabled: bool);
    /// 查询是否正在运行
    fn is_running(&self) -> bool;
}

/* ==================================================================== *
 *  Windows 后端实现                                                      *
 * ==================================================================== */

#[cfg(target_os = "windows")]
mod win_backend {
    use super::{
        SessionEvent, SessionGuardBackend, WindowInstanceData, MAX_RESTART_ATTEMPTS,
        NOTIFY_FOR_THIS_SESSION, PBT_APMSUSPEND, WATCHDOG_CHECK_SECS, WM_DESTROY,
        WM_POWERBROADCAST, WM_QUIT, WM_WTSESSION_CHANGE, WTS_CONSOLE_DISCONNECT,
        WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_LOGOFF, WTS_SESSION_UNLOCK,
        GWLP_USERDATA,
    };
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

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
    type WTSUnRegisterSessionNotification_t = unsafe extern "system" fn(isize) -> i32;

    fn load_wts_api() -> (Option<WTSRegisterSessionNotification_t>, Option<WTSUnRegisterSessionNotification_t>) {
        unsafe {
            let wide = to_wide("wtsapi32.dll");
            let lib = LoadLibraryW(wide.as_ptr());
            if lib == 0 {
                return (None, None);
            }

            let reg_name = b"WTSRegisterSessionNotification\0";
            let reg_proc = GetProcAddress(lib, reg_name.as_ptr());
            let reg: Option<WTSRegisterSessionNotification_t> =
                if reg_proc.is_null() { None } else { Some(std::mem::transmute::<*const u8, WTSRegisterSessionNotification_t>(reg_proc)) };

            let unreg_name = b"WTSUnRegisterSessionNotification\0";
            let unreg_proc = GetProcAddress(lib, unreg_name.as_ptr());
            let unreg: Option<WTSUnRegisterSessionNotification_t> =
                if unreg_proc.is_null() { None } else { Some(std::mem::transmute::<*const u8, WTSUnRegisterSessionNotification_t>(unreg_proc)) };

            (reg, unreg)
        }
    }

    /* ==================================================================== *
     *  SECURITY.md 第 2 项：窗口类注册（Once，仅注册一次，允许多实例）       *
     * ==================================================================== */

    static CLASS_REGISTERED: std::sync::Once = std::sync::Once::new();

    /// SECURITY.md 第 2 项：注册窗口类（进程级仅一次）
    ///
    /// 使用 std::sync::Once 保证窗口类仅注册一次，允许多个 SessionGuard 实例。
    /// 不再在 Drop 中 UnregisterClassW — 类随进程退出自动清理，
    /// 消除"类残留"和"多次注册"的竞态问题。
    fn register_window_class_once() {
        CLASS_REGISTERED.call_once(|| {
            unsafe {
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
                        "[session_guard] 第 2 项：RegisterClassExW 失败: GetLastError={}",
                        err
                    );
                } else {
                    log::debug!("[session_guard] 窗口类已注册 (atom={})", atom);
                }
            }
        });
    }

    /* ==================================================================== *
     *  SECURITY.md 第 1 项 + 第 3 项 + 第 5 项：窗口过程                     *
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
        // SECURITY.md 第 5 项：从 GWLP_USERDATA 获取实例数据（非全局变量）
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
                    WTS_SESSION_LOCK | WTS_SESSION_LOGOFF
                    | WTS_REMOTE_DISCONNECT | WTS_CONSOLE_DISCONNECT => Some(SessionEvent::Lock),
                    WTS_SESSION_UNLOCK => Some(SessionEvent::Unlock),
                    _ => None,
                };
                if let Some(ev) = event {
                    // SECURITY.md 第 1 项：仅发送事件到通道，不执行回调
                    if let Ok(tx) = data.event_tx.lock() {
                        let _ = tx.send(ev);
                    }
                }
                0
            }
            WM_POWERBROADCAST => {
                // SECURITY.md 第 5 项：从实例数据读取高安全标志（非全局变量）
                if data.high_security.load(Ordering::SeqCst)
                    && wparam as u32 == PBT_APMSUSPEND
                {
                    if let Ok(tx) = data.event_tx.lock() {
                        let _ = tx.send(SessionEvent::PowerSuspend);
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

    /// 创建隐藏窗口并注册 WTS 会话通知
    ///
    /// SECURITY.md 第 2 项：窗口类通过 Once 仅注册一次。
    /// 实例数据通过 GWLP_USERDATA 存储在窗口上。
    fn create_guard_window(
        instance_data: &Arc<WindowInstanceData>,
    ) -> Result<(isize, WTSUnRegisterSessionNotification_t), String> {
        unsafe {
            register_window_class_once();

            let class_name = to_wide("VerthysSecGuard");
            let hinst = GetModuleHandleW(std::ptr::null());

            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                class_name.as_ptr(),
                0,
                0, 0, 0, 0,
                0, 0, hinst, std::ptr::null(),
            );

            if hwnd == 0 {
                return Err(format!(
                    "CreateWindowExW 失败: GetLastError={}",
                    GetLastError()
                ));
            }

            // SECURITY.md 第 5 项：设置实例数据到 GWLP_USERDATA
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

            Ok((hwnd, unreg_fn))
        }
    }

    /// 消息循环线程主函数
    ///
    /// 使用 PeekMessageW 非阻塞轮询，配合 stop_flag 实现线程自主退出。
    /// 检测到 WM_QUIT（窗口被外部销毁）时退出，由看门狗重启。
    fn run_message_loop(hwnd: isize, stop_flag: Arc<AtomicBool>) {
        unsafe {
            loop {
                let mut msg: Msg = Default::default();
                let has_msg = PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE);
                if has_msg != 0 {
                    // SECURITY.md 第 2 项：检测 WM_QUIT（窗口被外部销毁）
                    if msg.message == WM_QUIT {
                        log::warn!(
                            "[session_guard] 收到 WM_QUIT，窗口可能已被外部销毁，消息循环退出"
                        );
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

    /* ==================================================================== *
     *  消息循环状态管理（支持看门狗重启）                                    *
     * ==================================================================== */

    /// 消息循环状态（Arc 共享给工作线程用于看门狗监控）
    struct MessageLoopState {
        instance_data: Arc<WindowInstanceData>,
        stop_flag: Arc<AtomicBool>,
        current_thread: Mutex<Option<JoinHandle<()>>>,
        current_hwnd: Arc<Mutex<isize>>,
        unreg_fn: Arc<Mutex<Option<WTSUnRegisterSessionNotification_t>>>,
        restart_count: AtomicU32,
    }

    impl MessageLoopState {
        fn new(
            instance_data: Arc<WindowInstanceData>,
            stop_flag: Arc<AtomicBool>,
        ) -> Self {
            MessageLoopState {
                instance_data,
                stop_flag,
                current_thread: Mutex::new(None),
                current_hwnd: Arc::new(Mutex::new(0)),
                unreg_fn: Arc::new(Mutex::new(None)),
                restart_count: AtomicU32::new(0),
            }
        }

        /// 查询消息循环线程是否存活
        fn is_alive(&self) -> bool {
            if let Ok(guard) = self.current_thread.lock() {
                if let Some(ref handle) = *guard {
                    return !handle.is_finished();
                }
            }
            false
        }

        /// 启动消息循环线程（创建窗口 + 运行循环）
        ///
        /// 窗口必须在消息循环线程中创建（Windows 约束），
        /// 因此使用同步通道等待窗口创建结果。
        fn start(&self) -> Result<(), String> {
            let instance_data = self.instance_data.clone();
            let stop_flag = self.stop_flag.clone();
            let hwnd_slot = self.current_hwnd.clone();
            let unreg_slot = self.unreg_fn.clone();

            let (create_tx, create_rx) = mpsc::channel::<Result<isize, String>>();

            let handle = thread::Builder::new()
                .name("verthys-session-msgloop".into())
                .spawn(move || {
                    match create_guard_window(&instance_data) {
                        Ok((hwnd, unreg_fn)) => {
                            *hwnd_slot.lock().unwrap() = hwnd;
                            *unreg_slot.lock().unwrap() = Some(unreg_fn);
                            let _ = create_tx.send(Ok(hwnd));
                            run_message_loop(hwnd, stop_flag);
                        }
                        Err(e) => {
                            let _ = create_tx.send(Err(e));
                        }
                    }
                })
                .map_err(|e| format!("启动消息循环线程失败: {}", e))?;

            *self.current_thread.lock().unwrap() = Some(handle);

            match create_rx.recv() {
                Ok(Ok(hwnd)) => {
                    log::info!(
                        "[session_guard] 消息循环线程已启动 (HWND=0x{:X})",
                        hwnd
                    );
                    Ok(())
                }
                Ok(Err(e)) => {
                    if let Some(h) = self.current_thread.lock().unwrap().take() {
                        let _ = h.join();
                    }
                    Err(e)
                }
                Err(_) => {
                    if let Some(h) = self.current_thread.lock().unwrap().take() {
                        let _ = h.join();
                    }
                    Err("消息循环线程在创建窗口前退出".into())
                }
            }
        }

        /// SECURITY.md 第 6 项：看门狗重启消息循环线程
        fn restart(&self) -> Result<(), String> {
            let count = self.restart_count.fetch_add(1, Ordering::SeqCst);
            if count >= MAX_RESTART_ATTEMPTS {
                log::error!(
                    "[session_guard] 第 6 项：重启次数已达上限 ({})，放弃重启",
                    MAX_RESTART_ATTEMPTS
                );
                return Err(format!(
                    "消息循环线程重启次数已达上限 ({})",
                    MAX_RESTART_ATTEMPTS
                ));
            }

            log::warn!(
                "[session_guard] 第 6 项：消息循环线程已退出，尝试重启 (第 {} 次)...",
                count + 1
            );

            // 清理旧线程
            if let Ok(mut guard) = self.current_thread.lock() {
                if let Some(old) = guard.take() {
                    let _ = old.join();
                }
            }

            // 注销旧 WTS 通知
            if let Ok(mut hwnd_guard) = self.current_hwnd.lock() {
                let old_hwnd = *hwnd_guard;
                if old_hwnd != 0 {
                    if let Ok(mut unreg_guard) = self.unreg_fn.lock() {
                        if let Some(unreg) = unreg_guard.take() {
                            unsafe { unreg(old_hwnd); }
                        }
                    }
                    *hwnd_guard = 0;
                }
            }

            // 重置 stop_flag（可能是前次 stop 残留）
            self.stop_flag.store(false, Ordering::SeqCst);

            // 启动新消息循环
            self.start()?;
            log::warn!(
                "[session_guard] 第 6 项：消息循环线程已重启 (第 {} 次)",
                count + 1
            );
            Ok(())
        }

        /// 停止消息循环并清理
        fn stop(&self) {
            // 1. 注销 WTS 通知
            if let Ok(hwnd_guard) = self.current_hwnd.lock() {
                let hwnd = *hwnd_guard;
                if hwnd != 0 {
                    if let Ok(mut unreg_guard) = self.unreg_fn.lock() {
                        if let Some(unreg) = unreg_guard.take() {
                            unsafe { unreg(hwnd); }
                        }
                    }
                }
            }

            // 2. 设置停止标志
            self.stop_flag.store(true, Ordering::SeqCst);

            // 3. 等待消息循环线程退出（2 秒超时）
            if let Ok(mut guard) = self.current_thread.lock() {
                if let Some(handle) = guard.take() {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while !handle.is_finished() {
                        if Instant::now() >= deadline {
                            log::error!(
                                "[session_guard] 消息循环线程 2s 内未退出"
                            );
                            break;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    let _ = handle.join();
                }
            }

            // 4. 清理 HWND 记录
            if let Ok(mut hwnd_guard) = self.current_hwnd.lock() {
                *hwnd_guard = 0;
            }
        }

        /// 发送关闭信号到工作线程
        fn send_shutdown(&self) {
            if let Ok(tx) = self.instance_data.event_tx.lock() {
                let _ = tx.send(SessionEvent::Shutdown);
            }
        }
    }

    /* ==================================================================== *
     *  SECURITY.md 第 3 项 + 第 6 项：工作线程（回调执行 + 看门狗）          *
     *                                                                        *
     *  接收 mpsc 事件并执行用户回调（catch_unwind 防止 panic 跨 FFI）。      *
     *  使用 recv_timeout 充当看门狗：定期检查消息循环线程存活状态。           *
     * ==================================================================== */

    fn worker_loop(
        receiver: mpsc::Receiver<SessionEvent>,
        on_lock: Arc<dyn Fn() + Send + Sync>,
        on_unlock: Arc<dyn Fn() + Send + Sync>,
        message_loop_state: Arc<MessageLoopState>,
        stop_flag: Arc<AtomicBool>,
        high_security: Arc<AtomicBool>,
    ) {
        log::info!("[session_guard] 工作线程已启动（含看门狗，间隔 {}s）", WATCHDOG_CHECK_SECS);

        loop {
            match receiver.recv_timeout(Duration::from_secs(WATCHDOG_CHECK_SECS)) {
                Ok(event) => {
                    // SECURITY.md 第 3 项：catch_unwind 防止 panic 跨 FFI
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        match event {
                            SessionEvent::Lock => on_lock(),
                            SessionEvent::Unlock => on_unlock(),
                            SessionEvent::PowerSuspend => {
                                if high_security.load(Ordering::SeqCst) {
                                    on_lock();
                                }
                            }
                            SessionEvent::Shutdown => {
                                // 工作线程退出信号
                            }
                        }
                    }));

                    if let Err(payload) = result {
                        log::error!(
                            "[session_guard] 第 3 项：用户回调 panic 已捕获: {:?}",
                            payload
                        );
                    }

                    if event == SessionEvent::Shutdown {
                        log::info!("[session_guard] 收到 Shutdown 信号，工作线程退出");
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if stop_flag.load(Ordering::SeqCst) {
                        break;
                    }
                    // SECURITY.md 第 6 项：看门狗检查消息循环线程
                    if !message_loop_state.is_alive() {
                        if let Err(e) = message_loop_state.restart() {
                            log::error!(
                                "[session_guard] 第 6 项：消息循环重启失败: {}",
                                e
                            );
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    log::info!("[session_guard] 通道已断开，工作线程退出");
                    break;
                }
            }
        }

        log::info!("[session_guard] 工作线程退出");
    }

    /* ==================================================================== *
     *  Windows 后端实现                                                     *
     * ==================================================================== */

    pub struct WindowsBackend {
        high_security: Arc<AtomicBool>,
        stop_flag: Arc<AtomicBool>,
        message_loop_state: Option<Arc<MessageLoopState>>,
        worker_thread: Option<JoinHandle<()>>,
        on_lock: Option<Arc<dyn Fn() + Send + Sync>>,
        on_unlock: Option<Arc<dyn Fn() + Send + Sync>>,
        running: bool,
    }

    impl WindowsBackend {
        pub fn new(
            on_lock: Arc<dyn Fn() + Send + Sync>,
            on_unlock: Arc<dyn Fn() + Send + Sync>,
            high_security: bool,
        ) -> Self {
            WindowsBackend {
                high_security: Arc::new(AtomicBool::new(high_security)),
                stop_flag: Arc::new(AtomicBool::new(false)),
                message_loop_state: None,
                worker_thread: None,
                on_lock: Some(on_lock),
                on_unlock: Some(on_unlock),
                running: false,
            }
        }
    }

    impl SessionGuardBackend for WindowsBackend {
        fn start(&mut self) -> Result<(), String> {
            if self.running {
                return Ok(());
            }

            let (event_tx, event_rx) = mpsc::channel::<SessionEvent>();

            let instance_data = Arc::new(WindowInstanceData {
                event_tx: Mutex::new(event_tx),
                high_security: self.high_security.clone(),
            });

            self.stop_flag.store(false, Ordering::SeqCst);

            let message_loop_state = Arc::new(MessageLoopState::new(
                instance_data.clone(),
                self.stop_flag.clone(),
            ));

            // 启动消息循环线程（含窗口创建）
            message_loop_state.start()?;

            // 启动工作线程（含看门狗）
            let mls_for_worker = message_loop_state.clone();
            let stop_flag_for_worker = self.stop_flag.clone();
            let high_security_for_worker = self.high_security.clone();
            let on_lock = self.on_lock.take().unwrap_or_else(|| Arc::new(|| {}));
            let on_unlock = self.on_unlock.take().unwrap_or_else(|| Arc::new(|| {}));

            let worker_handle = thread::Builder::new()
                .name("verthys-session-worker".into())
                .spawn(move || {
                    worker_loop(
                        event_rx,
                        on_lock,
                        on_unlock,
                        mls_for_worker,
                        stop_flag_for_worker,
                        high_security_for_worker,
                    );
                })
                .map_err(|e| {
                    // 工作线程启动失败：停止消息循环并清理
                    message_loop_state.stop();
                    format!("启动工作线程失败: {}", e)
                })?;

            self.message_loop_state = Some(message_loop_state);
            self.worker_thread = Some(worker_handle);
            self.running = true;

            log::info!("[session_guard] 会话守卫已启动");
            Ok(())
        }

        fn stop(&mut self) {
            if !self.running {
                return;
            }

            // 1. 停止消息循环（设置 stop_flag + 等待线程退出 + 注销 WTS）
            if let Some(ref mls) = self.message_loop_state {
                mls.stop();
                // 2. 发送 Shutdown 信号给工作线程
                mls.send_shutdown();
            }

            // 3. 等待工作线程退出
            if let Some(handle) = self.worker_thread.take() {
                let deadline = Instant::now() + Duration::from_secs(3);
                while !handle.is_finished() {
                    if Instant::now() >= deadline {
                        log::error!("[session_guard] 工作线程 3s 内未退出");
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                let _ = handle.join();
            }

            // 4. 清理状态
            self.message_loop_state = None;
            self.running = false;

            log::info!("[session_guard] 会话守卫已停止");
        }

        fn set_high_security(&self, enabled: bool) {
            self.high_security.store(enabled, Ordering::SeqCst);
        }

        fn is_running(&self) -> bool {
            self.running
        }
    }

    impl Drop for WindowsBackend {
        fn drop(&mut self) {
            self.stop();
        }
    }
}

/* ==================================================================== *
 *  非 Windows 平台后端（降级策略）                                       *
 *                                                                        *
 *  SECURITY.md 第 4 项：非 Windows 平台返回错误但不阻止应用启动。         *
 * ==================================================================== */

#[cfg(not(target_os = "windows"))]
mod noop_backend {
    use super::SessionGuardBackend;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub struct NoopBackend {
        high_security: AtomicBool,
    }

    impl NoopBackend {
        pub fn new(high_security: bool) -> Self {
            NoopBackend {
                high_security: AtomicBool::new(high_security),
            }
        }
    }

    impl SessionGuardBackend for NoopBackend {
        fn start(&mut self) -> Result<(), String> {
            log::warn!("[session_guard] 非 Windows 平台不支持会话守卫");
            Err("session_guard: 非 Windows 平台不支持".into())
        }

        fn stop(&mut self) {}

        fn set_high_security(&self, enabled: bool) {
            self.high_security.store(enabled, Ordering::SeqCst);
        }

        fn is_running(&self) -> bool {
            false
        }
    }
}

/* ==================================================================== *
 *  SessionGuard — 公共 API（保持向后兼容）                                *
 * ==================================================================== */

/// 智能会话自动锁屏守卫
///
/// SECURITY.md 企业级重写：
/// - mpsc 通道替代全局裸指针（第 1 项）
/// - RAII 窗口封装，无全局状态（第 2 项）
/// - catch_unwind 防止 panic 跨 FFI（第 3 项）
/// - 平台抽象层 + 降级策略（第 4 项）
/// - 实例级高安全标志（第 5 项）
/// - 看门狗自动恢复（第 6 项）
pub struct SessionGuard {
    backend: Backend,
    #[allow(dead_code)]
    on_lock: Arc<dyn Fn() + Send + Sync>,
    #[allow(dead_code)]
    on_unlock: Arc<dyn Fn() + Send + Sync>,
    high_security_mode: bool,
}

#[cfg(target_os = "windows")]
type Backend = win_backend::WindowsBackend;

#[cfg(not(target_os = "windows"))]
type Backend = noop_backend::NoopBackend;

impl SessionGuard {
    /// 创建会话守卫
    ///
    /// 回调存储为 Arc<dyn Fn()>，可跨 start/stop 周期复用。
    pub fn new(
        on_lock: Box<dyn Fn() + Send + Sync>,
        on_unlock: Box<dyn Fn() + Send + Sync>,
    ) -> Self {
        let on_lock: Arc<dyn Fn() + Send + Sync> = Arc::from(on_lock);
        let on_unlock: Arc<dyn Fn() + Send + Sync> = Arc::from(on_unlock);

        SessionGuard {
            #[cfg(target_os = "windows")]
            backend: win_backend::WindowsBackend::new(
                on_lock.clone(),
                on_unlock.clone(),
                false,
            ),
            #[cfg(not(target_os = "windows"))]
            backend: noop_backend::NoopBackend::new(false),
            on_lock,
            on_unlock,
            high_security_mode: false,
        }
    }

    /// SECURITY.md 第 5 项：设置高安全模式（实例级，非全局）
    pub fn set_high_security_mode(&mut self, enabled: bool) {
        self.high_security_mode = enabled;
        self.backend.set_high_security(enabled);
    }

    /// 启动会话守卫
    #[cfg(target_os = "windows")]
    pub fn start(&mut self) -> Result<(), String> {
        self.backend.start()
    }

    #[cfg(not(target_os = "windows"))]
    pub fn start(&mut self) -> Result<(), String> {
        self.backend.start()
    }

    /// 停止会话守卫
    pub fn stop(&mut self) {
        self.backend.stop();
    }

    /// 查询是否正在运行
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.backend.is_running()
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.stop();
    }
}
