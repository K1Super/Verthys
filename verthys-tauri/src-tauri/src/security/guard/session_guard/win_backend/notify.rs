/*
 * 消息循环状态、工作线程与 Windows 后端
 *
 * MessageLoopState 持有窗口 / 通知句柄与消息循环线程句柄，支持看门狗重启；
 * worker_loop 以 recv_timeout 充当看门狗，并在回调边界用 catch_unwind
 * 防止 panic 跨 FFI；WindowsBackend 组合两者并提供 SessionGuardBackend 实现。
 */

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::super::types::{
    SessionEvent, SessionGuardBackend, SessionLockReason, WindowInstanceData, MAX_RESTART_ATTEMPTS,
    WATCHDOG_CHECK_SECS,
};
use super::window::{
    create_guard_window, run_message_loop, UnregisterPowerSettingNotification,
    WTSUnRegisterSessionNotification_t,
};

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
    /// 显示器电源设置通知句柄（0 = 未注册），与窗口生命周期配对注销
    power_notify: Arc<Mutex<isize>>,
    restart_count: AtomicU32,
}

impl MessageLoopState {
    fn new(instance_data: Arc<WindowInstanceData>, stop_flag: Arc<AtomicBool>) -> Self {
        MessageLoopState {
            instance_data,
            stop_flag,
            current_thread: Mutex::new(None),
            current_hwnd: Arc::new(Mutex::new(0)),
            unreg_fn: Arc::new(Mutex::new(None)),
            power_notify: Arc::new(Mutex::new(0)),
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
        let power_slot = self.power_notify.clone();

        let (create_tx, create_rx) = mpsc::channel::<Result<isize, String>>();

        let handle = thread::Builder::new()
            .name("verthys-session-msgloop".into())
            .spawn(move || match create_guard_window(&instance_data) {
                Ok((hwnd, unreg_fn, power_notify)) => {
                    *hwnd_slot.lock().unwrap() = hwnd;
                    *unreg_slot.lock().unwrap() = Some(unreg_fn);
                    *power_slot.lock().unwrap() = power_notify;
                    let _ = create_tx.send(Ok(hwnd));
                    run_message_loop(hwnd, stop_flag);
                }
                Err(e) => {
                    let _ = create_tx.send(Err(e));
                }
            })
            .map_err(|e| format!("启动消息循环线程失败: {}", e))?;

        *self.current_thread.lock().unwrap() = Some(handle);

        match create_rx.recv() {
            Ok(Ok(hwnd)) => {
                log::info!("[session_guard] 消息循环线程已启动 (HWND=0x{:X})", hwnd);
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

    /// 注销 WTS 会话通知与显示器电源设置通知（幂等，清空句柄槽）
    ///
    /// 注销必须在窗口仍存活时执行；两路通知句柄独立管理，任一路
    /// 缺失不影响另一路注销。
    fn unregister_notifications(&self) {
        if let Ok(mut hwnd_guard) = self.current_hwnd.lock() {
            let old_hwnd = *hwnd_guard;
            if old_hwnd != 0 {
                if let Ok(mut unreg_guard) = self.unreg_fn.lock() {
                    if let Some(unreg) = unreg_guard.take() {
                        unsafe {
                            unreg(old_hwnd);
                        }
                    }
                }
            }
            *hwnd_guard = 0;
        }
        if let Ok(mut power_guard) = self.power_notify.lock() {
            let handle = *power_guard;
            if handle != 0 {
                unsafe {
                    UnregisterPowerSettingNotification(handle);
                }
            }
            *power_guard = 0;
        }
    }

    /// 看门狗重启消息循环线程
    fn restart(&self) -> Result<(), String> {
        let count = self.restart_count.fetch_add(1, Ordering::SeqCst);
        if count >= MAX_RESTART_ATTEMPTS {
            log::error!(
                "[session_guard] 消息循环线程重启次数已达上限 ({})，放弃重启",
                MAX_RESTART_ATTEMPTS
            );
            return Err(format!(
                "消息循环线程重启次数已达上限 ({})",
                MAX_RESTART_ATTEMPTS
            ));
        }

        log::warn!(
            "[session_guard] 消息循环线程已退出，尝试重启 (第 {} 次)...",
            count + 1
        );

        // 清理旧线程
        if let Ok(mut guard) = self.current_thread.lock() {
            if let Some(old) = guard.take() {
                let _ = old.join();
            }
        }

        // 注销旧 WTS / 电源设置通知
        self.unregister_notifications();

        // 重置 stop_flag（可能是前次 stop 残留）
        self.stop_flag.store(false, Ordering::SeqCst);

        // 启动新消息循环
        self.start()?;
        log::warn!("[session_guard] 消息循环线程已重启 (第 {} 次)", count + 1);
        Ok(())
    }

    /// 停止消息循环并清理
    fn stop(&self) {
        // 1. 注销 WTS / 电源设置通知
        self.unregister_notifications();

        // 2. 设置停止标志
        self.stop_flag.store(true, Ordering::SeqCst);

        // 3. 等待消息循环线程退出（2 秒超时）
        if let Ok(mut guard) = self.current_thread.lock() {
            if let Some(handle) = guard.take() {
                let deadline = Instant::now() + Duration::from_secs(2);
                while !handle.is_finished() {
                    if Instant::now() >= deadline {
                        log::error!("[session_guard] 消息循环线程 2s 内未退出");
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
 *  工作线程（回调执行 + 看门狗）          *
 *                                                                        *
 *  接收 mpsc 事件并执行用户回调（catch_unwind 防止 panic 跨 FFI）。      *
 *  使用 recv_timeout 充当看门狗：定期检查消息循环线程存活状态。           *
 * ==================================================================== */

fn worker_loop(
    receiver: mpsc::Receiver<SessionEvent>,
    on_lock: Arc<dyn Fn(SessionLockReason) + Send + Sync>,
    on_unlock: Arc<dyn Fn() + Send + Sync>,
    message_loop_state: Arc<MessageLoopState>,
    stop_flag: Arc<AtomicBool>,
    high_security: Arc<AtomicBool>,
) {
    log::info!(
        "[session_guard] 工作线程已启动（含看门狗，间隔 {}s）",
        WATCHDOG_CHECK_SECS
    );

    loop {
        match receiver.recv_timeout(Duration::from_secs(WATCHDOG_CHECK_SECS)) {
            Ok(event) => {
                // catch_unwind 防止 panic 跨 FFI
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match event {
                        SessionEvent::Lock(reason) => on_lock(reason),
                        SessionEvent::Unlock => on_unlock(),
                        /* 挂起必须无条件锁库：挂起窗口是内存镜像落盘
                         *（hiberfil）的唯一入口，不能由可关闭的高安全
                         * 开关决定。显示器关闭仍按高安全档门控。 */
                        SessionEvent::PowerSuspend => {
                            on_lock(SessionLockReason::Suspend);
                        }
                        SessionEvent::DisplayOff => {
                            if high_security.load(Ordering::SeqCst) {
                                on_lock(SessionLockReason::DisplayOff);
                            }
                        }
                        SessionEvent::Shutdown => {
                            // 工作线程退出信号
                        }
                    }
                }));

                if let Err(payload) = result {
                    log::error!("[session_guard] 用户回调 panic 已捕获: {:?}", payload);
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
                // 看门狗检查消息循环线程
                if !message_loop_state.is_alive() {
                    if let Err(e) = message_loop_state.restart() {
                        log::error!("[session_guard] 消息循环重启失败: {}", e);
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
    /* 回调以共享 Arc 持有而非 take 消费：停止后重新启动（含替换回调）
     * 仍能复用同一份回调，不会退化为空操作。 */
    on_lock: Arc<dyn Fn(SessionLockReason) + Send + Sync>,
    on_unlock: Arc<dyn Fn() + Send + Sync>,
    running: bool,
}

impl WindowsBackend {
    pub fn new(
        on_lock: Arc<dyn Fn(SessionLockReason) + Send + Sync>,
        on_unlock: Arc<dyn Fn() + Send + Sync>,
        high_security: bool,
    ) -> Self {
        WindowsBackend {
            high_security: Arc::new(AtomicBool::new(high_security)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            message_loop_state: None,
            worker_thread: None,
            on_lock,
            on_unlock,
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
        let on_lock = self.on_lock.clone();
        let on_unlock = self.on_unlock.clone();

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
