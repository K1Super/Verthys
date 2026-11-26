/*
 * clipboard_guard/guard.rs — ClipboardGuard 及生命周期管理
 */

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;

#[cfg(target_os = "windows")]
use std::sync::atomic::Ordering;
#[cfg(target_os = "windows")]
use std::thread;

use super::state::lock_state;
#[cfg(target_os = "windows")]
use super::state::{now_ms, ClipboardStage, CLIPBOARD_LOCK, PENDING_UPDATE, SENSITIVE_EXPIRE_SECS};

#[cfg(target_os = "windows")]
use super::clear::do_clear_internal;
#[cfg(target_os = "windows")]
use super::listener::run_listener_thread;

#[cfg(target_os = "windows")]
use super::win32::{
    GetLastError, GlobalAlloc, GlobalLock, GlobalUnlock, CF_PRIVATEFIRST, CF_UNICODETEXT,
    GMEM_DDESHARE_RAW, GMEM_MOVEABLE_RAW,
};

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{HANDLE, HWND};
#[cfg(target_os = "windows")]
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard, SetClipboardData,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Ole::OleInitialize;

/* ==================================================================== *
 *                        ClipboardGuard 结构体
 * ==================================================================== */
pub struct ClipboardGuard {
    /// 监听线程句柄（窗口由该线程创建并销毁）
    join_handle: Option<JoinHandle<()>>,
    /// 当前监听轮次的停止信号（每轮启动独立创建，避免跨轮串扰）
    stop_flag: Option<Arc<AtomicBool>>,
}

impl ClipboardGuard {
    pub fn new() -> Self {
        ClipboardGuard {
            join_handle: None,
            stop_flag: None,
        }
    }

    /// 停止并回收当前监听线程（有界等待，超时 detach 由进程退出回收）。
    ///
    /// 先置停止信号、再置 `monitoring=false`：监听线程在状态锁内检查停止
    /// 信号后才写入 `monitoring=true`，因此不会出现“停止后又被置回运行”的竞态。
    #[cfg(target_os = "windows")]
    fn stop_listener_thread(&mut self) {
        if let Some(flag) = self.stop_flag.take() {
            flag.store(true, Ordering::SeqCst);
        }
        {
            let mut state = lock_state();
            state.monitoring = false;
        }
        PENDING_UPDATE.store(false, Ordering::SeqCst);

        if let Some(handle) = self.join_handle.take() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while !handle.is_finished() {
                if std::time::Instant::now() >= deadline {
                    // 丢弃 JoinHandle 即 detach：线程持有独立停止信号，不会
                    // 再改写全局监听状态；其窗口资源随线程退出自行回收。
                    log::warn!("[clipboard_guard] 监听线程 3 秒内未退出，detach（随进程退出回收）");
                    return;
                }
                thread::sleep(std::time::Duration::from_millis(10));
            }
            let _ = handle.join();
        }
    }

    /* ---------------- 延迟清空写入 ---------------- */
    /// 写入敏感内容（延迟清空模式）：
    ///
    /// SetClipboardData 后绝不清空。
    /// 敏感内容正常驻留剪贴板中，供用户粘贴。
    /// 清空动作仅在以下条件触发时执行：
    ///   - 30 秒自动过期（check_sensitive_expire 轮询）
    ///   - 高安全模式下检测到外部 SetClipboardData（process_clipboard_update）
    ///   - 显式调用 clear / transactional_clear
    ///
    /// 写入时通过 CF_PRIVATEFIRST 标记，
    /// 从源头防止进入剪贴板历史记录。
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    pub fn write_sensitive(content: &str) -> Result<(), String> {
        // 串行化剪贴板物理 API 访问
        let _lock = CLIPBOARD_LOCK
            .lock()
            .map_err(|e| format!("CLIPBOARD_LOCK poisoned: {}", e))?;

        // 准备 CF_UNICODETEXT 内容：UTF-16 编码 + NUL 终止符
        let mut utf16: Vec<u16> = content.encode_utf16().collect();
        utf16.push(0u16);
        let size = utf16.len() * 2; // 字节数

        // 原子设置 Writing 阶段 + 过期时间
        {
            let mut state = lock_state();
            state.stage = ClipboardStage::Writing;
            state.expire_at_ms = now_ms() + SENSITIVE_EXPIRE_SECS * 1000;
        }

        let result: Result<(), String> = unsafe {
            let _ = OleInitialize(None);
            let hwnd = HWND(std::ptr::null_mut());
            if OpenClipboard(hwnd).is_err() {
                Err(format!(
                    "OpenClipboard 失败: GetLastError={}",
                    GetLastError()
                ))
            } else {
                // 先清空既有内容
                let _ = EmptyClipboard();

                // 1. GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE) 分配共享可移动内存
                let h_mem_raw = GlobalAlloc(GMEM_DDESHARE_RAW | GMEM_MOVEABLE_RAW, size);
                if h_mem_raw == 0 {
                    let _ = CloseClipboard();
                    Err(format!(
                        "GlobalAlloc(GMEM_DDESHARE|GMEM_MOVEABLE) 失败: GetLastError={}",
                        GetLastError()
                    ))
                } else {
                    // 2. GlobalLock → 拷贝 → GlobalUnlock
                    let ptr = GlobalLock(h_mem_raw);
                    if ptr.is_null() {
                        let _ = CloseClipboard();
                        Err(format!("GlobalLock 失败: GetLastError={}", GetLastError()))
                    } else {
                        std::ptr::copy_nonoverlapping(utf16.as_ptr() as *const u8, ptr, size);
                        let _ = GlobalUnlock(h_mem_raw);

                        // 3. SetClipboardData(CF_UNICODETEXT, handle)
                        //    SetClipboardData 接管内存所有权，不可 GlobalFree
                        match SetClipboardData(CF_UNICODETEXT, HANDLE(h_mem_raw as *mut _)) {
                            Ok(_) => {
                                // 写入 CF_PRIVATEFIRST 标记，
                                // 防止进入剪贴板历史记录（best-effort）
                                let h_priv = GlobalAlloc(GMEM_MOVEABLE_RAW, 1);
                                if h_priv != 0 {
                                    let priv_ptr = GlobalLock(h_priv);
                                    if !priv_ptr.is_null() {
                                        *priv_ptr = 1u8; // 标记字节
                                        let _ = GlobalUnlock(h_priv);
                                        let _ = SetClipboardData(
                                            CF_PRIVATEFIRST,
                                            HANDLE(h_priv as *mut _),
                                        );
                                    }
                                }

                                let _ = CloseClipboard();

                                // 绝不清空！敏感内容驻留供用户粘贴
                                log::info!(
                                    "[clipboard_guard] write_sensitive: 写入 {} 字符，\
                                     延迟清空模式（{} 秒后自动清空 / 外部写入触发清空）",
                                    content.chars().count(),
                                    SENSITIVE_EXPIRE_SECS
                                );
                                Ok(())
                            }
                            Err(e) => {
                                let _ = CloseClipboard();
                                Err(format!("SetClipboardData 失败: {}", e))
                            }
                        }
                    }
                }
            }
        };

        // 显式清零本地敏感缓冲区
        for w in utf16.iter_mut() {
            *w = 0;
        }

        // 原子更新状态
        {
            let mut state = lock_state();
            match &result {
                Ok(()) => {
                    state.stage = ClipboardStage::SensitivePresent;
                    state.last_seq = unsafe { GetClipboardSequenceNumber() };
                }
                Err(e) => {
                    state.stage = ClipboardStage::Idle;
                    log::error!("[clipboard_guard] write_sensitive 失败: {}", e);
                }
            }
        }

        result
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    pub fn write_sensitive(_content: &str) -> Result<(), String> {
        Err("clipboard_guard: 非 Windows 平台不支持".into())
    }

    /* ---------------- 事务式剪贴板安全清空 ---------------- */
    /// 事务式剪贴板安全清空
    ///
    /// 不进行垃圾覆写，直接调用 EmptyClipboard。
    /// 事务性体现在 OpenClipboard 重试 + 最终广播 WM_DESTROYCLIPBOARD。
    ///
    /// 完整事务序列：
    ///   1. OpenClipboard 获取所有权（重试 3 次，每次间隔 50ms）
    ///   2. EmptyClipboard 清空所有格式
    ///   3. 广播 WM_DESTROYCLIPBOARD 强制系统清除云剪贴板缓存
    ///   4. CloseClipboard
    ///
    /// 重试机制：OpenClipboard 失败（剪贴板被占用）时等待 50ms 重试，最多 3 次。
    /// 全部失败返回 Err，不静默返回 Ok。
    #[cfg(target_os = "windows")]
    pub fn transactional_clear() -> Result<(), String> {
        // 标记为 Writing 以忽略清空操作自身产生的通知
        {
            let mut state = lock_state();
            state.stage = ClipboardStage::Writing;
        }

        let result = do_clear_internal();

        // 原子更新状态
        let mut state = lock_state();
        state.stage = ClipboardStage::Idle;
        state.last_seq = unsafe { GetClipboardSequenceNumber() };
        state.expire_at_ms = 0;

        if let Err(ref e) = result {
            log::error!("[clipboard_guard] transactional_clear 失败: {}", e);
        }
        result
    }

    #[cfg(not(target_os = "windows"))]
    pub fn transactional_clear() -> Result<(), String> {
        Err("clipboard_guard: 非 Windows 平台不支持".into())
    }

    /* ---------------- 启动监听 ---------------- */
    /// 启动剪贴板格式监听器（AddClipboardFormatListener）+ 监听线程。
    ///
    /// 幂等语义：监听已在运行时重复启动直接成功。安全档位恢复链会在每次
    /// 进入中枢时重复下发同一开关，重复启动不得被当作失败上报。
    ///
    /// 启动握手：监听线程完成窗口创建与监听注册后回传 Ok/Err；
    /// 失败必须如实返回，绝不制造“已启动”假象。
    #[cfg(target_os = "windows")]
    pub fn start_monitoring(&mut self) -> Result<(), String> {
        // 1. 幂等判定：线程仍存活且状态为监听中 → 直接成功
        if lock_state().monitoring
            && self
                .join_handle
                .as_ref()
                .is_some_and(|handle| !handle.is_finished())
        {
            log::info!("[clipboard_guard] 监听已在运行，重复启动按幂等成功处理");
            return Ok(());
        }

        // 2. 回收上一轮残留（线程已退出但句柄未回收 / 状态残留）
        self.stop_listener_thread();

        // 3. 启动监听线程（窗口归属该线程，消息循环与本线程同源）
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_stop = stop_flag.clone();

        let handle = thread::Builder::new()
            .name("verthys-clipboard-guard".into())
            .spawn(move || run_listener_thread(ready_tx, thread_stop))
            .map_err(|e| format!("启动剪贴板监听线程失败: {}", e))?;

        self.join_handle = Some(handle);
        self.stop_flag = Some(stop_flag);

        // 4. 有界等待启动结果：超时按失败上报并回收线程
        match ready_rx.recv_timeout(std::time::Duration::from_secs(3)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                self.stop_listener_thread();
                Err(e)
            }
            Err(_) => {
                self.stop_listener_thread();
                Err("剪贴板监听线程启动超时".into())
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn start_monitoring(&mut self) -> Result<(), String> {
        Err("clipboard_guard: 非 Windows 平台不支持".into())
    }

    /* ---------------- 停止监听 ---------------- */
    /// 停止监听：置停止信号 → 有界等待线程自行销毁窗口并退出。
    ///
    /// 窗口由监听线程创建，必须由其自身销毁（Win32 跨线程 DestroyWindow 会
    /// 失败），因此这里不持有也不操作窗口句柄。
    #[cfg(target_os = "windows")]
    pub fn stop_monitoring(&mut self) {
        let was_monitoring = lock_state().monitoring;
        self.stop_listener_thread();

        // 清除敏感内容状态
        {
            let mut state = lock_state();
            state.stage = ClipboardStage::Idle;
            state.expire_at_ms = 0;
        }

        if was_monitoring {
            log::info!("[clipboard_guard] 剪贴板监听已停止");
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn stop_monitoring(&mut self) {}

    /* ---------------- 高安全模式开关 ---------------- */
    /// 启用 / 禁用「外部写入即清空」行为。
    /// 高安全标志仅作为状态字段，不依赖全局原子变量。
    pub fn set_high_security_mode(&mut self, enabled: bool) {
        let mut state = lock_state();
        state.high_security = enabled;
        log::info!(
            "[clipboard_guard] 高安全模式: {}",
            if enabled { "启用" } else { "禁用" }
        );
    }
}

impl Default for ClipboardGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        self.stop_monitoring();
    }
}
