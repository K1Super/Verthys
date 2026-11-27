/*
 * clipboard_guard/listener.rs — 监听窗口、窗口类注册、监听线程与异步更新处理
 *
 * 窗口过程仅标记事件，所有剪贴板操作在消息循环中异步处理。
 * 隐藏窗口与消息循环由同一线程创建，保证 WM_CLIPBOARDUPDATE 可达。
 */

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use windows::Win32::Foundation::HWND;
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, GetClipboardSequenceNumber, RemoveClipboardFormatListener,
};
use windows::Win32::System::Ole::{OleInitialize, OleUninitialize};

use super::clear::{check_sensitive_expire, do_clear_internal, ClearAction};
use super::state::{lock_state, ClipboardStage, PENDING_UPDATE};
use super::win32::{
    to_wide, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetLastError,
    GetModuleHandleW, Msg, PeekMessageW, RegisterClassExW, Sleep, TranslateMessage, WndClassExW,
    ERROR_CLASS_ALREADY_EXISTS, ERROR_INVALID_WINDOW_HANDLE, LISTENER_CLASS_NAME,
    WM_CLIPBOARDUPDATE, WM_DESTROY, WM_DESTROYCLIPBOARD,
};

/// PeekMessage 移除标志 PM_REMOVE = 0x0001
const PM_REMOVE: u32 = 0x0001;
/// 序列号轮询间隔（毫秒）
const POLL_INTERVAL_MS: u64 = 200;

/* ==================================================================== *
 *  窗口过程仅标记事件
 *
 *  clipboard_window_proc 不直接调用任何剪贴板 API。
 *  收到 WM_CLIPBOARDUPDATE / WM_DESTROYCLIPBOARD 时，仅设置 PENDING_UPDATE
 *  标志。消息循环中的轮询检测到该标志后，在主循环上下文中执行检查和处理。
 *
 *  这完全避免了窗口过程内的重入风险。
 * ==================================================================== */
unsafe extern "system" fn clipboard_window_proc(
    hwnd: isize,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match msg {
        WM_CLIPBOARDUPDATE | WM_DESTROYCLIPBOARD => {
            // 仅设置标志，不在窗口过程中执行任何剪贴板操作
            PENDING_UPDATE.store(true, Ordering::SeqCst);
            0
        }
        WM_DESTROY => 0,
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/* ==================================================================== *
 *  异步处理待处理的剪贴板事件
 *
 *  在消息循环上下文中调用（非窗口过程），安全地执行剪贴板检查和处理。
 *  外部 SetClipboardData（序列号递增）而非读取才是正确的触发条件。
 * ==================================================================== */
fn process_clipboard_update() {
    // 获取当前序列号（不需要打开剪贴板）
    let current = unsafe { GetClipboardSequenceNumber() };

    // 在锁内原子地读取状态并决定操作
    let action = {
        let mut state = lock_state();

        match state.stage {
            ClipboardStage::Writing => {
                // 本进程写入链中：仅刷新基线，不反应
                state.last_seq = current;
                return;
            }
            ClipboardStage::SensitivePresent => {
                if current > state.last_seq {
                    // 序列号递增 = 外部调用了 SetClipboardData（写入，非读取）
                    // 这才是正确的触发条件
                    if state.high_security {
                        // 高安全模式：立即清空
                        log::warn!(
                            "[clipboard_guard] 检测到外部剪贴板写入（seq {}→{}），\
                             高安全模式立即清空",
                            state.last_seq,
                            current
                        );
                        // 标记为 Writing 以忽略清空操作自身产生的通知
                        state.stage = ClipboardStage::Writing;
                        ClearAction::ClearAndReset
                    } else {
                        // 非高安全模式：外部已替换内容，更新基线，状态回归空闲
                        state.last_seq = current;
                        state.stage = ClipboardStage::Idle;
                        ClearAction::None
                    }
                } else {
                    // 序列号未变化（可能是 WM_DESTROYCLIPBOARD 通知），仅更新基线
                    state.last_seq = current;
                    ClearAction::None
                }
            }
            ClipboardStage::Idle => {
                // 空闲状态：仅更新基线
                state.last_seq = current;
                ClearAction::None
            }
        }
    };
    // 状态锁已释放

    if action == ClearAction::ClearAndReset {
        // 执行清空（获取 CLIPBOARD_LOCK 串行化剪贴板 API）
        let clear_result = do_clear_internal();

        // 更新状态
        let mut state = lock_state();
        state.stage = ClipboardStage::Idle;
        state.last_seq = unsafe { GetClipboardSequenceNumber() };

        if let Err(ref e) = clear_result {
            log::error!("[clipboard_guard] 外部写入触发清空失败: {}", e);
        }
    }
}

/* ---------- 创建隐藏监听窗口 ---------- */
/// 创建隐藏监听窗口（窗口归属调用线程，即监听线程）。
///
/// 必须先确保窗口类已注册；窗口类为进程级资源，进程内只注册一次。
fn create_listener_window() -> Result<isize, String> {
    ensure_listener_class()?;

    unsafe {
        let class_name = to_wide(LISTENER_CLASS_NAME);
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
        Ok(hwnd)
    }
}

/// 注册监听窗口类（进程内严格一次）。
///
/// 以 `OnceLock` 保证仅注册一次；并发或历史注册返回 1410
/// （ERROR_CLASS_ALREADY_EXISTS）时按“同名同类已存在”处理，不视为失败。
fn ensure_listener_class() -> Result<(), String> {
    static CLASS_READY: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if CLASS_READY.get().is_some() {
        return Ok(());
    }

    unsafe {
        let class_name = to_wide(LISTENER_CLASS_NAME);
        let hinst = GetModuleHandleW(std::ptr::null());

        let wc = WndClassExW {
            cbSize: std::mem::size_of::<WndClassExW>() as u32,
            lpfnWndProc: Some(clipboard_window_proc),
            hInstance: hinst,
            lpszClassName: class_name.as_ptr(),
            ..Default::default()
        };

        let atom = RegisterClassExW(&wc);
        if atom == 0 {
            let err_code = GetLastError();
            if err_code != ERROR_CLASS_ALREADY_EXISTS {
                return Err(format!("RegisterClassExW 失败: GetLastError={}", err_code));
            }
        }

        let _ = CLASS_READY.set(());
        Ok(())
    }
}

/* ==================================================================== *
 *  监听线程（窗口创建 + 监听注册 + 消息泵 / 序列号轮询）
 *
 *  关键约束：隐藏窗口必须由运行消息循环的线程创建。Win32 窗口消息只投递
 *  到创建该窗口的线程队列；若在命令线程创建窗口、在另一线程跑消息
 *  循环，WM_CLIPBOARDUPDATE 无法被监听线程读取，外部写入检测失效。
 * ==================================================================== */

/// 创建窗口并注册剪贴板格式监听。
///
/// 返回 `(hwnd, format_listener)`：
///   - `format_listener=true`：WM_CLIPBOARDUPDATE 事件通道可用；
///   - `format_listener=false`：降级为序列号轮询（窗口已销毁，hwnd=0）。
fn setup_listener() -> Result<(isize, bool), String> {
    unsafe {
        let mut hwnd = create_listener_window()?;

        if AddClipboardFormatListener(HWND(hwnd as *mut _)).is_ok() {
            return Ok((hwnd, true));
        }

        let err_code = GetLastError();
        if err_code == ERROR_INVALID_WINDOW_HANDLE {
            log::warn!(
                "[clipboard_guard] AddClipboardFormatListener 失败 \
                 (ERROR_INVALID_WINDOW_HANDLE)，重新创建窗口重试"
            );
            let _ = DestroyWindow(hwnd);
            hwnd = create_listener_window()?;
            if AddClipboardFormatListener(HWND(hwnd as *mut _)).is_ok() {
                return Ok((hwnd, true));
            }
            let retry_err = GetLastError();
            let _ = DestroyWindow(hwnd);
            return Err(format!(
                "AddClipboardFormatListener 重试仍失败: GetLastError={}",
                retry_err
            ));
        }

        // 权限拒绝或其他错误：降级为定时轮询（序列号变化仍可检测外部写入）
        log::warn!(
            "[clipboard_guard] AddClipboardFormatListener 失败: GetLastError={}，\
             降级为定时轮询模式（仅序列号轮询，无 WM_CLIPBOARDUPDATE）",
            err_code
        );
        let _ = DestroyWindow(hwnd);
        Ok((0, false))
    }
}

/// 监听线程退出前的资源回收（窗口句柄归属本线程，跨线程销毁会失败）
fn cleanup_listener(hwnd: isize, format_listener: bool) {
    if hwnd == 0 {
        return;
    }
    unsafe {
        if format_listener {
            let _ = RemoveClipboardFormatListener(HWND(hwnd as *mut _));
        }
        let _ = DestroyWindow(hwnd);
    }
}

/// 监听线程主体：创建窗口、上报启动结果、泵消息并轮询剪贴板序列号。
///
/// 启动结果通过 `ready` 同步回传：窗口创建/监听注册失败必须返回 Err，
/// 调用方据此如实上报，绝不制造“已启动”假象。
pub(super) fn run_listener_thread(
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
    stop: Arc<AtomicBool>,
) {
    unsafe {
        let ole_result = OleInitialize(None);
        if ole_result.is_err() {
            log::warn!(
                "[clipboard_guard] 监听线程 OleInitialize 失败: {:?}，剪贴板操作可能异常",
                ole_result
            );
        }

        let (hwnd, format_listener) = match setup_listener() {
            Ok(v) => v,
            Err(e) => {
                let _ = ready.send(Err(e));
                OleUninitialize();
                return;
            }
        };

        // 原子重置监听状态基线；停止信号与状态写入共用一把锁，
        // 与 stop 的“先置停止信号、后置 monitoring=false”形成串行化，
        // 避免停止与启动竞争时把 monitoring 重新置回 true。
        {
            let mut state = lock_state();
            if stop.load(Ordering::SeqCst) {
                drop(state);
                cleanup_listener(hwnd, format_listener);
                OleUninitialize();
                return;
            }
            state.stage = ClipboardStage::Idle;
            state.last_seq = GetClipboardSequenceNumber();
            state.expire_at_ms = 0;
            state.monitoring = true;
        }
        PENDING_UPDATE.store(false, Ordering::SeqCst);

        if ready.send(Ok(())).is_err() {
            // 调用方已放弃本次启动：立即清理退出，避免留下无主监听线程
            cleanup_listener(hwnd, format_listener);
            OleUninitialize();
            return;
        }

        log::info!(
            "[clipboard_guard] 剪贴板监听已启动 (hwnd={}, mode={})",
            hwnd,
            if format_listener {
                "format_listener"
            } else {
                "polling_only"
            }
        );

        let mut last_polled_seq = GetClipboardSequenceNumber();
        loop {
            // 1. 排干窗口消息（WM_CLIPBOARDUPDATE 仅置位 PENDING_UPDATE）
            loop {
                let mut msg = Msg::default();
                if PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) == 0 {
                    break;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // 2. 停止信号：主动停止 或 监听状态被置为关闭
            if stop.load(Ordering::SeqCst) || !lock_state().monitoring {
                break;
            }

            // 3. 外部写入检测：窗口消息 + 序列号轮询双通道。
            //    轮询通道同时覆盖 AddClipboardFormatListener 降级场景，
            //    保证“外部写入即清空”不依赖窗口消息是否可用。
            let pending = PENDING_UPDATE.swap(false, Ordering::SeqCst);
            let current = GetClipboardSequenceNumber();
            let seq_changed = current != last_polled_seq;
            last_polled_seq = current;
            if pending || seq_changed {
                process_clipboard_update();
            }

            // 4. 轮询敏感内容自动过期
            check_sensitive_expire();

            // 5. 阻塞式小睡，避免空转烧 CPU
            Sleep(POLL_INTERVAL_MS as u32);
        }

        // 线程退出前回收窗口与监听注册，再反初始化 OLE
        cleanup_listener(hwnd, format_listener);
        OleUninitialize();
        log::info!("[clipboard_guard] 剪贴板监听线程已退出");
    }
}
