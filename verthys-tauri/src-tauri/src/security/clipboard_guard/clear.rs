/*
 * clipboard_guard/clear.rs — 统一清空入口、内部清空实现、清空决策与过期轮询
 *
 * 直接调用 EmptyClipboard 并广播 WM_DESTROYCLIPBOARD，
 * 强制系统清除云剪贴板缓存。
 */

#[cfg(target_os = "windows")]
use super::state::{lock_state, now_ms, ClipboardStage, CLIPBOARD_LOCK, SENSITIVE_EXPIRE_SECS};

#[cfg(target_os = "windows")]
use super::win32::{PostMessageW, Sleep, HWND_BROADCAST, WM_DESTROYCLIPBOARD};

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::HWND;
#[cfg(target_os = "windows")]
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Ole::OleInitialize;

/// OpenClipboard 重试次数（剪贴板被占用时等待重试）
#[cfg(target_os = "windows")]
const OPEN_RETRIES: usize = 3;
/// 重试间隔（50ms）
#[cfg(target_os = "windows")]
const RETRY_INTERVAL_MS: u64 = 50;

/// 清空动作枚举（process_clipboard_update 的决策结果）
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClearAction {
    None,
    ClearAndReset,
}

/* ==================================================================== *
 *  统一剪贴板清空入口（公共接口）
 *
 *  所有剪贴板清空操作均通过此入口，包括：
 *    - mod.rs 的 clear_clipboard() 封装
 *    - ClipboardGuard 的 clear() 方法
 *    - 审计日志的 clear_clipboard 命令
 *
 *  直接调用 EmptyClipboard + 广播 WM_DESTROYCLIPBOARD。
 * ==================================================================== */

/// 统一剪贴板清空入口
///
/// 直接调用 EmptyClipboard 并广播 WM_DESTROYCLIPBOARD，
/// 强制系统清除云剪贴板缓存。
pub fn clear() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        do_clear_internal()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("clear_clipboard: 非 Windows 平台不支持".into())
    }
}

/* ==================================================================== *
 *  内部清空实现
 *
 *  直接调用 EmptyClipboard 并广播 WM_DESTROYCLIPBOARD。
 *  EmptyClipboard 本身已足够保护残留。
 * ==================================================================== */
#[cfg(target_os = "windows")]
pub(super) fn do_clear_internal() -> Result<(), String> {
    let _lock = CLIPBOARD_LOCK
        .lock()
        .map_err(|e| format!("CLIPBOARD_LOCK poisoned: {}", e))?;

    let mut last_err = String::new();

    unsafe {
        let _ = OleInitialize(None);

        // 重试 OpenClipboard（剪贴板被占用时等待 50ms × OPEN_RETRIES）
        let mut opened = false;
        for attempt in 0..OPEN_RETRIES {
            let hwnd = HWND(std::ptr::null_mut());
            match OpenClipboard(hwnd) {
                Ok(_) => {
                    opened = true;
                    break;
                }
                Err(e) => {
                    last_err = format!("OpenClipboard 失败（第 {} 次）: {}", attempt + 1, e);
                    if attempt + 1 < OPEN_RETRIES {
                        Sleep(RETRY_INTERVAL_MS as u32);
                    }
                }
            }
        }

        if !opened {
            return Err(last_err);
        }

        // 直接调用 EmptyClipboard 清空
        let empty_ok = EmptyClipboard().is_ok();

        // 广播 WM_DESTROYCLIPBOARD，强制系统清除云剪贴板缓存
        let post_ok = PostMessageW(HWND_BROADCAST, WM_DESTROYCLIPBOARD, 0, 0) != 0;

        let _ = CloseClipboard();

        log::info!(
            "[clipboard_guard] do_clear: EmptyClipboard={} WM_DESTROYCLIPBOARD 广播={}",
            empty_ok,
            post_ok
        );

        if empty_ok {
            Ok(())
        } else {
            Err("EmptyClipboard 失败".into())
        }
    }
}

/// 轮询敏感内容自动过期（30 秒后清空）
#[cfg(target_os = "windows")]
pub(super) fn check_sensitive_expire() {
    let action = {
        let state = lock_state();
        if state.stage != ClipboardStage::SensitivePresent {
            return;
        }
        if state.expire_at_ms == 0 {
            return;
        }
        if now_ms() >= state.expire_at_ms {
            log::info!(
                "[clipboard_guard] 敏感内容已超时（{} 秒），自动清空",
                SENSITIVE_EXPIRE_SECS
            );
            true
        } else {
            false
        }
    };

    if action {
        // 标记为 Writing 以忽略清空操作自身产生的通知
        {
            let mut state = lock_state();
            state.stage = ClipboardStage::Writing;
        }

        let clear_result = do_clear_internal();

        let mut state = lock_state();
        state.stage = ClipboardStage::Idle;
        state.last_seq = unsafe { GetClipboardSequenceNumber() };
        state.expire_at_ms = 0;

        if let Err(ref e) = clear_result {
            log::error!("[clipboard_guard] 超时触发清空失败: {}", e);
        }
    }
}
