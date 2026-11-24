//! worker/kernel_watchdog.rs — 运行中内核保护丢失的会话锁定看门狗
//!
//! 仅在 SECURE 档位、且本次会话曾观察到内核状态为 ACTIVE 时生效：
//! 连续两次采样非 ACTIVE 即调用宿主外部锁定，避免驱动停止/卸载后
//! 受保护进程在无内核保护的状态下继续持有已解锁会话。
//!
//! 从未 ACTIVE 的会话不锁定：SECURE 是 `preferred`，无驱动环境下的
//! 降级必须保持可用，不能在启动时就误判为丢失。

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tauri::AppHandle;

use super::session::{SessionInner, WorkerSession};

/// 与 VtyKernelState 的协议值对齐：3=ACTIVE。
const KERNEL_STATE_ACTIVE: u32 = 3;
/// 连续非 ACTIVE 采样次数达到该值才锁定。
const LOSS_MISSES_TO_LOCK: u32 = 2;
/// SECURE 预设代号（0=BALANCED, 1=SECURE, 2=PERFORMANCE, 3=CUSTOM）。
const SECURE_PRESET_CODE: u32 = 1;
/// 采样周期。
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// 单次状态查询超时。
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WatchAction {
    Continue,
    Lock,
}

/// 单次采样决策：返回 (下次 seen_active, 下次 misses, 动作)。
///
/// 只有「查询成功且明确非 ACTIVE」才累计丢失次数。查询失败/超时说明
/// worker 正在处理长任务或管道暂不可用，不能据此判定内核丢失；否则
/// 大批量导入/轮换期间会产生误锁。
pub(crate) fn kernel_watch_tick(
    secure: bool,
    state: Option<u32>,
    seen_active: bool,
    misses: u32,
) -> (bool, u32, WatchAction) {
    if !secure {
        return (false, 0, WatchAction::Continue);
    }
    if state == Some(KERNEL_STATE_ACTIVE) {
        return (true, 0, WatchAction::Continue);
    }
    if state.is_none() || !seen_active {
        return (seen_active, misses, WatchAction::Continue);
    }
    let next = misses.saturating_add(1);
    let action = if next >= LOSS_MISSES_TO_LOCK {
        WatchAction::Lock
    } else {
        WatchAction::Continue
    };
    (true, next, action)
}

/// 当前会话是否处于 SECURE。读取失败或未解锁时返回 false（不误锁）。
fn secure_active(app: &AppHandle) -> bool {
    matches!(
        crate::security_commands::preset_persistence::read_preset_persist(app),
        Ok(Some(persist)) if persist.code == SECURE_PRESET_CODE
    )
}

/// 通过 worker 轻量操作读取内核状态；任何失败返回 None。
fn query_kernel_state(session: &WorkerSession) -> Option<u32> {
    let response = session
        .send_json_with_timeout(r#"{"op":"kernel_status"}"#, QUERY_TIMEOUT)
        .ok()?;
    let value: serde_json::Value = serde_json::from_str(&response).ok()?;
    if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    value
        .get("kernel_status")?
        .get("state")?
        .as_u64()
        .map(|state| state as u32)
}

/// 启动看门狗线程。每个 worker 会话一个；会话退出后线程自行结束。
///
/// 线程只持有 `Weak`：会话被替换或销毁时，宿主持有的最后一个强引用释放即
/// 触发 SessionInner Drop（关闭 Job 并终止 worker），而不是被看门狗线程
/// 的强引用永久拖住。每轮采样临时升级，采样结束立即释放。
pub(crate) fn start(session: WorkerSession, app: AppHandle) {
    let weak: std::sync::Weak<SessionInner> = Arc::downgrade(&session.inner);
    let stop = session.stop_flag();
    drop(session);
    let thread = std::thread::Builder::new()
        .name("verthys-kernel-watchdog".into())
        .spawn(move || {
            let mut seen_active = false;
            let mut misses = 0u32;
            loop {
                std::thread::sleep(POLL_INTERVAL);
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let inner = match weak.upgrade() {
                    Some(inner) => inner,
                    None => break,
                };
                let session = WorkerSession { inner };
                if !session.is_alive() {
                    /*
                     * 非主动停止的 worker 退出：会话密钥已随进程消亡，
                     * 必须立即锁定，避免宿主停留在“已解锁但无安全核心”的
                     * 状态。主动替换/销毁会先置 stop，不进入此分支。
                     */
                    if !stop.load(Ordering::SeqCst) {
                        log::error!(
                            "[kernel-watchdog] worker 异常退出，执行会话锁定"
                        );
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            crate::security_commands::commands::session::perform_external_lock(
                                app,
                                "worker_exit",
                            )
                            .await;
                        });
                    }
                    break;
                }
                let secure = secure_active(&app);
                let state = if secure {
                    query_kernel_state(&session)
                } else {
                    None
                };
                let (next_seen, next_misses, action) =
                    kernel_watch_tick(secure, state, seen_active, misses);
                seen_active = next_seen;
                misses = next_misses;
                if action == WatchAction::Lock {
                    log::error!(
                        "[kernel-watchdog] 内核保护连续 {} 次非 ACTIVE，执行会话锁定",
                        misses
                    );
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        crate::security_commands::commands::session::perform_external_lock(
                            app,
                            "kernel_lost",
                        )
                        .await;
                    });
                    break;
                }
            }
        });
    if let Err(e) = thread {
        log::warn!("[kernel-watchdog] 看门狗线程启动失败（守卫降级）: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_state_arms_the_watch() {
        assert_eq!(
            kernel_watch_tick(true, Some(KERNEL_STATE_ACTIVE), false, 0),
            (true, 0, WatchAction::Continue)
        );
    }

    #[test]
    fn loss_locks_only_after_two_misses() {
        assert_eq!(
            kernel_watch_tick(true, Some(5), true, 0),
            (true, 1, WatchAction::Continue)
        );
        assert_eq!(
            kernel_watch_tick(true, Some(5), true, 1),
            (true, 2, WatchAction::Lock)
        );
    }

    #[test]
    fn query_failure_is_not_counted_as_loss() {
        assert_eq!(
            kernel_watch_tick(true, None, true, 1),
            (true, 1, WatchAction::Continue)
        );
        assert_eq!(
            kernel_watch_tick(true, None, true, 0),
            (true, 0, WatchAction::Continue)
        );
    }

    #[test]
    fn never_active_does_not_lock() {
        assert_eq!(
            kernel_watch_tick(true, Some(1), false, 0),
            (false, 0, WatchAction::Continue)
        );
        assert_eq!(
            kernel_watch_tick(true, None, false, 0),
            (false, 0, WatchAction::Continue)
        );
    }

    #[test]
    fn non_secure_resets_state() {
        assert_eq!(
            kernel_watch_tick(false, Some(5), true, 1),
            (false, 0, WatchAction::Continue)
        );
    }
}
