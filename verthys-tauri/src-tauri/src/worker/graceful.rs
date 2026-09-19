//! worker/graceful.rs — 优雅退出与诊断
//!
//! 优雅退出与强制终止结合
//!   - stdin 发 {"op":"shutdown"} 命令
//!   - 等待 1 秒让子进程自行清理
//!   - 超时 child.kill() + await
//!
//! 只读诊断，惰性清理
//!   - 子进程退出/管道断裂时，Actor 仅记录退出状态 + stderr 尾部构造错误
//!   - stdin/stdout/stderr 句柄保持原样至 Actor 销毁
//!
//! 本模块对外提供：
//!   - reject_request_after_exit：子进程退出后拒绝新请求
//!   - perform_graceful_shutdown：发送 shutdown + 优雅期 + 强制 kill
//!   - mark_child_dead_if_needed：检测并标记子进程死亡
//!   - diagnose_exit：只读诊断退出原因（含 stderr 快照）

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::process::{Child, ChildStdin};

use super::actor::write_line;
use super::protocol::{ActorRequest, GRACEFUL_SHUTDOWN_TIMEOUT, STDERR_DIAG_MAX_LEN};
use super::stderr::{snapshot_stderr, truncate_utf8, StderrRing};

/// 拒绝子进程退出后的请求
///
/// 子进程已退出但 Actor 仍在运行（等待通道关闭），所有新请求返回统一错误。
pub(crate) fn reject_request_after_exit(req: ActorRequest, pid: u32) {
    let err = Err(format!("worker 子进程 PID={} 已退出", pid));
    match req {
        ActorRequest::Send { reply, .. }
        | ActorRequest::SendStreamingUnlock { reply, .. } => {
            let _ = reply.send(err);
        }
        ActorRequest::WaitReady { reply, .. } => {
            let _ = reply.send(err.map(|_| ()));
        }
        ActorRequest::Shutdown { reply } => {
            let _ = reply.send(());
        }
    }
}

/* ------------------------------------------------------------------ *
 * 优雅退出                                                            *
 *                                                                    *
 * stdin 发 {"op":"shutdown"} 等 1s；                    *
 *   超时 child.kill() + await。                                       *
 * ------------------------------------------------------------------ */
pub(crate) async fn perform_graceful_shutdown(
    stdin: &mut ChildStdin,
    child: &mut Child,
    pid: u32,
    child_alive: &Arc<AtomicBool>,
) {
    // 先检查子进程是否已退出
    match child.try_wait() {
        Ok(Some(status)) => {
            log::info!(
                "[actor] PID={} 子进程已退出: code={:?}，无需 shutdown",
                pid,
                status.code()
            );
            child_alive.store(false, Ordering::SeqCst);
            return;
        }
        Ok(None) => {} // 仍运行
        Err(e) => {
            log::warn!("[actor] PID={} try_wait 错误: {}", pid, e);
            child_alive.store(false, Ordering::SeqCst);
            return;
        }
    }

    // 1. 发送 shutdown 命令
    let shutdown_json = serde_json::json!({"op": "shutdown"}).to_string();
    if let Err(e) = write_line(stdin, &shutdown_json).await {
        log::warn!(
            "[actor] PID={} 发送 shutdown 失败（管道可能已关闭）: {}",
            pid,
            e
        );
    } else {
        log::info!("[actor] PID={} 已发送 shutdown 命令", pid);
    }

    // 2. 等待 1 秒优雅期
    let exited = match tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => {
            log::info!(
                "[actor] PID={} 子进程优雅退出: code={:?}",
                pid,
                status.code()
            );
            true
        }
        Ok(Err(e)) => {
            log::warn!("[actor] PID={} wait 错误: {}", pid, e);
            true
        }
        Err(_) => {
            log::warn!(
                "[actor] PID={} {}s 优雅期超时，强制 kill",
                pid,
                GRACEFUL_SHUTDOWN_TIMEOUT.as_secs()
            );
            false
        }
    };

    // 3. 超时则强制 kill + wait
    if !exited {
        if let Err(e) = child.kill().await {
            log::warn!("[actor] PID={} kill 失败: {}", pid, e);
        }
        let _ = child.wait().await;
    }

    child_alive.store(false, Ordering::SeqCst);
}

/// 检查子进程是否已退出，若已退出则标记 child_alive = false
pub(crate) async fn mark_child_dead_if_needed(
    child: &mut Child,
    child_alive: &Arc<AtomicBool>,
    pid: u32,
) {
    match child.try_wait() {
        Ok(Some(status)) => {
            log::warn!(
                "[actor] PID={} 子进程已退出: code={:?}",
                pid,
                status.code()
            );
            child_alive.store(false, Ordering::SeqCst);
        }
        Ok(None) => {
            // 子进程仍在运行（可能是管道断裂但进程未退出）
            // 不标记为 dead，让后续请求重试
        }
        Err(e) => {
            log::warn!("[actor] PID={} try_wait 错误: {}", pid, e);
            child_alive.store(false, Ordering::SeqCst);
        }
    }
}

/// 诊断子进程退出：只读，不清空句柄
///
/// 只读诊断，惰性清理。
/// 仅读取退出状态 + stderr 环形缓冲区快照构造错误信息。
/// stdin/stdout/stderr 句柄保持原样至 Actor 销毁。
pub(crate) async fn diagnose_exit(
    child: &mut Child,
    pid: u32,
    stderr_ring: &Arc<StdMutex<StderrRing>>,
) -> String {
    // 1. 检查子进程退出状态
    let exit_info = match child.try_wait() {
        Ok(Some(status)) => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(signal) = status.signal() {
                    format!("exit: signal {} ({})", signal, signal_name(signal))
                } else {
                    format!("exit: code {}", status.code().unwrap_or(-1))
                }
            }
            #[cfg(not(unix))]
            {
                format!("exit: code {}", status.code().unwrap_or(-1))
            }
        }
        Ok(None) => "exit: still running (pipe closed)".to_string(),
        Err(e) => format!("exit: try_wait error: {}", e),
    };

    // 2. 读取 stderr 环形缓冲区快照
    let stderr_trim = snapshot_stderr(stderr_ring);

    // 3. 拼装诊断信息
    if stderr_trim.is_empty() {
        format!("worker exited ({}) PID={}", exit_info, pid)
    } else {
        let truncated = truncate_utf8(&stderr_trim, STDERR_DIAG_MAX_LEN);
        format!(
            "worker exited ({}) PID={} | stderr: {}",
            exit_info, pid, truncated
        )
    }
}

/// Unix 信号名称（用于诊断信息）
#[cfg(unix)]
fn signal_name(signal: i32) -> &'static str {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        6 => "SIGABRT",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        15 => "SIGTERM",
        _ => "UNKNOWN",
    }
}
