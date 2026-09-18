//! worker/actor.rs — Actor 主循环与请求处理
//!
//! ★ 第 10.1 项：异步 Actor 消灭锁与阻塞
//!   - Actor 通过 tokio::sync::mpsc<Request> 接收请求（每请求携带 oneshot 回复通道）
//!   - tokio::select! 同时等待：新请求 / stdout 可读 / 超时 / stderr 可读
//!   - 所有管道操作单任务内串行，无锁（死锁根本不可能发生）
//!
//! ★ 第 10.2 项：异步超时替代轮询循环
//!   - tokio::time::timeout 包裹 read_line()
//!   - 进度感知超时用 select! 循环每条进度行重置超时
//!
//! ★ 第 10.4 项：流式响应处理
//!   - 内部 handle_streaming_unlock_send 处理解锁进度流
//!
//! 本模块对外提供：
//!   - actor_loop：Actor 主循环（被 session::spawn 调用）
//!   - write_line：stdin 写入辅助（被 graceful::perform_graceful_shutdown 复用）

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::graceful::{
    diagnose_exit, mark_child_dead_if_needed, perform_graceful_shutdown, reject_request_after_exit,
};
use super::protocol::{
    ActorRequest, UnlockProgress, STDERR_DRAIN_FINAL_TIMEOUT, UNLOCK_PROGRESS_IDLE_TIMEOUT,
    UNLOCK_PROGRESS_OP,
};
use super::stderr::{snapshot_stderr, StderrRing};

/* ------------------------------------------------------------------ *
 * Actor 主循环                                                        *
 *                                                                    *
 * ★ 第 10.1 项：单任务内串行处理所有管道操作，无锁。                  *
 * ★ 第 10.5 项：独立 drain_stderr 任务持续异步读取 stderr。           *
 * ------------------------------------------------------------------ */

/// Actor 主循环
///
/// 持有子进程的所有句柄，通过 mpsc 接收请求，串行处理。
/// 所有管道 I/O 使用 tokio 异步 API，不阻塞任何线程。
pub(crate) async fn actor_loop(
    mut child: Child,
    mut stdin: ChildStdin,
    stdout: ChildStdout,
    stderr: tokio::process::ChildStderr,
    mut request_rx: mpsc::Receiver<ActorRequest>,
    pid: u32,
    child_alive: Arc<AtomicBool>,
    stderr_ring: Arc<StdMutex<StderrRing>>,
) {
    log::info!("[actor] PID={} Actor 任务启动", pid);

    // ★ 第 10.5 项：启动 stderr 持续排空任务
    //    独立 tokio::task，BufReader 行缓冲全量写入日志
    //    即使子进程疯狂输出，管道永远不会满，IPC 通信不会被后台日志卡死
    let stderr_ring_for_task = stderr_ring.clone();
    let stderr_task: JoinHandle<()> = tokio::spawn(super::stderr::drain_stderr(
        stderr,
        pid,
        stderr_ring_for_task,
    ));

    let mut stdout_reader = BufReader::new(stdout);

    // 主循环：接收请求并处理
    while let Some(req) = request_rx.recv().await {
        // 子进程已退出：拒绝所有新请求
        if !child_alive.load(Ordering::SeqCst) {
            reject_request_after_exit(req, pid);
            continue;
        }
        match req {
            ActorRequest::Send { json, timeout, reply } => {
                let result = handle_send(
                    &mut stdin,
                    &mut stdout_reader,
                    &json,
                    timeout,
                    pid,
                    &mut child,
                    &stderr_ring,
                    &child_alive,
                )
                .await;
                let _ = reply.send(result);
            }
            ActorRequest::SendStreamingUnlock {
                json,
                reply,
                progress_tx,
            } => {
                let result = handle_streaming_unlock_send(
                    &mut stdin,
                    &mut stdout_reader,
                    &json,
                    &progress_tx,
                    pid,
                    &mut child,
                    &stderr_ring,
                    &child_alive,
                )
                .await;
                let _ = reply.send(result);
            }
            ActorRequest::WaitReady { timeout, reply } => {
                let result =
                    handle_wait_ready(&mut stdout_reader, timeout, pid, &mut child, &stderr_ring)
                        .await;
                let _ = reply.send(result);
            }
            ActorRequest::Shutdown { reply } => {
                log::info!("[actor] PID={} 收到 Shutdown 请求，执行优雅退出", pid);
                perform_graceful_shutdown(&mut stdin, &mut child, pid, &child_alive).await;
                let _ = reply.send(());
                break;
            }
        }
    }

    // 请求通道关闭：执行优雅退出
    log::info!("[actor] PID={} 请求通道关闭，开始优雅退出", pid);
    perform_graceful_shutdown(&mut stdin, &mut child, pid, &child_alive).await;

    // 等待 stderr 任务结束（短超时，确保最后的 stderr 输出被消费）
    log::info!("[actor] PID={} 等待 stderr 任务结束（{}ms 超时）", pid, STDERR_DRAIN_FINAL_TIMEOUT.as_millis());
    let _ = tokio::time::timeout(STDERR_DRAIN_FINAL_TIMEOUT, stderr_task).await;

    log::info!("[actor] PID={} Actor 任务退出", pid);
}

/* ------------------------------------------------------------------ *
 * 请求处理函数                                                        *
 * ------------------------------------------------------------------ */

/// 处理普通 IPC 请求
///
/// ★ 第 10.2 项：tokio::time::timeout 包裹 read_line()，
///   替代 PeekNamedPipe + thread::sleep(50ms) 轮询。
/// ★ 第 10.3 项：只读诊断，不清空句柄。
/// ★ 企业级修复（D-PROGRESS-SKIP）：跳过进度行，防止协议污染
///   当 worker 的进度回调已注册（前一次 unlock 注册）且当前非流式请求
///   触发 FFI 调用 emit progress 时，进度行会混入 stdout。
///   handle_send 必须跳过 op="unlock_progress" 行，
///   只返回真正的最终响应，否则响应解析失败。
async fn handle_send(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    json: &str,
    timeout: Duration,
    pid: u32,
    child: &mut Child,
    stderr_ring: &Arc<StdMutex<StderrRing>>,
    child_alive: &Arc<AtomicBool>,
) -> Result<String, String> {
    // 写入 stdin
    if let Err(e) = write_line(stdin, json).await {
        mark_child_dead_if_needed(child, child_alive, pid).await;
        return Err(format!("write stdin: {}", e));
    }

    // ★ 企业级修复：使用 deadline 循环读取，跳过进度行
    // 总超时不变（deadline 固定），每行读取使用剩余时间
    let deadline = Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            // 总超时
            let stderr_snippet = snapshot_stderr(stderr_ring);
            log::error!(
                "[worker] IPC 超时（{}s）: PID={} 仍在运行但无响应，请求: {} | stderr: {}",
                timeout.as_secs(),
                pid,
                json,
                stderr_snippet
            );
            return Err(format!(
                "worker 响应超时（{}s）— 子进程 PID={} 可能已挂起 | 诊断: {}",
                timeout.as_secs(),
                pid,
                stderr_snippet
            ));
        }

        let mut line = String::new();
        let read_result = tokio::time::timeout(remaining, stdout.read_line(&mut line)).await;

        match read_result {
            Ok(Ok(0)) => {
                // EOF — 子进程已退出
                mark_child_dead_if_needed(child, child_alive, pid).await;
                let diag = diagnose_exit(child, pid, stderr_ring).await;
                return Err(format!("worker 管道关闭: {}", diag));
            }
            Ok(Ok(_n)) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    mark_child_dead_if_needed(child, child_alive, pid).await;
                    let diag = diagnose_exit(child, pid, stderr_ring).await;
                    return Err(format!("worker 返回空行: {}", diag));
                }

                // ★ 企业级修复：跳过进度行（unlock_progress）
                // 这些行由 C 层进度消费线程异步写入 stdout，不是当前请求的最终响应。
                // 解析 JSON 提取 op 字段，若为进度行则继续读取下一行。
                let is_progress_line = serde_json::from_str::<serde_json::Value>(&trimmed)
                    .ok()
                    .and_then(|v| {
                        v.get("op")
                            .and_then(|o| o.as_str())
                            .map(|s| s == UNLOCK_PROGRESS_OP)
                    })
                    .unwrap_or(false);

                if is_progress_line {
                    log::debug!(
                        "[worker] handle_send 跳过进度行（非流式请求中的残留进度）: PID={}",
                        pid
                    );
                    continue; // 读取下一行
                }

                return Ok(trimmed);
            }
            Ok(Err(e)) => {
                mark_child_dead_if_needed(child, child_alive, pid).await;
                return Err(format!("read stdout: {}", e));
            }
            Err(_) => {
                // 本轮读取超时（但总 deadline 可能未到）
                let stderr_snippet = snapshot_stderr(stderr_ring);
                log::error!(
                    "[worker] IPC 超时（{}s）: PID={} 仍在运行但无响应，请求: {} | stderr: {}",
                    timeout.as_secs(),
                    pid,
                    json,
                    stderr_snippet
                );
                return Err(format!(
                    "worker 响应超时（{}s）— 子进程 PID={} 可能已挂起 | 诊断: {}",
                    timeout.as_secs(),
                    pid,
                    stderr_snippet
                ));
            }
        }
    }
}

/// 处理解锁流式进度请求
///
/// ★ 第 10.4 项：进度行解析、推送与日志格式化。
/// ★ 第 10.2 项：进度感知超时，每收到一条进度行重置 deadline。
///
/// 协议：
///   - worker 在 call_unlock 阻塞期间，由 C 回调向 stdout 写入
///     多条 {"op":"unlock_progress",...} 进度行
///   - C 函数返回后写入最终 {"op":"unlock",...} 终止行
///   - 本函数识别进度行并推送 progress_tx，遇到终止行返回
async fn handle_streaming_unlock_send(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    json: &str,
    progress_tx: &mpsc::Sender<UnlockProgress>,
    pid: u32,
    child: &mut Child,
    stderr_ring: &Arc<StdMutex<StderrRing>>,
    child_alive: &Arc<AtomicBool>,
) -> Result<String, String> {
    let idle_timeout = UNLOCK_PROGRESS_IDLE_TIMEOUT;

    // 写入 stdin
    if let Err(e) = write_line(stdin, json).await {
        mark_child_dead_if_needed(child, child_alive, pid).await;
        return Err(format!("write stdin: {}", e));
    }

    // 进度感知 deadline：每收到一条进度行即重置
    let mut deadline = Instant::now() + idle_timeout;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());

        let mut line = String::new();
        let read_result = tokio::time::timeout(remaining, stdout.read_line(&mut line)).await;

        match read_result {
            Ok(Ok(0)) => {
                // EOF — 子进程已退出
                mark_child_dead_if_needed(child, child_alive, pid).await;
                let diag = diagnose_exit(child, pid, stderr_ring).await;
                return Err(format!("解锁期间 worker 管道关闭: {}", diag));
            }
            Ok(Ok(_)) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    // 空行，继续
                    continue;
                }

                // 解析 op 字段
                let op = serde_json::from_str::<serde_json::Value>(&trimmed)
                    .ok()
                    .and_then(|v| {
                        v.get("op")
                            .and_then(|o| o.as_str())
                            .map(|s| s.to_string())
                    });

                if op.as_deref() == Some(UNLOCK_PROGRESS_OP) {
                    // 进度行：解析并推送，重置 deadline
                    match serde_json::from_str::<UnlockProgress>(&trimmed) {
                        Ok(p) => {
                            log::info!(
                                "[worker] 解锁进度: stage={} percent={}% elapsed={}ms msg={}",
                                p.stage,
                                p.percent,
                                p.elapsed_ms,
                                p.message
                            );
                            // 推送到进度通道（best-effort，前端关闭则丢弃）
                            if progress_tx.send(p).await.is_err() {
                                log::warn!(
                                    "[worker] 解锁进度通道已关闭（前端可能已断开）: PID={}",
                                    pid
                                );
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "[worker] 解锁进度行解析失败: {} | raw={}",
                                e,
                                trimmed
                            );
                        }
                    }
                    deadline = Instant::now() + idle_timeout;
                } else {
                    // 非进度行：视为最终响应（op=unlock 或错误）
                    return Ok(trimmed);
                }
            }
            Ok(Err(e)) => {
                mark_child_dead_if_needed(child, child_alive, pid).await;
                return Err(format!("read stdout: {}", e));
            }
            Err(_) => {
                // 超时
                let stderr_snippet = snapshot_stderr(stderr_ring);
                log::error!(
                    "[worker] 解锁进度超时（{}s 无进度）: PID={} | stderr: {}",
                    idle_timeout.as_secs(),
                    pid,
                    stderr_snippet
                );
                return Err(format!(
                    "解锁进度超时（{}s 无进度）— 子进程 PID={} 可能已挂起 | 诊断: {}",
                    idle_timeout.as_secs(),
                    pid,
                    stderr_snippet
                ));
            }
        }
    }
}

/// 处理就绪检测请求
///
/// 等待 worker 主动推送的 ready 信号（非空行）。
/// 超时返回错误，不发送 ping，避免协议失步。
async fn handle_wait_ready(
    stdout: &mut BufReader<ChildStdout>,
    timeout: Duration,
    pid: u32,
    child: &mut Child,
    stderr_ring: &Arc<StdMutex<StderrRing>>,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let stderr_snippet = snapshot_stderr(stderr_ring);
            let stderr_display = if stderr_snippet.is_empty() {
                "<空 — 可能使用旧版本二进制>".to_string()
            } else {
                stderr_snippet
            };
            let combined = format!(
                "worker 就绪信号超时（{}s）— PID={} 可能已挂起 | stderr: {}",
                timeout.as_secs(),
                pid,
                stderr_display
            );
            log::error!("[worker] 就绪检测失败: {}", combined);
            return Err(format!("worker 就绪检测失败: {}", combined));
        }

        let mut line = String::new();
        match tokio::time::timeout(remaining, stdout.read_line(&mut line)).await {
            Ok(Ok(0)) => {
                // EOF — 子进程已退出
                let diag = diagnose_exit(child, pid, stderr_ring).await;
                log::error!("[worker] 就绪检测：子进程已崩溃: {}", diag);
                return Err(format!(
                    "worker 就绪检测失败: 子进程已崩溃 — {}",
                    diag
                ));
            }
            Ok(Ok(_)) => {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    log::info!("[worker] 收到就绪信号: {}", trimmed);
                    return Ok(());
                }
                // 空行，继续读取
            }
            Ok(Err(e)) => {
                return Err(format!("worker 就绪检测失败: read stdout: {}", e));
            }
            Err(_) => {
                let stderr_snippet = snapshot_stderr(stderr_ring);
                let stderr_display = if stderr_snippet.is_empty() {
                    "<空 — 可能使用旧版本二进制>".to_string()
                } else {
                    stderr_snippet
                };
                let combined = format!(
                    "worker 就绪信号超时（{}s）— PID={} 可能已挂起 | stderr: {}",
                    timeout.as_secs(),
                    pid,
                    stderr_display
                );
                log::error!("[worker] 就绪检测失败: {}", combined);
                return Err(format!("worker 就绪检测失败: {}", combined));
            }
        }
    }
}

/* ------------------------------------------------------------------ *
 * 辅助函数                                                            *
 * ------------------------------------------------------------------ */

/// 写入一行 JSON 到 stdin（带换行符 + flush）
pub(crate) async fn write_line(stdin: &mut ChildStdin, json: &str) -> Result<(), String> {
    stdin
        .write_all(json.as_bytes())
        .await
        .map_err(|e| format!("write stdin: {}", e))?;
    stdin
        .write_all(b"\n")
        .await
        .map_err(|e| format!("write stdin newline: {}", e))?;
    stdin
        .flush()
        .await
        .map_err(|e| format!("flush stdin: {}", e))?;
    Ok(())
}
