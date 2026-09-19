//! worker/session.rs — WorkerSession 公共 API（保留兼容签名）
//!
//! WorkerSession 改为异步 Actor 模型
//!
//! 内部通过 Arc<SessionInner> 共享状态：
//!   - request_tx: mpsc 通道发送请求到 Actor 任务
//!   - actor_handle: Actor 任务句柄（Drop 时等待退出）
//!   - runtime_handle: tokio 运行时句柄（sync 方法驱动 async future）
//!   - child_alive: 子进程存活标志（AtomicBool，is_alive() 读取）
//!   - pid / started_at: 看门狗元数据
//!
//! derive(Clone) 使其可被廉价克隆（Arc 引用计数 +1）。
//! AppState.session 为 RwLock<Option<WorkerSession>>，send 方法仅用 read()
//! 锁获取克隆后立即释放，多个 IPC 命令可并发获取 session 引用。
//! 实际的 stdin/stdout 串行化由 Actor 单任务保证（管道本质串行），
//! 但 RwLock 层不再阻塞 set_session 等写操作。
//!
//! 公共 API 兼容策略：
//!   保留 spawn/send_json/send_json_with_timeout/
//!   send_json_with_unlock_progress/wait_for_ready_signal/pid/elapsed_secs/
//!   is_alive/kill/Clone/Drop 签名，内部通过 Handle::block_on + block_in_place
//!   包装为同步返回，使 state.rs 与控制器无需立即改签名即可编译。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::actor::actor_loop;
use super::platform::assign_child_to_job_object;
#[cfg(target_os = "windows")]
use super::platform::JobHandle;
use super::protocol::{
    ActorRequest, UnlockProgress, DEFAULT_IPC_TIMEOUT, DROP_ACTOR_JOIN_TIMEOUT,
    READY_CHECK_TIMEOUT,
};
use super::stderr::StderrRing;

// Windows CloseHandle 用于 Drop 中显式关闭 Job Object 句柄
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::CloseHandle;

/// WorkerSession 改为异步 Actor 模型
///
/// 内部通过 Arc<SessionInner> 共享状态：
///   - request_tx: mpsc 通道发送请求到 Actor 任务
///   - actor_handle: Actor 任务句柄（Drop 时等待退出）
///   - runtime_handle: tokio 运行时句柄（sync 方法驱动 async future）
///   - child_alive: 子进程存活标志（AtomicBool，is_alive() 读取）
///   - pid / started_at: 看门狗元数据
///
/// derive(Clone) 使其可被廉价克隆（Arc 引用计数 +1）。
/// AppState.session 为 RwLock<Option<WorkerSession>>，send 方法仅用 read()
/// 锁获取克隆后立即释放，多个 IPC 命令可并发获取 session 引用。
/// 实际的 stdin/stdout 串行化由 Actor 单任务保证（管道本质串行），
/// 但 RwLock 层不再阻塞 set_session 等写操作。
#[derive(Clone)]
pub struct WorkerSession {
    pub(crate) inner: Arc<SessionInner>,
}

/// WorkerSession 内部状态（Arc 共享）
pub(crate) struct SessionInner {
    /// Actor 请求通道（封装在 StdMutex<Option> 中）
    /// - Some(Sender)：Actor 存活，可发送请求
    /// - None：Actor 已退出或正在关闭，拒绝新请求
    ///
    /// 通过 take() 取出并 drop 即可关闭通道，触发 Actor 主循环退出。
    /// 使用 std::sync::Mutex 因为持有时间极短（仅 clone/take），不跨 await。
    request_tx: StdMutex<Option<mpsc::Sender<ActorRequest>>>,
    /// Actor 任务句柄（Drop 时取出并等待退出）
    /// 使用 std::sync::Mutex 因为持有时间极短（仅 take），不跨 await
    actor_handle: StdMutex<Option<JoinHandle<()>>>,
    /// tokio 运行时句柄（用于在 sync 方法中通过 block_in_place + block_on 驱动 async）
    runtime_handle: tokio::runtime::Handle,
    /// 子进程 PID（看门狗记录）
    pid: u32,
    /// 启动时间（看门狗记录，用于检测超时和异常退出）
    started_at: Instant,
    /// 子进程存活标志（Actor 更新，is_alive() 读取）
    child_alive: Arc<AtomicBool>,
    /// ★ 企业级根治：Windows Job Object 句柄（KILL_ON_JOB_CLOSE）
    ///   父进程退出时内核自动关闭此句柄 → 自动终止 Job 内所有子进程
    ///   None 表示 Job Object 创建失败，回退到 kill_on_drop 兜底
    #[cfg(target_os = "windows")]
    job_handle: StdMutex<Option<JobHandle>>,
}

impl SessionInner {
    /// 克隆请求通道 Sender（如果 Actor 仍存活）
    ///
    /// 返回 None 表示通道已关闭（Actor 已退出或正在关闭）。
    fn clone_sender(&self) -> Option<mpsc::Sender<ActorRequest>> {
        self.request_tx
            .lock()
            .ok()
            .and_then(|g| g.clone())
    }

    /// 取出并丢弃请求通道 Sender，关闭通道
    ///
    /// 触发 Actor 主循环 recv() 返回 None，开始优雅退出。
    /// 幂等：多次调用安全（首次后 Option 为 None）。
    fn close_request_channel(&self) {
        if let Ok(mut guard) = self.request_tx.lock() {
            let _ = guard.take();
        }
    }
}

impl WorkerSession {
    /// 启动子进程：verthys-worker.exe <dll_path>
    ///
    /// 使用 tokio::process::Command 创建子进程，获取异步句柄。
    /// Actor 任务在当前 tokio 运行时中 spawn。
    ///
    /// 必须在 tokio 运行时上下文中调用（通常由 spawn_blocking 包裹）。
    pub fn spawn(worker_exe: &str, dll_path: &str) -> Result<Self, String> {
        // 捕获当前 tokio 运行时句柄
        // spawn 通常在 tokio::task::spawn_blocking 中调用，运行时上下文可用
        let runtime_handle = tokio::runtime::Handle::try_current().map_err(|e| {
            format!(
                "WorkerSession::spawn 必须在 tokio runtime 上下文中调用（通常由 spawn_blocking 包裹）: {}",
                e
            )
        })?;

        // 构建 tokio::process::Command
        let mut cmd = Command::new(worker_exe);
        cmd.arg(dll_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            // ★ 安全兜底：Actor 任务异常终止时子进程不会成为孤儿
            .kill_on_drop(true);

        // Windows: 不创建控制台窗口 + 后台任务降级
        // ★ BELOW_NORMAL_PRIORITY_CLASS (0x00004000)：
        //   worker 进程承载后台 Merkle 重建 / 全量扫描 / 完整性巡检等长尾任务，
        //   优先级低于 UI 主进程（NORMAL），保证前端 IPC 始终优先获得 CPU 调度。
        //   消除解锁后前 10 秒「后台任务抢占 CPU 导致界面卡顿」问题。
        //   效果：消除后台任务抢占 CPU 导致的解锁后界面卡顿。
        #[cfg(target_os = "windows")]
        {
            // tokio::process::Command 在 Windows 上有固有的 creation_flags 方法
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x00004000;
            cmd.creation_flags(CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS);
        }

        // 同步 spawn（tokio::process::Command::spawn 是同步方法，注册 I/O 驱动）
        let mut child = cmd.spawn().map_err(|e| format!("spawn worker: {}", e))?;

        let pid = child.id().ok_or_else(|| "无法获取子进程 PID".to_string())?;
        let stdin = child.stdin.take().ok_or_else(|| "no stdin".to_string())?;
        let stdout = child.stdout.take().ok_or_else(|| "no stdout".to_string())?;
        let stderr = child.stderr.take().ok_or_else(|| "no stderr".to_string())?;

        log::info!(
            "[watchdog] worker 子进程已启动: PID={}, dll={}",
            pid,
            dll_path
        );

        // 创建 Actor 请求通道
        let (request_tx, request_rx) = mpsc::channel::<ActorRequest>(32);

        // 子进程存活标志
        let child_alive = Arc::new(AtomicBool::new(true));

        // stderr 环形缓冲区（Actor 与 drain_stderr 任务共享）
        let stderr_ring = Arc::new(StdMutex::new(StderrRing::new()));

        // 在当前 tokio 运行时中 spawn Actor 任务
        let actor_handle = runtime_handle.spawn(actor_loop(
            child,
            stdin,
            stdout,
            stderr,
            request_rx,
            pid,
            child_alive.clone(),
            stderr_ring,
        ));

        Ok(WorkerSession {
            inner: Arc::new(SessionInner {
                request_tx: StdMutex::new(Some(request_tx)),
                actor_handle: StdMutex::new(Some(actor_handle)),
                runtime_handle,
                pid,
                started_at: Instant::now(),
                child_alive,
                #[cfg(target_os = "windows")]
                job_handle: StdMutex::new(assign_child_to_job_object(pid)),
            }),
        })
    }

    /// 获取子进程 PID（看门狗）
    pub fn pid(&self) -> u32 {
        self.inner.pid
    }

    /// 获取子进程已运行时间（秒，看门狗）
    pub fn elapsed_secs(&self) -> u64 {
        self.inner.started_at.elapsed().as_secs()
    }

    /// 检查子进程是否仍在运行
    ///
    /// 通过 AtomicBool 标志判断（Actor 在子进程退出时设为 false）。
    pub fn is_alive(&self) -> bool {
        self.inner.child_alive.load(Ordering::SeqCst)
    }

    /// 发送 JSON 请求并等待 JSON 响应（默认 15 秒超时）
    pub fn send_json(&self, json: &str) -> Result<String, String> {
        self.send_json_with_timeout(json, DEFAULT_IPC_TIMEOUT)
    }

    /// 发送 JSON 请求并等待 JSON 响应（自定义超时）
    ///
    /// 使用 tokio::time::timeout 包裹 read_line()，
    /// 替代 PeekNamedPipe + thread::sleep(50ms) 轮询。
    pub fn send_json_with_timeout(
        &self,
        json: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let json_owned = json.to_string();
        let request_tx = self.inner.clone_sender().ok_or_else(|| {
            "worker actor 已退出（通道已关闭）".to_string()
        })?;
        let runtime_handle = self.inner.runtime_handle.clone();

        block_on_with_handle(&runtime_handle, async move {
            let (reply_tx, reply_rx) = oneshot::channel();

            request_tx
                .send(ActorRequest::Send {
                    json: json_owned,
                    timeout,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| "worker actor 已退出（通道发送失败）".to_string())?;

            reply_rx
                .await
                .map_err(|_| "worker actor 通道关闭（任务已终止）".to_string())?
        })
    }

    /* ---------------------------------------------------------------- *
     * 解锁进度流式协议                                          *
     *                                                                  *
     * send_json_with_unlock_progress 专为 Verthys_Unlock 设计：           *
     *   - worker 在 call_unlock 阻塞期间，由 C 回调向 stdout 写入       *
     *     多条 {"op":"unlock_progress",...} 进度行                     *
     *   - C 函数返回后写入最终 {"op":"unlock",...} 终止行               *
     *   - 本方法识别进度行并调用 progress_cb，遇到终止行返回           *
     *                                                                  *
     * 超时策略（进度感知）：                                            *
     *   - 每收到一条进度行即重置 deadline（Argon2id 阶段无进度事件，   *
     *     需足够长的 idle timeout 覆盖 SECURE 预设 6~15s 派生时间）    *
     *   - 连续 idle_timeout 无进度视为挂起                              *
     *   - 初始等待也使用 idle_timeout                                  *
     * ---------------------------------------------------------------- */

    /// 发送解锁请求并流式接收进度
    ///
    /// - `json`：unlock 请求 JSON
    /// - `progress_cb`：每收到一条 unlock_progress 行时调用
    ///
    /// 返回最终 unlock 行的原始 JSON 字符串。
    ///
    /// 内部复用通用 handle_streaming_send<T> 泛型方法。
    pub fn send_json_with_unlock_progress(
        &self,
        json: &str,
        progress_cb: &dyn Fn(&UnlockProgress),
    ) -> Result<String, String> {
        let json_owned = json.to_string();
        let request_tx = self.inner.clone_sender().ok_or_else(|| {
            "worker actor 已退出（通道已关闭）".to_string()
        })?;
        let runtime_handle = self.inner.runtime_handle.clone();

        block_on_with_handle(&runtime_handle, async move {
            let (reply_tx, mut reply_rx) = oneshot::channel();
            let (progress_tx, mut progress_rx) = mpsc::channel::<UnlockProgress>(64);

            request_tx
                .send(ActorRequest::SendStreamingUnlock {
                    json: json_owned,
                    reply: reply_tx,
                    progress_tx,
                })
                .await
                .map_err(|_| "worker actor 已退出（通道发送失败）".to_string())?;

            loop {
                tokio::select! {
                    result = &mut reply_rx => {
                        /* ★ 企业级根治修复：drain progress_rx 残留进度消息
                         *
                         * 根因：tokio::select! 的公平性导致 reply_rx（最终响应）可能
                         * 在 progress_rx 中所有进度消息被处理完之前被选中。此时
                         * return 会 drop progress_rx，残留进度消息被丢弃，前端
                         * Tauri Channel 收到的最后一条消息可能是中间阶段的心跳
                         * （如"密钥计算较慢"），而非 100%"解锁完成"。
                         *
                         * 修复：reply_rx 就绪后，先 try_recv 排空 progress_rx 中
                         * 已入队的进度消息（同步调用 progress_cb 推送到 Tauri Channel），
                         * 确保所有进度消息按顺序到达前端，再返回最终响应。
                         *
                         * 注意：try_recv 是非阻塞的，仅排空已入队消息，不会等待
                         * Actor 推送新消息（Actor 此时已返回 handle_streaming_send
                         * 结果，不会再推送新进度）。 */
                        while let Ok(p) = progress_rx.try_recv() {
                            progress_cb(&p);
                        }
                        return match result {
                            Ok(r) => r,
                            Err(_) => Err("worker actor 通道关闭（任务已终止）".to_string()),
                        };
                    }
                    progress = progress_rx.recv() => {
                        if let Some(p) = progress {
                            progress_cb(&p);
                        }
                    }
                }
            }
        })
    }

    /// 就绪检测：等待 worker 主动推送的 ready 信号
    ///
    /// worker 在进入主循环前会主动写入 {"ok":true,"op":"ready"} 到 stdout。
    /// 此方法读取该信号，无需发送 ping，避免协议失步（ping 响应与 ready 信号混淆）。
    ///
    /// 诊断价值：
    ///   - 收到 ready 信号 → DLL 加载成功、Verthys_Init 成功、主循环已启动
    ///   - 超时 + stderr 有内容 → 可判断 worker 卡在哪一步（DLL 加载/Verthys_Init）
    ///   - 超时 + stderr 为空 → worker 使用旧版本二进制（无 eprintln 诊断）
    pub fn wait_for_ready_signal(&self) -> Result<(), String> {
        let request_tx = self.inner.clone_sender().ok_or_else(|| {
            "worker actor 已退出（通道已关闭）".to_string()
        })?;
        let runtime_handle = self.inner.runtime_handle.clone();

        block_on_with_handle(&runtime_handle, async move {
            let (reply_tx, reply_rx) = oneshot::channel();

            request_tx
                .send(ActorRequest::WaitReady {
                    timeout: READY_CHECK_TIMEOUT,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| "worker actor 已退出（通道发送失败）".to_string())?;

            reply_rx
                .await
                .map_err(|_| "worker actor 通道关闭（任务已终止）".to_string())?
        })
    }

    /// 终止子进程（1 秒优雅期 + 超时强制 TerminateProcess）
    ///
    /// 优雅退出与强制终止结合
    /// 流程：
    ///   1. 发送 Shutdown 请求到 Actor
    ///   2. Actor 向 stdin 发 {"op":"shutdown"} 命令
    ///   3. 等待 1 秒让子进程自行清理
    ///   4. 超时 child.kill()（Windows 即 TerminateProcess）+ child.wait() 回收
    ///   5. Actor 任务退出
    ///
    /// 安全保证：优雅退出让子进程有机会执行密钥三轮覆写与句柄释放；
    ///           1 秒硬超时兜底保证主进程关闭路径不被拖死。
    pub fn kill(&self) {
        let runtime_handle = self.inner.runtime_handle.clone();
        let pid = self.inner.pid;

        log::info!("[watchdog] kill() 调用: PID={}", pid);

        // 1. 关闭请求通道，触发 Actor 主循环退出并执行优雅关闭
        //    take() 取出 Sender 并 drop，所有 recv() 返回 None
        self.inner.close_request_channel();

        // 2. 取出 actor_handle 并等待退出
        let actor_handle_opt = self
            .inner
            .actor_handle
            .lock()
            .ok()
            .and_then(|mut g| g.take());

        if let Some(actor_handle) = actor_handle_opt {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                block_on_with_handle(&runtime_handle, async move {
                    match tokio::time::timeout(DROP_ACTOR_JOIN_TIMEOUT, actor_handle).await {
                        Ok(Ok(())) => {
                            log::info!("[watchdog] kill() 后 Actor 优雅退出: PID={}", pid)
                        }
                        Ok(Err(e)) => log::warn!(
                            "[watchdog] kill() 后 Actor 任务 panic: PID={} err={}",
                            pid,
                            e
                        ),
                        Err(_) => log::warn!(
                            "[watchdog] kill() 后 {}s 超时，Actor 任务分离: PID={}",
                            DROP_ACTOR_JOIN_TIMEOUT.as_secs(),
                            pid
                        ),
                    }
                });
            }));
        }
    }
}

/* ------------------------------------------------------------------ *
 * SessionInner 析构：确保 Actor 任务退出与子进程回收                   *
 *                                                                    *
 * 主线程 drop Sender，Actor 侦测通道关闭自动触发退出。  *
 * ------------------------------------------------------------------ */
impl Drop for SessionInner {
    fn drop(&mut self) {
        let pid = self.pid;
        log::info!("[actor] WorkerSession 析构开始: PID={}", pid);

        // 1. 关闭请求通道，触发 Actor 主循环退出
        //    take() 取出 Sender 并 drop，所有 recv() 返回 None
        self.close_request_channel();

        // 2. 取出 actor_handle（若 kill() 已取走则为 None）
        let actor_handle_opt = self
            .actor_handle
            .lock()
            .ok()
            .and_then(|mut g| g.take());

        if let Some(actor_handle) = actor_handle_opt {
            let runtime_handle = self.runtime_handle.clone();

            // 3. 等待 Actor 退出（带超时，防止 Drop 卡死进程）
            //    使用 catch_unwind 防止 Drop 中 panic 导致进程终止
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                block_on_with_handle(&runtime_handle, async move {
                    match tokio::time::timeout(DROP_ACTOR_JOIN_TIMEOUT, actor_handle).await {
                        Ok(Ok(())) => {
                            log::info!("[actor] PID={} 析构时 Actor 优雅退出完成", pid)
                        }
                        Ok(Err(e)) => log::warn!(
                            "[actor] PID={} 析构时 Actor 任务 panic: {}",
                            pid,
                            e
                        ),
                        Err(_) => log::warn!(
                            "[actor] PID={} 析构时 {}s 超时，强制分离 Actor 任务",
                            pid,
                            DROP_ACTOR_JOIN_TIMEOUT.as_secs()
                        ),
                    }
                });
            }));
        }

        // 4. 兜底：child_alive 标志设为 false
        //    若 Actor 未能正常退出（超时/panic），kill_on_drop(true) 仍会回收子进程
        self.child_alive.store(false, Ordering::SeqCst);

        // ★ 企业级根治：显式关闭 Job Object 句柄
        //   KILL_ON_JOB_CLOSE 在句柄关闭时自动终止 Job 内子进程（双保险）
        //   即使 Drop 链正常执行也释放内核资源，杜绝句柄泄漏
        #[cfg(target_os = "windows")]
        {
            if let Ok(mut g) = self.job_handle.lock() {
                if let Some(h) = g.take() {
                    unsafe { let _ = CloseHandle(h.0); }
                }
            }
        }

        log::info!("[actor] WorkerSession 析构完成: PID={}", pid);
    }
}

/// 在 tokio 运行时上下文中同步驱动 async future
///
/// ★ 公共 API 兼容策略：sync 方法内部通过 Handle::block_on + block_in_place 包装。
///
/// 策略：
///   - 若当前线程在 tokio 运行时上下文中（Handle::try_current 成功）：
///     使用 block_in_place + handle.block_on，避免嵌套 runtime panic
///   - 否则：直接 handle.block_on
///
/// 注意：tauri 使用多线程运行时，block_in_place 正常工作。
/// 测试中需使用 #[tokio::test(flavor = "multi_thread")]。
pub(crate) fn block_on_with_handle<F, T>(handle: &tokio::runtime::Handle, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        // 在某个 tokio 运行时内 — 使用 block_in_place 避免嵌套 runtime panic
        // 注意：若为 current_thread 运行时，block_in_place 会 panic
        // tauri 使用多线程运行时，正常情况下不会触发
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        // 不在任何 tokio 运行时内 — 直接 block_on
        handle.block_on(fut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 WorkerSession::spawn 在无 tokio 运行时上下文时返回错误
    #[test]
    fn test_spawn_requires_runtime() {
        // 不在 tokio 运行时上下文中
        let result = WorkerSession::spawn("nonexistent.exe", "nonexistent.dll");
        // 用 match 替代 unwrap_err()，避免要求 WorkerSession: Debug
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("spawn 应在无运行时上下文时失败"),
        };
        assert!(
            err.contains("tokio runtime"),
            "错误信息应提及 tokio runtime，实际: {}",
            err
        );
    }
}
