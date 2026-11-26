//! 会话生命周期：内部状态、启动、健康查询、终止与析构。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::worker::actor::actor_loop;
#[cfg(target_os = "windows")]
use super::heartbeat::{create_heartbeat_event, HeartbeatEvent};
use super::host_env::dev_machine_limiter_bypass;
#[cfg(target_os = "windows")]
use super::host_env::{prearm_image, test_register_failure};
use crate::worker::platform::verify_install_paths;
#[cfg(target_os = "windows")]
use crate::worker::platform::{
    prepare_suspended_worker, process_creation_time_quad, resume_and_close_suspended_worker,
    JobHandle,
};
use crate::worker::protocol::{ActorRequest, DROP_ACTOR_JOIN_TIMEOUT};
use crate::worker::stderr::StderrRing;
use crate::infrastructure::ipc_secure::IpcSecureChannel;

// Windows CloseHandle 用于 Drop 中显式关闭 Job Object 句柄
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, HANDLE};

/// WorkerSession：异步 Actor 模型的同步门面
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
/// RwLock 层不阻塞 set_session 等写操作。
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
    pub(super) request_tx: StdMutex<Option<mpsc::Sender<ActorRequest>>>,
    /// Actor 任务句柄（Drop 时取出并等待退出）
    /// 使用 std::sync::Mutex 因为持有时间极短（仅 take），不跨 await
    pub(super) actor_handle: StdMutex<Option<JoinHandle<()>>>,
    /// tokio 运行时句柄（用于在 sync 方法中通过 block_in_place + block_on 驱动 async）
    pub(super) runtime_handle: tokio::runtime::Handle,
    /// 子进程 PID（看门狗记录）
    pub(super) pid: u32,
    /// 启动时间（看门狗记录，用于检测超时和异常退出）
    pub(super) started_at: Instant,
    /// 子进程存活标志（Actor 更新，is_alive() 读取）
    pub(super) child_alive: Arc<AtomicBool>,
    /// Windows Job Object 句柄（KILL_ON_JOB_CLOSE）
    ///   父进程退出时内核自动关闭此句柄 → 自动终止 Job 内所有子进程
    ///   None 表示 Job Object 创建失败，回退到 kill_on_drop 兜底
    #[cfg(target_os = "windows")]
    pub(super) job_handle: StdMutex<Option<JobHandle>>,
    /// 父进程心跳事件（worker 每 500ms SetEvent；未创建时 None → 守卫降级）
    #[cfg(target_os = "windows")]
    pub(super) heartbeat_event: Option<Arc<HeartbeatEvent>>,
    /// worker 进程内的心跳事件句柄值（经签名 IPC 下发）
    #[cfg(target_os = "windows")]
    pub(super) heartbeat_worker_handle: u64,
    /// 挂起看门狗停止标志与线程句柄
    pub(super) suspend_stop: Arc<AtomicBool>,
    pub(super) suspend_thread: StdMutex<Option<std::thread::JoinHandle<()>>>,
    /// 会话正常停止标志：区分主动替换/销毁与 worker 异常退出。
    /// 主动停止时内核看门狗直接退出，不触发 worker_exit 锁定。
    pub(super) stop: Arc<AtomicBool>,
}

impl SessionInner {
    /// 克隆请求通道 Sender（如果 Actor 仍存活）
    ///
    /// 返回 None 表示通道已关闭（Actor 已退出或正在关闭）。
    pub(super) fn clone_sender(&self) -> Option<mpsc::Sender<ActorRequest>> {
        self.request_tx.lock().ok().and_then(|g| g.clone())
    }

    /// 取出并丢弃请求通道 Sender，关闭通道
    ///
    /// 触发 Actor 主循环 recv() 返回 None，开始优雅退出。
    /// 幂等：多次调用安全（首次后 Option 为 None）。
    pub(super) fn close_request_channel(&self) {
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

        // 先校验产物归属：Release 下 worker 与 DLL 必须位于安装目录内，
        // 避免解析逻辑被替换后启动目录外二进制。
        verify_install_paths(worker_exe, dll_path)?;

        // 会话密钥与挑战值经匿名管道首行交付（Actor 启动后写入），
        // 不进入子进程环境块：环境块可被同用户进程以 PROCESS_VM_READ 读取。
        let ipc_channel = IpcSecureChannel::new()?;

        // 构建 tokio::process::Command
        let mut cmd = Command::new(worker_exe);
        if let Some((key, value)) = dev_machine_limiter_bypass() {
            cmd.env(key, value);
        }
        cmd.arg(dll_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            // 安全兜底：Actor 任务异常终止时子进程不会成为孤儿
            .kill_on_drop(true);

        // Windows: 挂起创建 + 不创建控制台窗口 + 后台任务降级
        // CREATE_SUSPENDED (0x00000004)：
        //   子进程在加载任何用户态代码前保持挂起，宿主在此期间施加
        //   Job Object 资源上限与受限 DACL，再恢复主线程，消除
        //   「先运行后加固」的竞态窗口。
        // BELOW_NORMAL_PRIORITY_CLASS (0x00004000)：
        //   worker 进程承载后台 Merkle 重建 / 全量扫描 / 完整性巡检等长尾任务，
        //   优先级低于 UI 主进程（NORMAL），保证前端 IPC 始终优先获得 CPU 调度。
        #[cfg(target_os = "windows")]
        {
            // tokio::process::Command 在 Windows 上有固有的 creation_flags 方法
            const CREATE_SUSPENDED: u32 = 0x00000004;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x00004000;
            cmd.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS);
        }

        // A14：宿主在 worker 创建前 ARM 同目录 worker 路径，消除
        // 「worker 已存在但尚未 ARM」的同用户预开句柄窗口。
        // 失败按 preferred 降级为仅用户态防护，不伪造 ACTIVE。
        #[cfg(target_os = "windows")]
        let prearmed = match prearm_image(worker_exe) {
            Some(image) => {
                match crate::infrastructure::security_service_client::kernel_arm_host(image) {
                    Ok(()) => {
                        log::info!("[kernel-guard] 宿主预 ARM 已提交");
                        true
                    }
                    Err(e) => {
                        log::warn!("[kernel-guard] 宿主预 ARM 未生效（preferred）: {}", e);
                        false
                    }
                }
            }
            None => false,
        };
        #[cfg(not(target_os = "windows"))]
        let prearmed = false;

        // 同步 spawn（tokio::process::Command::spawn 是同步方法，注册 I/O 驱动）
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                if prearmed {
                    let _ = crate::infrastructure::security_service_client::kernel_disarm();
                }
                return Err(format!("spawn worker: {}", e));
            }
        };

        let pid = match child.id() {
            Some(pid) => pid,
            None => {
                if prearmed {
                    let _ = crate::infrastructure::security_service_client::kernel_disarm();
                }
                let _ = child.start_kill();
                return Err("无法获取子进程 PID".to_string());
            }
        };

        // 必须在 REGISTER 之前取得进程句柄并施加 Job/DACL：驱动确认后
        // 会剥离宿主新句柄的 SET_QUOTA/TERMINATE/SUSPEND_RESUME，已取得
        // 的句柄权限不会被追溯撤销。此时 worker 仍挂起，未执行任何指令。
        #[cfg(target_os = "windows")]
        let (hardened_job, suspended_process) = match prepare_suspended_worker(pid) {
            Ok(value) => value,
            Err(e) => {
                let _ = child.start_kill();
                if prearmed {
                    let _ = crate::infrastructure::security_service_client::kernel_disarm();
                }
                return Err(format!("worker 进程加固失败: {}", e));
            }
        };

        // worker 仍处于挂起态：提交 PID 与创建时间，服务与驱动复核身份后登记。
        #[cfg(target_os = "windows")]
        if prearmed {
            if test_register_failure() {
                log::warn!("[kernel-guard] 测试注入：强制 REGISTER 失败（preferred）");
                let _ = crate::infrastructure::security_service_client::kernel_disarm();
            } else {
                match child
                    .raw_handle()
                    .and_then(|raw| process_creation_time_quad(HANDLE(raw)).ok())
                {
                    Some(creation) => {
                        match crate::infrastructure::security_service_client::kernel_register(
                            pid, creation,
                        ) {
                            Ok(()) => log::info!("[kernel-guard] worker 已登记为受保护进程"),
                            Err(e) => {
                                log::warn!("[kernel-guard] worker 登记失败（preferred）: {}", e);
                                // 不留半登记状态：撤销 ARM，回退到用户态加固。
                                let _ = crate::infrastructure::security_service_client::kernel_disarm();
                            }
                        }
                    }
                    None => {
                        log::warn!("[kernel-guard] 无法读取 worker 创建时间，撤销预 ARM");
                        let _ = crate::infrastructure::security_service_client::kernel_disarm();
                    }
                }
            }
        }

        // 心跳事件必须在恢复执行前复制到挂起态 worker：prepare 取得的
        // 句柄仍保有 PROCESS_DUP_HANDLE，REGISTER 后再打开的新句柄会被剥离。
        #[cfg(target_os = "windows")]
        let heartbeat = create_heartbeat_event(suspended_process);
        #[cfg(target_os = "windows")]
        let (heartbeat_event, heartbeat_worker_handle) = match heartbeat {
            Some((event, handle)) => (Some(Arc::new(event)), handle),
            None => {
                log::warn!("[watchdog] 心跳事件创建失败，挂起看门狗降级");
                (None, 0)
            }
        };

        // REGISTER 完成后恢复执行；prepare 阶段取得的句柄仍保有恢复权限。
        #[cfg(target_os = "windows")]
        if let Err(e) = resume_and_close_suspended_worker(suspended_process) {
            unsafe {
                let _ = CloseHandle(hardened_job.0);
            }
            let _ = child.start_kill();
            if prearmed {
                let _ = crate::infrastructure::security_service_client::kernel_disarm();
            }
            return Err(format!("恢复 worker 执行失败: {}", e));
        }
        #[cfg(target_os = "windows")]
        log::info!(
            "[watchdog] worker PID={} 已加固并恢复：Job 单进程/2GiB 上限、受限 DACL",
            pid
        );

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
            Arc::new(ipc_channel),
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
                job_handle: StdMutex::new(Some(hardened_job)),
                #[cfg(target_os = "windows")]
                heartbeat_event,
                #[cfg(target_os = "windows")]
                heartbeat_worker_handle,
                suspend_stop: Arc::new(AtomicBool::new(false)),
                suspend_thread: StdMutex::new(None),
                stop: Arc::new(AtomicBool::new(false)),
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

    /// 标记会话正在正常停止（替换/销毁/应用退出）。
    ///
    /// 内核看门狗据此区分主动停止与 worker 异常退出；主动停止不再触发
    /// worker_exit 锁定，避免关闭流程被重复锁定干扰。
    pub(crate) fn request_stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        self.inner.suspend_stop.store(true, Ordering::SeqCst);
    }

    /// 会话正常停止标志（内核看门狗持有同一原子）。
    pub(crate) fn stop_flag(&self) -> Arc<AtomicBool> {
        self.inner.stop.clone()
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

        // 主动停止：看门狗直接退出，不把本次退出误判为 worker 异常。
        self.request_stop();

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

        // 0. 停止挂起看门狗（WaitForSingleObject 每秒醒来检查停止标志，
        //    join 最多等待约 1 秒，不阻塞锁定响应）
        self.suspend_stop.store(true, Ordering::SeqCst);
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(mut slot) = self.suspend_thread.lock() {
            if let Some(thread) = slot.take() {
                let _ = thread.join();
            }
        }

        // 1. 关闭请求通道，触发 Actor 主循环退出
        //    take() 取出 Sender 并 drop，所有 recv() 返回 None
        self.close_request_channel();

        // 2. 取出 actor_handle（若 kill() 已取走则为 None）
        let actor_handle_opt = self.actor_handle.lock().ok().and_then(|mut g| g.take());

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
                        Ok(Err(e)) => {
                            log::warn!("[actor] PID={} 析构时 Actor 任务 panic: {}", pid, e)
                        }
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

        // 显式关闭 Job Object 句柄
        //   KILL_ON_JOB_CLOSE 在句柄关闭时自动终止 Job 内子进程（双保险）
        //   即使 Drop 链正常执行也释放内核资源，杜绝句柄泄漏
        #[cfg(target_os = "windows")]
        {
            if let Ok(mut g) = self.job_handle.lock() {
                if let Some(h) = g.take() {
                    unsafe {
                        let _ = CloseHandle(h.0);
                    }
                }
            }
        }

        log::info!("[actor] WorkerSession 析构完成: PID={}", pid);
    }
}

/// 在 tokio 运行时上下文中同步驱动 async future
///
/// sync 方法内部通过 Handle::block_on + block_in_place 驱动 async future。
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
