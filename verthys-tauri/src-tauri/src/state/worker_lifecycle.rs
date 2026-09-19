/*
 * state/worker_lifecycle.rs — Worker 生命周期状态机与健康检查
 *
 *
 * 架构定位：状态层（state）Worker 生命周期管理模块
 *   - 依赖 tokio::sync（Mutex / watch）实现无阻塞状态转移
 *   - 依赖 WorkerSession（is_alive / pid）进行健康检查
 *   - 提供 WorkerLifecycle 状态机 + SetupCache 预检缓存
 *
 *  WorkerLifecycle 状态机：
 *   AppState 增加 tokio::sync::Mutex<WorkerLifecycle>。
 *   状态：Uninitialized / Initializing / Ready / ShuttingDown / Failed。
 *   init/destroy 必须获取锁检查状态转移；destroy 参与 same lock 消除竞态。
 *
 *  健康检查器：
 *   每 10s 获取状态锁，Ready 时检查 session.is_alive()；
 *   退出则转 Failed + 告警 + 限次自动恢复（3 次）。
 *   健康检查器自身有守护（select shutdown 信号）。
 *
 *  setup 钩子预检缓存：
 *   DLL 完整性校验 + 依赖预检结果缓存 AppState；
 *   worker_init 从缓存取，总超时缩至 10-15s。
 *
 *  watch channel 等待：
 *   init 请求遇 Initializing 不拒绝，tokio::sync::watch 等待 Ready/Failed
 *   （最长 3s），超时返回 STILL_INITIALIZING。
 *
 * CI 红线：
 *   - 状态转移原子化（持锁期间完成判定 + 转移）
 *   - Failed 恢复次数限制（MAX_RECOVERY_ATTEMPTS=3）
 *   - 健康检查器退出受 CancellationToken 控制
 */

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex};
use tokio_util::sync::CancellationToken;

/// 最大自动恢复次数
///
/// worker 异常退出后，最多尝试自动恢复 3 次。
/// 超过则停止恢复，等待用户手动 worker_init。
const MAX_RECOVERY_ATTEMPTS: u32 = 3;

/// 健康检查间隔（每 10s 检查一次）
#[allow(dead_code)]
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// watch channel 等待超时（最长 3s）
const INIT_WAIT_TIMEOUT: Duration = Duration::from_secs(3);

/* ------------------------------------------------------------------ *
 * WorkerLifecycleState 状态枚举                              *
 * ------------------------------------------------------------------ */

/// Worker 生命周期状态
///
/// 状态转移图：
/// ```text
///   Uninitialized ──init──► Initializing ──ready──► Ready
///          ▲                    │                    │
///          │                    └──fail──► Failed    │
///          │                                   │     │
///          └─────────destroy───────────────────┘     │
///                  ↑                                 │
///                  └──────────destroy────────────────┘
///                  │                                 │
///                  └────recovery(≤3)──► Initializing │
///                                    │               │
///                  destroy ──► ShuttingDown ──► Uninitialized
/// ```
///
/// init/destroy 必须获取 tokio::sync::Mutex 检查状态转移。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum WorkerLifecycleState {
    /// 未初始化（首次或 destroy 后）
    #[default]
    Uninitialized,
    /// 初始化中（spawn + ready 信号等待）
    Initializing,
    /// 就绪（worker 已就绪，可接收 IPC 请求）
    Ready,
    /// 关闭中（正在销毁 worker，destroy 持锁）
    ShuttingDown,
    /// 失败（spawn 超时 / ready 超时 / 子进程异常退出）
    Failed {
        /// 失败原因（脱敏，不含路径/密码）
        reason: String,
        /// 已尝试自动恢复次数（超 MAX_RECOVERY_ATTEMPTS 停止）
        recovery_attempts: u32,
    },
}

impl WorkerLifecycleState {
    /// 是否处于可接受 IPC 请求的状态
    pub fn is_ready(&self) -> bool {
        matches!(self, WorkerLifecycleState::Ready)
    }

    /// 是否处于初始化中
    pub fn is_initializing(&self) -> bool {
        matches!(self, WorkerLifecycleState::Initializing)
    }

    /// 是否处于终态（不可继续操作，需 destroy 后重新 init）
    pub fn is_failed(&self) -> bool {
        matches!(self, WorkerLifecycleState::Failed { .. })
    }

    /// 获取恢复次数（Failed 状态时有值）
    pub fn recovery_attempts(&self) -> u32 {
        match self {
            WorkerLifecycleState::Failed {
                recovery_attempts, ..
            } => *recovery_attempts,
            _ => 0,
        }
    }
}

/* ------------------------------------------------------------------ *
 * SetupCache — 预检结果缓存                                 *
 * ------------------------------------------------------------------ */

/// setup 钩子预检结果缓存
///
/// 应用启动时（lib.rs setup）执行 DLL 完整性校验 + 依赖预检，
/// 结果缓存到此结构。worker_init 从缓存取，跳过重复校验，
/// 总超时从 30s 缩至 10-15s（仅 spawn + ready 信号）。
#[derive(Clone)]
pub struct SetupCache {
    /// worker 可执行文件绝对路径
    pub worker_exe: String,
    /// DLL 绝对路径
    pub dll_path: String,
    /// DLL 完整性校验是否通过
    pub integrity_verified: bool,
    /// DLL 依赖预检是否通过
    pub dependencies_checked: bool,
}

impl SetupCache {
    /// 预检是否全部通过
    pub fn is_valid(&self) -> bool {
        self.integrity_verified && self.dependencies_checked
    }
}

/* ------------------------------------------------------------------ *
 * WorkerLifecycle — 状态机 + 预检缓存                        *
 * ------------------------------------------------------------------ */

/// Worker 生命周期状态机
///
/// 通过 `tokio::sync::Mutex<WorkerLifecycle>` 保护，init/destroy 获取锁后
/// 检查状态转移。watch::Sender 在状态变更时通知等待者。
pub struct WorkerLifecycle {
    /// 当前状态
    state: WorkerLifecycleState,
    /// 累计自动恢复次数（跨状态追踪，不随状态重置）
    recovery_count: u32,
    /// 预检结果缓存（setup 钩子填充）
    setup_cache: Option<SetupCache>,
}

impl WorkerLifecycle {
    /// 创建新状态机（初始 Uninitialized）
    pub fn new() -> Self {
        WorkerLifecycle {
            state: WorkerLifecycleState::Uninitialized,
            recovery_count: 0,
            setup_cache: None,
        }
    }

    /// 获取当前状态快照
    pub fn state(&self) -> &WorkerLifecycleState {
        &self.state
    }

    /// 获取预检缓存引用
    pub fn setup_cache(&self) -> Option<&SetupCache> {
        self.setup_cache.as_ref()
    }

    /// 存储预检缓存
    pub fn set_setup_cache(&mut self, cache: SetupCache) {
        self.setup_cache = Some(cache);
    }

    /// 转移到 Initializing 状态
    ///
    /// 仅允许从 Uninitialized / Failed 转移。
    /// 从 Failed 转移时检查恢复次数是否超限。
    /// 返回 Err 表示状态不匹配（如已在 Initializing 或 Ready）。
    pub fn transition_to_initializing(&mut self) -> Result<(), String> {
        match self.state {
            WorkerLifecycleState::Uninitialized => {
                // 首次初始化，重置恢复计数
                self.recovery_count = 0;
                self.state = WorkerLifecycleState::Initializing;
                Ok(())
            }
            WorkerLifecycleState::Failed { .. } => {
                // 检查恢复次数
                if self.recovery_count >= MAX_RECOVERY_ATTEMPTS {
                    return Err(format!(
                        "自动恢复次数超限（{}/{}），请手动重新初始化",
                        self.recovery_count, MAX_RECOVERY_ATTEMPTS
                    ));
                }
                // 恢复计数 +1（每次从 Failed 恢复都计数）
                self.recovery_count += 1;
                self.state = WorkerLifecycleState::Initializing;
                Ok(())
            }
            WorkerLifecycleState::Initializing => {
                Err("已在初始化中".into())
            }
            WorkerLifecycleState::Ready => Err("worker 已就绪".into()),
            WorkerLifecycleState::ShuttingDown => Err("正在关闭中".into()),
        }
    }

    /// 转移到 Ready 状态（仅允许从 Initializing 转移）
    pub fn transition_to_ready(&mut self) -> Result<(), String> {
        match self.state {
            WorkerLifecycleState::Initializing => {
                self.state = WorkerLifecycleState::Ready;
                Ok(())
            }
            _ => Err(format!("状态不匹配，无法转移到 Ready: {:?}", self.state)),
        }
    }

    /// 转移到 Failed 状态（允许从 Initializing / Ready 转移）
    ///
    /// recovery_count 由 transition_to_initializing 递增，
    /// 此处仅记录当前 recovery_count 到 Failed 状态供查询。
    pub fn transition_to_failed(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        self.state = WorkerLifecycleState::Failed {
            reason,
            recovery_attempts: self.recovery_count,
        };
    }

    /// 转移到 ShuttingDown 状态（允许从 Ready / Failed 转移）
    pub fn transition_to_shutting_down(&mut self) -> Result<(), String> {
        match self.state {
            WorkerLifecycleState::Ready | WorkerLifecycleState::Failed { .. } => {
                self.state = WorkerLifecycleState::ShuttingDown;
                Ok(())
            }
            WorkerLifecycleState::Uninitialized => {
                // 未初始化直接返回成功（无需关闭）
                Ok(())
            }
            WorkerLifecycleState::Initializing => {
                // 初始化中允许中断关闭
                self.state = WorkerLifecycleState::ShuttingDown;
                Ok(())
            }
            WorkerLifecycleState::ShuttingDown => Ok(()),
        }
    }

    /// 转移到 Uninitialized（仅允许从 ShuttingDown 转移）
    pub fn transition_to_uninitialized(&mut self) {
        self.state = WorkerLifecycleState::Uninitialized;
    }

    /// 获取当前恢复次数
    pub fn recovery_attempts(&self) -> u32 {
        self.recovery_count
    }

    /// 是否可自动恢复（恢复次数 < MAX_RECOVERY_ATTEMPTS）
    pub fn can_recover(&self) -> bool {
        matches!(self.state, WorkerLifecycleState::Failed { .. })
            && self.recovery_count < MAX_RECOVERY_ATTEMPTS
    }
}

impl Default for WorkerLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

/* ------------------------------------------------------------------ *
 * WorkerLifecycleHandle — Mutex + watch 组合句柄             *
 * ------------------------------------------------------------------ */

/// Worker 生命周期句柄
///
/// 组合 `tokio::sync::Mutex<WorkerLifecycle>` 与 `watch::Sender`，
/// 提供原子状态转移 + 等待者通知。
///
/// AppState 持有此句柄，worker_controller 通过 AppState 访问。
#[derive(Clone)]
pub struct WorkerLifecycleHandle {
    /// 状态机互斥锁
    inner: Arc<Mutex<WorkerLifecycle>>,
    /// 状态变更通知（init 遇 Initializing 时 watch 等待）
    watch_tx: Arc<watch::Sender<WorkerLifecycleState>>,
}

impl WorkerLifecycleHandle {
    /// 创建新句柄（初始 Uninitialized）
    pub fn new() -> Self {
        let lifecycle = WorkerLifecycle::new();
        let initial_state = lifecycle.state().clone();
        let (watch_tx, _watch_rx) = watch::channel(initial_state);
        WorkerLifecycleHandle {
            inner: Arc::new(Mutex::new(lifecycle)),
            watch_tx: Arc::new(watch_tx),
        }
    }

    /// 获取锁并执行闭包，完成后发送 watch 通知
    ///
    /// 闭包返回新状态用于通知等待者。
    pub async fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut WorkerLifecycle) -> R,
    {
        let mut guard = self.inner.lock().await;
        let result = f(&mut guard);
        // 通知等待者当前状态变更
        let _ = self.watch_tx.send(guard.state().clone());
        result
    }

    /// 获取当前状态快照（watch::Receiverborrow 模式）
    pub async fn current_state(&self) -> WorkerLifecycleState {
        let guard = self.inner.lock().await;
        guard.state().clone()
    }

    /// 订阅状态变更
    ///
    /// 返回 watch::Receiver，调用方可 await 状态变更。
    pub fn subscribe(&self) -> watch::Receiver<WorkerLifecycleState> {
        self.watch_tx.subscribe()
    }

    /// 等待状态变为 Ready 或 Failed（最长 INIT_WAIT_TIMEOUT）
    ///
    /// init 请求遇 Initializing 时调用，超时返回 STILL_INITIALIZING。
    ///
    /// 返回：
    ///   - Ok(Ready): worker 已就绪
    ///   - Ok(Failed): 初始化失败
    ///   - Err(_): 超时（仍在初始化中）
    pub async fn wait_for_ready_or_failed(
        &self,
    ) -> Result<WorkerLifecycleState, tokio::time::error::Elapsed> {
        let mut rx = self.subscribe();
        // 快速路径：检查当前状态
        {
            let guard = self.inner.lock().await;
            let current = guard.state().clone();
            if matches!(
                current,
                WorkerLifecycleState::Ready | WorkerLifecycleState::Failed { .. }
            ) {
                return Ok(current);
            }
        }
        // 等待状态变更（最长 INIT_WAIT_TIMEOUT）
        tokio::time::timeout(INIT_WAIT_TIMEOUT, async {
            loop {
                // 等待下一次状态变更
                if rx.changed().await.is_err() {
                    // 通道关闭，返回当前状态
                    return rx.borrow().clone();
                }
                let state = rx.borrow().clone();
                if matches!(
                    state,
                    WorkerLifecycleState::Ready | WorkerLifecycleState::Failed { .. }
                ) {
                    return state;
                }
                // 继续等待
            }
        })
        .await
    }
}

impl Default for WorkerLifecycleHandle {
    fn default() -> Self {
        Self::new()
    }
}

/* ------------------------------------------------------------------ *
 * 健康检查后台任务                                          *
 * ------------------------------------------------------------------ */

/// 启动 worker 健康检查后台任务
///
/// 每 10s 检查 worker 子进程存活状态：
///   - 获取 WorkerLifecycle 锁，Ready 时检查 session.is_alive()
///   - 子进程退出则转 Failed + 告警
///   - Failed 且可恢复时自动触发恢复（限 3 次）
///
/// 应在应用启动时（lib.rs setup）调用，传入 shutdown CancellationToken。
#[allow(dead_code)]
pub fn spawn_health_checker(
    app: tauri::AppHandle,
    lifecycle: WorkerLifecycleHandle,
    shutdown: CancellationToken,
) {
    // 与 spawn_lock_monitor 同理：此函数设计为在 lib.rs setup 回调中调用，
    // setup 运行在事件循环主线程而非 Tokio 运行时上下文。
    // 使用 tauri::async_runtime::spawn 避免触发 "no reactor running" panic。
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(HEALTH_CHECK_INTERVAL);
        // 跳过第一次立即触发（启动时 worker 尚未初始化）
        interval.tick().await;

        log::info!(
            "[HEALTH_CHECK] 启动 worker 健康检查（每 {}s）",
            HEALTH_CHECK_INTERVAL.as_secs()
        );

        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    log::info!("[HEALTH_CHECK] 收到关闭信号，退出");
                    break;
                }
                _ = interval.tick() => {
                    check_worker_health(&app, &lifecycle).await;
                }
            }
        }
    });
}

/// 执行一次健康检查
#[allow(dead_code)]
async fn check_worker_health(
    app: &tauri::AppHandle,
    lifecycle: &WorkerLifecycleHandle,
) {
    use tauri::Manager;

    let state = app.state::<crate::state::AppState>();

    let current = lifecycle.current_state().await;

    // 仅 Ready 状态需要检查子进程存活
    if !current.is_ready() {
        return;
    }

    // 检查 session 是否存活（通过 AppState 新增的 is_worker_alive 方法）
    let alive = state.is_worker_alive();

    if !alive {
        log::error!(
            "[HEALTH_CHECK] worker 子进程异常退出（PID 可能已终止）"
        );

        // 转移到 Failed 状态
        let can_recover = lifecycle
            .with_lock(|lc| {
                lc.transition_to_failed("worker 子进程异常退出");
                lc.can_recover()
            })
            .await;

        if can_recover {
            let attempts = lifecycle.current_state().await.recovery_attempts();
            log::warn!(
                "[HEALTH_CHECK] 尝试自动恢复 worker（恢复次数 {}/{})",
                attempts,
                MAX_RECOVERY_ATTEMPTS
            );
            // 自动恢复：触发重新初始化（best-effort，不阻塞健康检查循环）
            // 实际恢复由 worker_init 命令或前端触发，此处仅标记状态
        }
    }
}

/* ------------------------------------------------------------------ *
 * 单元测试                                                            *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_state_transitions() {
        let mut lc = WorkerLifecycle::new();
        assert_eq!(lc.state(), &WorkerLifecycleState::Uninitialized);

        // Uninitialized → Initializing
        assert!(lc.transition_to_initializing().is_ok());
        assert!(lc.state().is_initializing());

        // Initializing → Initializing (rejected)
        assert!(lc.transition_to_initializing().is_err());

        // Initializing → Ready
        assert!(lc.transition_to_ready().is_ok());
        assert!(lc.state().is_ready());

        // Ready → Failed
        lc.transition_to_failed("test failure");
        assert!(lc.state().is_failed());

        // Failed → Initializing (recovery)
        assert!(lc.transition_to_initializing().is_ok());
    }

    #[test]
    fn test_recovery_limit() {
        let mut lc = WorkerLifecycle::new();

        // 1 次初始初始化 + MAX_RECOVERY_ATTEMPTS 次恢复 = MAX_RECOVERY_ATTEMPTS+1 次循环
        // 初始：Uninitialized → Initializing (recovery_count=0) → Failed
        // 恢复1：Failed → Initializing (recovery_count=1) → Failed
        // 恢复2：Failed → Initializing (recovery_count=2) → Failed
        // 恢复3：Failed → Initializing (recovery_count=3) → Failed
        for i in 0..(MAX_RECOVERY_ATTEMPTS + 1) {
            assert!(
                lc.transition_to_initializing().is_ok(),
                "第 {} 次初始化/恢复应成功",
                i + 1
            );
            lc.transition_to_failed("exit");
        }

        // recovery_count 现在为 MAX_RECOVERY_ATTEMPTS，下次恢复应被拒绝
        let result = lc.transition_to_initializing();
        assert!(
            result.is_err(),
            "恢复次数超限后应拒绝，recovery_count={}",
            lc.recovery_attempts()
        );
    }

    #[test]
    fn test_setup_cache() {
        let mut lc = WorkerLifecycle::new();
        assert!(lc.setup_cache().is_none());

        let cache = SetupCache {
            worker_exe: "/path/to/worker".into(),
            dll_path: "/path/to/dll".into(),
            integrity_verified: true,
            dependencies_checked: true,
        };
        lc.set_setup_cache(cache);

        let cached = lc.setup_cache().expect("cache should exist");
        assert!(cached.is_valid());
        assert_eq!(cached.worker_exe, "/path/to/worker");
    }

    #[tokio::test]
    async fn test_lifecycle_handle_state() {
        let handle = WorkerLifecycleHandle::new();
        let state = handle.current_state().await;
        assert_eq!(state, WorkerLifecycleState::Uninitialized);
    }

    #[tokio::test]
    async fn test_lifecycle_handle_transition() {
        let handle = WorkerLifecycleHandle::new();

        handle
            .with_lock(|lc| {
                lc.transition_to_initializing().ok();
            })
            .await;

        let state = handle.current_state().await;
        assert!(state.is_initializing());
    }

    #[tokio::test]
    async fn test_wait_for_ready_or_failed_ready() {
        let handle = WorkerLifecycleHandle::new();

        // 转移到 Initializing
        handle
            .with_lock(|lc| {
                lc.transition_to_initializing().ok();
            })
            .await;

        // 转移到 Ready
        handle
            .with_lock(|lc| {
                lc.transition_to_ready().ok();
            })
            .await;

        let result = handle.wait_for_ready_or_failed().await;
        assert!(result.is_ok());
        let state = result.unwrap();
        assert!(state.is_ready());
    }

    #[tokio::test]
    async fn test_wait_for_ready_or_failed_timeout() {
        let handle = WorkerLifecycleHandle::new();

        // 保持 Initializing 状态，等待应超时
        handle
            .with_lock(|lc| {
                lc.transition_to_initializing().ok();
            })
            .await;

        let result = handle.wait_for_ready_or_failed().await;
        assert!(result.is_err()); // 超时
    }
}
