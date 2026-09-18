/*
 * state/mod.rs — 进程私有状态管理（全量重写）
 *
 *   "资源与状态管理"
 *   进程私有状态、多进程隔离资源应抽离至独立 state 模块
 *
 * 包含：
 *   - AppState: 主进程会话状态（worker IPC session + scan_state + init_lock）
 *   - ScanPipelineState<T>: 泛型双缓冲游标扫描状态（第 11.3 项）
 *   - LockedBuffer<T>: VirtualLock RAII 守卫（第 11.2 项）
 *   - PrefetchTaskHandle<T>: 长期预取任务控制（第 11.4 项）
 *   - InitLockGuard: 初始化锁 RAII 守卫
 *   - cleanup_scan_on_failure / cleanup_summary_scan_on_failure: 熔断清理
 *   - spawn_lock_monitor: 锁持有时间监控（第 11.7 项）
 *
 * 第 11.5 项 — 锁中毒处理：
 *   原：所有 Mutex/RwLock 的 lock()/read()/write() 用 unwrap_or_else(|e| e.into_inner())
 *   吞中毒——中毒时直接取出数据继续使用，可能操作不一致状态。
 *
 *   新：中毒时 into_inner() 取出后废弃（重置为 None/Default），记录严重告警，
 *   通知 worker 关闭游标。通过 lock_scan_state/lock_scan_summary_state/
 *   lock_verthys_file/read_session/write_session 方法统一处理。
 *
 * 第 11.6 项 — wait_io_complete 改 Notify：
 *   原：100ms 轮询 pending_io_count，延迟高且浪费 CPU。
 *   新：tokio::sync::Notify，end_io 调 notify_one，wait_io_complete 调 notified().await。
 *
 * 第 11.7 项 — 锁持有时间监控：
 *   AtomicU64 记录 scan_state/scan_summary_state 锁获取时间戳。
 *   后台任务每 5s 检查，持有超 30s 告警 + try_lock 强制重置。
 *
 * 分层依赖方向：state → worker / infrastructure / controller::types / util
 */

pub mod key_lifecycle;
pub mod locked_buffer;
pub mod scan_pipeline;
pub mod verthys_session;
pub mod worker_lifecycle;

// 重导出常用类型，供控制器直接 use crate::state::{...}
// VirtualLockable / PrefetchCommand 未通过 mod.rs 重导出（无外部消费者），
// 需要时可直接从 locked_buffer / scan_pipeline 模块导入。
#[allow(unused_imports)]
pub use key_lifecycle::{
    KeyLifecycle, KeyLifecycleState, VerifyAttemptResult, VerifyCheckResult,
};
#[allow(unused_imports)]
pub use locked_buffer::LockedBuffer;
#[allow(unused_imports)]
pub use scan_pipeline::{
    cleanup_pipeline_on_failure, PrefetchTaskHandle, ScanPipelineState, ScanRecord,
    ScanSessionState,
};
#[allow(unused_imports)]
pub use verthys_session::{PreheatToken, PreheatTokenStore, VerthysSessionGuard};
#[allow(unused_imports)]
pub use worker_lifecycle::{
    spawn_health_checker, SetupCache, WorkerLifecycle, WorkerLifecycleHandle,
    WorkerLifecycleState,
};

use crate::controller::types::{VerthysRecordEntry, VerthysSummaryEntry};
use crate::security::file_lock::VerthysFileLock;
// 注意：PreheatTokenStore / VerthysSessionGuard 已通过上方 pub use 重导出，
// 此处不再重复 use，避免 E0252 重复定义错误。
use crate::worker::WorkerSession;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::Manager;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/* ------------------------------------------------------------------ *
 * 第 11.7 项：TimedMutexGuard — 带时间戳的锁守卫                       *
 *                                                                    *
 * 包装 MutexGuard，构造时记录时间戳，Drop 时清除时间戳。               *
 * 后台任务通过时间戳检测锁持有时间，超 30s 告警 + 强制重置。            *
 * ------------------------------------------------------------------ */

/// 带时间戳的 Mutex 守卫（第 11.7 项）
///
/// 通过 `AppState::lock_scan_state` / `lock_scan_summary_state` 创建。
/// 构造时在 `timestamp` 字段记录当前 Unix 毫秒时间戳，Drop 时清零。
///
/// Deref/DerefMut 透传到 `MutexGuard`，使用方式与普通 `MutexGuard` 完全一致：
/// ```ignore
/// let mut guard = state.lock_scan_state();
/// if let Some(scan) = guard.as_mut() { ... }
/// ```
pub struct TimedMutexGuard<'a, T> {
    guard: std::sync::MutexGuard<'a, T>,
    timestamp: &'a AtomicU64,
}

impl<'a, T> Drop for TimedMutexGuard<'a, T> {
    fn drop(&mut self) {
        // 清除时间戳，表示锁已释放
        self.timestamp.store(0, Ordering::SeqCst);
    }
}

impl<'a, T> std::ops::Deref for TimedMutexGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        // 透传到 MutexGuard 内部的 T（MutexGuard 自身实现 Deref<Target=T>）
        &self.guard
    }
}

impl<'a, T> std::ops::DerefMut for TimedMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // 透传到 MutexGuard 内部的 T（MutexGuard 自身实现 DerefMut<Target=T>）
        &mut self.guard
    }
}

/// 获取当前 Unix 毫秒时间戳
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/* ------------------------------------------------------------------ *
 * AppState — 应用主状态                                                *
 * ------------------------------------------------------------------ */

/// 应用主状态
///
/// 通过 `tauri::Builder::manage(AppState::new())` 注册。
/// 所有控制器通过 `State<'_, AppState>` 访问。
///
/// 字段可见性：
///   - `init_lock` / `prefetch_done`：pub（AtomicBool，无中毒风险，直接访问）
///   - `session` / `scan_state` / `scan_summary_state` / `verthys_file_lock`：
///     私有（通过锁中毒恢复方法访问，第 11.5 项）
///   - `pending_io_count` / `io_notify` / `*_lock_acquired_ms`：
///     私有（通过 begin_io/end_io/wait_io_complete 等方法访问）
pub struct AppState {
    /// Worker 会话（RwLock 允许多读并发 send，写独占 set_session）
    ///
    /// 第 11.5 项：通过 read_session()/write_session() 访问，中毒时重置为 None。
    session: RwLock<Option<WorkerSession>>,
    /// 并发锁防重：初始化流程进行中拒绝并发请求
    pub init_lock: AtomicBool,
    /// 全量扫描状态（第 11.3 项：泛型 ScanPipelineState<VerthysRecordEntry>）
    ///
    /// 第 11.5 项：通过 lock_scan_state() 访问，中毒时重置为 None + 通知 worker。
    /// 第 11.7 项：lock_scan_state() 记录时间戳到 scan_lock_acquired_ms。
    scan_state: Mutex<Option<ScanPipelineState<VerthysRecordEntry>>>,
    /// 摘要扫描状态（与 scan_state 对称）
    scan_summary_state: Mutex<Option<ScanPipelineState<VerthysSummaryEntry>>>,
    /// .verthys 文件跨进程独占锁
    ///
    /// 第 11.5 项：通过 lock_verthys_file() 访问，中毒时重置为 None。
    verthys_file_lock: Mutex<Option<VerthysFileLock>>,
    /// Worker IO 操作计数器（verthys_flush 屏障）
    pending_io_count: AtomicU64,
    /// 第 11.6 项：IO 完成通知（替代 100ms 轮询）
    ///
    /// end_io 调 notify_one，wait_io_complete 调 notified().await。
    io_notify: Notify,
    /// 索引区预热完成标志
    pub prefetch_done: AtomicBool,
    /// 第 11.7 项：scan_state 锁获取时间戳（Unix 毫秒，0 = 未持有）
    scan_lock_acquired_ms: AtomicU64,
    /// 第 11.7 项：scan_summary_state 锁获取时间戳
    scan_summary_lock_acquired_ms: AtomicU64,
    /// 第 1.2 项：Worker 生命周期状态机（tokio::sync::Mutex + watch channel）
    ///
    /// worker_controller 的 init/destroy 通过此句柄检查状态转移，
    /// 消除并发竞态。健康检查器每 10s 检查 Ready 状态的子进程存活。
    pub worker_lifecycle: WorkerLifecycleHandle,
    /// 第 16.3 项：预热令牌存储（PreheatToken 一次性凭证）
    ///
    /// verthys_preheat 生成令牌，verthys_unlock 验证并消费令牌才启用零拷贝。
    /// 令牌 30s 超时失效 + 一次性消费，防止前端无凭据重复触发。
    pub preheat_token_store: PreheatTokenStore,
    /// 第 16.2 项：Verthys 会话 RAII 守卫
    ///
    /// verthys_unlock 成功后创建（Some），verthys_lock 时销毁（None）。
    /// Drop 自动释放文件锁，确保异常路径不遗漏。
    verthys_session: Mutex<Option<VerthysSessionGuard>>,
    /// 第 5.7 项 + 第 5.3 项：密钥生命周期状态机 + 指数冷却失败计数器
    ///
    /// 维护 GMK 状态（NoKey/Locked/Unlocked）与 verify_global_key 失败计数。
    /// derive_global_key 仅 NoKey，verify_global_key 仅 Locked，clear_global_key Unlocked→Locked。
    /// verify 连续失败 5 次触发指数冷却（2s/4s/8s/16s/32s 上限 60s）。
    /// 阶段 7 将与 BruteForceGate 联动（DPAPI 持久化 + 界面锁定 + 索引清空）。
    pub key_lifecycle: KeyLifecycle,
    /// ★ Comprehensive_optimization：照片导入会话状态（WAL + 去重哈希集 + 批次计数器）
    ///
    /// verthys_import_begin 创建，verthys_add_records_batch 期间追加 WAL + 串行 worker 插入，
    /// verthys_import_end 关闭。单 verthys 同一时刻仅一个活跃会话（Mutex 串行化保证）。
    /// 中毒处理：into_inner() 取出废弃 → 重置为 None → 告警。
    import_session: Mutex<Option<crate::repository::verthys_wal::ImportSession>>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            session: RwLock::new(None),
            init_lock: AtomicBool::new(false),
            scan_state: Mutex::new(None),
            scan_summary_state: Mutex::new(None),
            verthys_file_lock: Mutex::new(None),
            pending_io_count: AtomicU64::new(0),
            io_notify: Notify::new(),
            prefetch_done: AtomicBool::new(false),
            scan_lock_acquired_ms: AtomicU64::new(0),
            scan_summary_lock_acquired_ms: AtomicU64::new(0),
            worker_lifecycle: WorkerLifecycleHandle::new(),
            preheat_token_store: PreheatTokenStore::new(),
            verthys_session: Mutex::new(None),
            key_lifecycle: KeyLifecycle::new(),
            import_session: Mutex::new(None),
        }
    }

    /* ----------------------------------------------------------------
     * 第 11.5 项：锁中毒恢复方法                                      *
     *                                                                *
     * 所有 Mutex/RwLock 的 lock/read/write 统一通过这些方法访问。      *
     * 中毒时：into_inner() 取出 → 废弃（重置 None）→ 告警 → 通知 worker*
     * ---------------------------------------------------------------- */

    /// 锁定 scan_state（第 11.5 项 + 第 11.7 项）
    ///
    /// 中毒处理：into_inner() 取出废弃数据 → 重置为 None → 严重告警 →
    /// 通知 worker 关闭游标（best-effort）。
    ///
    /// 时间戳：构造时记录当前时间到 scan_lock_acquired_ms，
    /// TimedMutexGuard Drop 时清零。后台任务据此检测死锁。
    pub fn lock_scan_state(
        &self,
    ) -> TimedMutexGuard<'_, Option<ScanPipelineState<VerthysRecordEntry>>> {
        let guard = match self.scan_state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!(
                    "[POISON][scan_state] Mutex 中毒，废弃旧状态并重置为 None"
                );
                let mut g = poisoned.into_inner();
                // 废弃旧状态（LockedBuffer Drop 会擦除+解锁记录）
                *g = None;
                // 通知 worker 关闭游标（best-effort）
                let req = serde_json::json!({"op": "scan_close"});
                let _ = self.send(&req.to_string());
                g
            }
        };
        // 第 11.7 项：记录锁获取时间戳
        self.scan_lock_acquired_ms
            .store(now_ms(), Ordering::SeqCst);
        TimedMutexGuard {
            guard,
            timestamp: &self.scan_lock_acquired_ms,
        }
    }

    /// 锁定 scan_summary_state（第 11.5 项 + 第 11.7 项）
    ///
    /// 与 lock_scan_state 对称，操作 scan_summary_state。
    pub fn lock_scan_summary_state(
        &self,
    ) -> TimedMutexGuard<'_, Option<ScanPipelineState<VerthysSummaryEntry>>> {
        let guard = match self.scan_summary_state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!(
                    "[POISON][scan_summary_state] Mutex 中毒，废弃旧状态并重置为 None"
                );
                let mut g = poisoned.into_inner();
                *g = None;
                let req = serde_json::json!({"op": "scan_summary_close"});
                let _ = self.send(&req.to_string());
                g
            }
        };
        self.scan_summary_lock_acquired_ms
            .store(now_ms(), Ordering::SeqCst);
        TimedMutexGuard {
            guard,
            timestamp: &self.scan_summary_lock_acquired_ms,
        }
    }

    /// 锁定 verthys_file_lock（第 11.5 项）
    ///
    /// 中毒处理：into_inner() 取出废弃 → 重置为 None → 告警。
    /// 无时间戳监控（文件锁持有时间短，不涉及死锁风险）。
    pub fn lock_verthys_file(
        &self,
    ) -> std::sync::MutexGuard<'_, Option<VerthysFileLock>> {
        match self.verthys_file_lock.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!(
                    "[POISON][verthys_file_lock] Mutex 中毒，废弃旧锁并重置为 None"
                );
                let mut g = poisoned.into_inner();
                // 废弃旧文件锁（VerthysFileLock Drop 会释放 LockFileEx）
                *g = None;
                g
            }
        }
    }

    /// 读取 session（第 11.5 项：RwLock read 中毒恢复）
    ///
    /// 中毒时：RwLockReadGuard 不支持 DerefMut，无法在此重置数据。
    /// 仅记录告警并返回只读守卫。数据重置将在下次 write_session() 中毒处理时执行。
    fn read_session(&self) -> std::sync::RwLockReadGuard<'_, Option<WorkerSession>> {
        match self.session.read() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!(
                    "[POISON][session] RwLock read 中毒，返回只读守卫（数据可能不一致，待 write 时重置）"
                );
                // RwLockReadGuard 仅实现 Deref（非 DerefMut），无法在此重置数据。
                // 重置操作推迟到下次 write_session() 中毒分支执行。
                poisoned.into_inner()
            }
        }
    }

    /// 写入 session（第 11.5 项：RwLock write 中毒恢复）
    fn write_session(&self) -> std::sync::RwLockWriteGuard<'_, Option<WorkerSession>> {
        match self.session.write() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!(
                    "[POISON][session] RwLock write 中毒，废弃旧会话并重置为 None"
                );
                let mut g = poisoned.into_inner();
                *g = None;
                g
            }
        }
    }

    /* ----------------------------------------------------------------
     * 初始化锁                                                        *
     * ---------------------------------------------------------------- */

    /// 尝试获取初始化锁（非阻塞，成功返回 true）
    pub fn try_acquire_init_lock(&self) -> bool {
        self.init_lock
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// 释放初始化锁
    pub fn release_init_lock(&self) {
        self.init_lock.store(false, Ordering::SeqCst);
    }

    /* ----------------------------------------------------------------
     * 第 11.6 项：Worker IO 屏障（Notify 替代轮询）                    *
     *                                                                *
     * begin_io / end_io 配对调用，包裹 verthys_flush 等 IO 操作。         *
     * wait_io_complete 在 verthys_lock 销毁 worker 前调用。               *
     *                                                                *
     * 第 11.6 项变更：                                                *
     *   原：wait_io_complete 用 100ms 轮询 pending_io_count             *
     *   新：end_io 调 io_notify.notify_one()，                         *
     *       wait_io_complete 调 io_notify.notified().await             *
     * ---------------------------------------------------------------- */

    /// 标记 IO 操作开始（verthys_flush 入口调用）
    pub fn begin_io(&self) {
        self.pending_io_count.fetch_add(1, Ordering::SeqCst);
    }

    /// 标记 IO 操作结束（verthys_flush 出口调用，无论成功失败）
    ///
    /// 第 11.6 项：fetch_sub 后调 notify_one() 唤醒 wait_io_complete。
    pub fn end_io(&self) {
        self.pending_io_count.fetch_sub(1, Ordering::SeqCst);
        // 唤醒等待 IO 完成的调用方
        self.io_notify.notify_one();
    }

    /// 获取当前 pending IO 操作数
    pub fn get_pending_io_count(&self) -> u64 {
        self.pending_io_count.load(Ordering::SeqCst)
    }

    /// 等待所有 IO 操作完成（第 11.6 项：Notify 替代 100ms 轮询）
    ///
    /// verthys_lock 销毁 worker 前调用，防止持久化中途销毁 worker。
    ///
    /// 第 11.6 项变更：
    ///   原：while + sleep(100ms) 轮询，最坏 100ms 延迟
    ///   新：io_notify.notified().await + timeout，事件驱动零延迟
    ///
    /// 返回 true 表示所有 IO 已完成，false 表示超时（仍有 IO 在执行）。
    pub async fn wait_io_complete(&self, timeout: Duration) -> bool {
        // 快速路径：无待处理 IO
        if self.get_pending_io_count() == 0 {
            return true;
        }
        log::warn!(
            "[wait_io_complete] 等待 {} 个 IO 操作完成（超时 {}ms）",
            self.get_pending_io_count(),
            timeout.as_millis()
        );

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // 检查计数
            if self.get_pending_io_count() == 0 {
                log::info!("[wait_io_complete] 所有 IO 操作已完成");
                return true;
            }

            // 检查截止时间
            let now = tokio::time::Instant::now();
            if now >= deadline {
                log::error!(
                    "[wait_io_complete] 超时，仍有 {} 个 IO 操作未完成，强制销毁 worker",
                    self.get_pending_io_count()
                );
                return false;
            }

            // 等待通知或超时（第 11.6 项：Notify 替代 sleep）
            let remaining = deadline - now;
            let _ = tokio::time::timeout(remaining, self.io_notify.notified()).await;
            // 收到通知或超时后循环回检查计数
        }
    }

    /* ----------------------------------------------------------------
     * Worker 通信方法                                                 *
     *                                                                *
     * 第 11.5 项：所有 read()/write() 改用 read_session()/write_session()*
     * ---------------------------------------------------------------- */

    /// 发送 JSON 请求到 worker，返回响应 JSON（默认 15s 超时）
    pub fn send(&self, json: &str) -> Result<String, String> {
        let session = {
            let guard = self.read_session();
            guard.as_ref().ok_or("worker not initialized")?.clone()
        };
        session.send_json(json)
    }

    /// 发送 JSON 请求到 worker，自定义超时
    pub fn send_with_timeout(
        &self,
        json: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let session = {
            let guard = self.read_session();
            guard.as_ref().ok_or("worker not initialized")?.clone()
        };
        session.send_json_with_timeout(json, timeout)
    }

    /// 发送解锁请求并流式接收进度
    pub fn send_with_unlock_progress(
        &self,
        json: &str,
        progress_cb: &dyn Fn(&crate::worker::UnlockProgress),
    ) -> Result<String, String> {
        let session = {
            let guard = self.read_session();
            guard.as_ref().ok_or("worker not initialized")?.clone()
        };
        session.send_json_with_unlock_progress(json, progress_cb)
    }

    /// 原子批量发送（持锁期间不释放，防止 flush 的 lock/unlock 之间插入其他命令）
    pub fn send_batch(&self, reqs: &[&str]) -> Result<Vec<String>, String> {
        let session = {
            let guard = self.read_session();
            guard.as_ref().ok_or("worker not initialized")?.clone()
        };
        let mut responses = Vec::with_capacity(reqs.len());
        for req in reqs {
            responses.push(session.send_json(req)?);
        }
        Ok(responses)
    }

    /// 原子批量发送（自定义超时）
    pub fn send_batch_with_timeout(
        &self,
        reqs: &[&str],
        timeout: Duration,
    ) -> Result<Vec<String>, String> {
        let session = {
            let guard = self.read_session();
            guard.as_ref().ok_or("worker not initialized")?.clone()
        };
        let mut responses = Vec::with_capacity(reqs.len());
        for req in reqs {
            responses.push(session.send_json_with_timeout(req, timeout)?);
        }
        Ok(responses)
    }

    /// 设置 worker 会话（写操作，使用 write_session 独占锁）
    ///
    /// 传 None 销毁现有会话（Drop 自动 kill 子进程）。
    /// 传 Some(session) 替换现有会话（旧会话 Drop 自动 kill）。
    pub fn set_session(&self, session: Option<WorkerSession>) {
        let mut guard = self.write_session();
        *guard = session;
    }

    /// 检查 worker 是否已初始化（读操作，使用 read_session 共享锁）
    pub fn has_session(&self) -> bool {
        let guard = self.read_session();
        guard.is_some()
    }

    /// 第 1.4 项：检查 worker 子进程是否存活
    ///
    /// 健康检查器每 10s 调用，Ready 状态下检查子进程存活。
    /// session 不存在或 is_alive() 返回 false 均视为不存活。
    pub fn is_worker_alive(&self) -> bool {
        let guard = self.read_session();
        guard.as_ref().map(|s| s.is_alive()).unwrap_or(false)
    }

    /* ----------------------------------------------------------------
     * 第 16.2 项：VerthysSessionGuard 访问方法                           *
     * ---------------------------------------------------------------- */

    /// 锁定 verthys_session（第 16.2 项：RAII 会话守卫访问）
    ///
    /// 中毒处理：into_inner() 取出废弃 → 重置为 None → 告警。
    pub fn lock_verthys_session(&self) -> std::sync::MutexGuard<'_, Option<VerthysSessionGuard>> {
        match self.verthys_session.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!(
                    "[POISON][verthys_session] Mutex 中毒，废弃旧会话守卫并重置为 None"
                );
                let mut g = poisoned.into_inner();
                // 废弃旧会话守卫（VerthysSessionGuard Drop 会释放文件锁）
                *g = None;
                g
            }
        }
    }

    /// 检查 verthys 会话是否活跃（第 16.2 项）
    pub fn has_verthys_session(&self) -> bool {
        let guard = self.lock_verthys_session();
        guard.is_some()
    }

    /// 获取当前会话绑定的 verthys 路径（第 16.2 项）
    ///
    /// 返回 None 表示未解锁或会话已关闭。
    pub fn verthys_session_path(&self) -> Option<String> {
        let guard = self.lock_verthys_session();
        guard.as_ref().map(|s| s.verthys_path().to_string())
    }

    /* ----------------------------------------------------------------
     * ★ Comprehensive_optimization：照片导入会话（WAL）访问方法       *
     *                                                                *
     * verthys_import_begin 创建 ImportSession 存入 import_session，    *
     * verthys_add_records_batch 期间追加 WAL + 串行 worker 插入，      *
     * verthys_import_end 关闭。单 verthys 同一时刻仅一个活跃会话。       *
     * 中毒处理：into_inner() 取出废弃 → 重置为 None → 告警。         *
     * ---------------------------------------------------------------- */

    /// 锁定 import_session（★ Comprehensive_optimization：WAL 导入会话访问）
    ///
    /// 中毒处理：into_inner() 取出废弃会话（WalWriter Drop 关闭文件句柄，
    /// 已 committed 的哈希在磁盘 WAL 中持久化，下次 begin 可恢复）→
    /// 重置为 None → 严重告警。
    ///
    /// 返回的 MutexGuard 可直接 Option::take() / as_mut() / as_ref() 操作。
    pub fn lock_import_session(
        &self,
    ) -> std::sync::MutexGuard<'_, Option<crate::repository::verthys_wal::ImportSession>> {
        match self.import_session.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!(
                    "[POISON][import_session] Mutex 中毒，废弃旧导入会话并重置为 None"
                );
                let mut g = poisoned.into_inner();
                // 废弃旧会话（WalWriter Drop 关闭文件句柄；committed_hashes 已落盘可恢复）
                *g = None;
                g
            }
        }
    }

    /// 检查是否存在活跃的导入会话（防重入：单 verthys 同一时刻仅一个活跃会话）
    pub fn has_import_session(&self) -> bool {
        let guard = self.lock_import_session();
        guard.is_some()
    }

    /* ----------------------------------------------------------------
     * 第 11.7 项：锁持有时间监控                                      *
     * ---------------------------------------------------------------- */

    /// 检查锁持有时间戳，超 30s 告警 + try_lock 强制重置（第 11.7 项）
    ///
    /// 由后台任务每 5s 调用一次。检查 scan_state / scan_summary_state
    /// 的锁获取时间戳，如果持有超 30s（疑似死锁），尝试 try_lock 强制重置。
    fn check_lock_timestamps(&self) {
        let now = now_ms();
        const LOCK_HOLD_WARN_THRESHOLD_MS: u64 = 30_000; // 30 秒

        // 检查 scan_state
        let scan_ts = self.scan_lock_acquired_ms.load(Ordering::SeqCst);
        if scan_ts > 0 {
            let held = now.saturating_sub(scan_ts);
            if held > LOCK_HOLD_WARN_THRESHOLD_MS {
                log::error!(
                    "[LOCK_MONITOR] scan_state 持有 {}ms（超 {}ms 阈值），疑似死锁",
                    held,
                    LOCK_HOLD_WARN_THRESHOLD_MS
                );
                // 尝试 try_lock 强制重置
                if let Ok(mut guard) = self.scan_state.try_lock() {
                    log::warn!("[LOCK_MONITOR] scan_state try_lock 成功，强制重置为 None");
                    *guard = None;
                    self.scan_lock_acquired_ms.store(0, Ordering::SeqCst);
                    // 通知 worker 关闭游标
                    let req = serde_json::json!({"op": "scan_close"});
                    let _ = self.send(&req.to_string());
                } else {
                    log::warn!(
                        "[LOCK_MONITOR] scan_state try_lock 失败（仍被持有），仅告警"
                    );
                }
            }
        }

        // 检查 scan_summary_state
        let summary_ts = self.scan_summary_lock_acquired_ms.load(Ordering::SeqCst);
        if summary_ts > 0 {
            let held = now.saturating_sub(summary_ts);
            if held > LOCK_HOLD_WARN_THRESHOLD_MS {
                log::error!(
                    "[LOCK_MONITOR] scan_summary_state 持有 {}ms（超 {}ms 阈值），疑似死锁",
                    held,
                    LOCK_HOLD_WARN_THRESHOLD_MS
                );
                if let Ok(mut guard) = self.scan_summary_state.try_lock() {
                    log::warn!(
                        "[LOCK_MONITOR] scan_summary_state try_lock 成功，强制重置为 None"
                    );
                    *guard = None;
                    self.scan_summary_lock_acquired_ms.store(0, Ordering::SeqCst);
                    let req = serde_json::json!({"op": "scan_summary_close"});
                    let _ = self.send(&req.to_string());
                } else {
                    log::warn!(
                        "[LOCK_MONITOR] scan_summary_state try_lock 失败（仍被持有），仅告警"
                    );
                }
            }
        }
    }

    /// 启动锁持有时间监控后台任务（第 11.7 项）
    ///
    /// 每 5s 调用 check_lock_timestamps，检测 scan_state / scan_summary_state
    /// 是否被持有超 30s（疑似死锁）。超时则告警 + try_lock 强制重置。
    ///
    /// 应在应用启动时（lib.rs setup）调用，传入 shutdown CancellationToken
    /// 以便应用退出时停止监控。
    pub fn spawn_lock_monitor(app: tauri::AppHandle, shutdown: CancellationToken) {
        // 第 11.7 项：使用 tauri::async_runtime::spawn 而非 tokio::spawn。
        //
        // 原因：此函数由 lib.rs 的 setup 回调调用，setup 运行在 Tauri 事件循环
        // 主线程而非 Tokio 运行时上下文内。直接调用 tokio::spawn 会触发
        // "there is no reactor running, must be called from the context of a Tokio 1.x runtime"
        // panic（exit code 101），导致应用启动即崩溃。
        //
        // tauri::async_runtime::spawn 通过 Tauri 全局托管的 Tokio 运行时句柄派发任务，
        // 可在任意线程/上下文调用；任务一旦在 Tauri 运行时上执行，
        // tokio::select! / tokio::time::interval 等 Tokio 原语即处于合法上下文。
        tauri::async_runtime::spawn(async move {
            const CHECK_INTERVAL: Duration = Duration::from_secs(5);
            let mut interval = tokio::time::interval(CHECK_INTERVAL);
            // 跳过第一次立即触发（启动时锁未被持有）
            interval.tick().await;

            log::info!(
                "[LOCK_MONITOR] 启动锁持有时间监控（每 {}s 检查，阈值 30s）",
                CHECK_INTERVAL.as_secs()
            );

            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        log::info!("[LOCK_MONITOR] 收到关闭信号，退出");
                        break;
                    }
                    _ = interval.tick() => {
                        let state = app.state::<AppState>();
                        state.check_lock_timestamps();
                    }
                }
            }
        });
    }
}

/* ------------------------------------------------------------------ *
 * InitLockGuard — RAII 初始化锁守卫                                    *
 * ------------------------------------------------------------------ */

/// RAII 守卫：确保 init_lock 在函数退出时释放
pub struct InitLockGuard<'a> {
    pub state: &'a AppState,
}
impl<'a> Drop for InitLockGuard<'a> {
    fn drop(&mut self) {
        self.state.release_init_lock();
    }
}

/* ------------------------------------------------------------------ *
 * 熔断清理函数（委托到泛型 cleanup_pipeline_on_failure）                *
 * ------------------------------------------------------------------ */

/// 全量扫描熔断清理：停止预取 + 擦除缓冲 + 通知 worker 关闭游标
///
/// 第 11.4 项：cancel + 短超时等待退出（替代 handle.abort() + handle.await）
/// 第 11.3 项：委托到泛型 cleanup_pipeline_on_failure
pub async fn cleanup_scan_on_failure(state: &AppState) {
    cleanup_pipeline_on_failure::<VerthysRecordEntry>(
        &state.scan_state,
        state,
        Duration::from_secs(2),
    )
    .await;
}

/// 摘要扫描熔断清理：与 cleanup_scan_on_failure 对称
pub async fn cleanup_summary_scan_on_failure(state: &AppState) {
    cleanup_pipeline_on_failure::<VerthysSummaryEntry>(
        &state.scan_summary_state,
        state,
        Duration::from_secs(2),
    )
    .await;
}

/* ------------------------------------------------------------------ *
 * 单元测试                                                            *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_new() {
        let state = AppState::new();
        assert!(!state.has_session());
        assert_eq!(state.get_pending_io_count(), 0);
        assert!(!state.init_lock.load(Ordering::SeqCst));
        assert!(!state.prefetch_done.load(Ordering::SeqCst));
        assert_eq!(state.scan_lock_acquired_ms.load(Ordering::SeqCst), 0);
        assert_eq!(
            state.scan_summary_lock_acquired_ms.load(Ordering::SeqCst),
            0
        );
    }

    #[test]
    fn test_init_lock_acquire_release() {
        let state = AppState::new();
        assert!(state.try_acquire_init_lock());
        assert!(!state.try_acquire_init_lock()); // 已持有，再次获取失败
        state.release_init_lock();
        assert!(state.try_acquire_init_lock()); // 释放后可再次获取
        state.release_init_lock();
    }

    #[test]
    fn test_init_lock_guard_raii() {
        let state = AppState::new();
        // InitLockGuard 是 RAII 释放守卫：调用方先获取锁，guard 确保 Drop 时释放
        assert!(state.try_acquire_init_lock());
        assert!(state.init_lock.load(Ordering::SeqCst));
        {
            let _guard = InitLockGuard { state: &state };
            // guard 存在期间，锁应保持持有
            assert!(state.init_lock.load(Ordering::SeqCst));
        }
        // guard drop 后应自动释放
        assert!(!state.init_lock.load(Ordering::SeqCst));
    }

    #[test]
    fn test_io_barrier_begin_end() {
        let state = AppState::new();
        assert_eq!(state.get_pending_io_count(), 0);

        state.begin_io();
        assert_eq!(state.get_pending_io_count(), 1);

        state.begin_io();
        assert_eq!(state.get_pending_io_count(), 2);

        state.end_io();
        assert_eq!(state.get_pending_io_count(), 1);

        state.end_io();
        assert_eq!(state.get_pending_io_count(), 0);
    }

    #[tokio::test]
    async fn test_wait_io_complete_fast_path() {
        // 无待处理 IO 时应立即返回 true
        let state = AppState::new();
        let result = state.wait_io_complete(Duration::from_secs(1)).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_wait_io_complete_notify() {
        // 第 11.6 项：begin_io 后 wait_io_complete 应等待，
        // end_io 通知后应立即返回 true
        let state = std::sync::Arc::new(AppState::new());
        state.begin_io();

        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            // 短暂等待后 end_io，触发 notify_one
            tokio::time::sleep(Duration::from_millis(50)).await;
            state_clone.end_io();
        });

        let result = state
            .wait_io_complete(Duration::from_secs(2))
            .await;
        assert!(result);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_wait_io_complete_timeout() {
        // IO 未完成且超时应返回 false
        let state = AppState::new();
        state.begin_io();

        let result = state
            .wait_io_complete(Duration::from_millis(100))
            .await;
        assert!(!result);

        // 清理
        state.end_io();
    }

    #[test]
    fn test_lock_scan_state_timestamp() {
        // 第 11.7 项：锁定时记录时间戳，释放时清零
        let state = AppState::new();

        assert_eq!(state.scan_lock_acquired_ms.load(Ordering::SeqCst), 0);

        {
            let _guard = state.lock_scan_state();
            // 锁定后时间戳应非零
            assert!(state.scan_lock_acquired_ms.load(Ordering::SeqCst) > 0);
        }

        // guard drop 后时间戳应清零
        assert_eq!(state.scan_lock_acquired_ms.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_lock_scan_summary_state_timestamp() {
        let state = AppState::new();

        assert_eq!(
            state.scan_summary_lock_acquired_ms.load(Ordering::SeqCst),
            0
        );

        {
            let _guard = state.lock_scan_summary_state();
            assert!(
                state.scan_summary_lock_acquired_ms.load(Ordering::SeqCst) > 0
            );
        }

        assert_eq!(
            state.scan_summary_lock_acquired_ms.load(Ordering::SeqCst),
            0
        );
    }

    #[test]
    fn test_lock_scan_state_access() {
        // 验证 TimedMutexGuard 可以像 MutexGuard 一样使用
        let state = AppState::new();

        // 初始状态为 None
        {
            let guard = state.lock_scan_state();
            assert!(guard.is_none());
        }

        // 设置为 Some 后验证可访问
        {
            let mut guard = state.lock_scan_state();
            *guard = Some(ScanPipelineState::<VerthysRecordEntry> {
                shm_name: "test_shm".to_string(),
                current_buffer: None,
                exhausted: true,
                prefetch_task: None,
                pending_reply: None,
                session_state: crate::state::ScanSessionState::Active,
            });
        }

        // 验证值已存储
        {
            let guard = state.lock_scan_state();
            assert!(guard.is_some());
            let scan = guard.as_ref().unwrap();
            assert_eq!(scan.shm_name, "test_shm");
            assert!(scan.exhausted);
        }
    }

    #[test]
    fn test_lock_verthys_file() {
        // 第 11.5 项：verthys_file_lock 中毒恢复
        let state = AppState::new();

        {
            let guard = state.lock_verthys_file();
            assert!(guard.is_none());
        }

        {
            let mut guard = state.lock_verthys_file();
            *guard = None; // 模拟设置（实际由 verthys_unlock 设置）
        }
    }

    #[test]
    fn test_check_lock_timestamps_no_warning() {
        // 未持锁时 check 不应告警或重置
        let state = AppState::new();
        state.check_lock_timestamps();
        // 无 panic 即通过
    }

    #[test]
    fn test_check_lock_timestamps_stale() {
        // 模拟锁持有超 30s（设置旧时间戳），check 应尝试 try_lock 重置
        let state = AppState::new();

        // 设置一个 60s 前的时间戳
        let old_ts = now_ms().saturating_sub(60_000);
        state.scan_lock_acquired_ms.store(old_ts, Ordering::SeqCst);

        // 因为没有真正持有锁（只是设置了时间戳），try_lock 应成功
        state.check_lock_timestamps();

        // 时间戳应被清零
        assert_eq!(state.scan_lock_acquired_ms.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_timed_mutex_guard_deref_chain() {
        // 验证 TimedMutexGuard 的 Deref 链可以访问 Option 的方法
        let state = AppState::new();

        {
            let mut guard = state.lock_scan_state();
            // as_mut() 通过 DerefMut → MutexGuard → Option
            assert!(guard.as_mut().is_none());

            // 设置值
            *guard = Some(ScanPipelineState::<VerthysRecordEntry> {
                shm_name: "deref_test".to_string(),
                current_buffer: None,
                exhausted: false,
                prefetch_task: None,
                pending_reply: None,
                session_state: crate::state::ScanSessionState::Active,
            });
        }

        {
            let guard = state.lock_scan_state();
            // as_ref() 通过 Deref → MutexGuard → Option
            let scan = guard.as_ref().expect("should be Some");
            assert_eq!(scan.shm_name, "deref_test");
            assert!(!scan.exhausted);
        }
    }
}
