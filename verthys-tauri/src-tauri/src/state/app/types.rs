use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::AppState;

/// 会话代际校验失败：延迟到达的锁定/销毁请求命中了已更换的会话。
///
/// 错误文本以稳定码 `E_LOCK_SUPERSEDED` 开头，前端据此中止后续破坏性
/// 步骤并保留新会话；文本本身只用于日志与排障。
pub const SESSION_SUPERSEDED: &str = "E_LOCK_SUPERSEDED: 目标会话已被替换，本次锁定已放弃";

/* ------------------------------------------------------------------ *
 * TimedMutexGuard — 带时间戳的锁守卫                       *
 * ------------------------------------------------------------------ */

/// 带时间戳的 Mutex 守卫
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
    pub(super) guard: std::sync::MutexGuard<'a, T>,
    pub(super) timestamp: &'a AtomicU64,
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
pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/* ------------------------------------------------------------------ *
 * AppState — 应用主状态                                                *
 * ------------------------------------------------------------------ */

/// 数据面独占任务槽位（拾光导入/导出/还原、清藏导入，单 job 串行）
///
/// 槽位不是模块私有状态：它表达「已有一个重型数据面任务占用单写者通道与
/// worker 数据面」。拾光与清藏共享该槽位，任何新任务都必须先取得槽位，
/// 从结构上杜绝两个模块并发导入互相争抢会话。
///
/// 仅保存宿主侧 job 标识与取消标志；worker 侧 job 状态由 worker 自持，
/// 本槽位不做任何 worker 状态镜像。
pub struct DataPlaneJob {
    pub job_id: String,
    pub cancel: Arc<AtomicBool>,
}

/// 应用主状态
///
/// 通过 `tauri::Builder::manage(AppState::new())` 注册。
/// 所有控制器通过 `State<'_, AppState>` 访问。
///
/// 字段可见性：
///   - `init_lock`：pub（AtomicBool，无中毒风险，直接访问）
///   - `session` / `scan_state` / `scan_summary_state` / `verthys_file_lock`：
///     私有（通过锁中毒恢复方法访问）
///   - `pending_io_count` / `io_notify` / `*_lock_acquired_ms`：
///     私有（通过 begin_io/end_io/wait_io_complete 等方法访问）
/// IO 计数 RAII 守卫：Drop 时自动 end_io，保证异常与早退路径计数归零。
pub struct IoGuard<'a> {
    pub(super) state: &'a AppState,
}

impl Drop for IoGuard<'_> {
    fn drop(&mut self) {
        self.state.end_io();
    }
}
