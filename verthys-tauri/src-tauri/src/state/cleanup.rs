use std::sync::atomic::Ordering;
use std::time::Duration;

use tauri::Manager;
use tokio_util::sync::CancellationToken;

use crate::util::contracts::{VerthysRecordEntry, VerthysSummaryEntry};

use super::types::now_ms;
use super::{cleanup_pipeline_on_failure, AppState};

impl AppState {
    /* ----------------------------------------------------------------
     * 锁持有时间监控                                      *
     * ---------------------------------------------------------------- */

    /// 检查锁持有时间戳，超 30s 告警 + try_lock 强制重置
    ///
    /// 由后台任务每 5s 调用一次。检查 scan_state / scan_summary_state
    /// 的锁获取时间戳，如果持有超 30s（疑似死锁），尝试 try_lock 强制重置。
    pub(super) fn check_lock_timestamps(&self) {
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
                    log::warn!("[LOCK_MONITOR] scan_state try_lock 失败（仍被持有），仅告警");
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
                    log::warn!("[LOCK_MONITOR] scan_summary_state try_lock 成功，强制重置为 None");
                    *guard = None;
                    self.scan_summary_lock_acquired_ms
                        .store(0, Ordering::SeqCst);
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

    /// 启动锁持有时间监控后台任务
    ///
    /// 每 5s 调用 check_lock_timestamps，检测 scan_state / scan_summary_state
    /// 是否被持有超 30s（疑似死锁）。超时则告警 + try_lock 强制重置。
    ///
    /// 应在应用启动时（lib.rs setup）调用，传入 shutdown CancellationToken
    /// 以便应用退出时停止监控。
    pub fn spawn_lock_monitor(app: tauri::AppHandle, shutdown: CancellationToken) {
        // 使用 tauri::async_runtime::spawn 而非 tokio::spawn。
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
 * 熔断清理函数（委托到泛型 cleanup_pipeline_on_failure）                *
 * ------------------------------------------------------------------ */

/// 全量扫描熔断清理：停止预取 + 擦除缓冲 + 通知 worker 关闭游标
///
/// cancel + 短超时等待退出，委托到泛型 cleanup_pipeline_on_failure
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
