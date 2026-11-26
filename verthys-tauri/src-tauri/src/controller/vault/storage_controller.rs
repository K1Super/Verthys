/*
 * controller/storage_controller.rs — 存储统计与空间压缩命令
 *
 * 压缩由 worker 内 C 层同步执行；本模块负责：
 *   - 维护闸门（导入/扫描期间拒绝压缩）
 *   - 命名取消事件与进度事件
 *   - 压缩后重建会话哨兵锁（文件已被原子替换，旧句柄指向退役文件）
 */
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Emitter, State};

use crate::constants::command_names::cmd;
use crate::controller::types::{
    CompactResultDto, StorageStatsDto, VerthysResponse,
};
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::infrastructure::handle_factory::{
    close_event, create_named_non_inheritable_event, signal_event,
};
use crate::state::verthys_session::VerthysSessionGuard;
use crate::state::AppState;

const COMPACT_PROGRESS_EVENT: &str = "storage://compact-progress";
const COMPACT_DONE_EVENT: &str = "storage://compacted";
const MIN_RECLAIM_BYTES: u64 = 64u64 * 1024u64 * 1024u64;
const SMALL_CONTAINER_BYTES: u64 = 512u64 * 1024u64 * 1024u64;
const SMALL_MIN_RECLAIM_BYTES: u64 = 16u64 * 1024u64 * 1024u64;

#[derive(Clone)]
struct StorageCancelSignal {
    name: String,
    handle: isize,
}

static STORAGE_CANCEL: Mutex<Option<StorageCancelSignal>> = Mutex::new(None);
static COMPACT_RUNNING: AtomicBool = AtomicBool::new(false);

struct CompactRunningGuard;

impl CompactRunningGuard {
    fn enter() -> Result<Self, String> {
        if COMPACT_RUNNING
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("空间压缩正在进行，请稍后重试".to_string());
        }
        Ok(Self)
    }
}

impl Drop for CompactRunningGuard {
    fn drop(&mut self) {
        COMPACT_RUNNING.store(false, Ordering::SeqCst);
    }
}

fn make_cancel_signal() -> Result<StorageCancelSignal, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = format!(
        "Local\\VerthysStorageCompact-{}-{}",
        std::process::id(),
        nanos
    );
    let handle = create_named_non_inheritable_event(&name)?;
    let signal = StorageCancelSignal {
        name,
        handle: handle.0 as isize,
    };
    *STORAGE_CANCEL
        .lock()
        .map_err(|_| "压缩取消状态不可用".to_string())? = Some(signal.clone());
    Ok(signal)
}

fn clear_cancel_signal() {
    let signal = STORAGE_CANCEL
        .lock()
        .ok()
        .and_then(|mut guard| guard.take());
    if let Some(signal) = signal {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::HANDLE;
            close_event(HANDLE(signal.handle as *mut core::ffi::c_void));
        }
    }
}

/// 关闭可能存在的扫描游标：压缩会替换数据区文件，旧游标必须失效。
fn close_scan_cursors(state: &AppState) {
    {
        let mut guard = state.lock_scan_state();
        if guard.is_some() {
            let _ = state.send("{\"op\":\"scan_close\"}");
            *guard = None;
        }
    }
    {
        let mut guard = state.lock_scan_summary_state();
        if guard.is_some() {
            let _ = state.send("{\"op\":\"scan_summary_close\"}");
            *guard = None;
        }
    }
}

fn rebind_session_guard(app: &AppHandle, state: &AppState) {
    let Some(path) = state.verthys_session_path() else {
        return;
    };
    let session_id = format!(
        "pid-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );
    let mut guard = state.lock_verthys_session();
    /* 旧句柄指向 ReplaceFileW 退役的备份文件；先释放再锁新文件。 */
    *guard = None;
    match VerthysSessionGuard::new(&path, &session_id) {
        Ok(new_guard) => {
            *guard = Some(new_guard);
        }
        Err(e) => {
            log::error!(
                "[storage_compact] 会话哨兵锁重建失败（数据已压缩完成）: {}",
                e
            );
            let _ = app.emit(
                "storage://session-guard-error",
                serde_json::json!({"error": e}),
            );
        }
    }
}

async fn stats_inner(app: &AppHandle, state: &AppState) -> Result<StorageStatsDto, String> {
    require_unlocked(app, state, cmd::STORAGE_STATS)?;
    let raw = state.send_with_timeout(
        &serde_json::json!({"op": "storage_stats"}).to_string(),
        Duration::from_secs(120),
    )?;
    let resp: VerthysResponse =
        serde_json::from_str(&raw).map_err(|e| format!("存储统计响应解析失败: {}", e))?;
    if !resp.ok {
        return Err(resp.error.unwrap_or_else(|| "存储统计失败".to_string()));
    }
    resp.storage_stats
        .ok_or_else(|| "存储统计响应缺少字段".to_string())
}

async fn compact_inner(
    app: &AppHandle,
    state: &AppState,
) -> Result<VerthysResponse, String> {
    require_unlocked(app, state, cmd::STORAGE_COMPACT)?;
    if state.has_import_session() {
        return Err("导入进行中，请结束导入后再回收空间".to_string());
    }
    let _running = CompactRunningGuard::enter()?;
    close_scan_cursors(state);

    let signal = make_cancel_signal()?;
    let request = serde_json::json!({
        "op": "storage_compact",
        "cancel_event": signal.name,
    })
    .to_string();

    let emit_app = app.clone();
    let raw = state.send_with_storage_progress(&request, &move |p| {
        let _ = emit_app.emit(COMPACT_PROGRESS_EVENT, p);
    });
    clear_cancel_signal();
    let raw = match raw {
        Ok(raw) => raw,
        Err(e) => {
            let _ = app.emit("storage://compact-failed", serde_json::json!({"error": e}));
            return Err(e);
        }
    };
    let mut resp: VerthysResponse = match serde_json::from_str(&raw) {
        Ok(resp) => resp,
        Err(e) => {
            /* 响应不可解析意味着 worker 侧结果未知：压缩可能已替换容器，
             * 旧会话哨兵随即失效。只要进入过压缩请求，就必须重建哨兵，
             * 否则后续命令会持续撞上失效守卫。 */
            rebind_session_guard(app, state);
            let _ = app.emit(
                "storage://compact-failed",
                serde_json::json!({"error": format!("空间压缩响应解析失败: {}", e)}),
            );
            return Err(format!("空间压缩响应解析失败: {}", e));
        }
    };
    resp.adopt_worker_error_code();
    if resp.ok {
        rebind_session_guard(app, state);
        let payload = resp
            .compact_result
            .clone()
            .unwrap_or_else(CompactResultDto::default);
        let _ = app.emit(COMPACT_DONE_EVENT, payload);
    } else {
        let _ = app.emit(
            "storage://compact-failed",
            serde_json::json!({"error": resp.error.clone().unwrap_or_default()}),
        );
    }
    Ok(resp)
}

fn should_compact(stats: &StorageStatsDto) -> bool {
    let min = if stats.file_size < SMALL_CONTAINER_BYTES {
        SMALL_MIN_RECLAIM_BYTES
    } else {
        MIN_RECLAIM_BYTES
    };
    let ratio_floor = stats.file_size / 10u64;
    let threshold = min.max(ratio_floor);
    stats.reclaimable_bytes >= threshold && stats.reclaimable_bytes > 0u64
}

/// 删除/GC 成功后按阈值自动压缩；失败只记录日志，不改变删除结论。
pub(crate) async fn auto_compact_after_delete(app: &AppHandle, state: &AppState) {
    /* 给删除后的落盘校验、WAL 幂等键释放与孤儿 GC 留出收敛窗口，
     * 避免压缩抢占 worker 通道拖慢删除反馈。 */
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    if state.has_import_session() {
        return;
    }
    let stats = match stats_inner(app, state).await {
        Ok(s) => s,
        Err(e) => {
            log::debug!("[storage_auto_compact] 统计跳过: {}", e);
            return;
        }
    };
    if !should_compact(&stats) {
        return;
    }
    log::info!(
        "[storage_auto_compact] 可回收 {} 字节，开始自动压缩",
        stats.reclaimable_bytes
    );
    if let Err(e) = compact_inner(app, state).await {
        log::warn!("[storage_auto_compact] 自动压缩失败（删除已生效）: {}", e);
    }
}

#[tauri::command]
pub async fn verthys_storage_stats(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    let stats = stats_inner(&app, state.inner()).await?;
    let mut resp = VerthysResponse::ok(cmd::STORAGE_STATS);
    resp.storage_stats = Some(stats);
    Ok(resp)
}

#[tauri::command]
pub async fn verthys_storage_compact(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    compact_inner(&app, state.inner()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(file_size: u64, reclaimable_bytes: u64) -> StorageStatsDto {
        StorageStatsDto {
            file_size,
            reclaimable_bytes,
            ..StorageStatsDto::default()
        }
    }

    #[test]
    fn small_container_uses_ratio_or_byte_floor() {
        /* 256 MiB 的 10% = 25.6 MiB，高于 16 MiB 固定下限。 */
        assert!(!should_compact(&stats(256 * 1024 * 1024, 25 * 1024 * 1024)));
        assert!(should_compact(&stats(256 * 1024 * 1024, 26 * 1024 * 1024)));
        /* 128 MiB 的 10% = 12.8 MiB，固定下限 16 MiB 生效。 */
        assert!(!should_compact(&stats(128 * 1024 * 1024, 15 * 1024 * 1024)));
        assert!(should_compact(&stats(128 * 1024 * 1024, 16 * 1024 * 1024)));
    }

    #[test]
    fn large_container_uses_ratio_and_floor() {
        /* 4 GiB 容器 10% = 409.6 MiB，高于 64 MiB 固定下限。 */
        assert!(!should_compact(&stats(4 * 1024 * 1024 * 1024, 400 * 1024 * 1024)));
        assert!(should_compact(&stats(4 * 1024 * 1024 * 1024, 410 * 1024 * 1024)));
    }

    #[test]
    fn zero_reclaimable_never_compacts() {
        assert!(!should_compact(&stats(2 * 1024 * 1024 * 1024, 0)));
    }
}

#[tauri::command]
pub async fn verthys_storage_compact_cancel() -> Result<VerthysResponse, String> {
    /* 信号必须在持有取消槽锁时发出：压缩完成会 clear_cancel_signal 并
     * CloseHandle，锁外再发信号可能落到被系统复用的无关内核对象上。 */
    let guard = STORAGE_CANCEL
        .lock()
        .map_err(|_| "压缩取消状态不可用".to_string())?;
    let Some(signal) = guard.as_ref() else {
        return Err("当前没有可取消的空间压缩".to_string());
    };
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::HANDLE;
        signal_event(HANDLE(signal.handle as *mut core::ffi::c_void))
            .map_err(|e| format!("取消压缩失败: {}", e))?;
    }
    #[cfg(not(windows))]
    let _ = signal;
    Ok(VerthysResponse::ok(cmd::STORAGE_COMPACT_CANCEL))
}
