/*
 * 导入取消
 *
 * 职责边界：仅作用于 file-* job，避免清藏界面的取消请求打断照片导入。
 */

use crate::state::AppState;
use std::sync::atomic::Ordering;
use tauri::State;


use super::*;
/* ------------------------------------------------------------------ *
 * 命令：file_import_cancel                                            *
 * ------------------------------------------------------------------ */

/// 取消进行中的清藏导入。
///
/// 仅作用于 file-* job：共享数据面槽位同时承载拾光任务，跨模块取消必须被
/// 拒绝，避免清藏界面的延迟取消请求打断照片导入。
#[tauri::command]
pub async fn file_import_cancel(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let Some(job_id) = state.data_plane_job_id() else {
        return Ok(());
    };
    if !job_id.starts_with("file-") {
        return Ok(());
    }
    if let Some(flag) = state.data_plane_job_cancel_flag(&job_id) {
        flag.store(true, Ordering::SeqCst);
    }
    tauri::async_runtime::spawn(async move {
        let _ = send_worker(
            &app,
            serde_json::json!({"op": "file_import_job_cancel", "job_id": job_id}),
            END_TIMEOUT,
        )
        .await;
    });
    Ok(())
}
