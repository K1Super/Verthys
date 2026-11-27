/*
 * controller/storage_controller.rs — 存储统计命令
 *
 * 删除后的记录/分片段与退役 COW 节点由 C 存储引擎在提交时立即回收，
 * 后续写入优先复用空闲区、尾部落盘随提交截断；本模块只提供只读统计，
 * 不再暴露任何手动回收入口。
 */
use std::time::Duration;

use tauri::{AppHandle, State};

use crate::constants::command_names::cmd;
use crate::controller::types::{StorageStatsDto, VerthysResponse};
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::state::AppState;

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
