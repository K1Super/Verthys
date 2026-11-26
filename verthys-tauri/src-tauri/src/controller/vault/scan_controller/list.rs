/*
 * 按类型枚举记录 ID
 *
 * 职责边界：走类型盲索引分页，不读记录密文；单页上限与 C 层同源。
 */

use crate::controller::types::VerthysResponse;
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::state::AppState;
use std::time::Duration;
use tauri::State;

/* ------------------------------------------------------------------ *
 * 命令：verthys_list_ids_by_type                                     *
 *                                                                    *
 * 权威类型 ID 来源：类型盲索引，不读记录密文。前端按类型加载列表时  *
 * 必须使用本命令，不得依赖摘要扫描的 type（摘要恒为未知 0）。       *
 * 分页由 after_id 推进，单页上限与 C 层同源（4096）。                  *
 * ------------------------------------------------------------------ */

/// 类型 ID 枚举超时：仅索引游标，不涉及记录段解密，30s 为故障兜底。
const TYPE_LIST_TIMEOUT: Duration = Duration::from_secs(30);

#[tauri::command]
pub async fn verthys_list_ids_by_type(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    rtype: u32,
    after_id: u64,
    max_count: u64,
) -> Result<VerthysResponse, String> {
    const TYPE_LIST_BATCH_MAX: u64 = 4096;

    if let Err(msg) = require_unlocked(&app, &state, "list_ids_by_type") {
        return Ok(VerthysResponse::err("list_ids_by_type", &msg));
    }
    if rtype > 0xFFu32 || max_count == 0u64 || max_count > TYPE_LIST_BATCH_MAX {
        return Ok(VerthysResponse::err(
            "list_ids_by_type",
            "非法的类型或分页参数",
        ));
    }

    let req = serde_json::json!({
        "op": "list_ids_by_type",
        "rtype": rtype,
        "id": after_id,
        "max_count": max_count,
    });
    let resp_json = state.send_with_timeout(&req.to_string(), TYPE_LIST_TIMEOUT)?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}
