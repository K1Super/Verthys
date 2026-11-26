/*
 * 动态防护状态透传
 *
 * 职责边界：透传 worker 的 security_status op。防护状态是进程级事实，
 * 锁定态亦可查询，因此不经数据域会话闸门。
 */
use crate::controller::types::VerthysResponse;
use crate::state::AppState;
use tauri::State;
// ===== 动态防护状态查询 =====

/// 查询动态防护实时状态。
///
/// 透传 worker 的 security_status op，返回 7 条攻击路径的阻断/降级/失败
/// 计数与关键路径全阻断标志。防御状态为进程级事实，锁定态亦可查询。
#[tauri::command]
pub async fn verthys_security_status(
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    let req = serde_json::json!({
        "op": "security_status",
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}
