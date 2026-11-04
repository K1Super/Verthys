/*
 * pcr_controller.rs — v4 PCR 策略命令（前端 → 主进程 → worker → C）
 *
 * 职责边界：只做参数边界与解锁态检查，恢复码二次认证与 PCR 槽持久化
 * 由 C 层完成；本层不缓存恢复码、不写日志、不返回任何密钥。
 */
use std::time::Duration;

use serde_json::json;
use tauri::State;
use zeroize::Zeroizing;

use crate::controller::types::VerthysResponse;
use crate::controller::verthys_controller::require_unlocked;
use crate::state::AppState;

/// 恢复码校验收支：C 层接受空串仅限恢复会话，本层不据此放宽 UI。
const MAX_RECOVERY_CHARS: usize = 256;
const PCR_MASK: u32 = 0x00FF_FFFF;
const PCR_OP_TIMEOUT: Duration = Duration::from_secs(30);

fn forward(
    state: &AppState,
    req: &serde_json::Value,
    timeout: Duration,
) -> Result<VerthysResponse, String> {
    let line = Zeroizing::new(req.to_string());
    let resp_json = Zeroizing::new(state.send_with_timeout(line.as_str(), timeout)?);
    serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))
}

fn recovery_arg_ok(code: &str) -> bool {
    code.len() <= MAX_RECOVERY_CHARS
}

#[tauri::command]
pub async fn verthys_pcr_status(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "pcr_status") {
        return Ok(VerthysResponse::err("v4_pcr_status", &msg));
    }
    forward(&state, &json!({ "op": "v4_pcr_status" }), PCR_OP_TIMEOUT)
}

#[tauri::command]
pub async fn verthys_pcr_enable(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    pcr_select: u32,
    recovery_code: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "pcr_enable") {
        return Ok(VerthysResponse::err("v4_pcr_enable", &msg));
    }
    if pcr_select == 0 || (pcr_select & !PCR_MASK) != 0 {
        return Ok(VerthysResponse::err("v4_pcr_enable", "PCR 位图非法"));
    }
    if !recovery_arg_ok(&recovery_code) {
        return Ok(VerthysResponse::err("v4_pcr_enable", "恢复码长度非法"));
    }
    let recovery_code = Zeroizing::new(recovery_code);
    let req = json!({
        "op": "v4_pcr_enable",
        "pcr_select": pcr_select,
        "recovery_code": recovery_code.as_str(),
    });
    forward(&state, &req, PCR_OP_TIMEOUT)
}

#[tauri::command]
pub async fn verthys_pcr_disable(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    recovery_code: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "pcr_disable") {
        return Ok(VerthysResponse::err("v4_pcr_disable", &msg));
    }
    if !recovery_arg_ok(&recovery_code) {
        return Ok(VerthysResponse::err("v4_pcr_disable", "恢复码长度非法"));
    }
    let recovery_code = Zeroizing::new(recovery_code);
    let req = json!({
        "op": "v4_pcr_disable",
        "recovery_code": recovery_code.as_str(),
    });
    forward(&state, &req, PCR_OP_TIMEOUT)
}

#[tauri::command]
pub async fn verthys_pcr_reseal(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    recovery_code: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "pcr_reseal") {
        return Ok(VerthysResponse::err("v4_pcr_reseal", &msg));
    }
    if !recovery_arg_ok(&recovery_code) {
        return Ok(VerthysResponse::err("v4_pcr_reseal", "恢复码长度非法"));
    }
    let recovery_code = Zeroizing::new(recovery_code);
    let req = json!({
        "op": "v4_pcr_reseal",
        "recovery_code": recovery_code.as_str(),
    });
    forward(&state, &req, PCR_OP_TIMEOUT)
}
