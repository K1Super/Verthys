/*
 * v4_module_controller.rs — v4 模块状态与删除命令
 *
 * 职责边界：状态查询只读；删除由宿主注入当前容器口令 + 用户输入的
 * "DELETE" 字面量，C 层执行密码学销毁与叶清除。本层不缓存口令/恢复码。
 */
use std::time::Duration;

use serde_json::json;
use tauri::State;
use zeroize::Zeroizing;

use crate::controller::types::VerthysResponse;
use crate::controller::verthys_controller::{load_container_password, require_unlocked};
use crate::state::AppState;

const MODULE_COUNT: u32 = 3;
/// 状态查询是只读短操作
const MODULE_OP_TIMEOUT: Duration = Duration::from_secs(30);
/// 生命周期事务（启用重写 / 删除清除 / 关闭 / 轮换）耗时随模块数据量增长：
/// 分片重写吞吐约 900MiB/s，100GB 模块需约 2 分钟，留足余量避免 UI 超时后
/// 用户在 worker 仍写入时重试（重试会因已启用/已删除被策略拒绝）。
const MODULE_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(600);
/// 模块口令上限（C 层 VTY_MODULE_PASSWORD_MAX = 4096 字节）
const MAX_MODULE_PASSWORD_BYTES: usize = 4096;
/// 恢复码字符上限（C 层 recovery_arg_ok 限制 256 字符）
const MAX_RECOVERY_CODE_CHARS: usize = 256;

fn forward(
    state: &AppState,
    req: &serde_json::Value,
    timeout: Duration,
) -> Result<VerthysResponse, String> {
    let line = Zeroizing::new(req.to_string());
    let resp_json = Zeroizing::new(state.send_with_timeout(line.as_str(), timeout)?);
    serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))
}

fn module_ok(module_id: u32) -> bool {
    module_id < MODULE_COUNT
}

#[tauri::command]
pub async fn verthys_v4_module_status(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module_id: u32,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "v4_module_status") {
        return Ok(VerthysResponse::err("v4_module_status", &msg));
    }
    if !module_ok(module_id) {
        return Ok(VerthysResponse::err("v4_module_status", "模块索引非法"));
    }
    forward(
        &state,
        &json!({ "op": "v4_module_status", "module_id": module_id }),
        MODULE_OP_TIMEOUT,
    )
}

/// 启用模块保护：把该模块 MDEK 从 Keyring 移入 user/device(/recovery) 槽。
///
/// password 是**模块口令**（不是容器口令）；recovery_code 可选，提供时
/// 同时绑定恢复槽。启用会在 C 层单事务重写该模块的记录/分片，耗时随
/// 数据量增长，超时按最长模块操作预算。
#[tauri::command]
pub async fn verthys_v4_module_enable(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module_id: u32,
    password: String,
    recovery_code: Option<String>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "v4_module_enable") {
        return Ok(VerthysResponse::err("v4_module_enable", &msg));
    }
    if !module_ok(module_id) {
        return Ok(VerthysResponse::err("v4_module_enable", "模块索引非法"));
    }
    if password.is_empty() || password.len() > MAX_MODULE_PASSWORD_BYTES {
        return Ok(VerthysResponse::err("v4_module_enable", "模块口令长度非法"));
    }
    let recovery_code = recovery_code.unwrap_or_default();
    if recovery_code.len() > MAX_RECOVERY_CODE_CHARS {
        return Ok(VerthysResponse::err("v4_module_enable", "恢复码长度非法"));
    }
    let password = Zeroizing::new(password);
    let req = json!({
        "op": "v4_module_enable",
        "module_id": module_id,
        "password": password.as_str(),
        "recovery_code": recovery_code,
    });
    forward(&state, &req, MODULE_TRANSACTION_TIMEOUT)
}

/// 轮换模块口令：只重封 user 槽，不重写数据。
#[tauri::command]
pub async fn verthys_v4_module_rotate_password(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module_id: u32,
    old_password: String,
    new_password: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "v4_module_rotate_password") {
        return Ok(VerthysResponse::err("v4_module_rotate_password", &msg));
    }
    if !module_ok(module_id) {
        return Ok(VerthysResponse::err("v4_module_rotate_password", "模块索引非法"));
    }
    if old_password.is_empty()
        || new_password.is_empty()
        || old_password.len() > MAX_MODULE_PASSWORD_BYTES
        || new_password.len() > MAX_MODULE_PASSWORD_BYTES
    {
        return Ok(VerthysResponse::err(
            "v4_module_rotate_password",
            "模块口令长度非法",
        ));
    }
    let old_password = Zeroizing::new(old_password);
    let new_password = Zeroizing::new(new_password);
    let req = json!({
        "op": "v4_module_rotate_password",
        "module_id": module_id,
        "old_password": old_password.as_str(),
        "new_password": new_password.as_str(),
    });
    forward(&state, &req, MODULE_TRANSACTION_TIMEOUT)
}

/// 关闭模块保护：保留 MDEK 与数据，MDEK 回到 body Keyring。
#[tauri::command]
pub async fn verthys_v4_module_disable(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module_id: u32,
    password: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "v4_module_disable") {
        return Ok(VerthysResponse::err("v4_module_disable", &msg));
    }
    if !module_ok(module_id) {
        return Ok(VerthysResponse::err("v4_module_disable", "模块索引非法"));
    }
    if password.is_empty() || password.len() > MAX_MODULE_PASSWORD_BYTES {
        return Ok(VerthysResponse::err("v4_module_disable", "模块口令长度非法"));
    }
    let password = Zeroizing::new(password);
    let req = json!({
        "op": "v4_module_disable",
        "module_id": module_id,
        "password": password.as_str(),
    });
    forward(&state, &req, MODULE_TRANSACTION_TIMEOUT)
}

/// 绑定模块恢复槽：用模块口令解封当前 share，再用容器恢复码包裹 device share。
///
/// recovery_code 是**容器**一次性恢复码，不是模块口令；绑定后该模块可在
/// 换机时用同一恢复码替代设备因子（仍需模块口令）。
#[tauri::command]
pub async fn verthys_v4_module_bind_recovery(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module_id: u32,
    password: String,
    recovery_code: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "v4_module_bind_recovery") {
        return Ok(VerthysResponse::err("v4_module_bind_recovery", &msg));
    }
    if !module_ok(module_id) {
        return Ok(VerthysResponse::err(
            "v4_module_bind_recovery",
            "模块索引非法",
        ));
    }
    if password.is_empty() || password.len() > MAX_MODULE_PASSWORD_BYTES {
        return Ok(VerthysResponse::err("v4_module_bind_recovery", "模块口令长度非法"));
    }
    if recovery_code.is_empty() || recovery_code.len() > MAX_RECOVERY_CODE_CHARS {
        return Ok(VerthysResponse::err("v4_module_bind_recovery", "恢复码长度非法"));
    }
    let password = Zeroizing::new(password);
    let recovery_code = Zeroizing::new(recovery_code);
    let req = json!({
        "op": "v4_module_bind_recovery",
        "module_id": module_id,
        "password": password.as_str(),
        "recovery_code": recovery_code.as_str(),
    });
    forward(&state, &req, MODULE_TRANSACTION_TIMEOUT)
}

/// 换机后重密封模块设备槽：仅在恢复码解锁的会话中可用。
///
/// 普通会话调用会被 C 层策略拒绝；本层只做长度校验与超时预算，
/// 不把"是否恢复会话"降级为前端判断。
#[tauri::command]
pub async fn verthys_v4_module_reseal_device(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module_id: u32,
    password: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "v4_module_reseal_device") {
        return Ok(VerthysResponse::err("v4_module_reseal_device", &msg));
    }
    if !module_ok(module_id) {
        return Ok(VerthysResponse::err(
            "v4_module_reseal_device",
            "模块索引非法",
        ));
    }
    if password.is_empty() || password.len() > MAX_MODULE_PASSWORD_BYTES {
        return Ok(VerthysResponse::err(
            "v4_module_reseal_device",
            "模块口令长度非法",
        ));
    }
    let password = Zeroizing::new(password);
    let req = json!({
        "op": "v4_module_reseal_device",
        "module_id": module_id,
        "password": password.as_str(),
    });
    forward(&state, &req, MODULE_TRANSACTION_TIMEOUT)
}

/// 删除模块：不可逆。password 由宿主注入，confirm 必须严格为 "DELETE"。
#[tauri::command]
pub async fn verthys_v4_module_delete(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module_id: u32,
    confirm: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "v4_module_delete") {
        return Ok(VerthysResponse::err("v4_module_delete", &msg));
    }
    if !module_ok(module_id) {
        return Ok(VerthysResponse::err("v4_module_delete", "模块索引非法"));
    }
    if confirm != "DELETE" {
        return Ok(VerthysResponse::err("v4_module_delete", "确认字面量非法"));
    }
    let password = load_container_password(&app)?;
    let req = json!({
        "op": "v4_module_delete",
        "module_id": module_id,
        "password": password.as_str(),
        "confirm": "DELETE",
    });
    forward(&state, &req, MODULE_TRANSACTION_TIMEOUT)
}
