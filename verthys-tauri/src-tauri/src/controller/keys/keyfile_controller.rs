/*
 * keyfile_controller.rs — keyfile 因子命令（前端 → 主进程 → worker → C）
 *
 * 职责边界：
 *   - 只做参数边界（绝对路径、空值）与解锁态检查；
 *   - 口令仍由本机保管模块注入，前端不传；
 *   - keyfile 路径只作为参数转发，文件内容由 C 层在 worker 进程内读取/生成，
 *     不进入主进程、不进入 WebView、不写日志；
 *   - 不返回任何密钥或 keyfile 字节。
 */
use std::path::Path;
use std::time::Duration;

use serde_json::json;
use tauri::State;
use zeroize::Zeroizing;

use crate::controller::types::VerthysResponse;
use crate::controller::vault::verthys_controller::{
    load_existing_container_password, require_unlocked, write_verthys_audit,
    KEY_MATERIAL_MISSING_CODE, KEY_MATERIAL_MISSING_MESSAGE,
};
use crate::state::AppState;
use crate::util::audit_log::{keyfile_path_tag, AuditEventType, AuditResult};

const KEYFILE_OP_TIMEOUT: Duration = Duration::from_secs(60);

/// 会话内命令读取既有容器口令；缺失时返回结构化错误响应，绝不生成新密钥。
/// 错误响应装箱：VerthysResponse 较大，避免撑大 Result 的 Err 分支。
fn existing_password(
    app: &tauri::AppHandle,
    op: &str,
) -> Result<Zeroizing<String>, Box<VerthysResponse>> {
    match load_existing_container_password(app) {
        Ok(Some(password)) => Ok(password),
        Ok(None) => Err(Box::new(VerthysResponse::err_code(
            op,
            KEY_MATERIAL_MISSING_CODE,
            KEY_MATERIAL_MISSING_MESSAGE,
        ))),
        Err(e) => Err(Box::new(VerthysResponse::err(op, &e))),
    }
}

fn forward(
    state: &AppState,
    req: &serde_json::Value,
    timeout: Duration,
) -> Result<VerthysResponse, String> {
    let line = Zeroizing::new(req.to_string());
    let resp_json = Zeroizing::new(state.send_with_timeout(line.as_str(), timeout)?);
    serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))
}

/// keyfile 路径边界：绝对路径 + 拒绝设备命名空间 + 拒绝系统保护目录。
///
/// 文件内容仍只在 worker 内读取；这里只做主进程可判定的范围收窄，
/// 避免把任意绝对路径直接交给 worker 裁决。
fn keyfile_path_reject(path: &str, require_exists: bool) -> Option<&'static str> {
    let trimmed = path.trim();
    if trimmed.is_empty() || !Path::new(trimmed).is_absolute() {
        return Some("keyfile 路径必须是绝对路径");
    }
    let lower = trimmed.to_lowercase().replace('/', "\\");
    if lower.starts_with(r"\\.\") || lower.starts_with(r"\\?\globalroot") {
        return Some("keyfile 路径不允许设备命名空间");
    }
    match std::fs::canonicalize(trimmed) {
        Ok(canon) => {
            if crate::controller::vault::preflight_controller::is_system_protected_dir(&canon) {
                return Some("keyfile 路径不允许位于系统保护目录");
            }
        }
        Err(_) if require_exists => return Some("keyfile 文件不存在或不可访问"),
        Err(_) => {
            /* 目标尚不存在（enable 新建）：沿父目录向上找最长已存在祖先，
             * 防止用不存在的子目录绕过系统目录判定。 */
            let mut current = Path::new(trimmed).parent();
            while let Some(dir) = current {
                if let Ok(canon) = std::fs::canonicalize(dir) {
                    if crate::controller::vault::preflight_controller::is_system_protected_dir(
                        &canon,
                    ) {
                        return Some("keyfile 路径不允许位于系统保护目录");
                    }
                    break;
                }
                current = dir.parent();
            }
        }
    }
    None
}

#[tauri::command]
pub async fn verthys_keyfile_status(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "keyfile_status") {
        return Ok(VerthysResponse::err("v4_keyfile_status", &msg));
    }
    forward(&state, &json!({ "op": "v4_keyfile_status" }), KEYFILE_OP_TIMEOUT)
}

/// 启用/轮换 keyfile：生成新的 VKFL 到 keyfile_path（目标必须不存在）。
#[tauri::command]
pub async fn verthys_keyfile_enable(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    keyfile_path: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "keyfile_enable") {
        return Ok(VerthysResponse::err("v4_keyfile_enable", &msg));
    }
    if let Some(reason) = keyfile_path_reject(&keyfile_path, false) {
        return Ok(VerthysResponse::err("v4_keyfile_enable", reason));
    }
    let kf = keyfile_path.trim().to_string();
    state
        .authorize_worker_path("v4_keyfile_enable", "write", &kf)
        .map_err(|e| format!("keyfile 路径未授权: {}", e))?;
    let password = match existing_password(&app, "v4_keyfile_enable") {
        Ok(password) => password,
        Err(resp) => return Ok(*resp),
    };
    let req = json!({
        "op": "v4_keyfile_enable",
        "password": password.as_str(),
        "keyfile_path": kf.clone(),
    });
    drop(password);
    let resp = forward(&state, &req, KEYFILE_OP_TIMEOUT);
    // 审计只落路径哈希（含“恢复会话重绑”场景），不写路径明文
    let resource = state.verthys_session_path().unwrap_or_else(|| "-".to_string());
    write_verthys_audit(
        &app,
        AuditEventType::KeyfileFactor,
        &resource,
        if matches!(&resp, Ok(r) if r.ok) {
            AuditResult::Success
        } else {
            AuditResult::Failure
        },
        Some(format!("action=enable;path_hash={}", keyfile_path_tag(&kf))),
    );
    resp
}

/// 恢复会话重绑容器 user/device 槽（换机恢复后恢复本机日常解锁）。
///
/// 仅恢复码会话可用：是否恢复会话由 C 层判定，前端不参与。
/// keyfile_path 仅在容器启用 keyfile 时必填；文件内容只在 worker 内读取。
#[tauri::command]
pub async fn verthys_reseal_device(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    keyfile_path: Option<String>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "reseal_device") {
        return Ok(VerthysResponse::err("v4_reseal_device", &msg));
    }
    let kf = keyfile_path
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    if let Some(kf) = &kf {
        if let Some(reason) = keyfile_path_reject(kf, true) {
            return Ok(VerthysResponse::err("v4_reseal_device", reason));
        }
        state
            .authorize_worker_path("v4_reseal_device", "read", kf)
            .map_err(|e| format!("keyfile 路径未授权: {}", e))?;
    }
    let password = match existing_password(&app, "v4_reseal_device") {
        Ok(password) => password,
        Err(resp) => return Ok(*resp),
    };
    let req = json!({
        "op": "v4_reseal_device",
        "password": password.as_str(),
        "keyfile_path": kf.clone().unwrap_or_default(),
    });
    drop(password);
    let resp = forward(&state, &req, KEYFILE_OP_TIMEOUT);
    let resource = state.verthys_session_path().unwrap_or_else(|| "-".to_string());
    let detail = match kf.as_deref() {
        Some(path) => format!("action=reseal_device;path_hash={}", keyfile_path_tag(path)),
        None => "action=reseal_device;path_hash=none".to_string(),
    };
    write_verthys_audit(
        &app,
        AuditEventType::DeviceRebind,
        &resource,
        if matches!(&resp, Ok(r) if r.ok) {
            AuditResult::Success
        } else {
            AuditResult::Failure
        },
        Some(detail),
    );
    resp
}

/// 关闭 keyfile：普通会话必须提供当前 keyfile（文件合法但 secret 不对统一报 AUTH）；
/// 恢复码会话可省略路径（keyfile 丢失逃生），由 C 层按会话模式判定。
#[tauri::command]
pub async fn verthys_keyfile_disable(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    keyfile_path: Option<String>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "keyfile_disable") {
        return Ok(VerthysResponse::err("v4_keyfile_disable", &msg));
    }
    let kf = keyfile_path
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    if let Some(kf) = &kf {
        if let Some(reason) = keyfile_path_reject(kf, true) {
            return Ok(VerthysResponse::err("v4_keyfile_disable", reason));
        }
        state
            .authorize_worker_path("v4_keyfile_disable", "read", kf)
            .map_err(|e| format!("keyfile 路径未授权: {}", e))?;
    }
    let password = match existing_password(&app, "v4_keyfile_disable") {
        Ok(password) => password,
        Err(resp) => return Ok(*resp),
    };
    let req = json!({
        "op": "v4_keyfile_disable",
        "password": password.as_str(),
        "keyfile_path": kf.clone().unwrap_or_default(),
    });
    drop(password);
    let resp = forward(&state, &req, KEYFILE_OP_TIMEOUT);
    let resource = state.verthys_session_path().unwrap_or_else(|| "-".to_string());
    let detail = match kf.as_deref() {
        Some(path) => format!("action=disable;path_hash={}", keyfile_path_tag(path)),
        None => "action=disable-recovery;path_hash=none".to_string(),
    };
    write_verthys_audit(
        &app,
        AuditEventType::KeyfileFactor,
        &resource,
        if matches!(&resp, Ok(r) if r.ok) {
            AuditResult::Success
        } else {
            AuditResult::Failure
        },
        Some(detail),
    );
    resp
}
