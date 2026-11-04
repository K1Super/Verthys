/*
 * vault_rotate_controller.rs — 全库 DEK 轮换命令
 *
 * 职责边界：
 *   - 只做参数边界（路径绝对性、标志位、口令/恢复码长度）与结果契约；
 *   - 口令来自本机保管（容器口令）或用户输入的模块口令，本层不缓存、
 *     不写日志；轮换进度只含统计计数；
 *   - worker 访问、路径授权、会话哨兵锁重建全部经 service::vault_rotate
 *     契约完成，本层不引用 state / worker（分层单向依赖）。
 *
 * 审计：begin / commit / abort 每次记录结果；run 仅在失败时记录。
 * 审计只落源库路径哈希与新库路径哈希，不落路径明文与任何口令。
 */

use std::path::Path;

use zeroize::Zeroizing;

use crate::controller::types::VerthysResponse;
use crate::controller::verthys_controller::write_verthys_audit;
use crate::service::vault_rotate::{self, RotateProgress};
use crate::util::audit_log::{
    hash_resource, keyfile_path_tag, AuditEventType, AuditResult,
};

fn forward(result: Result<String, String>) -> Result<VerthysResponse, String> {
    let resp_json = Zeroizing::new(result?);
    let mut resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    /* worker 把稳定错误码放在 error 字段（ERR_XXXXXXXX）；补齐 error_code，
     * 让前端按码分支而不是按文案/字符串匹配。 */
    if !resp.ok && resp.error_code.is_none() {
        if let Some(err) = resp.error.as_deref() {
            if let Some(hex) = err.strip_prefix("ERR_") {
                if hex.len() == 8 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    resp.error_code = Some(err.to_string());
                }
            }
        }
    }
    Ok(resp)
}

/// 记录轮换审计事件：资源为源库路径（哈希化），详情不含路径明文。
fn audit_rotate(
    app: &tauri::AppHandle,
    action: &str,
    resp: &Result<VerthysResponse, String>,
    extra: Option<String>,
) {
    let resource = vault_rotate::session_path(app).unwrap_or_else(|| "-".to_string());
    let (result, tail) = match resp {
        Ok(r) if r.ok => (AuditResult::Success, String::new()),
        Ok(r) => (
            AuditResult::Failure,
            format!("error={}", r.error.as_deref().unwrap_or("unknown")),
        ),
        Err(e) => (AuditResult::Failure, format!("error={}", e)),
    };
    let mut detail = format!("action={}", action);
    if let Some(extra) = extra {
        detail.push(';');
        detail.push_str(&extra);
    }
    if !tail.is_empty() {
        detail.push(';');
        detail.push_str(&tail);
    }
    write_verthys_audit(
        app,
        AuditEventType::VerthysRotate,
        &resource,
        result,
        Some(detail),
    );
}

/// 开始轮换：new_path 必须是不存在且与源库同目录的绝对路径。
///
/// 同目录与不存在性由 C 层最终裁决（本层不预判存在性，避免 TOCTOU 假象）；
/// flags 仅允许显式移除 PCR 绑定位。
#[tauri::command]
pub async fn verthys_v4_rotate_begin(
    app: tauri::AppHandle,
    new_path: String,
    flags: Option<u32>,
) -> Result<VerthysResponse, String> {
    let new_path = new_path.trim().to_string();
    let flags_value = flags.unwrap_or(0);
    if new_path.is_empty() || !Path::new(&new_path).is_absolute() {
        return Ok(VerthysResponse::err(
            "v4_rotate_begin",
            "临时库路径必须是绝对路径",
        ));
    }
    if !vault_rotate::flags_ok(flags_value) {
        return Ok(VerthysResponse::err("v4_rotate_begin", "轮换标志非法"));
    }
    let resp = forward(vault_rotate::begin(&app, &new_path, flags_value));
    audit_rotate(
        &app,
        "begin",
        &resp,
        Some(format!(
            "flags={};path_hash={}",
            flags_value,
            hash_resource(&new_path)
        )),
    );
    resp
}

/// 登记一个已启用模块的轮换口令（并解锁源模块）。
///
/// password 是**模块口令**，不是容器口令；recovery_code 可空，提供时
/// C 层先做一次恢复码二次校验。
#[tauri::command]
pub async fn verthys_v4_rotate_unlock_module(
    app: tauri::AppHandle,
    module_id: u32,
    password: String,
    recovery_code: Option<String>,
) -> Result<VerthysResponse, String> {
    if !vault_rotate::module_id_ok(module_id) {
        return Ok(VerthysResponse::err(
            "v4_rotate_unlock_module",
            "模块索引非法",
        ));
    }
    if !vault_rotate::module_password_ok(&password) {
        return Ok(VerthysResponse::err(
            "v4_rotate_unlock_module",
            "模块口令长度非法",
        ));
    }
    let recovery_code = Zeroizing::new(recovery_code.unwrap_or_default());
    if !vault_rotate::recovery_code_ok(recovery_code.as_str()) {
        return Ok(VerthysResponse::err(
            "v4_rotate_unlock_module",
            "恢复码长度非法",
        ));
    }
    let password = Zeroizing::new(password);
    let recovery = if recovery_code.is_empty() {
        None
    } else {
        Some(recovery_code.as_str())
    };
    forward(vault_rotate::unlock_module(
        &app,
        module_id,
        password.as_str(),
        recovery,
    ))
}

/// 全量复制并提供进度；成功后才能提交，失败只能中止。
#[tauri::command]
pub async fn verthys_v4_rotate_run(
    app: tauri::AppHandle,
    on_progress: tauri::ipc::Channel<RotateProgress>,
) -> Result<VerthysResponse, String> {
    let resp = forward(vault_rotate::run(&app, &|progress| {
        // 前端通道断开不影响轮换本身（进度为观测通道）。
        let _ = on_progress.send(progress.clone());
    }));
    if !matches!(&resp, Ok(r) if r.ok) {
        // 成功态由 commit 记录；run 只记录失败（含超时/协议错误）。
        audit_rotate(&app, "run", &resp, None);
    }
    resp
}

/// 原子替换源库并推进回退锚点；成功后重建会话哨兵锁。
#[tauri::command]
pub async fn verthys_v4_rotate_commit(
    app: tauri::AppHandle,
    keep_old: Option<bool>,
) -> Result<VerthysResponse, String> {
    let keep_old = keep_old.unwrap_or(false);
    let resp = forward(vault_rotate::commit(&app, keep_old));
    let mut audit_detail = format!("keep_old={}", keep_old);
    if matches!(&resp, Ok(r) if r.ok) {
        match vault_rotate::refresh_session_after_commit(&app) {
            Ok(()) => audit_detail.push_str(";guard=ok"),
            Err(e) => {
                log::warn!("[vault_rotate] 会话哨兵锁重建失败（提交已生效，不回滚）: {}", e);
                audit_detail.push_str(";guard=degraded");
            }
        }
    }
    audit_rotate(&app, "commit", &resp, Some(audit_detail));
    resp
}

/// 恢复会话补录 keyfile：容器启用 KEYFILE 且当前会话未持有摘要时使用。
///
/// keyfile 路径只作为参数转发；文件内容由 C 层在 worker 进程内读取，
/// 不进入主进程与 WebView。
#[tauri::command]
pub async fn verthys_v4_rotate_attach_keyfile(
    app: tauri::AppHandle,
    keyfile_path: String,
) -> Result<VerthysResponse, String> {
    let keyfile_path = keyfile_path.trim().to_string();
    if keyfile_path.is_empty() || !Path::new(&keyfile_path).is_absolute() {
        return Ok(VerthysResponse::err(
            "v4_rotate_attach_keyfile",
            "keyfile 路径必须是绝对路径",
        ));
    }
    let resp = forward(vault_rotate::attach_keyfile(&app, &keyfile_path));
    audit_rotate(
        &app,
        "attach_keyfile",
        &resp,
        Some(format!("path_hash={}", keyfile_path_tag(&keyfile_path))),
    );
    resp
}

/// 请求取消正在进行的轮换 Run（仅解锁模块与复制阶段可用）。
#[tauri::command]
pub async fn verthys_v4_rotate_cancel(
    app: tauri::AppHandle,
) -> Result<VerthysResponse, String> {
    let resp = forward(vault_rotate::cancel());
    audit_rotate(&app, "cancel", &resp, None);
    resp
}

/// 丢弃临时库并释放作业；成功后句柄仍指向原库。
#[tauri::command]
pub async fn verthys_v4_rotate_abort(
    app: tauri::AppHandle,
) -> Result<VerthysResponse, String> {
    let resp = forward(vault_rotate::abort(&app));
    audit_rotate(&app, "abort", &resp, None);
    resp
}
