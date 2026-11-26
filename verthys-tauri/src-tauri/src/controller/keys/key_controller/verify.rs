/*
 * 命令：验证 GMK
 *
 * 职责边界：全局密钥验证的完整编排——互斥、服务端熔断闸门、生命周期
 * 与冷却检查、输入校验、worker 请求发送、状态转移与审计。
 */

use super::op_lock::{acquire_key_op, KEY_OP_BUSY_MESSAGE};
use super::requests::VerifyGlobalKeyReq;
use super::validation::{decode_and_validate_b64, validate_password_length, write_key_audit};
use super::DERIVE_VERIFY_TIMEOUT;
use crate::controller::api_error::ErrorCode;
use crate::controller::types::VerthysResponse;
use crate::state::{AppState, KeyLifecycleState, VerifyCheckResult};
use crate::util::audit_log::{AuditEventType, AuditResult};
use tauri::State;
use zeroize::Zeroizing;

// ===== 命令：验证 GMK =====

/// 验证全局密钥（后续解锁）
///
/// 状态要求：当前必须为 Locked，验证成功后进入 Unlocked。
/// 集成防暴力破解冷却（连续 5 次失败触发指数冷却）。
/// 密码零化处理，超时 15 秒，审计记录。
#[tauri::command]
pub async fn verthys_verify_global_key(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    password: String,
    bin_data_b64: String,
    bin_password: String,
    record_b64: String,
) -> Result<VerthysResponse, String> {
    let password = Zeroizing::new(password);
    log::info!("[verthys_verify_global_key] 开始验证 GMK");

    /* 与改钥/派生/清零互斥：验证成功会把 worker GMK 槽写成记录派生值，
     * 与改钥交错会让槽内密钥落后于最新记录。 */
    let Some(_key_op_guard) = acquire_key_op(state.inner(), "verify_global_key") else {
        return Ok(VerthysResponse::err("verify_global_key", KEY_OP_BUSY_MESSAGE));
    };

    // 服务端强制熔断闸门：锁定/过频状态下拒绝一切口令类操作（fail-closed）。
    // 与 unlock 共享同一守卫：两处口令入口的失败计数累加，成功任一即重置。
    // 经 service 层契约调用（实现由 security_commands 启动时注册）。
    use crate::service::unlock_gate::{
        gate_check, record_auth_failure, record_auth_success, GateDomain, UnlockGate,
        E_CNG_UNAVAILABLE, E_RATE_LIMITED,
    };
    match gate_check(&app, GateDomain::GlobalKey) {
        UnlockGate::Allowed => {}
        UnlockGate::Locked(secs) => {
            log::warn!(
                "[verthys_verify_global_key] 暴力熔断锁定中（剩余 {}s），拒绝尝试",
                secs
            );
            write_key_audit(
                &app,
                AuditEventType::KeyVerify,
                AuditResult::Denied,
                Some(format!(
                    "BRUTE_FORCE_LOCKOUT: 界面锁定 {} 秒（服务端强制）",
                    secs
                )),
            );
            return Ok(VerthysResponse::err_code_retry(
                "verify_global_key",
                E_RATE_LIMITED,
                &format!("尝试次数过多，已锁定 {} 秒，请稍后再试", secs),
                secs,
            ));
        }
        UnlockGate::RateLimited { retry_after_secs } => {
            log::warn!(
                "[verthys_verify_global_key] 最小尝试间隔未满足（剩余 {}s），拒绝尝试",
                retry_after_secs
            );
            write_key_audit(
                &app,
                AuditEventType::KeyVerify,
                AuditResult::Denied,
                Some(format!(
                    "RATE_LIMITED: 最小尝试间隔未满足（剩余 {} 秒）",
                    retry_after_secs
                )),
            );
            return Ok(VerthysResponse::err_code_retry(
                "verify_global_key",
                E_RATE_LIMITED,
                &format!("请求过于频繁，请 {} 秒后再试", retry_after_secs),
                retry_after_secs,
            ));
        }
        UnlockGate::Unavailable => {
            log::error!("[verthys_verify_global_key] 熔断守卫不可用（fail-closed 拒绝）");
            write_key_audit(
                &app,
                AuditEventType::KeyVerify,
                AuditResult::Denied,
                Some("熔断守卫不可用，fail-closed 拒绝验证".into()),
            );
            return Ok(VerthysResponse::err_code(
                "verify_global_key",
                E_CNG_UNAVAILABLE,
                "安全门禁暂时不可用，请重启应用后重试",
            ));
        }
    }

    let current_state = state.key_lifecycle.current_state();
    match current_state {
        // Locked：首次口令证明；Unlocked：中枢内重认证（改钥/导出核验）。
        // 两种状态都允许验证；重认证成功由 record_verify_success 幂等保持
        // Unlocked，失败不降级已认证会话。
        KeyLifecycleState::Locked | KeyLifecycleState::Unlocked => {}
        KeyLifecycleState::NoKey => {
            log::warn!(
                "[verthys_verify_global_key] 状态不匹配：当前 {}，仅 Locked/Unlocked 允许验证",
                current_state
            );
            write_key_audit(
                &app,
                AuditEventType::KeyVerify,
                AuditResult::Denied,
                Some(format!(
                    "状态不匹配：当前 {}，仅 Locked/Unlocked 允许验证",
                    current_state
                )),
            );
            return Ok(VerthysResponse::err(
                "verify_global_key",
                ErrorCode::KeyStateMismatch.default_message(),
            ));
        }
    }

    match state.key_lifecycle.check_verify_allowed() {
        VerifyCheckResult::Allow => {}
        VerifyCheckResult::Cooldown(remaining) => {
            log::warn!("[verthys_verify_global_key] 冷却中，剩余 {}s", remaining);
            write_key_audit(
                &app,
                AuditEventType::KeyVerify,
                AuditResult::Denied,
                Some(format!("冷却中，剩余 {}s", remaining)),
            );
            return Ok(VerthysResponse::err(
                "verify_global_key",
                ErrorCode::RateLimited.default_message(),
            ));
        }
    }

    if let Err(e) = validate_password_length(&password) {
        log::warn!("[verthys_verify_global_key] 密码长度校验失败");
        write_key_audit(
            &app,
            AuditEventType::KeyVerify,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Ok(VerthysResponse::err("verify_global_key", &e));
    }

    if let Err(e) = decode_and_validate_b64(&bin_data_b64) {
        log::warn!("[verthys_verify_global_key] bin_data 校验失败");
        write_key_audit(
            &app,
            AuditEventType::KeyVerify,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Ok(VerthysResponse::err("verify_global_key", &e));
    }
    // bin_password 是纯文本密码，不按 base64 解码：参与 PBKDF2 的是密码原始
    // 字节，含特殊字符或长度非 4 倍数的密码会被 base64 校验误拒。
    // 此处只做非空与最大长度校验。
    if bin_password.is_empty() {
        log::warn!("[verthys_verify_global_key] bin_password 为空");
        write_key_audit(
            &app,
            AuditEventType::KeyVerify,
            AuditResult::Denied,
            Some("密钥文件密码不能为空".into()),
        );
        return Ok(VerthysResponse::err(
            "verify_global_key",
            "密钥文件密码不能为空",
        ));
    }
    if let Err(e) = validate_password_length(&bin_password) {
        log::warn!("[verthys_verify_global_key] bin_password 长度校验失败");
        write_key_audit(
            &app,
            AuditEventType::KeyVerify,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Ok(VerthysResponse::err("verify_global_key", &e));
    }
    if let Err(e) = decode_and_validate_b64(&record_b64) {
        log::warn!("[verthys_verify_global_key] record 校验失败");
        write_key_audit(
            &app,
            AuditEventType::KeyVerify,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Ok(VerthysResponse::err("verify_global_key", &e));
    }

    let bin_data_b64 = Zeroizing::new(bin_data_b64);
    let bin_password = Zeroizing::new(bin_password);
    let record_b64 = Zeroizing::new(record_b64);

    let req_str = Zeroizing::new(
        serde_json::to_string(&VerifyGlobalKeyReq {
            op: "verify_global_key",
            password: &password,
            bin_data: &bin_data_b64,
            bin_password: &bin_password,
            data: &record_b64,
        })
        .map_err(|e| {
            log::error!("[verthys_verify_global_key] 请求序列化失败: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyVerify,
                AuditResult::Failure,
                Some(format!("请求序列化失败: {}", e)),
            );
            "验证密钥失败".to_string()
        })?,
    );

    let resp_json = state
        .send_with_timeout(req_str.as_str(), DERIVE_VERIFY_TIMEOUT)
        .map_err(|e| {
            log::error!("[verthys_verify_global_key] send 失败: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyVerify,
                AuditResult::Failure,
                Some(format!("worker 通信失败: {}", e)),
            );
            "验证密钥失败".to_string()
        })?;

    // 发送完成：序列化副本与全部敏感原件在此统一销毁（Zeroizing 擦除堆缓冲）
    drop(req_str);
    drop(record_b64);
    drop(bin_password);
    drop(bin_data_b64);
    drop(password);

    let mut resp: VerthysResponse = serde_json::from_str(&resp_json).map_err(|e| {
        log::error!(
            "[verthys_verify_global_key] 解析响应失败: {} | raw={}",
            e,
            crate::util::log_sanitizer::json_log_summary(&resp_json, &["op"])
        );
        write_key_audit(
            &app,
            AuditEventType::KeyVerify,
            AuditResult::Failure,
            Some(format!("响应解析失败: {}", e)),
        );
        "验证密钥失败".to_string()
    })?;
    resp.adopt_worker_error_code();

    if resp.ok {
        // 口令验证成功即重置熔断计数：无论后续状态转移是否成功，
        // 正确口令本身已证明非暴破会话。
        record_auth_success(&app);
        if let Err(e) = state.key_lifecycle.record_verify_success() {
            log::error!("[verthys_verify_global_key] 状态转移失败: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyVerify,
                AuditResult::Failure,
                Some(format!("状态转移失败: {}", e)),
            );
        } else {
            let reauth = current_state == KeyLifecycleState::Unlocked;
            log::info!(
                "[verthys_verify_global_key] GMK 验证成功（{}）",
                if reauth {
                    "重认证，保持 Unlocked"
                } else {
                    "状态已转移为 Unlocked"
                }
            );
            write_key_audit(&app, AuditEventType::KeyVerify, AuditResult::Success, None);
        }
    } else {
        // 服务端权威计数：仅认证域错误码计一次失败。
        // 通信层失败与功能性状态码不构成暴破证据，不计数。
        if resp.error.as_deref() == Some(crate::service::unlock_gate::AUTH_DOMAIN_ERROR) {
            record_auth_failure(&app);
        }
        let result = state.key_lifecycle.record_verify_failure();
        match result {
            crate::state::VerifyAttemptResult::FailureCooldown(secs) => {
                log::warn!(
                    "[verthys_verify_global_key] GMK 验证失败，触发 {}s 冷却",
                    secs
                );
                write_key_audit(
                    &app,
                    AuditEventType::KeyVerify,
                    AuditResult::Failure,
                    Some(format!("验证失败，触发 {}s 冷却", secs)),
                );
            }
            crate::state::VerifyAttemptResult::Failure => {
                log::warn!(
                    "[verthys_verify_global_key] GMK 验证失败（连续 {} 次）",
                    state.key_lifecycle.consecutive_failures()
                );
                write_key_audit(
                    &app,
                    AuditEventType::KeyVerify,
                    AuditResult::Failure,
                    resp.error.clone(),
                );
            }
            crate::state::VerifyAttemptResult::Success => {
                log::error!("[verthys_verify_global_key] 逻辑错误：失败路径返回 Success");
            }
        }
    }

    Ok(resp)
}
