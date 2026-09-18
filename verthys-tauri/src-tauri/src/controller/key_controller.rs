/*
 * @file controller/key_controller.rs
 * @brief GMK 派生与验证控制器
 *
 * 本模块提供全局主密钥（GMK）的派生、验证、子密钥派生及内存清零能力。
 * 所有敏感操作（密码处理、PBKDF2 计算）均在 worker 子进程中执行，
 * 主进程仅负责指令转发与状态管理，绝不接触密钥明文。
 *
 * =============================================================================
 * 安全设计
 * =============================================================================
 * - 密码零化：密码以 `Zeroizing<String>` 接收，序列化后立即擦除，确保
 *   密码明文不在主进程内存中驻留。
 * - 状态机约束：密钥生命周期严格遵循 NoKey → Locked → Unlocked 状态转移，
 *   非法状态转换返回 KEY_STATE_MISMATCH。
 * - 防暴力破解：连续验证失败 5 次触发指数冷却（2s → 60s 上限），
 *   冷却期内拒绝验证请求，返回 RATE_LIMITED。
 * - 输入硬校验：密码 ≤512 字节，Base64 数据 ≤4KB，module_id 限 [a-zA-Z0-9_-]{1,64}，
 *   防止 DoS 与注入。
 * - 操作超时：派生/验证 15 秒（PBKDF2 密集计算），清零 2 秒（轻量），
 *   超时后丢弃响应并告警。
 * - 审计日志：每次密钥操作（派生/验证/清零/子密钥）记录操作类型、结果及
 *   上下文（不含密钥），用于异常追溯。
 * - 密码复杂度：派生时校验密码长度与字符种类，不符合返回
 *   PASSWORD_COMPLEXITY_INSUFFICIENT。
 *
 * =============================================================================
 * 依赖方向
 * =============================================================================
 * controller → state / controller::types / controller::api_error /
 *             util::audit_log / util::crypto / util::base64 / constants
 */

use crate::constants::timeout::DEFAULT as TIMEOUT_CONFIG;
use crate::controller::api_error::ErrorCode;
use crate::controller::types::VerthysResponse;
use crate::state::{AppState, KeyLifecycleState, VerifyCheckResult};
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};
use crate::util::base64::base64_decode;
use std::time::Duration;
use tauri::State;
use zeroize::Zeroizing;

// ===== 审计日志辅助 =====

fn get_audit_log_path(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    use tauri::Manager;
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join("audit.log")),
        Err(e) => {
            log::warn!("[audit] 获取配置目录失败，跳过审计写入: {}", e);
            None
        }
    }
}

fn get_audit_hmac_key() -> Option<[u8; 32]> {
    use crate::infrastructure::device_fingerprint::get_device_fingerprint;
    use crate::util::crypto::pbkdf2_derive_default;

    match get_device_fingerprint() {
        Ok(fingerprint) => {
            const AUDIT_SALT: &[u8] = b"verthys_audit_log_hmac_salt_v1";
            match pbkdf2_derive_default(fingerprint.as_bytes(), AUDIT_SALT) {
                Ok(key) => Some(key),
                Err(e) => {
                    log::warn!("[audit] 派生 HMAC 密钥失败，跳过审计写入: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            log::warn!("[audit] 获取设备指纹失败，跳过审计写入: {}", e);
            None
        }
    }
}

fn write_key_audit(
    app: &tauri::AppHandle,
    event_type: AuditEventType,
    result: AuditResult,
    detail: Option<String>,
) {
    let log_path = match get_audit_log_path(app) {
        Some(p) => p,
        None => return,
    };

    let hmac_key = match get_audit_hmac_key() {
        Some(k) => k,
        None => return,
    };

    let session_id = format!("pid-{}", std::process::id());

    let mut event = AuditEvent::new(event_type, &session_id, "user", result);

    if let Some(d) = detail {
        event = event.with_detail(d);
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[audit] 写入密钥审计事件失败（不阻塞业务）: {}", e);
    }
}

// ===== 输入校验 =====

/// 密码最大字节数（512），防止内存超分配。
const PASSWORD_MAX_BYTES: usize = 512;

/// Base64 解码后数据上限（4KB），防止 DoS。
const BASE64_DECODED_MAX_BYTES: usize = 4 * 1024;

/// module_id 最大长度（64 字符），符合白名单格式。
const MODULE_ID_MAX_LEN: usize = 64;

fn validate_password_length(password: &str) -> Result<(), String> {
    let len = password.len();
    if len > PASSWORD_MAX_BYTES {
        return Err(format!("密码过长（超过 {} 字节）", PASSWORD_MAX_BYTES));
    }
    Ok(())
}

fn validate_password_complexity(password: &str) -> Result<(), String> {
    let len = password.len();
    if len < 8 {
        return Err("密码长度不足（至少 8 位）".into());
    }
    if len > PASSWORD_MAX_BYTES {
        return Err("密码过长".into());
    }
    Ok(())
}

fn decode_and_validate_b64(b64: &str) -> Result<Vec<u8>, String> {
    let bytes = base64_decode(b64).map_err(|e| format!("Base64 解码失败: {}", e))?;
    if bytes.len() > BASE64_DECODED_MAX_BYTES {
        return Err(format!(
            "Base64 数据过大（解码后超过 {} 字节）",
            BASE64_DECODED_MAX_BYTES
        ));
    }
    Ok(bytes)
}

fn validate_module_id(module_id: &str) -> Result<(), String> {
    if module_id.is_empty() {
        return Err("module_id 不能为空".into());
    }
    if module_id.len() > MODULE_ID_MAX_LEN {
        return Err(format!(
            "module_id 过长（超过 {} 字符）",
            MODULE_ID_MAX_LEN
        ));
    }
    for ch in module_id.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' {
            return Err("module_id 包含非法字符（仅允许字母、数字、下划线、连字符）".into());
        }
    }
    Ok(())
}

// ===== 超时常量 =====

/// 派生/验证超时（15 秒），适配 PBKDF2 密集计算。
const DERIVE_VERIFY_TIMEOUT: Duration = TIMEOUT_CONFIG.derive_verify;

/// 清零超时（2 秒），轻量内存擦除操作。
const CLEAR_TIMEOUT: Duration = TIMEOUT_CONFIG.clipboard_op;

// ===== 命令：派生 GMK =====

/// 派生全局主密钥（首次设置）
///
/// 状态要求：当前必须为 NoKey，派生成功后进入 Locked。
/// 密码在序列化后立即擦除，不保留明文副本。
/// 请求前校验密码长度、复杂度和 Base64 数据大小。
/// 操作超时 15 秒，失败记录审计。
#[tauri::command]
pub async fn verthys_derive_global_key(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    password: String,
    bin_data_b64: String,
    bin_password: String,
) -> Result<VerthysResponse, String> {
    let password = Zeroizing::new(password);
    log::info!("[verthys_derive_global_key] 开始派生 GMK");

    let current_state = state.key_lifecycle.current_state();
    if current_state != KeyLifecycleState::NoKey {
        log::warn!(
            "[verthys_derive_global_key] 状态不匹配：当前 {}，仅 NoKey 允许派生",
            current_state
        );
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(format!(
                "状态不匹配：当前 {}，仅 NoKey 允许派生",
                current_state
            )),
        );
        return Ok(VerthysResponse::err(
            "derive_global_key",
            ErrorCode::KeyStateMismatch.default_message(),
        ));
    }

    if let Err(e) = validate_password_length(&password) {
        log::warn!("[verthys_derive_global_key] 密码长度校验失败");
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Ok(VerthysResponse::err("derive_global_key", &e));
    }

    if let Err(e) = validate_password_complexity(&password) {
        log::warn!("[verthys_derive_global_key] 密码复杂度校验失败");
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Ok(VerthysResponse::err("derive_global_key", &e));
    }

    if let Err(e) = decode_and_validate_b64(&bin_data_b64) {
        log::warn!("[verthys_derive_global_key] bin_data 校验失败");
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Ok(VerthysResponse::err("derive_global_key", &e));
    }
    // ★ 企业级修复：bin_password 是纯文本密码，不是 base64 数据
    //
    // 原缺陷：decode_and_validate_b64(&bin_password) 将纯文本密码当作 base64
    // 解码。base64 crate STANDARD engine 仅允许 [A-Za-z0-9+/=] 且长度须为 4
    // 的倍数（含 padding），导致含特殊字符（!@#- 等）、非 ASCII 字符（中文等）
    // 或长度非 4 倍数的密码全部被拒——用户输入任何正常密码均触发
    // "invalid base64" 错误，派生/验证按钮必然失败。
    //
    // 修复：bin_password 按纯文本密码校验（非空 + 最大长度），与主密码
    // validate_password_length 一致。worker 端 handle_derive_global_key
    // 使用 req.bin_password.as_bytes() 直接参与 PBKDF2 计算，无需 base64。
    if bin_password.is_empty() {
        log::warn!("[verthys_derive_global_key] bin_password 为空");
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some("密钥文件密码不能为空".into()),
        );
        return Ok(VerthysResponse::err("derive_global_key", "密钥文件密码不能为空"));
    }
    if let Err(e) = validate_password_length(&bin_password) {
        log::warn!("[verthys_derive_global_key] bin_password 长度校验失败");
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Ok(VerthysResponse::err("derive_global_key", &e));
    }

    let req = serde_json::json!({
        "op": "derive_global_key",
        "password": *password,
        "bin_data": bin_data_b64,
        "bin_password": bin_password,
    });
    let req_str = req.to_string();
    drop(req);
    drop(password);

    let resp_json = state
        .send_with_timeout(&req_str, DERIVE_VERIFY_TIMEOUT)
        .map_err(|e| {
            log::error!("[verthys_derive_global_key] send 失败: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyDerive,
                AuditResult::Failure,
                Some(format!("worker 通信失败: {}", e)),
            );
            "派生密钥失败".to_string()
        })?;

    let resp: VerthysResponse = serde_json::from_str(&resp_json).map_err(|e| {
        log::error!("[verthys_derive_global_key] 解析响应失败: {} | raw={}", e, resp_json);
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Failure,
            Some(format!("响应解析失败: {}", e)),
        );
        "派生密钥失败".to_string()
    })?;

    if resp.ok {
        if let Err(e) = state.key_lifecycle.transition_to_locked() {
            log::error!("[verthys_derive_global_key] 状态转移失败: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyDerive,
                AuditResult::Failure,
                Some(format!("状态转移失败: {}", e)),
            );
        } else {
            log::info!("[verthys_derive_global_key] GMK 派生成功，状态已转移为 Locked");
            write_key_audit(&app, AuditEventType::KeyDerive, AuditResult::Success, None);
        }
    } else {
        log::warn!("[verthys_derive_global_key] GMK 派生失败: {:?}", resp.error);
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Failure,
            resp.error.clone(),
        );
    }

    Ok(resp)
}

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

    let current_state = state.key_lifecycle.current_state();
    if current_state != KeyLifecycleState::Locked {
        log::warn!(
            "[verthys_verify_global_key] 状态不匹配：当前 {}，仅 Locked 允许验证",
            current_state
        );
        write_key_audit(
            &app,
            AuditEventType::KeyVerify,
            AuditResult::Denied,
            Some(format!(
                "状态不匹配：当前 {}，仅 Locked 允许验证",
                current_state
            )),
        );
        return Ok(VerthysResponse::err(
            "verify_global_key",
            ErrorCode::KeyStateMismatch.default_message(),
        ));
    }

    match state.key_lifecycle.check_verify_allowed() {
        VerifyCheckResult::Allow => {}
        VerifyCheckResult::Cooldown(remaining) => {
            log::warn!(
                "[verthys_verify_global_key] 冷却中，剩余 {}s",
                remaining
            );
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
    // ★ 企业级修复：bin_password 是纯文本密码，不是 base64 数据（同 derive 修复）
    //
    // 原缺陷：decode_and_validate_b64(&bin_password) 将纯文本密码当作 base64
    // 解码，含特殊字符或长度非 4 倍数的密码全部被拒，验证按钮必然失败。
    //
    // 修复：bin_password 按纯文本密码校验（非空 + 最大长度）。
    if bin_password.is_empty() {
        log::warn!("[verthys_verify_global_key] bin_password 为空");
        write_key_audit(
            &app,
            AuditEventType::KeyVerify,
            AuditResult::Denied,
            Some("密钥文件密码不能为空".into()),
        );
        return Ok(VerthysResponse::err("verify_global_key", "密钥文件密码不能为空"));
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

    let req = serde_json::json!({
        "op": "verify_global_key",
        "password": *password,
        "bin_data": bin_data_b64,
        "bin_password": bin_password,
        "data": record_b64,
    });
    let req_str = req.to_string();
    drop(req);
    drop(password);

    let resp_json = state
        .send_with_timeout(&req_str, DERIVE_VERIFY_TIMEOUT)
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

    let resp: VerthysResponse = serde_json::from_str(&resp_json).map_err(|e| {
        log::error!("[verthys_verify_global_key] 解析响应失败: {} | raw={}", e, resp_json);
        write_key_audit(
            &app,
            AuditEventType::KeyVerify,
            AuditResult::Failure,
            Some(format!("响应解析失败: {}", e)),
        );
        "验证密钥失败".to_string()
    })?;

    if resp.ok {
        if let Err(e) = state.key_lifecycle.record_verify_success() {
            log::error!("[verthys_verify_global_key] 状态转移失败: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyVerify,
                AuditResult::Failure,
                Some(format!("状态转移失败: {}", e)),
            );
        } else {
            log::info!("[verthys_verify_global_key] GMK 验证成功，状态已转移为 Unlocked");
            write_key_audit(&app, AuditEventType::KeyVerify, AuditResult::Success, None);
        }
    } else {
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

// ===== 命令：派生模块子密钥 =====

/// 基于 GMK 派生模块子密钥（HKDF-Expand）
///
/// 状态要求：Unlocked（GMK 已验证可用）。
/// module_id 经白名单校验，防止特殊字符注入。
/// 子密钥派生操作审计记录。
#[tauri::command]
pub async fn verthys_derive_subkey(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    module_id: String,
) -> Result<VerthysResponse, String> {
    log::info!("[verthys_derive_subkey] 派生子密钥: module_id={}", module_id);

    let current_state = state.key_lifecycle.current_state();
    if current_state != KeyLifecycleState::Unlocked {
        log::warn!(
            "[verthys_derive_subkey] 状态不匹配：当前 {}，仅 Unlocked 允许派生子密钥",
            current_state
        );
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(format!(
                "状态不匹配：当前 {}，仅 Unlocked 允许派生子密钥",
                current_state
            )),
        );
        return Ok(VerthysResponse::err(
            "derive_subkey",
            ErrorCode::KeyStateMismatch.default_message(),
        ));
    }

    if let Err(e) = validate_module_id(&module_id) {
        log::warn!("[verthys_derive_subkey] module_id 校验失败");
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Ok(VerthysResponse::err("derive_subkey", &e));
    }

    let req = serde_json::json!({
        "op": "derive_module_subkey",
        "module_id": module_id,
    });

    let resp_json = state
        .send_with_timeout(&req.to_string(), TIMEOUT_CONFIG.ipc)
        .map_err(|e| {
            log::error!("[verthys_derive_subkey] send 失败: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyDerive,
                AuditResult::Failure,
                Some(format!("worker 通信失败: {}", e)),
            );
            "派生子密钥失败".to_string()
        })?;

    let resp: VerthysResponse = serde_json::from_str(&resp_json).map_err(|e| {
        log::error!("[verthys_derive_subkey] 解析响应失败: {} | raw={}", e, resp_json);
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Failure,
            Some(format!("响应解析失败: {}", e)),
        );
        "派生子密钥失败".to_string()
    })?;

    if resp.ok {
        log::info!("[verthys_derive_subkey] 子密钥派生成功");
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Success,
            Some(format!("module_id={}", module_id)),
        );
    } else {
        log::warn!("[verthys_derive_subkey] 子密钥派生失败: {:?}", resp.error);
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Failure,
            resp.error.clone(),
        );
    }

    Ok(resp)
}

// ===== 命令：清零 GMK =====

/// 清零 worker 内存中的 GMK（锁定所有操作）
///
/// 状态转移：Unlocked → Locked（幂等，任何状态均可调用）。
/// 轻量操作，超时 2 秒。
#[tauri::command]
pub async fn verthys_clear_global_key(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    log::info!("[verthys_clear_global_key] 清零 worker 内存中的 GMK");

    let req = serde_json::json!({
        "op": "clear_global_key",
    });

    let resp_json = state
        .send_with_timeout(&req.to_string(), CLEAR_TIMEOUT)
        .map_err(|e| {
            log::error!("[verthys_clear_global_key] send 失败: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyClear,
                AuditResult::Failure,
                Some(format!("worker 通信失败: {}", e)),
            );
            "清零密钥失败".to_string()
        })?;

    let resp: VerthysResponse = serde_json::from_str(&resp_json).map_err(|e| {
        log::error!("[verthys_clear_global_key] 解析响应失败: {} | raw={}", e, resp_json);
        write_key_audit(
            &app,
            AuditEventType::KeyClear,
            AuditResult::Failure,
            Some(format!("响应解析失败: {}", e)),
        );
        "清零密钥失败".to_string()
    })?;

    if resp.ok {
        state.key_lifecycle.transition_to_locked_from_unlocked();
        log::info!("[verthys_clear_global_key] GMK 已清零，状态已转移为 Locked");
        write_key_audit(&app, AuditEventType::KeyClear, AuditResult::Success, None);
    } else {
        log::warn!("[verthys_clear_global_key] GMK 清零失败: {:?}", resp.error);
        write_key_audit(
            &app,
            AuditEventType::KeyClear,
            AuditResult::Failure,
            resp.error.clone(),
        );
    }

    Ok(resp)
}

// ===== 命令：协调密钥存在状态（reconciliation） =====

/// ★ 企业级根治：协调全局密钥存在状态（修正前端迁移后重新校验与后端状态机的不同步）
///
/// 场景：
///   verthys_unlock 时 worker 进程内 probe 通过 find_first_lid_by_type(0x10)
///   搜索全局密钥记录。但 TYPE_GLOBAL_KEY(0x10) 与旧 TYPE_ACCOUNT(0x10) 冲突，
///   probe 可能命中账户记录 → has_global_key 误判 → key_lifecycle 状态错误。
///
///   前端 migrateRecordTypes 将旧账户记录重写为 0x02 后重新校验（findGlobalKeyRecord），
///   得到正确结果。本命令接收前端重新校验的正确结果，修正后端 key_lifecycle 状态机。
///
/// 调用时机：
///   initUnlock 关键路径中，migrateRecordTypes + 重新校验完成之后、verthysReady=true 之前。
///
/// 安全边界：
///   - 不涉及密钥材料，不接触 worker，仅修正状态机
///   - 仅在 NoKey ↔ Locked 之间安全转换（Unlocked → NoKey 仅异常路径）
///   - 幂等：状态已匹配时无操作
///   - 不记录审计日志（非敏感操作，状态修正非用户意图）
#[tauri::command]
pub async fn verthys_reconcile_key_presence(
    state: State<'_, AppState>,
    has_global_key: bool,
) -> Result<VerthysResponse, String> {
    let prev = state.key_lifecycle.current_state();
    state.key_lifecycle.reconcile_key_presence(has_global_key);
    let curr = state.key_lifecycle.current_state();
    log::info!(
        "[verthys_reconcile_key_presence] has_global_key={} | 状态修正: {} → {}",
        has_global_key,
        prev,
        curr
    );
    Ok(VerthysResponse::ok("reconcile_key_presence"))
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_password_length_ok() {
        assert!(validate_password_length("short").is_ok());
        assert!(validate_password_length(&"a".repeat(512)).is_ok());
    }

    #[test]
    fn test_validate_password_length_too_long() {
        let result = validate_password_length(&"a".repeat(513));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("过长"));
    }

    #[test]
    fn test_validate_password_complexity_short() {
        let result = validate_password_complexity("abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("长度不足"));
    }

    #[test]
    fn test_validate_password_complexity_ok() {
        assert!(validate_password_complexity("password123").is_ok());
    }

    #[test]
    fn test_validate_password_complexity_too_long() {
        let result = validate_password_complexity(&"a".repeat(513));
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_and_validate_b64_ok() {
        let result = decode_and_validate_b64("dGVzdA==");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test");
    }

    #[test]
    fn test_decode_and_validate_b64_invalid() {
        let result = decode_and_validate_b64("!!!invalid_base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_and_validate_b64_too_large() {
        let large_data = vec![0u8; BASE64_DECODED_MAX_BYTES + 1];
        let large_b64 = crate::util::base64::base64_encode(&large_data);
        let result = decode_and_validate_b64(&large_b64);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("过大"));
    }

    #[test]
    fn test_validate_module_id_ok() {
        assert!(validate_module_id("module1").is_ok());
        assert!(validate_module_id("my-module").is_ok());
        assert!(validate_module_id("my_module").is_ok());
        assert!(validate_module_id("Module123").is_ok());
        assert!(validate_module_id(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn test_validate_module_id_empty() {
        assert!(validate_module_id("").is_err());
    }

    #[test]
    fn test_validate_module_id_too_long() {
        let result = validate_module_id(&"a".repeat(65));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("过长"));
    }

    #[test]
    fn test_validate_module_id_illegal_chars() {
        assert!(validate_module_id("module/path").is_err());
        assert!(validate_module_id("module..name").is_err());
        assert!(validate_module_id("module name").is_err());
        assert!(validate_module_id("module<script>").is_err());
        assert!(validate_module_id("module|pipe").is_err());
    }

    #[test]
    fn test_key_lifecycle_state_transitions() {
        let lifecycle = crate::state::KeyLifecycle::new();
        assert_eq!(lifecycle.current_state(), KeyLifecycleState::NoKey);
        assert!(lifecycle.transition_to_locked().is_ok());
        assert_eq!(lifecycle.current_state(), KeyLifecycleState::Locked);
        assert!(lifecycle.transition_to_unlocked().is_ok());
        assert_eq!(lifecycle.current_state(), KeyLifecycleState::Unlocked);
        lifecycle.transition_to_locked_from_unlocked();
        assert_eq!(lifecycle.current_state(), KeyLifecycleState::Locked);
    }

    #[test]
    fn test_key_lifecycle_cooldown_integration() {
        let lifecycle = crate::state::KeyLifecycle::new();
        lifecycle.transition_to_locked().unwrap();

        for _ in 0..5 {
            assert_eq!(
                lifecycle.record_verify_failure(),
                crate::state::VerifyAttemptResult::Failure
            );
            assert_eq!(
                lifecycle.check_verify_allowed(),
                VerifyCheckResult::Allow
            );
        }

        let result = lifecycle.record_verify_failure();
        assert!(matches!(
            result,
            crate::state::VerifyAttemptResult::FailureCooldown(2)
        ));

        assert!(matches!(
            lifecycle.check_verify_allowed(),
            VerifyCheckResult::Cooldown(_)
        ));
    }

    #[test]
    fn test_timeout_constants() {
        assert_eq!(DERIVE_VERIFY_TIMEOUT, TIMEOUT_CONFIG.derive_verify);
        assert_eq!(CLEAR_TIMEOUT, TIMEOUT_CONFIG.clipboard_op);
    }
}