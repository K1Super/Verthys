/*
 * controller/key_change_controller.rs — 全局密钥修改（后端单命令）
 *
 * 为什么收口为单命令：改钥是"核验旧钥 → 派生新钥 → 写新记录 → 删旧记录
 * → 换 GMK 槽"的安全序列。前端多步编排会让状态机、记录与 GMK 槽在多个
 * IPC 之间出现中间态；本命令把序列下沉到 worker 单次调用，主进程只做
 * 闸门、生命周期、输入校验与审计。
 *
 * 状态要求：Locked（首次派生后未验证）或 Unlocked（中枢内重认证）。
 *
 * 失败语义：
 *   - 旧钥错误：不触碰记录与 GMK 槽，计一次认证失败
 *   - 新记录写失败/读回不一致：回收新记录，旧钥仍有效
 *   - 删旧失败：新记录已落盘即为成功（最新记录权威），返回
 *     cleanup_pending=true，残留由下次解锁收敛清除
 *   - 通信超时：结果未确认，禁止自动重试，提示重启后以新密钥验证
 */

use crate::constants::timeout::DEFAULT as TIMEOUT_CONFIG;
use crate::controller::key_controller::{
    decode_and_validate_b64, validate_password_complexity, validate_password_length,
    write_key_audit,
};
use crate::controller::types::VerthysResponse;
use crate::service::unlock_gate::{
    gate_check, record_auth_failure, record_auth_success, GateDomain, UnlockGate,
    AUTH_DOMAIN_ERROR, E_CNG_UNAVAILABLE, E_RATE_LIMITED,
};
use crate::state::{AppState, KeyLifecycleState, KeyOpGuard};
use crate::util::audit_log::{AuditEventType, AuditResult};
use std::time::Duration;
use tauri::State;
use zeroize::Zeroizing;

/// 改钥 IPC 超时：两次 PBKDF2 + 记录写读删，40s 覆盖慢盘余量。
const CHANGE_KEY_TIMEOUT: Duration = TIMEOUT_CONFIG.change_global_key;

/// 改钥请求体（借用序列化；敏感字段不产生 owned 明文副本）
#[derive(serde::Serialize)]
struct ChangeGlobalKeyReq<'a> {
    op: &'static str,
    password: &'a str,
    bin_data: &'a str,
    bin_password: &'a str,
    new_password: &'a str,
    new_bin_data: &'a str,
    new_bin_password: &'a str,
}

/// 修改全局密钥（成功时 worker 已完成 GMK 换槽）
///
/// 安全边界：
///   - 熔断闸门与 verify 共享 GlobalKey 域（失败计数/冷却同源）
///   - 生命周期 NoKey 拒绝；Locked/Unlocked 允许
///   - 成功后状态幂等推进为 Unlocked
#[tauri::command]
pub async fn verthys_change_global_key(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    old_password: String,
    old_bin_data_b64: String,
    old_bin_password: String,
    new_password: String,
    new_bin_data_b64: String,
    new_bin_password: String,
) -> Result<VerthysResponse, String> {
    let old_password = Zeroizing::new(old_password);
    let old_bin_data_b64 = Zeroizing::new(old_bin_data_b64);
    let old_bin_password = Zeroizing::new(old_bin_password);
    let new_password = Zeroizing::new(new_password);
    let new_bin_data_b64 = Zeroizing::new(new_bin_data_b64);
    let new_bin_password = Zeroizing::new(new_bin_password);

    log::info!("[verthys_change_global_key] 开始修改全局密钥");

    // 1. 密钥操作互斥：改钥不得与验证/首次派生交错
    if !state.try_acquire_key_op_lock() {
        log::warn!("[verthys_change_global_key] 已有密钥操作在飞，拒绝并发改钥");
        return Ok(VerthysResponse::err(
            "change_global_key",
            "有进行中的密钥操作，请稍候再试",
        ));
    }
    let _key_op_guard = KeyOpGuard { state: state.inner() };

    // 2. 服务端强制熔断闸门（与 verify 共享失败计数）
    match gate_check(&app, GateDomain::GlobalKey) {
        UnlockGate::Allowed => {}
        UnlockGate::Locked(secs) => {
            write_key_audit(
                &app,
                AuditEventType::KeyDerive,
                AuditResult::Denied,
                Some(format!("BRUTE_FORCE_LOCKOUT: 界面锁定 {} 秒（服务端强制）", secs)),
            );
            return Ok(VerthysResponse::err_code_retry(
                "change_global_key",
                E_RATE_LIMITED,
                &format!("尝试次数过多，已锁定 {} 秒，请稍后再试", secs),
                secs,
            ));
        }
        UnlockGate::RateLimited { retry_after_secs } => {
            write_key_audit(
                &app,
                AuditEventType::KeyDerive,
                AuditResult::Denied,
                Some(format!(
                    "RATE_LIMITED: 最小尝试间隔未满足（剩余 {} 秒）",
                    retry_after_secs
                )),
            );
            return Ok(VerthysResponse::err_code_retry(
                "change_global_key",
                E_RATE_LIMITED,
                &format!("请求过于频繁，请 {} 秒后再试", retry_after_secs),
                retry_after_secs,
            ));
        }
        UnlockGate::Unavailable => {
            write_key_audit(
                &app,
                AuditEventType::KeyDerive,
                AuditResult::Denied,
                Some("熔断守卫不可用，fail-closed 拒绝改钥".into()),
            );
            return Ok(VerthysResponse::err_code(
                "change_global_key",
                E_CNG_UNAVAILABLE,
                "安全门禁暂时不可用，请重启应用后重试",
            ));
        }
    }

    // 3. 生命周期：NoKey 无记录可改；Locked/Unlocked 均允许（重认证）
    match state.key_lifecycle.current_state() {
        KeyLifecycleState::Locked | KeyLifecycleState::Unlocked => {}
        KeyLifecycleState::NoKey => {
            write_key_audit(
                &app,
                AuditEventType::KeyDerive,
                AuditResult::Denied,
                Some("状态不匹配：当前 NoKey，无全局密钥记录".into()),
            );
            return Ok(VerthysResponse::err_code(
                "change_global_key",
                "E_GLOBAL_KEY_RECORD_NOT_FOUND",
                "全局密钥尚未初始化",
            ));
        }
    }

    // 4. 冷却检查（重认证/首次验证共用）
    if let crate::state::VerifyCheckResult::Cooldown(remaining) =
        state.key_lifecycle.check_verify_allowed()
    {
        return Ok(VerthysResponse::err_code_retry(
            "change_global_key",
            E_RATE_LIMITED,
            &format!("请 {} 秒后再试", remaining),
            remaining,
        ));
    }

    // 5. 输入校验（旧钥只校验长度；新钥必须满足复杂度）
    if old_password.is_empty() {
        return Ok(VerthysResponse::err(
            "change_global_key",
            "当前访问密钥不能为空",
        ));
    }
    if let Err(e) = validate_password_length(&old_password) {
        return Ok(VerthysResponse::err("change_global_key", &e));
    }
    if old_bin_password.is_empty() {
        return Ok(VerthysResponse::err("change_global_key", "当前密钥口令不能为空"));
    }
    if let Err(e) = validate_password_length(&old_bin_password) {
        return Ok(VerthysResponse::err("change_global_key", &e));
    }
    if let Err(e) = decode_and_validate_b64(&old_bin_data_b64) {
        return Ok(VerthysResponse::err("change_global_key", &e));
    }
    if let Err(e) = validate_password_complexity(&new_password) {
        return Ok(VerthysResponse::err("change_global_key", &e));
    }
    if new_bin_password.is_empty() {
        return Ok(VerthysResponse::err("change_global_key", "新密钥口令不能为空"));
    }
    if let Err(e) = validate_password_length(&new_bin_password) {
        return Ok(VerthysResponse::err("change_global_key", &e));
    }
    if let Err(e) = decode_and_validate_b64(&new_bin_data_b64) {
        return Ok(VerthysResponse::err("change_global_key", &e));
    }

    // 6. 序列化请求（借用字段；发送后统一擦除）
    let req_str = Zeroizing::new(
        serde_json::to_string(&ChangeGlobalKeyReq {
            op: "change_global_key",
            password: old_password.as_str(),
            bin_data: old_bin_data_b64.as_str(),
            bin_password: old_bin_password.as_str(),
            new_password: new_password.as_str(),
            new_bin_data: new_bin_data_b64.as_str(),
            new_bin_password: new_bin_password.as_str(),
        })
        .map_err(|e| {
            log::error!("[verthys_change_global_key] 请求序列化失败: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyDerive,
                AuditResult::Failure,
                Some("请求序列化失败".into()),
            );
            "修改密钥失败".to_string()
        })?,
    );

    // 7. 单次 worker 调用
    let resp_json = match state.send_with_timeout(req_str.as_str(), CHANGE_KEY_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            log::error!("[verthys_change_global_key] worker 通信失败/超时: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyDerive,
                AuditResult::Failure,
                Some(format!("worker 通信失败/超时: {}", e)),
            );
            drop(req_str);
            drop(new_bin_password);
            drop(new_bin_data_b64);
            drop(new_password);
            drop(old_bin_data_b64);
            drop(old_bin_password);
            drop(old_password);
            return Ok(VerthysResponse::err_code(
                "change_global_key",
                "E_GLOBAL_KEY_CHANGE_UNCONFIRMED",
                "修改结果未确认：请重启应用后以新密钥验证",
            ));
        }
    };

    // 发送完成：序列化副本与全部敏感原件统一销毁
    drop(req_str);
    drop(new_bin_password);
    drop(new_bin_data_b64);
    drop(new_password);
    drop(old_bin_data_b64);
    drop(old_bin_password);
    drop(old_password);

    let mut resp: VerthysResponse = serde_json::from_str(&resp_json).map_err(|e| {
        log::error!(
            "[verthys_change_global_key] 响应解析失败: {} | raw={}",
            e,
            crate::util::log_sanitizer::json_log_summary(&resp_json, &["op"])
        );
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Failure,
            Some(format!("响应解析失败: {}", e)),
        );
        "修改密钥失败".to_string()
    })?;
    resp.adopt_worker_error_code();

    if resp.ok {
        // 口令证明成功：重置熔断计数；状态幂等推进 Unlocked
        record_auth_success(&app);
        if let Err(e) = state.key_lifecycle.record_verify_success() {
            log::error!("[verthys_change_global_key] 状态推进失败: {}", e);
        }
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Success,
            Some(format!(
                "change_global_key;id={:?};deleted={};cleanup_pending={}",
                resp.id,
                resp.ids.as_ref().map(|v| v.len()).unwrap_or(0),
                resp.cleanup_pending.unwrap_or(false)
            )),
        );
        log::info!(
            "[verthys_change_global_key] 修改成功（lid={:?}，清理待完成={}）",
            resp.id,
            resp.cleanup_pending.unwrap_or(false)
        );
        return Ok(resp);
    }

    // 失败：仅认证域错误计数（落盘/索引错误不构成本地暴破证据）
    let error_code = resp.error.as_deref().unwrap_or("");
    if error_code == AUTH_DOMAIN_ERROR {
        record_auth_failure(&app);
        let _ = state.key_lifecycle.record_verify_failure();
        write_key_audit(
            &app,
            AuditEventType::KeyVerify,
            AuditResult::Failure,
            Some("旧全局密钥验证失败".into()),
        );
        return Ok(VerthysResponse::err_code(
            "change_global_key",
            "E_GLOBAL_KEY_VERIFY_FAILED",
            "旧密钥验证失败，请检查",
        ));
    }
    if error_code == "ERR_00000003" {
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Failure,
            Some("全局密钥记录不存在".into()),
        );
        return Ok(VerthysResponse::err_code(
            "change_global_key",
            "E_GLOBAL_KEY_RECORD_NOT_FOUND",
            "未找到全局密钥记录",
        ));
    }

    write_key_audit(
        &app,
        AuditEventType::KeyDerive,
        AuditResult::Failure,
        Some(format!("新记录落盘/读回失败: {}", error_code)),
    );
    Ok(VerthysResponse::err_code(
        "change_global_key",
        "E_GLOBAL_KEY_PERSIST_FAILED",
        "新密钥写入失败，旧密钥仍有效",
    ))
}
