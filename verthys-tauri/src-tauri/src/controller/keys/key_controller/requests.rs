/*
 * 借用式请求体与派生前置检查
 *
 * 职责边界：派生/验证请求体结构定义，以及派生类命令的公共前置检查
 * （熔断闸门、生命周期状态、输入校验、worker 请求序列化）。
 * 不含 worker 通信与响应处理。
 */

use super::validation::{
    decode_and_validate_b64, validate_password_complexity, validate_password_length,
    write_key_audit,
};
use crate::controller::api_error::ErrorCode;
use crate::state::{AppState, KeyLifecycleState};
use crate::util::audit_log::{AuditEventType, AuditResult};
use zeroize::Zeroizing;

// ===== 借用式请求构造 =====

/// derive_global_key 请求体（借用序列化）
///
/// 敏感字段全部以 &str 借用传入：serde 直接把引用序列化进输出字符串，
/// 全程不产生 serde_json::Value 的 owned 明文拷贝；序列化结果立即
/// 进入 Zeroizing 容器，随各敏感原件在发送后统一擦除。
#[derive(serde::Serialize)]
pub(super) struct DeriveGlobalKeyReq<'a> {
    pub(super) op: &'static str,
    pub(super) password: &'a str,
    pub(super) bin_data: &'a str,
    pub(super) bin_password: &'a str,
}

/// verify_global_key 请求体（借用序列化，策略同 DeriveGlobalKeyReq）
#[derive(serde::Serialize)]
pub(super) struct VerifyGlobalKeyReq<'a> {
    pub(super) op: &'static str,
    pub(super) password: &'a str,
    pub(super) bin_data: &'a str,
    pub(super) bin_password: &'a str,
    pub(super) data: &'a str,
}

/// 派生类命令公共前置检查的输入上下文（聚合参数，避免长参数表）
pub(super) struct DerivePrecheckCtx<'a> {
    pub(super) app: &'a tauri::AppHandle,
    pub(super) state: &'a AppState,
    pub(super) op: &'static str,
    pub(super) allowed_states: &'a [KeyLifecycleState],
    pub(super) password: &'a Zeroizing<String>,
    pub(super) bin_data_b64: &'a str,
    pub(super) bin_password: &'a str,
}

/// 派生类命令公共前置检查：熔断闸门（fail-closed）+ 生命周期状态
/// 检查 + 输入校验 + worker 请求序列化。
///
/// 返回序列化完成的请求（Zeroizing）；Err 为拒绝文案（审计已写入）。
/// 安全纪律：bin_data/bin_password 的序列化只借用不拷贝，请求字符串
/// 与命令侧 Zeroizing 原件统一在发送完成后擦除；bin_password 按纯文
/// 本密码校验（非 base64——参与 PBKDF2 的是密码原始字节）。
pub(super) fn precheck_derive_request(
    ctx: DerivePrecheckCtx<'_>,
) -> Result<Zeroizing<String>, String> {
    let DerivePrecheckCtx {
        app,
        state,
        op,
        allowed_states,
        password,
        bin_data_b64,
        bin_password,
    } = ctx;
    // 1. 服务端强制熔断闸门：锁定/过频状态下拒绝一切口令类操作。
    //    派生失败本身不计数——NoKey 态是首次设置新秘密，无既有秘密可暴破。
    //    经 service 层契约调用（实现由 security_commands 启动时注册）。
    use crate::service::unlock_gate::{gate_check, GateDomain, UnlockGate};
    match gate_check(app, GateDomain::Derive) {
        UnlockGate::Allowed => {}
        UnlockGate::Locked(secs) => {
            write_key_audit(
                app,
                AuditEventType::KeyDerive,
                AuditResult::Denied,
                Some(format!(
                    "BRUTE_FORCE_LOCKOUT: 界面锁定 {} 秒（服务端强制）",
                    secs
                )),
            );
            return Err(format!("尝试次数过多，已锁定 {} 秒，请稍后再试", secs));
        }
        UnlockGate::RateLimited { retry_after_secs } => {
            write_key_audit(
                app,
                AuditEventType::KeyDerive,
                AuditResult::Denied,
                Some(format!(
                    "RATE_LIMITED: 最小尝试间隔未满足（剩余 {} 秒）",
                    retry_after_secs
                )),
            );
            return Err(format!("请求过于频繁，请 {} 秒后再试", retry_after_secs));
        }
        UnlockGate::Unavailable => {
            write_key_audit(
                app,
                AuditEventType::KeyDerive,
                AuditResult::Denied,
                Some("熔断守卫不可用，fail-closed 拒绝派生".into()),
            );
            return Err("安全模块暂时不可用，请重启应用后重试".to_string());
        }
    }

    // 2. 生命周期状态检查
    let current = state.key_lifecycle.current_state();
    if !allowed_states.contains(&current) {
        log::warn!("[{}] 状态不匹配：当前 {}", op, current);
        write_key_audit(
            app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(format!("状态不匹配：当前 {}", current)),
        );
        return Err(ErrorCode::KeyStateMismatch.default_message().to_string());
    }

    // 3. 输入校验
    if let Err(e) = validate_password_length(password) {
        write_key_audit(
            app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Err(e);
    }
    if let Err(e) = validate_password_complexity(password) {
        write_key_audit(
            app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Err(e);
    }
    if let Err(e) = decode_and_validate_b64(bin_data_b64) {
        write_key_audit(
            app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Err(e);
    }
    if bin_password.is_empty() {
        write_key_audit(
            app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some("密钥文件密码不能为空".into()),
        );
        return Err("密钥文件密码不能为空".to_string());
    }
    if let Err(e) = validate_password_length(bin_password) {
        write_key_audit(
            app,
            AuditEventType::KeyDerive,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Err(e);
    }

    // 4. 请求序列化
    Ok(Zeroizing::new(
        serde_json::to_string(&DeriveGlobalKeyReq {
            op,
            password,
            bin_data: bin_data_b64,
            bin_password,
        })
        .map_err(|e| {
            log::error!("[{}] 请求序列化失败: {}", op, e);
            write_key_audit(
                app,
                AuditEventType::KeyDerive,
                AuditResult::Failure,
                Some(format!("请求序列化失败: {}", e)),
            );
            "派生密钥失败".to_string()
        })?,
    ))
}
