/*
 * commands/brute_force.rs — 暴力拦截命令
 *
 *
 * 职责：
 *   暴力拦截 Tauri 命令实现：
 *     - security_brute_check：检查当前是否允许尝试解锁
 *     - security_brute_record_failure：记录一次解锁失败
 *     - security_generate_auth_token：生成一次性权限令牌（要求金库已解锁）
 *     - security_brute_record_success：记录一次解锁成功（需 auth_token）
 *     - security_brute_clear_purge：清除熔断状态（需 auth_token）
 *     - security_brute_status：获取暴力拦截状态快照
 */

use tauri::State;

use crate::security::brute_force::{AttemptResult, BruteForceCheck};
use crate::util::audit_log::{AuditEventType, AuditResult};

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::auth::{
    generate_auth_token, store_auth_token, verify_and_consume_auth_token,
};
use crate::security_commands::persistence::{ensure_brute_force_loaded, persist_brute_force_state};
use crate::security_commands::responses::{
    AuthTokenResult, BruteForceCheckResponse, BruteForceStatus, SecurityResult,
};
use crate::security_commands::state::{lock_brute_force_or_recover, SecurityState};

/* ====================================================================== *
 *  1. 暴力拦截命令             *
 * ====================================================================== */

/// 检查当前是否允许尝试解锁
#[tauri::command]
pub fn security_brute_check(
    app: tauri::AppHandle,
    state: State<SecurityState>,
) -> Result<BruteForceCheckResponse, String> {
    // 首次访问时从持久化加载状态
    ensure_brute_force_loaded(&app, &state);

    let guard = lock_brute_force_or_recover(&state)?;
    Ok(match guard.check() {
        BruteForceCheck::Allow => BruteForceCheckResponse::Allow,
        BruteForceCheck::Locked(secs) => BruteForceCheckResponse::Locked { remaining_secs: secs },
        BruteForceCheck::PurgeRequired => BruteForceCheckResponse::PurgeRequired,
    })
}

/// 记录一次解锁失败
/// 返回触发的动作：Failure / FailureLocked(秒数) / FailurePurgeRequired
#[tauri::command]
pub fn security_brute_record_failure(
    app: tauri::AppHandle,
    state: State<SecurityState>,
) -> Result<BruteForceCheckResponse, String> {
    // 首次访问时从持久化加载状态
    ensure_brute_force_loaded(&app, &state);

    let response = {
        let guard = lock_brute_force_or_recover(&state)?;
        let result = guard.record_failure();

        // 状态变更后持久化
        persist_brute_force_state(&app, &guard);

        // 审计日志
        let (audit_result, audit_detail) = match &result {
            AttemptResult::Failure => (AuditResult::Failure, None),
            AttemptResult::FailureLocked(secs) => (
                AuditResult::Failure,
                Some(format!("BRUTE_FORCE_LOCKOUT: 界面锁定 {} 秒", secs)),
            ),
            AttemptResult::FailurePurgeRequired => (
                AuditResult::Failure,
                Some("BRUTE_FORCE_PURGE: 触发索引清空 + 完整性校验".into()),
            ),
            AttemptResult::Success => (AuditResult::Success, None),
            // 速率限制
            AttemptResult::RateLimited => (
                AuditResult::Denied,
                Some("RATE_LIMITED: record_failure 调用速率超限".into()),
            ),
            // 锁定/Purge 期间冻结
            AttemptResult::Frozen(secs) => (
                AuditResult::Denied,
                Some(format!("FROZEN: 记录接口冻结 (剩余 {} 秒)", secs)),
            ),
        };

        let event_type = match &result {
            AttemptResult::FailureLocked(_) => AuditEventType::BruteForceLockout,
            AttemptResult::FailurePurgeRequired => AuditEventType::BruteForceLockout,
            _ => AuditEventType::SecurityCommand,
        };
        write_security_audit(&app, &state, event_type, audit_result, None, audit_detail);

        match result {
            AttemptResult::Success => BruteForceCheckResponse::Allow,
            AttemptResult::Failure => BruteForceCheckResponse::Allow,
            AttemptResult::FailureLocked(secs) => {
                BruteForceCheckResponse::Locked { remaining_secs: secs }
            }
            AttemptResult::FailurePurgeRequired => BruteForceCheckResponse::PurgeRequired,
            // 速率限制 — 返回当前状态
            AttemptResult::RateLimited => match guard.check() {
                BruteForceCheck::Allow => BruteForceCheckResponse::Allow,
                BruteForceCheck::Locked(s) => {
                    BruteForceCheckResponse::Locked { remaining_secs: s }
                }
                BruteForceCheck::PurgeRequired => BruteForceCheckResponse::PurgeRequired,
            },
            // 冻结 — secs>0 表示锁定中，secs=0 表示 PurgeRequired
            AttemptResult::Frozen(secs) => {
                if secs > 0 {
                    BruteForceCheckResponse::Locked { remaining_secs: secs }
                } else {
                    BruteForceCheckResponse::PurgeRequired
                }
            }
        }
    };

    Ok(response)
}

/// 生成一次性权限令牌
///
/// 前置条件：金库已解锁（KeyLifecycle 处于 Unlocked 状态）。
/// 令牌为一次性使用，验证后立即消费。
#[tauri::command]
pub fn security_generate_auth_token(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    app_state: State<'_, crate::state::AppState>,
) -> Result<AuthTokenResult, String> {
    // 检查金库是否已解锁
    let key_state = app_state.key_lifecycle.current_state();
    if key_state != crate::state::KeyLifecycleState::Unlocked {
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Denied,
            None,
            Some(format!(
                "PERMISSION_DENIED: 生成权限令牌要求金库已解锁，当前状态: {}",
                key_state.as_str()
            )),
        );
        return Ok(AuthTokenResult {
            ok: false,
            token: None,
            detail: "生成权限令牌要求金库已解锁".into(),
        });
    }

    let token = generate_auth_token();
    store_auth_token(&state, token.clone());

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        None,
        Some("生成权限令牌（一次性）".into()),
    );

    Ok(AuthTokenResult {
        ok: true,
        token: Some(token),
        detail: "权限令牌已生成".into(),
    })
}

/// 记录一次解锁成功（重置连续失败计数）
///
/// 要求：
///   1. 携带有效的 auth_token（一次性消费）
///   2. 金库处于 Unlocked 状态（防止前端无凭据调用重置计数）
#[tauri::command]
pub fn security_brute_record_success(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    app_state: State<'_, crate::state::AppState>,
    auth_token: Option<String>,
) -> Result<SecurityResult, String> {
    // 验证 auth_token（一次性消费）
    if !verify_and_consume_auth_token(&state, auth_token.as_deref()) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::BruteForceReset,
            AuditResult::Denied,
            None,
            Some("PERMISSION_DENIED: record_success 缺少有效 auth_token".into()),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "记录解锁成功需要有效授权令牌",
        ));
    }

    // 检查金库是否确实已解锁
    let key_state = app_state.key_lifecycle.current_state();
    if key_state != crate::state::KeyLifecycleState::Unlocked {
        write_security_audit(
            &app,
            &state,
            AuditEventType::BruteForceReset,
            AuditResult::Denied,
            None,
            Some(format!(
                "PERMISSION_DENIED: record_success 要求金库已解锁，当前: {}",
                key_state.as_str()
            )),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "金库未解锁，无法记录解锁成功",
        ));
    }

    // 首次访问时从持久化加载状态
    ensure_brute_force_loaded(&app, &state);

    {
        let guard = lock_brute_force_or_recover(&state)?;
        guard.record_success();
        // 状态变更后持久化
        persist_brute_force_state(&app, &guard);
    }

    write_security_audit(
        &app,
        &state,
        AuditEventType::BruteForceReset,
        AuditResult::Success,
        None,
        Some("解锁成功，失败计数已重置".into()),
    );

    Ok(SecurityResult::success("解锁成功，失败计数已重置"))
}

/// 清除熔断状态（PurgeRequired 处理完成后调用）
///
/// 要求：携带有效的 auth_token（一次性消费）
#[tauri::command]
pub fn security_brute_clear_purge(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    auth_token: Option<String>,
) -> Result<SecurityResult, String> {
    // 验证 auth_token
    if !verify_and_consume_auth_token(&state, auth_token.as_deref()) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Denied,
            None,
            Some("PERMISSION_DENIED: clear_purge 缺少有效 auth_token".into()),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "清除熔断状态需要有效授权令牌",
        ));
    }

    {
        let guard = lock_brute_force_or_recover(&state)?;
        guard.clear_purge();
        persist_brute_force_state(&app, &guard);
    }

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        None,
        Some("熔断状态已清除".into()),
    );

    Ok(SecurityResult::success("熔断状态已清除"))
}

/// 获取暴力拦截状态快照
#[tauri::command]
pub fn security_brute_status(
    app: tauri::AppHandle,
    state: State<SecurityState>,
) -> Result<BruteForceStatus, String> {
    // 首次访问时从持久化加载状态
    ensure_brute_force_loaded(&app, &state);

    let guard = lock_brute_force_or_recover(&state)?;
    let check = guard.check();
    Ok(BruteForceStatus {
        consecutive_failures: guard.consecutive_failures(),
        total_failures: guard.total_failures(),
        remaining_lock_secs: guard.remaining_lock_secs(),
        purge_required: matches!(check, BruteForceCheck::PurgeRequired),
    })
}
