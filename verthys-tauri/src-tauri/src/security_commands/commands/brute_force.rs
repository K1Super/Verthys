/*
 * commands/brute_force.rs — 暴力拦截命令
 *
 *
 * 职责：
 *   暴力拦截 Tauri 命令实现：
 *     - security_brute_check：检查当前是否允许尝试解锁
 *     - security_brute_clear_purge：清除熔断状态（需金库已解锁）
 *     - security_brute_status：获取暴力拦截状态快照
 */

use tauri::State;

use crate::security::brute_force::BruteForceCheck;
use crate::util::audit_log::{AuditEventType, AuditResult};

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::persistence::{ensure_brute_force_loaded, persist_brute_force_state};
use crate::security_commands::responses::{
    BruteForceCheckResponse, BruteForceStatus, SecurityResult,
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
        BruteForceCheck::Locked(secs) => BruteForceCheckResponse::Locked {
            remaining_secs: secs,
        },
        BruteForceCheck::PurgeRequired => BruteForceCheckResponse::PurgeRequired,
    })
}

/// 清除熔断状态（PurgeRequired 处理完成后调用）
///
/// 授权：金库必须处于 Unlocked 状态。清除熔断会重置连续失败计数，
/// 若未经验证即可清除，攻击者可反复触发熔断后立即清除以绕过退避。
/// 未验证场景的安全清理流程需另行提供凭证证明，不在本命令放行。
#[tauri::command]
pub fn security_brute_clear_purge(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    app_state: State<'_, crate::state::AppState>,
) -> Result<SecurityResult, String> {
    // 授权检查：仅完成主密码验证的会话可清除熔断
    let key_state = app_state.key_lifecycle.current_state();
    if key_state != crate::state::KeyLifecycleState::Unlocked {
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Denied,
            None,
            Some(format!(
                "PERMISSION_DENIED: clear_purge 要求金库已解锁，当前: {}",
                key_state.as_str()
            )),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "清除熔断状态需要已解锁的会话",
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
