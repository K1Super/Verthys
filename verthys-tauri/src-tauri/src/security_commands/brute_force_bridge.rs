/*
 * security_commands/brute_force_bridge.rs — 口令类命令的服务端暴力熔断桥接
 *
 *
 * 职责：
 *   为口令进入 FFI 的服务端命令（verthys_unlock / verthys_verify_global_key）
 *   提供强制暴力熔断接入点，由服务端权威计数：前端不再承担失败计数
 *   职责，仅查询展示锁定态。
 *
 *   - gate_check：入口闸门。锁定/清空状态下，口令不进入任何
 *     业务逻辑（不触 FFI、不触文件锁）。
 *   - record_auth_failure：认证域失败计数 + 持久化 + 审计。
 *   - record_auth_success：成功重置连续失败计数 + 持久化 + 审计。
 *
 * 语义约定：
 *   - 计数与 DPAPI 持久化、审计行为与 security_brute_record_failure /
 *     security_brute_record_success 命令完全一致（同一守卫、同一持久化层），
 *     区别仅在调用方为服务端自身，无需会话授权检查。
 *   - 桥接层不做二次决策：record_failure 的 RateLimited/Frozen 语义
 *     由守卫内部消化，仅透传审计。
 */

use tauri::AppHandle;

use crate::security::brute_force::{AttemptResult, BruteForceCheck};
use crate::util::audit_log::{AuditEventType, AuditResult};

use super::audit::write_security_audit;
use super::persistence::{ensure_brute_force_loaded, persist_brute_force_state};
use super::state::{lock_brute_force_or_recover, SecurityState};

/// worker 错误码统一化后的认证域错误标识（口令错误/认证数据损坏）。
/// 仅此错误码构成暴破证据并计数；通信层失败、格式错误与功能性
/// 状态码不计数，防止非口令因素被误判为暴破。
pub(crate) const AUTH_DOMAIN_ERROR: &str = "ERR_00000002";

/// 口令类命令入口的熔断判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnlockGate {
    /// 允许发起本次尝试
    Allowed,
    /// 熔断锁定中，携带剩余秒数
    Locked(u64),
    /// 失败次数已达清空阈值，要求先执行索引清空与完整性校验
    PurgeRequired,
    /// 守卫状态不可用（锁中毒等内部异常）。
    /// 安全语义为 fail-closed：无法确认熔断状态时拒绝放行。
    Unavailable,
}

/// 口令类命令入口熔断检查（在口令进入任何业务逻辑之前调用）。
pub(crate) fn gate_check(app: &AppHandle, state: &SecurityState) -> UnlockGate {
    ensure_brute_force_loaded(app, state);

    let guard = match lock_brute_force_or_recover(state) {
        Ok(g) => g,
        Err(e) => {
            log::error!("[unlock_gate] 获取熔断守卫失败（fail-closed）: {}", e);
            return UnlockGate::Unavailable;
        }
    };

    match guard.check() {
        BruteForceCheck::Allow => UnlockGate::Allowed,
        BruteForceCheck::Locked(secs) => UnlockGate::Locked(secs),
        BruteForceCheck::PurgeRequired => UnlockGate::PurgeRequired,
    }
}

/// 记录一次服务端观察到的认证域失败（口令错误等）。
///
/// 审计事件类型随触发结果变化：达到锁定/清空阈值时记为
/// BruteForceLockout，普通失败记为 SecurityCommand。
pub(crate) fn record_auth_failure(app: &AppHandle, state: &SecurityState) {
    ensure_brute_force_loaded(app, state);

    let guard = match lock_brute_force_or_recover(state) {
        Ok(g) => g,
        Err(e) => {
            log::error!("[unlock_gate] 失败计数跳过（获取熔断守卫失败）: {}", e);
            return;
        }
    };

    let result = guard.record_failure();
    persist_brute_force_state(app, &guard);

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
        AttemptResult::RateLimited => (
            AuditResult::Denied,
            Some("RATE_LIMITED: unlock 失败计数速率超限".into()),
        ),
        AttemptResult::Frozen(secs) => (
            AuditResult::Denied,
            Some(format!("FROZEN: unlock 计数接口冻结 (剩余 {} 秒)", secs)),
        ),
    };

    let event_type = match &result {
        AttemptResult::FailureLocked(_) | AttemptResult::FailurePurgeRequired => {
            AuditEventType::BruteForceLockout
        }
        _ => AuditEventType::SecurityCommand,
    };
    write_security_audit(
        app,
        state,
        event_type,
        audit_result,
        None,
        audit_detail,
    );
}

/// 记录一次服务端观察到的口令验证成功：重置连续失败计数。
///
/// 调用前提：响应 ok=true（服务端已在响应中确认成功，
/// 无需会话授权检查——与前端命令版的授权要求不同）。
pub(crate) fn record_auth_success(app: &AppHandle, state: &SecurityState) {
    ensure_brute_force_loaded(app, state);

    let guard = match lock_brute_force_or_recover(state) {
        Ok(g) => g,
        Err(e) => {
            log::error!("[unlock_gate] 成功重置跳过（获取熔断守卫失败）: {}", e);
            return;
        }
    };

    guard.record_success();
    persist_brute_force_state(app, &guard);

    write_security_audit(
        app,
        state,
        AuditEventType::BruteForceReset,
        AuditResult::Success,
        None,
        Some("解锁成功，失败计数已重置（服务端强制）".into()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::brute_force::{BruteForceConfig, BruteForceGuard};

    /// 守卫核心语义回归：连续失败达到阈值后 check 进入锁定，成功后重置。
    /// 桥接层与命令层共享同一守卫实现，此处验证锁定阈值与重置语义的
    /// 契约（具体阈值以 BruteForceGuard 内部配置为准）。
    #[test]
    fn 连续失败后锁定_成功后重置() {
        // 禁用速率限制（紧密循环下限流会吞掉计数），速率限制语义
        // 由 security::brute_force::tests::test_rate_limiting 独立覆盖。
        let guard = BruteForceGuard::with_config(BruteForceConfig {
            rate_limit_ms: 0,
            ..BruteForceConfig::default()
        });

        // 连续失败直至触发锁定或清空（达到任一熔断态即停）
        let mut locked = false;
        for _ in 0..64 {
            let r = guard.record_failure();
            if matches!(
                r,
                AttemptResult::FailureLocked(_) | AttemptResult::FailurePurgeRequired
            ) {
                locked = true;
                break;
            }
        }
        assert!(
            locked,
            "连续失败 64 次后必须进入锁定或清空熔断态，实际 check={:?}",
            guard.check()
        );
        assert!(
            !matches!(guard.check(), BruteForceCheck::Allow),
            "熔断态下 check 不得为 Allow"
        );

        // 成功重置：恢复 Allow
        guard.record_success();
        assert!(matches!(guard.check(), BruteForceCheck::Allow));
    }
}
