/*
 * commands/kernel_guard.rs — 内核防护降级审计命令
 *
 * 职责：
 *   SECURE 预设采用 preferred 策略时，内核保护未 ACTIVE 属于安全事实，
 *   由观测侧（前端）触发一次降级审计写入（KERNEL_GUARD_DEGRADED）。
 *
 * 边界：
 *   - 只记录观测事实，不改变内核状态、不触发驱动或服务操作；
 *   - 状态/原因码按协议值域校验，超界拒绝，防止前端口径漂移污染审计链；
 *   - 不要求会话授权：降级可能发生在会话锁定期间，授权门禁会让
 *     安全事实无法留痕；命令无副作用，不属于敏感操作。
 */

use tauri::State;

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::state::SecurityState;
use crate::util::audit_log::{AuditEventType, AuditResult};

/// 与 VtyKernelState 对齐的值域上界（0=未知 … 10=不支持）
const KERNEL_STATE_MAX: u32 = 10;

/// 与 VtyKernelReason 对齐的值域上界（0=无附加原因 … 11=坏响应）
const KERNEL_REASON_MAX: u32 = 11;

/// 校验状态/原因码值域（超界返回 Err，不做静默截断）
fn validate_kernel_codes(kernel_state: u32, kernel_reason: u32) -> Result<(), String> {
    if kernel_state > KERNEL_STATE_MAX {
        return Err(format!(
            "E_INVALID_ARG: kernel_state 超出值域: {}（上限 {}）",
            kernel_state, KERNEL_STATE_MAX
        ));
    }
    if kernel_reason > KERNEL_REASON_MAX {
        return Err(format!(
            "E_INVALID_ARG: kernel_reason 超出值域: {}（上限 {}）",
            kernel_reason, KERNEL_REASON_MAX
        ));
    }
    Ok(())
}

/// 记录内核防护降级审计事件（SECURE preferred 下的用户态降级事实）
#[tauri::command]
pub fn verthys_audit_kernel_degraded(
    app: tauri::AppHandle,
    state: State<'_, SecurityState>,
    kernel_state: u32,
    kernel_reason: u32,
) -> Result<(), String> {
    validate_kernel_codes(kernel_state, kernel_reason)?;
    write_security_audit(
        &app,
        &state,
        AuditEventType::KernelGuardDegraded,
        AuditResult::Failure,
        None,
        Some(format!(
            "kernel_state={} kernel_reason={}",
            kernel_state, kernel_reason
        )),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_known_state_reason_pairs() {
        assert!(validate_kernel_codes(0, 0).is_ok());
        assert!(validate_kernel_codes(3, 0).is_ok());
        assert!(validate_kernel_codes(10, 11).is_ok());
    }

    #[test]
    fn rejects_out_of_range_values() {
        assert!(validate_kernel_codes(11, 0).is_err());
        assert!(validate_kernel_codes(0, 12).is_err());
        assert!(validate_kernel_codes(u32::MAX, u32::MAX).is_err());
    }
}
