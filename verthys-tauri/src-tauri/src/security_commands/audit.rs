/*
 * audit.rs — 安全命令审计日志辅助
 *
 * 职责：把安全命令执行结果接入统一审计落盘。HMAC 密钥派生与扩展块写入
 * 由 infrastructure::audit 统一提供，避免多处重复派生与口径漂移。
 */

use crate::infrastructure::audit::write_audit_with_extensions;
use crate::util::audit_log::{AuditEventType, AuditExtensions, AuditResult};

use super::state::SecurityState;

/// 写入安全命令审计事件
pub(crate) fn write_security_audit(
    app: &tauri::AppHandle,
    state: &SecurityState,
    event_type: AuditEventType,
    result: AuditResult,
    resource: Option<&str>,
    detail: Option<String>,
) {
    write_audit_with_extensions(
        app,
        state.session_id(),
        event_type,
        result,
        resource,
        detail,
        AuditExtensions::default(),
    );
}
