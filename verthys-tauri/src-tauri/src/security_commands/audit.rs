/*
 * audit.rs — 安全命令审计日志辅助
 *
 *
 * 职责：
 *   统一结构化审计日志：每个安全命令执行时记录审计事件。
 *   - get_audit_log_path：审计日志文件路径（app_config_dir/audit.log）
 *   - get_audit_hmac_key：审计日志 HMAC 密钥（设备指纹派生）
 *   - write_security_audit：写入安全命令审计事件（不阻塞业务）
 */

use tauri::Manager;

use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};

use super::state::SecurityState;

/* ====================================================================== *
 *  第 13.2.7 项：审计日志辅助                                             *
 * ====================================================================== */

/// 第 13.2.7 项：获取审计日志文件路径
fn get_audit_log_path(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join("audit.log")),
        Err(e) => {
            log::warn!("[security_audit] 获取配置目录失败: {}", e);
            None
        }
    }
}

/// 第 13.2.7 项：获取审计日志 HMAC 密钥（设备指纹派生）
fn get_audit_hmac_key() -> Option<[u8; 32]> {
    use crate::infrastructure::device_fingerprint::get_device_fingerprint;
    use crate::util::crypto::pbkdf2_derive_default;

    match get_device_fingerprint() {
        Ok(fingerprint) => {
            const AUDIT_SALT: &[u8] = b"verthys_audit_log_hmac_salt_v1";
            match pbkdf2_derive_default(fingerprint.as_bytes(), AUDIT_SALT) {
                Ok(key) => Some(key),
                Err(e) => {
                    log::warn!("[security_audit] 派生 HMAC 密钥失败: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            log::warn!("[security_audit] 获取设备指纹失败: {}", e);
            None
        }
    }
}

/// 第 13.2.7 项：写入安全命令审计事件
pub(super) fn write_security_audit(
    app: &tauri::AppHandle,
    state: &SecurityState,
    event_type: AuditEventType,
    result: AuditResult,
    resource: Option<&str>,
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

    let mut event = AuditEvent::new(event_type, state.session_id(), "user", result);

    if let Some(r) = resource {
        event = event.with_resource(r);
    }
    if let Some(d) = detail {
        event = event.with_detail(d);
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[security_audit] 写入审计事件失败（不阻塞业务）: {}", e);
    }
}
