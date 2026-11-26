/*
 * 密钥输入校验与审计写入
 *
 * 职责边界：口令与 Base64 输入硬校验、密钥操作审计事件落盘。
 * 不含生命周期状态判断与 worker 通信。
 */

use crate::infrastructure::audit::get_audit_hmac_key;
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};
use crate::util::base64::base64_decode;

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

pub(crate) fn write_key_audit(
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
pub(crate) const PASSWORD_MAX_BYTES: usize = 512;

/// Base64 解码后数据上限（4KB），防止 DoS。
pub(crate) const BASE64_DECODED_MAX_BYTES: usize = 4 * 1024;

pub(crate) fn validate_password_length(password: &str) -> Result<(), String> {
    let len = password.len();
    if len > PASSWORD_MAX_BYTES {
        return Err(format!("密码过长（超过 {} 字节）", PASSWORD_MAX_BYTES));
    }
    Ok(())
}

pub(crate) fn validate_password_complexity(password: &str) -> Result<(), String> {
    let len = password.len();
    if len < 8 {
        return Err("密码长度不足（至少 8 位）".into());
    }
    if len > PASSWORD_MAX_BYTES {
        return Err("密码过长".into());
    }
    Ok(())
}

pub(crate) fn decode_and_validate_b64(b64: &str) -> Result<Vec<u8>, String> {
    let bytes = base64_decode(b64).map_err(|e| format!("Base64 解码失败: {}", e))?;
    if bytes.len() > BASE64_DECODED_MAX_BYTES {
        return Err(format!(
            "Base64 数据过大（解码后超过 {} 字节）",
            BASE64_DECODED_MAX_BYTES
        ));
    }
    Ok(bytes)
}
