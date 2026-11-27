/*
 * infrastructure/audit.rs — 审计日志落盘与 HMAC 密钥单例
 *
 * 审计密钥由设备指纹经 PBKDF2 派生（十万次迭代）。派生成本高且材料在
 * 进程生命周期内不变，必须全进程共享同一缓存；分散在各业务模块会造成
 * 重复派生与审计口径漂移。
 */

use tauri::Manager;

use crate::util::audit_log::{
    append_audit, AuditEvent, AuditEventType, AuditExtensions, AuditResult,
};

/// 审计日志文件路径（应用配置目录下的 audit.log）
pub(crate) fn get_audit_log_path(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join("audit.log")),
        Err(e) => {
            log::warn!("[audit] 获取配置目录失败: {}", e);
            None
        }
    }
}

/// 审计 HMAC 密钥进程级缓存。
///
/// 仅缓存成功结果：设备指纹采集或派生瞬时失败不占用缓存，下次调用仍可
/// 自愈重试。
static AUDIT_HMAC_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// 获取审计日志 HMAC 密钥（设备指纹派生，进程内派生一次后复用）。
pub(crate) fn get_audit_hmac_key() -> Option<[u8; 32]> {
    use crate::infrastructure::device_fingerprint::get_device_fingerprint;
    use crate::util::crypto::pbkdf2_derive_default;

    if let Some(key) = AUDIT_HMAC_KEY.get() {
        return Some(*key);
    }

    match get_device_fingerprint() {
        Ok(fingerprint) => {
            const AUDIT_SALT: &[u8] = b"verthys_audit_log_hmac_salt_v1";
            match pbkdf2_derive_default(fingerprint.as_bytes(), AUDIT_SALT) {
                Ok(key) => {
                    let _ = AUDIT_HMAC_KEY.set(key);
                    Some(key)
                }
                Err(e) => {
                    log::warn!("[audit] 派生 HMAC 密钥失败: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            log::warn!("[audit] 获取设备指纹失败: {}", e);
            None
        }
    }
}

/// 仅测试使用：确认成功派生的密钥已进入进程级缓存。
#[cfg(test)]
pub(crate) fn audit_hmac_key_is_cached() -> bool {
    AUDIT_HMAC_KEY.get().is_some()
}

/// 写入审计事件（含结构化扩展块）。
///
/// 扩展块只承载非敏感结构化信息；为空时不写入该字段，历史记录的序列化
/// 字节序与链式验签因此完全不受影响。
pub(crate) fn write_audit_with_extensions(
    app: &tauri::AppHandle,
    session_id: &str,
    event_type: AuditEventType,
    result: AuditResult,
    resource: Option<&str>,
    detail: Option<String>,
    extensions: AuditExtensions,
) {
    let log_path = match get_audit_log_path(app) {
        Some(p) => p,
        None => return,
    };

    let hmac_key = match get_audit_hmac_key() {
        Some(k) => k,
        None => return,
    };

    let mut event = AuditEvent::new(event_type, session_id, "user", result);

    if let Some(r) = resource {
        event = event.with_resource(r);
    }
    if let Some(d) = detail {
        event = event.with_detail(d);
    }
    if !extensions.is_empty() {
        event = event.with_extensions(extensions);
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[audit] 写入审计事件失败（不阻塞业务）: {}", e);
    }
}
