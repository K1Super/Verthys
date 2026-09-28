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

use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditExtensions, AuditResult};

use super::state::SecurityState;

/* ====================================================================== *
 *  审计日志辅助                                             *
 * ====================================================================== */

/// 获取审计日志文件路径
fn get_audit_log_path(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join("audit.log")),
        Err(e) => {
            log::warn!("[security_audit] 获取配置目录失败: {}", e);
            None
        }
    }
}

/// 审计 HMAC 密钥进程级缓存
///
/// 派生成本为设备指纹采集 + PBKDF2 十万次迭代（调试构建可达数百毫秒）。
/// 密钥材料（设备指纹、固定盐）在进程生命周期内不变，因此只在首次成功时
/// 派生一次；每次审计重派生会让用户操作（如防截屏开关）产生可感的秒级延迟。
/// 仅缓存成功结果：采集/派生瞬时失败不占用缓存，下次写入仍可自愈重试。
static AUDIT_HMAC_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// 获取审计日志 HMAC 密钥（设备指纹派生，进程内派生一次后复用）
fn get_audit_hmac_key() -> Option<[u8; 32]> {
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

/// 写入安全命令审计事件
pub(super) fn write_security_audit(
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

/// 写入审计事件（含结构化扩展块）
///
/// 扩展块只承载非敏感结构化信息；为空时不写入该字段，历史记录的序列化
/// 字节序与链式验签因此完全不受影响。
/// 不依赖 SecurityState：便于不持有安全状态的命令层复用同一落盘路径。
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
        log::warn!("[security_audit] 写入审计事件失败（不阻塞业务）: {}", e);
    }
}
