/*
 * 文件操作审计
 *
 * 职责边界：文件读写与导出事件的审计写入。路径只落域分离哈希，不写明文；
 * 审计失败仅告警，不阻塞业务。
 */

use crate::infrastructure::audit::get_audit_hmac_key;
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};
use std::path::PathBuf;
use tauri::Manager;

// ===== 审计日志辅助 =====

pub(super) fn get_audit_log_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join("audit.log")),
        Err(e) => {
            log::warn!("[audit] 获取配置目录失败，跳过审计写入: {}", e);
            None
        }
    }
}

/// 记录文件操作审计事件。
///
/// 审计条目包含操作类型、路径哈希、结果和文件大小（若成功），
/// 不记录文件内容或明文路径。
pub(super) fn write_file_audit(
    app: &tauri::AppHandle,
    event_type: AuditEventType,
    path: &str,
    result: AuditResult,
    size: Option<u64>,
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

    let mut event = AuditEvent::new(event_type, &session_id, "user", result).with_resource(path);

    let mut detail_parts = Vec::new();
    if let Some(s) = size {
        detail_parts.push(format!("size={}B", s));
    }
    if let Some(d) = detail {
        detail_parts.push(d);
    }
    if !detail_parts.is_empty() {
        event = event.with_detail(detail_parts.join(" | "));
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[audit] 写入文件审计事件失败（不阻塞业务）: {}", e);
    }
}
