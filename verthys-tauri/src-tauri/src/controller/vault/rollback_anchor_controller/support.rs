/*
 * 回退锚点共享辅助
 *
 * 职责边界：扫描取消标志、会话标识、UUID 规范化与容器头识别、审计写入
 * 以及 worker 转发。审计只记录 UUID 哈希与计数，不记录路径。
 */

use std::fs::{self};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};


use crate::controller::types::VerthysResponse;
use crate::infrastructure::audit::write_audit_with_extensions;
use crate::state::AppState;
use crate::util::audit_log::{AuditEventType, AuditExtensions, AuditResult};

use super::*;
pub(super) fn scan_cancelled() -> bool {
    SCAN_CANCEL.load(Ordering::SeqCst)
}

pub(super) fn session_id() -> String {
    format!("pid-{}", std::process::id())
}

pub(super) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(super) fn audit_anchor(
    app: &tauri::AppHandle,
    event: AuditEventType,
    result: AuditResult,
    resource: Option<&str>,
    detail: Option<String>,
) {
    write_audit_with_extensions(
        app,
        &session_id(),
        event,
        result,
        resource,
        detail,
        AuditExtensions::default(),
    );
}

pub(super) fn forward(state: &AppState, req: &serde_json::Value) -> Result<VerthysResponse, String> {
    let line = req.to_string();
    let resp_json = state.send_with_timeout(&line, ANCHOR_OP_TIMEOUT)?;
    let mut resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    resp.adopt_worker_error_code();
    Ok(resp)
}

pub(super) fn is_uuid_hex(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 读取容器固定头并提取 UUID；任何字段不合法返回 None。
///
/// 只依赖 76 字节固定头：magic、主版本、header_len 与 UUID 偏移 12。
/// 不校验尾哈希/槽区，因为扫描阶段不打开容器、也不需要证明其可解锁。
pub(crate) fn header_uuid(header: &[u8; CONTAINER_HEADER_BYTES]) -> Option<[u8; 16]> {
    if header[0..4] != CONTAINER_MAGIC {
        return None;
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != CONTAINER_VERSION_MAJOR {
        return None;
    }
    let header_len = u16::from_le_bytes([header[8], header[9]]);
    if header_len < CONTAINER_HEADER_BYTES as u16 {
        return None;
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&header[12..28]);
    Some(uuid)
}

pub(super) fn uuid_hex(uuid: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in uuid {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

pub(super) fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

pub(super) fn is_container_candidate(path: &Path) -> bool {
    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(e) => e.to_ascii_lowercase(),
        None => return false,
    };
    ext == "vty" || ext == "verthys"
}

/// 统一展示为 Windows 原生分隔符；状态指针使用正斜杠，扫描证据使用反斜杠，
/// 不统一会让覆盖范围与证据列出现两种写法。
pub(super) fn native_path(path: &str) -> String {
    let trimmed = path.trim();
    if cfg!(windows) {
        trimmed.replace('/', "\\")
    } else {
        trimmed.to_string()
    }
}
