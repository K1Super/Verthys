/*
 * 用户授权文件元数据
 *
 * 职责边界：读取用户授权文件的长度与修改时间，供分块规划与来源身份校验。
 * 与读取命令共用路径校验链，保证"能 stat 的文件与能读的文件"范围一致。
 */

use super::super::audit::write_file_audit;
use super::super::USER_FILE_CHUNK_OP_TIMEOUT;
use super::path_guard::is_system_critical_path;
use crate::controller::api_error::ErrorCode;
use crate::util::audit_log::{AuditEventType, AuditResult};
use crate::util::path::sanitize_path;

/// 用户授权文件的元数据快照（分块规划与来源身份校验的输入）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserFileStat {
    /// 文件长度（字节）
    pub size: u64,
    /// 最后修改时间（Unix 纪元毫秒）
    pub mtime_ms: u64,
}

/// 同步读取用户授权文件的元数据（跳过白名单，拒绝系统关键目录）。
///
/// 与读取命令共用同一校验链（字符级校验 + canonicalize + 系统关键目录拒绝），
/// 保证"能 stat 的文件与能读的文件"范围一致。
///
/// 修改时间不可得即报错而非回退默认值：身份校验以 `(size, mtime_ms)`
/// 为依据，缺失该字段会让"源文件被替换"不可检测。
pub(in super::super) fn user_file_stat_blocking(path: &str) -> Result<UserFileStat, String> {
    use std::time::UNIX_EPOCH;

    crate::util::path::validate_path_input(path).map_err(|e| {
        log::warn!(
            "[user_file_stat] 路径校验失败: {} | {}",
            sanitize_path(path),
            e
        );
        ErrorCode::InvalidPath.default_message().to_string()
    })?;

    let canonical = std::fs::canonicalize(path).map_err(|e| {
        log::warn!(
            "[user_file_stat] 路径解析失败: {} | {}",
            sanitize_path(path),
            e
        );
        ErrorCode::InvalidPath.default_message().to_string()
    })?;

    if is_system_critical_path(&canonical) {
        log::warn!(
            "[user_file_stat] 拒绝读取系统关键目录: {}",
            sanitize_path(path)
        );
        return Err(ErrorCode::PermissionDenied.default_message().to_string());
    }

    let metadata = std::fs::metadata(&canonical).map_err(|e| {
        log::warn!("[user_file_stat] 获取文件元数据失败: {}", e);
        ErrorCode::InvalidPath.default_message().to_string()
    })?;
    let mtime_ms = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .ok_or_else(|| {
            log::warn!("[user_file_stat] 无法获取修改时间: {}", sanitize_path(path));
            "无法获取文件修改时间".to_string()
        })?;

    log::info!(
        "[user_file_stat] 元数据读取成功: size={} mtime_ms={} | {}",
        metadata.len(),
        mtime_ms,
        sanitize_path(path)
    );
    Ok(UserFileStat {
        size: metadata.len(),
        mtime_ms,
    })
}

/// 读取用户通过对话框选择的文件的元数据快照（二进制 IPC 之外的轻量 JSON 返回）。
///
/// 用途：清藏导入前获取文件长度用于分块规划，并留存 `(size, mtime_ms)`
/// 作为来源身份基线——导入过程中按批边界复查，源文件被改写即中止。
///
/// 安全策略与 read_user_file 一致（跳过白名单 + 系统关键目录拒绝 + 审计日志）。
#[tauri::command]
pub async fn user_file_stat(app: tauri::AppHandle, path: String) -> Result<UserFileStat, String> {
    log::info!(
        "[user_file_stat] 开始读取用户选择文件元数据: {}",
        sanitize_path(&path)
    );

    let path_clone = path.clone();
    let stat_result = tokio::time::timeout(
        USER_FILE_CHUNK_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || user_file_stat_blocking(&path_clone)),
    )
    .await;

    match stat_result {
        Err(_) => {
            log::error!(
                "[user_file_stat] 超时（{}s）| {}",
                USER_FILE_CHUNK_OP_TIMEOUT.as_secs(),
                sanitize_path(&path)
            );
            write_file_audit(
                &app,
                AuditEventType::FileRead,
                &path,
                AuditResult::Failure,
                None,
                Some(format!(
                    "stat 超时 {}s",
                    USER_FILE_CHUNK_OP_TIMEOUT.as_secs()
                )),
            );
            Err(ErrorCode::TemporaryFailure.default_message().to_string())
        }
        Ok(Err(e)) => {
            log::error!("[user_file_stat] spawn_blocking 异常: {}", e);
            write_file_audit(
                &app,
                AuditEventType::FileRead,
                &path,
                AuditResult::Failure,
                None,
                Some(format!("任务异常: {}", e)),
            );
            Err(ErrorCode::Internal.default_message().to_string())
        }
        Ok(Ok(Ok(stat))) => {
            write_file_audit(
                &app,
                AuditEventType::FileRead,
                &path,
                AuditResult::Success,
                Some(stat.size),
                Some("stat".to_string()),
            );
            Ok(stat)
        }
        Ok(Ok(Err(e))) => {
            write_file_audit(
                &app,
                AuditEventType::FileRead,
                &path,
                AuditResult::Failure,
                None,
                Some(e.clone()),
            );
            Err(e)
        }
    }
}
