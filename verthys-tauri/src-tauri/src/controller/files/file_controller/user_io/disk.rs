/*
 * 磁盘空间查询
 *
 * 职责边界：解析目标卷并回报剩余可用字节。目标可能尚未创建，查询前回退到
 * 最近已存在祖先（同一卷）；卷信息不可得即报错，不按 0 空间拒绝合法操作。
 */

use super::path_guard::resolve_user_file_target;
use crate::constants::timeout::DEFAULT as TIMEOUT_CONFIG;
use crate::controller::api_error::ErrorCode;
use crate::state::AppState;
use crate::util::path::sanitize_path;
use std::path::PathBuf;
use tauri::State;

/// 磁盘剩余空间读数（命令应答负载）
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiskSpaceInfo {
    /// 剩余可用字节数
    pub free_bytes: u64,
}

/// 向上回溯到最近的已存在祖先路径（目标可能尚未创建）。
///
/// Win32 卷查询要求入参路径存在：导出保存位置与容器文件都可能尚未落盘，
/// 直接查询会失败；回退到最近已存在的祖先目录即得到同一卷的读数。
pub(in super::super) fn nearest_existing_ancestor(path: &std::path::Path) -> Option<PathBuf> {
    let mut current = path;
    loop {
        if current.exists() {
            return Some(current.to_path_buf());
        }
        match current.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => current = parent,
            _ => return None,
        }
    }
}

/// 查询路径所在卷的剩余空间（字节）。
///
/// 路径解析：显式路径走用户授权目标的解析链（存在即 canonicalize，不存在则
/// 解析父目录后拼接，导出目标常尚未创建）；缺省时取当前会话容器路径，
/// 供导入侧在写块之前预检容器卷。查询前回退到最近已存在祖先（同一卷）。
/// 卷信息不可得即报错（DISK_SPACE_UNKNOWN），不得按 0 空间拒绝合法操作，
/// 也不得静默放行。
pub(in super::super) fn check_disk_space_blocking(
    path: Option<&str>,
    session_path: Option<&str>,
) -> Result<DiskSpaceInfo, String> {
    use crate::util::disk::get_disk_space_bytes;

    let resolved: PathBuf = match path {
        Some(p) => resolve_user_file_target(p, "check_disk_space")?,
        None => match session_path {
            Some(p) => PathBuf::from(p),
            None => {
                log::warn!("[check_disk_space] 无显式路径且无活跃容器路径");
                return Err(ErrorCode::InvalidPath.default_message().to_string());
            }
        },
    };

    let query_path = match nearest_existing_ancestor(&resolved) {
        Some(p) => p,
        None => {
            log::warn!(
                "[check_disk_space] 路径不存在且无已存在祖先: {}",
                sanitize_path(&resolved.to_string_lossy())
            );
            return Err(ErrorCode::InvalidPath.default_message().to_string());
        }
    };

    match get_disk_space_bytes(&query_path) {
        Some(free_bytes) => Ok(DiskSpaceInfo { free_bytes }),
        None => {
            log::warn!(
                "[check_disk_space] 无法获取磁盘空间: {}",
                sanitize_path(&query_path.to_string_lossy())
            );
            Err(ErrorCode::DiskSpaceUnknown.default_message().to_string())
        }
    }
}

/// 查询用户授权路径（或当前容器卷）的剩余磁盘空间（字节）。
///
/// 用途：导入前预检容器卷（路径缺省分支）与导出前预检目标卷（显式路径分支），
/// 空间不足由调用方前置拒绝，避免读到一半或写出部分暂存后才失败。
#[tauri::command]
pub async fn check_disk_space(
    state: State<'_, AppState>,
    path: Option<String>,
) -> Result<DiskSpaceInfo, String> {
    let session_path = state.verthys_session_path();
    log::info!(
        "[check_disk_space] 查询磁盘空间: path={} 容器路径={}",
        path.as_deref()
            .map(sanitize_path)
            .unwrap_or_else(|| "（缺省）".to_string()),
        session_path
            .as_deref()
            .map(sanitize_path)
            .unwrap_or_else(|| "（无）".to_string()),
    );

    let result = tokio::time::timeout(
        TIMEOUT_CONFIG.preflight,
        tokio::task::spawn_blocking(move || {
            check_disk_space_blocking(path.as_deref(), session_path.as_deref())
        }),
    )
    .await;

    match result {
        Err(_) => {
            log::error!(
                "[check_disk_space] 查询超时（{}s）",
                TIMEOUT_CONFIG.preflight.as_secs()
            );
            Err(ErrorCode::TemporaryFailure.default_message().to_string())
        }
        Ok(Err(e)) => {
            log::error!("[check_disk_space] spawn_blocking 异常: {}", e);
            Err(ErrorCode::Internal.default_message().to_string())
        }
        Ok(Ok(r)) => r,
    }
}
