/*
 * commands/cleanup.rs — 痕迹清理命令
 *
 *
 * 职责：
 *   痕迹清理 Tauri 命令实现（async + spawn_blocking）：
 *     - security_cleanup_recent：清空系统最近使用记录
 *     - security_secure_delete：安全删除文件（logical_id + 文件名校验）
 *     - security_cleanup_crash_residue：清理崩溃残留临时文件
 */

use tauri::State;

use crate::security::cleanup::{clear_recent_records, cleanup_crash_residue, secure_delete_file, DeleteMode};
use crate::util::audit_log::{AuditEventType, AuditResult};

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::path_resolver::{resolve_logical_path, LOGICAL_TEMP_DIR};
use crate::security_commands::state::SecurityState;

/* ====================================================================== *
 *  4. 痕迹清理命令                      *
 * ====================================================================== */

/// 清空系统最近使用记录（async + spawn_blocking）
#[tauri::command]
pub async fn security_cleanup_recent(
    app: tauri::AppHandle,
    state: State<'_, SecurityState>,
) -> Result<(), String> {
    // spawn_blocking 执行阻塞式 I/O
    let result = tokio::task::spawn_blocking(clear_recent_records)
        .await
        .map_err(|e| format!("清理任务执行失败: {}", e))?;

    result.map_err(|e| {
        log::error!("[security_cleanup_recent] 清理失败: {}", e);
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Failure,
            None,
            Some(format!("清理失败: {}", e)),
        );
        e
    })?;

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        None,
        Some("系统最近记录已清理".into()),
    );

    log::info!("[security_cleanup_recent] 系统最近记录已清理");
    Ok(())
}

/// 安全删除文件
///
/// path 参数改为 logical_id（"verthys_dir"/"temp_dir"/"data_dir"），
///               由后端从受信上下文解析实际路径。
/// 使用 spawn_blocking 执行 Gutmann/Simple 覆写（可能耗时数秒）。
///
/// mode: "gutmann"=35-pass(Gutmann 标准), "simple"=3-pass(随机覆写)
/// file_name: 相对于逻辑目录的文件名（不允许包含 .. 或绝对路径）
#[tauri::command]
pub async fn security_secure_delete(
    app: tauri::AppHandle,
    state: State<'_, SecurityState>,
    logical_id: String,
    file_name: String,
    mode: String,
) -> Result<(), String> {
    // 解析逻辑路径
    let base_dir = resolve_logical_path(&app, &logical_id)?;

    // 校验 file_name 不包含目录遍历
    if file_name.contains("..") || file_name.contains('\\') && file_name.contains(':') {
        return Err("文件名包含非法字符（禁止目录遍历）".into());
    }
    // 禁止绝对路径
    crate::util::path::validate_path_input(&file_name)
        .map_err(|e| format!("文件名校验失败: {}", e))?;
    // file_name 必须是相对路径（不能以盘符开头）
    if file_name.len() >= 2 && file_name.as_bytes()[1] == b':' {
        return Err("文件名不能是绝对路径".into());
    }

    let target_path = base_dir.join(&file_name);
    let target_str = target_path.to_string_lossy().to_string();

    // 最终路径必须在白名单基目录内
    let canonical = std::fs::canonicalize(&target_path)
        .map_err(|e| format!("目标文件不存在或路径解析失败: {}", e))?;
    if !canonical.starts_with(&base_dir) {
        return Err("目标路径不在白名单基目录内（安全拒绝）".into());
    }

    // 彻底移除 Gutmann 35 遍覆写模式
    // 仅提供 Standard（1 遍全零覆写）和 SSD（覆写 + TRIM）模式
    let delete_mode = match mode.as_str() {
        "ssd" => DeleteMode::Ssd,
        _ => DeleteMode::Standard,
    };

    let path_for_task = target_str.clone();
    // spawn_blocking 执行安全删除（1 遍覆写 + 可选 TRIM）
    let result = tokio::task::spawn_blocking(move || {
        secure_delete_file(&path_for_task, delete_mode)
    })
    .await
    .map_err(|e| format!("安全删除任务执行失败: {}", e))?;

    result.map_err(|e| {
        log::error!("[security_secure_delete] 删除失败: {}", e);
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecureDelete,
            AuditResult::Failure,
            Some(&target_str),
            Some(format!("安全删除失败: {}", e)),
        );
        e
    })?;

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecureDelete,
        AuditResult::Success,
        Some(&target_str),
        Some(format!("文件已安全删除 (mode={})", mode)),
    );

    log::info!("[security_secure_delete] 文件已安全删除");
    Ok(())
}

/// 清理崩溃残留临时文件
///
/// 不再接收前端传入的 temp_dir，改用 app_config_dir/tmp。
/// 使用 spawn_blocking 执行文件系统扫描和清理。
#[tauri::command]
pub async fn security_cleanup_crash_residue(
    app: tauri::AppHandle,
    state: State<'_, SecurityState>,
) -> Result<usize, String> {
    // 从受信上下文获取临时目录
    let temp_dir = resolve_logical_path(&app, LOGICAL_TEMP_DIR)?;
    let temp_dir_str = temp_dir.to_string_lossy().to_string();

    // spawn_blocking 执行清理
    let result = tokio::task::spawn_blocking(move || {
        cleanup_crash_residue(&temp_dir_str)
    })
    .await
    .map_err(|e| format!("清理任务执行失败: {}", e))?;

    let count = result.map_err(|e| {
        log::error!("[security_cleanup_crash_residue] 清理失败: {}", e);
        write_security_audit(
            &app,
            &state,
            AuditEventType::CleanupCrashResidue,
            AuditResult::Failure,
            None,
            Some(format!("清理失败: {}", e)),
        );
        e
    })?;

    write_security_audit(
        &app,
        &state,
        AuditEventType::CleanupCrashResidue,
        AuditResult::Success,
        None,
        Some(format!("已清理 {} 个残留文件", count)),
    );

    log::info!("[security_cleanup_crash_residue] 已清理 {} 个残留文件", count);
    Ok(count)
}
