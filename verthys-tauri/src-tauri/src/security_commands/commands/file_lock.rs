/*
 * commands/file_lock.rs — 文件锁与 ACL 命令
 *
 *    "优化.md" 第十三章 — 13.2.1 / 13.2.3 / 13.2.7 项
 *
 * 职责：
 *   文件锁 Tauri 命令实现：
 *     - security_harden_private_dir：加固私有目录 ACL（spawn_blocking）
 */

use tauri::State;

use crate::security::file_lock::harden_private_dir;
use crate::util::audit_log::{AuditEventType, AuditResult};

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::path_resolver::resolve_logical_path;
use crate::security_commands::state::SecurityState;

/* ====================================================================== *
 *  5. 文件锁与 ACL 命令（第 13.2.1 / 13.2.3 / 13.2.7 项）                 *
 * ====================================================================== */

/// 第 13.2.1 / 13.2.3 项：加固私有目录 ACL（当前用户完全控制，其他用户拒绝访问）
///
/// 第 13.2.1 项：dir 参数改为 logical_id，由后端从受信上下文解析。
/// 第 13.2.3 项：使用 spawn_blocking 执行 ACL 操作（可能耗时）。
#[tauri::command]
pub async fn security_harden_private_dir(
    app: tauri::AppHandle,
    state: State<'_, SecurityState>,
    logical_id: String,
) -> Result<(), String> {
    // 第 13.2.1 项：解析逻辑路径
    let dir = resolve_logical_path(&app, &logical_id)?;
    let dir_str = dir.to_string_lossy().to_string();

    // 第 13.2.3 项：spawn_blocking 执行 ACL 加固
    let result = tokio::task::spawn_blocking(move || harden_private_dir(&dir_str))
        .await
        .map_err(|e| format!("ACL 加固任务执行失败: {}", e))?;

    result.map_err(|e| {
        log::error!("[security_harden_private_dir] 加固失败: {}", e);
        write_security_audit(
            &app,
            &state,
            AuditEventType::HardenPrivateDir,
            AuditResult::Failure,
            Some(&logical_id),
            Some(format!("ACL 加固失败: {}", e)),
        );
        e
    })?;

    write_security_audit(
        &app,
        &state,
        AuditEventType::HardenPrivateDir,
        AuditResult::Success,
        Some(&logical_id),
        Some("目录 ACL 已加固".into()),
    );

    log::info!("[security_harden_private_dir] 目录 ACL 已加固");
    Ok(())
}
