/*
 * commands/module_whitelist.rs — 模块巡检命令
 *
 *
 * 职责：
 *   模块巡检 Tauri 命令实现：
 *     - security_module_patrol：巡检当前进程已加载模块（spawn_blocking）
 *     - security_add_trusted_path：添加受信任路径到白名单（需已解锁会话）
 *     - security_clear_trusted_paths：清空受信任路径白名单（需已解锁会话）
 */

use tauri::State;

use crate::security::module_whitelist;
use crate::util::audit_log::{AuditEventType, AuditResult};

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::auth::require_session_authorized;
use crate::security_commands::path_resolver::get_install_dir;
use crate::security_commands::persistence::persist_trusted_paths;
use crate::security_commands::responses::{SecurityResult, UnknownModuleInfo};
use crate::security_commands::state::SecurityState;

/* ====================================================================== *
 *  3. 模块巡检命令                               *
 * ====================================================================== */

/// 巡检当前进程已加载模块，返回未知/可疑模块列表
///
/// 修复：install_dir 从 current_exe 推导，不信任前端输入。
/// 使用 spawn_blocking 执行巡检（可能耗时）。
#[tauri::command]
pub async fn security_module_patrol(
    app: tauri::AppHandle,
    state: State<'_, SecurityState>,
) -> Result<Vec<UnknownModuleInfo>, String> {
    // 从 current_exe 获取安装目录
    let install_dir = get_install_dir()?;

    // spawn_blocking 执行阻塞式巡检
    let unknown = tokio::task::spawn_blocking(move || module_whitelist::patrol_modules(&install_dir))
        .await
        .map_err(|e| format!("巡检任务执行失败: {}", e))?;

    // 审计日志
    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        None,
        Some(format!("模块巡检完成，发现 {} 个未知模块", unknown.len())),
    );

    Ok(unknown
        .into_iter()
        .map(|m| UnknownModuleInfo {
            name: m.name,
            path: m.path,
            reason: m.reason,
        })
        .collect())
}

/// 添加受信任路径到白名单
///
/// 授权：需已解锁的会话，防止被篡改的前端任意操纵安全基线
/// 白名单路径经 GetLongPathNameW 真实化后存储，防止短文件名/符号链接绕过。
#[tauri::command]
pub fn security_add_trusted_path(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    app_state: State<'_, crate::state::AppState>,
    path: String,
) -> Result<SecurityResult, String> {
    // 授权检查：白名单变更需已解锁的会话
    if let Err(msg) = require_session_authorized(&app_state) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Denied,
            Some(&path),
            Some(format!("PERMISSION_DENIED: add_trusted_path {}", msg)),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "添加受信任路径需要已解锁的会话",
        ));
    }

    // 路径校验
    crate::util::path::validate_path_input(&path)
        .map_err(|e| format!("路径校验失败: {}", e))?;

    module_whitelist::add_trusted_path(&path);

    // 白名单变更后持久化
    persist_trusted_paths(&app);

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        Some(&path),
        Some("已添加受信任路径".into()),
    );

    log::info!("[security_add_trusted_path] 已添加受信任路径");
    Ok(SecurityResult::success("已添加受信任路径"))
}

/// 清空受信任路径白名单
///
/// 授权：需已解锁的会话。
#[tauri::command]
pub fn security_clear_trusted_paths(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    app_state: State<'_, crate::state::AppState>,
) -> Result<SecurityResult, String> {
    // 授权检查：白名单变更需已解锁的会话
    if let Err(msg) = require_session_authorized(&app_state) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Denied,
            None,
            Some(format!("PERMISSION_DENIED: clear_trusted_paths {}", msg)),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "清空受信任路径白名单需要已解锁的会话",
        ));
    }

    module_whitelist::clear_trusted_paths();

    // 白名单变更后持久化
    persist_trusted_paths(&app);

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        None,
        Some("已清空受信任路径白名单".into()),
    );

    log::info!("[security_clear_trusted_paths] 已清空受信任路径白名单");
    Ok(SecurityResult::success("已清空受信任路径白名单"))
}
