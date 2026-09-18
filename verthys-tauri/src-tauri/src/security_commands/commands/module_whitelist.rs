/*
 * commands/module_whitelist.rs — 模块巡检命令
 *
 *    "" 第十三章 — 13.2.1 / 13.2.3 项 / SECURITY.md 第 3 项
 *
 * 职责：
 *   模块巡检 Tauri 命令实现：
 *     - security_module_patrol：巡检当前进程已加载模块（spawn_blocking）
 *     - security_add_trusted_path：添加受信任路径到白名单（需 auth_token）
 *     - security_clear_trusted_paths：清空受信任路径白名单（需 auth_token）
 */

use tauri::State;

use crate::security::module_whitelist;
use crate::util::audit_log::{AuditEventType, AuditResult};

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::auth::verify_and_consume_auth_token;
use crate::security_commands::path_resolver::get_install_dir;
use crate::security_commands::persistence::persist_trusted_paths;
use crate::security_commands::responses::{SecurityResult, UnknownModuleInfo};
use crate::security_commands::state::SecurityState;

/* ====================================================================== *
 *  3. 模块巡检命令（第 13.2.1 / 13.2.3 项）                               *
 * ====================================================================== */

/// 第 13.2.1 项：巡检当前进程已加载模块，返回未知/可疑模块列表
///
/// 修复：install_dir 从 current_exe 推导，不信任前端输入。
/// 第 13.2.3 项：使用 spawn_blocking 执行巡检（可能耗时）。
#[tauri::command]
pub async fn security_module_patrol(
    app: tauri::AppHandle,
    state: State<'_, SecurityState>,
) -> Result<Vec<UnknownModuleInfo>, String> {
    // 第 13.2.1 项：从 current_exe 获取安装目录
    let install_dir = get_install_dir()?;

    // 第 13.2.3 项：spawn_blocking 执行阻塞式巡检
    let unknown = tokio::task::spawn_blocking(move || module_whitelist::patrol_modules(&install_dir))
        .await
        .map_err(|e| format!("巡检任务执行失败: {}", e))?;

    // 第 13.2.7 项：审计日志
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

/// SECURITY.md 第 3 项：添加受信任路径到白名单（需管理员授权）
///
/// 要求：携带有效的 auth_token（一次性消费），防止前端被篡改后任意操纵白名单。
/// 白名单路径经 GetLongPathNameW 真实化后存储，防止短文件名/符号链接绕过。
#[tauri::command]
pub fn security_add_trusted_path(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    path: String,
    auth_token: Option<String>,
) -> Result<SecurityResult, String> {
    // SECURITY.md 第 3 项：验证 auth_token（白名单需管理员授权）
    if !verify_and_consume_auth_token(&state, auth_token.as_deref()) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Denied,
            Some(&path),
            Some("PERMISSION_DENIED: add_trusted_path 缺少有效 auth_token".into()),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "添加受信任路径需要有效授权令牌",
        ));
    }

    // 第 13.2.1 项：路径校验
    crate::util::path::validate_path_input(&path)
        .map_err(|e| format!("路径校验失败: {}", e))?;

    module_whitelist::add_trusted_path(&path);

    // SECURITY.md 第 3 项：白名单变更后持久化
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

/// SECURITY.md 第 3 项：清空受信任路径白名单（需管理员授权）
#[tauri::command]
pub fn security_clear_trusted_paths(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    auth_token: Option<String>,
) -> Result<SecurityResult, String> {
    // SECURITY.md 第 3 项：验证 auth_token
    if !verify_and_consume_auth_token(&state, auth_token.as_deref()) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Denied,
            None,
            Some("PERMISSION_DENIED: clear_trusted_paths 缺少有效 auth_token".into()),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "清空受信任路径白名单需要有效授权令牌",
        ));
    }

    module_whitelist::clear_trusted_paths();

    // SECURITY.md 第 3 项：白名单变更后持久化
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
