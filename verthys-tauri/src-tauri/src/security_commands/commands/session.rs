/*
 * commands/session.rs — 会话守卫命令
 *
 *    "" 第十三章 — 13.2.5 / 13.2.8 项
 *
 * 职责：
 *   会话守卫 Tauri 命令实现：
 *     - security_session_start：启动会话守卫（必须获取主窗口 HWND，失败不静默）
 *     - security_session_stop：停止会话守卫
 *     - security_session_set_high_security：设置高安全模式（需 auth_token）
 */

use tauri::{Manager, State};

use crate::util::audit_log::{AuditEventType, AuditResult};

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::auth::verify_and_consume_auth_token;
use crate::security_commands::responses::SecurityResult;
use crate::security_commands::state::{lock_session_guard_or_recover, SecurityState};

/* ====================================================================== *
 *  2. 会话守卫命令（第 13.2.5 / 13.2.8 项）                               *
 * ====================================================================== */

/// 第 13.2.8 项：启动会话守卫（监听系统锁屏/解锁事件）
///
/// 修复：获取主窗口 HWND 作为必须参数，获取失败则命令失败，绝不静默。
/// HWND 用于 SetWindowDisplayAffinity 等关联操作。
#[tauri::command]
pub fn security_session_start(
    app: tauri::AppHandle,
    state: State<SecurityState>,
) -> Result<(), String> {
    // 第 13.2.8 项：获取主窗口 HWND（必须成功，不静默忽略）
    let hwnd = app
        .get_webview_window("main")
        .ok_or_else(|| {
            log::error!("[security_session_start] 第 13.2.8 项：主窗口未找到");
            "主窗口未找到，无法启动会话守卫".to_string()
        })?
        .hwnd()
        .map_err(|e| {
            log::error!("[security_session_start] 第 13.2.8 项：获取 HWND 失败: {}", e);
            format!("获取 HWND 失败: {}", e)
        })?
        .0 as isize;

    log::info!(
        "[security_session_start] 第 13.2.8 项：获取主窗口 HWND=0x{:X}",
        hwnd
    );

    let mut guard = lock_session_guard_or_recover(&state)?;
    // SessionGuard::start 内部创建隐藏窗口并注册 WTS 会话通知
    // HWND 已获取并记录，用于后续 SetWindowDisplayAffinity 等关联操作
    guard.start().map_err(|e| {
        log::error!("[security_session_start] 启动失败: {}", e);
        e
    })?;

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        None,
        Some(format!("会话守卫已启动 (HWND=0x{:X})", hwnd)),
    );

    log::info!("[security_session_start] 会话守卫已启动");
    Ok(())
}

/// 停止会话守卫
#[tauri::command]
pub fn security_session_stop(
    app: tauri::AppHandle,
    state: State<SecurityState>,
) -> Result<(), String> {
    let mut guard = lock_session_guard_or_recover(&state)?;
    guard.stop();

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        None,
        Some("会话守卫已停止".into()),
    );

    log::info!("[security_session_stop] 会话守卫已停止");
    Ok(())
}

/// 第 13.2.5 项：设置高安全模式（启用电源挂起监听 + 更激进的锁屏策略）
///
/// 要求：携带有效的 auth_token（一次性消费），防止前端恶意关闭安全防护
#[tauri::command]
pub fn security_session_set_high_security(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    enabled: bool,
    auth_token: Option<String>,
) -> Result<SecurityResult, String> {
    // 第 13.2.5 项：验证 auth_token
    if !verify_and_consume_auth_token(&state, auth_token.as_deref()) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Denied,
            None,
            Some(format!(
                "PERMISSION_DENIED: set_high_security({}) 缺少有效 auth_token",
                enabled
            )),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "设置高安全模式需要有效授权令牌",
        ));
    }

    {
        let mut guard = lock_session_guard_or_recover(&state)?;
        guard.set_high_security_mode(enabled);
    }

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        None,
        Some(format!("高安全模式: {}", if enabled { "启用" } else { "禁用" })),
    );

    log::info!(
        "[security_session_set_high_security] 高安全模式: {}",
        if enabled { "启用" } else { "禁用" }
    );
    Ok(SecurityResult::success(if enabled {
        "高安全模式已启用"
    } else {
        "高安全模式已禁用"
    }))
}
