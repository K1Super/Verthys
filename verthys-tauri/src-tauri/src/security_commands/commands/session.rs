/*
 * commands/session.rs — 会话守卫命令
 *
 *
 *
 * 职责：
 *   会话守卫 Tauri 命令实现：
 *     - security_session_start：启动会话守卫（必须获取主窗口 HWND，失败不静默）
 *     - security_session_stop：停止会话守卫
 *     - security_session_set_hardening：设置会话硬化开关（需已解锁会话）
 */

use tauri::{Manager, State};

use crate::state::AppState;
use crate::util::audit_log::{AuditEventType, AuditResult};

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::auth::require_session_authorized;
use crate::security_commands::responses::SecurityResult;
use crate::security_commands::state::{lock_session_guard_or_recover, SecurityState};

/* ====================================================================== *
 *  2. 会话守卫命令                               *
 * ====================================================================== */

/// 启动会话守卫（监听系统锁屏/解锁事件）
///
/// 修复：获取主窗口 HWND 作为必须参数，获取失败则命令失败，绝不静默。
/// HWND 用于 SetWindowDisplayAffinity 等关联操作。
#[tauri::command]
pub fn security_session_start(
    app: tauri::AppHandle,
    state: State<SecurityState>,
) -> Result<(), String> {
    // 获取主窗口 HWND（必须成功，不静默忽略）
    let hwnd = app
        .get_webview_window("main")
        .ok_or_else(|| {
            log::error!("[security_session_start] 第 13.2.8 项：主窗口未找到");
            "主窗口未找到，无法启动会话守卫".to_string()
        })?
        .hwnd()
        .map_err(|e| {
            log::error!(
                "[security_session_start] 第 13.2.8 项：获取 HWND 失败: {}",
                e
            );
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

/// 设置会话硬化开关（挂起锁定 / 剪贴板监听）
///
/// 两项能力相互独立，各自启停：
///   - suspend_lock：系统挂起（睡眠）时是否销毁密钥；
///   - clipboard_monitor：是否监听外部剪贴板写入并清空（锁定清空为恒定底线）。
///
/// 授权：当前会话必须已解锁容器且存在主密钥记录，防止未建立会话的
/// 进程操纵防护级别。挂起锁定标志为进程内原子写，持锁时间可忽略。
/// 剪贴板监听启动失败如实回报错误码，不回滚已设置的挂起标志——
/// 两项能力相互独立，不制造"整体成功"的假象。
#[tauri::command]
pub fn security_session_set_hardening(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    app_state: State<'_, AppState>,
    suspend_lock: bool,
    clipboard_monitor: bool,
) -> Result<SecurityResult, String> {
    if let Err(msg) = require_session_authorized(&app_state) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Denied,
            None,
            Some(format!(
                "PERMISSION_DENIED: set_hardening(suspend_lock={}, clipboard_monitor={}) {}",
                suspend_lock, clipboard_monitor, msg
            )),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "设置会话硬化开关需要已解锁的会话",
        ));
    }

    {
        let mut guard = lock_session_guard_or_recover(&state)?;
        guard.set_high_security_mode(suspend_lock);
    }

    // 剪贴板监听随开关启停：失败如实回报错误码，不回滚挂起标志
    match state.set_clipboard_guard(clipboard_monitor) {
        Ok(()) => {
            write_security_audit(
                &app,
                &state,
                AuditEventType::SecurityCommand,
                AuditResult::Success,
                None,
                Some(format!(
                    "会话硬化开关: 挂起锁定={}（剪贴板监听{}）",
                    if suspend_lock { "启用" } else { "禁用" },
                    if clipboard_monitor { "已启动" } else { "已停止" }
                )),
            );
            log::info!(
                "[security_session_set_hardening] 挂起锁定: {}, 剪贴板监听: {}",
                suspend_lock, clipboard_monitor
            );
            Ok(SecurityResult::success("会话硬化开关已更新"))
        }
        Err(e) => {
            write_security_audit(
                &app,
                &state,
                AuditEventType::SecurityCommand,
                AuditResult::Failure,
                None,
                Some(format!(
                    "CLIPBOARD_MONITOR_FAILED: set_hardening(suspend_lock={}, clipboard_monitor={}) {}",
                    suspend_lock, clipboard_monitor, e
                )),
            );
            log::error!(
                "[security_session_set_hardening] 剪贴板监听启动失败: {}",
                e
            );
            Ok(SecurityResult::error(
                "CLIPBOARD_MONITOR_FAILED",
                format!("挂起锁定已设置，但剪贴板监听启动失败: {}", e),
            ))
        }
    }
}
