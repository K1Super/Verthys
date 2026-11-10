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

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tauri::{Emitter, Manager, State};

use crate::controller::worker_controller;
use crate::state::AppState;
use crate::util::audit_log::{AuditEventType, AuditResult};

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::auth::require_session_authorized;
use crate::security_commands::responses::SecurityResult;
use crate::security_commands::state::{lock_session_guard_or_recover, SecurityState};

/* ====================================================================== *
 *  外部锁定序列（系统锁屏 / 注销 / 断连 / 挂起）                          *
 * ====================================================================== */

/// 外部锁定并发闸门：系统事件可能连续到达（挂起 + 锁屏），只允许一个
/// 销毁序列在途，后到事件直接返回，避免对已销毁会话重复操作。
static EXTERNAL_LOCK_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

#[derive(Clone, serde::Serialize)]
struct ExternalLockPayload {
    reason: &'static str,
}

#[derive(Clone, serde::Serialize)]
struct RuntimeGuardsPayload {
    flags: u32,
}

/* 守卫位变更后通知前端立即重采样防御状态。
 * 首次状态拉取可能与 security_session_start 的守卫下发并发，导致首个
 * 60s 周期内把“已接线”误读为“可修复降级”；该事件用于消除该时间窗。 */
fn emit_runtime_guards(app: &tauri::AppHandle, flags: u32) {
    let _ = app.emit(
        "verthys://runtime-guards",
        RuntimeGuardsPayload { flags },
    );
}

/// 下发运行时守卫位（完整掩码语义；bit1=挂起守卫已接线）。
///
/// worker 未就绪时下发失败属预期路径（启动期/已锁定），只记录诊断，
/// 不阻断任何流程。worker 会与心跳位合并后通知 C 层。
pub(crate) fn notify_runtime_guards(app_state: &AppState, suspend_lock: bool) {
    let flags: u32 = if suspend_lock { 0x02 } else { 0 };
    let request = format!(r#"{{"op":"runtime_guards","flags":{}}}"#, flags);
    match app_state.send_with_timeout(&request, Duration::from_secs(3)) {
        Ok(_) => log::info!(
            "[session_guard] 运行时守卫位已下发: flags=0x{:X}",
            flags
        ),
        Err(e) => log::debug!(
            "[session_guard] 运行时守卫位下发失败（worker 未就绪时属预期）: {}",
            e
        ),
    }
}

/// 系统事件触发的同步锁定序列：请求 worker 锁库（3s 上限）→ 销毁 worker
/// 会话（进程消亡即密钥消亡）→ 通知前端重置密钥视图。
///
/// 不经过前端 lockAll：锁屏/挂起事件到达时 WebView 可能已不可调度，
/// 安全动作必须由主进程直接完成。失败只记录诊断，销毁路径本身具有
/// 最终性（会话句柄 Drop 终止子进程）。
pub(crate) async fn perform_external_lock(app: tauri::AppHandle, reason: &'static str) {
    if EXTERNAL_LOCK_IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        log::info!(
            "[session_guard] 外部锁定已在执行，忽略重复事件: {}",
            reason
        );
        return;
    }

    let state = app.state::<AppState>();
    if !state.has_session() {
        log::info!("[session_guard] 外部锁定事件 {} 到达时无活动会话", reason);
        EXTERNAL_LOCK_IN_PROGRESS.store(false, Ordering::SeqCst);
        return;
    }

    log::warn!("[session_guard] 外部锁定序列开始: reason={}", reason);

    /* 1. 请求 worker 锁库（有界）：flush 并清零会话密钥；失败也继续销毁。 */
    match state.send_with_timeout(r#"{"op":"lock"}"#, Duration::from_secs(3)) {
        Ok(_) => log::info!("[session_guard] worker 锁库完成: {}", reason),
        Err(e) => log::warn!(
            "[session_guard] worker 锁库超时/失败，转入强制销毁: {} ({})",
            reason,
            e
        ),
    }

    /* 2. 销毁 worker 会话：终止子进程，残留密钥随进程消亡。 */
    match worker_controller::worker_destroy(app.state::<AppState>()).await {
        Ok(_) => log::info!("[session_guard] worker 会话已销毁: {}", reason),
        Err(e) => log::error!(
            "[session_guard] worker 会话销毁失败: {} ({})",
            reason,
            e
        ),
    }

    /* 3. 宿主侧残留收口：轮换取消状态与剪贴板明文不得跨锁定残留。 */
    crate::service::vault_rotate::reset_on_lock();
    if !crate::security::clear_clipboard() {
        log::warn!("[session_guard] 外部锁定清空剪贴板失败");
    }

    /* 4. 通知前端重置密钥状态与视图（前端不调用锁库命令，避免与
     *    已销毁 worker 竞态）。 */
    let _ = app.emit(
        "verthys://external-lock",
        ExternalLockPayload { reason },
    );

    EXTERNAL_LOCK_IN_PROGRESS.store(false, Ordering::SeqCst);
}

/* ====================================================================== *
 *  2. 会话守卫命令                               *
 * ====================================================================== */

/// 启动会话守卫（监听系统锁屏/解锁事件）
///
/// 获取主窗口 HWND 作为必须参数，获取失败则命令失败，绝不静默。
/// HWND 用于 SetWindowDisplayAffinity 等关联操作。
#[tauri::command]
pub fn security_session_start(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    app_state: State<'_, AppState>,
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

    /* 守卫已接线：向 worker 下发 bit1，状态面板据此区分"看门狗已接线"
     * 与"可修复缺口"。锁定时/worker 未就绪时下发失败只记诊断。 */
    notify_runtime_guards(&app_state, true);
    emit_runtime_guards(&app, 0x02);

    log::info!("[security_session_start] 会话守卫已启动");
    Ok(())
}

/// 停止会话守卫
#[tauri::command]
pub fn security_session_stop(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    app_state: State<'_, AppState>,
) -> Result<(), String> {
    let mut guard = lock_session_guard_or_recover(&state)?;
    guard.stop();

    /* 停止守卫：下发 0，worker 清除挂起位（心跳位由 worker 自行保留）。 */
    notify_runtime_guards(&app_state, false);
    emit_runtime_guards(&app, 0x00);

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

/// 设置会话硬化开关（显示器关闭锁定 / 剪贴板监听）
///
/// 系统挂起（PBT_APMSUSPEND）现恒触发锁库，不受本开关控制：挂起窗口
/// 是内存镜像落盘的唯一入口，不允许被用户配置关闭。本开关只控制
/// 显示器关闭时的额外锁定与剪贴板监听。
///
/// 授权：当前会话必须已解锁容器且存在主密钥记录，防止未建立会话的
/// 进程操纵防护级别。
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
                    "会话硬化开关: 显示器关闭锁定={}（系统挂起恒锁库）",
                    if suspend_lock { "启用" } else { "禁用" }
                )),
            );
            log::info!(
                "[security_session_set_hardening] 显示器关闭锁定: {}, 剪贴板监听: {}",
                suspend_lock,
                clipboard_monitor
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
            log::error!("[security_session_set_hardening] 剪贴板监听启动失败: {}", e);
            Ok(SecurityResult::error(
                "CLIPBOARD_MONITOR_FAILED",
                format!("挂起锁定已设置，但剪贴板监听启动失败: {}", e),
            ))
        }
    }
}
