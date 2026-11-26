/*
 * 启动序列与窗口目标收集
 *
 * 职责边界：启动时默认施加保护（先于窗口可见生效）、启动恢复对账与
 * 原生重试对话框。任一窗口取句柄失败即整体失败，禁止静默跳过。
 */

use crate::util::audit_log::{AuditEventType, AuditExtensions, AuditResult};
use tauri::Manager;

use super::*;
/* ====================================================================== *
 *  窗口目标收集                                                           *
 * ====================================================================== */

/// 收集当前全部 WebView 窗口作为保护目标
///
/// 任一窗口取句柄失败即整体失败：静默跳过会造成"保护成功但该窗口裸奔"的假象。
pub fn collect_targets(app: &tauri::AppHandle) -> Result<Vec<WindowTarget>, PrivacyError> {
    let mut targets = Vec::new();
    for (label, window) in app.webview_windows() {
        match window.hwnd() {
            Ok(hwnd) => targets.push(WindowTarget {
                label,
                hwnd: hwnd.0 as isize,
            }),
            Err(e) => {
                return Err(PrivacyError::Affinity(format!(
                    "窗口 '{}' 获取句柄失败: {}",
                    label, e
                )))
            }
        }
    }
    // 应用顺序确定化（便于审计与复现），与窗口枚举顺序无关
    targets.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(targets)
}

/* ====================================================================== *
 *  启动序列                                                               *
 * ====================================================================== */

/// 启动序列结果
pub enum StartupOutcome {
    /// 保护已生效（槽位待采纳，前端挂载后接管）
    Protected { generation: Generation },
    /// 未保护：保护尝试失败且已还原（保护默认开启，不存在"按用户意图跳过"）
    Unprotected,
    /// 还原失败（窗口取值未知）：需要用户驱动对账后才可显示主窗口
    NeedsRecovery,
}

/// 启动序列：在窗口可见前施加保护并回读
///
/// 防截屏是默认开启的应用级保护：**每次启动一律自动施加，不依赖任何持久化
/// 意图，也不需要用户手动开启**；用户在当前会话内显式关闭后仅本次会话有效，
/// 重启回到默认开启。恰好在 `setup` 钩子内执行：Tauri 在钩子之前按配置建窗
/// （此时窗口已存在但不可见），而前端命令要等钩子返回后才开始派发，
/// 因此不存在与前端查询并发的竞态。
pub fn startup_engage(app: &tauri::AppHandle, coordinator: &PrivacyCoordinator) -> StartupOutcome {
    let targets = match collect_targets(app) {
        Ok(targets) => targets,
        Err(cause) => {
            log::error!("[privacy] 启动保护失败：{}", cause.detail());
            coordinator.audit.write(
                AuditEventType::PrivacyModeChange,
                AuditResult::Failure,
                format!("启动保护未生效（{}），按未保护进入", cause.detail()),
                AuditExtensions::default(),
            );
            return StartupOutcome::Unprotected;
        }
    };

    match coordinator.startup_protect(&targets) {
        Ok(generation) => StartupOutcome::Protected { generation },
        Err(PrivacyError::RolledBack { cause }) => {
            log::warn!("[privacy] 启动保护失败，已还原：{}", cause.detail());
            StartupOutcome::Unprotected
        }
        Err(PrivacyError::Quarantined) => StartupOutcome::NeedsRecovery,
        Err(other) => {
            log::error!("[privacy] 启动保护未生效：{}", other.detail());
            StartupOutcome::Unprotected
        }
    }
}

/// 启动恢复对话框：还原失败时窗口取值未知，显示任何窗口都可能呈现
/// "看起来受保护、实际未受保护"，因此只给"重试对账 / 退出"两个出口。
/// 返回 true 表示对账成功（可以显示主窗口），false 表示用户选择退出。
pub fn run_startup_recovery_dialog(
    app: &tauri::AppHandle,
    coordinator: &PrivacyCoordinator,
) -> bool {
    let message = "防截屏保护未能启用，且窗口保护状态无法还原。\n\n\
                   选择\"重试\"将重新加固保护并进入应用；\n\
                   选择\"取消\"将退出应用（不显示任何窗口）。";
    loop {
        if !native_retry_dialog(message) {
            return false;
        }
        let targets = match collect_targets(app) {
            Ok(targets) => targets,
            Err(cause) => {
                log::error!("[privacy] 恢复对账前收集窗口失败：{}", cause.detail());
                continue;
            }
        };
        match coordinator.reconcile(&targets) {
            Ok(outcome) => {
                log::info!("[privacy] 恢复对账成功（enabled={}）", outcome.enabled);
                return true;
            }
            Err(cause) => {
                log::error!("[privacy] 恢复对账失败：{}", cause.detail());
            }
        }
    }
}

/// 原生"重试 / 取消"对话框；返回 true 表示用户选择重试
#[cfg(target_os = "windows")]
fn native_retry_dialog(message: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDRETRY, MB_ICONWARNING, MB_RETRYCANCEL, MB_SETFOREGROUND, MB_TOPMOST,
    };

    fn to_wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let text = to_wide(message);
    let caption = to_wide("Verthys 防截屏保护");
    let result = unsafe {
        MessageBoxW(
            None,
            PCWSTR(text.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_RETRYCANCEL | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
        )
    };
    result == IDRETRY
}

#[cfg(not(target_os = "windows"))]
fn native_retry_dialog(_message: &str) -> bool {
    false
}
