use serde_json::json;
use std::time::Duration;
use tauri::{AppHandle, Manager, State};

#[cfg(feature = "e2e_update")]
use crate::state::AppState;

use super::check::current_version;
#[cfg(feature = "e2e_update")]
use super::check::{updater_check, updater_prepare};
#[cfg(feature = "e2e_update")]
use super::lifecycle::{updater_begin_lock, updater_confirm_lock, updater_install};
#[cfg(feature = "e2e_update")]
use super::types::LockOutcome;
use super::types::{StartupState, UpdaterError, UpdaterState};
use super::{health, lkg, log, manifest, marker, native, repair};

/// 审计有效更新配置；失败写事件并由后续检查拒绝执行。
pub fn audit_config(app: &AppHandle) -> Result<(), UpdaterError> {
    match manifest::audit_config(app) {
        Ok(()) => Ok(()),
        Err(error) => {
            log::append(
                app,
                "config_invalid",
                "Config",
                Some(&error.code),
                "error",
                json!({}),
            );
            Err(error)
        }
    }
}

/// 读取启动状态；阶段决定前端执行自检、等待安装还是进入修复。
#[tauri::command]
pub fn updater_startup_state(app: AppHandle) -> Result<StartupState, UpdaterError> {
    let current = current_version(&app);
    let repair_confirmed = repair::confirm_if_completed(&app, &current);
    // 用户可能已手动重装旧版或直接安装了更新版本；过期修复状态不再提示。
    if !repair_confirmed {
        if let Some(state) = repair::read(&app) {
            if state.state == "awaiting_repair" && current != state.failed_version {
                let _ = repair::clear(&app);
            }
        }
    }
    let repair_view = repair::view(&app);
    // 清理超期候选物料；仍被近期标记引用的候选不受影响。
    let _ = lkg::cleanup_candidates(&app, None);

    let marker = match marker::read_pending(&app) {
        Ok(value) => value,
        Err(error) => {
            let quarantined = marker::quarantine_pending(&app);
            log::append(
                &app,
                "marker_invalid",
                "HealthCheck",
                Some(&error.code),
                "error",
                json!({ "quarantined": quarantined.is_ok() }),
            );
            return Ok(StartupState {
                has_pending: false,
                phase: "marker_invalid".to_string(),
                current_version: current,
                from_version: None,
                to_version: None,
                release_id: None,
                marker_state: Some("invalid".to_string()),
                repair_available: repair_view.available,
                repair_version: repair_view.version,
            });
        }
    };

    // 标记由当前进程发起安装时写入，只有重启后的新进程才有权判定健康状态。
    let marker = marker.filter(|value| value.owner_pid != std::process::id());
    let Some(marker) = marker else {
        let phase = if repair_confirmed {
            "repair_confirmed"
        } else if repair_view.available {
            "repair_available"
        } else {
            "none"
        };
        return Ok(StartupState {
            has_pending: false,
            phase: phase.to_string(),
            current_version: current,
            from_version: None,
            to_version: None,
            release_id: None,
            marker_state: None,
            repair_available: repair_view.available,
            repair_version: repair_view.version,
        });
    };

    if marker.to_version == current {
        return Ok(StartupState {
            has_pending: true,
            phase: "health_check".to_string(),
            current_version: current,
            from_version: Some(marker.from_version),
            to_version: Some(marker.to_version),
            release_id: Some(marker.release_id),
            marker_state: Some(marker.state),
            repair_available: repair_view.available,
            repair_version: repair_view.version,
        });
    }

    let age = marker::handoff_age_minutes(&marker).unwrap_or(i64::MAX);
    if marker.state == "install_handoff" && age < marker::INSTALL_SETTLE_WINDOW_MINUTES {
        return Ok(StartupState {
            has_pending: true,
            phase: "install_in_progress".to_string(),
            current_version: current,
            from_version: Some(marker.from_version),
            to_version: Some(marker.to_version),
            release_id: Some(marker.release_id),
            marker_state: Some(marker.state),
            repair_available: repair_view.available,
            repair_version: repair_view.version,
        });
    }

    let archived = marker::finish_pending(&app, "install_failed", Some("安装未完成或版本未变更"))?;
    let _ = repair::write_from_marker(&app, &archived);
    log::append(
        &app,
        "install_failed",
        "HealthCheck",
        Some("E_UPDATER_INSTALL_FAILED"),
        "error",
        json!({ "releaseId": archived.release_id }),
    );
    let repair_view = repair::view(&app);
    Ok(StartupState {
        has_pending: false,
        phase: "install_failed".to_string(),
        current_version: current,
        from_version: Some(archived.from_version),
        to_version: Some(archived.to_version),
        release_id: Some(archived.release_id),
        marker_state: Some(archived.state),
        repair_available: repair_view.available,
        repair_version: repair_view.version,
    })
}

/// 由 Rust 执行新版本健康自检并归档结论；前端只能触发与展示。
#[tauri::command]
pub async fn updater_run_health(app: AppHandle) -> Result<health::HealthReport, UpdaterError> {
    app.state::<UpdaterState>().mark_health_handled();
    match tokio::time::timeout(Duration::from_secs(60), health::run(&app)).await {
        Ok(report) => report,
        Err(_) => {
            log::append(
                &app,
                "health_fail",
                "HealthCheck",
                Some("E_UPDATER_HEALTH_FAIL"),
                "error",
                json!({ "reason": "timeout" }),
            );
            Err(UpdaterError::new(
                "E_UPDATER_HEALTH_FAIL",
                "健康自检超时",
                true,
            ))
        }
    }
}

/// 查询当前可用的修复物料；前端查询即视为已接管恢复提示。
#[tauri::command]
pub fn updater_repair_state(
    app: AppHandle,
    state: State<'_, UpdaterState>,
) -> Result<repair::RepairStateView, UpdaterError> {
    state.mark_health_handled();
    Ok(repair::view(&app))
}

/// 复验旧版物料并启动修复安装器；成功后进程退出。
#[tauri::command]
pub fn updater_run_repair(app: AppHandle) -> Result<(), UpdaterError> {
    repair::run(&app)
}

/// 启动原生兜底：前端未在时限内处理时，由系统对话框提供最小恢复路径。
pub fn spawn_native_watchdog(app: AppHandle) {
    let current = current_version(&app);
    let pending = marker::read_pending(&app)
        .ok()
        .flatten()
        .is_some_and(|value| value.owner_pid != std::process::id() && value.to_version == current);
    let repair_pending = repair::read(&app)
        .is_some_and(|value| value.state == "awaiting_repair" || value.state == "repair_started");
    if !pending && !repair_pending {
        return;
    }

    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(90));
        if app.state::<UpdaterState>().health_handled() {
            return;
        }
        let current = current_version(&app);
        let pending = marker::read_pending(&app)
            .ok()
            .flatten()
            .is_some_and(|value| {
                value.owner_pid != std::process::id() && value.to_version == current
            });
        if pending {
            native::prompt_pending(&app);
            return;
        }
        if let Some(state) = repair::read(&app) {
            if state.state == "awaiting_repair" || state.state == "repair_started" {
                native::prompt_failure(&app);
            }
        }
    });
}

/// 导出脱敏日志 zip 到用户选择的路径；返回最终文件路径。
#[tauri::command]
pub fn updater_export_logs(app: AppHandle, target_path: String) -> Result<String, UpdaterError> {
    /* 该入口只服务开发悬浮球；发布态直接拒绝，避免用户侧或外部 IPC 调用。 */
    if !cfg!(debug_assertions) {
        return Err(UpdaterError::new(
            "E_UPDATER_INTERNAL",
            "更新日志导出仅在开发构建可用",
            false,
        ));
    }
    log::export(&app, &target_path)
}

/// 自动执行一次完整更新；仅在启用 e2e_update 特性且设置环境变量时调用。
#[cfg(feature = "e2e_update")]
pub async fn run_e2e_update(app: AppHandle) -> Result<(), UpdaterError> {
    use tauri::Manager;

    let state = app.state::<UpdaterState>();
    let check = updater_check(app.clone(), state).await?.ok_or_else(|| {
        log::append(
            &app,
            "e2e_failed",
            "Checking",
            Some("E_UPDATER_VERSION_BLOCKED"),
            "error",
            json!({}),
        );
        UpdaterError::new("E_UPDATER_VERSION_BLOCKED", "E2E 未发现可用更新", false)
    })?;

    let state = app.state::<UpdaterState>();
    let prepared = updater_prepare(app.clone(), state, check.update_id.clone())
        .await
        .inspect_err(|error| {
            log::append(
                &app,
                "e2e_failed",
                "Verifying",
                Some(&error.code),
                "error",
                json!({}),
            );
        })?;
    log::append(
        &app,
        "e2e_prepared",
        "Verifying",
        None,
        "info",
        json!({
            "releaseId": prepared.release_id,
            "sha256": prepared.sha256,
            "fileVersion": prepared.file_version,
        }),
    );

    let state = app.state::<UpdaterState>();
    let challenge = updater_begin_lock(app.clone(), state, check.update_id.clone()).await?;

    let state = app.state::<UpdaterState>();
    let app_state = app.state::<AppState>();
    let receipt = updater_confirm_lock(
        app.clone(),
        state,
        app_state,
        challenge.challenge,
        LockOutcome {
            clean: true,
            flushed: true,
            dirty: false,
            errors: Vec::new(),
            duration_ms: 0,
        },
    )?;

    let state = app.state::<UpdaterState>();
    updater_install(app.clone(), state, check.update_id, receipt.receipt)
}
