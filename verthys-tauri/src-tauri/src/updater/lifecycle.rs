use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
use std::time::Instant;
use tauri::{AppHandle, State};

use crate::state::AppState;

use super::check::{ensure_release_unchanged, recheck_release, verification_event};
use super::gate;
use super::types::{
    busy_error, cancel_lock, cancelled_error, elevation_denied, inner_lock, lock_unknown,
    plugin_error, session_invalid, LockOutcome, PreparedBytes, UpdaterError, UpdaterState,
};
use super::{authenticode, lkg, log, manifest, marker, pe, precheck, verify};

/// 为当前已准备的会话签发锁库挑战；挑战一次性使用且短期有效。
#[tauri::command]
pub async fn updater_begin_lock(
    app: AppHandle,
    state: State<'_, UpdaterState>,
    update_id: String,
) -> Result<gate::ChallengeView, UpdaterError> {
    let _operation = state.operation.try_lock().map_err(|_| busy_error())?;
    let (session_snapshot, prepared_sha) = {
        let inner = inner_lock(&state);
        let session = inner
            .session
            .as_ref()
            .filter(|value| value.id == update_id)
            .ok_or_else(session_invalid)?;
        let prepared = session
            .prepared
            .as_ref()
            .ok_or_else(|| UpdaterError::new("E_UPDATER_INTERNAL", "安装包尚未准备完成", true))?;
        (session.clone(), prepared.sha256.clone())
    };

    let install_id = marker::install_id(&app)?;
    let refreshed = recheck_release(&app, &session_snapshot, &install_id).await?;

    let mut inner = inner_lock(&state);
    let (session_id, release_id, sha256) = {
        let session = inner
            .session
            .as_ref()
            .filter(|value| value.id == update_id)
            .ok_or_else(session_invalid)?;
        let prepared = session
            .prepared
            .as_ref()
            .ok_or_else(|| UpdaterError::new("E_UPDATER_INTERNAL", "安装包尚未准备完成", true))?;
        if prepared.sha256 != prepared_sha {
            return Err(session_invalid());
        }
        ensure_release_unchanged(&session.manifest, &refreshed)?;
        (
            session.id.clone(),
            session.manifest.release_id.clone(),
            prepared.sha256.clone(),
        )
    };
    log::append(
        &app,
        "release_recheck_ok",
        "Locking",
        None,
        "info",
        json!({ "releaseId": &release_id }),
    );
    let challenge = gate::Challenge::issue(&session_id, &release_id, &sha256);
    let view = challenge.view();
    inner.challenge = Some(challenge);
    inner.receipt = None;
    Ok(view)
}

/// 提交锁库结果：只接受与挑战、会话、字节绑定的完整干净证据。
#[tauri::command]
pub fn updater_confirm_lock(
    app: AppHandle,
    state: State<'_, UpdaterState>,
    app_state: State<'_, AppState>,
    challenge: String,
    outcome: LockOutcome,
) -> Result<gate::ReceiptView, UpdaterError> {
    let _operation = state.operation.try_lock().map_err(|_| busy_error())?;
    let mut inner = inner_lock(&state);
    let Some(current) = inner
        .challenge
        .take()
        .filter(|value| value.id() == challenge)
    else {
        return Err(lock_unknown("锁库挑战不存在或已被替换"));
    };
    if current.is_expired(Instant::now()) {
        return Err(lock_unknown("锁库挑战已过期"));
    }
    let (session_id, release_id, sha256) = {
        let session = inner
            .session
            .as_ref()
            .filter(|value| value.id == current.session_id())
            .ok_or_else(|| lock_unknown("锁库会话已失效"))?;
        let prepared = session
            .prepared
            .as_ref()
            .ok_or_else(|| lock_unknown("安装包尚未准备完成"))?;
        (
            session.id.clone(),
            session.manifest.release_id.clone(),
            prepared.sha256.clone(),
        )
    };
    if !current.matches(&session_id, &release_id, &sha256) {
        return Err(lock_unknown("锁库挑战与当前会话不一致"));
    }

    let worker_alive = app_state.is_worker_alive();
    let session_alive = app_state.has_verthys_session();
    let clean = outcome.clean
        && outcome.flushed
        && !outcome.dirty
        && outcome.errors.is_empty()
        && !worker_alive
        && !session_alive;
    if !clean {
        let code = if outcome.dirty {
            "E_UPDATER_LOCK_DIRTY"
        } else {
            "E_UPDATER_LOCK_FAILED"
        };
        log::append(
            &app,
            "lock_failed",
            "Locking",
            Some(code),
            "error",
            json!({
                "flushed": outcome.flushed,
                "dirty": outcome.dirty,
                "errors": outcome.errors.len(),
                "workerAlive": worker_alive,
                "sessionAlive": session_alive,
            }),
        );
        return Err(UpdaterError::new(
            code,
            "锁库结果不完整或会话未完全关闭",
            true,
        ));
    }

    let receipt = gate::Receipt::issue(&session_id, &release_id, &sha256);
    let view = receipt.view();
    inner.receipt = Some(receipt);
    log::append(
        &app,
        "lock_ok",
        "Locking",
        None,
        "info",
        json!({ "durationMs": outcome.duration_ms }),
    );
    Ok(view)
}

/// 放弃当前锁库挑战；保留已准备字节，允许重新走锁库流程。
#[tauri::command]
pub fn updater_abort_lock(state: State<'_, UpdaterState>) -> Result<(), UpdaterError> {
    let _operation = state.operation.try_lock().map_err(|_| busy_error())?;
    let mut inner = inner_lock(&state);
    inner.challenge = None;
    inner.receipt = None;
    Ok(())
}

/// 安装已准备的更新；安装器接管后进程退出。
#[tauri::command]
pub fn updater_install(
    app: AppHandle,
    state: State<'_, UpdaterState>,
    update_id: String,
    receipt: String,
) -> Result<(), UpdaterError> {
    let _operation = state.operation.try_lock().map_err(|_| busy_error())?;
    let state_ref: &UpdaterState = &state;
    let generation = state_ref.generation.load(Ordering::SeqCst);

    let (update, prepared, manifest) = {
        let mut inner = inner_lock(state_ref);
        let Some(current) = inner.receipt.take().filter(|value| value.id() == receipt) else {
            return Err(lock_unknown("安装回执不存在或已被使用"));
        };
        if current.is_expired(Instant::now()) {
            return Err(lock_unknown("安装回执已过期"));
        }
        let session = inner
            .session
            .as_ref()
            .filter(|value| value.id == update_id)
            .ok_or_else(session_invalid)?;
        let prepared = session
            .prepared
            .as_ref()
            .ok_or_else(|| UpdaterError::new("E_UPDATER_INTERNAL", "安装包尚未准备完成", true))?;
        if !current.matches(&session.id, &session.manifest.release_id, &prepared.sha256) {
            return Err(lock_unknown("安装回执与当前会话不一致"));
        }
        (
            session.update.clone(),
            prepared.clone(),
            session.manifest.clone(),
        )
    };

    precheck::run(&app, &manifest).inspect_err(|error| {
        log::append(
            &app,
            "precheck_blocked",
            "Precheck",
            Some(&error.code),
            "warn",
            json!({}),
        );
    })?;
    verify_prepared(&app, &prepared, &manifest, &update.signature).inspect_err(|error| {
        log::append(
            &app,
            verification_event(&error.code),
            "Verifying",
            Some(&error.code),
            "error",
            json!({}),
        );
    })?;
    // 预检期间用户可能取消：代际号变化或会话消失都必须阻止安装器启动。
    if state_ref.generation.load(Ordering::SeqCst) != generation {
        return Err(cancelled_error());
    }
    {
        let inner = inner_lock(state_ref);
        if !inner
            .session
            .as_ref()
            .is_some_and(|value| value.id == update_id)
        {
            return Err(cancelled_error());
        }
    }
    let _install_lock = precheck::InstallLock::acquire()?;

    precheck::ensure_lkg_space(&app, manifest.size)?;
    let previous = lkg::current(&app)?;
    let candidate = lkg::stage_candidate(&app, &manifest, &prepared, &update.signature)?;
    marker::write_pending(
        &app,
        &manifest,
        &prepared,
        &update_id,
        previous,
        Some(candidate),
    )?;
    {
        let mut inner = inner_lock(state_ref);
        inner.challenge = None;
        inner.receipt = None;
    }
    log::append(
        &app,
        "install_handoff",
        "Installing",
        None,
        "info",
        json!({ "releaseId": manifest.release_id }),
    );

    match update.install(&prepared.bytes) {
        Ok(()) => Ok(()),
        Err(error) => {
            // 安装器未启动时回滚标记：否则下次启动会把未发生的安装误判为
            // “安装进行中”，用户取消提权后尤其明显。
            if let Ok(path) = marker::pending_path(&app) {
                let _ = std::fs::remove_file(path);
            }
            let mapped = if elevation_denied(&error) {
                UpdaterError::new(
                    "E_UPDATER_ELEVATION_DENIED",
                    "用户未允许管理员权限，安装器未启动",
                    true,
                )
            } else {
                plugin_error(error)
            };
            log::append(
                &app,
                "install_failed",
                "Installing",
                Some(&mapped.code),
                "error",
                json!({ "releaseId": manifest.release_id }),
            );
            Err(mapped)
        }
    }
}

/// 取消更新：下载在途时立即中断；检查、锁库与安装移交必须串行完成，不接受取消。
#[tauri::command]
pub fn updater_cancel(app: AppHandle, state: State<'_, UpdaterState>) -> Result<(), UpdaterError> {
    let state_ref: &UpdaterState = &state;
    let slot = cancel_lock(state_ref).take();
    // 下载在途时立即中断；没有取消槽说明正处于检查、锁库或安装移交，
    // 这些阶段必须串行完成，不能用取消把会话从中间清掉。
    let _operation = if slot.is_none() {
        Some(state_ref.operation.try_lock().map_err(|_| busy_error())?)
    } else {
        None
    };
    let _ = state_ref.generation.fetch_add(1, Ordering::SeqCst);
    if let Some(slot) = slot {
        slot.token.cancel();
    }
    {
        let mut inner = inner_lock(state_ref);
        inner.session = None;
        inner.challenge = None;
        inner.receipt = None;
    }
    state_ref.set_critical(false);
    log::append(&app, "cancelled", "Idle", None, "info", json!({}));
    Ok(())
}

/// 设置/清除“禁止关闭”临界区；由前端在锁库与安装移交期间调用。
#[tauri::command]
pub fn updater_set_critical(
    state: State<'_, UpdaterState>,
    active: bool,
) -> Result<(), UpdaterError> {
    state.set_critical(active);
    Ok(())
}

/// 安装前复验：签名、哈希与 PE 版本必须与准备阶段完全一致。
fn verify_prepared(
    app: &AppHandle,
    prepared: &PreparedBytes,
    manifest: &manifest::ValidatedManifest,
    signature: &str,
) -> Result<(), UpdaterError> {
    if prepared.bytes.len() as u64 != manifest.size {
        return Err(UpdaterError::new(
            "E_UPDATER_SIZE_MISMATCH",
            "安装包大小与清单不一致",
            false,
        ));
    }
    verify::verify_installer(app, &prepared.bytes, signature)?;
    let digest = format!("{:x}", Sha256::digest(&prepared.bytes));
    if digest != prepared.sha256 || digest != manifest.sha256 {
        return Err(UpdaterError::new(
            "E_UPDATER_HASH_MISMATCH",
            "安装包哈希与清单不一致",
            false,
        ));
    }
    let file_version = pe::file_version_from_bytes(&prepared.bytes)?;
    if file_version != prepared.file_version || file_version != manifest.file_version {
        return Err(UpdaterError::new(
            "E_UPDATER_PE_VERSION_MISMATCH",
            "安装包 PE 版本与清单不一致",
            false,
        ));
    }
    // 安装前对同一内存字节再跑一次系统签名验证，覆盖准备后到移交前的窗口。
    let authenticode = manifest::authenticode_config(app)?;
    authenticode::verify_bytes(app, &prepared.bytes, &authenticode)?;
    Ok(())
}
