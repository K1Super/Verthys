use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_updater::UpdaterExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::startup::audit_config;
use super::types::{
    busy_error, cancel_lock, cancelled_error, inner_lock, plugin_error, session_invalid,
    CancelSlot, CancelSlotGuard, PreparedBytes, PreparedUpdate, Session, UpdateCheckResult,
    UpdaterError, UpdaterState,
};
use super::{authenticode, log, manifest, marker, pe, precheck, transport, verify};

pub(super) fn current_version(app: &AppHandle) -> String {
    app.package_info().version.to_string()
}

/// 检查更新并保存会话；返回 `None` 表示没有可用更新。
#[tauri::command]
pub async fn updater_check(
    app: AppHandle,
    state: State<'_, UpdaterState>,
) -> Result<Option<UpdateCheckResult>, UpdaterError> {
    audit_config(&app)?;
    let channel = manifest::configured_channel(&app)?;
    let _operation = state.operation.try_lock().map_err(|_| busy_error())?;
    let generation = state.generation.load(Ordering::SeqCst);
    *cancel_lock(&state) = None;

    log::append(
        &app,
        "check_sent",
        "Checking",
        None,
        "info",
        json!({ "channel": channel }),
    );
    // 检查必须在上限内结束：端点无响应时若沿用插件默认的无超时行为，界面会
    // 永久停在“检查中”，且并发保护会让后续手动检查全部被拒绝。
    let updater = app
        .updater_builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(plugin_error)?;
    // 外层再包一层总时限：端点数量增加时，单请求超时无法保证整体在 30 s 内结束。
    let update =
        match tokio::time::timeout(std::time::Duration::from_secs(30), updater.check()).await {
            Ok(result) => result.map_err(|error| {
                let mapped = plugin_error(error);
                log::append(
                    &app,
                    "check_failed",
                    "Checking",
                    Some(&mapped.code),
                    "error",
                    json!({}),
                );
                mapped
            })?,
            Err(_) => {
                let mapped = UpdaterError::new("E_UPDATER_NETWORK", "检查更新超时", true);
                log::append(
                    &app,
                    "check_failed",
                    "Checking",
                    Some(&mapped.code),
                    "error",
                    json!({ "reason": "timeout" }),
                );
                return Err(mapped);
            }
        };
    let Some(update) = update else {
        log::append(&app, "check_miss", "Checking", None, "info", json!({}));
        return Ok(None);
    };

    let install_id = marker::install_id(&app)?;
    let validated = match manifest::validate(&app, &update, &channel, &install_id) {
        Ok(Some(value)) => value,
        Ok(None) => {
            log::append(&app, "check_miss", "Checking", None, "info", json!({}));
            return Ok(None);
        }
        Err(error) => {
            let event = if error.code == "E_UPDATER_MANIFEST_SIG_INVALID" {
                "manifest_sig_invalid"
            } else {
                "manifest_invalid"
            };
            log::append(
                &app,
                event,
                "Checking",
                Some(&error.code),
                "error",
                json!({}),
            );
            return Err(error);
        }
    };

    let update_id = Uuid::new_v4().to_string();
    let result = UpdateCheckResult {
        update_id: update_id.clone(),
        current_version: update.current_version.clone(),
        version: update.version.clone(),
        date: update.date.map(|value| value.to_string()),
        notes: update.body.clone(),
        release_id: validated.release_id.clone(),
        channel: validated.channel.clone(),
        file_version: validated.file_version.clone(),
        size: validated.size,
        force_update: validated.force_update,
    };

    {
        let mut guard = inner_lock(&state);
        if state.generation.load(Ordering::SeqCst) != generation {
            return Err(cancelled_error());
        }
        guard.session = Some(Session {
            id: update_id,
            update,
            manifest: validated,
            channel,
            prepared: None,
        });
        guard.challenge = None;
        guard.receipt = None;
    }

    log::append(
        &app,
        "check_hit",
        "Checking",
        None,
        "info",
        json!({
            "releaseId": result.release_id,
            "toVersion": result.version,
            "size": result.size,
        }),
    );
    Ok(Some(result))
}

/// 预检并下载安装包；完成后字节已通过全部静态校验。
#[tauri::command]
pub async fn updater_prepare(
    app: AppHandle,
    state: State<'_, UpdaterState>,
    update_id: String,
) -> Result<PreparedUpdate, UpdaterError> {
    let _operation = state.operation.try_lock().map_err(|_| busy_error())?;
    let state_ref: &UpdaterState = &state;
    let generation = state_ref.generation.load(Ordering::SeqCst);
    let session = {
        let guard = inner_lock(state_ref);
        guard
            .session
            .as_ref()
            .filter(|value| value.id == update_id)
            .cloned()
            .ok_or_else(session_invalid)?
    };

    precheck::run(&app, &session.manifest).inspect_err(|error| {
        log::append(
            &app,
            "precheck_blocked",
            "Precheck",
            Some(&error.code),
            "warn",
            json!({}),
        );
    })?;

    let total = session.manifest.size;
    if total > manifest::MAX_INSTALLER_BYTES {
        return Err(UpdaterError::new(
            "E_UPDATER_SIZE_MISMATCH",
            "安装包超过允许的最大字节数",
            false,
        ));
    }

    let cancel_token = CancellationToken::new();
    {
        let mut slot = cancel_lock(state_ref);
        *slot = Some(CancelSlot {
            generation,
            token: cancel_token.clone(),
        });
    }
    let _cancel_guard = CancelSlotGuard {
        state: state_ref,
        generation,
    };

    let url = reqwest::Url::parse(&session.manifest.download_url)
        .map_err(|_| UpdaterError::new("E_UPDATER_MANIFEST_INVALID", "下载地址无法解析", false))?;
    // 明文下载必须由配置显式开启；开启后仍受主机白名单与全部字节校验约束。
    let allow_insecure = session.channel == "local" || manifest::insecure_transport(&app);
    let spec = transport::DownloadSpec {
        url,
        expected_size: total,
        allow_http: allow_insecure,
        allow_loopback: session.channel == "local",
        allowed_hosts: session.manifest.allowed_download_hosts.clone(),
        no_proxy: session.channel == "local",
    };
    let deadline = Instant::now() + Duration::from_secs(600);

    let mut attempt = 0u8;
    let bytes = loop {
        attempt += 1;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let timeout = UpdaterError::new("E_UPDATER_NETWORK", "下载总时长超限", true);
            log::append(
                &app,
                "download_failed",
                "Downloading",
                Some(&timeout.code),
                "error",
                json!({ "attempt": attempt }),
            );
            return Err(timeout);
        }
        let _ = app.emit(
            "updater://progress",
            json!({ "event": "Started", "data": { "contentLength": total } }),
        );
        log::append(
            &app,
            "download_start",
            "Downloading",
            None,
            "info",
            json!({ "attempt": attempt }),
        );
        let progress_app = app.clone();
        let mut last_emit = Instant::now();
        let mut pending_bytes = 0usize;
        match transport::download(&spec, &cancel_token, remaining, move |chunk_length, _| {
            pending_bytes += chunk_length;
            if last_emit.elapsed() >= Duration::from_millis(100) {
                let _ = progress_app.emit(
                    "updater://progress",
                    json!({
                        "event": "Progress",
                        "data": { "chunkLength": pending_bytes }
                    }),
                );
                pending_bytes = 0;
                last_emit = Instant::now();
            }
        })
        .await
        {
            Ok(bytes) => break bytes,
            Err(mapped) => {
                if mapped.code == "E_UPDATER_CANCELLED" {
                    return Err(mapped);
                }
                let event = verification_event(&mapped.code);
                if attempt >= 4 || !mapped.retryable {
                    log::append(
                        &app,
                        event,
                        "Downloading",
                        Some(&mapped.code),
                        "error",
                        json!({ "attempt": attempt }),
                    );
                    return Err(mapped);
                }
                let delay = match attempt {
                    1 => 2,
                    2 => 5,
                    _ => 10,
                };
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        }
    };

    log::append(
        &app,
        "download_success",
        "Downloading",
        None,
        "info",
        json!({ "bytes": bytes.len(), "attempt": attempt }),
    );
    let _ = app.emit(
        "updater://progress",
        json!({ "event": "Finished", "data": {} }),
    );
    let prepared = validate_downloaded(bytes, &session.manifest, |data| {
        verify::verify_installer(&app, data, &session.update.signature)
    })
    .inspect_err(|error| {
        log::append(
            &app,
            verification_event(&error.code),
            "Verifying",
            Some(&error.code),
            "error",
            json!({}),
        );
    })?;

    // Authenticode 是独立信任根：在内存校验通过后写入临时副本交给系统验证，
    // 失败立即中止，不进入锁库与安装。生产渠道由配置审计强制开启。
    let authenticode_config = manifest::authenticode_config(&app)?;
    if authenticode_config.require {
        let app_for_auth = app.clone();
        let bytes_for_auth = prepared.bytes.clone();
        let auth = tokio::task::spawn_blocking(move || {
            authenticode::verify_bytes(&app_for_auth, &bytes_for_auth, &authenticode_config)
        })
        .await
        .map_err(|error| {
            UpdaterError::new(
                "E_UPDATER_AUTHENTICODE_INVALID",
                format!("Authenticode 验证任务失败: {error}"),
                false,
            )
        })?;
        match auth {
            Ok(Some(identity)) => log::append(
                &app,
                "authenticode_ok",
                "Verifying",
                None,
                "info",
                json!({
                    "subject": identity.subject,
                    "thumbprint": &identity.thumbprint[..8],
                }),
            ),
            Ok(None) => {}
            Err(error) => {
                log::append(
                    &app,
                    "authenticode_invalid",
                    "Verifying",
                    Some(&error.code),
                    "error",
                    json!({}),
                );
                return Err(error);
            }
        }
    } else {
        log::append(
            &app,
            "authenticode_skipped",
            "Verifying",
            None,
            "info",
            json!({}),
        );
    }

    let sha256 = prepared.sha256.clone();
    let file_version = prepared.file_version.clone();
    {
        let mut guard = inner_lock(state_ref);
        if state_ref.generation.load(Ordering::SeqCst) != generation {
            return Err(cancelled_error());
        }
        let Some(current) = guard.session.as_mut().filter(|value| value.id == update_id) else {
            return Err(cancelled_error());
        };
        current.prepared = Some(prepared);
        guard.challenge = None;
        guard.receipt = None;
    }

    log::append(
        &app,
        "sig_ok",
        "Verifying",
        None,
        "info",
        json!({ "releaseId": session.manifest.release_id }),
    );
    log::append(
        &app,
        "hash_ok",
        "Verifying",
        None,
        "info",
        json!({ "hashPrefix": &sha256[..12] }),
    );

    Ok(PreparedUpdate {
        update_id,
        version: session.update.version.clone(),
        release_id: session.manifest.release_id,
        sha256,
        size: session.manifest.size,
        file_version,
    })
}

/// 把校验错误码映射为稳定的本地事件名；用户文案与事件名互不替代。
pub(super) fn verification_event(code: &str) -> &'static str {
    match code {
        "E_UPDATER_SIZE_MISMATCH" => "size_mismatch",
        "E_UPDATER_HASH_MISMATCH" => "hash_mismatch",
        "E_UPDATER_PE_VERSION_MISMATCH" => "pe_version_mismatch",
        "E_UPDATER_SIG_INVALID" => "sig_invalid",
        "E_UPDATER_SIG_PUBKEY_MISMATCH" => "pubkey_mismatch",
        "E_UPDATER_AUTHENTICODE_INVALID" => "authenticode_invalid",
        _ => "download_failed",
    }
}

/// 对下载字节执行大小、签名、哈希与 PE 版本校验；闭包用于注入签名验证入口。
///
/// 入参按所有权接收，校验通过后直接复用同一块缓冲，避免大安装包在校验边界
/// 复制出第二份内存。
pub(super) fn validate_downloaded<F>(
    bytes: Vec<u8>,
    manifest: &manifest::ValidatedManifest,
    verify_signature: F,
) -> Result<PreparedBytes, UpdaterError>
where
    F: FnOnce(&[u8]) -> Result<(), UpdaterError>,
{
    if bytes.len() as u64 != manifest.size {
        return Err(UpdaterError::new(
            "E_UPDATER_SIZE_MISMATCH",
            "安装包大小与清单不一致",
            false,
        ));
    }
    verify_signature(&bytes)?;
    let digest = Sha256::digest(&bytes);
    let sha256 = format!("{:x}", digest);
    if sha256 != manifest.sha256 {
        return Err(UpdaterError::new(
            "E_UPDATER_HASH_MISMATCH",
            "安装包哈希与清单不一致",
            false,
        ));
    }
    let file_version = pe::file_version_from_bytes(&bytes)?;
    if file_version != manifest.file_version {
        return Err(UpdaterError::new(
            "E_UPDATER_PE_VERSION_MISMATCH",
            "安装包 PE 版本与清单不一致",
            false,
        ));
    }
    Ok(PreparedBytes {
        bytes,
        sha256,
        size: manifest.size,
        file_version,
    })
}

/// 发布已撤回或已变更：不允许继续安装已下载的旧发布。
fn withdrawn_error() -> UpdaterError {
    UpdaterError::new(
        "E_UPDATER_INSTALL_REVOKED",
        "发布已撤回或变更，安装已中止",
        false,
    )
}

/// 复检后的发布必须与已准备会话完全一致；版本、字节或版本身份变化都拒绝。
pub(super) fn ensure_release_unchanged(
    current: &manifest::ValidatedManifest,
    refreshed: &manifest::ValidatedManifest,
) -> Result<(), UpdaterError> {
    let same = current.release_id == refreshed.release_id
        && current.version == refreshed.version
        && current.sha256 == refreshed.sha256
        && current.size == refreshed.size
        && current.file_version == refreshed.file_version;
    if same {
        Ok(())
    } else {
        Err(withdrawn_error())
    }
}

/// 锁库前在线复检清单：暂停、撤回、灰度排除或发布变更都阻止安装。
///
/// 下载与安装之间可能隔着用户确认与锁库；若发布在此期间被撤回，必须在这里
/// 中止，而不是等安装器接管。网络失败按可重试错误处理，不放行未经确认的发布。
pub(super) async fn recheck_release(
    app: &AppHandle,
    session: &Session,
    install_id: &str,
) -> Result<manifest::ValidatedManifest, UpdaterError> {
    let updater = app
        .updater_builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(plugin_error)?;
    let refreshed = match tokio::time::timeout(Duration::from_secs(10), updater.check()).await {
        Ok(Ok(Some(update))) => update,
        Ok(Ok(None)) => {
            log::append(
                app,
                "release_withdrawn",
                "Locking",
                Some("E_UPDATER_INSTALL_REVOKED"),
                "error",
                json!({ "reason": "missing" }),
            );
            return Err(withdrawn_error());
        }
        Ok(Err(error)) => {
            let mapped = plugin_error(error);
            log::append(
                app,
                "release_recheck_failed",
                "Locking",
                Some(&mapped.code),
                "error",
                json!({}),
            );
            return Err(mapped);
        }
        Err(_) => {
            let mapped = UpdaterError::new("E_UPDATER_NETWORK", "发布复检超时", true);
            log::append(
                app,
                "release_recheck_failed",
                "Locking",
                Some(&mapped.code),
                "error",
                json!({ "reason": "timeout" }),
            );
            return Err(mapped);
        }
    };

    let validated = match manifest::validate(app, &refreshed, &session.channel, install_id) {
        Ok(Some(value)) => value,
        Ok(None) => {
            log::append(
                app,
                "release_withdrawn",
                "Locking",
                Some("E_UPDATER_INSTALL_REVOKED"),
                "error",
                json!({ "reason": "paused_or_rollout" }),
            );
            return Err(withdrawn_error());
        }
        Err(error) => {
            log::append(
                app,
                "release_recheck_failed",
                "Locking",
                Some(&error.code),
                "error",
                json!({}),
            );
            return Err(error);
        }
    };
    ensure_release_unchanged(&session.manifest, &validated).inspect_err(|error| {
        log::append(
            app,
            "release_withdrawn",
            "Locking",
            Some(&error.code),
            "error",
            json!({}),
        );
    })?;
    Ok(validated)
}
