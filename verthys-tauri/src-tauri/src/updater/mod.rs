/*
 * updater/mod.rs — 本机更新服务入口
 *
 * 职责：检查清单、预检环境、下载安装包、复验签名与哈希、读取 PE 版本、
 * 校验锁库结果、写入更新标记、安装并记录事件。
 *
 * 安全边界：所有准入判定都在 Rust 侧完成；前端只消费结果与展示状态。
 * 检查、准备、安装由操作锁串行化；取消通过令牌与代际号中断在途下载，不排队。
 * 安装只接受与当前会话绑定的有效回执；准备后的字节保存在内存，移交后进程退出。
 */

mod authenticode;
mod error;
mod gate;
mod health;
mod lkg;
mod log;
mod manifest;
mod marker;
mod native;
mod pe;
mod precheck;
mod repair;
mod transport;
mod verify;

use gate::{Challenge, Receipt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::state::AppState;

/// 更新域错误：错误码供前端映射，message 只用于诊断，retryable 指示是否可重试。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdaterError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl UpdaterError {
    fn new(code: &str, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            retryable,
        }
    }
}

impl std::fmt::Display for UpdaterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for UpdaterError {}

/// 锁库结果由前端在 `lockAll` 完成后提交，Rust 侧只接受完整、干净的结果。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockOutcome {
    pub clean: bool,
    pub flushed: bool,
    pub dirty: bool,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub duration_ms: u64,
}

/// 前端可见的更新检查结果。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckResult {
    pub update_id: String,
    pub current_version: String,
    pub version: String,
    pub date: Option<String>,
    pub notes: Option<String>,
    pub release_id: String,
    pub channel: String,
    pub file_version: String,
    pub size: u64,
    pub force_update: bool,
}

/// 准备完成的更新：字节已经过签名、哈希、大小、PE 版本校验。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedUpdate {
    pub update_id: String,
    pub version: String,
    pub release_id: String,
    pub sha256: String,
    pub size: u64,
    pub file_version: String,
}

/// 启动时读取到的更新状态；phase 决定前端应执行自检、等待安装还是进入修复。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupState {
    pub has_pending: bool,
    pub phase: String,
    pub current_version: String,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub release_id: Option<String>,
    pub marker_state: Option<String>,
    pub repair_available: bool,
    pub repair_version: Option<String>,
}

/// 一次更新会话。`Update` 由插件创建，准备阶段产生的字节单独保存。
struct Session {
    id: String,
    update: Update,
    manifest: manifest::ValidatedManifest,
    channel: String,
    prepared: Option<PreparedBytes>,
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            update: self.update.clone(),
            manifest: self.manifest.clone(),
            channel: self.channel.clone(),
            prepared: None,
        }
    }
}

#[derive(Clone, Debug)]
struct PreparedBytes {
    bytes: Vec<u8>,
    sha256: String,
    size: u64,
    file_version: String,
}

/// 会话、挑战与回执集中在同一临界区，避免三者出现跨字段不一致。
#[derive(Default)]
struct UpdaterInner {
    session: Option<Session>,
    challenge: Option<Challenge>,
    receipt: Option<Receipt>,
}

/// 在途下载的取消槽：代际号防止取消命中后续新会话。
struct CancelSlot {
    generation: u64,
    token: CancellationToken,
}

/// 更新服务共享状态。
///
/// 长耗时的检查、下载、安装由 `operation` 串行化；取消不排队，靠令牌与代际号
/// 让在途操作自行退出，避免用户取消后仍要等待操作锁。
pub struct UpdaterState {
    inner: Mutex<UpdaterInner>,
    operation: tokio::sync::Mutex<()>,
    cancel: Mutex<Option<CancelSlot>>,
    generation: AtomicU64,
    critical_until: Mutex<Option<Instant>>,
    health_handled: AtomicBool,
}

impl Default for UpdaterState {
    fn default() -> Self {
        Self {
            inner: Mutex::new(UpdaterInner::default()),
            operation: tokio::sync::Mutex::new(()),
            cancel: Mutex::new(None),
            generation: AtomicU64::new(0),
            critical_until: Mutex::new(None),
            health_handled: AtomicBool::new(false),
        }
    }
}

/// 临界区最长存活时间：安装移交异常时仍必须允许用户关闭窗口。
const CRITICAL_TTL: Duration = Duration::from_secs(180);

impl UpdaterState {
    /// 标记或清除“禁止关闭”窗口；带时限，避免异常路径把应用永久锁住。
    pub fn set_critical(&self, active: bool) {
        let mut guard = self
            .critical_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = if active {
            Some(Instant::now() + CRITICAL_TTL)
        } else {
            None
        };
    }

    pub fn is_critical(&self) -> bool {
        let guard = self
            .critical_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.is_some_and(|until| Instant::now() < until)
    }

    /// 标记前端已触发健康自检；原生兜底据此避免重复弹窗。
    pub fn mark_health_handled(&self) {
        self.health_handled.store(true, Ordering::SeqCst);
    }

    pub fn health_handled(&self) -> bool {
        self.health_handled.load(Ordering::SeqCst)
    }
}

/// 取消槽清理守卫：无论从哪个分支返回，都只在代际号仍匹配时清除，避免误删新槽。
struct CancelSlotGuard<'a> {
    state: &'a UpdaterState,
    generation: u64,
}

impl Drop for CancelSlotGuard<'_> {
    fn drop(&mut self) {
        let mut slot = cancel_lock(self.state);
        if slot
            .as_ref()
            .is_some_and(|value| value.generation == self.generation)
        {
            *slot = None;
        }
    }
}

fn plugin_error(error: tauri_plugin_updater::Error) -> UpdaterError {
    let text = error.to_string();
    let lower = text.to_lowercase();
    if lower.contains("insecure transport") {
        return UpdaterError::new("E_UPDATER_MANIFEST_INVALID", text, false);
    }
    if lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("reqwest")
        || lower.contains("network")
        || lower.contains("connection")
        || lower.contains("could not fetch")
    {
        return UpdaterError::new("E_UPDATER_NETWORK", text, true);
    }
    if lower.contains("different key") || lower.contains("unexpected key") {
        return UpdaterError::new("E_UPDATER_SIG_PUBKEY_MISMATCH", text, false);
    }
    if lower.contains("signature") || lower.contains("minisign") {
        return UpdaterError::new("E_UPDATER_SIG_INVALID", text, false);
    }
    if lower.contains("target") || lower.contains("platform") {
        return UpdaterError::new("E_UPDATER_MANIFEST_INVALID", text, false);
    }
    if lower.contains("version") {
        return UpdaterError::new("E_UPDATER_VERSION_BLOCKED", text, false);
    }
    UpdaterError::new("E_UPDATER_INTERNAL", text, true)
}

fn inner_lock(state: &UpdaterState) -> MutexGuard<'_, UpdaterInner> {
    state
        .inner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn cancel_lock(state: &UpdaterState) -> MutexGuard<'_, Option<CancelSlot>> {
    state
        .cancel
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn busy_error() -> UpdaterError {
    UpdaterError::new("E_UPDATER_BUSY", "已有更新操作在进行", true)
}

fn cancelled_error() -> UpdaterError {
    UpdaterError::new("E_UPDATER_CANCELLED", "更新已取消", false)
}

fn session_invalid() -> UpdaterError {
    UpdaterError::new("E_UPDATER_SESSION_INVALID", "更新会话不存在或已失效", true)
}

fn lock_unknown(message: impl Into<String>) -> UpdaterError {
    UpdaterError::new("E_UPDATER_LOCK_UNKNOWN", message, true)
}

fn current_version(app: &AppHandle) -> String {
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
fn verification_event(code: &str) -> &'static str {
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
fn validate_downloaded<F>(
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
fn ensure_release_unchanged(
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
async fn recheck_release(
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
    let challenge = Challenge::issue(&session_id, &release_id, &sha256);
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

    let receipt = Receipt::issue(&session_id, &release_id, &sha256);
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
            let mapped = plugin_error(error);
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

impl From<UpdaterError> for String {
    fn from(value: UpdaterError) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_release_unchanged, plugin_error, validate_downloaded, verification_event,
        UpdaterError,
    };
    use crate::updater::manifest::ValidatedManifest;

    fn manifest_fixture(version: &str, sha256: &str) -> ValidatedManifest {
        ValidatedManifest {
            release_id: format!("20261023-120000-{version}-b5e487ad"),
            channel: "local".into(),
            version: version.into(),
            force_update: false,
            size: 1024,
            sha256: sha256.into(),
            file_version: version.into(),
            download_url: "http://127.0.0.1:8765/installer.exe".into(),
            allowed_download_hosts: vec!["127.0.0.1".into()],
        }
    }

    #[test]
    fn release_recheck_accepts_identical_release() {
        let current = manifest_fixture("4.1.6", &"a".repeat(64));
        let refreshed = manifest_fixture("4.1.6", &"a".repeat(64));
        assert!(ensure_release_unchanged(&current, &refreshed).is_ok());
    }

    #[test]
    fn release_recheck_rejects_changed_release_or_bytes() {
        let current = manifest_fixture("4.1.6", &"a".repeat(64));
        let changed_version = manifest_fixture("4.1.7", &"a".repeat(64));
        let changed_bytes = manifest_fixture("4.1.6", &"b".repeat(64));
        assert_eq!(
            ensure_release_unchanged(&current, &changed_version)
                .unwrap_err()
                .code,
            "E_UPDATER_INSTALL_REVOKED"
        );
        assert_eq!(
            ensure_release_unchanged(&current, &changed_bytes)
                .unwrap_err()
                .code,
            "E_UPDATER_INSTALL_REVOKED"
        );
    }
    use sha2::{Digest, Sha256};
    use std::path::Path;

    fn plugin_minisign(error: minisign_verify::Error) -> tauri_plugin_updater::Error {
        tauri_plugin_updater::Error::Minisign(error)
    }

    #[test]
    fn key_id_mismatch_is_distinguished() {
        let mapped = plugin_error(plugin_minisign(minisign_verify::Error::UnexpectedKeyId));
        assert_eq!(mapped.code, "E_UPDATER_SIG_PUBKEY_MISMATCH");
    }

    #[test]
    fn invalid_signature_maps_to_signature_error() {
        let mapped = plugin_error(plugin_minisign(minisign_verify::Error::InvalidSignature));
        assert_eq!(mapped.code, "E_UPDATER_SIG_INVALID");
    }

    #[test]
    fn error_display_contains_code() {
        let error: UpdaterError = UpdaterError::new("E_UPDATER_NETWORK", "timeout", true);
        assert!(error.to_string().contains("E_UPDATER_NETWORK"));
    }

    #[test]
    fn verification_failures_map_to_specific_events() {
        assert_eq!(
            verification_event("E_UPDATER_SIZE_MISMATCH"),
            "size_mismatch"
        );
        assert_eq!(
            verification_event("E_UPDATER_HASH_MISMATCH"),
            "hash_mismatch"
        );
        assert_eq!(
            verification_event("E_UPDATER_PE_VERSION_MISMATCH"),
            "pe_version_mismatch"
        );
        assert_eq!(verification_event("E_UPDATER_SIG_INVALID"), "sig_invalid");
        assert_eq!(
            verification_event("E_UPDATER_SIG_PUBKEY_MISMATCH"),
            "pubkey_mismatch"
        );
        assert_eq!(verification_event("E_UPDATER_NETWORK"), "download_failed");
    }

    #[test]
    fn webview_capabilities_expose_no_updater_commands() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities/default.json");
        let payload = std::fs::read(&path).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let permissions = value["permissions"]
            .as_array()
            .expect("capability permissions must be an array");
        assert!(
            permissions
                .iter()
                .filter_map(serde_json::Value::as_str)
                .all(|permission| !permission.starts_with("updater:")),
            "webview must not be able to invoke updater plugin commands"
        );
    }

    #[test]
    fn validates_downloaded_bytes_and_rejects_mismatch() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let manifest_path = root.join("build/updater/latest.json");
        if !manifest_path.exists() {
            return;
        }
        let latest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let platform = &latest["platforms"]["windows-x86_64"];
        let url = platform["url"].as_str().unwrap();
        let file_name = url.rsplit('/').next().unwrap();
        let installer = manifest_path.parent().unwrap().join(file_name);
        let signature = installer.with_file_name(format!("{file_name}.sig"));
        if !installer.exists() || !signature.exists() {
            return;
        }
        let version = latest["version"].as_str().unwrap().to_string();
        let file_version = platform["file_version"].as_str().unwrap().to_string();
        let config: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("verthys-tauri/src-tauri/tauri.conf.json")).unwrap(),
        )
        .unwrap();
        let pubkey = config["plugins"]["updater"]["pubkey"].as_str().unwrap();
        let bytes = std::fs::read(&installer).unwrap();
        let signature_text = std::fs::read_to_string(&signature).unwrap();
        let signature_text = signature_text.trim();
        let expected_size = bytes.len() as u64;
        let expected_hash = format!("{:x}", Sha256::digest(&bytes));
        let manifest = super::manifest::ValidatedManifest {
            release_id: "test-release".to_string(),
            channel: "local".to_string(),
            version,
            force_update: false,
            size: expected_size,
            sha256: expected_hash,
            file_version: file_version.clone(),
            download_url: "http://127.0.0.1:8765/installer.exe".to_string(),
            allowed_download_hosts: vec!["127.0.0.1".to_string()],
        };

        let prepared = validate_downloaded(bytes.clone(), &manifest, |data| {
            super::verify::verify_bytes_with_pubkey(pubkey, data, signature_text)
        })
        .unwrap();
        assert_eq!(prepared.file_version, file_version);

        let mut wrong_version = manifest.clone();
        wrong_version.file_version = "9.9.9".to_string();
        let error = validate_downloaded(bytes.clone(), &wrong_version, |_| Ok(())).unwrap_err();
        assert_eq!(error.code, "E_UPDATER_PE_VERSION_MISMATCH");

        let mut wrong_hash = manifest;
        wrong_hash.sha256 = "0".repeat(64);
        let error = validate_downloaded(bytes, &wrong_hash, |_| Ok(())).unwrap_err();
        assert_eq!(error.code, "E_UPDATER_HASH_MISMATCH");
    }
}
