use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tauri_plugin_updater::Update;
use tokio_util::sync::CancellationToken;

use super::gate::{Challenge, Receipt};
use super::manifest;

/// 更新域错误：错误码供前端映射，message 只用于诊断，retryable 指示是否可重试。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdaterError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl UpdaterError {
    pub(super) fn new(code: &str, message: impl Into<String>, retryable: bool) -> Self {
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
pub(super) struct Session {
    pub(super) id: String,
    pub(super) update: Update,
    pub(super) manifest: manifest::ValidatedManifest,
    pub(super) channel: String,
    pub(super) prepared: Option<PreparedBytes>,
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
pub(super) struct PreparedBytes {
    pub(super) bytes: Vec<u8>,
    pub(super) sha256: String,
    pub(super) size: u64,
    pub(super) file_version: String,
}

/// 会话、挑战与回执集中在同一临界区，避免三者出现跨字段不一致。
#[derive(Default)]
pub(super) struct UpdaterInner {
    pub(super) session: Option<Session>,
    pub(super) challenge: Option<Challenge>,
    pub(super) receipt: Option<Receipt>,
}

/// 在途下载的取消槽：代际号防止取消命中后续新会话。
pub(super) struct CancelSlot {
    pub(super) generation: u64,
    pub(super) token: CancellationToken,
}

/// 更新服务共享状态。
///
/// 长耗时的检查、下载、安装由 `operation` 串行化；取消不排队，靠令牌与代际号
/// 让在途操作自行退出，避免用户取消后仍要等待操作锁。
pub struct UpdaterState {
    inner: Mutex<UpdaterInner>,
    pub(super) operation: tokio::sync::Mutex<()>,
    cancel: Mutex<Option<CancelSlot>>,
    pub(super) generation: AtomicU64,
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
pub(super) struct CancelSlotGuard<'a> {
    pub(super) state: &'a UpdaterState,
    pub(super) generation: u64,
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

/// ShellExecute 在用户取消提权时以 ERROR_CANCELLED 返回，安装器没有真正启动。
pub(super) fn elevation_denied(error: &tauri_plugin_updater::Error) -> bool {
    matches!(
        error,
        tauri_plugin_updater::Error::Io(source)
            if source.raw_os_error() == Some(windows::Win32::Foundation::ERROR_CANCELLED.0 as i32)
    )
}

pub(super) fn plugin_error(error: tauri_plugin_updater::Error) -> UpdaterError {
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

pub(super) fn inner_lock(state: &UpdaterState) -> MutexGuard<'_, UpdaterInner> {
    state
        .inner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(super) fn cancel_lock(state: &UpdaterState) -> MutexGuard<'_, Option<CancelSlot>> {
    state
        .cancel
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(super) fn busy_error() -> UpdaterError {
    UpdaterError::new("E_UPDATER_BUSY", "已有更新操作在进行", true)
}

pub(super) fn cancelled_error() -> UpdaterError {
    UpdaterError::new("E_UPDATER_CANCELLED", "更新已取消", false)
}

pub(super) fn session_invalid() -> UpdaterError {
    UpdaterError::new("E_UPDATER_SESSION_INVALID", "更新会话不存在或已失效", true)
}

pub(super) fn lock_unknown(message: impl Into<String>) -> UpdaterError {
    UpdaterError::new("E_UPDATER_LOCK_UNKNOWN", message, true)
}

impl From<UpdaterError> for String {
    fn from(value: UpdaterError) -> Self {
        value.to_string()
    }
}
