/*
 * updater/marker.rs — 更新标记、安装标识与归档
 *
 * 安装器接管后进程退出，重启时判断“这次启动由更新触发”只能读取磁盘标记。
 * 标记同时承载健康自检所需的物料身份、回退物料与代际信息；任何字段解析失败
 * 都必须显式隔离并进入修复路径，不能当作“没有更新”静默跳过。
 */

use super::manifest::ValidatedManifest;
use super::PreparedBytes;
use super::UpdaterError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};
use uuid::Uuid;
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

/// 当前标记结构版本；旧版本在读取时迁移，写回时统一升级。
pub const MARKER_SCHEMA: u32 = 2;

/// 安装进行中的判定窗口：超过该时长仍未出现新版本，视为安装失败。
pub const INSTALL_SETTLE_WINDOW_MINUTES: i64 = 15;

/// 历史归档保留数量；配合按时间排序，防止目录无限增长。
const HISTORY_KEEP: usize = 10;

/// 回退物料身份；路径、哈希、版本与签名必须成组校验。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LkgRecord {
    pub path: String,
    pub sha256: String,
    pub version: String,
    pub file_version: String,
    pub release_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingMarker {
    pub schema_version: u32,
    #[serde(default)]
    pub install_session_id: String,
    pub release_id: String,
    pub from_version: String,
    pub to_version: String,
    pub installer_sha256: String,
    pub installer_size: u64,
    pub file_version: String,
    #[serde(default)]
    pub lkg: Option<LkgRecord>,
    #[serde(default)]
    pub candidate: Option<LkgRecord>,
    pub created_at: String,
    #[serde(default)]
    pub handoff_at: String,
    pub nonce: String,
    pub owner_pid: u32,
    pub state: String,
    pub detail: Option<String>,
}

const ALLOWED_STATES: [&str; 6] = [
    "install_handoff",
    "health_confirmed",
    "rolled_back",
    "install_failed",
    "repair_started",
    "repair_confirmed",
];

pub(crate) fn updater_dir(app: &AppHandle) -> Result<PathBuf, UpdaterError> {
    let base = app.path().app_data_dir().map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法解析应用数据目录: {error}"),
            true,
        )
    })?;
    let dir = base.join("updater");
    std::fs::create_dir_all(&dir).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法创建更新目录: {error}"),
            true,
        )
    })?;
    Ok(dir)
}

pub(crate) fn pending_path(app: &AppHandle) -> Result<PathBuf, UpdaterError> {
    Ok(updater_dir(app)?.join("pending.json"))
}

/// 读取或创建安装标识；灰度 bucket 只依赖该随机标识，不使用设备指纹。
pub fn install_id(app: &AppHandle) -> Result<String, UpdaterError> {
    let path = updater_dir(app)?.join("install_id");
    if let Ok(value) = std::fs::read_to_string(&path) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let value = Uuid::new_v4().to_string();
    std::fs::write(&path, value.as_bytes()).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法写入安装标识: {error}"),
            true,
        )
    })?;
    Ok(value)
}

/// 安装前原子写入标记；失败即中止安装。
pub fn write_pending(
    app: &AppHandle,
    manifest: &ValidatedManifest,
    prepared: &PreparedBytes,
    session_id: &str,
    lkg: Option<LkgRecord>,
    candidate: Option<LkgRecord>,
) -> Result<(), UpdaterError> {
    let now = Utc::now().to_rfc3339();
    let marker = PendingMarker {
        schema_version: MARKER_SCHEMA,
        install_session_id: session_id.to_string(),
        release_id: manifest.release_id.clone(),
        from_version: app.package_info().version.to_string(),
        to_version: manifest.version.clone(),
        installer_sha256: prepared.sha256.clone(),
        installer_size: prepared.size,
        file_version: prepared.file_version.clone(),
        lkg,
        candidate,
        created_at: now.clone(),
        handoff_at: now,
        nonce: Uuid::new_v4().to_string(),
        owner_pid: std::process::id(),
        state: "install_handoff".to_string(),
        detail: None,
    };
    let payload = serde_json::to_vec_pretty(&marker).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            format!("更新标记序列化失败: {error}"),
            false,
        )
    })?;
    write_atomic(&pending_path(app)?, &payload)
}

/// 读取标记；文件不存在返回 `None`，结构非法返回错误由调用方隔离。
pub fn read_pending(app: &AppHandle) -> Result<Option<PendingMarker>, UpdaterError> {
    let path = pending_path(app)?;
    let payload = match std::fs::read(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(UpdaterError::new(
                "E_UPDATER_MARKER_INVALID",
                format!("读取更新标记失败: {error}"),
                false,
            ))
        }
    };
    parse_marker(&payload).map(Some)
}

/// 解析并校验标记；旧版本在内存中迁移，字段非法一律拒绝。
fn parse_marker(payload: &[u8]) -> Result<PendingMarker, UpdaterError> {
    let mut marker: PendingMarker = serde_json::from_slice(payload).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            format!("更新标记结构非法: {error}"),
            false,
        )
    })?;

    if marker.schema_version == 1 {
        if marker.handoff_at.is_empty() {
            marker.handoff_at = marker.created_at.clone();
        }
    } else if marker.schema_version != MARKER_SCHEMA {
        return Err(UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            "更新标记版本不受支持",
            false,
        ));
    }

    if marker.release_id.is_empty()
        || marker.release_id.len() > 64
        || !marker
            .release_id
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || value == '-' || value == '.')
    {
        return Err(UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            "更新标记 release_id 非法",
            false,
        ));
    }
    if semver::Version::parse(&marker.to_version).is_err() {
        return Err(UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            "更新标记目标版本非法",
            false,
        ));
    }
    if marker.installer_sha256.len() != 64
        || !marker
            .installer_sha256
            .chars()
            .all(|value| value.is_ascii_hexdigit())
    {
        return Err(UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            "更新标记安装包哈希非法",
            false,
        ));
    }
    if marker.owner_pid == 0 || !ALLOWED_STATES.contains(&marker.state.as_str()) {
        return Err(UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            "更新标记状态非法",
            false,
        ));
    }
    parse_rfc3339(&marker.created_at).ok_or_else(|| {
        UpdaterError::new("E_UPDATER_MARKER_INVALID", "更新标记时间戳非法", false)
    })?;
    parse_rfc3339(&marker.handoff_at).ok_or_else(|| {
        UpdaterError::new("E_UPDATER_MARKER_INVALID", "更新标记移交时间非法", false)
    })?;
    Ok(marker)
}

/// 写入自检结论并归档；返回归档后的标记，供调用方推进回退物料。
pub fn finish_pending(
    app: &AppHandle,
    state: &str,
    detail: Option<&str>,
) -> Result<PendingMarker, UpdaterError> {
    if !ALLOWED_STATES.contains(&state) {
        return Err(UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            "未知的更新结论",
            false,
        ));
    }
    let Some(mut marker) = read_pending(app)? else {
        return Err(UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            "不存在待处理的更新标记",
            false,
        ));
    };
    marker.schema_version = MARKER_SCHEMA;
    marker.state = state.to_string();
    marker.detail = detail.map(str::to_string);
    let payload = serde_json::to_vec_pretty(&marker).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            format!("更新标记序列化失败: {error}"),
            false,
        )
    })?;

    let history_dir = updater_dir(app)?.join("history");
    std::fs::create_dir_all(&history_dir).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            format!("无法创建更新历史目录: {error}"),
            false,
        )
    })?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let history = history_dir.join(format!("{}-{stamp}.json", marker.release_id));
    std::fs::write(&history, &payload).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            format!("无法归档更新标记: {error}"),
            false,
        )
    })?;
    let _ = std::fs::remove_file(pending_path(app)?);
    prune_history(&history_dir, HISTORY_KEEP);
    Ok(marker)
}

/// 将非法标记改名隔离；返回隔离后的路径，便于日志引用。
pub fn quarantine_pending(app: &AppHandle) -> Result<PathBuf, UpdaterError> {
    let path = pending_path(app)?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let target = updater_dir(app)?.join(format!("pending.corrupt-{stamp}.json"));
    std::fs::rename(&path, &target).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            format!("无法隔离更新标记: {error}"),
            false,
        )
    })?;
    Ok(target)
}

/// 计算移交后经过的时长；时间戳非法返回 `None`。
pub fn handoff_age_minutes(marker: &PendingMarker) -> Option<i64> {
    let handoff =
        parse_rfc3339(&marker.handoff_at).or_else(|| parse_rfc3339(&marker.created_at))?;
    Some(Utc::now().signed_duration_since(handoff).num_minutes())
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
}

/// 历史归档按修改时间保留最近若干份，删除旧文件失败不阻断更新。
fn prune_history(dir: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, path))
        })
        .collect();
    files.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    for (_, path) in files.into_iter().skip(keep) {
        let _ = std::fs::remove_file(path);
    }
}

/// 原子写入：同级临时文件 → fsync → 替换目标。
pub(crate) fn write_atomic(path: &Path, payload: &[u8]) -> Result<(), UpdaterError> {
    let parent = path
        .parent()
        .ok_or_else(|| UpdaterError::new("E_UPDATER_MARKER_INVALID", "更新标记路径非法", false))?;
    std::fs::create_dir_all(parent).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            format!("无法创建标记目录: {error}"),
            false,
        )
    })?;
    let temp = parent.join(format!(".pending-{}.tmp", Uuid::new_v4()));
    let mut file = std::fs::File::create(&temp).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            format!("无法创建临时标记: {error}"),
            false,
        )
    })?;
    file.write_all(payload).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            format!("无法写入临时标记: {error}"),
            false,
        )
    })?;
    file.sync_all().map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            format!("无法同步临时标记: {error}"),
            false,
        )
    })?;
    drop(file);

    let from = wide_path(&temp);
    let to = wide_path(path);
    let result = unsafe {
        MoveFileExW(
            PCWSTR(from.as_ptr()),
            PCWSTR(to.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(UpdaterError::new(
            "E_UPDATER_MARKER_INVALID",
            "更新标记原子替换失败",
            false,
        ));
    }
    Ok(())
}

fn wide_path(path: &Path) -> Vec<u16> {
    OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_marker, LkgRecord, MARKER_SCHEMA};
    use serde_json::json;

    fn valid_payload(schema: u32) -> serde_json::Value {
        json!({
            "schemaVersion": schema,
            "installSessionId": "session-1",
            "releaseId": "20261023-084324-4.1.4-b5e487ad",
            "fromVersion": "4.1.3",
            "toVersion": "4.1.4",
            "installerSha256": "a".repeat(64),
            "installerSize": 4963436,
            "fileVersion": "4.1.4",
            "lkg": null,
            "candidate": null,
            "createdAt": "2026-10-23T08:43:24Z",
            "handoffAt": "2026-10-23T08:43:25Z",
            "nonce": "nonce-1",
            "ownerPid": 1234,
            "state": "install_handoff",
            "detail": null
        })
    }

    #[test]
    fn old_marker_is_migrated_in_memory() {
        let mut payload = valid_payload(1);
        payload["handoffAt"] = json!("");
        let marker = parse_marker(serde_json::to_vec(&payload).unwrap().as_slice()).unwrap();
        assert_eq!(marker.schema_version, 1);
        assert_eq!(marker.handoff_at, marker.created_at);
    }

    #[test]
    fn current_marker_keeps_lkg_identity() {
        let mut payload = valid_payload(MARKER_SCHEMA);
        payload["lkg"] = json!({
            "path": "C:/data/known-good.exe",
            "sha256": "b".repeat(64),
            "version": "4.1.3",
            "fileVersion": "4.1.3",
            "releaseId": "20261022-185317-4.1.3-b5e487ad",
            "signature": "c2ln"
        });
        let marker = parse_marker(serde_json::to_vec(&payload).unwrap().as_slice()).unwrap();
        let lkg: LkgRecord = marker.lkg.unwrap();
        assert_eq!(lkg.version, "4.1.3");
        assert_eq!(lkg.release_id, "20261022-185317-4.1.3-b5e487ad");
    }

    #[test]
    fn illegal_release_id_is_rejected() {
        let mut payload = valid_payload(MARKER_SCHEMA);
        payload["releaseId"] = json!("../../escape");
        assert!(parse_marker(serde_json::to_vec(&payload).unwrap().as_slice()).is_err());
    }

    #[test]
    fn unknown_state_is_rejected() {
        let mut payload = valid_payload(MARKER_SCHEMA);
        payload["state"] = json!("whatever");
        assert!(parse_marker(serde_json::to_vec(&payload).unwrap().as_slice()).is_err());
    }
}
