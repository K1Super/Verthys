/*
 * updater/repair.rs — 回退物料状态与修复执行
 *
 * 健康自检失败后，标记会被归档；后续启动只能依赖独立的修复状态文件知道
 * “上一版本是否仍可重装”。修复必须在启动安装器前重新校验物料，并先销毁
 * worker，避免旧进程继续占用待替换文件。
 */

use super::lkg;
use super::log;
use super::marker::{self, LkgRecord, PendingMarker};
use super::UpdaterError;
use crate::state::AppState;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};
use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

const REPAIR_FILE: &str = "repair.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairStateFile {
    pub failed_version: String,
    pub failed_release_id: String,
    pub lkg: Option<LkgRecord>,
    pub state: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairStateView {
    pub available: bool,
    pub version: Option<String>,
    pub release_id: Option<String>,
    pub state: Option<String>,
    pub reason: Option<String>,
}

fn repair_path(app: &AppHandle) -> Result<PathBuf, UpdaterError> {
    Ok(marker::updater_dir(app)?.join(REPAIR_FILE))
}

/// 健康失败时落盘修复状态；即使没有回退物料也写入，供前端如实展示。
pub fn write_from_marker(app: &AppHandle, marker: &PendingMarker) -> Result<(), UpdaterError> {
    let state = RepairStateFile {
        failed_version: marker.to_version.clone(),
        failed_release_id: marker.release_id.clone(),
        lkg: marker.lkg.clone(),
        state: "awaiting_repair".to_string(),
        reason: marker
            .detail
            .clone()
            .unwrap_or_else(|| "新版本健康自检未通过".to_string()),
        created_at: Utc::now().to_rfc3339(),
    };
    write_state(app, &state)
}

/// 读取修复状态；文件损坏时隔离并视为无状态，避免阻断启动。
pub fn read(app: &AppHandle) -> Option<RepairStateFile> {
    let path = repair_path(app).ok()?;
    let payload = std::fs::read(&path).ok()?;
    match serde_json::from_slice::<RepairStateFile>(&payload) {
        Ok(state) => Some(state),
        Err(error) => {
            let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
            let target = path.with_file_name(format!("repair.corrupt-{stamp}.json"));
            let _ = std::fs::rename(&path, &target);
            log::append(
                app,
                "repair_failed",
                "Repair",
                Some("E_UPDATER_MARKER_INVALID"),
                "error",
                serde_json::json!({ "reason": error.to_string() }),
            );
            None
        }
    }
}

/// 前端可见的修复状态；只报告物料是否存在，不做签名校验以免阻塞界面。
pub fn view(app: &AppHandle) -> RepairStateView {
    if let Some(state) = read(app) {
        return view_from_state(&state);
    }
    // 健康自检可能尚未落盘结论；只要标记仍属于当前版本，就按标记里的 LKG 展示。
    if let Ok(Some(marker)) = marker::read_pending(app) {
        let current = app.package_info().version.to_string();
        if marker.owner_pid != std::process::id() && marker.to_version == current {
            return view_from_marker(&marker);
        }
    }
    RepairStateView {
        available: false,
        version: None,
        release_id: None,
        state: None,
        reason: None,
    }
}

fn view_from_state(state: &RepairStateFile) -> RepairStateView {
    let available = state
        .lkg
        .as_ref()
        .is_some_and(|record| PathBuf::from(&record.path).exists());
    RepairStateView {
        available,
        version: state.lkg.as_ref().map(|record| record.version.clone()),
        release_id: state.lkg.as_ref().map(|record| record.release_id.clone()),
        state: Some(state.state.clone()),
        reason: Some(state.reason.clone()),
    }
}

/// 由刚归档的标记推导修复可见性；用于健康报告，不额外依赖磁盘状态。
pub fn view_from_marker(marker: &PendingMarker) -> RepairStateView {
    let available = marker
        .lkg
        .as_ref()
        .is_some_and(|record| PathBuf::from(&record.path).exists());
    RepairStateView {
        available,
        version: marker.lkg.as_ref().map(|record| record.version.clone()),
        release_id: marker.lkg.as_ref().map(|record| record.release_id.clone()),
        state: Some("awaiting_repair".to_string()),
        reason: marker.detail.clone(),
    }
}

/// 执行修复：复验物料、销毁 worker、以管理员权限启动旧版安装器并退出当前进程。
pub fn run(app: &AppHandle) -> Result<(), UpdaterError> {
    // 用户可能在健康结论落盘前直接触发修复；先把仍在等待的标记归档，
    // 否则修复后的下一次启动会把旧标记误判为“安装进行中”。
    let current = app.package_info().version.to_string();
    let pending_marker = marker::read_pending(app)
        .ok()
        .flatten()
        .filter(|value| value.owner_pid != std::process::id() && value.to_version == current);
    if pending_marker.is_some() {
        let _ = marker::finish_pending(app, "rolled_back", Some("用户触发修复"));
    }

    let mut state = match read(app) {
        Some(state) => state,
        None => {
            let Some(marker) = pending_marker else {
                return Err(material_missing());
            };
            let state = RepairStateFile {
                failed_version: marker.to_version.clone(),
                failed_release_id: marker.release_id.clone(),
                lkg: marker.lkg.clone(),
                state: "awaiting_repair".to_string(),
                reason: marker
                    .detail
                    .clone()
                    .unwrap_or_else(|| "健康自检未完成".to_string()),
                created_at: Utc::now().to_rfc3339(),
            };
            write_state(app, &state)?;
            state
        }
    };
    let Some(record) = state.lkg.clone() else {
        return Err(material_missing());
    };
    lkg::verify(app, &record)?;

    state.state = "repair_started".to_string();
    write_state(app, &state)?;
    log::append(
        app,
        "repair_started",
        "Repair",
        None,
        "info",
        serde_json::json!({ "version": record.version, "releaseId": record.release_id }),
    );

    // 先释放 worker，避免其继续占用 DLL/共享内存导致安装器替换失败。
    let app_state = app.state::<AppState>();
    app_state.set_session(None);
    std::thread::sleep(std::time::Duration::from_millis(300));

    match launch_installer_elevated(Path::new(&record.path), "/UPDATE /P /R") {
        Ok(()) => std::process::exit(0),
        Err(error) => {
            state.state = "repair_failed".to_string();
            state.reason = format!("无法启动旧版安装器: {}", error.message);
            let _ = write_state(app, &state);
            log::append(
                app,
                "repair_failed",
                "Repair",
                Some(&error.code),
                "error",
                serde_json::json!({}),
            );
            Err(error)
        }
    }
}

/// 以管理员权限启动安装器：机器级安装必须提权，确认后安装器接管进程。
/// 用户取消提权时安装器从未启动，按专用错误码返回，不能记作安装失败。
fn launch_installer_elevated(path: &Path, parameters: &str) -> Result<(), UpdaterError> {
    let verb = wide("runas");
    let file = wide(path.as_os_str());
    let arguments = wide(parameters);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(arguments.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: 结构体中的指针均指向本函数局部持有的 NUL 结尾 UTF-16 缓冲区，
    // 调用期间保持有效；cbSize 已按结构体类型填写。
    match unsafe { ShellExecuteExW(&mut info) } {
        Ok(()) => {
            if !info.hProcess.is_invalid() {
                // SAFETY: hProcess 是 ShellExecuteExW 返回且尚未关闭的进程句柄。
                unsafe {
                    let _ = CloseHandle(info.hProcess);
                }
            }
            Ok(())
        }
        Err(error) if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) => {
            Err(UpdaterError::new(
                "E_UPDATER_ELEVATION_DENIED",
                "用户未允许管理员权限，安装器未启动",
                true,
            ))
        }
        Err(error) => Err(UpdaterError::new(
            "E_UPDATER_INSTALL_FAILED",
            format!("无法启动旧版安装器: {error}"),
            true,
        )),
    }
}

/// 转为以 NUL 结尾的 UTF-16 字符串，Shell API 要求指针在调用期间有效。
fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// 启动时确认上一次修复是否已完成；版本已回到回退物料即算成功。
pub fn confirm_if_completed(app: &AppHandle, current_version: &str) -> bool {
    let Some(mut state) = read(app) else {
        return false;
    };
    if state.state != "repair_started" {
        return false;
    }
    let Some(record) = state.lkg.as_ref() else {
        return false;
    };
    if record.version != current_version {
        return false;
    }
    state.state = "repair_confirmed".to_string();
    let _ = write_state(app, &state);
    log::append(
        app,
        "repair_confirmed",
        "Repair",
        None,
        "info",
        serde_json::json!({ "version": record.version }),
    );
    // 已确认的修复不再需要在每次启动重复提示；状态已进入日志。
    let _ = clear(app);
    true
}

pub fn clear(app: &AppHandle) -> Result<(), UpdaterError> {
    let path = repair_path(app)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法清除修复状态: {error}"),
            true,
        )),
    }
}

fn write_state(app: &AppHandle, state: &RepairStateFile) -> Result<(), UpdaterError> {
    let payload = serde_json::to_vec_pretty(state).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("修复状态序列化失败: {error}"),
            true,
        )
    })?;
    marker::write_atomic(&repair_path(app)?, &payload)
}

fn material_missing() -> UpdaterError {
    UpdaterError::new(
        "E_UPDATER_ROLLBACK_MATERIAL_MISSING",
        "未找到可用的旧版安装包",
        false,
    )
}
