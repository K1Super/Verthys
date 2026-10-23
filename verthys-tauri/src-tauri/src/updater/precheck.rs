/*
 * updater/precheck.rs — 安装前环境预检
 *
 * 预检必须在下载前完成，避免把大文件下载完才发现磁盘不足、目录不可写或
 * 已有第二个实例占用程序目录。任一失败都返回稳定错误码，由前端给出可执行指引。
 */

use super::manifest::ValidatedManifest;
use super::UpdaterError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use tauri::AppHandle;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, TRUE};
use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::CreateMutexW;

const SPACE_MARGIN_BYTES: u64 = 100 * 1024 * 1024;

/// 安装移交期间的进程级互斥量名称；同一登录会话内只允许一个安装者。
const INSTALL_MUTEX_NAME: &str = "Local\\Verthys.Updater.Install";

/// 安装互斥量守卫：持有期间阻止第二个进程进入安装移交。
pub struct InstallLock(HANDLE);

impl InstallLock {
    /// 获取安装互斥量；已被其他进程持有时立即失败，不排队等待。
    pub fn acquire() -> Result<Self, UpdaterError> {
        let name: Vec<u16> = OsStr::new(INSTALL_MUTEX_NAME)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle =
            unsafe { CreateMutexW(None, TRUE, PCWSTR(name.as_ptr())) }.map_err(|error| {
                UpdaterError::new(
                    "E_UPDATER_PRECHECK_SINGLE_INSTANCE",
                    format!("无法创建安装互斥量: {error}"),
                    true,
                )
            })?;
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err(UpdaterError::new(
                "E_UPDATER_PRECHECK_SINGLE_INSTANCE",
                "另一个更新安装正在进行",
                true,
            ));
        }
        Ok(Self(handle))
    }
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// 校验应用数据目录所在卷能容纳一份回退物料。
pub fn ensure_lkg_space(app: &AppHandle, installer_size: u64) -> Result<(), UpdaterError> {
    let dir = super::marker::updater_dir(app)?;
    let free = available_space(&dir)?;
    // 候选物料与上一份已知良好物料可能同时存在，按两份预留。
    let required = installer_size
        .saturating_mul(2)
        .saturating_add(SPACE_MARGIN_BYTES);
    if free < required {
        return Err(UpdaterError::new(
            "E_UPDATER_PRECHECK_SPACE",
            format!("回退物料空间不足：需要 {required} 字节，可用 {free} 字节"),
            true,
        ));
    }
    Ok(())
}

/// 执行预检；成功返回后仍可能在下载期间发生环境变化，因此安装前还会复检。
pub fn run(_app: &AppHandle, manifest: &ValidatedManifest) -> Result<(), UpdaterError> {
    let exe = std::env::current_exe().map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法定位当前程序: {error}"),
            true,
        )
    })?;
    let install_dir = exe
        .parent()
        .ok_or_else(|| UpdaterError::new("E_UPDATER_INTERNAL", "无法定位安装目录", true))?;

    ensure_no_other_instance(&exe)?;
    ensure_disk_space(install_dir, manifest.size)?;
    ensure_dir_writable(install_dir)?;
    Ok(())
}

fn ensure_disk_space(install_dir: &Path, installer_size: u64) -> Result<(), UpdaterError> {
    let free = available_space(install_dir)?;
    let required = installer_size
        .saturating_mul(2)
        .saturating_add(SPACE_MARGIN_BYTES);
    if free < required {
        return Err(UpdaterError::new(
            "E_UPDATER_PRECHECK_SPACE",
            format!("磁盘空间不足：需要 {required} 字节，可用 {free} 字节"),
            true,
        ));
    }
    Ok(())
}

fn available_space(path: &Path) -> Result<u64, UpdaterError> {
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut free = 0u64;
    unsafe { GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), Some(&mut free), None, None) }.map_err(
        |error| {
            UpdaterError::new(
                "E_UPDATER_PRECHECK_SPACE",
                format!("无法读取磁盘空间: {error}"),
                true,
            )
        },
    )?;
    Ok(free)
}

fn ensure_dir_writable(install_dir: &Path) -> Result<(), UpdaterError> {
    let probe = install_dir.join(format!(".verthys-updater-probe-{}", std::process::id()));
    let result = std::fs::write(&probe, b"probe")
        .and_then(|_| std::fs::read(&probe))
        .and_then(|_| std::fs::remove_file(&probe));
    if let Err(error) = result {
        return Err(UpdaterError::new(
            "E_UPDATER_PRECHECK_DIR_WRITABLE",
            format!("安装目录不可写: {error}"),
            true,
        ));
    }
    Ok(())
}

fn ensure_no_other_instance(current_exe: &Path) -> Result<(), UpdaterError> {
    let current_name = current_exe
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| UpdaterError::new("E_UPDATER_INTERNAL", "无法读取当前程序名", true))?;
    let current_pid = std::process::id();

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_PRECHECK_SINGLE_INSTANCE",
            format!("无法枚举进程: {error}"),
            true,
        )
    })?;
    let result = scan_processes(snapshot, current_name, current_pid);
    unsafe {
        let _ = CloseHandle(snapshot);
    }
    if result {
        return Err(UpdaterError::new(
            "E_UPDATER_PRECHECK_SINGLE_INSTANCE",
            "检测到第二个 Verthys 实例正在运行",
            true,
        ));
    }
    Ok(())
}

fn scan_processes(snapshot: HANDLE, current_name: &str, current_pid: u32) -> bool {
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_err() {
        return false;
    }
    loop {
        if entry.th32ProcessID != current_pid {
            let name = String::from_utf16_lossy(&entry.szExeFile);
            let name = name.trim_end_matches('\0');
            if name.eq_ignore_ascii_case(current_name) {
                return true;
            }
        }
        if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
            return false;
        }
    }
}
