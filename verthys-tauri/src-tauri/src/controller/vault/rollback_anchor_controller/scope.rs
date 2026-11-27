/*
 * 本地磁盘范围与自定义位置
 *
 * 职责边界：枚举本地固定/可移动磁盘根目录；自定义位置做规范化、去重与
 * 数量上限校验。磁盘枚举只提供“覆盖范围”，不执行遍历。
 */

use std::collections::HashSet;
use std::fs::{self};
use std::path::{Path, PathBuf};

use crate::repository::anchor_scan_store::{self, ScanStore, StoredScanRoot};
use crate::util::path::validate_path_input;

use super::*;

fn matches_dir_list(name: &std::ffi::OsStr, list: &[&str]) -> bool {
    name.to_str()
        .map(|name| list.iter().any(|skip| name.eq_ignore_ascii_case(skip)))
        .unwrap_or(false)
}

pub(super) fn is_volume_skip_dir(name: &std::ffi::OsStr) -> bool {
    matches_dir_list(name, VOLUME_SKIP_DIRS)
}

pub(super) fn is_nested_skip_dir(name: &std::ffi::OsStr) -> bool {
    matches_dir_list(name, NESTED_SKIP_DIRS)
}

pub(super) fn is_volume_nested_skip_dir(name: &std::ffi::OsStr) -> bool {
    matches_dir_list(name, VOLUME_NESTED_SKIP_DIRS)
}

#[cfg(windows)]
pub(super) fn fixed_drive_roots() -> Vec<PathBuf> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDriveStringsW};

    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    let mut buffer = [0u16; 512];
    let len = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) } as usize;
    if len == 0 || len > buffer.len() {
        return Vec::new();
    }
    let strings: Vec<u16> = buffer[..len as usize].to_vec();
    let mut drives = Vec::new();
    let mut start = 0usize;
    while start < strings.len() {
        let end = strings[start..].iter().position(|&c| c == 0);
        match end {
            Some(0) => break,
            Some(n) => {
                let drive = String::from_utf16_lossy(&strings[start..start + n]);
                if drive.len() >= 2 {
                    let wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
                    let drive_type = unsafe { GetDriveTypeW(PCWSTR::from_raw(wide.as_ptr())) };
                    if drive_type == DRIVE_FIXED || drive_type == DRIVE_REMOVABLE {
                        drives.push(PathBuf::from(drive));
                    }
                }
                start += n + 1;
            }
            None => break,
        }
    }
    drives
}

#[cfg(not(windows))]
pub(super) fn fixed_drive_roots() -> Vec<PathBuf> {
    Vec::new()
}

/* ------------------------------------------------------------------ *
 * 自定义位置                                                           *
 * ------------------------------------------------------------------ */

pub(super) fn normalize_custom_roots(roots: Vec<String>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in roots {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        validate_path_input(trimmed).map_err(|e| format!("扫描位置非法: {}", e))?;
        if !Path::new(trimmed).is_absolute() {
            return Err("扫描位置必须是绝对路径".to_string());
        }
        let metadata = fs::metadata(trimmed).map_err(|e| format!("扫描位置不可用: {}", e))?;
        if !metadata.is_dir() {
            return Err("扫描位置必须是目录".to_string());
        }
        if seen.insert(anchor_scan_store::path_key(trimmed)) {
            out.push(native_path(trimmed));
        }
    }
    Ok(out)
}

pub(super) fn add_custom_roots(store: &mut ScanStore, additions: &[String]) -> Result<(), String> {
    let mut custom_count = store
        .roots
        .iter()
        .filter(|root| root.source == "custom")
        .count();
    for path in additions {
        if let Some(index) = anchor_scan_store::find_index(store, path) {
            if store.roots[index].source != "custom" {
                if custom_count >= SCAN_MAX_CUSTOM_ROOTS {
                    return Err(format!("自定义扫描位置最多 {} 个", SCAN_MAX_CUSTOM_ROOTS));
                }
                store.roots[index].source = "custom".to_string();
                store.roots[index].kind = "dir".to_string();
                custom_count += 1;
            }
            continue;
        }
        if custom_count >= SCAN_MAX_CUSTOM_ROOTS {
            return Err(format!("自定义扫描位置最多 {} 个", SCAN_MAX_CUSTOM_ROOTS));
        }
        store.roots.push(StoredScanRoot::new(path, "dir", "custom"));
        custom_count += 1;
    }
    Ok(())
}
