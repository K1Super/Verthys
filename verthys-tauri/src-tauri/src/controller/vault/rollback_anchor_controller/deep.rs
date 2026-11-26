/*
 * 深度扫描与自定义位置
 *
 * 职责边界：深度扫描仅在用户显式触发时枚举固定磁盘顶级目录；自定义
 * 位置做规范化、去重与数量上限校验。
 */

use std::collections::HashSet;
use std::fs::{self};
use std::path::{Path, PathBuf};

use tauri::AppHandle;

use crate::repository::anchor_scan_store::{self, ScanStore, StoredScanRoot};
use crate::util::path::validate_path_input;

use super::*;
use tauri::Manager;

pub(super) fn is_deep_skip_dir(name: &str) -> bool {
    DEEP_SKIP_DIRS
        .iter()
        .any(|skip| name.eq_ignore_ascii_case(skip))
}

#[cfg(windows)]
pub(super) fn fixed_drive_roots() -> Vec<PathBuf> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDriveStringsW};

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
                    if drive_type == DRIVE_FIXED {
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

pub(super) fn push_deep_user_target(
    store: &mut ScanStore,
    targets: &mut Vec<ScanTarget>,
    seen: &mut HashSet<String>,
    path: PathBuf,
) {
    if !fs::metadata(&path)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        return;
    }
    let display = path.to_string_lossy().to_string();
    let key = anchor_scan_store::path_key(&display);
    if !seen.insert(key.clone()) {
        /* 同一路径已作为顶级目录登记时提升为 DeepUser，保证它在深度扫描中
         * 优先于其它顶级目录被扫描。 */
        if let Some(existing) = targets
            .iter_mut()
            .find(|target| anchor_scan_store::path_key(&target.path) == key)
        {
            if existing.source == RootSource::Deep {
                existing.source = RootSource::DeepUser;
            }
        }
        if let Some(index) = anchor_scan_store::find_index(store, &display) {
            if store.roots[index].source == "deep" {
                store.roots[index].source = "deep_user".to_string();
            }
        }
        return;
    }
    targets.push(ScanTarget {
        path: display.clone(),
        kind: TargetKind::Dir,
        source: RootSource::DeepUser,
    });
    anchor_scan_store::get_or_insert(store, &display, "dir", "deep_user");
}

/// 枚举固定磁盘的顶级目录，并显式加入当前用户桌面/文档/下载；返回本轮深度目标。
pub(super) fn ensure_deep_targets(store: &mut ScanStore, app: &AppHandle) -> Vec<ScanTarget> {
    let mut targets = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for volume in fixed_drive_roots() {
        let entries = match fs::read_dir(&volume) {
            Ok(entries) => entries,
            Err(e) => {
                log::warn!("[anchor-scan] 深度扫描枚举卷失败: {}", e);
                continue;
            }
        };
        for entry in entries.flatten() {
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if is_deep_skip_dir(&name) {
                continue;
            }
            let path = entry.path();
            if let Ok(metadata) = fs::symlink_metadata(&path) {
                if is_reparse_or_symlink(&metadata) {
                    continue;
                }
            }
            let display = path.to_string_lossy().to_string();
            if seen.insert(anchor_scan_store::path_key(&display)) {
                targets.push(ScanTarget {
                    path: display.clone(),
                    kind: TargetKind::Dir,
                    source: RootSource::Deep,
                });
            }
            // 已存在的位置保留原来源（例如自定义位置），不重复登记。
            anchor_scan_store::get_or_insert(store, &display, "dir", "deep");
        }
    }

    /* 桌面/文档/下载不作为默认自动扫描项，但深度扫描是显式全盘动作，
     * 必须保证覆盖它们。作为独立深度目标可避免被 C:\Users 下 AppData
     * 等大目录耗尽时间预算，也能跟随 OneDrive 重定向的根目录。 */
    for path in [
        app.path().desktop_dir().ok(),
        app.path().document_dir().ok(),
        app.path().download_dir().ok(),
    ]
    .into_iter()
    .flatten()
    {
        push_deep_user_target(store, &mut targets, &mut seen, path);
    }

    // 离线卷/上次登记的深度位置也参与本轮，用于刷新“不可用”状态。
    for root in &store.roots {
        if root.kind != "dir" {
            continue;
        }
        let source = match root.source.as_str() {
            "deep" => RootSource::Deep,
            "deep_user" => RootSource::DeepUser,
            _ => continue,
        };
        let key = anchor_scan_store::path_key(&root.path);
        if seen.insert(key) {
            targets.push(ScanTarget {
                path: root.path.clone(),
                kind: TargetKind::Dir,
                source,
            });
        }
    }
    targets
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
