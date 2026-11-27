/*
 * 扫描目标与位置来源
 *
 * 职责边界：当前/最近容器文件探针、自定义位置与本地磁盘根的合并、去重
 * 与排序。目标只描述“到哪里找证据”，不执行遍历。
 *
 * 持久化边界：只有自定义位置与磁盘根进入扫描证据库；当前/最近容器探针
 * 仅用于本轮快速定位，不落盘，因此容器改名或移动后不会留下失效路径。
 */

use std::collections::HashMap;
use std::path::Path;

use tauri::AppHandle;

use crate::repository::anchor_scan_store::{self, ScanStore};
use crate::repository::recent_paths;
use crate::repository::verthys_state::read_last_verthys_path;

use super::*;

/* ------------------------------------------------------------------ *
 * 扫描目标与位置来源                                                    *
 * ------------------------------------------------------------------ */

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(super) enum RootSource {
    /// 当前/上次打开的容器文件（瞬态探针）
    Container,
    /// 最近打开过的容器文件（瞬态探针）
    Recent,
    /// 用户显式添加的位置（持久化）
    Custom,
    /// 本地固定或可移动磁盘根（持久化）
    Volume,
}

impl RootSource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            RootSource::Container => "container",
            RootSource::Recent => "recent",
            RootSource::Custom => "custom",
            RootSource::Volume => "volume",
        }
    }

    pub(super) fn priority(self) -> u8 {
        match self {
            RootSource::Container => 0,
            RootSource::Recent => 1,
            RootSource::Custom => 2,
            RootSource::Volume => 3,
        }
    }

    /// 只有覆盖位置进入证据库；探针的路径变化不应变成持久化残留。
    pub(super) fn is_persistent(self) -> bool {
        matches!(self, RootSource::Custom | RootSource::Volume)
    }
}

pub(super) fn source_priority(source: &str) -> u8 {
    match source {
        "container" => 0,
        "recent" => 1,
        "custom" => 2,
        "volume" => 3,
        _ => 4,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(super) enum TargetKind {
    File,
    Dir,
}

impl TargetKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            TargetKind::File => "file",
            TargetKind::Dir => "dir",
        }
    }

    pub(super) fn order(self) -> u8 {
        match self {
            TargetKind::File => 0,
            TargetKind::Dir => 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ScanTarget {
    pub(super) path: String,
    pub(super) kind: TargetKind,
    pub(super) source: RootSource,
}

pub(super) fn target_key(target: &ScanTarget) -> String {
    format!(
        "{}:{}",
        target.kind.as_str(),
        anchor_scan_store::path_key(&target.path)
    )
}

pub(super) fn insert_target(map: &mut HashMap<String, ScanTarget>, target: ScanTarget) {
    let key = target_key(&target);
    match map.get(&key) {
        Some(existing) if existing.source.priority() <= target.source.priority() => {}
        _ => {
            map.insert(key, target);
        }
    }
}

/// 历史容器只生成精确文件探针；目录覆盖由磁盘根遍历承担。
pub(super) fn targets_from_history(
    history: &[(String, RootSource)],
    store: &ScanStore,
) -> Vec<ScanTarget> {
    let mut map: HashMap<String, ScanTarget> = HashMap::new();
    for (path, source) in history {
        let trimmed = native_path(path);
        if trimmed.is_empty() {
            continue;
        }
        insert_target(
            &mut map,
            ScanTarget {
                path: trimmed,
                kind: TargetKind::File,
                source: *source,
            },
        );
    }
    for root in &store.roots {
        let source = match root.source.as_str() {
            "custom" => RootSource::Custom,
            // 磁盘根由每轮枚举补充；探针不持久化。
            _ => continue,
        };
        if root.kind == "file" {
            continue;
        }
        insert_target(
            &mut map,
            ScanTarget {
                path: native_path(&root.path),
                kind: TargetKind::Dir,
                source,
            },
        );
    }
    let mut targets: Vec<ScanTarget> = map.into_values().collect();
    sort_targets(&mut targets);
    targets
}

/// 自动扫描目标：当前/最近容器探针 + 自定义位置 + 本地磁盘根。
pub(super) fn resolve_scan_targets(
    app: &AppHandle,
    config_dir: &Path,
    store: &ScanStore,
) -> Vec<ScanTarget> {
    let mut history: Vec<(String, RootSource)> = Vec::new();
    if let Ok(Some(last)) = read_last_verthys_path(app) {
        history.push((last, RootSource::Container));
    }
    match recent_paths::load(config_dir) {
        Ok(paths) => {
            for path in paths {
                history.push((path, RootSource::Recent));
            }
        }
        Err(e) => log::warn!("[anchor-scan] 最近容器路径读取失败: {}", e),
    }
    let mut targets = targets_from_history(&history, store);
    let mut map: HashMap<String, ScanTarget> = HashMap::new();
    for target in targets.drain(..) {
        insert_target(&mut map, target);
    }
    for volume in fixed_drive_roots() {
        let path = volume.to_string_lossy().to_string();
        if path.is_empty() {
            continue;
        }
        insert_target(
            &mut map,
            ScanTarget {
                path,
                kind: TargetKind::Dir,
                source: RootSource::Volume,
            },
        );
    }
    targets = map.into_values().collect();
    sort_targets(&mut targets);
    targets
}

/// 同一目标只保留优先级最高的来源；探针在前，磁盘根最后，保证进度先可见。
pub(super) fn sort_targets(targets: &mut [ScanTarget]) {
    targets.sort_by_key(|target| {
        (
            target.source.priority(),
            target.kind.order(),
            anchor_scan_store::path_key(&target.path),
        )
    });
}
