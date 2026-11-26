/*
 * 扫描目标与位置来源
 *
 * 职责边界：当前/上次容器、最近容器、深度扫描根与自定义位置的合并、
 * 去重与排序。目标只描述“到哪里找证据”，不执行遍历。
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
    /// 当前/上次打开的容器
    Container,
    /// 用户显式添加的位置
    Custom,
    /// 最近打开过的容器
    Recent,
    /// 深度扫描时显式加入的当前用户桌面/文档/下载
    DeepUser,
    /// 深度扫描枚举出的固定磁盘顶级目录
    Deep,
}

impl RootSource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            RootSource::Container => "container",
            RootSource::Custom => "custom",
            RootSource::Recent => "recent",
            RootSource::DeepUser => "deep_user",
            RootSource::Deep => "deep",
        }
    }

    pub(super) fn priority(self) -> u8 {
        match self {
            RootSource::Container => 0,
            RootSource::Custom => 1,
            RootSource::Recent => 2,
            RootSource::DeepUser => 3,
            RootSource::Deep => 4,
        }
    }
}

pub(super) fn source_priority(source: &str) -> u8 {
    match source {
        "container" => 0,
        "custom" => 1,
        "recent" => 2,
        "deep_user" => 3,
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

pub(super) fn push_history_targets(map: &mut HashMap<String, ScanTarget>, path: &str, source: RootSource) {
    let trimmed = native_path(path);
    if trimmed.is_empty() {
        return;
    }
    insert_target(
        map,
        ScanTarget {
            path: trimmed.clone(),
            kind: TargetKind::File,
            source,
        },
    );
    if let Some(parent) = Path::new(&trimmed).parent() {
        let dir = parent.to_string_lossy().to_string();
        if !dir.is_empty() && dir != trimmed {
            insert_target(
                map,
                ScanTarget {
                    path: dir,
                    kind: TargetKind::Dir,
                    source,
                },
            );
        }
    }
}

/// 从历史路径与已保存位置构建自动扫描目标。
pub(super) fn targets_from_history(history: &[(String, RootSource)], store: &ScanStore) -> Vec<ScanTarget> {
    let mut map: HashMap<String, ScanTarget> = HashMap::new();
    for (path, source) in history {
        push_history_targets(&mut map, path, *source);
    }
    for root in &store.roots {
        let source = match root.source.as_str() {
            "container" => RootSource::Container,
            "recent" => RootSource::Recent,
            "custom" => RootSource::Custom,
            // 深度扫描位置只在用户显式触发深度扫描时参与
            _ => continue,
        };
        let kind = if root.kind == "file" {
            TargetKind::File
        } else {
            TargetKind::Dir
        };
        let stored_path = native_path(&root.path);
        insert_target(
            &mut map,
            ScanTarget {
                path: stored_path.clone(),
                kind,
                source,
            },
        );
        // 既有证据中只有文件根时，仍补齐父目录，保证同目录其他容器可被发现。
        if kind == TargetKind::File {
            if let Some(parent) = Path::new(&stored_path).parent() {
                let dir = parent.to_string_lossy().to_string();
                if !dir.is_empty() && dir != stored_path {
                    insert_target(
                        &mut map,
                        ScanTarget {
                            path: dir,
                            kind: TargetKind::Dir,
                            source,
                        },
                    );
                }
            }
        }
    }
    let mut targets: Vec<ScanTarget> = map.into_values().collect();
    sort_targets(&mut targets, store);
    targets
}

/// 自动扫描目标：容器文件/目录、最近容器文件/目录、自定义位置。
pub(super) fn resolve_auto_targets(app: &AppHandle, config_dir: &Path, store: &ScanStore) -> Vec<ScanTarget> {
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
    targets_from_history(&history, store)
}

/// 同一目标只保留优先级最高的来源；文件优先于目录，深度目标按上次尝试时间轮转。
pub(super) fn sort_targets(targets: &mut Vec<ScanTarget>, store: &ScanStore) {
    let mut auto = Vec::new();
    let mut deep = Vec::new();
    for target in targets.drain(..) {
        if target.source == RootSource::Deep {
            deep.push(target);
        } else {
            auto.push(target);
        }
    }
    auto.sort_by_key(|target| {
        (
            target.source.priority(),
            target.kind.order(),
            anchor_scan_store::path_key(&target.path),
        )
    });
    deep.sort_by_key(|target| {
        let key = anchor_scan_store::path_key(&target.path);
        let last_attempt = store
            .roots
            .iter()
            .find(|root| anchor_scan_store::path_key(&root.path) == key)
            .map(|root| root.last_attempt_at)
            .unwrap_or(0);
        (last_attempt, key)
    });
    targets.extend(auto);
    targets.extend(deep);
}
