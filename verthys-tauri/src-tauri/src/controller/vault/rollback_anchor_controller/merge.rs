/*
 * 扫描快照合并
 *
 * 职责边界：按 UUID 合并同一容器多路径证据，保留历史快照；重新扫描只
 * 更新对应位置，不抹掉其它位置的既有证据。
 */

use std::collections::BTreeMap;


use crate::repository::anchor_scan_store::{self, ScanStore, StoredScanEntry};

use super::*;

pub(super) fn merge_paths(map: &mut BTreeMap<String, CollectedPaths>, uuid: &str, path: &str) {
    let entry = map.entry(uuid.to_string()).or_default();
    if entry.keys.insert(anchor_scan_store::path_key(path)) {
        if entry.paths.len() < SCAN_MAX_PATHS_PER_UUID {
            entry.paths.push(path.to_string());
        }
    }
}

pub(super) fn union_entries(
    old_entries: Vec<StoredScanEntry>,
    new_entries: Vec<StoredScanEntry>,
) -> (Vec<StoredScanEntry>, bool) {
    let mut map: BTreeMap<String, CollectedPaths> = BTreeMap::new();
    let mut overflow = false;
    for entry in old_entries.into_iter().chain(new_entries) {
        for path in entry.paths {
            let slot = map.entry(entry.uuid.clone()).or_default();
            if slot.keys.insert(anchor_scan_store::path_key(&path)) {
                if slot.paths.len() < SCAN_MAX_PATHS_PER_UUID {
                    slot.paths.push(path);
                } else {
                    overflow = true;
                }
            }
        }
    }
    let entries = map
        .into_iter()
        .map(|(uuid, mut entry)| {
            entry.paths.sort();
            StoredScanEntry {
                uuid,
                paths: entry.paths,
            }
        })
        .collect();
    (entries, overflow)
}

pub(super) fn apply_root_outcome(store: &mut ScanStore, target: &ScanTarget, outcome: RootOutcome, now: u64) {
    let root = anchor_scan_store::get_or_insert(
        store,
        &target.path,
        target.kind.as_str(),
        target.source.as_str(),
    );
    if target.source.priority() < source_priority(&root.source) {
        root.source = target.source.as_str().to_string();
    }
    root.kind = target.kind.as_str().to_string();
    root.last_attempt_at = now;
    root.available = outcome.available;
    if !outcome.available {
        // 位置不可用（离线盘/目录被删）：保留上次证据，仅标记不可用。
        return;
    }
    root.files_seen = outcome.counters.files_seen;
    root.matched_count = outcome.counters.matched;
    root.permission_errors = outcome.counters.permission_errors;
    root.other_errors = outcome.counters.other_errors;
    root.truncated = outcome.counters.truncated;
    if outcome.counters.truncated {
        // 截断扫描只能做并集：已覆盖到的既有路径可能本次没来得及走到。
        let (entries, overflow) = union_entries(std::mem::take(&mut root.entries), outcome.entries);
        root.entries = entries;
        if overflow {
            root.truncated = true;
        }
    } else {
        root.entries = outcome.entries;
        root.last_success_at = now;
    }
}
