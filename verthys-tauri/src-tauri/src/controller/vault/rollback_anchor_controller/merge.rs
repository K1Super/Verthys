/*
 * 扫描快照合并
 *
 * 职责边界：按 UUID 合并同一容器多路径证据，保留历史快照；重新扫描只
 * 更新对应位置，不抹掉其它位置的既有证据。
 */

use std::collections::BTreeMap;
use std::io::ErrorKind;

use crate::repository::anchor_scan_store::{self, ScanStore, StoredScanEntry};

use super::*;

pub(super) fn merge_paths(
    map: &mut BTreeMap<String, CollectedPaths>,
    uuid: &str,
    path: &str,
    capped: bool,
) {
    let entry = map.entry(uuid.to_string()).or_default();
    entry.capped |= capped;
    if entry.keys.insert(anchor_scan_store::path_key(path)) {
        if entry.paths.len() < SCAN_MAX_PATHS_PER_UUID {
            entry.paths.push(path.to_string());
        } else {
            /* 单锚点证据列表超出展示上限：只标记该条目，不影响遍历完整性。 */
            entry.capped = true;
        }
    }
}

/// 截断扫描取并集后，逐条确认旧证据仍然存在。
///
/// 仅将“确定不存在（NotFound）”的路径移出证据；权限或暂时性错误保留原记录。
/// 这样容器改名/移动后，即使本轮因某个目录受限而未能完整遍历，也不会把
/// 旧路径永久留在证据列。
fn drop_missing_paths(entries: &mut Vec<StoredScanEntry>) {
    for entry in entries.iter_mut() {
        entry.paths.retain(|path| match std::fs::metadata(path) {
            Ok(metadata) => metadata.is_file(),
            Err(e) => e.kind() != ErrorKind::NotFound,
        });
    }
    entries.retain(|entry| !entry.paths.is_empty());
}

pub(super) fn union_entries(
    old_entries: Vec<StoredScanEntry>,
    new_entries: Vec<StoredScanEntry>,
) -> Vec<StoredScanEntry> {
    let mut map: BTreeMap<String, CollectedPaths> = BTreeMap::new();
    for entry in old_entries.into_iter().chain(new_entries) {
        let StoredScanEntry {
            uuid,
            paths,
            capped,
        } = entry;
        for path in paths {
            merge_paths(&mut map, &uuid, &path, capped);
        }
    }
    map.into_iter()
        .map(|(uuid, mut entry)| {
            entry.paths.sort();
            StoredScanEntry {
                uuid,
                paths: entry.paths,
                capped: entry.capped,
            }
        })
        .collect()
}

pub(super) fn apply_root_outcome(
    store: &mut ScanStore,
    target: &ScanTarget,
    outcome: RootOutcome,
    now: u64,
) {
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
        // 并集后逐条确认旧路径仍存在，容器改名/移动不会留下失效证据。
        let mut entries = union_entries(std::mem::take(&mut root.entries), outcome.entries);
        drop_missing_paths(&mut entries);
        root.entries = entries;
    } else {
        root.entries = outcome.entries;
        root.last_success_at = now;
    }
}
