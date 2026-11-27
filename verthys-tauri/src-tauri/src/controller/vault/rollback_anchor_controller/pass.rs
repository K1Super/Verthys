/*
 * 扫描轮次与结果组装
 *
 * 职责边界：单次全量扫描的目标准备、并行遍历、证据落盘、失效根清理与
 * 结果组装。证据只用于展示，不作为自动删除依据。
 *
 * 持久化边界：自定义位置与磁盘根进入证据库；当前/最近容器探针只在本轮
 * 结果中出现。容器改名或移动后，旧探针路径不会被写入或保留。
 */

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use tauri::ipc::Channel;
use tauri::AppHandle;

use crate::controller::types::{
    AnchorScanEntry, AnchorScanProgress, AnchorScanResult, AnchorScanRootReport, VerthysResponse,
};
use crate::repository::anchor_scan_store::{self, ScanStore, StoredScanRoot};
use crate::repository::verthys_state::read_last_verthys_path;
use crate::util::audit_log::{AuditEventType, AuditResult};

use super::*;

#[derive(Default)]
pub(super) struct PassOutcome {
    /// 是否真实执行了本轮扫描（false 表示返回持久化快照）
    pub(super) ran: bool,
    pub(super) totals: Counters,
    pub(super) deferred: HashSet<String>,
    pub(super) partial: bool,
    /// 当前/最近容器探针证据：只参与本轮结果，不落盘
    pub(super) transient_roots: Vec<StoredScanRoot>,
}

pub(super) fn run_scan_pass(
    app: AppHandle,
    config_dir: PathBuf,
    mut store: ScanStore,
    progress: Channel<AnchorScanProgress>,
) -> Result<(ScanStore, PassOutcome), String> {
    let current_container = read_last_verthys_path(&app)
        .ok()
        .flatten()
        .unwrap_or_default();
    /* 开始即失效缓存：扫描中途崩溃时，磁盘上留下的只能是“未完成”标记，
     * 下次打开必须重新遍历，不能把旧证据当成最近一次完整结果。 */
    store.last_pass_at = 0;
    store.last_pass_partial = true;
    store.last_pass_truncated = false;
    store.last_pass_files_seen = 0;
    store.last_pass_matched = 0;
    store.last_pass_permission_errors = 0;
    store.last_pass_other_errors = 0;
    store.last_pass_deferred.clear();
    store.last_pass_container_path = anchor_scan_store::path_key(&current_container);
    anchor_scan_store::save(&config_dir, &store)?;

    let mut targets = resolve_scan_targets(&app, &config_dir, &store);
    /* 盘符集合独立枚举：自定义位置与磁盘根重合时目标会按优先级去重为
     * custom，但覆盖率判定仍需知道该路径属于本地磁盘。 */
    let volume_keys: HashSet<String> = fixed_drive_roots()
        .iter()
        .map(|volume| anchor_scan_store::path_key(&volume.to_string_lossy()))
        .collect();
    let mut outcome = PassOutcome {
        ran: true,
        ..Default::default()
    };
    if targets.len() > SCAN_MAX_TARGETS {
        for target in targets.drain(SCAN_MAX_TARGETS..) {
            outcome
                .deferred
                .insert(anchor_scan_store::path_key(&target.path));
        }
    }
    /* 自定义目录已被单独调度，磁盘根遍历到此子树时直接跳过，避免同一批
     * 文件在多个目标中重复枚举。 */
    let covered: HashSet<String> = targets
        .iter()
        .filter(|target| target.source == RootSource::Custom && target.kind == TargetKind::Dir)
        .map(|target| anchor_scan_store::path_key(&target.path))
        .collect();

    let _ = progress.send(AnchorScanProgress {
        phase: "scanning".to_string(),
        roots_total: targets.len() as u64,
        roots_done: 0,
        current_path: String::new(),
        files_seen: 0,
        matched_count: 0,
        partial: false,
    });

    let budget = ScanBudget::new(SCAN_MAX_FILES, SCAN_BUDGET);
    let outcomes = scan_targets(&targets, &budget, &covered, |tick| {
        let _ = progress.send(AnchorScanProgress {
            phase: "scanning".to_string(),
            roots_total: tick.roots_total as u64,
            roots_done: tick.roots_done as u64,
            current_path: tick.current_path,
            files_seen: tick.files_seen,
            matched_count: tick.matched,
            partial: tick.partial,
        });
    });

    let now = now_secs();
    let mut probe_outside_volume = false;
    for (target, root_outcome) in targets.iter().zip(outcomes) {
        outcome.totals.merge(&root_outcome.counters);
        if target.source.is_persistent() {
            apply_root_outcome(&mut store, target, root_outcome, now);
            continue;
        }
        if !is_under_volume(&target.path, &volume_keys) {
            /* 网络盘或未纳入磁盘根的探针位置：证据只在本轮有效，无法保证
             * 下次缓存视图仍完整，标记为不完整以阻止自动勾选缺失。 */
            probe_outside_volume = true;
        }
        if !root_outcome.available {
            continue;
        }
        let mut root = StoredScanRoot::new(&target.path, "file", target.source.as_str());
        root.available = true;
        root.last_attempt_at = now;
        root.files_seen = root_outcome.counters.files_seen;
        root.matched_count = root_outcome.counters.matched;
        root.permission_errors = root_outcome.counters.permission_errors;
        root.other_errors = root_outcome.counters.other_errors;
        root.truncated = root_outcome.counters.truncated;
        root.entries = root_outcome.entries;
        if !root.truncated {
            root.last_success_at = now;
        }
        outcome.transient_roots.push(root);
    }

    /* 自动根由每轮重新枚举或重新探测，失效后不得留在证据库；自定义位置
     * 由用户显式管理，暂时不可用时保留其历史证据并允许手动移除。 */
    anchor_scan_store::retain_current_roots(&mut store, &volume_keys);
    let custom_unavailable = store
        .roots
        .iter()
        .any(|root| root.source == "custom" && !root.available);

    outcome.partial = outcome.totals.truncated
        || !outcome.deferred.is_empty()
        || probe_outside_volume
        || custom_unavailable
        || volume_keys.is_empty()
        || scan_cancelled();
    store.last_pass_at = now;
    store.last_pass_partial = outcome.partial;
    store.last_pass_truncated = outcome.totals.truncated;
    store.last_pass_files_seen = outcome.totals.files_seen;
    store.last_pass_matched = outcome.totals.matched;
    store.last_pass_permission_errors = outcome.totals.permission_errors;
    store.last_pass_other_errors = outcome.totals.other_errors;
    store.last_pass_deferred = outcome.deferred.iter().cloned().collect();
    anchor_scan_store::prune(&mut store, SCAN_MAX_STORED_ROOTS);
    anchor_scan_store::save(&config_dir, &store)?;

    let _ = progress.send(AnchorScanProgress {
        phase: "done".to_string(),
        roots_total: targets.len() as u64,
        roots_done: targets.len() as u64,
        current_path: String::new(),
        files_seen: outcome.totals.files_seen,
        matched_count: outcome.totals.matched,
        partial: outcome.partial,
    });

    Ok((store, outcome))
}

pub(super) fn is_under_volume(path: &str, volumes: &HashSet<String>) -> bool {
    let key = anchor_scan_store::path_key(path);
    volumes.iter().any(|volume| {
        if key == *volume {
            return true;
        }
        let base = volume.trim_end_matches('\\');
        key.starts_with(&format!("{}\\", base))
    })
}

pub(super) fn build_scan_result(store: &ScanStore, outcome: &PassOutcome) -> AnchorScanResult {
    let mut merged: BTreeMap<String, CollectedPaths> = BTreeMap::new();
    for root in store.roots.iter().chain(outcome.transient_roots.iter()) {
        for entry in &root.entries {
            for path in &entry.paths {
                merge_paths(&mut merged, &entry.uuid, path, entry.capped);
            }
        }
    }
    let entries: Vec<AnchorScanEntry> = merged
        .into_iter()
        .map(|(uuid, mut paths)| {
            paths.paths.sort();
            AnchorScanEntry {
                uuid,
                paths: paths.paths,
                capped: paths.capped,
            }
        })
        .collect();

    let deferred: HashSet<String> = if outcome.ran {
        outcome.deferred.clone()
    } else {
        store.last_pass_deferred.iter().cloned().collect()
    };
    let mut roots: Vec<AnchorScanRootReport> = store
        .roots
        .iter()
        .chain(outcome.transient_roots.iter())
        .map(|root| AnchorScanRootReport {
            path: root.path.clone(),
            kind: root.kind.clone(),
            source: root.source.clone(),
            available: root.available,
            last_success_at: root.last_success_at,
            last_attempt_at: root.last_attempt_at,
            files_seen: root.files_seen,
            matched_count: root.matched_count,
            permission_errors: root.permission_errors,
            other_errors: root.other_errors,
            truncated: root.truncated,
            deferred: deferred.contains(&anchor_scan_store::path_key(&root.path)),
            entry_count: root.entries.len() as u64,
        })
        .collect();
    roots.sort_by_key(|root| {
        (
            source_priority(&root.source),
            if root.kind == "file" { 0u8 } else { 1u8 },
            anchor_scan_store::path_key(&root.path),
        )
    });

    let (files_seen, matched_count, permission_errors, other_errors, truncated, partial) =
        if outcome.ran {
            (
                outcome.totals.files_seen,
                outcome.totals.matched,
                outcome.totals.permission_errors,
                outcome.totals.other_errors,
                outcome.totals.truncated,
                outcome.partial,
            )
        } else {
            (
                store.last_pass_files_seen,
                store.last_pass_matched,
                store.last_pass_permission_errors,
                store.last_pass_other_errors,
                store.last_pass_truncated,
                store.last_pass_partial,
            )
        };

    AnchorScanResult {
        entries,
        roots,
        files_seen,
        matched_count,
        truncated,
        partial,
        permission_errors,
        other_errors,
        scanned_at: store.last_pass_at,
        depth: VOLUME_SCAN_MAX_DEPTH as u64,
        cached: !outcome.ran,
    }
}

pub(super) fn load_store(config_dir: &Path) -> ScanStore {
    match anchor_scan_store::load(config_dir) {
        Ok(store) => store,
        Err(e) => {
            log::warn!("[anchor-scan] 扫描证据不可用，按空库重建: {}", e);
            ScanStore::default()
        }
    }
}

pub(super) fn is_cache_fresh(store: &ScanStore) -> bool {
    if store.last_pass_at == 0 || store.roots.is_empty() {
        return false;
    }
    now_secs().saturating_sub(store.last_pass_at) < SCAN_CACHE_TTL_SECS
}

/// 切换容器后必须重新扫描：旧缓存可能只覆盖上一个容器目录。
pub(super) fn cache_matches_current_container(app: &AppHandle, store: &ScanStore) -> bool {
    let current = read_last_verthys_path(app)
        .ok()
        .flatten()
        .unwrap_or_default();
    anchor_scan_store::path_key(&current) == store.last_pass_container_path
}

pub(super) fn audit_scan(app: &AppHandle, result: &AnchorScanResult) {
    audit_anchor(
        app,
        AuditEventType::RollbackAnchorScan,
        AuditResult::Success,
        None,
        Some(format!(
            "roots={} files_seen={} matched={} truncated={} partial={} permission_errors={} other_errors={}",
            result.roots.len(),
            result.files_seen,
            result.matched_count,
            result.truncated,
            result.partial,
            result.permission_errors,
            result.other_errors
        )),
    );
}

pub(super) fn scan_response(result: AnchorScanResult) -> VerthysResponse {
    let mut resp = VerthysResponse::ok("rollback_anchor_scan");
    resp.anchor_scan = Some(result);
    resp
}

pub(super) fn scan_invalid(message: String) -> VerthysResponse {
    let mut resp = VerthysResponse::err("rollback_anchor_scan", &message);
    resp.error_code = Some("ERR_00000001".into());
    resp
}
