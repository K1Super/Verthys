/*
 * 扫描轮次与结果组装
 *
 * 职责边界：单次扫描轮次的取消检查、快照持久化、缓存新鲜度判定与结果
 * 组装。证据只用于展示，不作为自动删除依据。
 */

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use tauri::ipc::Channel;
use tauri::AppHandle;

use crate::controller::types::{
    AnchorScanEntry, AnchorScanProgress, AnchorScanResult, AnchorScanRootReport, VerthysResponse,
};
use crate::repository::anchor_scan_store::{self, ScanStore};
use crate::repository::verthys_state::read_last_verthys_path;
use crate::util::audit_log::{AuditEventType, AuditResult};

use super::*;

#[derive(Default)]
pub(super) struct PassOutcome {
    /// 是否真实执行了本轮扫描（false 表示返回持久化快照）
    ran: bool,
    totals: Counters,
    deferred: HashSet<String>,
    partial: bool,
}

pub(super) fn run_scan_pass(
    app: AppHandle,
    config_dir: PathBuf,
    mut store: ScanStore,
    deep: bool,
    progress: Channel<AnchorScanProgress>,
) -> Result<(ScanStore, PassOutcome), String> {
    let now = now_secs();
    let current_container = read_last_verthys_path(&app)
        .ok()
        .flatten()
        .unwrap_or_default();
    store.last_pass_at = now;
    store.last_pass_partial = true;
    store.last_pass_truncated = false;
    store.last_pass_deep = deep;
    store.last_pass_files_seen = 0;
    store.last_pass_matched = 0;
    store.last_pass_permission_errors = 0;
    store.last_pass_other_errors = 0;
    store.last_pass_deferred.clear();
    store.last_pass_container_path = anchor_scan_store::path_key(&current_container);
    anchor_scan_store::save(&config_dir, &store)?;

    let mut targets = resolve_auto_targets(&app, &config_dir, &store);
    if deep {
        let _ = progress.send(AnchorScanProgress {
            phase: "collecting".to_string(),
            roots_total: 0,
            roots_done: 0,
            current_path: String::new(),
            files_seen: 0,
            matched_count: 0,
            partial: false,
        });
        targets.extend(ensure_deep_targets(&mut store, &app));
        anchor_scan_store::save(&config_dir, &store)?;
    }
    // 去重（同一路径可能同时来自自定义与深度），再按来源与轮转顺序排序。
    let mut unique: HashMap<String, ScanTarget> = HashMap::new();
    for target in targets {
        insert_target(&mut unique, target);
    }
    let mut targets: Vec<ScanTarget> = unique.into_values().collect();
    sort_targets(&mut targets, &store);
    let mut deferred_by_limit = HashSet::new();
    if targets.len() > SCAN_MAX_TARGETS {
        for target in targets.drain(SCAN_MAX_TARGETS..) {
            deferred_by_limit.insert(anchor_scan_store::path_key(&target.path));
        }
    }

    let total = targets.len() as u64;
    let mut outcome = PassOutcome {
        ran: true,
        deferred: deferred_by_limit,
        ..Default::default()
    };
    let global_deadline = Instant::now() + if deep { DEEP_BUDGET } else { SCAN_BUDGET };
    let root_slice = if deep {
        DEEP_ROOT_SLICE
    } else {
        SCAN_ROOT_SLICE
    };
    let max_depth = if deep { DEEP_MAX_DEPTH } else { SCAN_MAX_DEPTH };
    let mut budget = ScanBudget {
        global_deadline,
        max_files: SCAN_MAX_FILES,
        files_seen: 0,
    };
    let mut done = 0u64;

    let _ = progress.send(AnchorScanProgress {
        phase: "scanning".to_string(),
        roots_total: total,
        roots_done: 0,
        current_path: String::new(),
        files_seen: 0,
        matched_count: 0,
        partial: false,
    });

    for (index, target) in targets.iter().enumerate() {
        if scan_cancelled() {
            for rest in &targets[index..] {
                outcome
                    .deferred
                    .insert(anchor_scan_store::path_key(&rest.path));
            }
            break;
        }
        if Instant::now() >= global_deadline || budget.files_seen >= budget.max_files {
            outcome
                .deferred
                .insert(anchor_scan_store::path_key(&target.path));
            continue;
        }
        let _ = progress.send(AnchorScanProgress {
            phase: "scanning".to_string(),
            roots_total: total,
            roots_done: done,
            current_path: target.path.clone(),
            files_seen: outcome.totals.files_seen,
            matched_count: outcome.totals.matched,
            partial: outcome.totals.truncated,
        });
        let root_deadline = std::cmp::min(global_deadline, Instant::now() + root_slice);
        let root_outcome = scan_target(target, &mut budget, root_deadline, max_depth);
        outcome.totals.merge(&root_outcome.counters);
        apply_root_outcome(&mut store, target, root_outcome, now);
        store.last_pass_at = now;
        store.last_pass_partial = true;
        store.last_pass_files_seen = outcome.totals.files_seen;
        store.last_pass_matched = outcome.totals.matched;
        store.last_pass_permission_errors = outcome.totals.permission_errors;
        store.last_pass_other_errors = outcome.totals.other_errors;
        store.last_pass_truncated = outcome.totals.truncated;
        anchor_scan_store::save(&config_dir, &store)?;
        done += 1;
        let _ = progress.send(AnchorScanProgress {
            phase: "scanning".to_string(),
            roots_total: total,
            roots_done: done,
            current_path: String::new(),
            files_seen: outcome.totals.files_seen,
            matched_count: outcome.totals.matched,
            partial: outcome.totals.truncated,
        });
    }

    outcome.partial = outcome.totals.truncated || !outcome.deferred.is_empty();
    store.last_pass_at = now_secs();
    store.last_pass_partial = outcome.partial;
    store.last_pass_truncated = outcome.totals.truncated;
    store.last_pass_deep = deep;
    store.last_pass_files_seen = outcome.totals.files_seen;
    store.last_pass_matched = outcome.totals.matched;
    store.last_pass_permission_errors = outcome.totals.permission_errors;
    store.last_pass_other_errors = outcome.totals.other_errors;
    store.last_pass_deferred = outcome.deferred.iter().cloned().collect();
    anchor_scan_store::prune(&mut store, SCAN_MAX_STORED_ROOTS);
    anchor_scan_store::save(&config_dir, &store)?;

    let _ = progress.send(AnchorScanProgress {
        phase: "done".to_string(),
        roots_total: total,
        roots_done: done,
        current_path: String::new(),
        files_seen: outcome.totals.files_seen,
        matched_count: outcome.totals.matched,
        partial: outcome.partial,
    });

    Ok((store, outcome))
}

pub(super) fn build_scan_result(store: &ScanStore, outcome: &PassOutcome, deep: bool) -> AnchorScanResult {
    let mut merged: BTreeMap<String, CollectedPaths> = BTreeMap::new();
    for root in &store.roots {
        for entry in &root.entries {
            for path in &entry.paths {
                merge_paths(&mut merged, &entry.uuid, path);
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
        deep: if outcome.ran {
            deep
        } else {
            store.last_pass_deep
        },
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
            "roots={} deep={} files_seen={} matched={} truncated={} partial={} permission_errors={} other_errors={}",
            result.roots.len(),
            result.deep,
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
