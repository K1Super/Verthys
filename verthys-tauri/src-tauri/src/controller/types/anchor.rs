/*
 * 回退锚点 DTO
 *
 * 职责边界：锚点条目、扫描根报告、扫描结果与进度。
 */

use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub struct AnchorInfo {
    pub uuid: String,
    pub generation: u64,
    /// unknown / active / dead / tampered
    pub witness: String,
}

/// 单个 UUID 的扫描证据：同一 UUID 可能对应多个容器路径。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnchorScanEntry {
    pub uuid: String,
    pub paths: Vec<String>,
}

/// 单个扫描位置的覆盖率与状态。
///
/// deferred 表示本次扫描因预算用尽没有尝试该位置；证据仍沿用上次快照。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnchorScanRootReport {
    pub path: String,
    /// file / dir
    pub kind: String,
    /// container / recent / custom / deep
    pub source: String,
    pub available: bool,
    pub last_success_at: u64,
    pub last_attempt_at: u64,
    pub files_seen: u64,
    pub matched_count: u64,
    pub permission_errors: u64,
    pub other_errors: u64,
    pub truncated: bool,
    pub deferred: bool,
    pub entry_count: u64,
}

/// 容器扫描摘要（只读；路径仅在本次响应内展示，不写入审计）。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnchorScanResult {
    pub entries: Vec<AnchorScanEntry>,
    /// 所有已知位置的覆盖率；前端据此展示扫描范围与不完整状态
    pub roots: Vec<AnchorScanRootReport>,
    pub files_seen: u64,
    pub matched_count: u64,
    pub truncated: bool,
    /// 本次扫描是否不完整（预算用尽、位置未尝试或遍历截断）
    pub partial: bool,
    pub permission_errors: u64,
    pub other_errors: u64,
    pub scanned_at: u64,
    pub deep: bool,
}

/// 扫描进度（仅深度扫描等长任务逐位置推送）。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnchorScanProgress {
    pub phase: String,
    pub roots_total: u64,
    pub roots_done: u64,
    pub current_path: String,
    pub files_seen: u64,
    pub matched_count: u64,
    pub partial: bool,
}


