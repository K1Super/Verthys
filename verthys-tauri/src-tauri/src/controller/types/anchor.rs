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
    ///
    /// active 只表示 TPM 见证密钥存在且指纹匹配，不代表容器文件仍然存在。
    pub witness: String,
}

/// 批量释放的单条结果（仅 verthys_rollback_anchor_release_batch 返回）。
#[derive(Serialize, Deserialize)]
pub struct AnchorReleaseOutcome {
    pub uuid: String,
    /// true=本次删除条目；false=条目不存在（仍幂等清理见证）
    pub released: bool,
    /// true=该 UUID 的见证键删除失败
    pub cleanup_failed: bool,
}

/// 单个 UUID 的扫描证据：同一 UUID 可能对应多个容器路径。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnchorScanEntry {
    pub uuid: String,
    pub paths: Vec<String>,
    /// 路径数超过单锚点展示上限，列表只保留前若干条。
    ///
    /// 只描述证据展示完整性；该 UUID 已被找到，不代表目录遍历被截断。
    pub capped: bool,
}

/// 单个扫描位置的覆盖率与状态。
///
/// deferred 表示本次扫描因目标上限没有尝试该位置；证据仍沿用上次快照。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnchorScanRootReport {
    pub path: String,
    /// file / dir
    pub kind: String,
    /// container / recent / custom / volume
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
    /// 目录遍历被预算、取消或读取错误截断；单 UUID 证据展示上限不计入
    pub truncated: bool,
    /// 本次扫描是否不完整（预算用尽、位置不可用或遍历截断）
    pub partial: bool,
    pub permission_errors: u64,
    pub other_errors: u64,
    pub scanned_at: u64,
    /// 全盘扫描的最大目录层级（从盘符根算起；自定义位置更深）
    pub depth: u64,
    /// 本次结果是否来自持久化缓存（true 表示未实际遍历磁盘）
    pub cached: bool,
}

/// 扫描进度（长时间全量扫描逐目标推送）。
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
