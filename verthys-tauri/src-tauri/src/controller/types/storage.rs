/*
 * 存储统计与空间压缩 DTO
 *
 * 职责边界：活数据/可回收字节统计与压缩结果。
 */

use serde::{Deserialize, Serialize};
/// 存储统计投影（非敏感计数）
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct StorageStatsDto {
    pub file_size: u64,
    pub data_end: u64,
    pub live_tree_bytes: u64,
    pub live_segment_bytes: u64,
    pub live_bytes: u64,
    pub reclaimable_bytes: u64,
    pub record_count: u64,
    pub file_count: u64,
    pub chunk_count: u64,
}

/// 空间压缩结果投影
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CompactResultDto {
    pub stage: u32,
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub reclaimed_bytes: u64,
    pub records: u64,
    pub chunks: u64,
    pub bytes: u64,
    pub live_bytes: u64,
}


