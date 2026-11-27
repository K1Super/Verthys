/*
 * 存储统计 DTO
 *
 * 职责边界：活数据/可回收字节统计。
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



