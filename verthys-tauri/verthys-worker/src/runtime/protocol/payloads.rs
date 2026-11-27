/* payloads.rs — 媒体、文件与存储统计载荷
 *
 * 职责：照片/文件导入导出、读取、预览、元数据扫描与存储统计的响应载荷结构体。
 */

use serde::Serialize;

/// 照片导入单步结果：chunk / skipped / done / cancelled。
#[derive(Serialize)]
pub(crate) struct MediaNextPayload {
    pub(crate) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) entry_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_hash: Option<String>,
    /// true=密文已进入 worker 暂存区，响应不携带块密文
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_staged: Option<bool>,
    #[serde(default)]
    pub(crate) file_done: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) thumb_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) animated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

/// 照片导入收尾结果：已封装的 meta 密文与记录名，可选预览密文。
#[derive(Serialize)]
pub(crate) struct MediaFinishPayload {
    pub(crate) meta_b64: String,
    pub(crate) record_name: String,
    /// 预览记录密文（base64）；预览生成/封装失败时缺省
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) preview_b64: Option<String>,
    /// 预览记录名（preview_<entry_key>）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) preview_record_name: Option<String>,
    /// 还原产物的动图三态（仅 photo_restore_photo_finish 返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) animated: Option<bool>,
}

/// 清藏原生导入单步结果：chunk / empty / deduped / skipped / done / cancelled。
#[derive(Serialize)]
pub(crate) struct FileNextPayload {
    pub(crate) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_hash: Option<String>,
    /// true=密文已进入 worker 暂存区，响应不携带块密文
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_staged: Option<bool>,
    #[serde(default)]
    pub(crate) file_done: bool,
    /// 结构化失败原因码（与前端既有错误分类同值；仅 skipped 携带）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    /// 诊断文本（不直接面向用户；宿主按原因码归类）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

/// 清藏原生导入收尾结果：meta 载荷与列表回填所需的全部字段。
#[derive(Serialize)]
pub(crate) struct FileFinishPayload {
    pub(crate) meta_b64: String,
    pub(crate) record_name: String,
    pub(crate) file_hash: String,
    pub(crate) entry_key: String,
    pub(crate) size: u64,
    pub(crate) total_chunks: u32,
    pub(crate) encrypted: bool,
    pub(crate) chunk_hashes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) salt_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iterations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) password_check: Option<String>,
}

/// 预览记录写回负载（仅 photo_read_job_begin 懒生成时返回）。
#[derive(Serialize)]
pub(crate) struct MediaPreviewRecord {
    pub(crate) name: String,
    pub(crate) data_b64: String,
}

/// 网格展示用的照片元数据（仅 photo_meta_get 返回）。
#[derive(Serialize)]
pub(crate) struct MediaMetaItem {
    pub(crate) meta_id: u64,
    pub(crate) name: String,
    pub(crate) mime: String,
    pub(crate) size: u64,
    pub(crate) file_hash: String,
    pub(crate) entry_key: String,
    /// 展示用缩略图（base64；既有布局内联，瘦身布局读独立记录）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) thumb_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) animated: Option<bool>,
    pub(crate) created_at: i64,
    /// 索引瘦身布局标记
    pub(crate) slim: bool,
}

/// 照片元数据损坏扫描结果（仅 photo_meta_probe 返回）。
#[derive(Serialize)]
pub(crate) struct MediaDamageScan {
    pub(crate) checked: u64,
    pub(crate) damaged: Vec<u64>,
    pub(crate) inconclusive: u64,
}

/// VENC 预览清单（仅 photo_venc_inspect 返回）。
#[derive(Serialize)]
pub(crate) struct MediaVencPreview {
    pub(crate) name: String,
    pub(crate) mime: String,
    pub(crate) size: u64,
    pub(crate) file_hash: String,
    pub(crate) thumb_b64: String,
    pub(crate) chunk_count: u32,
    pub(crate) created_at: i64,
}

/// 照片读取结果：preview（一次返回整张预览）/ chunk（原图分块）/ done / cancelled。
#[derive(Serialize)]
pub(crate) struct MediaReadPayload {
    pub(crate) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) meta_id: Option<u64>,
    /// 照片显示名（来自 meta）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunk_total: Option<u32>,
    /// 展示字节（预览 JPEG 或原图明文块，base64）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data_b64: Option<String>,
    /// 原图明文块的共享内存名称（存在时宿主改读 SHM，data_b64 为空）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) shm_name: Option<String>,
    /// 共享内存中的明文载荷长度（字节）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) shm_len: Option<u64>,
    /// 预览是否直接命中已落库记录（false/缺省表示本次新生成）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) preview_cached: Option<bool>,
}

/// 照片导出单事件：file_begin / segment / file_end / photo / done。
#[derive(Serialize)]
pub(crate) struct MediaExportPayload {
    pub(crate) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_index: Option<u32>,
    /// 建议文件名（宿主净化与唯一化后落盘）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) size: Option<u64>,
    /// 当前文件的一段字节（base64，解码后 ≤4MiB）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data_b64: Option<String>,
    /// file_end 的成败：false 表示该文件必须中止
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_ok: Option<bool>,
    /// 照片结果（status=photo）的名称与原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    /// 失败原因分类（ok/failed/skipped）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) photo_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_code: Option<String>,
}

/// 存储统计投影（仅 storage_stats 返回；非敏感计数）
#[derive(Serialize, Clone, Default)]
pub(crate) struct StorageStatsEntry {
    pub(crate) file_size: u64,
    pub(crate) data_end: u64,
    pub(crate) live_tree_bytes: u64,
    pub(crate) live_segment_bytes: u64,
    pub(crate) live_bytes: u64,
    pub(crate) reclaimable_bytes: u64,
    pub(crate) record_count: u64,
    pub(crate) file_count: u64,
    pub(crate) chunk_count: u64,
}

