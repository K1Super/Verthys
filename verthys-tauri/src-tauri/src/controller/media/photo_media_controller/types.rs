/*
 * 照片数据面 DTO 与 worker 回包结构
 *
 * 职责边界：前端契约类型（进度/结果/预览/导出）与 worker IPC 回包结构。
 * 仅承载数据形状，不含业务逻辑；字段命名与前端 camelCase 契约对齐。
 */
use crate::util::contracts::ChunkBlob;
use serde::{Deserialize, Serialize};
/* ------------------------------------------------------------------ *
 * 前端契约类型                                                        *
 * ------------------------------------------------------------------ */

/// 导入进度（Channel 推送；camelCase 与前端字段对齐）
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoImportProgress {
    pub total_files: u64,
    pub done_files: u64,
    pub skipped: u64,
    pub failed: u64,
    pub current_name: String,
    pub current_chunk: u32,
    pub total_chunks: u32,
    pub percent: u8,
    pub elapsed_ms: u64,
    pub phase: String,
}

/// 单张成功导入的照片
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoImportItem {
    pub meta_id: u64,
    /// worker 生成的记录名（meta_<文件名>）
    pub name: String,
    /// 真实文件名
    pub display_name: String,
    pub thumb_b64: String,
    pub size: u64,
    pub mime: String,
    /// 三态：候选动图格式为 true/false；其他格式缺省（不序列化为 null）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub animated: Option<bool>,
}

/// 单张失败照片（reason 限定为前端既有枚举）
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoImportFailure {
    pub index: u32,
    pub name: String,
    pub reason: String,
    pub retryable: bool,
}

/// 导入结果
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoImportResult {
    pub ok: bool,
    pub imported: Vec<PhotoImportItem>,
    pub failed_records: Vec<PhotoImportFailure>,
    pub skipped: u64,
    pub total: u64,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub cancelled: bool,
}

/* ------------------------------------------------------------------ *
 * worker 协议投影                                                     *
 * ------------------------------------------------------------------ */

#[derive(Deserialize)]
pub(super) struct WorkerReply {
    #[serde(default)]
    pub(super) ok: bool,
    #[serde(default)]
    pub(super) error: Option<String>,
    #[serde(default)]
    pub(super) error_code: Option<String>,
    #[serde(default)]
    pub(super) photo: Option<PhotoPayload>,
    #[serde(default)]
    pub(super) photo_finish: Option<PhotoFinishPayload>,
    #[serde(default)]
    pub(super) photo_read: Option<PhotoReadPayload>,
    #[serde(default)]
    pub(super) photo_record: Option<PhotoRecordPayload>,
    #[serde(default)]
    pub(super) photo_export: Option<PhotoExportPayload>,
    #[serde(default)]
    pub(super) photo_meta: Option<Vec<WorkerMetaItem>>,
    #[serde(default)]
    pub(super) photo_damage: Option<WorkerDamageScan>,
    #[serde(default)]
    pub(super) photo_previews: Option<Vec<WorkerVencPreview>>,
    #[serde(default)]
    pub(super) failed_ids: Option<Vec<u64>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct WorkerMetaItem {
    pub(super) meta_id: u64,
    pub(super) name: String,
    pub(super) mime: String,
    pub(super) size: u64,
    pub(super) file_hash: String,
    pub(super) entry_key: String,
    #[serde(default)]
    pub(super) thumb_b64: Option<String>,
    #[serde(default)]
    pub(super) animated: Option<bool>,
    pub(super) created_at: i64,
    pub(super) slim: bool,
}

#[derive(Deserialize)]
pub(super) struct WorkerDamageScan {
    pub(super) checked: u64,
    pub(super) damaged: Vec<u64>,
    pub(super) inconclusive: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct WorkerVencPreview {
    pub(super) name: String,
    pub(super) mime: String,
    pub(super) size: u64,
    pub(super) file_hash: String,
    pub(super) thumb_b64: String,
    pub(super) chunk_count: u32,
    pub(super) created_at: i64,
}

/// 照片读取结果（worker 协议投影）
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PhotoReadPayload {
    #[serde(default)]
    pub(super) status: String,
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) mime: Option<String>,
    #[serde(default)]
    pub(super) size: Option<u64>,
    #[serde(default)]
    pub(super) chunk_index: Option<u32>,
    #[serde(default)]
    pub(super) chunk_total: Option<u32>,
    #[serde(default)]
    pub(super) data_b64: Option<String>,
    /// 原图明文块所在共享内存名称（存在时优先于 data_b64）
    #[serde(default)]
    pub(super) shm_name: Option<String>,
    /// 共享内存中的明文载荷长度
    #[serde(default)]
    pub(super) shm_len: Option<u64>,
    #[serde(default)]
    pub(super) preview_cached: Option<bool>,
}

/// 懒生成预览的待写回记录
#[derive(Deserialize)]
pub(super) struct PhotoRecordPayload {
    pub(super) name: String,
    pub(super) data_b64: String,
}

#[derive(Deserialize)]
pub(super) struct PhotoPayload {
    #[serde(default)]
    pub(super) status: String,
    #[serde(default)]
    pub(super) file_index: Option<u32>,
    #[serde(default)]
    pub(super) file_name: Option<String>,
    #[serde(default)]
    pub(super) mime: Option<String>,
    #[serde(default)]
    pub(super) size: Option<u64>,
    #[serde(default)]
    pub(super) entry_key: Option<String>,
    #[serde(default)]
    pub(super) chunk_index: Option<u32>,
    #[serde(default)]
    pub(super) chunk_total: Option<u32>,
    #[serde(default)]
    pub(super) chunk_key: Option<String>,
    #[serde(default)]
    pub(super) chunk_hash: Option<String>,
    /// true=密文在 worker 暂存区，响应不携带块密文
    #[serde(default)]
    pub(super) chunk_staged: Option<bool>,
    #[serde(default)]
    pub(super) file_done: bool,
    #[serde(default)]
    pub(super) thumb_b64: Option<String>,
    #[serde(default)]
    pub(super) animated: Option<bool>,
    #[serde(default)]
    pub(super) error: Option<String>,
}

/// worker 导出的单事件投影
#[derive(Deserialize)]
pub(super) struct PhotoExportPayload {
    #[serde(default)]
    pub(super) status: String,
    #[serde(default)]
    pub(super) file_index: Option<u32>,
    #[serde(default)]
    pub(super) file_name: Option<String>,
    #[serde(default)]
    pub(super) mime: Option<String>,
    #[serde(default)]
    pub(super) data_b64: Option<String>,
    #[serde(default)]
    pub(super) file_ok: Option<bool>,
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) reason: Option<String>,
    #[serde(default)]
    pub(super) photo_status: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PhotoFinishPayload {
    pub(super) meta_b64: String,
    pub(super) record_name: String,
    #[serde(default)]
    pub(super) preview_b64: Option<String>,
    #[serde(default)]
    pub(super) preview_record_name: Option<String>,
    #[serde(default)]
    pub(super) animated: Option<bool>,
}

/* ------------------------------------------------------------------ *
 * 内部状态                                                            *
 * ------------------------------------------------------------------ */

#[derive(Default)]
pub(super) struct ImportTotals {
    pub(super) total: u64,
    pub(super) done: u64,
    pub(super) skipped: u64,
    pub(super) failed: u64,
}

/// 当前文件的分块/元数据累积状态；file_index 变化即视为新文件
#[derive(Default)]
pub(super) struct FileProgress {
    pub(super) file_index: Option<u32>,
    pub(super) file_name: String,
    pub(super) mime: String,
    pub(super) size: u64,
    pub(super) entry_key: String,
    pub(super) thumb_b64: String,
    pub(super) animated: Option<bool>,
    pub(super) chunk_ids: Vec<u64>,
    pub(super) chunk_hashes: Vec<String>,
    pub(super) buffer: Vec<ChunkBlob>,
    pub(super) abandoned: bool,
    pub(super) failure_recorded: bool,
}

pub(super) enum MetaAppend {
    Imported(u64),
    Skipped,
    Failed(String),
}

/* ------------------------------------------------------------------ *
 * worker IPC 辅助                                                     *
 * ------------------------------------------------------------------ */
