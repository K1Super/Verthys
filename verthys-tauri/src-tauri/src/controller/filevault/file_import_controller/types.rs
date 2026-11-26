/*
 * 清藏导入契约 DTO 与 worker 回包结构
 *
 * 职责边界：前端进度/结果契约与 worker IPC 回包；字段命名与前端 camelCase
 * 对齐。仅承载数据形状，不含业务逻辑。
 */

use crate::util::contracts::ChunkBlob;
use serde::{Deserialize, Serialize};


/* ------------------------------------------------------------------ *
 * 前端契约类型                                                        *
 * ------------------------------------------------------------------ */

/// 待导入文件：展示名与 MIME 由前端解析后随路径下发。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileImportSource {
    pub path: String,
    pub name: String,
    pub mime: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileImportProgress {
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileKdfOut {
    pub version: u32,
    pub salt_b64: String,
    pub iterations: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileImportEntry {
    pub meta_id: u64,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub total_chunks: u32,
    pub encrypted: bool,
    pub meta_name: String,
    pub meta_b64: String,
    pub chunk_ids: Vec<u64>,
    pub chunk_hashes: Vec<String>,
    pub chunk_size: u64,
    pub file_hash: String,
    pub entry_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf: Option<FileKdfOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_check: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileImportFailure {
    pub index: u32,
    pub name: String,
    /// 结构化原因码（前端据既有分类表映射文案）
    pub code: String,
    /// 诊断文本（不直接展示给用户）
    pub message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileImportResult {
    pub ok: bool,
    pub entries: Vec<FileImportEntry>,
    pub failures: Vec<FileImportFailure>,
    pub skipped: Vec<String>,
    pub success_count: u64,
    pub skipped_count: u64,
    pub fail_count: u64,
    pub total: u64,
    pub elapsed_ms: u64,
    pub cancelled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_warning: Option<String>,
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
    pub(super) file: Option<FileNext>,
    #[serde(default)]
    pub(super) file_finish: Option<FileFinish>,
}

/// 收尾失败：消息与结构化原因码分离，宿主按码归类而不解析文本。
pub(super) struct WorkerFailure {
    pub(super) message: String,
    pub(super) code: Option<String>,
}

impl WorkerFailure {
    pub(super) fn code_or(&self, fallback: &str) -> String {
        self.code.clone().unwrap_or_else(|| fallback.to_string())
    }
}

#[derive(Deserialize)]
pub(super) struct FileNext {
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
    pub(super) chunk_index: Option<u32>,
    #[serde(default)]
    pub(super) chunk_total: Option<u32>,
    #[serde(default)]
    pub(super) chunk_key: Option<String>,
    #[serde(default)]
    pub(super) chunk_hash: Option<String>,
    #[serde(default)]
    pub(super) chunk_staged: Option<bool>,
    #[serde(default)]
    pub(super) file_done: bool,
    #[serde(default)]
    pub(super) reason: Option<String>,
    #[serde(default)]
    pub(super) error: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct FileFinish {
    pub(super) meta_b64: String,
    pub(super) record_name: String,
    pub(super) file_hash: String,
    pub(super) entry_key: String,
    pub(super) size: u64,
    pub(super) total_chunks: u32,
    pub(super) encrypted: bool,
    pub(super) chunk_hashes: Vec<String>,
    #[serde(default)]
    pub(super) salt_b64: Option<String>,
    #[serde(default)]
    pub(super) iterations: Option<u32>,
    #[serde(default)]
    pub(super) password_check: Option<String>,
}

/* ------------------------------------------------------------------ *
 * 内部状态                                                            *
 * ------------------------------------------------------------------ */

#[derive(Default)]
pub(super) struct Totals {
    pub(super) total: u64,
    pub(super) done: u64,
    pub(super) skipped: u64,
    pub(super) failed: u64,
}

#[derive(Default)]
pub(super) struct FileProgress {
    pub(super) file_index: Option<u32>,
    pub(super) file_name: String,
    pub(super) mime: String,
    pub(super) size: u64,
    pub(super) total_chunks: u32,
    pub(super) chunk_ids: Vec<u64>,
    pub(super) buffer: Vec<ChunkBlob>,
    pub(super) abandoned: bool,
    pub(super) failure_recorded: bool,
}

pub(super) enum MetaAppend {
    Imported(u64),
    Skipped,
    Failed(String),
}
