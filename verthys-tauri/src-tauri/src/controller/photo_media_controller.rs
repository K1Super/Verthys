/*
 * controller/photo_media_controller.rs — 宿主侧原生照片导入控制器
 *
 * 职责：把 worker 的原生导入 job（读文件 / BLAKE3 / 缩略图 / 加密分块）与
 * 宿主单写者通道串起来：逐块取密文 → 经写者落库 → 收尾写 meta，并把进度
 * 通过 Channel 推给前端。
 *
 * 关键约束：
 *   - 同一时刻只允许一个照片导入任务（对导入会话的串行占用由 AppState 槽位保证）；
 *   - worker 侧 job 按 path 批（≤10,000）切分，每个子批独立 job_id，共享同一导入会话；
 *   - 路径授权 TTL 600s，导入中途按剩余路径滚动续期，避免大批量授权过期；
 *   - 单文件失败必须继续后续文件，绝不因单张照片中止整批；
 *   - 源文件只读，不删除、不移动。
 *
 * 依赖方向：controller → state / util / controller::verthys_batch_controller
 */

use crate::constants::record_types::{TYPE_PHOTO_CHUNK, TYPE_PHOTO_PREVIEW};
use crate::controller::file_controller::{
    audit_export_event, stream_abort_blocking, stream_append_blocking, stream_create_blocking,
    stream_finalize_blocking,
};
use crate::controller::verthys_batch_controller::{
    submit_writer_cmd, verthys_gc_orphan_chunks, verthys_import_begin, verthys_import_end,
    IMPORT_SESSION_BUSY_CODE,
};
use crate::controller::verthys_controller::require_unlocked;
use crate::state::file_streams::FileStreamState;
use crate::state::import_writer::{self, BatchAppendOutcome, ChunkAppendOutcome, WriterCommand};
use crate::state::AppState;
use crate::util::contracts::{BatchRecordInput, ChunkBlob};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::ipc::Channel;
use tauri::{Manager, State};

/// 单个 worker job 的路径上限（与 worker 侧 MAX_JOB_PATHS 一致）
const MAX_JOB_PATHS: usize = 10_000;

/// 路径授权 / job 建立超时
const AUTHORIZE_TIMEOUT: Duration = Duration::from_secs(60);
const BEGIN_TIMEOUT: Duration = Duration::from_secs(60);
/// 单次 next / finish 的超时：首次 next 会触发 100MiB 文件的整文件哈希与缩略图
const NEXT_TIMEOUT: Duration = Duration::from_secs(300);
const FINISH_TIMEOUT: Duration = Duration::from_secs(300);
/// 子批 job 结束超时
const END_TIMEOUT: Duration = Duration::from_secs(30);

/// 路径授权续期阈值：worker TTL 为 600s，取一半时间滚动续期
const GRANT_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// 块缓冲上限：凑满 2 块（约 8MiB 明文）立即落库，压低内存驻留
const CHUNK_BUFFER_LIMIT: usize = 2;

/// 照片 meta 记录类型（与前端 TYPE_PHOTO_META 同值）
const PHOTO_META_RTYPE: u32 = 0x01;

const PHASE_SCANNING: &str = "scanning";
const PHASE_IMPORTING: &str = "importing";
const PHASE_FINISHING: &str = "finishing";
const PHASE_DONE: &str = "done";
const PHASE_CANCELLED: &str = "cancelled";

/// 结构化错误码：并发导入被拒绝（前端据此提示已有任务进行中）
const ERROR_CODE_BUSY: &str = "E_PHOTO_IMPORT_BUSY";
/// 结构化错误码：容器会话未就绪
const ERROR_CODE_NOT_READY: &str = "E_VERTHYS_NOT_READY";

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
struct WorkerReply {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    photo: Option<PhotoPayload>,
    #[serde(default)]
    photo_finish: Option<PhotoFinishPayload>,
    #[serde(default)]
    photo_read: Option<PhotoReadPayload>,
    #[serde(default)]
    photo_record: Option<PhotoRecordPayload>,
    #[serde(default)]
    photo_export: Option<PhotoExportPayload>,
    #[serde(default)]
    photo_meta: Option<Vec<WorkerMetaItem>>,
    #[serde(default)]
    photo_damage: Option<WorkerDamageScan>,
    #[serde(default)]
    photo_previews: Option<Vec<WorkerVencPreview>>,
    #[serde(default)]
    failed_ids: Option<Vec<u64>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct WorkerMetaItem {
    meta_id: u64,
    name: String,
    mime: String,
    size: u64,
    file_hash: String,
    entry_key: String,
    #[serde(default)]
    thumb_b64: Option<String>,
    #[serde(default)]
    animated: Option<bool>,
    created_at: i64,
    slim: bool,
}

#[derive(Deserialize)]
struct WorkerDamageScan {
    checked: u64,
    damaged: Vec<u64>,
    inconclusive: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct WorkerVencPreview {
    name: String,
    mime: String,
    size: u64,
    file_hash: String,
    thumb_b64: String,
    chunk_count: u32,
    created_at: i64,
}

/// 照片读取结果（worker 协议投影）
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct PhotoReadPayload {
    #[serde(default)]
    status: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    mime: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    chunk_index: Option<u32>,
    #[serde(default)]
    chunk_total: Option<u32>,
    #[serde(default)]
    data_b64: Option<String>,
    #[serde(default)]
    preview_cached: Option<bool>,
}

/// 懒生成预览的待写回记录
#[derive(Deserialize)]
struct PhotoRecordPayload {
    name: String,
    data_b64: String,
}

#[derive(Deserialize)]
struct PhotoPayload {
    #[serde(default)]
    status: String,
    #[serde(default)]
    file_index: Option<u32>,
    #[serde(default)]
    file_name: Option<String>,
    #[serde(default)]
    mime: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    entry_key: Option<String>,
    #[serde(default)]
    chunk_index: Option<u32>,
    #[serde(default)]
    chunk_total: Option<u32>,
    #[serde(default)]
    chunk_key: Option<String>,
    #[serde(default)]
    chunk_b64: Option<String>,
    #[serde(default)]
    chunk_hash: Option<String>,
    #[serde(default)]
    file_done: bool,
    #[serde(default)]
    thumb_b64: Option<String>,
    #[serde(default)]
    animated: Option<bool>,
    #[serde(default)]
    error: Option<String>,
}

/// worker 导出的单事件投影
#[derive(Deserialize)]
struct PhotoExportPayload {
    #[serde(default)]
    status: String,
    #[serde(default)]
    file_index: Option<u32>,
    #[serde(default)]
    file_name: Option<String>,
    #[serde(default)]
    mime: Option<String>,
    #[serde(default)]
    data_b64: Option<String>,
    #[serde(default)]
    file_ok: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    photo_status: Option<String>,
}

#[derive(Deserialize)]
struct PhotoFinishPayload {
    meta_b64: String,
    record_name: String,
    #[serde(default)]
    preview_b64: Option<String>,
    #[serde(default)]
    preview_record_name: Option<String>,
    #[serde(default)]
    animated: Option<bool>,
}

/* ------------------------------------------------------------------ *
 * 内部状态                                                            *
 * ------------------------------------------------------------------ */

#[derive(Default)]
struct ImportTotals {
    total: u64,
    done: u64,
    skipped: u64,
    failed: u64,
}

/// 当前文件的分块/元数据累积状态；file_index 变化即视为新文件
#[derive(Default)]
struct FileProgress {
    file_index: Option<u32>,
    file_name: String,
    mime: String,
    size: u64,
    entry_key: String,
    thumb_b64: String,
    animated: Option<bool>,
    chunk_ids: Vec<u64>,
    chunk_hashes: Vec<String>,
    buffer: Vec<ChunkBlob>,
    abandoned: bool,
    failure_recorded: bool,
}

enum MetaAppend {
    Imported(u64),
    Skipped,
    Failed(String),
}

/* ------------------------------------------------------------------ *
 * worker IPC 辅助                                                     *
 * ------------------------------------------------------------------ */

/// 阻塞式 worker IPC 必须移出异步运行时线程
async fn send_worker(
    app: &tauri::AppHandle,
    payload: serde_json::Value,
    timeout: Duration,
) -> Result<String, String> {
    let app = app.clone();
    let json = payload.to_string();
    match tauri::async_runtime::spawn_blocking(move || {
        app.state::<AppState>()
            .send_with_timeout(&json, timeout)
    })
    .await
    {
        Ok(result) => result,
        Err(e) => Err(format!("worker 通信任务异常: {}", e)),
    }
}

fn parse_reply(what: &str, raw: &str) -> Result<WorkerReply, String> {
    serde_json::from_str(raw).map_err(|e| format!("{} 响应解析失败: {}", what, e))
}

async fn authorize_batch(
    app: &tauri::AppHandle,
    job_id: &str,
    paths: &[String],
) -> Result<(), String> {
    let raw = send_worker(
        app,
        serde_json::json!({
            "op": "authorize_path_batch",
            "job_id": job_id,
            "paths": paths,
        }),
        AUTHORIZE_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("authorize_path_batch", &raw)?;
    if reply.ok {
        Ok(())
    } else {
        Err(reply
            .error
            .unwrap_or_else(|| "照片路径授权失败".to_string()))
    }
}

async fn begin_job(
    app: &tauri::AppHandle,
    job_id: &str,
    paths: &[String],
) -> Result<(), String> {
    let raw = send_worker(
        app,
        serde_json::json!({
            "op": "photo_import_job_begin",
            "job_id": job_id,
            "paths": paths,
        }),
        BEGIN_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("photo_import_job_begin", &raw)?;
    if reply.ok {
        Ok(())
    } else {
        Err(reply
            .error
            .unwrap_or_else(|| "照片导入任务建立失败".to_string()))
    }
}

async fn end_job(app: &tauri::AppHandle, job_id: &str) -> Result<(), String> {
    let raw = send_worker(
        app,
        serde_json::json!({"op": "photo_import_job_end", "job_id": job_id}),
        END_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("photo_import_job_end", &raw)?;
    if reply.ok {
        Ok(())
    } else {
        Err(reply
            .error
            .unwrap_or_else(|| "照片导入任务结束失败".to_string()))
    }
}

/// 收尾单文件：worker 校验块数与增量哈希后返回 meta 密文
async fn finish_job(
    app: &tauri::AppHandle,
    job_id: &str,
    chunk_ids: &[u64],
) -> Result<PhotoFinishPayload, String> {
    let raw = send_worker(
        app,
        serde_json::json!({
            "op": "photo_import_job_finish",
            "job_id": job_id,
            "chunk_ids": chunk_ids,
        }),
        FINISH_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("photo_import_job_finish", &raw)?;
    if !reply.ok {
        return Err(reply
            .error
            .unwrap_or_else(|| "照片收尾失败".to_string()));
    }
    reply
        .photo_finish
        .ok_or_else(|| "照片收尾响应缺少结果".to_string())
}

/* ------------------------------------------------------------------ *
 * 写者通道辅助                                                        *
 * ------------------------------------------------------------------ */

/// 提交当前缓冲的全部块；块数/失败下标/0 ID 任一异常即视为该文件失败
async fn flush_chunk_buffer(
    app: &tauri::AppHandle,
    file: &mut FileProgress,
) -> Result<(), String> {
    if file.buffer.is_empty() {
        return Ok(());
    }
    let writer = import_writer::ensure(app)?;
    let chunks = std::mem::take(&mut file.buffer);
    let expected = chunks.len();
    let (reply_tx, reply_rx) =
        tokio::sync::oneshot::channel::<Result<ChunkAppendOutcome, String>>();
    let cmd = WriterCommand::AppendChunks {
        chunks,
        reply: reply_tx,
    };
    let outcome = submit_writer_cmd(&writer, cmd, reply_rx).await?;
    if !outcome.failed_indices.is_empty() || outcome.ids.len() != expected {
        return Err("照片块写入被拒绝".to_string());
    }
    if outcome.ids.iter().any(|id| *id == 0) {
        return Err("照片块未分配记录 ID".to_string());
    }
    file.chunk_ids.extend(outcome.ids);
    Ok(())
}

/// 写入 meta 记录；依赖写者按 entry_key 做幂等去重
async fn append_meta(
    app: &tauri::AppHandle,
    file: &FileProgress,
    finish: &PhotoFinishPayload,
) -> MetaAppend {
    let writer = match import_writer::ensure(app) {
        Ok(w) => w,
        Err(e) => {
            log::warn!("[photo_import] meta 写者不可用: {}", e);
            return MetaAppend::Failed(e);
        }
    };
    let mut records = vec![BatchRecordInput {
        rtype: PHOTO_META_RTYPE,
        name: finish.record_name.clone(),
        entry_key: file.entry_key.clone(),
        data_b64: finish.meta_b64.clone(),
        chunk_ids: Some(file.chunk_ids.clone()),
        chunk_hashes: Some(file.chunk_hashes.clone()),
    }];
    /* 预览与 meta 共用条目键：同一批次提交，导入重试时一起幂等跳过。
     * 预览是派生缓存，缺失不影响照片可用性。 */
    if let (Some(preview_b64), Some(preview_name)) =
        (finish.preview_b64.as_ref(), finish.preview_record_name.as_ref())
    {
        records.push(BatchRecordInput {
            rtype: TYPE_PHOTO_PREVIEW,
            name: preview_name.clone(),
            entry_key: file.entry_key.clone(),
            data_b64: preview_b64.clone(),
            chunk_ids: None,
            chunk_hashes: None,
        });
    }
    let (reply_tx, reply_rx) =
        tokio::sync::oneshot::channel::<Result<BatchAppendOutcome, String>>();
    let cmd = WriterCommand::AppendPending {
        records,
        progress: None,
        reply: reply_tx,
    };
    let outcome = match submit_writer_cmd(&writer, cmd, reply_rx).await {
        Ok(o) => o,
        Err(e) => {
            log::warn!("[photo_import] meta 写入通道失败: {}", e);
            return MetaAppend::Failed(e);
        }
    };
    let id = outcome.ids.first().copied().unwrap_or(0);
    if id > 0 {
        /* 预览失败只丢派生缓存，照片本身已导入；逐条失败下标如实记录。 */
        if !outcome.failed_indices.is_empty() {
            log::warn!(
                "[photo_import] 预览记录写入失败（照片已导入）: failed={:?}",
                outcome.failed_indices
            );
        }
        return MetaAppend::Imported(id);
    }
    if outcome.failed_indices.is_empty() {
        MetaAppend::Skipped
    } else {
        // 写者应答不含逐条错误文本，只能按「服务端拒绝」归类；
        // 容量告罄由返回 Err 的通道级错误识别。
        let msg = "照片索引写入被拒绝".to_string();
        log::warn!("[photo_import] meta 写入失败: {}", msg);
        MetaAppend::Failed(msg)
    }
}

/* ------------------------------------------------------------------ *
 * 失败归类                                                            *
 * ------------------------------------------------------------------ */

fn is_storage_full(msg: &str) -> bool {
    msg.contains("ERR_0000000F")
}

/// worker skipped 的原因文本 → 前端既有枚举
fn map_skipped_reason(reason: &str) -> (&'static str, bool) {
    if reason.contains("超过单张照片上限") {
        ("file-too-large", false)
    } else if reason.contains("加密") {
        ("encrypt-failed", false)
    } else if reason.contains("授权") {
        // 授权过期可通过重试恢复；本地读取失败需要用户介入
        ("read-failed", true)
    } else if reason.contains("读取")
        || reason.contains("打开")
        || reason.contains("定位")
        || reason.contains("为空")
        || reason.contains("不支持")
    {
        ("read-failed", false)
    } else {
        ("unknown", false)
    }
}

fn meta_name(file_name: &str) -> String {
    format!("meta_{}", file_name)
}

fn record_file_failure(
    totals: &mut ImportTotals,
    failed_records: &mut Vec<PhotoImportFailure>,
    file: &mut FileProgress,
    batch_offset: u32,
    reason: &str,
    retryable: bool,
) {
    if file.failure_recorded {
        return;
    }
    file.failure_recorded = true;
    totals.failed += 1;
    failed_records.push(PhotoImportFailure {
        index: batch_offset.saturating_add(file.file_index.unwrap_or(0)),
        name: meta_name(&file.file_name),
        reason: reason.to_string(),
        retryable,
    });
}

fn is_job_gone(err: &str) -> bool {
    err.contains("job 不存在") || err.contains("已结束")
}

/// 丢弃残留导入会话（锁库/崩溃后未 end）：不压缩 WAL，保留磁盘续传状态。
///
/// 只丢弃绑定到其他容器路径的会话；当前容器的活跃会话（例如清藏在导入）
/// 不在此处抢占，调用方继续按 E_IMPORT_SESSION_BUSY 提示用户。
fn discard_stale_import_session(app: &tauri::AppHandle) -> bool {
    let state = app.state::<AppState>();
    let current = state.verthys_session_path();
    let stale = {
        let mut guard = state.lock_import_session();
        let belongs_to_current = guard
            .as_ref()
            .map(|session| current.as_deref() == Some(session.verthys_path.as_str()))
            .unwrap_or(false);
        if belongs_to_current {
            None
        } else {
            guard.take()
        }
    };
    match stale {
        Some(session) => {
            log::warn!(
                "[photo_media] 丢弃残留导入会话 import_id={}（保留磁盘 WAL）",
                session.import_id
            );
            state.set_bulk_defer(false);
            true
        }
        None => false,
    }
}

/* ------------------------------------------------------------------ *
 * 进度推送                                                            *
 * ------------------------------------------------------------------ */

fn emit_progress(
    channel: &Channel<PhotoImportProgress>,
    totals: &ImportTotals,
    phase: &str,
    current_name: &str,
    current_chunk: u32,
    total_chunks: u32,
    elapsed: Duration,
) {
    let percent = if phase == PHASE_FINISHING || phase == PHASE_DONE {
        100
    } else if totals.total == 0 {
        0
    } else {
        (totals.done.saturating_mul(100) / totals.total).min(99) as u8
    };
    // 进度只是展示，Channel 断开不应阻断存储路径
    let _ = channel.send(PhotoImportProgress {
        total_files: totals.total,
        done_files: totals.done,
        skipped: totals.skipped,
        failed: totals.failed,
        current_name: current_name.to_string(),
        current_chunk,
        total_chunks,
        percent,
        elapsed_ms: elapsed.as_millis() as u64,
        phase: phase.to_string(),
    });
}

/* ------------------------------------------------------------------ *
 * job_id 生成                                                         *
 * ------------------------------------------------------------------ */

fn generate_job_id() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let mut rand_buf = [0u8; 4];
    let random = match getrandom::getrandom(&mut rand_buf) {
        Ok(()) => u32::from_le_bytes(rand_buf),
        // 随机源不可用时用时间低位兜底：job_id 只需进程内唯一
        Err(_) => ts as u32,
    };
    format!("photo-{}-{:x}", ts, random)
}

/* ------------------------------------------------------------------ *
 * 命令：photo_import_start                                            *
 * ------------------------------------------------------------------ */

#[tauri::command]
pub async fn photo_import_start(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    paths: Vec<String>,
    on_progress: Channel<PhotoImportProgress>,
) -> Result<PhotoImportResult, String> {
    let started = Instant::now();
    let total = paths.len() as u64;

    if let Err(msg) = require_unlocked(&app, &state, "photo_import_start") {
        return Ok(failure_result(
            total,
            started,
            msg,
            Some(ERROR_CODE_NOT_READY.to_string()),
        ));
    }

    if paths.is_empty() {
        return Ok(failure_result(total, started, "未选择照片".to_string(), None));
    }

    let job_id = generate_job_id();
    let cancel = match state.try_begin_photo_import(&job_id) {
        Ok(flag) => flag,
        Err(msg) => {
            return Ok(failure_result(
                total,
                started,
                msg,
                Some(ERROR_CODE_BUSY.to_string()),
            ))
        }
    };

    let result = run_import(&app, &job_id, cancel, paths, on_progress, started).await;

    // 所有返回路径都必须释放槽位；按 job_id 比对，避免误清后来者
    state.finish_photo_import(&job_id);

    /* 成功/取消/失败收尾后都回收无主块（块已落库但 meta 未提交的半成品）。
     * best-effort：清理失败不影响本次导入语义；重试会重新上传。 */
    {
        let gc_app = app.clone();
        tauri::async_runtime::spawn(async move {
            let gc_state = gc_app.state::<AppState>();
            match verthys_gc_orphan_chunks(gc_app.clone(), gc_state).await {
                Ok(resp) if !resp.ok => log::warn!(
                    "[photo_import] 孤儿块清理失败: {}",
                    resp.error.unwrap_or_else(|| "未知错误".to_string())
                ),
                Err(e) => log::warn!("[photo_import] 孤儿块清理异常: {}", e),
                _ => {}
            }
        });
    }

    Ok(result)
}

fn failure_result(
    total: u64,
    started: Instant,
    error: String,
    error_code: Option<String>,
) -> PhotoImportResult {
    PhotoImportResult {
        ok: false,
        imported: Vec::new(),
        failed_records: Vec::new(),
        skipped: 0,
        total,
        elapsed_ms: started.elapsed().as_millis() as u64,
        error: Some(error),
        error_code,
        cancelled: false,
    }
}

/* ------------------------------------------------------------------ *
 * 导入主流程                                                          *
 * ------------------------------------------------------------------ */

async fn run_import(
    app: &tauri::AppHandle,
    base_job_id: &str,
    cancel: Arc<AtomicBool>,
    paths: Vec<String>,
    channel: Channel<PhotoImportProgress>,
    started: Instant,
) -> PhotoImportResult {
    let mut totals = ImportTotals {
        total: paths.len() as u64,
        ..Default::default()
    };
    let mut imported: Vec<PhotoImportItem> = Vec::new();
    let mut failed_records: Vec<PhotoImportFailure> = Vec::new();
    let mut cancelled = false;
    let mut session_error: Option<String> = None;

    emit_progress(&channel, &totals, PHASE_SCANNING, "", 0, 0, started.elapsed());

    // 建立导入会话；会话冲突（锁库/崩溃残留）时丢弃旧会话后重试一次
    let mut begin = match verthys_import_begin(app.clone(), app.state::<AppState>(), None).await {
        Ok(resp) => resp,
        Err(e) => {
            return PhotoImportResult {
                ok: false,
                imported,
                failed_records,
                skipped: 0,
                total: totals.total,
                elapsed_ms: started.elapsed().as_millis() as u64,
                error: Some(e),
                error_code: None,
                cancelled: false,
            }
        }
    };
    if !begin.ok
        && begin.error_code.as_deref() == Some(IMPORT_SESSION_BUSY_CODE)
        && discard_stale_import_session(app)
    {
        log::warn!("[photo_import] 已丢弃其他容器的残留导入会话，重试建立会话");
        begin = match verthys_import_begin(app.clone(), app.state::<AppState>(), None).await {
            Ok(resp) => resp,
            Err(e) => {
                return PhotoImportResult {
                    ok: false,
                    imported,
                    failed_records,
                    skipped: 0,
                    total: totals.total,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    error: Some(e),
                    error_code: None,
                    cancelled: false,
                }
            }
        };
    }
    if !begin.ok {
        return PhotoImportResult {
            ok: false,
            imported,
            failed_records,
            skipped: 0,
            total: totals.total,
            elapsed_ms: started.elapsed().as_millis() as u64,
            error: begin.error,
            error_code: begin.error_code,
            cancelled: false,
        };
    }

    for (batch_index, batch_paths) in paths.chunks(MAX_JOB_PATHS).enumerate() {
        if cancel.load(Ordering::SeqCst) {
            cancelled = true;
            break;
        }

        // 首个批次直接沿用基础 job_id，使 cancel 能命中 worker 侧真实 job
        let job_id = if batch_index == 0 {
            base_job_id.to_string()
        } else {
            format!("{}-{}", base_job_id, batch_index)
        };
        // 失败下标对前端是全局输入下标，需叠加本批在原始 paths 中的偏移
        let batch_offset = (batch_index * MAX_JOB_PATHS) as u32;

        if let Err(e) = authorize_batch(app, &job_id, batch_paths).await {
            log::error!("[photo_import] 批量路径授权失败: {}", e);
            session_error = Some(e);
            break;
        }
        if let Err(e) = begin_job(app, &job_id, batch_paths).await {
            log::error!("[photo_import] 照片导入任务建立失败: {}", e);
            session_error = Some(e);
            let _ = end_job(app, &job_id).await;
            break;
        }

        let mut grant_refreshed_at = Instant::now();
        let mut next_index: u32 = 0;
        let mut file = FileProgress::default();

        loop {
            if cancel.load(Ordering::SeqCst) {
                cancelled = true;
                break;
            }

            // TTL 滚动续期：仅续期尚未处理的路径，已打开的文件不受影响
            if grant_refreshed_at.elapsed() >= GRANT_REFRESH_INTERVAL {
                let start = (next_index as usize + 1).min(batch_paths.len());
                let remaining = &batch_paths[start..];
                if !remaining.is_empty() {
                    if let Err(e) = authorize_batch(app, &job_id, remaining).await {
                        log::error!("[photo_import] 授权续期失败: {}", e);
                        session_error = Some(e);
                        break;
                    }
                }
                grant_refreshed_at = Instant::now();
            }

            let raw = match send_worker(
                app,
                serde_json::json!({"op": "photo_import_job_next", "job_id": job_id}),
                NEXT_TIMEOUT,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    session_error = Some(e);
                    break;
                }
            };
            let reply = match parse_reply("photo_import_job_next", &raw) {
                Ok(v) => v,
                Err(e) => {
                    session_error = Some(e);
                    break;
                }
            };
            if !reply.ok {
                let err = reply
                    .error
                    .unwrap_or_else(|| "照片导入失败".to_string());
                if cancel.load(Ordering::SeqCst) {
                    cancelled = true;
                } else if is_job_gone(&err) {
                    // job 已被取消或清理，按批结束处理
                    log::warn!("[photo_import] worker job 已结束: {}", err);
                } else {
                    // 会话级错误：结束整个导入，不做无限重试
                    log::error!("[photo_import] next 失败: {}", err);
                    session_error = Some(err);
                }
                break;
            }

            let Some(photo) = reply.photo else {
                session_error = Some("照片导入响应缺少 photo 字段".to_string());
                break;
            };

            if let Some(idx) = photo.file_index {
                next_index = idx;
            }
            let current_name = photo.file_name.clone().unwrap_or_default();
            let current_chunk = photo.chunk_index.map(|i| i.saturating_add(1)).unwrap_or(0);
            let total_chunks = photo.chunk_total.unwrap_or(0);

            match photo.status.as_str() {
                "chunk" => {
                    if file.file_index != photo.file_index {
                        file = FileProgress {
                            file_index: photo.file_index,
                            ..Default::default()
                        };
                    }
                    file.file_name = photo.file_name.clone().unwrap_or_default();
                    file.mime = photo.mime.clone().unwrap_or_default();
                    if let Some(size) = photo.size {
                        file.size = size;
                    }
                    file.entry_key = photo.entry_key.clone().unwrap_or_default();
                    if photo.file_done {
                        file.thumb_b64 = photo.thumb_b64.clone().unwrap_or_default();
                        file.animated = photo.animated;
                    }

                    if !file.abandoned {
                        file.chunk_hashes
                            .push(photo.chunk_hash.clone().unwrap_or_default());
                        file.buffer.push(ChunkBlob {
                            chunk_key: photo.chunk_key.clone().unwrap_or_default(),
                            data_b64: photo.chunk_b64.clone().unwrap_or_default(),
                            rtype: Some(TYPE_PHOTO_CHUNK),
                        });
                        if file.buffer.len() >= CHUNK_BUFFER_LIMIT {
                            if let Err(e) = flush_chunk_buffer(app, &mut file).await {
                                log::warn!(
                                    "[photo_import] 文件 {} 块写入失败: {}",
                                    file.file_name,
                                    e
                                );
                                file.abandoned = true;
                                let reason = if is_storage_full(&e) {
                                    "storage-full"
                                } else {
                                    "chunk-upload-failed"
                                };
                                record_file_failure(
                                    &mut totals,
                                    &mut failed_records,
                                    &mut file,
                                    batch_offset,
                                    reason,
                                    !is_storage_full(&e),
                                );
                            }
                        }
                    }

                    if photo.file_done {
                        if !file.abandoned {
                            if let Err(e) = flush_chunk_buffer(app, &mut file).await {
                                log::warn!(
                                    "[photo_import] 文件 {} 尾块写入失败: {}",
                                    file.file_name,
                                    e
                                );
                                file.abandoned = true;
                                let reason = if is_storage_full(&e) {
                                    "storage-full"
                                } else {
                                    "chunk-upload-failed"
                                };
                                record_file_failure(
                                    &mut totals,
                                    &mut failed_records,
                                    &mut file,
                                    batch_offset,
                                    reason,
                                    !is_storage_full(&e),
                                );
                            }
                        }

                        if file.abandoned {
                            // 放弃文件仍需 finish 让 worker 清空当前游标，
                            // 否则下一次 next 会因分块序号越界而报错
                            let _ = finish_job(app, &job_id, &file.chunk_ids).await;
                        } else {
                            match finish_job(app, &job_id, &file.chunk_ids).await {
                                Ok(finish) => match append_meta(app, &file, &finish).await {
                                    MetaAppend::Imported(meta_id) => {
                                        imported.push(PhotoImportItem {
                                            meta_id,
                                            name: finish.record_name.clone(),
                                            display_name: file.file_name.clone(),
                                            thumb_b64: file.thumb_b64.clone(),
                                            size: file.size,
                                            mime: file.mime.clone(),
                                            animated: file.animated,
                                        });
                                    }
                                    MetaAppend::Skipped => {
                                        // 条目键幂等跳过：本次未新增记录
                                        totals.skipped += 1;
                                    }
                                    MetaAppend::Failed(e) => {
                                        let reason = if is_storage_full(&e) {
                                            "storage-full"
                                        } else {
                                            "server-rejected"
                                        };
                                        record_file_failure(
                                            &mut totals,
                                            &mut failed_records,
                                            &mut file,
                                            batch_offset,
                                            reason,
                                            !is_storage_full(&e),
                                        );
                                    }
                                },
                                Err(e) => {
                                    log::warn!(
                                        "[photo_import] 文件 {} 收尾失败: {}",
                                        file.file_name,
                                        e
                                    );
                                    let reason = if is_storage_full(&e) {
                                        "storage-full"
                                    } else {
                                        "server-rejected"
                                    };
                                    record_file_failure(
                                        &mut totals,
                                        &mut failed_records,
                                        &mut file,
                                        batch_offset,
                                        reason,
                                        !is_storage_full(&e),
                                    );
                                }
                            }
                        }

                        totals.done += 1;
                        emit_progress(
                            &channel,
                            &totals,
                            PHASE_IMPORTING,
                            &current_name,
                            current_chunk,
                            total_chunks,
                            started.elapsed(),
                        );
                        file = FileProgress::default();
                        continue;
                    }

                    emit_progress(
                        &channel,
                        &totals,
                        PHASE_IMPORTING,
                        &current_name,
                        current_chunk,
                        total_chunks,
                        started.elapsed(),
                    );
                }
                "skipped" => {
                    let source = photo.file_name.clone().unwrap_or_default();
                    let reason_text = photo.error.clone().unwrap_or_default();
                    let (reason, retryable) = map_skipped_reason(&reason_text);
                    failed_records.push(PhotoImportFailure {
                        index: batch_offset.saturating_add(photo.file_index.unwrap_or(0)),
                        name: meta_name(&source),
                        reason: reason.to_string(),
                        retryable,
                    });
                    totals.failed += 1;
                    totals.done += 1;
                    emit_progress(
                        &channel,
                        &totals,
                        PHASE_IMPORTING,
                        &source,
                        current_chunk,
                        total_chunks,
                        started.elapsed(),
                    );
                }
                "done" => break,
                "cancelled" => {
                    cancelled = true;
                    break;
                }
                other => {
                    session_error = Some(format!("未知的照片导入状态: {}", other));
                    break;
                }
            }
        }

        // 子批结束（正常/取消/会话错误）：结束 worker job，失败只记日志
        if let Err(e) = end_job(app, &job_id).await {
            log::warn!("[photo_import] 结束 worker job 失败（忽略）: {}", e);
        }

        if cancelled || session_error.is_some() {
            break;
        }
    }

    emit_progress(
        &channel,
        &totals,
        PHASE_FINISHING,
        "",
        0,
        0,
        started.elapsed(),
    );

    // 会话成功仅当未取消、无失败、无会话级错误
    let success = !cancelled && totals.failed == 0 && session_error.is_none();
    let mut end_error: Option<String> = None;
    let mut end_code: Option<String> = None;
    match verthys_import_end(app.clone(), app.state::<AppState>(), success).await {
        Ok(resp) => {
            if !resp.ok {
                end_error = Some(
                    resp.error
                        .unwrap_or_else(|| "结束导入会话失败".to_string()),
                );
                end_code = resp.error_code;
            }
        }
        Err(e) => end_error = Some(e),
    }

    let final_phase = if cancelled {
        PHASE_CANCELLED
    } else {
        PHASE_DONE
    };
    emit_progress(
        &channel,
        &totals,
        final_phase,
        "",
        0,
        0,
        started.elapsed(),
    );

    // end 失败不得声称成功：错误合入结果，不覆盖已记录的会话级错误
    if let Some(end_msg) = end_error {
        let merged = match session_error {
            Some(prev) => format!("{}；{}", prev, end_msg),
            None => end_msg,
        };
        return PhotoImportResult {
            ok: false,
            imported,
            failed_records,
            skipped: totals.skipped,
            total: totals.total,
            elapsed_ms: started.elapsed().as_millis() as u64,
            error: Some(merged),
            error_code: end_code,
            cancelled,
        };
    }

    PhotoImportResult {
        ok: !cancelled && session_error.is_none() && failed_records.is_empty(),
        imported,
        failed_records,
        skipped: totals.skipped,
        total: totals.total,
        elapsed_ms: started.elapsed().as_millis() as u64,
        error: session_error,
        error_code: None,
        cancelled,
    }
}

/* ------------------------------------------------------------------ *
 * 命令：photo_import_cancel                                           *
 * ------------------------------------------------------------------ */

/// 取消当前照片导入：本地取消标志为权威信号，worker 侧取消为 best-effort。
///
/// worker job 的子批 ID 带批序号后缀，取消任务只持有基础 job_id；即使
/// worker 侧未命中，导入循环在每个事件前检查本地标志也会及时退出。
#[tauri::command]
pub async fn photo_import_cancel(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let Some(job_id) = state.photo_import_job_id() else {
        // 无活跃任务视为幂等成功
        return Ok(());
    };
    if let Some(flag) = state.photo_import_cancel_flag(&job_id) {
        flag.store(true, Ordering::SeqCst);
    }

    // 不阻塞命令返回：worker 侧取消尽力而为
    tauri::async_runtime::spawn(async move {
        let _ = send_worker(
            &app,
            serde_json::json!({"op": "photo_import_job_cancel", "job_id": job_id}),
            END_TIMEOUT,
        )
        .await;
    });

    Ok(())
}

/* ------------------------------------------------------------------ *
 * Phase 4：网格元数据、损坏探测与备份预览                             *
 * ------------------------------------------------------------------ */

const META_BATCH_MAX: usize = 32;
const META_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_BATCH_MAX: usize = 512;
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);
const PARSE_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoMetaItem {
    pub meta_id: u64,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub file_hash: String,
    pub entry_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub animated: Option<bool>,
    pub created_at: i64,
    pub slim: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoMetaBatch {
    pub items: Vec<PhotoMetaItem>,
    pub failed_ids: Vec<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoDamageScan {
    pub checked: u64,
    pub damaged: Vec<u64>,
    pub inconclusive: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoParsePreview {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub file_hash: String,
    pub thumb_b64: String,
    pub chunk_count: u32,
    pub created_at: i64,
}

/// 批量读取网格展示元数据与缩略图（worker 内解密，前端不再接触记录密文）。
#[tauri::command]
pub async fn photo_meta_get(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    meta_ids: Vec<u64>,
) -> Result<PhotoMetaBatch, String> {
    require_unlocked(&app, &state, "photo_meta_get")?;
    let mut items = Vec::with_capacity(meta_ids.len());
    let mut failed_ids = Vec::new();
    for batch in meta_ids.chunks(META_BATCH_MAX) {
        let raw = send_worker(
            &app,
            serde_json::json!({"op": "photo_meta_get", "ids": batch}),
            META_TIMEOUT,
        )
        .await?;
        let reply = parse_reply("photo_meta_get", &raw)?;
        if !reply.ok {
            return Err(reply
                .error
                .unwrap_or_else(|| "照片元数据读取失败".to_string()));
        }
        for item in reply.photo_meta.unwrap_or_default() {
            items.push(PhotoMetaItem {
                meta_id: item.meta_id,
                name: item.name,
                mime: item.mime,
                size: item.size,
                file_hash: item.file_hash,
                entry_key: item.entry_key,
                thumb_b64: item.thumb_b64,
                animated: item.animated,
                created_at: item.created_at,
                slim: item.slim,
            });
        }
        failed_ids.extend(reply.failed_ids.unwrap_or_default());
    }
    Ok(PhotoMetaBatch { items, failed_ids })
}

/// 损坏扫描：只把内容层认证失败且非历史明文的记录判为确定损坏。
#[tauri::command]
pub async fn photo_meta_probe(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    meta_ids: Vec<u64>,
) -> Result<PhotoDamageScan, String> {
    require_unlocked(&app, &state, "photo_meta_probe")?;
    let mut scan = PhotoDamageScan {
        checked: 0,
        damaged: Vec::new(),
        inconclusive: 0,
    };
    for batch in meta_ids.chunks(PROBE_BATCH_MAX) {
        let raw = send_worker(
            &app,
            serde_json::json!({"op": "photo_meta_probe", "ids": batch}),
            PROBE_TIMEOUT,
        )
        .await?;
        let reply = parse_reply("photo_meta_probe", &raw)?;
        if !reply.ok {
            return Err(reply
                .error
                .unwrap_or_else(|| "照片损坏扫描失败".to_string()));
        }
        let Some(part) = reply.photo_damage else {
            return Err("损坏扫描响应缺少结果".to_string());
        };
        scan.checked += part.checked;
        scan.damaged.extend(part.damaged);
        scan.inconclusive += part.inconclusive;
    }
    Ok(scan)
}

/// 备份预览：worker 流式解析 .venc 清单，不把容器读入前端。
#[tauri::command]
pub async fn photo_parse_start(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: String,
    token: String,
) -> Result<Vec<PhotoParsePreview>, String> {
    require_unlocked(&app, &state, "photo_parse_start")?;
    if path.trim().is_empty() {
        return Err("未选择备份文件".to_string());
    }
    let token = token.trim().to_string();
    if token.len() < 8 {
        return Err("令牌格式不正确（至少 8 位字符）".to_string());
    }
    let job_id = format!("parse-{}", generate_job_id());
    authorize_batch_for(&app, &job_id, &[path.clone()], "photo_parse").await?;
    let result = send_worker(
        &app,
        serde_json::json!({
            "op": "photo_venc_inspect",
            "job_id": job_id,
            "path": path,
            "token": token,
        }),
        PARSE_TIMEOUT,
    )
    .await;
    // 预览不保留 worker job；end 幂等清理并撤销路径授权
    end_restore_job(&app, &job_id).await;
    let raw = result?;
    let reply = parse_reply("photo_venc_inspect", &raw)?;
    if !reply.ok {
        return Err(reply
            .error
            .unwrap_or_else(|| "备份文件解析失败".to_string()));
    }
    Ok(reply
        .photo_previews
        .unwrap_or_default()
        .into_iter()
        .map(|p| PhotoParsePreview {
            name: p.name,
            mime: p.mime,
            size: p.size,
            file_hash: p.file_hash,
            thumb_b64: p.thumb_b64,
            chunk_count: p.chunk_count,
            created_at: p.created_at,
        })
        .collect())
}

/* ------------------------------------------------------------------ *
 * Phase 2：预览与原图读取                                             *
 * ------------------------------------------------------------------ */

/// 预览首屏预算：历史照片首次懒生成需要读块/解码/编码，给足余量
const PREVIEW_TIMEOUT: Duration = Duration::from_secs(120);
const READ_BEGIN_TIMEOUT: Duration = Duration::from_secs(30);
/// 单块解密超时：4MiB 块 + AEAD 在低端机也有充足余量
const READ_NEXT_TIMEOUT: Duration = Duration::from_secs(60);
const READ_END_TIMEOUT: Duration = Duration::from_secs(10);
/// 预览派生记录写入（单条 add_record，含 TPM 锚点提交）
const DERIVED_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// 布局不支持原生读取：前端据此回退旧 JS 查看链路。
pub const PHOTO_LAYOUT_UNSUPPORTED: &str = "E_PHOTO_LAYOUT_UNSUPPORTED";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoPreviewResult {
    pub data_b64: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// true=命中已落库预览记录；false=本次懒生成
    pub cached: bool,
    pub elapsed_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoFullBegin {
    pub job_id: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub chunk_total: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoFullChunk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_b64: Option<String>,
    pub chunk_index: u32,
    pub chunk_total: u32,
    pub done: bool,
}

fn read_error(reply: &WorkerReply) -> String {
    if let Some(code) = reply.error_code.as_deref() {
        return format!("{}: {}", code, reply.error.clone().unwrap_or_default());
    }
    reply
        .error
        .clone()
        .unwrap_or_else(|| "照片读取失败".to_string())
}

async fn end_read_job(app: &tauri::AppHandle, job_id: &str) {
    let _ = send_worker(
        app,
        serde_json::json!({"op": "photo_read_job_end", "job_id": job_id}),
        READ_END_TIMEOUT,
    )
    .await;
}

/// 读取预览：命中预览记录直接返回；缺失时 worker 懒生成并回传待写记录。
#[tauri::command]
pub async fn photo_preview_get(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    meta_id: u64,
) -> Result<PhotoPreviewResult, String> {
    let started = Instant::now();
    require_unlocked(&app, &state, "photo_preview_get")?;
    if meta_id == 0 {
        return Err("照片 ID 非法".to_string());
    }

    let job_id = format!("preview-{}", generate_job_id());
    let raw = send_worker(
        &app,
        serde_json::json!({
            "op": "photo_read_job_begin",
            "job_id": job_id,
            "mode": "preview",
            "meta_id": meta_id,
        }),
        PREVIEW_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("photo_read_job_begin", &raw)?;
    if !reply.ok {
        return Err(read_error(&reply));
    }
    let read = reply
        .photo_read
        .ok_or_else(|| "预览响应缺少结果".to_string())?;
    if read.status != "preview" {
        return Err(format!("预览状态异常: {}", read.status));
    }
    let data_b64 = read
        .data_b64
        .ok_or_else(|| "预览响应缺少图像数据".to_string())?;

    // 懒生成的预览：经单写者落库；失败只告警，本次仍返回已生成字节
    if let Some(record) = reply.photo_record {
        let write = async {
            let writer = import_writer::ensure(&app)?;
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<Result<u64, String>>();
            let cmd = WriterCommand::AppendDerived {
                record: BatchRecordInput {
                    rtype: TYPE_PHOTO_PREVIEW,
                    name: record.name,
                    entry_key: String::new(),
                    data_b64: record.data_b64,
                    chunk_ids: None,
                    chunk_hashes: None,
                },
                reply: reply_tx,
            };
            submit_writer_cmd(&writer, cmd, reply_rx).await
        };
        match tokio::time::timeout(DERIVED_WRITE_TIMEOUT, write).await {
            Ok(Ok(_id)) => {}
            Ok(Err(e)) => log::warn!("[photo_preview] 预览记录写入失败（不影响本次显示）: {}", e),
            Err(_) => log::warn!("[photo_preview] 预览记录写入超时（不影响本次显示）"),
        }
    }

    // 预览为一次性操作，begin 不保留 worker job；end 幂等清理
    end_read_job(&app, &job_id).await;

    Ok(PhotoPreviewResult {
        data_b64,
        name: read.name.unwrap_or_default(),
        mime: read.mime.unwrap_or_default(),
        size: read.size.unwrap_or(0),
        cached: read.preview_cached.unwrap_or(false),
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

/// 打开原图读取 job；返回块数与显示字段。
#[tauri::command]
pub async fn photo_full_begin(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    meta_id: u64,
) -> Result<PhotoFullBegin, String> {
    require_unlocked(&app, &state, "photo_full_begin")?;
    if meta_id == 0 {
        return Err("照片 ID 非法".to_string());
    }
    let job_id = format!("full-{}", generate_job_id());
    let raw = send_worker(
        &app,
        serde_json::json!({
            "op": "photo_read_job_begin",
            "job_id": job_id,
            "mode": "full",
            "meta_id": meta_id,
        }),
        READ_BEGIN_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("photo_read_job_begin", &raw)?;
    if !reply.ok {
        return Err(read_error(&reply));
    }
    let read = reply
        .photo_read
        .ok_or_else(|| "原图读取响应缺少结果".to_string())?;
    Ok(PhotoFullBegin {
        job_id,
        name: read.name.unwrap_or_default(),
        mime: read.mime.unwrap_or_default(),
        size: read.size.unwrap_or(0),
        chunk_total: read.chunk_total.unwrap_or(0),
    })
}

/// 拉取下一块原图明文；done=true 时 worker job 已自动结束。
#[tauri::command]
pub async fn photo_full_next(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    job_id: String,
) -> Result<PhotoFullChunk, String> {
    require_unlocked(&app, &state, "photo_full_next")?;
    if job_id.is_empty() {
        return Err("读取 job 非法".to_string());
    }
    let raw = send_worker(
        &app,
        serde_json::json!({"op": "photo_read_job_next", "job_id": job_id}),
        READ_NEXT_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("photo_read_job_next", &raw)?;
    if !reply.ok {
        return Err(read_error(&reply));
    }
    let read = reply
        .photo_read
        .ok_or_else(|| "原图读取响应缺少结果".to_string())?;
    let done = match read.status.as_str() {
        "chunk" => false,
        "done" => true,
        "cancelled" => return Err("E_PHOTO_READ_CANCELLED".to_string()),
        other => return Err(format!("原图读取状态异常: {}", other)),
    };
    if done {
        end_read_job(&app, &job_id).await;
    }
    Ok(PhotoFullChunk {
        data_b64: read.data_b64,
        chunk_index: read.chunk_index.unwrap_or(0),
        chunk_total: read.chunk_total.unwrap_or(0),
        done,
    })
}

/// 取消原图读取：worker 停止后续产出并清理 job。
#[tauri::command]
pub async fn photo_full_cancel(
    app: tauri::AppHandle,
    _state: State<'_, AppState>,
    job_id: String,
) -> Result<(), String> {
    if job_id.is_empty() {
        return Ok(());
    }
    let _ = send_worker(
        &app,
        serde_json::json!({"op": "photo_read_job_cancel", "job_id": job_id}),
        READ_END_TIMEOUT,
    )
    .await;
    end_read_job(&app, &job_id).await;
    Ok(())
}

/* ------------------------------------------------------------------ *
 * Phase 3：原生导出                                                   *
 * ------------------------------------------------------------------ */

const EXPORT_BEGIN_TIMEOUT: Duration = Duration::from_secs(30);
/// 单次 next 可能读取并解密整张照片（100MiB 上限）
const EXPORT_NEXT_TIMEOUT: Duration = Duration::from_secs(300);
const EXPORT_END_TIMEOUT: Duration = Duration::from_secs(15);
/// 导出文件名 UTF-8 字节上限（含扩展名，与前端 MAX_EXPORT_FILENAME_BYTES 一致）
const MAX_EXPORT_FILENAME_BYTES: usize = 200;

const EXPORT_PHASE_SCANNING: &str = "scanning";
const EXPORT_PHASE_EXPORTING: &str = "exporting";
const EXPORT_PHASE_FINISHING: &str = "finishing";
const EXPORT_PHASE_DONE: &str = "done";
const EXPORT_PHASE_CANCELLED: &str = "cancelled";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoExportProgress {
    pub total_files: u64,
    pub done_files: u64,
    pub failed: u64,
    pub exported: u64,
    pub current_name: String,
    pub percent: u8,
    pub elapsed_ms: u64,
    pub phase: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoExportFailure {
    pub index: u32,
    pub name: String,
    pub reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoExportResult {
    pub ok: bool,
    pub exported: u64,
    pub failed: Vec<PhotoExportFailure>,
    pub total: u64,
    pub elapsed_ms: u64,
    pub cancelled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

struct ActiveExportFile {
    entry: Arc<Mutex<FileStreamState>>,
    file_index: u32,
    target: String,
    name: String,
}

async fn stream_create_async(target: PathBuf) -> Result<(String, Arc<Mutex<FileStreamState>>), String> {
    let target = target.to_string_lossy().to_string();
    match tokio::time::timeout(
        Duration::from_secs(120),
        tauri::async_runtime::spawn_blocking(move || stream_create_blocking(&target)),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => Err(format!("写入会话任务异常: {}", e)),
        Err(_) => Err("创建写入会话超时".to_string()),
    }
}

async fn stream_append_async(
    entry: Arc<Mutex<FileStreamState>>,
    data: Vec<u8>,
) -> Result<(), String> {
    match tokio::time::timeout(
        Duration::from_secs(60),
        tauri::async_runtime::spawn_blocking(move || stream_append_blocking(&entry, &data)),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => Err(format!("写入任务异常: {}", e)),
        Err(_) => Err("写入数据超时".to_string()),
    }
}

async fn stream_finalize_async(entry: Arc<Mutex<FileStreamState>>) -> Result<u64, String> {
    match tokio::time::timeout(
        Duration::from_secs(120),
        tauri::async_runtime::spawn_blocking(move || stream_finalize_blocking(entry)),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => Err(format!("落盘任务异常: {}", e)),
        Err(_) => Err("落盘超时".to_string()),
    }
}

async fn stream_abort_async(entry: Arc<Mutex<FileStreamState>>) {
    let _ = tokio::time::timeout(
        Duration::from_secs(60),
        tauri::async_runtime::spawn_blocking(move || stream_abort_blocking(entry)),
    )
    .await;
}

fn emit_export_progress(
    channel: &Channel<PhotoExportProgress>,
    total: u64,
    done: u64,
    failed: u64,
    exported: u64,
    current_name: &str,
    phase: &str,
    started: Instant,
) {
    let percent = if matches!(phase, EXPORT_PHASE_FINISHING | EXPORT_PHASE_DONE) {
        100
    } else if total == 0 {
        0
    } else {
        (done.saturating_mul(100) / total).min(99) as u8
    };
    let _ = channel.send(PhotoExportProgress {
        total_files: total,
        done_files: done,
        failed,
        exported,
        current_name: current_name.to_string(),
        percent,
        elapsed_ms: started.elapsed().as_millis() as u64,
        phase: phase.to_string(),
    });
}

/// 文件名净化：与前端 `sanitizeFileName` 同规则。
fn sanitize_file_name(name: &str, max_utf8_bytes: usize) -> String {
    let mut cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                ' '
            } else {
                c
            }
        })
        .collect();
    cleaned = cleaned
        .trim_matches(|c: char| c.is_whitespace() || c == '.')
        .trim()
        .to_string();
    if cleaned.is_empty() {
        return "photo".to_string();
    }
    let stem = cleaned.split('.').next().unwrap_or("").to_ascii_lowercase();
    if matches!(
        stem.as_str(),
        "con" | "prn" | "aux" | "nul" | "com1" | "com2" | "com3" | "com4" | "com5" | "com6"
            | "com7" | "com8" | "com9" | "lpt1" | "lpt2" | "lpt3" | "lpt4" | "lpt5" | "lpt6"
            | "lpt7" | "lpt8" | "lpt9"
    ) {
        cleaned = format!("_{}", cleaned);
    }
    if cleaned.len() <= max_utf8_bytes {
        return cleaned;
    }
    let mut out = String::new();
    for ch in cleaned.chars() {
        let mut candidate = out.clone();
        candidate.push(ch);
        if candidate.len() > max_utf8_bytes {
            break;
        }
        out = candidate;
    }
    if out.is_empty() {
        "photo".to_string()
    } else {
        out
    }
}

/// 批次内大小写不敏感唯一化；与前端 `uniqueFileName` 同规则。
fn unique_file_name(base: &str, used: &mut HashSet<String>) -> String {
    let (stem, ext) = match base.rfind('.') {
        Some(idx) if idx > 0 => (&base[..idx], &base[idx..]),
        _ => (base, ""),
    };
    let mut candidate = base.to_string();
    let mut n = 0u32;
    while used.contains(&candidate.to_lowercase()) {
        n += 1;
        candidate = format!("{}_{}{}", stem, n, ext);
    }
    used.insert(candidate.to_lowercase());
    candidate
}

fn mime_extension(mime: &str) -> &'static str {
    match mime {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/webp" => "webp",
        "image/gif" => "gif",
        "image/bmp" => "bmp",
        "image/apng" => "apng",
        _ => "bin",
    }
}

fn strip_image_extension(name: &str) -> &str {
    let lower = name.to_ascii_lowercase();
    for ext in [".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".apng"] {
        if lower.ends_with(ext) {
            return &name[..name.len() - ext.len()];
        }
    }
    name
}

fn export_file_name(
    format: &str,
    raw_name: &str,
    mime: &str,
    index: u32,
    used: &mut HashSet<String>,
) -> String {
    match format {
        "png" => {
            let stem = strip_image_extension(raw_name);
            let cleaned = sanitize_file_name(stem, MAX_EXPORT_FILENAME_BYTES - 4);
            let stem = if cleaned == "photo" {
                format!("photo_{}", index)
            } else {
                cleaned
            };
            unique_file_name(&format!("{}.png", stem), used)
        }
        "venc-multiple" => {
            let cleaned = sanitize_file_name(raw_name, MAX_EXPORT_FILENAME_BYTES - 5);
            unique_file_name(&format!("{}.venc", cleaned), used)
        }
        _ => {
            if Path::new(raw_name).extension().is_some() {
                let cleaned = sanitize_file_name(raw_name, MAX_EXPORT_FILENAME_BYTES);
                unique_file_name(&cleaned, used)
            } else {
                let ext = mime_extension(mime);
                let budget = MAX_EXPORT_FILENAME_BYTES.saturating_sub(ext.len() + 1);
                let cleaned = sanitize_file_name(raw_name, budget);
                unique_file_name(&format!("{}.{}", cleaned, ext), used)
            }
        }
    }
}

#[tauri::command]
pub async fn photo_export_start(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    ids: Vec<u64>,
    format: String,
    dest: String,
    token: Option<String>,
    on_progress: Channel<PhotoExportProgress>,
) -> Result<PhotoExportResult, String> {
    let started = Instant::now();
    let total = ids.len() as u64;
    if let Err(msg) = require_unlocked(&app, &state, "photo_export_start") {
        return Ok(PhotoExportResult {
            ok: false,
            exported: 0,
            failed: Vec::new(),
            total,
            elapsed_ms: 0,
            cancelled: false,
            error: Some(msg),
            error_code: Some(ERROR_CODE_NOT_READY.to_string()),
        });
    }
    if !matches!(
        format.as_str(),
        "original" | "venc-single" | "venc-multiple" | "png"
    ) {
        return Ok(PhotoExportResult {
            ok: false,
            exported: 0,
            failed: Vec::new(),
            total,
            elapsed_ms: 0,
            cancelled: false,
            error: Some("导出格式非法".to_string()),
            error_code: None,
        });
    }
    let needs_token = matches!(format.as_str(), "venc-single" | "venc-multiple");
    let token = token.unwrap_or_default().trim().to_string();
    if needs_token && token.len() < 8 {
        return Ok(PhotoExportResult {
            ok: false,
            exported: 0,
            failed: Vec::new(),
            total,
            elapsed_ms: 0,
            cancelled: false,
            error: Some("加密令牌至少 8 位字符".to_string()),
            error_code: None,
        });
    }
    if dest.trim().is_empty() {
        return Ok(PhotoExportResult {
            ok: false,
            exported: 0,
            failed: Vec::new(),
            total,
            elapsed_ms: 0,
            cancelled: false,
            error: Some("未选择导出位置".to_string()),
            error_code: None,
        });
    }
    if format != "venc-single" && !Path::new(&dest).is_dir() {
        return Ok(PhotoExportResult {
            ok: false,
            exported: 0,
            failed: Vec::new(),
            total,
            elapsed_ms: 0,
            cancelled: false,
            error: Some("导出目录不存在".to_string()),
            error_code: None,
        });
    }

    let job_id = generate_job_id();
    let cancel = match state.try_begin_photo_import(&job_id) {
        Ok(flag) => flag,
        Err(msg) => {
            return Ok(PhotoExportResult {
                ok: false,
                exported: 0,
                failed: Vec::new(),
                total,
                elapsed_ms: 0,
                cancelled: false,
                error: Some(msg),
                error_code: Some(ERROR_CODE_BUSY.to_string()),
            })
        }
    };

    let result = run_export(
        &app, &job_id, cancel, ids, format, dest, token, on_progress, started,
    )
    .await;
    state.finish_photo_import(&job_id);
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
async fn run_export(
    app: &tauri::AppHandle,
    job_id: &str,
    cancel: Arc<AtomicBool>,
    ids: Vec<u64>,
    format: String,
    dest: String,
    token: String,
    channel: Channel<PhotoExportProgress>,
    started: Instant,
) -> PhotoExportResult {
    let total = ids.len() as u64;
    let mut exported = 0u64;
    let mut done = 0u64;
    let mut failures: Vec<PhotoExportFailure> = Vec::new();
    let mut failed_indices: HashSet<u32> = HashSet::new();
    let mut cancelled = false;
    let mut session_error: Option<String> = None;
    let mut error_code: Option<String> = None;
    let single = format == "venc-single";
    let dest_dir = if single {
        None
    } else {
        Some(PathBuf::from(&dest))
    };
    let mut used_names: HashSet<String> = HashSet::new();
    let mut active: Option<ActiveExportFile> = None;
    let mut discarding_file = false;
    // venc-single 只有一个目标文件：任一写盘失败都必须回滚整批成功计数
    let mut single_write_failed = false;
    let mut single_ok_photos: Vec<(u32, String)> = Vec::new();
    // 只有 finalize 成功（目标文件已原子替换）才允许保留成功计数
    let mut single_finalized = false;

    emit_export_progress(
        &channel,
        total,
        0,
        0,
        0,
        "",
        EXPORT_PHASE_SCANNING,
        started,
    );

    let begin_reply = match send_worker(
        app,
        serde_json::json!({
            "op": "photo_export_job_begin",
            "job_id": job_id,
            "ids": ids,
            "format": format,
            "token": token,
        }),
        EXPORT_BEGIN_TIMEOUT,
    )
    .await
    {
        Ok(raw) => match parse_reply("photo_export_job_begin", &raw) {
            Ok(reply) => reply,
            Err(e) => {
                return PhotoExportResult {
                    ok: false,
                    exported: 0,
                    failed: failures,
                    total,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    cancelled: false,
                    error: Some(e),
                    error_code: None,
                }
            }
        },
        Err(e) => {
            return PhotoExportResult {
                ok: false,
                exported: 0,
                failed: failures,
                total,
                elapsed_ms: started.elapsed().as_millis() as u64,
                cancelled: false,
                error: Some(e),
                error_code: None,
            }
        }
    };
    if !begin_reply.ok {
        let result = PhotoExportResult {
            ok: false,
            exported: 0,
            failed: failures,
            total,
            elapsed_ms: started.elapsed().as_millis() as u64,
            cancelled: false,
            error: begin_reply.error.clone(),
            error_code: None,
        };
        let _ = end_export_job(app, job_id).await;
        return result;
    }

    loop {
        if cancel.load(Ordering::SeqCst) {
            cancelled = true;
            break;
        }
        let raw = match send_worker(
            app,
            serde_json::json!({"op": "photo_export_job_next", "job_id": job_id}),
            EXPORT_NEXT_TIMEOUT,
        )
        .await
        {
            Ok(raw) => raw,
            Err(e) => {
                session_error = Some(e);
                break;
            }
        };
        let reply = match parse_reply("photo_export_job_next", &raw) {
            Ok(reply) => reply,
            Err(e) => {
                session_error = Some(e);
                break;
            }
        };
        if !reply.ok {
            session_error = reply.error.clone();
            error_code = reply.error_code.clone();
            break;
        }
        let Some(event) = reply.photo_export else {
            session_error = Some("导出响应缺少事件".to_string());
            break;
        };

        match event.status.as_str() {
            "file_begin" => {
                let index = event.file_index.unwrap_or(0);
                let raw_name = event.file_name.unwrap_or_default();
                let mime = event.mime.unwrap_or_default();
                let target = if single {
                    PathBuf::from(&dest)
                } else {
                    let dir = dest_dir.as_ref().expect("非单文件模式必须有目录");
                    let file_name = export_file_name(&format, &raw_name, &mime, index, &mut used_names);
                    dir.join(file_name)
                };
                let target_text = target.to_string_lossy().to_string();
                match stream_create_async(target).await {
                    Ok((_stream_id, entry)) => {
                        audit_export_event(app, &target_text, true, None, None);
                        active = Some(ActiveExportFile {
                            entry,
                            file_index: index,
                            target: target_text,
                            name: raw_name.clone(),
                        });
                        discarding_file = false;
                    }
                    Err(e) => {
                        log::warn!("[photo_export] 创建目标文件失败: {}", e);
                        audit_export_event(app, &target_text, false, None, Some(e.clone()));
                        if single {
                            single_write_failed = true;
                            session_error = Some(format!("创建目标文件失败: {}", e));
                        } else if failed_indices.insert(index) {
                            failures.push(PhotoExportFailure {
                                index,
                                name: raw_name,
                                reason: "write-failed".to_string(),
                            });
                        }
                        discarding_file = true;
                    }
                }
            }
            "segment" => {
                if discarding_file {
                    continue;
                }
                let Some(active_file) = active.as_ref() else {
                    continue;
                };
                let Some(data_b64) = event.data_b64 else {
                    session_error = Some("导出段缺少数据".to_string());
                    break;
                };
                let data = match BASE64.decode(data_b64.as_bytes()) {
                    Ok(data) => data,
                    Err(_) => {
                        session_error = Some("导出段编码非法".to_string());
                        break;
                    }
                };
                if let Err(e) =
                    stream_append_async(Arc::clone(&active_file.entry), data).await
                {
                    log::warn!("[photo_export] 写入目标文件失败: {}", e);
                    let index = active_file.file_index;
                    let name = active_file.name.clone();
                    if let Some(file) = active.take() {
                        audit_export_event(app, &file.target, false, None, Some(e.clone()));
                        stream_abort_async(file.entry).await;
                    }
                    discarding_file = true;
                    if single {
                        single_write_failed = true;
                        session_error = Some(format!("写入目标文件失败: {}", e));
                        exported = 0;
                        for (idx, name) in single_ok_photos.drain(..) {
                            if failed_indices.insert(idx) {
                                failures.push(PhotoExportFailure {
                                    index: idx,
                                    name,
                                    reason: "write-failed".to_string(),
                                });
                            }
                        }
                    } else if failed_indices.insert(index) {
                        failures.push(PhotoExportFailure {
                            index,
                            name,
                            reason: "write-failed".to_string(),
                        });
                    }
                }
            }
            "file_end" => {
                if discarding_file {
                    discarding_file = false;
                    continue;
                }
                let Some(file) = active.take() else {
                    continue;
                };
                let file_ok = event.file_ok.unwrap_or(false);
                if file_ok {
                    match stream_finalize_async(file.entry).await {
                        Ok(size) => {
                            audit_export_event(app, &file.target, true, Some(size), None);
                            if single {
                                single_finalized = true;
                            }
                        }
                        Err(e) => {
                            log::warn!("[photo_export] 落盘失败: {}", e);
                            audit_export_event(app, &file.target, false, None, Some(e.clone()));
                            if single {
                                single_write_failed = true;
                                session_error = Some(e);
                                exported = 0;
                                for (idx, name) in single_ok_photos.drain(..) {
                                    if failed_indices.insert(idx) {
                                        failures.push(PhotoExportFailure {
                                            index: idx,
                                            name,
                                            reason: "write-failed".to_string(),
                                        });
                                    }
                                }
                            } else if failed_indices.insert(file.file_index) {
                                failures.push(PhotoExportFailure {
                                    index: file.file_index,
                                    name: file.name.clone(),
                                    reason: "write-failed".to_string(),
                                });
                            }
                        }
                    }
                } else {
                    audit_export_event(app, &file.target, false, None, Some("file_ok=false".to_string()));
                    stream_abort_async(file.entry).await;
                }
            }
            "photo" => {
                let index = event.file_index.unwrap_or(0);
                let name = event.name.unwrap_or_default();
                match event.photo_status.as_deref() {
                    Some("ok") => {
                        if single {
                            if single_write_failed {
                                if failed_indices.insert(index) {
                                    failures.push(PhotoExportFailure {
                                        index,
                                        name: name.clone(),
                                        reason: "write-failed".to_string(),
                                    });
                                }
                            } else if !failed_indices.contains(&index) {
                                exported += 1;
                                single_ok_photos.push((index, name.clone()));
                            }
                        } else if !failed_indices.contains(&index) {
                            exported += 1;
                        }
                    }
                    Some("failed") => {
                        if failed_indices.insert(index) {
                            failures.push(PhotoExportFailure {
                                index,
                                name: name.clone(),
                                reason: event.reason.unwrap_or_else(|| "unknown".to_string()),
                            });
                        }
                    }
                    _ => {}
                }
                done += 1;
                emit_export_progress(
                    &channel,
                    total,
                    done,
                    failures.len() as u64,
                    exported,
                    &name,
                    EXPORT_PHASE_EXPORTING,
                    started,
                );
            }
            "done" => break,
            "cancelled" => {
                cancelled = true;
                break;
            }
            other => {
                session_error = Some(format!("未知的导出状态: {}", other));
                break;
            }
        }
    }

    if let Some(file) = active.take() {
        audit_export_event(app, &file.target, false, None, Some("导出中止".to_string()));
        stream_abort_async(file.entry).await;
    }
    /* 单文件容器未 finalize（取消/会话错误）时目标文件不存在：
     * 不得保留 exported 计数，已通过的照片按 write-failed 记账。 */
    if single && !single_finalized {
        exported = 0;
        for (index, name) in single_ok_photos.drain(..) {
            if failed_indices.insert(index) {
                failures.push(PhotoExportFailure {
                    index,
                    name,
                    reason: "write-failed".to_string(),
                });
            }
        }
    }
    let _ = end_export_job(app, job_id).await;

    emit_export_progress(
        &channel,
        total,
        done,
        failures.len() as u64,
        exported,
        "",
        if cancelled {
            EXPORT_PHASE_CANCELLED
        } else {
            EXPORT_PHASE_FINISHING
        },
        started,
    );

    PhotoExportResult {
        ok: !cancelled && session_error.is_none() && failures.is_empty(),
        exported,
        failed: failures,
        total,
        elapsed_ms: started.elapsed().as_millis() as u64,
        cancelled,
        error: session_error,
        error_code,
    }
}

async fn end_export_job(app: &tauri::AppHandle, job_id: &str) {
    let _ = send_worker(
        app,
        serde_json::json!({"op": "photo_export_job_end", "job_id": job_id}),
        EXPORT_END_TIMEOUT,
    )
    .await;
}

#[tauri::command]
pub async fn photo_export_cancel(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let Some(job_id) = state.photo_import_job_id() else {
        return Ok(());
    };
    if let Some(flag) = state.photo_import_cancel_flag(&job_id) {
        flag.store(true, Ordering::SeqCst);
    }
    tauri::async_runtime::spawn(async move {
        let _ = send_worker(
            &app,
            serde_json::json!({"op": "photo_export_job_cancel", "job_id": job_id}),
            EXPORT_END_TIMEOUT,
        )
        .await;
    });
    Ok(())
}

/* ------------------------------------------------------------------ *
 * Phase 3：原生备份还原                                               *
 * ------------------------------------------------------------------ */

const RESTORE_BEGIN_TIMEOUT: Duration = Duration::from_secs(60);
const RESTORE_NEXT_TIMEOUT: Duration = Duration::from_secs(120);
const RESTORE_FINISH_TIMEOUT: Duration = Duration::from_secs(60);
const RESTORE_END_TIMEOUT: Duration = Duration::from_secs(15);

/// 备份还原批次时间戳序：与前端 `nextImportTimestamp` 同语义，
/// 保证 `parsed_<ts>_<index>` 记录名跨批次唯一。
static LAST_IMPORT_TIMESTAMP: AtomicI64 = AtomicI64::new(0);

fn next_import_timestamp() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let mut previous = LAST_IMPORT_TIMESTAMP.load(Ordering::SeqCst);
    loop {
        let next = now.max(previous.saturating_add(1));
        match LAST_IMPORT_TIMESTAMP.compare_exchange(
            previous,
            next,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => return next,
            Err(current) => previous = current,
        }
    }
}

async fn authorize_batch_for(
    app: &tauri::AppHandle,
    job_id: &str,
    paths: &[String],
    target_op: &str,
) -> Result<(), String> {
    let raw = send_worker(
        app,
        serde_json::json!({
            "op": "authorize_path_batch",
            "job_id": job_id,
            "paths": paths,
            "target_op": target_op,
        }),
        AUTHORIZE_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("authorize_path_batch", &raw)?;
    if reply.ok {
        Ok(())
    } else {
        Err(reply
            .error
            .unwrap_or_else(|| "备份还原路径授权失败".to_string()))
    }
}

async fn finish_restore_photo(
    app: &tauri::AppHandle,
    job_id: &str,
    chunk_ids: &[u64],
    skip_photo: bool,
) -> Result<PhotoFinishPayload, String> {
    let raw = send_worker(
        app,
        serde_json::json!({
            "op": "photo_restore_photo_finish",
            "job_id": job_id,
            "chunk_ids": chunk_ids,
            "skip_photo": skip_photo,
        }),
        RESTORE_FINISH_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("photo_restore_photo_finish", &raw)?;
    if !reply.ok {
        return Err(reply
            .error
            .unwrap_or_else(|| "照片收尾失败".to_string()));
    }
    reply
        .photo_finish
        .ok_or_else(|| "照片收尾响应缺少结果".to_string())
}

async fn append_restored_meta(
    app: &tauri::AppHandle,
    record_name: &str,
    entry_key: &str,
    meta_b64: &str,
    chunk_ids: &[u64],
    chunk_hashes: &[String],
) -> MetaAppend {
    let writer = match import_writer::ensure(app) {
        Ok(w) => w,
        Err(e) => return MetaAppend::Failed(e),
    };
    let record = BatchRecordInput {
        rtype: PHOTO_META_RTYPE,
        name: record_name.to_string(),
        entry_key: entry_key.to_string(),
        data_b64: meta_b64.to_string(),
        chunk_ids: Some(chunk_ids.to_vec()),
        chunk_hashes: Some(chunk_hashes.to_vec()),
    };
    let (reply_tx, reply_rx) =
        tokio::sync::oneshot::channel::<Result<BatchAppendOutcome, String>>();
    let cmd = WriterCommand::AppendPending {
        records: vec![record],
        progress: None,
        reply: reply_tx,
    };
    let outcome = match submit_writer_cmd(&writer, cmd, reply_rx).await {
        Ok(o) => o,
        Err(e) => return MetaAppend::Failed(e),
    };
    let id = outcome.ids.first().copied().unwrap_or(0);
    if id > 0 {
        MetaAppend::Imported(id)
    } else if outcome.failed_indices.is_empty() {
        MetaAppend::Skipped
    } else {
        MetaAppend::Failed("照片索引写入被拒绝".to_string())
    }
}

#[tauri::command]
pub async fn photo_restore_start(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: String,
    token: String,
    expected_hashes: Vec<String>,
    on_progress: Channel<PhotoImportProgress>,
) -> Result<PhotoImportResult, String> {
    let started = Instant::now();
    let total = expected_hashes.len() as u64;
    if let Err(msg) = require_unlocked(&app, &state, "photo_restore_start") {
        return Ok(failure_result(
            total,
            started,
            msg,
            Some(ERROR_CODE_NOT_READY.to_string()),
        ));
    }
    let token = token.trim().to_string();
    if token.len() < 8 {
        return Ok(failure_result(
            total,
            started,
            "令牌格式不正确（至少 8 位字符）".to_string(),
            None,
        ));
    }
    if path.trim().is_empty() {
        return Ok(failure_result(total, started, "未选择备份文件".to_string(), None));
    }

    let job_id = generate_job_id();
    let cancel = match state.try_begin_photo_import(&job_id) {
        Ok(flag) => flag,
        Err(msg) => {
            return Ok(failure_result(
                total,
                started,
                msg,
                Some(ERROR_CODE_BUSY.to_string()),
            ))
        }
    };

    let result = run_restore(
        &app,
        &job_id,
        cancel,
        path,
        token,
        expected_hashes,
        on_progress,
        started,
    )
    .await;
    state.finish_photo_import(&job_id);

    {
        let gc_app = app.clone();
        tauri::async_runtime::spawn(async move {
            let gc_state = gc_app.state::<AppState>();
            match verthys_gc_orphan_chunks(gc_app.clone(), gc_state).await {
                Ok(resp) if !resp.ok => log::warn!(
                    "[photo_restore] 孤儿块清理失败: {}",
                    resp.error.unwrap_or_else(|| "未知错误".to_string())
                ),
                Err(e) => log::warn!("[photo_restore] 孤儿块清理异常: {}", e),
                _ => {}
            }
        });
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
async fn run_restore(
    app: &tauri::AppHandle,
    job_id: &str,
    cancel: Arc<AtomicBool>,
    path: String,
    token: String,
    expected_hashes: Vec<String>,
    channel: Channel<PhotoImportProgress>,
    started: Instant,
) -> PhotoImportResult {
    let mut totals = ImportTotals {
        total: expected_hashes.len() as u64,
        ..Default::default()
    };
    let mut imported: Vec<PhotoImportItem> = Vec::new();
    let mut failed_records: Vec<PhotoImportFailure> = Vec::new();
    let mut cancelled = false;
    let mut session_error: Option<String> = None;
    let mut file = FileProgress::default();
    let mut skip_current = false;
    let import_timestamp = next_import_timestamp();
    let mut grant_refreshed_at = Instant::now();
    let path_for_grant = path.clone();

    emit_progress(&channel, &totals, PHASE_SCANNING, "", 0, 0, started.elapsed());

    if let Err(e) = authorize_batch_for(app, job_id, &[path.clone()], "photo_restore").await {
        return PhotoImportResult {
            ok: false,
            imported,
            failed_records,
            skipped: 0,
            total: totals.total,
            elapsed_ms: started.elapsed().as_millis() as u64,
            error: Some(e),
            error_code: None,
            cancelled: false,
        };
    }

    let mut begin = match verthys_import_begin(app.clone(), app.state::<AppState>(), None).await {
        Ok(resp) => resp,
        Err(e) => {
            let _ = end_restore_job(app, job_id).await;
            return PhotoImportResult {
                ok: false,
                imported,
                failed_records,
                skipped: 0,
                total: totals.total,
                elapsed_ms: started.elapsed().as_millis() as u64,
                error: Some(e),
                error_code: None,
                cancelled: false,
            };
        }
    };
    if !begin.ok
        && begin.error_code.as_deref() == Some(IMPORT_SESSION_BUSY_CODE)
        && discard_stale_import_session(app)
    {
        log::warn!("[photo_restore] 已丢弃其他容器的残留导入会话，重试建立会话");
        begin = match verthys_import_begin(app.clone(), app.state::<AppState>(), None).await {
            Ok(resp) => resp,
            Err(e) => {
                let _ = end_restore_job(app, job_id).await;
                return PhotoImportResult {
                    ok: false,
                    imported,
                    failed_records,
                    skipped: 0,
                    total: totals.total,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    error: Some(e),
                    error_code: None,
                    cancelled: false,
                };
            }
        };
    }
    if !begin.ok {
        let _ = end_restore_job(app, job_id).await;
        return PhotoImportResult {
            ok: false,
            imported,
            failed_records,
            skipped: 0,
            total: totals.total,
            elapsed_ms: started.elapsed().as_millis() as u64,
            error: begin.error,
            error_code: begin.error_code,
            cancelled: false,
        };
    }
    let committed: HashSet<String> = begin.entry_keys.unwrap_or_default().into_iter().collect();

    let begin_restore = send_worker(
        app,
        serde_json::json!({
            "op": "photo_restore_job_begin",
            "job_id": job_id,
            "path": path_for_grant.clone(),
            "token": token,
            "expected_hashes": expected_hashes,
        }),
        RESTORE_BEGIN_TIMEOUT,
    )
    .await;
    let begin_reply = match begin_restore {
        Ok(raw) => match parse_reply("photo_restore_job_begin", &raw) {
            Ok(reply) => reply,
            Err(e) => {
                let _ = verthys_import_end(app.clone(), app.state::<AppState>(), false).await;
                return PhotoImportResult {
                    ok: false,
                    imported,
                    failed_records,
                    skipped: 0,
                    total: totals.total,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    error: Some(e),
                    error_code: None,
                    cancelled: false,
                };
            }
        },
        Err(e) => {
            let _ = verthys_import_end(app.clone(), app.state::<AppState>(), false).await;
            return PhotoImportResult {
                ok: false,
                imported,
                failed_records,
                skipped: 0,
                total: totals.total,
                elapsed_ms: started.elapsed().as_millis() as u64,
                error: Some(e),
                error_code: None,
                cancelled: false,
            };
        }
    };
    if !begin_reply.ok {
        let _ = verthys_import_end(app.clone(), app.state::<AppState>(), false).await;
        let _ = end_restore_job(app, job_id).await;
        return PhotoImportResult {
            ok: false,
            imported,
            failed_records,
            skipped: 0,
            total: totals.total,
            elapsed_ms: started.elapsed().as_millis() as u64,
            error: begin_reply.error,
            error_code: begin_reply.error_code,
            cancelled: false,
        };
    }

    loop {
        if cancel.load(Ordering::SeqCst) {
            cancelled = true;
            break;
        }
        // 大容器还原可能超过 worker 侧 600s 授权窗口：滚动续期同一路径
        if grant_refreshed_at.elapsed() >= GRANT_REFRESH_INTERVAL {
            if let Err(e) = authorize_batch_for(
                app,
                job_id,
                &[path_for_grant.clone()],
                "photo_restore",
            )
            .await
            {
                session_error = Some(e);
                break;
            }
            grant_refreshed_at = Instant::now();
        }
        let raw = match send_worker(
            app,
            serde_json::json!({"op": "photo_restore_job_next", "job_id": job_id}),
            RESTORE_NEXT_TIMEOUT,
        )
        .await
        {
            Ok(raw) => raw,
            Err(e) => {
                session_error = Some(e);
                break;
            }
        };
        let reply = match parse_reply("photo_restore_job_next", &raw) {
            Ok(reply) => reply,
            Err(e) => {
                session_error = Some(e);
                break;
            }
        };
        if !reply.ok {
            let err = reply
                .error
                .unwrap_or_else(|| "备份还原失败".to_string());
            if is_job_gone(&err) {
                log::warn!("[photo_restore] worker job 已结束: {}", err);
            } else {
                session_error = Some(err);
            }
            break;
        }
        let Some(photo) = reply.photo else {
            session_error = Some("备份还原响应缺少 photo 字段".to_string());
            break;
        };

        match photo.status.as_str() {
            "photo" => {
                file = FileProgress {
                    file_index: photo.file_index,
                    file_name: photo.file_name.clone().unwrap_or_default(),
                    mime: photo.mime.clone().unwrap_or_default(),
                    size: photo.size.unwrap_or(0),
                    entry_key: photo.entry_key.clone().unwrap_or_default(),
                    thumb_b64: photo.thumb_b64.clone().unwrap_or_default(),
                    ..Default::default()
                };
                skip_current = !file.entry_key.is_empty() && committed.contains(&file.entry_key);
            }
            "chunk" => {
                let last = photo
                    .chunk_index
                    .zip(photo.chunk_total)
                    .map(|(index, total)| index.saturating_add(1) >= total)
                    .unwrap_or(false);
                if !skip_current && !file.abandoned {
                    file.chunk_hashes
                        .push(photo.chunk_hash.clone().unwrap_or_default());
                    file.buffer.push(ChunkBlob {
                        chunk_key: photo.chunk_key.clone().unwrap_or_default(),
                        data_b64: photo.chunk_b64.clone().unwrap_or_default(),
                        rtype: Some(TYPE_PHOTO_CHUNK),
                    });
                    if file.buffer.len() >= CHUNK_BUFFER_LIMIT {
                        if let Err(e) = flush_chunk_buffer(app, &mut file).await {
                            log::warn!(
                                "[photo_restore] 文件 {} 块写入失败: {}",
                                file.file_name,
                                e
                            );
                            file.abandoned = true;
                            let reason = if is_storage_full(&e) {
                                "storage-full"
                            } else {
                                "chunk-upload-failed"
                            };
                            record_file_failure(
                                &mut totals,
                                &mut failed_records,
                                &mut file,
                                0,
                                reason,
                                !is_storage_full(&e),
                            );
                        }
                    }
                }
                if !last {
                    continue;
                }

                if skip_current {
                    if let Err(e) =
                        finish_restore_photo(app, job_id, &[], true).await
                    {
                        session_error = Some(e);
                        break;
                    }
                    totals.skipped += 1;
                } else if file.abandoned {
                    if let Err(e) =
                        finish_restore_photo(app, job_id, &[], true).await
                    {
                        session_error = Some(e);
                        break;
                    }
                } else {
                    if let Err(e) = flush_chunk_buffer(app, &mut file).await {
                        log::warn!(
                            "[photo_restore] 文件 {} 尾块写入失败: {}",
                            file.file_name,
                            e
                        );
                        let reason = if is_storage_full(&e) {
                            "storage-full"
                        } else {
                            "chunk-upload-failed"
                        };
                        record_file_failure(
                            &mut totals,
                            &mut failed_records,
                            &mut file,
                            0,
                            reason,
                            !is_storage_full(&e),
                        );
                        if let Err(e) = finish_restore_photo(app, job_id, &[], true).await {
                            session_error = Some(e);
                            break;
                        }
                    } else {
                        let finish = match finish_restore_photo(
                            app,
                            job_id,
                            &file.chunk_ids,
                            false,
                        )
                        .await
                        {
                            Ok(finish) => finish,
                            Err(e) => {
                                session_error = Some(e);
                                break;
                            }
                        };
                        let record_name =
                            format!("parsed_{}_{}", import_timestamp, file.file_index.unwrap_or(0));
                        match append_restored_meta(
                            app,
                            &record_name,
                            &file.entry_key,
                            &finish.meta_b64,
                            &file.chunk_ids,
                            &file.chunk_hashes,
                        )
                        .await
                        {
                            MetaAppend::Imported(meta_id) => imported.push(PhotoImportItem {
                                meta_id,
                                name: record_name,
                                display_name: file.file_name.clone(),
                                thumb_b64: file.thumb_b64.clone(),
                                size: file.size,
                                mime: file.mime.clone(),
                                animated: finish.animated,
                            }),
                            MetaAppend::Skipped => totals.skipped += 1,
                            MetaAppend::Failed(e) => {
                                let reason = if is_storage_full(&e) {
                                    "storage-full"
                                } else {
                                    "server-rejected"
                                };
                                record_file_failure(
                                    &mut totals,
                                    &mut failed_records,
                                    &mut file,
                                    0,
                                    reason,
                                    !is_storage_full(&e),
                                );
                            }
                        }
                    }
                }

                totals.done += 1;
                emit_progress(
                    &channel,
                    &totals,
                    PHASE_IMPORTING,
                    &file.file_name,
                    0,
                    0,
                    started.elapsed(),
                );
                file = FileProgress::default();
                skip_current = false;
            }
            "done" => break,
            "cancelled" => {
                cancelled = true;
                break;
            }
            other => {
                session_error = Some(format!("未知的还原状态: {}", other));
                break;
            }
        }
    }

    // 在途照片未收尾：显式释放 worker 状态（失败只记录日志）
    let _ = finish_restore_photo(app, job_id, &[], true).await;
    let _ = end_restore_job(app, job_id).await;

    let success = !cancelled && session_error.is_none() && failed_records.is_empty();
    let mut end_error: Option<String> = None;
    let mut end_code: Option<String> = None;
    match verthys_import_end(app.clone(), app.state::<AppState>(), success).await {
        Ok(resp) => {
            if !resp.ok {
                end_error = Some(
                    resp.error
                        .unwrap_or_else(|| "结束导入会话失败".to_string()),
                );
                end_code = resp.error_code;
            }
        }
        Err(e) => end_error = Some(e),
    }

    emit_progress(
        &channel,
        &totals,
        if cancelled {
            PHASE_CANCELLED
        } else {
            PHASE_FINISHING
        },
        "",
        0,
        0,
        started.elapsed(),
    );

    if let Some(end_msg) = end_error {
        let merged = match session_error {
            Some(prev) => format!("{}；{}", prev, end_msg),
            None => end_msg,
        };
        return PhotoImportResult {
            ok: false,
            imported,
            failed_records,
            skipped: totals.skipped,
            total: totals.total,
            elapsed_ms: started.elapsed().as_millis() as u64,
            error: Some(merged),
            error_code: end_code,
            cancelled,
        };
    }

    PhotoImportResult {
        ok: !cancelled && session_error.is_none() && failed_records.is_empty(),
        imported,
        failed_records,
        skipped: totals.skipped,
        total: totals.total,
        elapsed_ms: started.elapsed().as_millis() as u64,
        error: session_error,
        error_code: None,
        cancelled,
    }
}

async fn end_restore_job(app: &tauri::AppHandle, job_id: &str) {
    let _ = send_worker(
        app,
        serde_json::json!({"op": "photo_restore_job_end", "job_id": job_id}),
        RESTORE_END_TIMEOUT,
    )
    .await;
}

#[tauri::command]
pub async fn photo_restore_cancel(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let Some(job_id) = state.photo_import_job_id() else {
        return Ok(());
    };
    if let Some(flag) = state.photo_import_cancel_flag(&job_id) {
        flag.store(true, Ordering::SeqCst);
    }
    tauri::async_runtime::spawn(async move {
        let _ = send_worker(
            &app,
            serde_json::json!({"op": "photo_restore_job_cancel", "job_id": job_id}),
            RESTORE_END_TIMEOUT,
        )
        .await;
    });
    Ok(())
}

#[cfg(test)]
mod phase3_tests {
    use super::*;

    #[test]
    fn sanitize_matches_frontend_rules() {
        assert_eq!(sanitize_file_name("a/b:c?.jpg", 200), "a b c .jpg");
        assert_eq!(sanitize_file_name("  ...jpg...  ", 200), "jpg");
        assert_eq!(sanitize_file_name("", 200), "photo");
        assert_eq!(sanitize_file_name("CON.venc", 200), "_CON.venc");
        assert_eq!(sanitize_file_name("con", 200), "_con");
        assert_eq!(sanitize_file_name("console.txt", 200), "console.txt");

        let long = format!("{}.jpg", "a".repeat(300));
        let cleaned = sanitize_file_name(&long, 200);
        assert_eq!(cleaned.len(), 200, "必须按 UTF-8 字节截断");
        assert!(cleaned.chars().all(|c| c == 'a'));

        // 多字节字符不得被截断成半个码点
        let cjk = "照".repeat(100);
        let cleaned = sanitize_file_name(&cjk, 199);
        assert!(cleaned.len() <= 199);
        assert!(cleaned.is_char_boundary(cleaned.len()));
    }

    #[test]
    fn unique_names_are_case_insensitive_and_keep_extension() {
        let mut used = HashSet::new();
        assert_eq!(unique_file_name("A.jpg", &mut used), "A.jpg");
        assert_eq!(unique_file_name("a.jpg", &mut used), "a_1.jpg");
        assert_eq!(unique_file_name("a.jpg", &mut used), "a_2.jpg");
        assert_eq!(unique_file_name("noext", &mut used), "noext");
        assert_eq!(unique_file_name("noext", &mut used), "noext_1");
    }

    #[test]
    fn export_file_names_follow_format_rules() {
        let mut used = HashSet::new();
        assert_eq!(
            export_file_name("png", "a/b.JPG", "image/jpeg", 7, &mut used),
            "a b.png"
        );
        assert_eq!(
            export_file_name("png", "a/b.JPG", "image/jpeg", 8, &mut used),
            "a b_1.png"
        );
        assert_eq!(
            export_file_name("venc-multiple", "x.jpg", "image/jpeg", 0, &mut used),
            "x.jpg.venc"
        );
        assert_eq!(
            export_file_name("original", "noext", "image/jpeg", 0, &mut used),
            "noext.jpg"
        );
        let long = "a".repeat(300);
        let file = export_file_name("original", &long, "image/jpeg", 0, &mut used);
        assert!(file.len() <= MAX_EXPORT_FILENAME_BYTES);
        assert!(file.ends_with(".jpg"));
    }

    #[test]
    fn import_timestamp_is_monotonic() {
        let a = next_import_timestamp();
        let b = next_import_timestamp();
        assert!(b > a, "记录名时间戳必须严格递增");
    }
}
