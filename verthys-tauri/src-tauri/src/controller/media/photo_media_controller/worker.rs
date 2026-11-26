/*
 * worker IPC 桥接与导入/还原共享辅助
 *
 * 职责边界：统一封装阻塞 worker 调用、回包解析、路径批授权、job 生命周期、
 * 分块缓冲提交、meta 追加、进度推送与作业 ID 生成。导入、读取、导出、
 * 还原四条流水线共用本模块，禁止各自复制协议细节。
 */

use crate::constants::record_types::{TYPE_PHOTO_CHUNK, TYPE_PHOTO_PREVIEW};
use crate::controller::vault::verthys_batch_controller::submit_writer_cmd;
use crate::state::import_writer::{self, BatchAppendOutcome, ChunkAppendOutcome, WriterCommand};
use crate::state::AppState;
use crate::util::contracts::{BatchRecordInput, ChunkBlob};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::ipc::Channel;
use tauri::Manager;

use super::*;

/// 源文件路径安全校验：字符级校验 + 系统关键目录拒绝。
///
/// 无法 canonicalize 的路径（文件已移除 / 无权限）交给 worker 按文件级错误
/// 报告，不能让单个不可解析文件毁掉整批导入。
pub(super) fn ensure_source_allowed(path: &str) -> Result<(), String> {
    if path.is_empty() || path.contains('\0') {
        return Err("文件路径非法".to_string());
    }
    crate::util::path::validate_path_input(path).map_err(|_| "文件路径非法".to_string())?;
    if let Ok(canonical) = std::fs::canonicalize(path) {
        if crate::controller::files::file_controller::is_system_critical_path(&canonical) {
            return Err("拒绝读取系统关键目录".to_string());
        }
    }
    Ok(())
}

pub(super) async fn send_worker(
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

pub(super) fn parse_reply(what: &str, raw: &str) -> Result<WorkerReply, String> {
    serde_json::from_str(raw).map_err(|e| format!("{} 响应解析失败: {}", what, e))
}

pub(super) async fn authorize_batch(
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

pub(super) async fn begin_job(
    app: &tauri::AppHandle,
    job_id: &str,
    paths: &[String],
    committed_entry_keys: &[String],
) -> Result<(), String> {
    let raw = send_worker(
        app,
        serde_json::json!({
            "op": "photo_import_job_begin",
            "job_id": job_id,
            "paths": paths,
            "committed_entry_keys": committed_entry_keys,
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

pub(super) async fn end_job(app: &tauri::AppHandle, job_id: &str) -> Result<(), String> {
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
pub(super) async fn finish_job(
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
pub(super) async fn flush_chunk_buffer(
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
    if outcome.ids.contains(&0) {
        return Err("照片块未分配记录 ID".to_string());
    }
    file.chunk_ids.extend(outcome.ids);
    Ok(())
}

/// 把 worker 返回的暂存块引用加入缓冲。
///
/// 照片导入只接受 worker 暂存通道：引用不完整或 worker 未启用暂存即失败，
/// 绝不回退到内联块密文（回退会重新引入 base64 大字符串搬运）。
pub(super) fn buffer_staged_chunk(
    file: &mut FileProgress,
    job_id: &str,
    photo: &PhotoPayload,
) -> Result<(), String> {
    if photo.chunk_staged != Some(true) {
        return Err("worker 未启用块暂存通道".to_string());
    }
    let chunk_key = photo.chunk_key.clone().unwrap_or_default();
    let chunk_hash = photo.chunk_hash.clone().unwrap_or_default();
    if chunk_key.is_empty() || chunk_hash.is_empty() {
        return Err("worker 返回的暂存块引用不完整".to_string());
    }
    file.chunk_hashes.push(chunk_hash.clone());
    file.buffer.push(ChunkBlob {
        chunk_key,
        data_b64: String::new(),
        rtype: Some(TYPE_PHOTO_CHUNK),
        staged: true,
        job_id: job_id.to_string(),
        chunk_hash,
    });
    Ok(())
}

/// 写入 meta 记录；依赖写者按 entry_key 做幂等去重
pub(super) async fn append_meta(
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

pub(super) fn is_storage_full(msg: &str) -> bool {
    msg.contains("ERR_0000000F")
}

/// worker skipped 的原因文本 → 前端既有枚举
pub(super) fn map_skipped_reason(reason: &str) -> (&'static str, bool) {
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

pub(super) fn meta_name(file_name: &str) -> String {
    format!("meta_{}", file_name)
}

pub(super) fn record_file_failure(
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

pub(super) fn is_job_gone(err: &str) -> bool {
    err.contains("job 不存在") || err.contains("已结束")
}

/// 丢弃残留导入会话（锁库/崩溃后未 end）：不压缩 WAL，保留磁盘续传状态。
///
/// 只丢弃绑定到其他容器路径的会话；当前容器的活跃会话（例如清藏在导入）
/// 不在此处抢占，调用方继续按 E_IMPORT_SESSION_BUSY 提示用户。
pub(super) fn discard_stale_import_session(app: &tauri::AppHandle) -> bool {
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

pub(super) fn emit_progress(
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
    } else {
        totals
            .done
            .saturating_mul(100)
            .checked_div(totals.total)
            .map_or(0, |value| value.min(99) as u8)
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

pub(super) fn generate_job_id() -> String {
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

pub(super) fn failure_result(
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

pub(super) async fn authorize_batch_for(
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
