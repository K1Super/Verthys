/*
 * worker IPC 桥接与导入共享辅助
 *
 * 职责边界：统一封装阻塞 worker 调用、回包解析、路径批授权、job 生命周期、
 * 分块缓冲提交、meta 追加、失败记录与进度推送。
 */

use crate::constants::record_types::{TYPE_FILEVERTHYS_CHUNK, TYPE_FILEVERTHYS_META};
use crate::controller::vault::verthys_batch_controller::submit_writer_cmd;
use crate::state::import_writer::{self, BatchAppendOutcome, ChunkAppendOutcome, WriterCommand};
use crate::state::AppState;
use crate::util::contracts::{BatchRecordInput, ChunkBlob};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::ipc::Channel;
use tauri::Manager;


use super::*;
/* ------------------------------------------------------------------ *
 * worker IPC 辅助                                                     *
 * ------------------------------------------------------------------ */

pub(super) async fn send_worker(
    app: &tauri::AppHandle,
    payload: serde_json::Value,
    timeout: Duration,
) -> Result<String, String> {
    let app = app.clone();
    let json = payload.to_string();
    match tauri::async_runtime::spawn_blocking(move || {
        app.state::<AppState>().send_with_timeout(&json, timeout)
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
            "target_op": "file_import",
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
            .unwrap_or_else(|| "文件路径授权失败".to_string()))
    }
}

pub(super) async fn begin_job(
    app: &tauri::AppHandle,
    job_id: &str,
    files: &[FileImportSource],
    password: &str,
    committed_entry_keys: &[String],
) -> Result<(), String> {
    let raw = send_worker(
        app,
        serde_json::json!({
            "op": "file_import_job_begin",
            "job_id": job_id,
            "files": files,
            "password": password,
            "committed_entry_keys": committed_entry_keys,
        }),
        BEGIN_TIMEOUT,
    )
    .await?;
    let reply = parse_reply("file_import_job_begin", &raw)?;
    if reply.ok {
        Ok(())
    } else {
        Err(reply
            .error
            .unwrap_or_else(|| "清藏导入任务建立失败".to_string()))
    }
}

pub(super) async fn finish_job(
    app: &tauri::AppHandle,
    job_id: &str,
    chunk_ids: &[u64],
) -> Result<FileFinish, WorkerFailure> {
    let raw = send_worker(
        app,
        serde_json::json!({
            "op": "file_import_job_finish",
            "job_id": job_id,
            "chunk_ids": chunk_ids,
        }),
        FINISH_TIMEOUT,
    )
    .await
    .map_err(|message| WorkerFailure { message, code: None })?;
    let reply = parse_reply("file_import_job_finish", &raw)
        .map_err(|message| WorkerFailure { message, code: None })?;
    if !reply.ok {
        return Err(WorkerFailure {
            message: reply
                .error
                .unwrap_or_else(|| "文件收尾失败".to_string()),
            code: reply.error_code,
        });
    }
    reply.file_finish.ok_or_else(|| WorkerFailure {
        message: "文件收尾响应缺少结果".to_string(),
        code: None,
    })
}

pub(super) async fn end_job(app: &tauri::AppHandle, job_id: &str) {
    let _ = send_worker(
        app,
        serde_json::json!({"op": "file_import_job_end", "job_id": job_id}),
        END_TIMEOUT,
    )
    .await;
}

/* ------------------------------------------------------------------ *
 * 写者通道辅助                                                        *
 * ------------------------------------------------------------------ */

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
    let outcome = submit_writer_cmd(
        &writer,
        WriterCommand::AppendChunks {
            chunks,
            reply: reply_tx,
        },
        reply_rx,
    )
    .await?;
    if !outcome.failed_indices.is_empty() || outcome.ids.len() != expected {
        return Err("文件块写入被拒绝".to_string());
    }
    if outcome.ids.contains(&0) {
        return Err("文件块未分配记录 ID".to_string());
    }
    file.chunk_ids.extend(outcome.ids);
    Ok(())
}

pub(super) fn buffer_staged_chunk(
    file: &mut FileProgress,
    job_id: &str,
    event: &FileNext,
) -> Result<(), String> {
    if event.chunk_staged != Some(true) {
        return Err("worker 未启用块暂存通道".to_string());
    }
    let chunk_key = event.chunk_key.clone().unwrap_or_default();
    let chunk_hash = event.chunk_hash.clone().unwrap_or_default();
    if chunk_key.is_empty() || chunk_hash.is_empty() {
        return Err("worker 返回的暂存块引用不完整".to_string());
    }
    file.buffer.push(ChunkBlob {
        chunk_key,
        data_b64: String::new(),
        rtype: Some(TYPE_FILEVERTHYS_CHUNK),
        staged: true,
        job_id: job_id.to_string(),
        chunk_hash,
    });
    Ok(())
}

pub(super) async fn append_meta(
    app: &tauri::AppHandle,
    file: &FileProgress,
    finish: &FileFinish,
) -> MetaAppend {
    let writer = match import_writer::ensure(app) {
        Ok(w) => w,
        Err(e) => return MetaAppend::Failed(e),
    };
    let record = BatchRecordInput {
        rtype: TYPE_FILEVERTHYS_META,
        name: finish.record_name.clone(),
        entry_key: finish.entry_key.clone(),
        data_b64: finish.meta_b64.clone(),
        chunk_ids: Some(file.chunk_ids.clone()),
        chunk_hashes: Some(finish.chunk_hashes.clone()),
    };
    let (reply_tx, reply_rx) =
        tokio::sync::oneshot::channel::<Result<BatchAppendOutcome, String>>();
    let outcome = match submit_writer_cmd(
        &writer,
        WriterCommand::AppendPending {
            records: vec![record],
            progress: None,
            reply: reply_tx,
        },
        reply_rx,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return MetaAppend::Failed(e),
    };
    let id = outcome.ids.first().copied().unwrap_or(0);
    if id > 0 {
        return MetaAppend::Imported(id);
    }
    if outcome.failed_indices.is_empty() {
        MetaAppend::Skipped
    } else {
        MetaAppend::Failed("文件元数据写入被拒绝".to_string())
    }
}

/* ------------------------------------------------------------------ *
 * 失败归类与进度                                                      *
 * ------------------------------------------------------------------ */

pub(super) fn is_storage_full(msg: &str) -> bool {
    msg.contains("ERR_0000000F")
}

pub(super) fn record_file_failure(
    totals: &mut Totals,
    failures: &mut Vec<FileImportFailure>,
    file: &mut FileProgress,
    index: u32,
    code: &str,
    message: &str,
) {
    if file.failure_recorded {
        return;
    }
    file.failure_recorded = true;
    totals.failed += 1;
    failures.push(FileImportFailure {
        index,
        name: file.file_name.clone(),
        code: code.to_string(),
        message: message.to_string(),
    });
}

pub(super) fn progress_percent(done_files: u64, file_done: u32, file_total: u32, total_files: u64) -> u8 {
    if total_files == 0 {
        return 0;
    }
    let file_part = file_done
        .saturating_mul(100)
        .checked_div(file_total)
        .unwrap_or(0);
    let combined = done_files.saturating_mul(100).saturating_add(file_part as u64);
    (combined / total_files).min(99) as u8
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_progress(
    channel: &Channel<FileImportProgress>,
    totals: &Totals,
    phase: &str,
    current_name: &str,
    current_chunk: u32,
    total_chunks: u32,
    percent: u8,
    elapsed: Duration,
) {
    let percent = if matches!(phase, PHASE_FINISHING | PHASE_DONE) {
        100
    } else {
        percent
    };
    let _ = channel.send(FileImportProgress {
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
        Err(_) => ts as u32,
    };
    format!("file-{}-{:x}", ts, random)
}
