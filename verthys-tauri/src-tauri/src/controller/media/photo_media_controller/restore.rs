/*
 * 原生备份还原流水线
 *
 * 职责边界：备份文件解析、路径授权、分块还原入库、索引回写与取消。
 * 还原使用单调递增批次时间戳保证记录名跨批次唯一。
 */

use crate::controller::vault::verthys_batch_controller::{
    submit_writer_cmd, verthys_gc_orphan_chunks, verthys_import_begin, verthys_import_end,
    IMPORT_SESSION_BUSY_CODE,
};
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::state::import_writer::{self, BatchAppendOutcome, WriterCommand};
use crate::state::AppState;
use crate::util::contracts::BatchRecordInput;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::ipc::Channel;
use tauri::{Manager, State};

use super::*;
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
    if let Err(msg) = ensure_source_allowed(&path) {
        return Ok(failure_result(total, started, msg, None));
    }

    let job_id = generate_job_id();
    let cancel = match state.try_begin_data_plane_job(&job_id) {
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
    state.finish_data_plane_job(&job_id);

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

    if let Err(e) =
        authorize_batch_for(app, job_id, std::slice::from_ref(&path), "photo_restore").await
    {
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
                std::slice::from_ref(&path_for_grant),
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
                    if let Err(e) = buffer_staged_chunk(&mut file, job_id, &photo) {
                        log::warn!(
                            "[photo_restore] 文件 {} 块暂存引用非法: {}",
                            file.file_name,
                            e
                        );
                        file.abandoned = true;
                        record_file_failure(
                            &mut totals,
                            &mut failed_records,
                            &mut file,
                            0,
                            "chunk-upload-failed",
                            true,
                        );
                    } else if file.buffer.len() >= CHUNK_BUFFER_LIMIT {
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

pub(super) async fn end_restore_job(app: &tauri::AppHandle, job_id: &str) {
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
    let Some(job_id) = state.data_plane_job_id() else {
        return Ok(());
    };
    /* 共享数据面槽位同时承载清藏任务：仅取消照片作业。 */
    if !job_id.starts_with("photo-") {
        return Ok(());
    }
    if let Some(flag) = state.data_plane_job_cancel_flag(&job_id) {
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
mod tests {
    use super::*;
#[test]
fn import_timestamp_is_monotonic() {
    let a = next_import_timestamp();
    let b = next_import_timestamp();
    assert!(b > a, "记录名时间戳必须严格递增");
}}
