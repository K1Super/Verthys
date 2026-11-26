/*
 * 照片原生导入流水线
 *
 * 职责边界：导入命令入口、路径分批、单写者落库、失败续跑与取消。
 * 单文件失败必须继续后续文件；作业串行占用由 AppState 槽位保证。
 */

use crate::controller::vault::verthys_batch_controller::{
    verthys_gc_orphan_chunks, verthys_import_begin, verthys_import_end,
    IMPORT_SESSION_BUSY_CODE,
};
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::state::AppState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tauri::ipc::Channel;
use tauri::{Manager, State};

use super::*;
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

    for path in &paths {
        if let Err(msg) = ensure_source_allowed(path) {
            return Ok(failure_result(total, started, msg, None));
        }
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

    let result = run_import(&app, &job_id, cancel, paths, on_progress, started).await;

    // 所有返回路径都必须释放槽位；按 job_id 比对，避免误清后来者
    state.finish_data_plane_job(&job_id);

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

    /* 会话已提交的条目键一次性交给 worker：命中在打开文件前跳过，
     * 不读盘、不哈希、不解码。键集合在会话内不变（写入由本流程串行完成）。 */
    let committed_entry_keys = begin.entry_keys.clone().unwrap_or_default();

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
        if let Err(e) = begin_job(app, &job_id, batch_paths, &committed_entry_keys).await {
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
                        if let Err(e) = buffer_staged_chunk(&mut file, &job_id, &photo) {
                            log::warn!(
                                "[photo_import] 文件 {} 块暂存引用非法: {}",
                                file.file_name,
                                e
                            );
                            file.abandoned = true;
                            record_file_failure(
                                &mut totals,
                                &mut failed_records,
                                &mut file,
                                batch_offset,
                                "chunk-upload-failed",
                                true,
                            );
                        } else if file.buffer.len() >= CHUNK_BUFFER_LIMIT {
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
                "deduped" => {
                    // 条目键命中宿主已提交集合：本次未新增记录，不是失败
                    let source = photo.file_name.clone().unwrap_or_default();
                    totals.skipped += 1;
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
    let Some(job_id) = state.data_plane_job_id() else {
        // 无活跃任务视为幂等成功
        return Ok(());
    };
    /* 共享数据面槽位同时承载清藏任务：取消必须按 job 前缀隔离，
     * 避免照片界面的延迟取消请求打断清藏导入。 */
    if !job_id.starts_with("photo-") {
        return Ok(());
    }
    if let Some(flag) = state.data_plane_job_cancel_flag(&job_id) {
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
