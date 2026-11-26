/*
 * 清藏导入主流水线
 *
 * 职责边界：逐文件取块、累积缓冲、提交写者、失败续跑与取消检查。
 * 单文件失败必须继续后续文件，源文件只读。
 */

use crate::controller::vault::verthys_batch_controller::{
    verthys_import_begin, verthys_import_end,
    IMPORT_SESSION_BUSY_CODE,
};
use crate::controller::vault::verthys_controller::verthys_force_close_import_session;
use crate::state::AppState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tauri::ipc::Channel;
use tauri::Manager;


use super::*;
/* ------------------------------------------------------------------ *
 * 导入主流程                                                          *
 * ------------------------------------------------------------------ */

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_import(
    app: &tauri::AppHandle,
    job_id: &str,
    cancel: Arc<AtomicBool>,
    files: Vec<FileImportSource>,
    password: &str,
    allow_session_takeover: bool,
    container_path: Option<String>,
    channel: Channel<FileImportProgress>,
    started: Instant,
) -> FileImportResult {
    let mut totals = Totals {
        total: files.len() as u64,
        ..Default::default()
    };
    let mut entries: Vec<FileImportEntry> = Vec::new();
    let mut failures: Vec<FileImportFailure> = Vec::new();
    let mut skipped_names: Vec<String> = Vec::new();
    let mut cancelled = false;
    let mut session_error: Option<String> = None;
    let mut error_code: Option<String> = None;

    emit_progress(
        &channel,
        &totals,
        PHASE_SCANNING,
        "",
        0,
        0,
        0,
        started.elapsed(),
    );

    // 建立导入会话；用户已确认接管时结束上一会话（保留其断点），再重试
    let mut begin = match verthys_import_begin(app.clone(), app.state::<AppState>(), None).await {
        Ok(resp) => resp,
        Err(e) => {
            return failure_result(totals.total, started, e, None);
        }
    };
    if !begin.ok
        && begin.error_code.as_deref() == Some(IMPORT_SESSION_BUSY_CODE)
        && allow_session_takeover
    {
        let _ = verthys_import_end(app.clone(), app.state::<AppState>(), false).await;
        begin = match verthys_import_begin(app.clone(), app.state::<AppState>(), None).await {
            Ok(resp) => resp,
            Err(e) => return failure_result(totals.total, started, e, None),
        };
        if !begin.ok && begin.error_code.as_deref() == Some(IMPORT_SESSION_BUSY_CODE) {
            let _ = verthys_force_close_import_session(
                app.clone(),
                app.state::<AppState>(),
            )
            .await;
            begin = match verthys_import_begin(app.clone(), app.state::<AppState>(), None).await {
                Ok(resp) => resp,
                Err(e) => return failure_result(totals.total, started, e, None),
            };
        }
    }
    if !begin.ok {
        return failure_result(
            totals.total,
            started,
            begin
                .error
                .clone()
                .unwrap_or_else(|| "导入会话建立失败".to_string()),
            begin.error_code.clone(),
        );
    }
    let committed_entry_keys = begin.entry_keys.clone().unwrap_or_default();

    let paths: Vec<String> = files.iter().map(|f| f.path.clone()).collect();
    if let Err(e) = authorize_batch(app, job_id, &paths).await {
        let _ = verthys_import_end(app.clone(), app.state::<AppState>(), false).await;
        return failure_result(totals.total, started, e, None);
    }
    if let Err(e) = begin_job(app, job_id, &files, password, &committed_entry_keys).await {
        let _ = verthys_import_end(app.clone(), app.state::<AppState>(), false).await;
        let _ = end_job(app, job_id).await;
        return failure_result(totals.total, started, e, None);
    }

    let mut grant_refreshed_at = Instant::now();
    let mut file = FileProgress::default();

    loop {
        if cancel.load(Ordering::SeqCst) {
            cancelled = true;
            break;
        }
        if grant_refreshed_at.elapsed() >= GRANT_REFRESH_INTERVAL {
            if let Err(e) = authorize_batch(app, job_id, &paths).await {
                session_error = Some(e);
                break;
            }
            grant_refreshed_at = Instant::now();
        }

        let raw = match send_worker(
            app,
            serde_json::json!({"op": "file_import_job_next", "job_id": job_id}),
            NEXT_TIMEOUT,
        )
        .await
        {
            Ok(raw) => raw,
            Err(e) => {
                session_error = Some(e);
                break;
            }
        };
        let reply = match parse_reply("file_import_job_next", &raw) {
            Ok(reply) => reply,
            Err(e) => {
                session_error = Some(e);
                break;
            }
        };
        if !reply.ok {
            let err = reply
                .error
                .unwrap_or_else(|| "清藏导入失败".to_string());
            if is_job_gone(&err) {
                log::warn!("[file_import] worker job 已结束: {}", err);
            } else {
                session_error = Some(err);
            }
            break;
        }
        let Some(event) = reply.file else {
            session_error = Some("清藏导入响应缺少 file 字段".to_string());
            break;
        };

        match event.status.as_str() {
            "chunk" => {
                let index = event.file_index.unwrap_or(0);
                if file.file_index != Some(index) {
                    file = FileProgress {
                        file_index: Some(index),
                        ..Default::default()
                    };
                }
                file.file_name = event.file_name.clone().unwrap_or_default();
                file.mime = event.mime.clone().unwrap_or_default();
                if let Some(size) = event.size {
                    file.size = size;
                }
                if let Some(total) = event.chunk_total {
                    file.total_chunks = total;
                }

                /* 容器卷空间预检：在文件首个块到达时判定（此时已知真实长度，
                 * 且尚未提交任何块）。读数不可得时不阻断，真实写入失败仍会
                 * 以明确错误暴露。 */
                if event.chunk_index == Some(0) && !file.abandoned {
                    if let Some(free) = container_free_bytes(container_path.as_deref()) {
                        if free < required_space(file.size) {
                            log::warn!(
                                "[file_import] 容器空间不足，放弃文件 {}: free={} required={}",
                                file.file_name,
                                free,
                                required_space(file.size)
                            );
                            abandon_file(app, job_id, &mut file).await;
                            record_file_failure(
                                &mut totals,
                                &mut failures,
                                &mut file,
                                index,
                                "E_DISK_FULL",
                                "容器卷可用空间不足",
                            );
                        }
                    }
                }

                if !file.abandoned {
                    if let Err(e) = buffer_staged_chunk(&mut file, job_id, &event) {
                        log::warn!(
                            "[file_import] 文件 {} 块暂存引用非法: {}",
                            file.file_name,
                            e
                        );
                        abandon_file(app, job_id, &mut file).await;
                        record_file_failure(
                            &mut totals,
                            &mut failures,
                            &mut file,
                            index,
                            "E_CHUNK_FAILED",
                            &e,
                        );
                    } else if file.buffer.len() >= CHUNK_BUFFER_LIMIT {
                        if let Err(e) = flush_chunk_buffer(app, &mut file).await {
                            log::warn!(
                                "[file_import] 文件 {} 块写入失败: {}",
                                file.file_name,
                                e
                            );
                            abandon_file(app, job_id, &mut file).await;
                            let code = if is_storage_full(&e) {
                                "E_DISK_FULL"
                            } else {
                                "E_CHUNK_FAILED"
                            };
                            record_file_failure(
                                &mut totals,
                                &mut failures,
                                &mut file,
                                index,
                                code,
                                &e,
                            );
                        }
                    }
                }

                if event.file_done {
                    if !file.abandoned {
                        if let Err(e) = flush_chunk_buffer(app, &mut file).await {
                            log::warn!(
                                "[file_import] 文件 {} 尾块写入失败: {}",
                                file.file_name,
                                e
                            );
                            abandon_file(app, job_id, &mut file).await;
                            let code = if is_storage_full(&e) {
                                "E_DISK_FULL"
                            } else {
                                "E_CHUNK_FAILED"
                            };
                            record_file_failure(
                                &mut totals,
                                &mut failures,
                                &mut file,
                                index,
                                code,
                                &e,
                            );
                        }
                    }

                    if !file.abandoned {
                        match finish_job(app, job_id, &file.chunk_ids).await {
                            Ok(finish) => {
                                /* 先校验回填字段再写 meta：字段不完整时不得落一条
                                 * 无法进入列表的孤条目。 */
                                if let Err(e) = validate_finish(&finish) {
                                    log::error!(
                                        "[file_import] 收尾字段校验失败，拒绝写入 meta: {}",
                                        e
                                    );
                                    record_file_failure(
                                        &mut totals,
                                        &mut failures,
                                        &mut file,
                                        index,
                                        "E_META_FAILED",
                                        &e,
                                    );
                                } else {
                                    match append_meta(app, &file, &finish).await {
                                        MetaAppend::Imported(meta_id) => {
                                            match build_entry(meta_id, &file, &finish) {
                                                Ok(entry) => entries.push(entry),
                                                Err(e) => {
                                                    log::error!(
                                                        "[file_import] 元数据回填字段缺失: {}",
                                                        e
                                                    );
                                                    record_file_failure(
                                                        &mut totals,
                                                        &mut failures,
                                                        &mut file,
                                                        index,
                                                        "E_META_FAILED",
                                                        &e,
                                                    );
                                                }
                                            }
                                        }
                                        MetaAppend::Skipped => {
                                            totals.skipped += 1;
                                            skipped_names.push(file.file_name.clone());
                                        }
                                        MetaAppend::Failed(e) => {
                                            let code = if is_storage_full(&e) {
                                                "E_DISK_FULL"
                                            } else {
                                                "E_META_FAILED"
                                            };
                                            record_file_failure(
                                                &mut totals,
                                                &mut failures,
                                                &mut file,
                                                index,
                                                code,
                                                &e,
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!(
                                    "[file_import] 文件 {} 收尾失败: {}",
                                    file.file_name,
                                    e.message
                                );
                                let code = e.code_or("E_META_FAILED");
                                record_file_failure(
                                    &mut totals,
                                    &mut failures,
                                    &mut file,
                                    index,
                                    &code,
                                    &e.message,
                                );
                            }
                        }
                    }

                    totals.done += 1;
                    let percent = progress_percent(
                        totals.done.saturating_sub(1),
                        file.total_chunks,
                        file.total_chunks,
                        totals.total,
                    );
                    emit_progress(
                        &channel,
                        &totals,
                        PHASE_IMPORTING,
                        &file.file_name,
                        file.total_chunks,
                        file.total_chunks,
                        percent,
                        started.elapsed(),
                    );
                    file = FileProgress::default();
                    continue;
                }

                let done_chunks = event.chunk_index.map(|i| i.saturating_add(1)).unwrap_or(0);
                let percent = progress_percent(
                    totals.done,
                    done_chunks,
                    file.total_chunks,
                    totals.total,
                );
                emit_progress(
                    &channel,
                    &totals,
                    PHASE_IMPORTING,
                    &file.file_name,
                    done_chunks,
                    file.total_chunks,
                    percent,
                    started.elapsed(),
                );
            }
            "empty" => {
                let index = event.file_index.unwrap_or(0);
                file = FileProgress {
                    file_index: Some(index),
                    file_name: event.file_name.clone().unwrap_or_default(),
                    mime: event.mime.clone().unwrap_or_default(),
                    size: event.size.unwrap_or(0),
                    total_chunks: 0,
                    ..Default::default()
                };
                match finish_job(app, job_id, &[]).await {
                    Ok(finish) => {
                        if let Err(e) = validate_finish(&finish) {
                            record_file_failure(
                                &mut totals,
                                &mut failures,
                                &mut file,
                                index,
                                "E_META_FAILED",
                                &e,
                            );
                        } else {
                            match append_meta(app, &file, &finish).await {
                                MetaAppend::Imported(meta_id) => {
                                    match build_entry(meta_id, &file, &finish) {
                                        Ok(entry) => entries.push(entry),
                                        Err(e) => record_file_failure(
                                            &mut totals,
                                            &mut failures,
                                            &mut file,
                                            index,
                                            "E_META_FAILED",
                                            &e,
                                        ),
                                    }
                                }
                                MetaAppend::Skipped => {
                                    totals.skipped += 1;
                                    skipped_names.push(file.file_name.clone());
                                }
                                MetaAppend::Failed(e) => {
                                    let code = if is_storage_full(&e) {
                                        "E_DISK_FULL"
                                    } else {
                                        "E_META_FAILED"
                                    };
                                    record_file_failure(
                                        &mut totals,
                                        &mut failures,
                                        &mut file,
                                        index,
                                        code,
                                        &e,
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let code = e.code_or("E_META_FAILED");
                        record_file_failure(
                            &mut totals,
                            &mut failures,
                            &mut file,
                            index,
                            &code,
                            &e.message,
                        );
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
                    progress_percent(
                        totals.done.saturating_sub(1),
                        1,
                        1,
                        totals.total,
                    ),
                    started.elapsed(),
                );
                file = FileProgress::default();
            }
            "deduped" => {
                let name = event.file_name.clone().unwrap_or_default();
                totals.skipped += 1;
                totals.done += 1;
                skipped_names.push(name.clone());
                emit_progress(
                    &channel,
                    &totals,
                    PHASE_IMPORTING,
                    &name,
                    0,
                    0,
                    progress_percent(totals.done.saturating_sub(1), 1, 1, totals.total),
                    started.elapsed(),
                );
            }
            "skipped" => {
                let index = event.file_index.unwrap_or(0);
                let name = event.file_name.clone().unwrap_or_default();
                let code = event.reason.clone().unwrap_or_else(|| "E_UNKNOWN".to_string());
                let detail = event.error.clone().unwrap_or_default();
                log::warn!("[file_import] 文件 {} 跳过: {} ({})", name, detail, code);
                file = FileProgress {
                    file_index: Some(index),
                    file_name: name,
                    ..Default::default()
                };
                record_file_failure(&mut totals, &mut failures, &mut file, index, &code, &detail);
                totals.done += 1;
                emit_progress(
                    &channel,
                    &totals,
                    PHASE_IMPORTING,
                    &file.file_name,
                    0,
                    0,
                    progress_percent(totals.done.saturating_sub(1), 1, 1, totals.total),
                    started.elapsed(),
                );
                file = FileProgress::default();
            }
            "done" => break,
            "cancelled" => {
                cancelled = true;
                break;
            }
            other => {
                session_error = Some(format!("未知的清藏导入状态: {}", other));
                break;
            }
        }
    }

    // 在途文件未收尾：取走 worker 游标并丢弃（失败只记录日志）
    if file.file_index.is_some() {
        let _ = finish_job(app, job_id, &[]).await;
    }
    if cancelled {
        let _ = send_worker(
            app,
            serde_json::json!({"op": "file_import_job_cancel", "job_id": job_id}),
            END_TIMEOUT,
        )
        .await;
    }
    end_job(app, job_id).await;

    emit_progress(
        &channel,
        &totals,
        PHASE_FINISHING,
        "",
        0,
        0,
        100,
        started.elapsed(),
    );

    let success = !cancelled && session_error.is_none() && totals.failed == 0;
    let mut session_warning = None;
    match verthys_import_end(app.clone(), app.state::<AppState>(), success).await {
        Ok(resp) => {
            if !resp.ok {
                session_warning = Some(
                    resp.error
                        .unwrap_or_else(|| "结束导入会话失败".to_string()),
                );
                error_code = resp.error_code.clone();
            }
        }
        Err(e) => session_warning = Some(e),
    }

    emit_progress(
        &channel,
        &totals,
        if cancelled {
            PHASE_CANCELLED
        } else {
            PHASE_DONE
        },
        "",
        0,
        0,
        100,
        started.elapsed(),
    );

    let success_count = entries.len() as u64;
    FileImportResult {
        ok: !cancelled
            && session_error.is_none()
            && failures.is_empty()
            && session_warning.is_none(),
        entries,
        failures,
        skipped: skipped_names,
        success_count,
        skipped_count: totals.skipped,
        fail_count: totals.failed,
        total: totals.total,
        elapsed_ms: started.elapsed().as_millis() as u64,
        cancelled,
        error: session_error.or_else(|| session_warning.clone()),
        error_code,
        session_warning,
    }
}
