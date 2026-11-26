/*
 * 原生导出流水线
 *
 * 职责边界：导出命令入口、扫描与导出阶段、流式原子写盘、失败隔离与取消。
 * worker 产出字节，宿主只负责命名、去重与落盘；导出结果逐文件汇报。
 */

use crate::controller::files::file_controller::{
    audit_export_event, stream_abort_blocking, stream_append_blocking, stream_create_blocking,
    stream_finalize_blocking,
};
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::state::file_streams::FileStreamState;
use crate::state::AppState;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::Channel;
use tauri::State;

use super::*;
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
    /* 超时只放弃等待；取消标志确保阻塞任务不会在返回失败后继续 rename。 */
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_task = cancel.clone();
    match tokio::time::timeout(
        Duration::from_secs(120),
        tauri::async_runtime::spawn_blocking(move || {
            stream_finalize_blocking(entry, Some(cancel_for_task.as_ref()))
        }),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => Err(format!("落盘任务异常: {}", e)),
        Err(_) => {
            cancel.store(true, Ordering::SeqCst);
            Err("落盘结果未确认，请核对导出文件".to_string())
        }
    }
}

async fn stream_abort_async(entry: Arc<Mutex<FileStreamState>>) {
    let _ = tokio::time::timeout(
        Duration::from_secs(60),
        tauri::async_runtime::spawn_blocking(move || stream_abort_blocking(entry)),
    )
    .await;
}

#[derive(Clone, Copy)]
struct ExportCounts {
    total: u64,
    done: u64,
    failed: u64,
    exported: u64,
}

fn emit_export_progress(
    channel: &Channel<PhotoExportProgress>,
    counts: ExportCounts,
    current_name: &str,
    phase: &str,
    started: Instant,
) {
    let ExportCounts {
        total,
        done,
        failed,
        exported,
    } = counts;
    let percent = if matches!(phase, EXPORT_PHASE_FINISHING | EXPORT_PHASE_DONE) {
        100
    } else {
        done
            .saturating_mul(100)
            .checked_div(total)
            .map_or(0, |value| value.min(99) as u8)
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
    let cancel = match state.try_begin_data_plane_job(&job_id) {
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
    state.finish_data_plane_job(&job_id);
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
        ExportCounts {
            total,
            done: 0,
            failed: 0,
            exported: 0,
        },
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
                    Some("failed") if failed_indices.insert(index) => {
                        failures.push(PhotoExportFailure {
                            index,
                            name: name.clone(),
                            reason: event.reason.unwrap_or_else(|| "unknown".to_string()),
                        });
                    }
                    _ => {}
                }
                done += 1;
                emit_export_progress(
                    &channel,
                    ExportCounts {
                        total,
                        done,
                        failed: failures.len() as u64,
                        exported,
                    },
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
        ExportCounts {
            total,
            done,
            failed: failures.len() as u64,
            exported,
        },
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
            serde_json::json!({"op": "photo_export_job_cancel", "job_id": job_id}),
            EXPORT_END_TIMEOUT,
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
}
