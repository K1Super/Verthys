/*
 * 导入命令入口
 *
 * 职责边界：入参校验、并发槽位占用、���件级路径安全校验与启动结果包装。
 */

use crate::controller::files::file_controller::is_system_critical_path;
use crate::controller::vault::verthys_batch_controller::verthys_gc_orphan_chunks;
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::state::AppState;
use std::time::Instant;
use tauri::ipc::Channel;
use tauri::{Manager, State};
use zeroize::Zeroizing;


use super::*;
/* ------------------------------------------------------------------ *
 * 命令：file_import_start                                             *
 * ------------------------------------------------------------------ */

#[tauri::command]
pub async fn file_import_start(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    files: Vec<FileImportSource>,
    password: Option<String>,
    allow_session_takeover: bool,
    on_progress: Channel<FileImportProgress>,
) -> Result<FileImportResult, String> {
    let started = Instant::now();
    let total = files.len() as u64;
    let password = Zeroizing::new(password.unwrap_or_default());

    if let Err(msg) = require_unlocked(&app, &state, "file_import_start") {
        return Ok(failure_result(
            total,
            started,
            msg,
            Some(ERROR_CODE_NOT_READY.to_string()),
        ));
    }
    if files.is_empty() {
        return Ok(failure_result(total, started, "未选择文件".to_string(), None));
    }
    if files.len() > MAX_FILES {
        return Ok(failure_result(
            total,
            started,
            format!("单次导入不超过 {} 个文件", MAX_FILES),
            None,
        ));
    }
    let sources_for_validation = files.clone();
    match tauri::async_runtime::spawn_blocking(move || validate_sources(&sources_for_validation))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(msg)) => return Ok(failure_result(total, started, msg, None)),
        Err(e) => {
            return Ok(failure_result(
                total,
                started,
                format!("文件校验任务异常: {}", e),
                None,
            ))
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

    let result = run_import(
        &app,
        &job_id,
        cancel,
        files,
        password.as_str(),
        allow_session_takeover,
        state.verthys_session_path(),
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
                    "[file_import] 孤儿块清理失败: {}",
                    resp.error.unwrap_or_else(|| "未知错误".to_string())
                ),
                Err(e) => log::warn!("[file_import] 孤儿块清理异常: {}", e),
                _ => {}
            }
        });
    }

    Ok(result)
}

fn validate_sources(files: &[FileImportSource]) -> Result<(), String> {
    for file in files {
        if file.name.is_empty() || file.name.contains('\0') {
            return Err("文件名非法".to_string());
        }
        if file.path.is_empty() || file.path.contains('\0') {
            return Err("文件路径非法".to_string());
        }
        crate::util::path::validate_path_input(&file.path)
            .map_err(|_| "文件路径非法".to_string())?;
        /* 系统关键目录是安全边界：路径可解析时必须拒绝。
         * 无法解析（文件已移除 / 无权限）或目标不是普通文件时，
         * 交给 worker 按文件级错误报告，不能让单个文件毁掉整批导入。 */
        if let Ok(canonical) = std::fs::canonicalize(&file.path) {
            if is_system_critical_path(&canonical) {
                return Err("拒绝读取系统关键目录".to_string());
            }
        }
    }
    Ok(())
}

pub(super) fn failure_result(
    total: u64,
    started: Instant,
    error: String,
    error_code: Option<String>,
) -> FileImportResult {
    FileImportResult {
        ok: false,
        entries: Vec::new(),
        failures: Vec::new(),
        skipped: Vec::new(),
        success_count: 0,
        skipped_count: 0,
        fail_count: 0,
        total,
        elapsed_ms: started.elapsed().as_millis() as u64,
        cancelled: false,
        error: Some(error),
        error_code,
        session_warning: None,
    }
}
