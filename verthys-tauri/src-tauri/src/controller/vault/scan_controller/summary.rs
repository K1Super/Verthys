/*
 * 摘要扫描（open / next / close）
 *
 * 职责边界：轻量元数据游标，与全量扫描同构，区别仅在状态槽、条目类型与
 * worker op 前缀；不读取数据块。
 */

use crate::controller::api_error::ErrorCode;
use crate::controller::types::{VerthysResponse, VerthysSummaryEntry};
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::state::{
    cleanup_summary_scan_on_failure, AppState, LockedBuffer,
    PrefetchTaskHandle, ScanPipelineState, ScanRecord, ScanSessionState,
};
use crate::util::audit_log::{AuditEventType, AuditResult};
use std::time::Duration;
use tauri::State;

use super::*;
use super::shared::{
    gen_shm_batch_key, restore_summary_scan_pipeline, validate_batch_count, validate_shm_name,
    write_scan_audit,
};
/* ------------------------------------------------------------------ *
 * 摘要扫描控制器（轻量元数据，不读数据块）                  *
 *                                                                    *
 * 与全量扫描控制器完全对称，区别：                                     *
 *   - 操作 scan_summary_state 而非 scan_state                         *
 *   - 使用 VerthysSummaryEntry 而非 VerthysRecordEntry                    *
 *   - worker 端 op 为 scan_summary_open/fetch/close/abort             *
 *                                                                    *
 * 全量与摘要共用 ScanPipelineState<T> + PrefetchTaskHandle<T>*
 * 与全量扫描同构的校验/状态机/审计                      *
 * ------------------------------------------------------------------ */

/// 打开摘要扫描游标，返回首批摘要记录
#[tauri::command]
pub async fn verthys_scan_summary_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    start_id: u64,
    batch_size: u64,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "scan_summary_open") {
        return Ok(VerthysResponse::err("scan_summary_open", &msg));
    }
    // 若已有摘要扫描在进行，先关闭旧游标
    let old_scan = {
        let mut guard = state.lock_scan_summary_state();
        guard.take()
    };
    if let Some(mut old) = old_scan {
        if let Some(handle) = old.prefetch_task.take() {
            handle.shutdown(PREFETCH_SHUTDOWN_TIMEOUT).await;
        }
        old.pending_reply.take();
        old.current_buffer.take();
        // 通知 worker 取消旧游标
        let req = serde_json::json!({"op": "scan_summary_abort"});
        let _ = state.send(&req.to_string());
    }

    // 1. 发送 scan_summary_open 到 worker（首批同样携带 SHM 认证密钥）
    let (open_key, open_key_b64) = gen_shm_batch_key();
    let req = serde_json::json!({
        "op": "scan_summary_open",
        "id": start_id,
        "max_count": batch_size,
        "shm_key": open_key_b64,
    });
    let resp_json = state.send_with_timeout(&req.to_string(), SCAN_OPEN_TIMEOUT)?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    if !resp.ok {
        write_scan_audit(
            &app,
            AuditEventType::ScanOpen,
            AuditResult::Failure,
            resp.error.clone(),
        );
        return Ok(resp);
    }

    let shm_name = resp
        .shm_name
        .clone()
        .ok_or_else(|| "scan_summary_open response missing shm_name".to_string())?;

    // 2. shm_name 白名单校验
    if let Err(e) = validate_shm_name(&shm_name) {
        log::error!("[scan_summary_open] shm_name 校验失败");
        write_scan_audit(
            &app,
            AuditEventType::ScanOpen,
            AuditResult::Denied,
            Some("shm_name validation failed".into()),
        );
        let abort_req = serde_json::json!({"op": "scan_summary_abort"});
        let _ = state.send_with_timeout(&abort_req.to_string(), Duration::from_secs(5));
        return Err(e);
    }

    let exhausted = resp.exhausted.unwrap_or(false);

    // 3. 从共享内存读取首批摘要记录 → LockedBuffer
    let (records, _shm_exhausted, worker_record_count) =
        VerthysSummaryEntry::read_from_shm(&shm_name, Some(&open_key[..]))?;

    // 4. 批次记录数校验
    if let Err(e) = validate_batch_count(records.len(), worker_record_count) {
        write_scan_audit(
            &app,
            AuditEventType::ScanCircuitBreaker,
            AuditResult::Failure,
            Some(e),
        );
        cleanup_summary_scan_on_failure(state.inner()).await;
        return Err(ErrorCode::ShmCorrupted.default_message().to_string());
    }

    let locked_buffer =
        LockedBuffer::new(records).map_err(|e| format!("VirtualLock failed: {}", e))?;
    let return_records = locked_buffer.records().to_vec();

    // 5. 后台预取 B 区（若未遍历结束）
    let (prefetch_task, pending_reply) = if !exhausted {
        let handle =
            PrefetchTaskHandle::<VerthysSummaryEntry>::spawn(app.clone(), shm_name.clone());
        let reply_rx = handle.send_fetch(batch_size).await?;
        (Some(handle), Some(reply_rx))
    } else {
        (None, None)
    };

    // 6. 存入 ScanPipelineState（session_state = Active）
    {
        let mut guard = state.lock_scan_summary_state();
        *guard = Some(ScanPipelineState {
            shm_name,
            current_buffer: Some(locked_buffer),
            exhausted,
            prefetch_task,
            pending_reply,
            session_state: ScanSessionState::Active,
        });
    }

    // 7. 审计日志
    write_scan_audit(
        &app,
        AuditEventType::ScanOpen,
        AuditResult::Success,
        Some(format!(
            "summary batch_size={}, returned={}, exhausted={}",
            batch_size,
            return_records.len(),
            exhausted
        )),
    );

    // 8. 返回首批摘要记录
    Ok(VerthysResponse {
        ok: true,
        op: "scan_summary_open".into(),
        summary_records: Some(return_records),
        exhausted: Some(exhausted),
        ..VerthysResponse::ok("scan_summary_open")
    })
}

/// 拉取下一批摘要记录（双缓冲流水线切换）
#[tauri::command]
pub async fn verthys_scan_summary_next(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    batch_size: u64,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "scan_summary_next") {
        return Ok(VerthysResponse::err("scan_summary_next", &msg));
    }
    // 1. 取出整个 ScanPipelineState
    let mut scan = {
        let mut guard = state.lock_scan_summary_state();
        guard.take().ok_or("summary scan not open")?
    };

    // 2. ScanSessionState 状态机检查
    if !scan.session_state.allow_next() {
        let rejected_state = scan.session_state;
        log::warn!(
            "[scan_summary_next] 第 2.4 项：状态机拒绝 next（当前 {:?}）",
            rejected_state
        );
        restore_summary_scan_pipeline(state.inner(), scan);
        write_scan_audit(
            &app,
            AuditEventType::ScanNext,
            AuditResult::Denied,
            Some(format!("state={:?} reject next", rejected_state)),
        );
        return Ok(VerthysResponse::err(
            "scan_summary_next",
            ErrorCode::ShmCorrupted.default_message(),
        ));
    }

    // 3. Drop 旧 current_buffer
    scan.current_buffer.take();

    let shm_name = scan.shm_name.clone();

    // 4. 等待预取完成（摘要扫描无失败条目：元数据直读不解密数据块）
    let (new_records, new_exhausted, worker_record_count, _failed_ids) = if scan.exhausted {
        (Vec::new(), true, 0, Vec::new())
    } else if let Some(reply_rx) = scan.pending_reply.take() {
        match reply_rx.await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                scan.session_state = ScanSessionState::Failed;
                restore_summary_scan_pipeline(state.inner(), scan);
                write_scan_audit(
                    &app,
                    AuditEventType::ScanCircuitBreaker,
                    AuditResult::Failure,
                    Some(format!("summary prefetch error: {}", e)),
                );
                cleanup_summary_scan_on_failure(state.inner()).await;
                return Err(e);
            }
            Err(_) => {
                scan.session_state = ScanSessionState::Failed;
                restore_summary_scan_pipeline(state.inner(), scan);
                write_scan_audit(
                    &app,
                    AuditEventType::ScanCircuitBreaker,
                    AuditResult::Failure,
                    Some("summary prefetch reply channel closed".into()),
                );
                cleanup_summary_scan_on_failure(state.inner()).await;
                return Err("summary prefetch reply channel closed".to_string());
            }
        }
    } else {
        // 5. 降级同步单缓冲模式
        log::warn!("[scan_summary_next] 无 pending_reply，降级同步单缓冲模式");
        let (fallback_key, fallback_key_b64) = gen_shm_batch_key();
        let req = serde_json::json!({
            "op": "scan_summary_fetch",
            "id": batch_size,
            "shm_key": fallback_key_b64,
        });
        let resp_json = state.send_with_timeout(&req.to_string(), SCAN_NEXT_TIMEOUT)?;
        let resp: VerthysResponse =
            serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
        if !resp.ok {
            scan.session_state = ScanSessionState::Failed;
            restore_summary_scan_pipeline(state.inner(), scan);
            cleanup_summary_scan_on_failure(state.inner()).await;
            return Ok(resp);
        }
        let (records, exhausted, count) =
            VerthysSummaryEntry::read_from_shm(&shm_name, Some(&fallback_key[..]))?;
        (records, exhausted, count, Vec::new())
    };

    // 5. 批次记录数校验
    if let Err(e) = validate_batch_count(new_records.len(), worker_record_count) {
        scan.session_state = ScanSessionState::Failed;
        restore_summary_scan_pipeline(state.inner(), scan);
        write_scan_audit(
            &app,
            AuditEventType::ScanCircuitBreaker,
            AuditResult::Failure,
            Some(e),
        );
        cleanup_summary_scan_on_failure(state.inner()).await;
        return Err(ErrorCode::ShmCorrupted.default_message().to_string());
    }

    // 6. LockedBuffer 锁定新记录
    let locked_buffer =
        LockedBuffer::new(new_records).map_err(|e| format!("VirtualLock failed: {}", e))?;
    let return_records = locked_buffer.records().to_vec();
    let return_empty = return_records.is_empty();

    // 7. 发送下一轮 Fetch
    let new_pending_reply = if !new_exhausted && !return_empty {
        if let Some(task) = &scan.prefetch_task {
            Some(task.send_fetch(batch_size).await?)
        } else {
            None
        }
    } else {
        None
    };

    if new_exhausted {
        if let Some(task) = scan.prefetch_task.take() {
            task.shutdown(PREFETCH_SHUTDOWN_TIMEOUT).await;
        }
    }

    // 8. 存回 ScanPipelineState
    scan.current_buffer = Some(locked_buffer);
    scan.exhausted = new_exhausted;
    scan.pending_reply = new_pending_reply;
    restore_summary_scan_pipeline(state.inner(), scan);

    // 9. 审计日志
    write_scan_audit(
        &app,
        AuditEventType::ScanNext,
        AuditResult::Success,
        Some(format!(
            "summary returned={}, exhausted={}",
            return_records.len(),
            new_exhausted && return_empty
        )),
    );

    // 10. 返回摘要记录
    Ok(VerthysResponse {
        ok: true,
        op: "scan_summary_next".into(),
        summary_records: Some(return_records),
        exhausted: Some(new_exhausted && return_empty),
        ..VerthysResponse::ok("scan_summary_next")
    })
}

/// 关闭摘要扫描游标，释放所有资源
#[tauri::command]
pub async fn verthys_scan_summary_close(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "scan_summary_close") {
        return Ok(VerthysResponse::err("scan_summary_close", &msg));
    }

    let scan_opt = {
        let mut guard = state.lock_scan_summary_state();
        guard.take()
    };

    if let Some(mut scan) = scan_opt {
        if let Some(handle) = scan.prefetch_task.take() {
            handle.shutdown(PREFETCH_SHUTDOWN_TIMEOUT).await;
        }
        scan.pending_reply.take();
        scan.current_buffer.take();
        // session_state → Closed
        scan.session_state = ScanSessionState::Closed;
    }

    let req = serde_json::json!({"op": "scan_summary_close"});
    let resp_json = state.send_with_timeout(&req.to_string(), SCAN_CLOSE_TIMEOUT)?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;

    let result = if resp.ok {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    write_scan_audit(&app, AuditEventType::ScanClose, result, resp.error.clone());

    Ok(resp)
}
