/*
 * 全量记录扫描（open / next / close）
 *
 * 职责边界：全量记录游标的打开、预取批次拉取、批次一致性校验与关闭。
 * 每批必须校验 records.len() == worker record_count，不一致即熔断。
 */

use crate::controller::api_error::ErrorCode;
use crate::controller::types::{VerthysRecordEntry, VerthysResponse};
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::state::{
    cleanup_scan_on_failure, AppState, LockedBuffer,
    PrefetchTaskHandle, ScanPipelineState, ScanRecord, ScanSessionState,
};
use crate::util::audit_log::{AuditEventType, AuditResult};
use std::time::Duration;
use tauri::State;

use super::*;
use super::shared::{
    gen_shm_batch_key, restore_scan_pipeline, validate_batch_count, validate_shm_name,
    write_scan_audit,
};
/* ------------------------------------------------------------------ *
 * 全量扫描控制器                                                       *
 * ------------------------------------------------------------------ */

/// 打开扫描游标，返回首批记录
///
/// 流程：
///   1. 若已有扫描在进行，先关闭旧游标（shutdown 预取 + 擦除缓冲 + scan_abort）
///   2. 发送 scan_open 到 worker（创建共享内存 + 打开 C 游标 + 首批预加载）
///   3. 校验 shm_name 白名单
///   4. 从共享内存读取首批记录 → LockedBuffer（VirtualLock + RAII）
///   5. 校验 records.len() == worker record_count
///   6. 若未遍历结束，启动长期预取任务并发送首批 Fetch
///   7. 存入 ScanPipelineState（session_state = Active）
///   8. 审计日志
///
/// project / inline_max_bytes 为扫描投影参数（可选，缺省 = FULL 全量解密）：
/// 索引/列表类调用传 project="index" 与内联阈值，超过阈值的记录只回索引
/// 条目（不解密、不搬运数据），避免大批量数据集的扫描整批失败。
#[tauri::command]
pub async fn verthys_scan_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    start_id: u64,
    batch_size: u64,
    project: Option<String>,
    inline_max_bytes: Option<u64>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, "scan_open") {
        return Ok(VerthysResponse::err("scan_open", &msg));
    }

    // 若已有扫描在进行，先关闭旧游标
    let old_scan = {
        let mut guard = state.lock_scan_state();
        guard.take()
    };
    if let Some(mut old) = old_scan {
        // shutdown 旧预取任务（cancel + 等待退出）
        if let Some(handle) = old.prefetch_task.take() {
            handle.shutdown(PREFETCH_SHUTDOWN_TIMEOUT).await;
        }
        // drop pending_reply + current_buffer（LockedBuffer Drop: 擦除 + 解锁）
        // 擦除顺序由 LockedBuffer Drop 保证（先 zeroize while VirtualLock'd → 再 VirtualUnlock）
        old.pending_reply.take();
        old.current_buffer.take();
        // 通知 worker 取消旧游标（发 scan_abort 回滚）
        let req = serde_json::json!({"op": "scan_abort"});
        let _ = state.send(&req.to_string());
    }

    // 1. 发送 scan_open 到 worker（首批同样携带 SHM 认证密钥）
    let (open_key, open_key_b64) = gen_shm_batch_key();
    let mut req = serde_json::json!({
        "op": "scan_open",
        "id": start_id,
        "max_count": batch_size,
        "shm_key": open_key_b64,
    });
    // 投影与内联阈值按需附加：缺省字段等价于 FULL 全量解密（既有调用方语义不变）
    if let Some(p) = project.as_deref() {
        if !p.is_empty() {
            req["project"] = serde_json::Value::String(p.to_string());
        }
    }
    if let Some(n) = inline_max_bytes {
        req["inline_max_bytes"] = serde_json::json!(n);
    }
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

    // 首批失败条目：上游按 lid 记账（解密失败/索引不一致），随响应透传前端
    let open_failed_ids = resp.failed_ids.clone().unwrap_or_default();

    let shm_name = resp
        .shm_name
        .clone()
        .ok_or_else(|| "scan_open response missing shm_name".to_string())?;

    // 2. shm_name 白名单校验
    if let Err(e) = validate_shm_name(&shm_name) {
        log::error!("[scan_open] shm_name 校验失败");
        write_scan_audit(
            &app,
            AuditEventType::ScanOpen,
            AuditResult::Denied,
            Some("shm_name validation failed".into()),
        );
        // 通知 worker 取消游标
        let abort_req = serde_json::json!({"op": "scan_abort"});
        let _ = state.send_with_timeout(&abort_req.to_string(), Duration::from_secs(5));
        return Err(e);
    }

    let exhausted = resp.exhausted.unwrap_or(false);

    // 3. 从共享内存读取首批记录 → LockedBuffer（VirtualLock RAII）
    let (records, _shm_exhausted, worker_record_count) =
        VerthysRecordEntry::read_from_shm(&shm_name, Some(&open_key[..]))?;

    // 4. 批次记录数校验
    if let Err(e) = validate_batch_count(records.len(), worker_record_count) {
        write_scan_audit(
            &app,
            AuditEventType::ScanCircuitBreaker,
            AuditResult::Failure,
            Some(e.clone()),
        );
        // 熔断清理 + 通知 worker 重置
        cleanup_scan_on_failure(state.inner()).await;
        return Err(ErrorCode::ShmCorrupted.default_message().to_string());
    }

    let locked_buffer =
        LockedBuffer::new(records).map_err(|e| format!("VirtualLock failed: {}", e))?;
    // 克隆用于响应（原记录保持锁定存储于 current_buffer）
    let return_records = locked_buffer.records().to_vec();

    // 5. 后台预取 B 区（若未遍历结束）
    // 启动长期预取任务，发送首批 Fetch
    let (prefetch_task, pending_reply) = if !exhausted {
        let handle = PrefetchTaskHandle::<VerthysRecordEntry>::spawn(app.clone(), shm_name.clone());
        // 发送失败：向上传播错误，handle 随函数提前返回被 Drop
        // 自动取消预取任务（cancel + 关闭命令通道，PrefetchTaskHandle::drop）
        let reply_rx = handle.send_fetch(batch_size).await?;
        (Some(handle), Some(reply_rx))
    } else {
        (None, None)
    };

    // 6. 存入 ScanPipelineState（session_state = Active）
    {
        let mut guard = state.lock_scan_state();
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
            "batch_size={}, returned={}, exhausted={}",
            batch_size,
            return_records.len(),
            exhausted
        )),
    );

    // 8. 返回首批记录
    Ok(VerthysResponse {
        ok: true,
        op: "scan_open".into(),
        records: Some(return_records),
        exhausted: Some(exhausted),
        failed_ids: if open_failed_ids.is_empty() {
            None
        } else {
            Some(open_failed_ids)
        },
        ..VerthysResponse::ok("scan_open")
    })
}

/// 拉取下一批记录（双缓冲流水线切换）
///
/// 流程：
///   1. 取出整个 ScanPipelineState
///   2. 检查 session_state == Active，Failed/Closed 拒绝
///   3. Drop 旧 current_buffer（LockedBuffer Drop: 先擦除后解锁）
///   4. 等待 pending_reply → 新记录 + worker record_count
///   5. 校验 records.len() == worker record_count
///   6. LockedBuffer 锁定新记录
///   7. 若未遍历结束，通过同一预取任务发送下一轮 Fetch
///   8. 存回 ScanPipelineState
///   9. 审计日志
#[tauri::command]
pub async fn verthys_scan_next(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    batch_size: u64,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "scan_next") {
        return Ok(VerthysResponse::err("scan_next", &msg));
    }

    // 1. 取出整个 ScanPipelineState（lock_scan_state 中毒恢复）
    let mut scan = {
        let mut guard = state.lock_scan_state();
        guard.take().ok_or("scan not open")?
    };

    // 2. ScanSessionState 状态机检查
    if !scan.session_state.allow_next() {
        let rejected_state = scan.session_state;
        log::warn!(
            "[scan_next] 第 2.4 项：状态机拒绝 next（当前 {:?}）",
            rejected_state
        );
        // 存回状态
        restore_scan_pipeline(state.inner(), scan);
        write_scan_audit(
            &app,
            AuditEventType::ScanNext,
            AuditResult::Denied,
            Some(format!("state={:?} reject next", rejected_state)),
        );
        return Ok(VerthysResponse::err(
            "scan_next",
            ErrorCode::ShmCorrupted.default_message(),
        ));
    }

    // 3. Drop 旧 current_buffer（LockedBuffer Drop: 先 zeroize 后 VirtualUnlock）
    // RAII 保证擦除顺序
    scan.current_buffer.take();

    let shm_name = scan.shm_name.clone();

    // 4. 等待预取完成
    let (new_records, new_exhausted, worker_record_count, failed_ids) = if scan.exhausted {
        // 已经遍历结束，无更多数据
        (Vec::new(), true, 0, Vec::new())
    } else if let Some(reply_rx) = scan.pending_reply.take() {
        // 等待长期预取任务的回复
        // reply_rx.await 返回 Result<Result<(Vec<T>, bool, usize), String>, RecvError>
        match reply_rx.await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                // 预取任务返回错误 → 状态转 Failed
                scan.session_state = ScanSessionState::Failed;
                restore_scan_pipeline(state.inner(), scan);
                // 预取失败触发熔断清理
                write_scan_audit(
                    &app,
                    AuditEventType::ScanCircuitBreaker,
                    AuditResult::Failure,
                    Some(format!("prefetch error: {}", e)),
                );
                cleanup_scan_on_failure(state.inner()).await;
                return Err(e);
            }
            Err(_) => {
                // 通道关闭（任务崩溃）→ 状态转 Failed
                scan.session_state = ScanSessionState::Failed;
                restore_scan_pipeline(state.inner(), scan);
                write_scan_audit(
                    &app,
                    AuditEventType::ScanCircuitBreaker,
                    AuditResult::Failure,
                    Some("prefetch reply channel closed (task crashed?)".into()),
                );
                cleanup_scan_on_failure(state.inner()).await;
                return Err("prefetch reply channel closed (task crashed?)".to_string());
            }
        }
    } else {
        // 无 pending_reply（异常状态），同步拉取降级单缓冲模式
        log::warn!("[scan_next] 无 pending_reply，降级同步单缓冲模式");
        let (fallback_key, fallback_key_b64) = gen_shm_batch_key();
        let req = serde_json::json!({
            "op": "scan_fetch",
            "id": batch_size,
            "shm_key": fallback_key_b64,
        });
        let resp_json = state.send_with_timeout(&req.to_string(), SCAN_NEXT_TIMEOUT)?;
        let resp: VerthysResponse =
            serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
        if !resp.ok {
            scan.session_state = ScanSessionState::Failed;
            restore_scan_pipeline(state.inner(), scan);
            cleanup_scan_on_failure(state.inner()).await;
            return Ok(resp);
        }
        let fallback_failed = resp.failed_ids.clone().unwrap_or_default();
        let (records, exhausted, count) =
            VerthysRecordEntry::read_from_shm(&shm_name, Some(&fallback_key[..]))?;
        (records, exhausted, count, fallback_failed)
    };

    // 5. 批次记录数校验
    if let Err(e) = validate_batch_count(new_records.len(), worker_record_count) {
        scan.session_state = ScanSessionState::Failed;
        restore_scan_pipeline(state.inner(), scan);
        write_scan_audit(
            &app,
            AuditEventType::ScanCircuitBreaker,
            AuditResult::Failure,
            Some(e),
        );
        cleanup_scan_on_failure(state.inner()).await;
        return Err(ErrorCode::ShmCorrupted.default_message().to_string());
    }

    // 6. LockedBuffer 锁定新记录
    let locked_buffer =
        LockedBuffer::new(new_records).map_err(|e| format!("VirtualLock failed: {}", e))?;
    let return_records = locked_buffer.records().to_vec();
    let return_empty = return_records.is_empty();

    // 7. 若未遍历结束，通过同一预取任务发送下一轮 Fetch（长期任务复用）
    let new_pending_reply = if !new_exhausted && !return_empty {
        if let Some(task) = &scan.prefetch_task {
            Some(task.send_fetch(batch_size).await?)
        } else {
            None
        }
    } else {
        None
    };

    // 若已遍历结束，shutdown 预取任务
    if new_exhausted {
        if let Some(task) = scan.prefetch_task.take() {
            task.shutdown(PREFETCH_SHUTDOWN_TIMEOUT).await;
        }
    }

    // 8. 存回 ScanPipelineState（保持 Active）
    scan.current_buffer = Some(locked_buffer);
    scan.exhausted = new_exhausted;
    scan.pending_reply = new_pending_reply;
    // session_state 保持 Active（除非上方已转 Failed）
    restore_scan_pipeline(state.inner(), scan);

    // 9. 审计日志
    write_scan_audit(
        &app,
        AuditEventType::ScanNext,
        AuditResult::Success,
        Some(format!(
            "returned={}, exhausted={}",
            return_records.len(),
            new_exhausted && return_empty
        )),
    );

    // 10. 返回记录
    Ok(VerthysResponse {
        ok: true,
        op: "scan_next".into(),
        records: Some(return_records),
        exhausted: Some(new_exhausted && return_empty),
        failed_ids: if failed_ids.is_empty() {
            None
        } else {
            Some(failed_ids)
        },
        ..VerthysResponse::ok("scan_next")
    })
}

/// 关闭扫描游标，释放所有资源
///
/// scan_close 触发 cancel + 等待任务自退出（非 abort）
///
/// 流程：
///   1. 取出 ScanPipelineState
///   2. shutdown 预取任务（cancel + 等待退出）
///   3. drop pending_reply + current_buffer（LockedBuffer Drop: 擦除 + 解锁）
///   4. 发送 scan_close 到 worker（正常关闭，非 abort）
///   5. session_state → Closed
///   6. 审计日志
#[tauri::command]
pub async fn verthys_scan_close(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "scan_close") {
        return Ok(VerthysResponse::err("scan_close", &msg));
    }

    // 1. 取出 ScanPipelineState（lock_scan_state 中毒恢复）
    let scan_opt = {
        let mut guard = state.lock_scan_state();
        guard.take()
    };

    if let Some(mut scan) = scan_opt {
        // 2. shutdown 预取任务（cancel + 短超时等待退出）
        if let Some(handle) = scan.prefetch_task.take() {
            handle.shutdown(PREFETCH_SHUTDOWN_TIMEOUT).await;
        }
        // 3. drop pending_reply + current_buffer
        // LockedBuffer Drop 先 zeroize 后 VirtualUnlock
        scan.pending_reply.take();
        scan.current_buffer.take();
        // session_state → Closed
        scan.session_state = ScanSessionState::Closed;
    }

    // 4. 通知 worker 关闭游标（正常 close，非 abort）
    let req = serde_json::json!({"op": "scan_close"});
    let resp_json = state.send_with_timeout(&req.to_string(), SCAN_CLOSE_TIMEOUT)?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;

    // 5. 审计日志
    let result = if resp.ok {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    write_scan_audit(&app, AuditEventType::ScanClose, result, resp.error.clone());

    Ok(resp)
}
