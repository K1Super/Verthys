/*
 * controller/scan_controller.rs — 游标批量扫描控制器
 *
 * 双缓冲流水线：
 *   verthys_scan_open  → 首批 → A 区（current_buffer），后台预取 B 区
 *   verthys_scan_next  → 返回 A 区，等待 B 区 → 新 current_buffer，后台预取下一批
 *   verthys_scan_close → 取消预取、安全擦除、关闭游标
 *   verthys_scan_abort → 第 2.1 项：取消并回滚游标（发 scan_abort 到 worker）
 *
 * 第 11.2-11.7 项变更：
 *   - LockedBuffer RAII 替代 virtual_lock/unlock + secure_zero 自由函数
 *   - PrefetchTaskHandle 长期任务 + mpsc + CancellationToken 替代 spawn_blocking + abort
 *   - state.lock_scan_state() 替代 state.scan_state.lock().unwrap_or_else(...)
 *   - ScanPipelineState<T> 替代 ScanState / ScanSummaryState
 *
 * 第 2.1-2.7 项变更（阶段 6）：
 *   - 2.1: CancellationToken + scan_abort 回滚游标；scan_close 触发 cancel + 等待退出
 *   - 2.3: 擦除顺序由 LockedBuffer Drop 保证（先 zeroize while VirtualLock'd → 再 VirtualUnlock）
 *   - 2.4: ScanSessionState 状态机（Active/Failed/Closed），操作经状态转移
 *   - 2.5: 泛型 ScanPipeline<T: ScanRecord>（全量+摘要共用，已由阶段 4 实现）
 *   - 2.6: shm_name 正则校验 ^[a-zA-Z0-9_\-]{1,64}$ + TimeoutConfig 超时提取
 *   - 2.7: 每批校验 records.len() == worker record_count，不一致熔断 + 审计 + 通知 worker 重置
 *
 * 依赖方向：controller → state / infrastructure / controller::types / util
 */

use crate::controller::api_error::ErrorCode;
use crate::controller::types::{VerthysRecordEntry, VerthysResponse, VerthysSummaryEntry};
use crate::state::{
    cleanup_scan_on_failure, cleanup_summary_scan_on_failure, AppState, LockedBuffer,
    PrefetchTaskHandle, ScanPipelineState, ScanRecord, ScanSessionState,
};
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};
use std::time::Duration;
use tauri::State;

/* ------------------------------------------------------------------ *
 * 第 2.6 项：超时配置（提取为常量，对应 TimeoutConfig::DEFAULT）         *
 * ------------------------------------------------------------------ */

/// 预取任务关闭超时（第 2.6 项：对应 TimeoutConfig.scan_prefetch_shutdown）
const PREFETCH_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// scan_open 超时（第 2.6 项：对应 TimeoutConfig.scan_open）
const SCAN_OPEN_TIMEOUT: Duration = Duration::from_secs(60);
/// scan_next 超时（第 2.6 项：对应 TimeoutConfig.scan_next）
const SCAN_NEXT_TIMEOUT: Duration = Duration::from_secs(60);
/// scan_close 超时（第 2.6 项：对应 TimeoutConfig.scan_close）
const SCAN_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);
/// 预取内部二级超时（第 2.6 项：对应 TimeoutConfig.scan_prefetch）
/// 注：生产代码在 scan_pipeline::do_prefetch_blocking 中直接使用 TimeoutConfig::DEFAULT.scan_prefetch，
/// 此常量供测试校验一致性。
#[allow(dead_code)]
const SCAN_PREFETCH_TIMEOUT: Duration = Duration::from_secs(60);

/* ------------------------------------------------------------------ *
 * 第 2.6 项 + 第 2.7 项：shm_name 校验 + 批次校验 + 审计               *
 *                                                                    *
 * 与 key_controller / file_controller 中的审计实现同模式。            *
 * 资源标识哈希化，HMAC 密钥由设备指纹派生，失败不阻塞业务。           *
 * ------------------------------------------------------------------ */

/// 第 2.6 项：获取审计日志文件路径
fn get_audit_log_path(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    use tauri::Manager;
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join("audit.log")),
        Err(e) => {
            log::warn!("[audit] 获取配置目录失败，跳过审计写入: {}", e);
            None
        }
    }
}

/// 第 2.6 项：获取审计日志 HMAC 密钥（设备指纹派生）
fn get_audit_hmac_key() -> Option<[u8; 32]> {
    use crate::infrastructure::device_fingerprint::get_device_fingerprint;
    use crate::util::crypto::pbkdf2_derive_default;

    match get_device_fingerprint() {
        Ok(fingerprint) => {
            const AUDIT_SALT: &[u8] = b"verthys_audit_log_hmac_salt_v1";
            match pbkdf2_derive_default(fingerprint.as_bytes(), AUDIT_SALT) {
                Ok(key) => Some(key),
                Err(e) => {
                    log::warn!("[audit] 派生 HMAC 密钥失败，跳过审计写入: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            log::warn!("[audit] 获取设备指纹失败，跳过审计写入: {}", e);
            None
        }
    }
}

/// 第 2.7 项：写入扫描操作审计事件（不阻塞业务流程）
///
/// 封装 audit_log::append_audit 的错误处理：
///   - 获取审计日志路径失败 → 跳过
///   - 获取 HMAC 密钥失败 → 跳过
///   - append_audit 失败 → 记录 warning，不传播错误
fn write_scan_audit(
    app: &tauri::AppHandle,
    event_type: AuditEventType,
    result: AuditResult,
    detail: Option<String>,
) {
    let log_path = match get_audit_log_path(app) {
        Some(p) => p,
        None => return,
    };

    let hmac_key = match get_audit_hmac_key() {
        Some(k) => k,
        None => return,
    };

    let session_id = format!("pid-{}", std::process::id());

    let mut event = AuditEvent::new(event_type, &session_id, "user", result);

    if let Some(d) = detail {
        event = event.with_detail(d);
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[audit] 写入扫描审计事件失败（不阻塞业务）: {}", e);
    }
}

/// 第 2.6 项：shm_name 白名单校验
///
/// 校验 shm_name 匹配 `^[a-zA-Z0-9_\-]{1,64}$`，防止路径注入。
/// 委托到 `constants::shm::is_valid_shm_name`（与 worker 同源定义）。
///
/// 校验失败返回 SHM_CORRUPTED 错误码的 VerthysResponse。
fn validate_shm_name(shm_name: &str) -> Result<(), String> {
    use crate::constants::is_valid_shm_name;
    if !is_valid_shm_name(shm_name) {
        log::warn!(
            "[scan] shm_name 校验失败（仅字母/数字/下划线/连字符，1-64 字符）"
        );
        return Err(ErrorCode::ShmCorrupted.default_message().to_string());
    }
    Ok(())
}

/// 第 2.7 项：批次记录数校验
///
/// 校验实际解析的记录数与 worker 报告的 record_count 一致。
/// 不一致表示共享内存数据损坏（部分记录因边界校验被跳过），
/// 触发熔断：审计 + 通知 worker 重置。
///
/// # 参数
/// - `actual_count`: read_from_shm 返回的 records.len()
/// - `expected_count`: SHM 头部 worker 写入的 record_count
///
/// # 返回
/// - Ok(()): 记录数一致
/// - Err(msg): 不一致，调用方应触发熔断清理
fn validate_batch_count(actual_count: usize, expected_count: usize) -> Result<(), String> {
    if actual_count != expected_count {
        log::error!(
            "[scan] 第 2.7 项：批次记录数不一致 actual={} expected={}，触发熔断",
            actual_count,
            expected_count
        );
        return Err(format!(
            "批次记录数不一致（actual={}, expected={}），共享内存数据可能损坏",
            actual_count, expected_count
        ));
    }
    Ok(())
}

/* ------------------------------------------------------------------ *
 * 全量扫描控制器                                                       *
 * ------------------------------------------------------------------ */

/// 打开扫描游标，返回首批记录
///
/// 第 2.1-2.7 项流程：
///   1. 若已有扫描在进行，先关闭旧游标（shutdown 预取 + 擦除缓冲 + scan_abort）
///   2. 发送 scan_open 到 worker（创建共享内存 + 打开 C 游标 + 首批预加载）
///   3. 第 2.6 项：校验 shm_name 白名单
///   4. 从共享内存读取首批记录 → LockedBuffer（VirtualLock + RAII）
///   5. 第 2.7 项：校验 records.len() == worker record_count
///   6. 若未遍历结束，启动长期预取任务并发送首批 Fetch
///   7. 第 2.4 项：存入 ScanPipelineState（session_state = Active）
///   8. 第 2.7 项：审计日志
#[tauri::command]
pub async fn verthys_scan_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    start_id: u64,
    batch_size: u64,
) -> Result<VerthysResponse, String> {
    // 若已有扫描在进行，先关闭旧游标
    let old_scan = {
        let mut guard = state.lock_scan_state();
        guard.take()
    };
    if let Some(mut old) = old_scan {
        // shutdown 旧预取任务（第 2.1 项：cancel + 等待退出）
        if let Some(handle) = old.prefetch_task.take() {
            handle.shutdown(PREFETCH_SHUTDOWN_TIMEOUT).await;
        }
        // drop pending_reply + current_buffer（LockedBuffer Drop: 擦除 + 解锁）
        // 第 2.3 项：擦除顺序由 LockedBuffer Drop 保证（先 zeroize while VirtualLock'd → 再 VirtualUnlock）
        old.pending_reply.take();
        old.current_buffer.take();
        // 第 2.1 项：通知 worker 取消旧游标（发 scan_abort 回滚）
        let req = serde_json::json!({"op": "scan_abort"});
        let _ = state.send(&req.to_string());
    }

    // 1. 发送 scan_open 到 worker
    let req = serde_json::json!({
        "op": "scan_open",
        "id": start_id,
        "rtype": batch_size,
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
        .ok_or_else(|| "scan_open response missing shm_name".to_string())?;

    // 2. 第 2.6 项：shm_name 白名单校验
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

    // 3. 从共享内存读取首批记录 → LockedBuffer（第 11.2 项：VirtualLock RAII）
    let (records, _shm_exhausted, worker_record_count) =
        VerthysRecordEntry::read_from_shm(&shm_name)?;

    // 4. 第 2.7 项：批次记录数校验
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

    let locked_buffer = LockedBuffer::new(records)
        .map_err(|e| format!("VirtualLock failed: {}", e))?;
    // 克隆用于响应（原记录保持锁定存储于 current_buffer）
    let return_records = locked_buffer.records().to_vec();

    // 5. 后台预取 B 区（若未遍历结束）
    // 第 2.1 项：启动长期预取任务，发送首批 Fetch
    let (prefetch_task, pending_reply) = if !exhausted {
        let handle =
            PrefetchTaskHandle::<VerthysRecordEntry>::spawn(app.clone(), shm_name.clone());
        // 发送失败：向上传播错误，handle 随函数提前返回被 Drop
        // 自动取消预取任务（cancel + 关闭命令通道，见 PrefetchTaskHandle::drop）
        let reply_rx = handle.send_fetch(batch_size).await?;
        (Some(handle), Some(reply_rx))
    } else {
        (None, None)
    };

    // 6. 存入 ScanPipelineState（第 2.4 项：session_state = Active）
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

    // 7. 第 2.7 项：审计日志
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
        ..VerthysResponse::ok("scan_open")
    })
}

/// 拉取下一批记录（双缓冲流水线切换）
///
/// 第 2.1-2.7 项流程：
///   1. 取出整个 ScanPipelineState
///   2. 第 2.4 项：检查 session_state == Active，Failed/Closed 拒绝
///   3. Drop 旧 current_buffer（LockedBuffer Drop: 先擦除后解锁，第 2.3 项）
///   4. 等待 pending_reply → 新记录 + worker record_count
///   5. 第 2.7 项：校验 records.len() == worker record_count
///   6. LockedBuffer 锁定新记录
///   7. 若未遍历结束，通过同一预取任务发送下一轮 Fetch
///   8. 存回 ScanPipelineState
///   9. 第 2.7 项：审计日志
#[tauri::command]
pub async fn verthys_scan_next(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    batch_size: u64,
) -> Result<VerthysResponse, String> {
    // 1. 取出整个 ScanPipelineState（第 11.5 项：lock_scan_state 中毒恢复）
    let mut scan = {
        let mut guard = state.lock_scan_state();
        guard.take().ok_or("scan not open")?
    };

    // 2. 第 2.4 项：ScanSessionState 状态机检查
    if !scan.session_state.allow_next() {
        let rejected_state = scan.session_state;
        log::warn!(
            "[scan_next] 第 2.4 项：状态机拒绝 next（当前 {:?}）",
            rejected_state
        );
        // 存回状态
        {
            let mut guard = state.lock_scan_state();
            *guard = Some(scan);
        }
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
    // 第 2.3 项：RAII 保证擦除顺序，替代 virtual_unlock + secure_zero
    scan.current_buffer.take();

    let shm_name = scan.shm_name.clone();

    // 4. 等待预取完成
    let (new_records, new_exhausted, worker_record_count) = if scan.exhausted {
        // 已经遍历结束，无更多数据
        (Vec::new(), true, 0)
    } else if let Some(reply_rx) = scan.pending_reply.take() {
        // 第 2.1 项：等待长期预取任务的回复
        // reply_rx.await 返回 Result<Result<(Vec<T>, bool, usize), String>, RecvError>
        match reply_rx.await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                // 第 2.4 项：预取任务返回错误 → 状态转 Failed
                scan.session_state = ScanSessionState::Failed;
                {
                    let mut guard = state.lock_scan_state();
                    *guard = Some(scan);
                }
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
                // 第 2.4 项：通道关闭（任务崩溃）→ 状态转 Failed
                scan.session_state = ScanSessionState::Failed;
                {
                    let mut guard = state.lock_scan_state();
                    *guard = Some(scan);
                }
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
        // 第 2.7 项：无 pending_reply（异常状态），同步拉取降级单缓冲模式
        log::warn!("[scan_next] 无 pending_reply，降级同步单缓冲模式");
        let req = serde_json::json!({"op": "scan_fetch", "id": batch_size});
        let resp_json = state.send_with_timeout(&req.to_string(), SCAN_NEXT_TIMEOUT)?;
        let resp: VerthysResponse =
            serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
        if !resp.ok {
            scan.session_state = ScanSessionState::Failed;
            {
                let mut guard = state.lock_scan_state();
                *guard = Some(scan);
            }
            cleanup_scan_on_failure(state.inner()).await;
            return Ok(resp);
        }
        let (records, exhausted, count) = VerthysRecordEntry::read_from_shm(&shm_name)?;
        (records, exhausted, count)
    };

    // 5. 第 2.7 项：批次记录数校验
    if let Err(e) = validate_batch_count(new_records.len(), worker_record_count) {
        scan.session_state = ScanSessionState::Failed;
        {
            let mut guard = state.lock_scan_state();
            *guard = Some(scan);
        }
        write_scan_audit(
            &app,
            AuditEventType::ScanCircuitBreaker,
            AuditResult::Failure,
            Some(e),
        );
        cleanup_scan_on_failure(state.inner()).await;
        return Err(ErrorCode::ShmCorrupted.default_message().to_string());
    }

    // 6. LockedBuffer 锁定新记录（第 11.2 项）
    let locked_buffer = LockedBuffer::new(new_records)
        .map_err(|e| format!("VirtualLock failed: {}", e))?;
    let return_records = locked_buffer.records().to_vec();
    let return_empty = return_records.is_empty();

    // 7. 若未遍历结束，通过同一预取任务发送下一轮 Fetch（第 2.1 项：长期任务复用）
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

    // 8. 存回 ScanPipelineState（第 2.4 项：保持 Active）
    scan.current_buffer = Some(locked_buffer);
    scan.exhausted = new_exhausted;
    scan.pending_reply = new_pending_reply;
    // session_state 保持 Active（除非上方已转 Failed）
    {
        let mut guard = state.lock_scan_state();
        *guard = Some(scan);
    }

    // 9. 第 2.7 项：审计日志
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
        ..VerthysResponse::ok("scan_next")
    })
}

/// 关闭扫描游标，释放所有资源
///
/// 第 2.1 项：scan_close 触发 cancel + 等待任务自退出（非 abort）
///
/// 流程：
///   1. 取出 ScanPipelineState
///   2. shutdown 预取任务（cancel + 等待退出）
///   3. drop pending_reply + current_buffer（LockedBuffer Drop: 擦除 + 解锁）
///   4. 发送 scan_close 到 worker（正常关闭，非 abort）
///   5. 第 2.4 项：session_state → Closed
///   6. 第 2.7 项：审计日志
#[tauri::command]
pub async fn verthys_scan_close(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    // 1. 取出 ScanPipelineState（第 11.5 项：lock_scan_state 中毒恢复）
    let scan_opt = {
        let mut guard = state.lock_scan_state();
        guard.take()
    };

    if let Some(mut scan) = scan_opt {
        // 2. shutdown 预取任务（第 2.1 项：cancel + 短超时等待退出）
        if let Some(handle) = scan.prefetch_task.take() {
            handle.shutdown(PREFETCH_SHUTDOWN_TIMEOUT).await;
        }
        // 3. drop pending_reply + current_buffer
        // 第 2.3 项：LockedBuffer Drop 先 zeroize 后 VirtualUnlock
        scan.pending_reply.take();
        scan.current_buffer.take();
        // 第 2.4 项：session_state → Closed
        scan.session_state = ScanSessionState::Closed;
    }

    // 4. 通知 worker 关闭游标（正常 close，非 abort）
    let req = serde_json::json!({"op": "scan_close"});
    let resp_json = state.send_with_timeout(&req.to_string(), SCAN_CLOSE_TIMEOUT)?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;

    // 5. 第 2.7 项：审计日志
    let result = if resp.ok { AuditResult::Success } else { AuditResult::Failure };
    write_scan_audit(&app, AuditEventType::ScanClose, result, resp.error.clone());

    Ok(resp)
}

/// 第 2.1 项：取消扫描并回滚游标
///
/// 与 scan_close 的区别：
///   - scan_close：正常关闭，发 scan_close 到 worker
///   - scan_abort：取消并回滚，发 scan_abort 到 worker（语义为"中断回滚"）
///
/// 适用场景：
///   - 用户主动取消扫描
///   - 前端通道关闭时 CancellationToken 通知
///   - 异常路径需要立即回滚游标
#[tauri::command]
pub async fn verthys_scan_abort(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    // 1. 取出 ScanPipelineState
    let scan_opt = {
        let mut guard = state.lock_scan_state();
        guard.take()
    };

    if let Some(mut scan) = scan_opt {
        // 2. shutdown 预取任务（cancel + 等待退出）
        if let Some(handle) = scan.prefetch_task.take() {
            handle.shutdown(PREFETCH_SHUTDOWN_TIMEOUT).await;
        }
        // 3. drop pending_reply + current_buffer
        scan.pending_reply.take();
        scan.current_buffer.take();
        // 第 2.4 项：session_state → Closed
        scan.session_state = ScanSessionState::Closed;
    }

    // 4. 第 2.1 项：通知 worker 取消并回滚游标（发 scan_abort）
    let req = serde_json::json!({"op": "scan_abort"});
    let resp_json = state.send_with_timeout(&req.to_string(), SCAN_CLOSE_TIMEOUT)?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;

    // 5. 审计日志
    let result = if resp.ok { AuditResult::Success } else { AuditResult::Failure };
    write_scan_audit(&app, AuditEventType::ScanAbort, result, resp.error.clone());

    Ok(resp)
}

/* ------------------------------------------------------------------ *
 * 摘要扫描控制器（Phase 2C：轻量元数据，不读数据块）                  *
 *                                                                    *
 * 与全量扫描控制器完全对称，区别：                                     *
 *   - 操作 scan_summary_state 而非 scan_state                         *
 *   - 使用 VerthysSummaryEntry 而非 VerthysRecordEntry                    *
 *   - worker 端 op 为 scan_summary_open/fetch/close/abort             *
 *                                                                    *
 * 第 11.3 项：全量与摘要共用 ScanPipelineState<T> + PrefetchTaskHandle<T>*
 * 第 2.1-2.7 项：与全量扫描同构的校验/状态机/审计                      *
 * ------------------------------------------------------------------ */

/// 打开摘要扫描游标，返回首批摘要记录
#[tauri::command]
pub async fn verthys_scan_summary_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    start_id: u64,
    batch_size: u64,
) -> Result<VerthysResponse, String> {
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
        // 第 2.1 项：通知 worker 取消旧游标
        let req = serde_json::json!({"op": "scan_summary_abort"});
        let _ = state.send(&req.to_string());
    }

    // 1. 发送 scan_summary_open 到 worker
    let req = serde_json::json!({
        "op": "scan_summary_open",
        "id": start_id,
        "rtype": batch_size,
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

    // 2. 第 2.6 项：shm_name 白名单校验
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
        VerthysSummaryEntry::read_from_shm(&shm_name)?;

    // 4. 第 2.7 项：批次记录数校验
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

    let locked_buffer = LockedBuffer::new(records)
        .map_err(|e| format!("VirtualLock failed: {}", e))?;
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

    // 6. 存入 ScanPipelineState（第 2.4 项：session_state = Active）
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
    // 1. 取出整个 ScanPipelineState
    let mut scan = {
        let mut guard = state.lock_scan_summary_state();
        guard.take().ok_or("summary scan not open")?
    };

    // 2. 第 2.4 项：ScanSessionState 状态机检查
    if !scan.session_state.allow_next() {
        let rejected_state = scan.session_state;
        log::warn!(
            "[scan_summary_next] 第 2.4 项：状态机拒绝 next（当前 {:?}）",
            rejected_state
        );
        {
            let mut guard = state.lock_scan_summary_state();
            *guard = Some(scan);
        }
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

    // 4. 等待预取完成
    let (new_records, new_exhausted, worker_record_count) = if scan.exhausted {
        (Vec::new(), true, 0)
    } else if let Some(reply_rx) = scan.pending_reply.take() {
        match reply_rx.await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                scan.session_state = ScanSessionState::Failed;
                {
                    let mut guard = state.lock_scan_summary_state();
                    *guard = Some(scan);
                }
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
                {
                    let mut guard = state.lock_scan_summary_state();
                    *guard = Some(scan);
                }
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
        // 第 2.7 项：降级同步单缓冲模式
        log::warn!("[scan_summary_next] 无 pending_reply，降级同步单缓冲模式");
        let req = serde_json::json!({"op": "scan_summary_fetch", "id": batch_size});
        let resp_json = state.send_with_timeout(&req.to_string(), SCAN_NEXT_TIMEOUT)?;
        let resp: VerthysResponse =
            serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
        if !resp.ok {
            scan.session_state = ScanSessionState::Failed;
            {
                let mut guard = state.lock_scan_summary_state();
                *guard = Some(scan);
            }
            cleanup_summary_scan_on_failure(state.inner()).await;
            return Ok(resp);
        }
        let (records, exhausted, count) = VerthysSummaryEntry::read_from_shm(&shm_name)?;
        (records, exhausted, count)
    };

    // 5. 第 2.7 项：批次记录数校验
    if let Err(e) = validate_batch_count(new_records.len(), worker_record_count) {
        scan.session_state = ScanSessionState::Failed;
        {
            let mut guard = state.lock_scan_summary_state();
            *guard = Some(scan);
        }
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
    let locked_buffer = LockedBuffer::new(new_records)
        .map_err(|e| format!("VirtualLock failed: {}", e))?;
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
    {
        let mut guard = state.lock_scan_summary_state();
        *guard = Some(scan);
    }

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
        // 第 2.4 项：session_state → Closed
        scan.session_state = ScanSessionState::Closed;
    }

    let req = serde_json::json!({"op": "scan_summary_close"});
    let resp_json = state.send_with_timeout(&req.to_string(), SCAN_CLOSE_TIMEOUT)?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;

    let result = if resp.ok { AuditResult::Success } else { AuditResult::Failure };
    write_scan_audit(&app, AuditEventType::ScanClose, result, resp.error.clone());

    Ok(resp)
}

/// 第 2.1 项：取消摘要扫描并回滚游标
#[tauri::command]
pub async fn verthys_scan_summary_abort(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
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
        scan.session_state = ScanSessionState::Closed;
    }

    // 第 2.1 项：发 scan_summary_abort 到 worker
    let req = serde_json::json!({"op": "scan_summary_abort"});
    let resp_json = state.send_with_timeout(&req.to_string(), SCAN_CLOSE_TIMEOUT)?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;

    let result = if resp.ok { AuditResult::Success } else { AuditResult::Failure };
    write_scan_audit(&app, AuditEventType::ScanAbort, result, resp.error.clone());

    Ok(resp)
}

/* ------------------------------------------------------------------ *
 * 单元测试                                                            *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_shm_name_valid() {
        // 第 2.6 项：合法 shm_name
        assert!(validate_shm_name("verthys_scan_3f7a9b2e1c").is_ok());
        assert!(validate_shm_name("abc123_-XYZ").is_ok());
        assert!(validate_shm_name("a").is_ok());
    }

    #[test]
    fn test_validate_shm_name_invalid() {
        // 第 2.6 项：非法 shm_name
        assert!(validate_shm_name("").is_err()); // 空
        assert!(validate_shm_name("path/with/slash").is_err()); // 斜杠
        assert!(validate_shm_name("with space").is_err()); // 空格
        assert!(validate_shm_name("with..dots").is_err()); // 点号
        assert!(validate_shm_name("中文").is_err()); // 非 ASCII
        assert!(validate_shm_name(&"a".repeat(65)).is_err()); // 超长
        assert!(validate_shm_name("../../etc/passwd").is_err()); // 路径穿越
    }

    #[test]
    fn test_validate_batch_count_match() {
        // 第 2.7 项：记录数一致
        assert!(validate_batch_count(0, 0).is_ok());
        assert!(validate_batch_count(100, 100).is_ok());
        assert!(validate_batch_count(10000, 10000).is_ok());
    }

    #[test]
    fn test_validate_batch_count_mismatch() {
        // 第 2.7 项：记录数不一致（数据损坏）
        assert!(validate_batch_count(99, 100).is_err());
        assert!(validate_batch_count(101, 100).is_err());
        assert!(validate_batch_count(0, 1).is_err());
        assert!(validate_batch_count(1, 0).is_err());
    }

    #[test]
    fn test_scan_session_state_allow_next() {
        // 第 2.4 项：状态机检查
        assert!(ScanSessionState::Active.allow_next());
        assert!(!ScanSessionState::Failed.allow_next());
        assert!(!ScanSessionState::Closed.allow_next());
    }

    #[test]
    fn test_scan_timeouts_match_timeout_config() {
        // 第 2.6 项：常量与 TimeoutConfig 默认值一致
        use crate::constants::timeout::DEFAULT as TC;
        assert_eq!(SCAN_OPEN_TIMEOUT, TC.scan_open);
        assert_eq!(SCAN_NEXT_TIMEOUT, TC.scan_next);
        assert_eq!(SCAN_CLOSE_TIMEOUT, TC.scan_close);
        assert_eq!(SCAN_PREFETCH_TIMEOUT, TC.scan_prefetch);
        assert_eq!(PREFETCH_SHUTDOWN_TIMEOUT, TC.scan_prefetch_shutdown);
    }
}
