/*
 * 落盘、锁定与落盘自查
 *
 * 职责边界：lock 落盘、锁定前置闸门、会话代际校验后的销毁、flush 刷盘、
 * worker 进程内落盘自查，以及异常场景下导入会话的强制关闭。
 * 锁定路径必须先持久化再销毁 worker，禁止把未确认落盘伪装成成功。
 */

use super::*;
use crate::controller::types::VerthysResponse;
use crate::state::AppState;
use crate::util::audit_log::{AuditEventType, AuditResult};
use tauri::State;
// ===== 持久化落盘 =====

/// 发送 lock 指令强制 worker 将内存数据持久化到磁盘，但不销毁 worker。
///
/// 配合 verthys_lock 使用，实现「先持久化→停 C 线程→销毁 worker」的完整流程。
/// 超时 8 秒，若失败或超时仅记录警告，不阻塞后续销毁。
#[tauri::command]
pub async fn verthys_lock_persist(state: State<'_, AppState>) -> Result<VerthysResponse, String> {
    state.begin_io();
    let lock_req = r#"{"op":"lock"}"#;
    let lock_timeout = std::time::Duration::from_secs(8);

    let result = match state.send_with_timeout(lock_req, lock_timeout) {
        Ok(resp_json) => match serde_json::from_str::<VerthysResponse>(&resp_json) {
            Ok(resp) => {
                if !resp.ok {
                    log::warn!(
                        "[verthys_lock_persist] worker lock 返回失败: {:?}",
                        resp.error
                    );
                }
                Ok(resp)
            }
            Err(e) => {
                log::warn!("[verthys_lock_persist] 解析 lock 响应失败: {}", e);
                Ok(VerthysResponse::err(
                    "lock",
                    "落盘结果未确认（响应解析失败）",
                ))
            }
        },
        Err(e) => {
            log::warn!(
                "[verthys_lock_persist] worker lock 超时或失败（仍允许后续销毁兜底）: {}",
                e
            );
            Ok(VerthysResponse::err("lock", "落盘结果未确认（通信超时或失败）"))
        }
    };
    state.end_io();
    result
}

// ===== 锁定（销毁 worker） =====

/// 锁定前置闸门：请求取消并等待全库轮换 Run 收敛（后端有界 30s）。
///
/// 前端在任何破坏性锁定步骤（清 GMK / 落盘 / 销毁 worker）之前调用。
/// 失败表示轮换仍在执行，本次锁定必须整体放弃并保留会话与空闲计时；
/// 前端超时结果不能作为安全边界 —— `verthys_lock` / `worker_destroy`
/// 内部仍保留同一闸门与代际校验作为最后防线。
#[tauri::command]
pub async fn verthys_prepare_lock() -> Result<VerthysResponse, String> {
    tauri::async_runtime::spawn_blocking(|| {
        crate::service::vault_rotate::prepare_for_lock(std::time::Duration::from_secs(30))
    })
    .await
    .map_err(|e| format!("锁定闸门执行失败: {e}"))??;
    Ok(VerthysResponse::ok("prepare_lock"))
}

/// 释放无会话归属的锁定资源（代际冲突路径）。
///
/// 只在确认当前没有任何 worker 会话时调用：此时残留的哨兵锁与旧文件锁
/// 不属于任何活动会话，必须回收，否则下一次解锁会命中过期锁。若存在新
/// 会话，这些资源归新会话所有，不得在此释放。
fn release_orphan_lock_resources(state: &AppState) {
    crate::service::vault_rotate::reset_on_lock();
    if let Some(guard) = state.lock_verthys_session().take() {
        log::info!("[verthys_lock] 清理无会话归属的 VerthysSessionGuard");
        drop(guard);
    }
    if let Some(lock_guard) = state.lock_verthys_file().take() {
        log::info!("[verthys_lock] 清理无会话归属的 verthys_file_lock");
        drop(lock_guard);
    }
}

/// 销毁 worker 子进程并清理资源（剪贴板、文件锁）。
///
/// 调用前应先执行 verthys_lock_persist 确保持久化完成。
/// 销毁前等待所有进行中的 IO 操作完成（最长 10 秒），超时则强制销毁。
/// 销毁后状态回到 Uninitialized，VerthysSessionGuard Drop 自动释放文件锁。
///
/// 代际校验：等待轮换收敛与 IO 收敛期间会话可能被替换（新解锁）。命令
/// 入口记录代际，实际销毁前用 `clear_session_if_epoch` 原子校验并清空；
/// 代际已变则返回 `SESSION_SUPERSEDED`，绝不把锁定打在**新会话**上。
#[tauri::command]
pub async fn verthys_lock(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    let session_path = state.verthys_session_path();
    let epoch = state.session_epoch();

    /* 轮换 Run 在 worker 内执行时，锁请求只能排队；直接销毁会话会让
     * worker 继续持有 GMK。先请求取消并等待 Run 收敛（有界），超时则
     * 拒绝本次锁定，避免“已锁定但密钥仍驻留”的假象。等待使用阻塞线程，
     * 不占用异步执行器。 */
    tauri::async_runtime::spawn_blocking(|| {
        crate::service::vault_rotate::prepare_for_lock(std::time::Duration::from_secs(30))
    })
    .await
    .map_err(|e| format!("锁定闸门执行失败: {e}"))??;

    let _ = state
        .wait_io_complete(std::time::Duration::from_secs(10))
        .await;

    /* 检查与销毁在写锁内原子完成：若等待期间已有新会话接管，立即放弃，
     * 后续的密钥生命周期重置、剪贴板清理与文件锁释放都不得执行。 */
    if !state.clear_session_if_epoch(epoch) {
        log::warn!("[verthys_lock] 等待期间会话代际已变更，放弃本次锁定");
        /* 代际已变但当前没有任何会话：说明另一路径（如 worker_destroy）
         * 只清了 worker 会话而未释放哨兵锁。此时补全孤儿清理，避免旧
         * VerthysSessionGuard/文件锁泄漏到下一次解锁；若确有新会话存在，
         * 那些资源归新会话所有，绝不在这里释放。 */
        if !state.has_session() {
            release_orphan_lock_resources(&state);
        }
        return Err(crate::state::SESSION_SUPERSEDED.to_string());
    }

    /* 锁库即终止照片任务：本地取消标志为权威信号，worker 已随会话销毁。
     * 残留导入会话必须在这里丢弃，否则下一次解锁后 import_begin 恒
     * E_IMPORT_SESSION_BUSY，且删除级联会误用旧库内存台账。丢弃会话
     * 不执行 end/压缩，磁盘 WAL 保留断点续传状态。 */
    if let Some(job_id) = state.data_plane_job_id() {
        if let Some(flag) = state.data_plane_job_cancel_flag(&job_id) {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    if let Some(session) = state.lock_import_session().take() {
        log::warn!(
            "[verthys_lock] 丢弃锁库前残留导入会话 import_id={}（保留磁盘 WAL）",
            session.import_id
        );
    }
    state.set_bulk_defer(false);

    /* C 层会话销毁会中止轮换作业；宿主侧的取消事件与“可取消”状态
     * 必须同步释放，不能跨会话残留。 */
    crate::service::vault_rotate::reset_on_lock();

    // worker 已随会话销毁，GMK 已消失，重置密钥生命周期为 NoKey
    state.key_lifecycle.reset_to_no_key();

    if !crate::security::clear_clipboard() {
        log::warn!("[verthys_lock] 剪贴板清零失败");
    }

    {
        let mut session_guard = state.lock_verthys_session();
        if session_guard.is_some() {
            log::info!("[verthys_lock] 销毁 VerthysSessionGuard（Drop 自动释放文件锁）");
            *session_guard = None;
        }
    }

    {
        let mut lock_guard = state.lock_verthys_file();
        if lock_guard.is_some() {
            log::info!("[verthys_lock] 清理旧版 verthys_file_lock");
            *lock_guard = None;
        }
    }

    if let Some(ref path) = session_path {
        write_verthys_audit(
            &app,
            AuditEventType::VerthysLock,
            path,
            AuditResult::Success,
            None,
        );
    }

    // 痕迹清理（锁定 / 退出时机的执行路径）：清理系统最近记录中指向
    // 本应用文件的条目。fire-and-forget：专用阻塞线程执行（COM 初始化
    // 在任务内完成），失败仅审计 + 告警，不阻塞锁定响应。
    crate::security::trace_cleanup::run_locked_cleanup_async(app.clone());

    Ok(VerthysResponse::ok("lock"))
}

// ===== 刷新（Verthys_Flush） =====

/// 刷盘：调用 Verthys_Flush 提交未完成事务，保持 worker 会话不中断。
/// 的 add_record 已提交 DataRoot，此函数再次执行幂等保存，确保
/// 目录脏状态/待提交段与元数据一致。失败必须向上传播，不得把
/// “未确认落盘”伪装成成功。
/// 不清零密钥、不改变 worker 状态（始终 UNLOCKED），无 lock+unlock 竞态风险。
#[tauri::command]
pub async fn verthys_flush(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "flush") {
        return Ok(VerthysResponse::err("flush", &msg));
    }

    // 直接发送 {"op":"flush"} → worker call_flush → C Verthys_Flush
    //   - commit 未完成事务（add_record 已 vtxn_commit，通常 no-op）
    //   - 不清零密钥、不改变 state（始终保持 UNLOCKED）
    //   - 不重新加载索引（避免大 verthys 的索引加载超时）
    //   - 单次 IPC，无 lock+unlock 的竞态风险
    //
    //   AddRecord 已即时提交，但 flush 负责再次确认 DataRoot/元数据与
    //   目录脏状态一致；flush op 失败或 IPC 失败时必须返回 err，
    //   让上层区分“已确认落盘”与“未确认落盘”，不得吞错报成功。
    state.begin_io();
    let result = {
        let req = serde_json::json!({"op": "flush"}).to_string();
        match state.send_with_timeout(&req, std::time::Duration::from_secs(15)) {
            Ok(resp_json) => match serde_json::from_str::<VerthysResponse>(&resp_json) {
                Ok(resp) => {
                    if !resp.ok {
                        log::warn!(
                            "[verthys_flush] flush op 返回失败: {:?}",
                            resp.error
                        );
                    }
                    Ok(resp)
                }
                Err(e) => {
                    log::error!("[verthys_flush] flush 响应解析失败: {}", e);
                    Ok(VerthysResponse::err("flush", "flush response parse failed"))
                }
            },
            Err(e) => {
                log::error!("[verthys_flush] flush IPC 失败: {}", e);
                Ok(VerthysResponse::err("flush", "flush ipc failed"))
            }
        }
    };
    state.end_io();
    result
}

// ===== 落盘自查（worker 进程内 C 层持锁句柄） =====

/// 磁盘级落盘校验：由 worker 进程内用 C 层持锁句柄自查盘面结构。
///
/// 为什么不走主进程直接读盘：Windows 字节范围锁为强制锁——容器会话在
/// C 层子进程内以独占方式持有超级块区 [0,64KB)。主进程以
/// `std::fs::File::open` 新开句柄读取该区间恒被 ERROR_LOCK_VIOLATION
/// （os error 33）拒绝，主进程直读必然失败，产生"持久化失败"误报并阻断
/// 解析导入。故校验必须下沉到持有会话句柄的 worker 子进程，
/// 由该进程用 C 层会话持锁句柄完成自查（Verthys_VerifyPersist）。
///
/// 命令名保持不变（前端契约）；结构化字段（status_code/file_size/
/// mtime_ms/header_magic/header_version）随响应同名字段透传，前端据此做
/// 三态判定（OK / 可重试 IO / 结构性失败）。
#[tauri::command]
pub async fn verthys_verify_disk_persist(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：无容器会话时 worker 内无持锁句柄，无从自查
    if let Err(msg) = require_unlocked(&app, &state, "verthys_verify_disk_persist") {
        return Ok(VerthysResponse::err("verthys_verify_disk_persist", &msg));
    }

    state.begin_io();
    let result = (|| {
        let req = serde_json::json!({"op": "verify_persist"}).to_string();
        match state.send_with_timeout(&req, std::time::Duration::from_secs(10)) {
            Ok(resp_json) => {
                // worker 响应含 verify_persist 结构化字段，serde 同名透传
                let resp: VerthysResponse = serde_json::from_str(&resp_json)
                    .map_err(|e| format!("parse verify_persist response: {}", e))?;
                if resp.ok {
                    log::info!(
                        "[verthys_verify_disk_persist] 落盘自查通过: file_size={:?} magic=0x{:08X}",
                        resp.file_size,
                        resp.header_magic.unwrap_or(0)
                    );
                } else {
                    log::warn!(
                        "[verthys_verify_disk_persist] 落盘自查未通过: status_code={:?} detail={:?}",
                        resp.status_code,
                        resp.error
                    );
                }
                Ok(resp)
            }
            Err(e) => {
                log::warn!("[verthys_verify_disk_persist] worker IPC 失败: {}", e);
                Ok(VerthysResponse::err(
                    "verthys_verify_disk_persist",
                    "verification IPC failed",
                ))
            }
        }
    })();
    state.end_io();
    result
}

/// 强制关闭（丢弃）当前活跃的导入会话。
///
/// 语义：异常/中断场景下清理卡住的导入会话，使后续导入可重新 begin。
/// 与 verthys_import_end 的区别：不写 end、不压缩 WAL——会话被直接丢弃，
/// 盘面 WAL 保留，断点续传状态（committed 哈希）在下次 begin 时可恢复。
/// 幂等：无活跃会话时直接返回 ok。
#[tauri::command]
pub async fn verthys_force_close_import_session(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "verthys_force_close_import_session") {
        return Ok(VerthysResponse::err(
            "verthys_force_close_import_session",
            &msg,
        ));
    }

    // 取走并丢弃会话：WalWriter Drop 关闭文件句柄，但不执行 end/压缩，
    // 保留断点续传状态。无会话时 take() 返回 None，幂等。
    let dropped = {
        let mut guard = state.lock_import_session();
        match guard.take() {
            Some(session) => Some(session.import_id.clone()),
            None => None,
        }
    };
    match dropped {
        Some(import_id) => {
            log::warn!(
                "[verthys_force_close_import_session] 强制关闭导入会话 import_id={}（不压缩 WAL，保留续传状态）",
                import_id
            );
        }
        None => {
            log::info!("[verthys_force_close_import_session] 无活跃导入会话，幂等返回");
        }
    }

    Ok(VerthysResponse::ok("verthys_force_close_import_session"))
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::infrastructure::file_lock::VerthysFileLock;
    use crate::state::verthys_session::VerthysSessionGuard;
#[test]
fn orphan_lock_cleanup_releases_session_guard_and_file_lock() {
    let state = AppState::new();
    let path = temp_container_path("orphan_lock_cleanup");
    make_container_fixture(&path).unwrap();
    let guard = VerthysSessionGuard::new(path.to_str().unwrap(), "orphan-lock-test")
        .expect("会话守卫创建失败");
    *state.lock_verthys_session() = Some(guard);
    let file_lock = VerthysFileLock::lock_shared(path.to_str().unwrap())
        .expect("文件锁创建失败");
    *state.lock_verthys_file() = Some(file_lock);

    release_orphan_lock_resources(&state);

    assert!(
        state.lock_verthys_session().is_none(),
        "代际冲突且无会话时必须释放哨兵锁"
    );
    assert!(
        state.lock_verthys_file().is_none(),
        "代际冲突且无会话时必须释放旧文件锁"
    );
    let _ = std::fs::remove_file(&path);
}}
