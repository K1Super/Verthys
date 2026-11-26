/*
 * 命令：清零、状态协调与强制复位
 *
 * 职责边界：worker GMK 内存清零、用前端校验结果协调密钥存在状态、
 * 失败补偿链的幂等强制复位。均不涉及密钥材料导出。
 */

use super::op_lock::{acquire_key_op, KEY_OP_BUSY_MESSAGE};
use super::validation::write_key_audit;
use super::CLEAR_TIMEOUT;
use crate::controller::types::VerthysResponse;
use crate::state::{AppState, KeyLifecycleState};
use crate::util::audit_log::{AuditEventType, AuditResult};
use tauri::State;

// ===== 命令：清零 GMK =====

/// 清零 worker 内存中的 GMK（锁定所有操作）
///
/// 状态转移：Unlocked → Locked（幂等，任何状态均可调用）。
/// 轻量操作，超时 2 秒。
#[tauri::command]
pub async fn verthys_clear_global_key(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    log::info!("[verthys_clear_global_key] 清零 worker 内存中的 GMK");

    /* 与改钥/派生/验证互斥：清零与改钥交错会清掉刚换入的新 GMK 槽。 */
    let Some(_key_op_guard) = acquire_key_op(state.inner(), "clear_global_key") else {
        return Ok(VerthysResponse::err("clear_global_key", KEY_OP_BUSY_MESSAGE));
    };

    let req = serde_json::json!({
        "op": "clear_global_key",
    });

    let resp_json = state
        .send_with_timeout(&req.to_string(), CLEAR_TIMEOUT)
        .map_err(|e| {
            log::error!("[verthys_clear_global_key] send 失败: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyClear,
                AuditResult::Failure,
                Some(format!("worker 通信失败: {}", e)),
            );
            "清零密钥失败".to_string()
        })?;

    let resp: VerthysResponse = serde_json::from_str(&resp_json).map_err(|e| {
        log::error!(
            "[verthys_clear_global_key] 解析响应失败: {} | raw={}",
            e,
            crate::util::log_sanitizer::json_log_summary(&resp_json, &["op"])
        );
        write_key_audit(
            &app,
            AuditEventType::KeyClear,
            AuditResult::Failure,
            Some(format!("响应解析失败: {}", e)),
        );
        "清零密钥失败".to_string()
    })?;

    if resp.ok {
        state.key_lifecycle.transition_to_locked_from_unlocked();
        log::info!("[verthys_clear_global_key] GMK 已清零，状态已转移为 Locked");
        write_key_audit(&app, AuditEventType::KeyClear, AuditResult::Success, None);
    } else {
        log::warn!("[verthys_clear_global_key] GMK 清零失败: {:?}", resp.error);
        write_key_audit(
            &app,
            AuditEventType::KeyClear,
            AuditResult::Failure,
            resp.error.clone(),
        );
    }

    Ok(resp)
}

// ===== 命令：协调密钥存在状态（reconciliation） =====

/// 协调全局密钥存在状态（用前端重新校验的结果修正后端状态机）
///
/// 场景：
///   verthys_unlock 时 worker 进程内 probe 通过 find_first_lid_by_type(0x10)
///   搜索全局密钥记录。但 TYPE_GLOBAL_KEY(0x10) 与旧 TYPE_ACCOUNT(0x10) 冲突，
///   probe 可能命中账户记录 → has_global_key 误判 → key_lifecycle 状态错误。
///
///   前端 migrateRecordTypes 将旧账户记录重写为 0x02 后重新校验（findGlobalKeyRecord），
///   得到正确结果。本命令接收前端重新校验的正确结果，修正后端 key_lifecycle 状态机。
///
/// 调用时机：
///   initUnlock 关键路径中，migrateRecordTypes + 重新校验完成之后、verthysReady=true 之前。
///
/// 安全边界：
///   - 不涉及密钥材料，不接触 worker，仅修正状态机
///   - 仅在 NoKey ↔ Locked 之间安全转换（Unlocked → NoKey 仅异常路径）
///   - 幂等：状态已匹配时无操作
///   - 不记录审计日志（非敏感操作，状态修正非用户意图）
#[tauri::command]
pub async fn verthys_reconcile_key_presence(
    state: State<'_, AppState>,
    has_global_key: bool,
) -> Result<VerthysResponse, String> {
    let prev = state.key_lifecycle.current_state();
    /* 降级保护：Unlocked 表示 worker 内存已持有可用 GMK。允许此状态下把
     * 生命周期改成 NoKey，会让后续 derive 通过 NoKey 校验并覆盖既有 GMK
     * 记录（无需旧口令）。该转换只允许在锁定/未验证状态下发生。 */
    if !has_global_key && prev == KeyLifecycleState::Unlocked {
        log::warn!("[verthys_reconcile_key_presence] 拒绝在 Unlocked 状态降级为 NoKey");
        return Ok(VerthysResponse::err(
            "reconcile_key_presence",
            "解锁会话中禁止降级全局密钥状态",
        ));
    }
    state.key_lifecycle.reconcile_key_presence(has_global_key);
    let curr = state.key_lifecycle.current_state();
    log::info!(
        "[verthys_reconcile_key_presence] has_global_key={} | 状态修正: {} → {}",
        has_global_key,
        prev,
        curr
    );
    Ok(VerthysResponse::ok("reconcile_key_presence"))
}

// ===== 命令：幂等强制复位全局密钥状态 =====

/// 失败补偿链最终兜底：GMK 清零（best-effort，worker 不可用不阻断）
/// + 状态机任何状态强制回 NoKey。前端在 clear/reconcile 补偿动作
/// 连续失败后调用，保证不残留中间态死锁；任何状态下调用均幂等。
#[tauri::command]
pub async fn verthys_reset_global_key_state(
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    /* 与 derive / verify / clear 共用同一把密钥操作锁：复位流程包含
     * clear_global_key 转发，若与派生并发，状态机与 worker GMK 槽可能
     * 分别落在不同代际。 */
    let Some(_key_op_guard) = acquire_key_op(state.inner(), "reset_global_key_state") else {
        return Ok(VerthysResponse::err(
            "reset_global_key_state",
            KEY_OP_BUSY_MESSAGE,
        ));
    };
    /* 强制复位同样受降级保护：Unlocked 下复位为 NoKey 会打开
     * derive（无需旧 GMK 校验）覆盖既有密钥记录的路径。 */
    if state.key_lifecycle.current_state() == KeyLifecycleState::Unlocked {
        log::warn!("[verthys_reset_global_key_state] 拒绝在 Unlocked 状态强制复位");
        return Ok(VerthysResponse::err(
            "reset_global_key_state",
            "解锁会话中禁止复位全局密钥状态",
        ));
    }
    // GMK 清零 best-effort：worker 通信失败也不影响状态复位
    let _ = state.send_with_timeout(
        &serde_json::json!({ "op": "clear_global_key" }).to_string(),
        CLEAR_TIMEOUT,
    );
    let prev = state.key_lifecycle.current_state();
    state.key_lifecycle.force_reset_no_key();
    log::info!(
        "[verthys_reset_global_key_state] 强制复位: {} → {}",
        prev,
        state.key_lifecycle.current_state()
    );
    Ok(VerthysResponse::ok("reset_global_key_state"))
}
