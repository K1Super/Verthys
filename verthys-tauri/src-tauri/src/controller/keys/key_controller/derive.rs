/*
 * 命令：派生并持久化 GMK
 *
 * 职责边界：首次初始化时的 GMK 派生命令编排——互斥、前置检查、
 * worker 请求发送与响应审计。
 */

use super::op_lock::{acquire_key_op, KEY_OP_BUSY_MESSAGE};
use super::requests::{precheck_derive_request, DerivePrecheckCtx};
use super::validation::write_key_audit;
use super::DERIVE_VERIFY_TIMEOUT;
use crate::controller::types::VerthysResponse;
use crate::state::{AppState, KeyLifecycleState};
use crate::util::audit_log::{AuditEventType, AuditResult};
use tauri::State;
use zeroize::Zeroizing;

// ===== 命令：派生并持久化 GMK =====

/// 派生并持久化全局密钥（首次初始化专用，敏感操作下沉）。
///
/// worker 进程内原子完成「派生 → 收敛残留 → 写入 → 读回逐字节验证」，
/// 响应内联返回记录 lid 与 recordB64。存储不经 add_record 命令——
/// 派生、落盘与逐字节读回验证在同一 worker 调用内原子完成，不产生
/// 派生存放跨两次 IPC 的中间态窗口。
/// 仅 NoKey 状态允许（Unlocked 时的密钥更换走 derive + add_record）。
#[tauri::command]
pub async fn verthys_derive_and_store_global_key(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    password: String,
    bin_data_b64: String,
    bin_password: String,
) -> Result<VerthysResponse, String> {
    let password = Zeroizing::new(password);
    let bin_data_b64 = Zeroizing::new(bin_data_b64);
    let bin_password = Zeroizing::new(bin_password);
    log::info!("[verthys_derive_and_store_global_key] 开始派生并持久化 GMK");

    /* 与改钥/验证/清零互斥：派生会写记录并换 GMK 槽，交错执行会覆盖
     * 另一操作刚刚确认的密钥。 */
    let Some(_key_op_guard) = acquire_key_op(state.inner(), "derive_and_store_global_key") else {
        return Ok(VerthysResponse::err(
            "derive_and_store_global_key",
            KEY_OP_BUSY_MESSAGE,
        ));
    };

    let req_str = match precheck_derive_request(DerivePrecheckCtx {
        app: &app,
        state: &state,
        op: "derive_and_store_global_key",
        allowed_states: &[KeyLifecycleState::NoKey],
        password: &password,
        bin_data_b64: &bin_data_b64,
        bin_password: &bin_password,
    }) {
        Ok(r) => r,
        Err(msg) => return Ok(VerthysResponse::err("derive_and_store_global_key", &msg)),
    };

    let resp_json = state
        .send_with_timeout(req_str.as_str(), DERIVE_VERIFY_TIMEOUT)
        .map_err(|e| {
            log::error!("[verthys_derive_and_store_global_key] send 失败: {}", e);
            write_key_audit(
                &app,
                AuditEventType::KeyDerive,
                AuditResult::Failure,
                Some(format!("worker 通信失败: {}", e)),
            );
            "派生密钥失败".to_string()
        })?;

    // 发送完成：序列化副本与全部敏感原件在此统一销毁（Zeroizing 擦除堆缓冲）
    drop(req_str);
    drop(bin_password);
    drop(bin_data_b64);
    drop(password);

    let resp: VerthysResponse = serde_json::from_str(&resp_json).map_err(|e| {
        log::error!(
            "[verthys_derive_and_store_global_key] 解析响应失败: {} | raw={}",
            e,
            crate::util::log_sanitizer::json_log_summary(&resp_json, &["op"])
        );
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Failure,
            Some(format!("响应解析失败: {}", e)),
        );
        "派生密钥失败".to_string()
    })?;

    if resp.ok {
        log::info!(
            "[verthys_derive_and_store_global_key] GMK 派生并持久化成功（lid={:?}，读回已验证）",
            resp.id
        );
        write_key_audit(&app, AuditEventType::KeyDerive, AuditResult::Success, None);
    } else {
        log::warn!(
            "[verthys_derive_and_store_global_key] GMK 派生持久化失败: {:?}",
            resp.error
        );
        write_key_audit(
            &app,
            AuditEventType::KeyDerive,
            AuditResult::Failure,
            resp.error.clone(),
        );
    }

    Ok(resp)
}
