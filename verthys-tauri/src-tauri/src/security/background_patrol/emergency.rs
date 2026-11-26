/*
 * 独立应急响应通道
 *
 * 当连续检测到威胁时，BackgroundPatrol 直接通过 AppState::set_session(None)
 * 强制销毁 Worker，并通过文件锁和共享标志阻止任何新建会话。
 *
 * 前端事件仅作为辅助通知，后端强制措施先于前端执行。
 */

use tauri::{AppHandle, Emitter, Manager};

use crate::security::module_whitelist::UnknownModule;
use crate::state::AppState;
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};

use super::os::{now_secs, sanitize_path};
use super::patrol::PatrolContext;
use super::persistence::derive_hmac_key;
use super::{
    CONSECUTIVE_TRIGGER_THRESHOLD, EMERGENCY_EVENT_NAME, EMERG_CODE_INJECTION_BLOCK,
    EMERG_SIG_UNKNOWN_DLL,
};

/// 应急事件载荷（序列化发送给前端）
#[derive(serde::Serialize, Clone)]
struct EmergencyPayload {
    /// 应急信号位掩码（EMERG_SIG_UNKNOWN_DLL = 0x0010）
    signal: u32,
    /// 信号语义名称
    signal_name: &'static str,
    /// 匿名故障类型码（0xE0002 = 注入阻断）
    fault_code: u32,
    /// 触发模块完整路径
    module_path: String,
    /// 触发模块文件名
    module_name: String,
    /// 连续检测次数（达到阈值）
    consecutive_count: u32,
    /// 触发时间戳（UNIX 秒）
    timestamp_secs: u64,
    /// 安装目录（巡检白名单基准）
    install_dir: String,
    /// 已执行巡检总次数
    patrol_count: u64,
    /// 是否已执行后端强制熔断（set_session(None)）
    backend_circuit_breaker_executed: bool,
}

pub(super) fn trigger_emergency_signal(ctx: &PatrolContext, module: &UnknownModule) {
    let (patrol_count, install_dir) = match ctx.state.lock() {
        Ok(st) => (st.patrol_count, st.install_dir.clone()),
        Err(_) => (0u64, String::new()),
    };

    log::error!(
        "[background_patrol][应急] DLL 注入/劫持检测！模块 {} 路径={} 在连续 {} 次巡检中出现，\
         触发应急信号 EMERG_SIG_UNKNOWN_DLL(0x{:04X}) 故障码 0x{:05X}（巡检 #{}）",
        module.name,
        sanitize_path(&module.path),
        CONSECUTIVE_TRIGGER_THRESHOLD,
        EMERG_SIG_UNKNOWN_DLL,
        EMERG_CODE_INJECTION_BLOCK,
        patrol_count
    );

    // 写入审计日志（威胁检测）
    write_patrol_audit(
        &ctx.app,
        AuditEventType::PatrolThreat,
        AuditResult::Failure,
        Some(format!(
            "DLL 注入检测: 模块={} 连续 {} 次 (信号=0x{:04X} 故障码=0x{:05X} 巡检=#{})",
            module.name,
            CONSECUTIVE_TRIGGER_THRESHOLD,
            EMERG_SIG_UNKNOWN_DLL,
            EMERG_CODE_INJECTION_BLOCK,
            patrol_count
        )),
    );

    // 后端独立应急响应（先于前端执行）
    let circuit_breaker_executed =
        execute_backend_circuit_breaker(&ctx.app, &format!("dll_injection:{}", module.name));

    // 写入审计日志（应急熔断执行）
    write_patrol_audit(
        &ctx.app,
        AuditEventType::PatrolEmergency,
        if circuit_breaker_executed {
            AuditResult::Success
        } else {
            AuditResult::Failure
        },
        Some(format!(
            "后端强制熔断: 销毁 Worker 会话 (结果={})",
            if circuit_breaker_executed {
                "成功"
            } else {
                "失败"
            }
        )),
    );

    let payload = EmergencyPayload {
        signal: EMERG_SIG_UNKNOWN_DLL,
        signal_name: "DLL_HIJACK_INJECTION",
        fault_code: EMERG_CODE_INJECTION_BLOCK,
        module_path: module.path.clone(),
        module_name: module.name.clone(),
        consecutive_count: CONSECUTIVE_TRIGGER_THRESHOLD,
        timestamp_secs: now_secs(),
        install_dir,
        patrol_count,
        backend_circuit_breaker_executed: circuit_breaker_executed,
    };

    // 发送 Tauri 事件：前端辅助通知（熔断已由后端执行）
    if let Err(e) = ctx.app.emit(EMERGENCY_EVENT_NAME, payload) {
        log::error!(
            "[background_patrol][应急] 发送应急事件失败（前端未收到辅助通知）: {}",
            e
        );
    }
}

/// 执行后端强制熔断
///
/// 直接通过 AppState::set_session(None) 销毁 Worker 会话。
/// 子进程退出即销毁所有密钥与句柄。
///
/// 返回 true 表示熔断已执行，false 表示执行失败（如 AppState 未注册）。
pub(super) fn execute_backend_circuit_breaker(app: &AppHandle, reason: &str) -> bool {
    log::error!(
        "[background_patrol][应急] 执行后端强制熔断：销毁 Worker 会话 (reason={})",
        reason
    );

    match app.try_state::<AppState>() {
        Some(state) => {
            // 直接销毁 Worker 会话（Drop 自动 kill 子进程，销毁所有密钥与句柄）
            state.set_session(None);
            log::error!(
                "[background_patrol][应急] Worker 会话已强制销毁 (reason={})",
                reason
            );
            true
        }
        None => {
            log::error!("[background_patrol][应急] 无法获取 AppState，强制熔断失败（状态未注册）");
            false
        }
    }
}

/* ====================================================================== *
 *  审计日志辅助                                                            *
 * ====================================================================== */

/// 写入巡检审计事件（不阻塞巡检流程）
pub(super) fn write_patrol_audit(
    app: &AppHandle,
    event_type: AuditEventType,
    result: AuditResult,
    detail: Option<String>,
) {
    let log_path = match app.path().app_config_dir() {
        Ok(dir) => dir.join("audit.log"),
        Err(e) => {
            log::warn!("[background_patrol] 获取配置目录失败，跳过审计写入: {}", e);
            return;
        }
    };

    let hmac_key = match derive_hmac_key() {
        Some(k) => k,
        None => return,
    };

    let session_id = format!("pid-{}", std::process::id());
    let mut event = AuditEvent::new(event_type, &session_id, "background_patrol", result);

    if let Some(d) = detail {
        event = event.with_detail(d);
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[background_patrol] 写入审计事件失败（不阻塞巡检）: {}", e);
    }
}
