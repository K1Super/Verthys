/*
 * 数据域会话闸门与审计写入
 *
 * 职责边界：容器会话是否存在是数据域命令的唯一准入判据；拒绝时写审计并
 * 返回稳定的 KeyStateMismatch 错误码。审计写入失败仅告警，不阻塞业务。
 */
use crate::controller::api_error::ErrorCode;
use crate::infrastructure::audit::get_audit_hmac_key;
use crate::state::AppState;
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};
// ===== 审计日志辅助 =====

/// 获取审计日志文件路径，存放于应用配置目录下。
/// 若路径解析失败，返回 None，调用方应跳过审计写入。
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

/// 写入 verthys 相关审计事件，路径哈希化存储，不记录明文。
/// 写入失败仅警告，不阻塞业务流程。
pub(crate) fn write_verthys_audit(
    app: &tauri::AppHandle,
    event_type: AuditEventType,
    verthys_path: &str,
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

    let mut event =
        AuditEvent::new(event_type, &session_id, "user", result).with_resource(verthys_path);

    if let Some(d) = detail {
        event = event.with_detail(d);
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[audit] 写入审计事件失败（不阻塞业务）: {}", e);
    }
}

/// 数据域统一容器会话闸门
///
/// 记录数据读写命令必须先经本闸门：容器会话未建立（未解锁或已锁定）
/// 时写入审计 Denied 事件并返回错误文案，命令入口据此直接拒绝而不
/// 触碰 worker。拒绝以 KeyStateMismatch 错误码呈现，与 C 层 LOCKED
/// 同域可区分。
///
/// 判定依据是容器会话（VerthysSessionGuard 存在），而非全局密钥生命
/// 周期状态：记录数据由容器密钥加密保护，解锁容器即获得读写权；模块
/// 密钥等应用层密钥与 GMK 验证状态无关，GMK 授权由密钥命令自身裁决。
pub(crate) fn require_unlocked(
    app: &tauri::AppHandle,
    state: &AppState,
    cmd: &str,
) -> Result<(), String> {
    if state_allows_data_access(state) {
        return Ok(());
    }
    let current = state.key_lifecycle.current_state();
    log::warn!("[gate] {} 被容器会话闸门拒绝（生命周期 {}）", cmd, current);
    write_verthys_audit(
        app,
        AuditEventType::SecurityCommand,
        cmd,
        AuditResult::Denied,
        Some(format!(
            "容器会话未建立，拒绝数据域访问（生命周期 {}）",
            current
        )),
    );
    Err(ErrorCode::KeyStateMismatch.default_message().to_string())
}

/// 数据域访问状态判定（纯函数）：仅容器会话存在（已解锁未锁定）时
/// 允许记录数据读写。与闸门拆分以便无 AppHandle 环境下直接测试状态
/// 策略。
fn state_allows_data_access(state: &AppState) -> bool {
    state.has_verthys_session()
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::state::verthys_session::VerthysSessionGuard;
#[test]
fn data_access_gate_follows_container_session() {
    let state = AppState::new();
    // 无容器会话（未解锁）：拒绝
    assert!(!state_allows_data_access(&state));

    // 建立容器会话：放行（生命周期保持 NoKey —— 数据域仅依赖
    // 容器解锁，不依赖全局密钥验证状态）
    let path = temp_container_path("gate_session");
    make_container_fixture(&path).unwrap();
    let guard = VerthysSessionGuard::new(path.to_str().unwrap(), "gate-session-test")
        .expect("会话守卫创建失败");
    *state.lock_verthys_session() = Some(guard);
    assert!(state_allows_data_access(&state));

    // 会话销毁（锁定）：拒绝
    *state.lock_verthys_session() = None;
    assert!(!state_allows_data_access(&state));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn data_access_gate_message_is_key_state_mismatch() {
    // 闸门错误文案使用 KeyStateMismatch 的默认消息（文案稳定契约）
    let msg = ErrorCode::KeyStateMismatch.default_message();
    assert_eq!(msg, "密钥状态不匹配");
}}
