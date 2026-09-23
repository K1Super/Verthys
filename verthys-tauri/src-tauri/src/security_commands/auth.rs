/*
 * auth.rs — 敏感安全命令的会话授权检查
 *
 * 职责：
 *   为敏感安全命令提供统一的会话授权判定：仅当容器已解锁且存在
 *   主密钥记录（密钥生命周期为 Locked 或 Unlocked）时放行，
 *   NoKey 拒绝。授权信号取自后端密钥生命周期状态机，前端无法伪造。
 */

use crate::state::{AppState, KeyLifecycleState};

/// 检查当前会话是否具备敏感操作的授权。
///
/// 放行条件：密钥生命周期为 Locked 或 Unlocked——这两种状态只在
/// 容器解锁完成且确认存在主密钥记录后出现，等价于本次会话已通过
/// 至少一次秘密证明（全局密钥验证或首次初始化）。
/// NoKey（容器未解锁或无主密钥记录）拒绝。
///
/// Err 为拒绝文案，由调用方写入审计后返回给前端。
pub(super) fn require_session_authorized(app_state: &AppState) -> Result<(), String> {
    match app_state.key_lifecycle.current_state() {
        KeyLifecycleState::Locked | KeyLifecycleState::Unlocked => Ok(()),
        KeyLifecycleState::NoKey => {
            Err("会话未授权：容器未解锁或未设置全局密钥".to_string())
        }
    }
}