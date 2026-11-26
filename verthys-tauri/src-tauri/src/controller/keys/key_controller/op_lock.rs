/*
 * 密钥操作互斥
 *
 * 职责边界：密钥操作互斥守卫与忙提示文案。改钥、GMK 派生、验证与清零
 * 共用同一把锁，防止交错执行导致 worker GMK 槽与最新记录不一致。
 */

use crate::state::{AppState, KeyOpGuard};

pub(super) const KEY_OP_BUSY_MESSAGE: &str = "有进行中的密钥操作，请稍候再试";

/// 获取密钥操作互斥守卫；已有操作在飞时返回 None。
///
/// 改钥、GMK 派生、验证与清零共享同一把锁：四者都会读写 worker GMK 槽
/// 与全局密钥记录，交错执行会让槽内密钥与最新记录不一致。
pub(super) fn acquire_key_op<'a>(state: &'a AppState, op: &str) -> Option<KeyOpGuard<'a>> {
    if !state.try_acquire_key_op_lock() {
        log::warn!("[{}] 已有密钥操作在飞，拒绝并发执行", op);
        return None;
    }
    Some(KeyOpGuard { state })
}
