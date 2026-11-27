/*
 * clipboard_guard/state.rs — 统一状态、全局静态、锁与时间辅助
 *
 * 全部状态由单一 Mutex<ClipboardStateData> 保护。
 * 所有状态读取和修改都在获取锁后原子完成，避免瞬时不一致窗口。
 */

use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// 敏感内容自动过期时长（写入后 30 秒自动清空）
pub(super) const SENSITIVE_EXPIRE_SECS: u64 = 30;

/// 剪贴板状态阶段枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClipboardStage {
    /// 空闲：无敏感内容驻留
    Idle,
    /// 本进程正在写入剪贴板（忽略自身写入链产生的通知）
    Writing,
    /// 敏感内容已驻留剪贴板，等待清空触发（过期 / 外部写入 / 显式清空）
    SensitivePresent,
}

/// 统一剪贴板状态（受 CLIPBOARD_STATE Mutex 保护）
pub(super) struct ClipboardStateData {
    /// 当前阶段
    pub(super) stage: ClipboardStage,
    /// 上次记录的剪贴板序列号（基线）
    pub(super) last_seq: u32,
    /// 敏感内容过期时间戳（毫秒，UNIX_EPOCH 起）
    pub(super) expire_at_ms: u64,
    /// 高安全模式：启用时外部写入即触发清空
    pub(super) high_security: bool,
    /// 监听是否运行
    pub(super) monitoring: bool,
}

/// 全局统一剪贴板状态
static CLIPBOARD_STATE: Mutex<ClipboardStateData> = Mutex::new(ClipboardStateData {
    stage: ClipboardStage::Idle,
    last_seq: 0,
    expire_at_ms: 0,
    high_security: false,
    monitoring: false,
});

/// 窗口过程仅设置此标志，消息循环中异步处理
pub(super) static PENDING_UPDATE: AtomicBool = AtomicBool::new(false);

/// 剪贴板写入串行化锁（跨线程互斥访问剪贴板物理 API）
pub(super) static CLIPBOARD_LOCK: Mutex<()> = Mutex::new(());

/// 辅助：安全获取状态锁（处理 poison）
pub(super) fn lock_state() -> std::sync::MutexGuard<'static, ClipboardStateData> {
    CLIPBOARD_STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/* ---------- 辅助：当前毫秒时间戳 ---------- */
pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
