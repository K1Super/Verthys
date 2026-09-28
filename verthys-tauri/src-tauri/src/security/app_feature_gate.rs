/*
 * security/app_feature_gate.rs — 应用侧档位门控（单一写入点，多消费方只读）
 *
 * 职责：
 *   保存最近一次由预设应用/回读路径确认的跨层特性位（与 C 运行时策略层
 *   的投影契约逐位对齐），供应用侧能力的执行方（模块巡检 / 完整性核验 /
 *   痕迹清理 / USB 克隆检测）在运行期判断当前档位是否启用对应能力。
 *
 * 权威关系：C 运行时策略层是唯一权威；本模块是其投影在应用侧的只读镜像。
 * 写入方：仅预设应用/回读路径（security_commands 侧）。消费方只读。
 *
 * 未知状态语义：尚未应用任何预设时按保守值（全部能力开启）处理——
 * 任何异常路径都朝"防护更严"方向失败，禁止朝"防护全关"失败。
 *
 * 线程安全：单一 AtomicU32 读写，无锁；位序为跨层契约，禁止重排。
 */
use std::sync::atomic::{AtomicU32, Ordering};

/* 特性位（与 C 侧 SEC_FEAT_* 逐位对齐，禁止重排） */
pub(crate) const FEAT_ANTI_DEBUG: u32 = 1 << 0;
pub(crate) const FEAT_ANTI_INJECT: u32 = 1 << 1;
pub(crate) const FEAT_INTEGRITY_CHECK: u32 = 1 << 2;
pub(crate) const FEAT_MEMORY_GUARD: u32 = 1 << 3;
pub(crate) const FEAT_KEY_SEPARATION: u32 = 1 << 4;
pub(crate) const FEAT_EMERGENCY_RESPONSE: u32 = 1 << 5;
pub(crate) const FEAT_SESSION_LOCK_IDLE: u32 = 1 << 6;
pub(crate) const FEAT_MODULE_PATROL: u32 = 1 << 7;
pub(crate) const FEAT_CLIPBOARD_GUARD: u32 = 1 << 8;
pub(crate) const FEAT_USB_CLONE_DETECT: u32 = 1 << 9;
pub(crate) const FEAT_TRACE_CLEANUP: u32 = 1 << 10;

/// 有效位掩码（11 位）
pub(crate) const FEAT_VALID_MASK: u32 = 0x7FF;

/// 保守基线：全能力开启（未知状态/初始化完成前的默认值）
pub(crate) const FEAT_CONSERVATIVE: u32 = FEAT_VALID_MASK;

static APP_FEATURES: AtomicU32 = AtomicU32::new(FEAT_CONSERVATIVE);

/// 写入应用侧特性位（仅预设应用/回读路径调用；非法位被掩码清除）
pub(crate) fn store(bits: u32) {
    APP_FEATURES.store(bits & FEAT_VALID_MASK, Ordering::SeqCst);
}

/// 查询当前应用侧特性位（消费方只读）
pub(crate) fn snapshot() -> u32 {
    APP_FEATURES.load(Ordering::SeqCst)
}

/// 查询指定能力位是否启用
pub(crate) fn enabled(bit: u32) -> bool {
    snapshot() & bit != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_conservative_all_enabled() {
        // 未应用预设时保守全开（任何能力门控都朝防护更严方向失败）
        assert_eq!(snapshot(), FEAT_CONSERVATIVE);
        assert!(enabled(FEAT_MODULE_PATROL));
        assert!(enabled(FEAT_INTEGRITY_CHECK));
        assert!(enabled(FEAT_TRACE_CLEANUP));
    }

    #[test]
    fn test_store_masks_invalid_bits() {
        store(0xFFFF_FFFF);
        assert_eq!(snapshot(), FEAT_VALID_MASK);
        store(0);
        assert!(!enabled(FEAT_MODULE_PATROL));
        assert!(!enabled(FEAT_TRACE_CLEANUP));
        // 复位保守值，避免影响其他用例
        store(FEAT_CONSERVATIVE);
    }
}