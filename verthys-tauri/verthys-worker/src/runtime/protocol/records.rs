/* records.rs — 记录、回退锚点与状态报告
 *
 * 职责：RecordEntry（含 Drop 清零）/ AnchorEntry / SecurityStatusReport / KernelStatusReport。
 */

use serde::Serialize;
use zeroize::Zeroize;

/// 批量枚举返回的单条记录（用于 enumerate_records / scan_fetch 操作）
#[derive(Serialize)]
pub(crate) struct RecordEntry {
    pub(crate) id: u64,
    pub(crate) rtype: u32,
    pub(crate) name: String,
    pub(crate) data: String, // base64
}

impl Drop for RecordEntry {
    /* 记录名与 base64 数据都属于敏感明文派生，Drop 时清零堆缓冲，
     * 避免批量枚举响应在序列化完成后把明文留在分配器中。 */
    fn drop(&mut self) {
        self.name.zeroize();
        self.data.zeroize();
    }
}

/// 回退锚点条目（仅 rollback_anchor_list 返回）。
/// 只含公开定位信息与见证状态，不含指纹、路径或任何密钥材料。
#[derive(Serialize)]
pub(crate) struct AnchorEntry {
    pub(crate) uuid: String,
    pub(crate) generation: u64,
    /// unknown / active / dead / tampered
    ///
    /// active 只表示 TPM 见证密钥存在且指纹匹配，不代表容器文件仍然存在
    pub(crate) witness: String,
}

/// 批量释放的单条结果（仅 rollback_anchor_release_batch 返回）。
#[derive(Serialize)]
pub(crate) struct AnchorReleaseOutcome {
    pub(crate) uuid: String,
    /// true=本次删除条目；false=条目不存在（仍幂等清理见证）
    pub(crate) released: bool,
    /// true=该 UUID 的见证键删除失败
    pub(crate) cleanup_failed: bool,
}

/* 防御闭环状态报告（与 verthys.h
 * VerthysSecurityStatus 字段一一对应；path_state 下标 = VerthysDefensePath，
 * 值域 = VerthysDefenseState：0=未校验 1=已阻断 2=降级 3=失败）。
 * 0x0014 追加 path_reason/limited_count/policy_flags/checked_at_unix_ms。 */
#[derive(Serialize)]
pub(crate) struct SecurityStatusReport {
    /// 逐路径防御状态（7 项：挂起绕过/内存转储/休眠取证/Hook/DLL劫持/进程读取/跨设备）
    pub(crate) path_state: [u32; 7],
    pub(crate) blocked_count: u32,
    pub(crate) degraded_count: u32,
    pub(crate) failed_count: u32,
    pub(crate) all_critical_blocked: bool,
    pub(crate) has_degraded: bool,
    /// 逐路径判定原因码（VerthysDefenseReason）
    pub(crate) path_reason: [u32; 7],
    /// 架构限制导致的降级路径数
    pub(crate) limited_count: u32,
    /// 运行时守卫与策略位（bit0=心跳 bit1=挂起守卫 bit2=防转储巡检）
    pub(crate) policy_flags: u32,
    /// 快照采样时间（Unix 毫秒）
    pub(crate) checked_at_unix_ms: u64,
    /// 内核加固状态（可选；旧核心或查询失败时为 None）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kernel_status: Option<KernelStatusReport>,
}

#[derive(Serialize)]
pub(crate) struct KernelStatusReport {
    pub(crate) state: u32,
    pub(crate) reason: u32,
    pub(crate) capabilities: u32,
    pub(crate) protocol_major: u16,
    pub(crate) protocol_minor: u16,
}
