/*
 * 安全防护状态报告
 *
 * 职责边界：动态防护与内核防护状态的结构化报告，字段与 worker 协议一一对应。
 */

use serde::{Deserialize, Serialize};
// ===== VerthysResponse（遗留兼容结构）=====
//
// ApiResponse<T> 泛型信封 + 操作特化响应类型已定义在 api_error.rs。
// 新代码禁止使用 VerthysResponse，应使用 ApiResponse<T> 或结构化响应类型；
// 现有控制器仍有使用，迁移完成前保留本结构。

/* 防御闭环状态报告（主进程侧镜像）
 * 与 worker protocol.rs SecurityStatusReport 字段一一对应（serde 名称对齐）；
 * path_state 下标 = VerthysDefensePath（verthys.h）：
 *   0=挂起绕过 1=内存转储 2=休眠取证 3=IAT/Inline Hook
 *   4=DLL 劫持 5=进程读取 6=跨设备迁移
 * 值域 = VerthysDefenseState：0=未校验 1=已阻断 2=降级 3=失败
 * path_reason 值域 = VerthysDefenseReason（0x0014 追加）。 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatusReport {
    pub path_state: [u32; 7],
    pub blocked_count: u32,
    pub degraded_count: u32,
    pub failed_count: u32,
    pub all_critical_blocked: bool,
    pub has_degraded: bool,
    pub path_reason: [u32; 7],
    pub limited_count: u32,
    pub policy_flags: u32,
    pub checked_at_unix_ms: u64,
    #[serde(default)]
    pub kernel_status: Option<KernelStatusReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelStatusReport {
    pub state: u32,
    pub reason: u32,
    pub capabilities: u32,
    pub protocol_major: u16,
    pub protocol_minor: u16,
}


