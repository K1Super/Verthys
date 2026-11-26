/*
 * 初始化状态与设备绑定状态
 *
 * 职责边界：启动初始化三态、设备绑定状态与绑定结果枚举。
 */

use serde::{Deserialize, Serialize};
use ts_rs::TS;
// ===== InitStatus / DeviceBindingStatus 枚举 =====

/// 加密库初始化状态枚举
///
/// 替代字符串状态（"none"/"ready"/"broken"），提供类型安全。
/// 前端通过枚举变体进行差异化处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "bindings/")]
pub enum InitStatus {
    /// 未初始化（全新用户，无 .verthys 文件）
    #[default]
    None,
    /// 初始化中（worker 正在创建/派生密钥）
    Initializing,
    /// 就绪（.verthys 存在且 magic 合法，可解锁）
    Ready,
    /// 损坏（.verthys magic 不合法 / 状态文件损坏）
    Broken,
    /// 维护中（迁移中 / 修复中 / 恢复模式）
    Maintenance,
}

impl InitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            InitStatus::None => "none",
            InitStatus::Initializing => "initializing",
            InitStatus::Ready => "ready",
            InitStatus::Broken => "broken",
            InitStatus::Maintenance => "maintenance",
        }
    }
}

/// 设备绑定状态枚举
///
/// 替代字符串状态，提供类型安全的设备绑定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "bindings/")]
pub enum DeviceBindingStatus {
    /// 完全匹配
    Match,
    /// 不匹配（设备指纹变更）
    Mismatch,
    /// 未绑定（首次运行）
    Unbound,
    /// 部分匹配（部分硬件变更，触发有限恢复模式）
    PartialMatch,
    /// 查询错误
    Error,
}

impl DeviceBindingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceBindingStatus::Match => "match",
            DeviceBindingStatus::Mismatch => "mismatch",
            DeviceBindingStatus::Unbound => "unbound",
            DeviceBindingStatus::PartialMatch => "partial_match",
            DeviceBindingStatus::Error => "error",
        }
    }
}

/// 设备绑定校验结果（结构化返回）
///
/// 替代魔术字符串，提供类型安全的设备绑定结果。
/// status 为状态枚举，detail 为用户可读描述，error_code 供前端差异化处理。
#[derive(Debug, Clone, serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct DeviceBindingResult {
    /// 绑定状态枚举（match/mismatch/unbound/partial_match/error）
    pub status: DeviceBindingStatus,
    /// 用户可读描述（不含敏感信息）
    pub detail: String,
    /// 错误码（status=error 时有值）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// 匹配度百分比（0-100，status=match/partial_match 时有值）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_score: Option<u32>,
}
