/*
 * 防护面结构化响应
 *
 * 职责边界：剪贴板清理与隐私模式的命令响应契约（错误码 + 可选凭证）。
 */

use ts_rs::TS;
// ===== 剪贴板结构化响应 =====

/// 剪贴板清空结果（结构化返回）
///
/// 替代恒成功返回，提供类型安全的剪贴板操作结果。
/// error_code 供前端差异化处理（CLIPBOARD_LOCKED / RATE_LIMITED / CLIPBOARD_MONITOR_FAILED）。
#[derive(Debug, Clone, serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct ClipboardResult {
    /// 操作是否成功（true=剪贴板已安全擦除）
    pub ok: bool,
    /// 用户可读描述（不含敏感信息）
    pub detail: String,
    /// 标准化错误码
    ///
    /// 取值：
    ///   - CLIPBOARD_LOCKED：剪贴板被占用，重试后仍失败
    ///   - RATE_LIMITED：频率超限（>10次/分钟）
    ///   - CLIPBOARD_MONITOR_FAILED：监听启动失败
    ///   - TEMPORARY_FAILURE：临时性故障
    ///   - INTERNAL：内部错误
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

impl ClipboardResult {
    pub fn success() -> Self {
        ClipboardResult {
            ok: true,
            detail: "剪贴板已安全擦除".into(),
            error_code: None,
        }
    }

    pub fn error(code: &str, detail: impl Into<String>) -> Self {
        ClipboardResult {
            ok: false,
            detail: detail.into(),
            error_code: Some(code.into()),
        }
    }
}

/// 防截屏保护设置结果（结构化返回）
///
/// 窗口捕获排除为整体成功或整体失败，不存在部分保护：
/// partial_protection 字段保留以维持结构稳定，其值恒为假。
#[derive(Debug, Clone, serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct PrivacyModeResult {
    /// 操作是否成功（true=保护已按预期切换）
    pub ok: bool,
    /// 保护当前状态（true=已启用，false=已关闭）
    pub enabled: bool,
    /// 恒为假：保护不存在"部分成功"，保留字段仅为契约稳定
    pub partial_protection: bool,
    /// 用户可读描述（不含敏感信息）
    pub detail: String,
    /// 标准化错误码
    ///
    /// 取值：
    ///   - PRIVACY_BUSY：已有过渡进行中
    ///   - PRIVACY_QUARANTINED：处于隔离状态，需先对账修复
    ///   - PRIVACY_NO_TARGET_WINDOW：未找到可保护窗口
    ///   - PRIVACY_VERIFY_MISMATCH：设置后回读值不符
    ///   - PRIVACY_ROLLED_BACK：失败并已还原，可重试
    ///   - PRIVACY_TOKEN_MISSING：关闭未提供凭证
    ///   - PRIVACY_TOKEN_INVALID：凭证不匹配
    ///   - PRIVACY_LEASE_HELD：已有未决关闭操作
    ///   - PRIVACY_LEASE_EXPIRED：凭证世代已变更
    ///   - PRIVACY_NOT_RESTORED / PRIVACY_ALREADY_ADOPTED：采纳状态不符
    ///   - PRIVACY_TOKEN_INVARIANT_VIOLATION：槽位不变式被破坏
    ///   - PRIVACY_TRANSITION_SUPERSEDED：过渡被新的状态变更取代
    ///   - RATE_LIMITED：频率超限
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// 会话令牌（仅开启成功时返回一次）
    ///
    /// 关闭保护需作为 auth_token 传入；成功后即失效、失败后仍可重试，
    /// 不可重复使用，也不存在无授权的重新签发入口。
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

impl PrivacyModeResult {
    pub fn success(enabled: bool) -> Self {
        let detail = if enabled {
            "防截屏保护已启用".into()
        } else {
            "防截屏保护已关闭".into()
        };
        PrivacyModeResult {
            ok: true,
            enabled,
            partial_protection: false,
            detail,
            error_code: None,
            session_token: None,
        }
    }

    /// 成功并附带会话令牌
    ///
    /// 空令牌按"无令牌"处理：幂等短路与关闭成功都不返回令牌，
    /// 空串若被当作令牌下发，前端会把无效凭证当成有效凭证保存。
    pub fn success_with_token(enabled: bool, token: impl Into<String>) -> Self {
        let detail = if enabled {
            "防截屏保护已启用".into()
        } else {
            "防截屏保护已关闭".into()
        };
        let token = token.into();
        PrivacyModeResult {
            ok: true,
            enabled,
            partial_protection: false,
            detail,
            error_code: None,
            session_token: if enabled && !token.is_empty() {
                Some(token)
            } else {
                None
            },
        }
    }

    pub fn error(code: &str, detail: impl Into<String>) -> Self {
        PrivacyModeResult {
            ok: false,
            enabled: false,
            partial_protection: false,
            detail: detail.into(),
            error_code: Some(code.into()),
            session_token: None,
        }
    }
}

/// 防截屏保护状态快照
///
/// 前端据此决定按钮状态、是否需要接管会话与是否给出恢复入口；
/// 状态与槽位是两处字段的组合，由后端一次锁内读取给出。
#[derive(Debug, Clone, serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct PrivacyStatusResult {
    /// 状态机：disabled / enabled / transitioning / quarantined
    pub state: String,
    /// 凭证槽位：empty / pending_adoption / active
    pub slot: String,
    /// 受保护窗口数量
    #[ts(type = "number")]
    pub protected_count: usize,
    /// 隔离原因（仅 quarantined 时存在）
    ///
    /// 取值：rollback_failed / stuck_in_transition /
    /// token_invariant_violation / reconcile_failed
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantined_reason: Option<String>,
}
