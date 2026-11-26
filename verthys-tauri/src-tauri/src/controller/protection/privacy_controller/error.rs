/*
 * 隐私模式错误分类
 *
 * 职责边界：每类失败有唯一稳定错误码与用户可读描述，前端按码分支，
 * 不解析描述文本。
 */

/// 隐私模式错误分类
///
/// 每个分类都有唯一的错误码与用户可读描述，前端按错误码决定界面行为；
/// 不使用字符串比较错误消息的方式判断失败原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyError {
    /// 已有过渡进行中
    Busy,
    /// 处于隔离状态，仅对账可达
    Quarantined,
    /// 非隔离状态下调用对账
    NotQuarantined,
    /// 未找到可保护窗口
    NoTargetWindow,
    /// 亲和性系统调用失败
    Affinity(String),
    /// 设置后回读值不符
    VerifyMismatch { expected: u32, actual: u32 },
    /// 失败并已还原到变更前的取值
    RolledBack { cause: Box<PrivacyError> },
    /// 未提供凭证
    TokenMissing,
    /// 凭证不匹配
    TokenInvalid,
    /// 已有未决租约（租约悬挂）
    LeaseHeld,
    /// 凭证世代已变更（租约过期）
    LeaseExpired,
    /// 无待采纳会话
    NotRestored,
    /// 重复采纳
    AlreadyAdopted,
    /// 槽位不变式被破坏
    TokenInvariantViolation,
    /// 过渡被更新操作取代
    TransitionSuperseded,
    /// 触发限流
    RateLimited { max_per_minute: usize },
}

impl PrivacyError {
    /// 错误码（前端按码分支，不解析描述文本）
    pub fn code(&self) -> &'static str {
        match self {
            PrivacyError::Busy => "PRIVACY_BUSY",
            PrivacyError::Quarantined => "PRIVACY_QUARANTINED",
            PrivacyError::NotQuarantined => "PRIVACY_NOT_QUARANTINED",
            PrivacyError::NoTargetWindow => "PRIVACY_NO_TARGET_WINDOW",
            PrivacyError::Affinity(_) => "PRIVACY_TEMPORARY_FAILURE",
            PrivacyError::VerifyMismatch { .. } => "PRIVACY_VERIFY_MISMATCH",
            PrivacyError::RolledBack { .. } => "PRIVACY_ROLLED_BACK",
            PrivacyError::TokenMissing => "PRIVACY_TOKEN_MISSING",
            PrivacyError::TokenInvalid => "PRIVACY_TOKEN_INVALID",
            PrivacyError::LeaseHeld => "PRIVACY_LEASE_HELD",
            PrivacyError::LeaseExpired => "PRIVACY_LEASE_EXPIRED",
            PrivacyError::NotRestored => "PRIVACY_NOT_RESTORED",
            PrivacyError::AlreadyAdopted => "PRIVACY_ALREADY_ADOPTED",
            PrivacyError::TokenInvariantViolation => "PRIVACY_TOKEN_INVARIANT_VIOLATION",
            PrivacyError::TransitionSuperseded => "PRIVACY_TRANSITION_SUPERSEDED",
            PrivacyError::RateLimited { .. } => "RATE_LIMITED",
        }
    }

    /// 用户可读描述（不含路径、句柄等敏感信息）
    pub fn detail(&self) -> String {
        match self {
            PrivacyError::Busy => "已有保护状态变更进行中".into(),
            PrivacyError::Quarantined => "防截屏保护处于隔离状态，需要先修复".into(),
            PrivacyError::NotQuarantined => "当前不处于隔离状态".into(),
            PrivacyError::NoTargetWindow => "未找到可保护的窗口".into(),
            PrivacyError::Affinity(msg) => format!("窗口保护设置失败: {}", msg),
            PrivacyError::VerifyMismatch { expected, actual } => {
                format!(
                    "窗口保护回读不匹配（期望 0x{:X}，实际 0x{:X}）",
                    expected, actual
                )
            }
            PrivacyError::RolledBack { cause } => {
                format!("保护失败，已还原到变更前状态（{}）", cause.detail())
            }
            PrivacyError::TokenMissing => "关闭防截屏保护需要会话凭证".into(),
            PrivacyError::TokenInvalid => "会话凭证无效".into(),
            PrivacyError::LeaseHeld => "已有待确认的关闭操作，请稍后重试".into(),
            PrivacyError::LeaseExpired => "会话凭证已过期，请重新开启保护后再关闭".into(),
            PrivacyError::NotRestored => "没有待接管的保护会话".into(),
            PrivacyError::AlreadyAdopted => "保护会话已接管".into(),
            PrivacyError::TokenInvariantViolation => "保护凭证状态异常".into(),
            PrivacyError::TransitionSuperseded => "操作已被新的状态变更取代".into(),
            PrivacyError::RateLimited { max_per_minute } => {
                format!("操作过于频繁，每分钟最多 {} 次", max_per_minute)
            }
        }
    }
}
