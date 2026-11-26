/*
 * 凭证槽位、平台出口与状态机
 *
 * 职责边界：短期租约与凭证摘要槽位、亲和性读写出口、审计出口，以及
 * Disabled/Enabled/Transition/Quarantined 状态定义。状态与凭证在同一
 * 把锁下维护，窗口清单与隔离原因均由状态派生。
 */

use crate::util::audit_log::{AuditEventType, AuditExtensions, AuditResult};
use std::time::Instant;

use super::*;
/* ====================================================================== *
 *  授权凭证槽位                                                           *
 * ====================================================================== */

pub type Generation = u64;

/// 短期租约：绑定签发时的世代与槽位占用
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub id: u64,
    pub generation: Generation,
}

/// 槽位三态
///
/// - 空：无凭证，开启流程的起点与成功关闭后的终点
/// - 待采纳：保护已生效但尚未向任何前端会话签发凭证（仅启动恢复与对账后进入）
/// - 生效：凭证已签发且未被消费；至多一个未决租约
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SlotState {
    Empty,
    PendingAdoption {
        generation: Generation,
    },
    Active {
        generation: Generation,
        digest: [u8; 32],
        lease: Option<u64>,
    },
}

/// 凭证槽位
///
/// 只持有明文凭证的摘要：后端不驻留可被再次使用的明文；
/// 校验（占用租约）与提交（消费）分离，使"关闭失败可重试"成立。
#[derive(Debug)]
pub struct TokenSlot {
    pub(super) state: SlotState,
    pub(super) next_generation: Generation,
    pub(super) next_lease_id: u64,
}

pub(super) fn digest_of(plaintext: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hasher.finalize().into()
}

impl TokenSlot {
    pub(super) fn new() -> Self {
        TokenSlot {
            state: SlotState::Empty,
            next_generation: 1,
            next_lease_id: 1,
        }
    }

    /// 槽位状态名（供状态查询）
    pub(super) fn state_name(&self) -> &'static str {
        match self.state {
            SlotState::Empty => "empty",
            SlotState::PendingAdoption { .. } => "pending_adoption",
            SlotState::Active { .. } => "active",
        }
    }

    pub(super) fn current_generation(&self) -> Option<Generation> {
        match self.state {
            SlotState::Empty => None,
            SlotState::PendingAdoption { generation } => Some(generation),
            SlotState::Active { generation, .. } => Some(generation),
        }
    }

    /// 签发新凭证（仅空态允许）；明文只在此次返回中出现
    pub(super) fn rotate(&mut self) -> Result<(String, Generation), PrivacyError> {
        if !matches!(self.state, SlotState::Empty) {
            return Err(PrivacyError::TokenInvariantViolation);
        }
        Ok(self.issue())
    }

    pub(super) fn issue(&mut self) -> (String, Generation) {
        let generation = self.next_generation;
        self.next_generation += 1;
        let plaintext = crate::util::random::random_hex(32);
        let digest = digest_of(&plaintext);
        self.state = SlotState::Active {
            generation,
            digest,
            lease: None,
        };
        (plaintext, generation)
    }

    /// 校验并占用租约（不消费摘要；失败后可重试）
    pub(super) fn verify(&mut self, plaintext: &str) -> Result<Lease, PrivacyError> {
        let (generation, matched) = match &self.state {
            SlotState::Active {
                generation,
                digest,
                lease,
            } => {
                if lease.is_some() {
                    return Err(PrivacyError::LeaseHeld);
                }
                (
                    *generation,
                    crate::util::crypto::ct_eq(&digest_of(plaintext), digest.as_slice()),
                )
            }
            _ => return Err(PrivacyError::TokenInvalid),
        };
        if !matched {
            return Err(PrivacyError::TokenInvalid);
        }
        let id = self.next_lease_id;
        self.next_lease_id += 1;
        if let SlotState::Active { lease, .. } = &mut self.state {
            *lease = Some(id);
        }
        Ok(Lease { id, generation })
    }

    /// 提交：世代与租约都匹配时消费至空态，摘要随之丢弃
    pub(super) fn commit(&mut self, lease: &Lease) -> Result<(), PrivacyError> {
        let matched = match &self.state {
            SlotState::Active {
                generation,
                lease: pending,
                ..
            } => *generation == lease.generation && *pending == Some(lease.id),
            _ => false,
        };
        if !matched {
            return Err(PrivacyError::LeaseExpired);
        }
        self.state = SlotState::Empty;
        Ok(())
    }

    /// 释放占用：保留摘要供重试
    pub(super) fn release(&mut self, lease: &Lease) {
        let matched = match &self.state {
            SlotState::Active {
                generation,
                lease: pending,
                ..
            } => *generation == lease.generation && *pending == Some(lease.id),
            _ => false,
        };
        if matched {
            if let SlotState::Active { lease: pending, .. } = &mut self.state {
                *pending = None;
            }
        }
    }

    /// 标记待采纳（启动恢复；对已生效槽位执行时丢弃摘要并轮换世代）
    pub(super) fn mark_pending_adoption(&mut self) -> Generation {
        let generation = self.next_generation;
        self.next_generation += 1;
        self.state = SlotState::PendingAdoption { generation };
        generation
    }

    /// 采纳：待采纳转为生效并签发新明文；旧世代立即失效
    pub(super) fn adopt(&mut self) -> Result<(String, Generation), PrivacyError> {
        if matches!(self.state, SlotState::PendingAdoption { .. }) {
            return Ok(self.issue());
        }
        if matches!(self.state, SlotState::Active { .. }) {
            return Err(PrivacyError::AlreadyAdopted);
        }
        Err(PrivacyError::NotRestored)
    }

    pub(super) fn reset_to_empty(&mut self) {
        self.state = SlotState::Empty;
    }
}

/* ====================================================================== *
 *  平台原语出口与审计出口                                                  *
 * ====================================================================== */

/// 窗口亲和性读写出口：生产实现转发到安全层原语；
/// 抽成接口使协调器可注入假实现做确定性单元测试（含失败注入）
pub trait AffinityOps: Send + Sync {
    fn get(&self, hwnd: isize) -> Result<u32, String>;
    fn set(&self, hwnd: isize, value: u32) -> Result<(), String>;
    /// 当前系统应使用的保护取值（旧系统降级为仅监视器）
    fn protection_value(&self) -> u32;
}

/// 生产实现：转发到安全层窗口亲和性原语
pub struct Win32AffinityOps;

impl AffinityOps for Win32AffinityOps {
    fn get(&self, hwnd: isize) -> Result<u32, String> {
        crate::security::window_affinity::get_raw_affinity(hwnd)
    }

    fn set(&self, hwnd: isize, value: u32) -> Result<(), String> {
        crate::security::window_affinity::set_raw_affinity(hwnd, value)
    }

    fn protection_value(&self) -> u32 {
        crate::security::window_affinity::protection_value()
    }
}

/// 审计出口：协调器只描述发生了什么（事件、结果、描述、扩展块），
/// 落盘由注入实现承担——便于单测与分层（协调器不依赖 AppHandle）
pub trait AuditSink: Send + Sync {
    fn write(
        &self,
        event: AuditEventType,
        result: AuditResult,
        detail: String,
        extensions: AuditExtensions,
    );
}

/// 生产审计出口：写入防篡改审计链（app_config_dir/audit.log）
pub struct AppAuditSink {
    pub(super) app: tauri::AppHandle,
}

impl AppAuditSink {
    pub fn new(app: tauri::AppHandle) -> Self {
        AppAuditSink { app }
    }
}

impl AuditSink for AppAuditSink {
    fn write(
        &self,
        event: AuditEventType,
        result: AuditResult,
        detail: String,
        extensions: AuditExtensions,
    ) {
        crate::infrastructure::audit::write_audit_with_extensions(
            &self.app,
            &format!("pid-{}", std::process::id()),
            event,
            result,
            None,
            Some(detail),
            extensions,
        );
    }
}

/* ====================================================================== *
 *  状态机                                                                 *
 * ====================================================================== */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StableState {
    Disabled,
    Enabled,
}

/// 隔离原因（具体原因描述随审计落盘，状态内只保留分类）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineReason {
    /// 还原失败：窗口取值未知，现场清单可信
    RollbackFailed,
    /// 过渡任务异常终止：窗口真实状态未知
    StuckInTransition,
    /// 凭证槽位不变式被破坏
    TokenInvariantViolation,
    /// 对账本身失败
    ReconcileFailed,
}

impl QuarantineReason {
    pub(super) fn name(&self) -> &'static str {
        match self {
            QuarantineReason::RollbackFailed => "rollback_failed",
            QuarantineReason::StuckInTransition => "stuck_in_transition",
            QuarantineReason::TokenInvariantViolation => "token_invariant_violation",
            QuarantineReason::ReconcileFailed => "reconcile_failed",
        }
    }
}

/// 窗口引用（保护目标与受保护清单共用同一结构）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowTarget {
    pub label: String,
    pub hwnd: isize,
}

/// 窗口快照：变更前的实际取值（回滚的唯一依据）
#[derive(Debug, Clone)]
pub struct WindowSnapshot {
    pub(super) label: String,
    pub(super) hwnd: isize,
    pub(super) original: u32,
}

#[derive(Debug)]
pub(super) enum PrivacyState {
    Disabled,
    Enabled {
        generation: Generation,
        protected: Vec<WindowTarget>,
    },
    Transitioning {
        transition_id: u64,
        previous: StableState,
        started_at: Instant,
    },
    Quarantined {
        previous: StableState,
        reason: QuarantineReason,
        /// 仅还原失败路径非空：未能回到原值的窗口现场（对账不依赖它，只入审计）
        #[allow(dead_code)]
        stuck: Vec<WindowSnapshot>,
    },
}

impl PrivacyState {
    pub(super) fn stable(&self) -> Option<StableState> {
        match self {
            PrivacyState::Disabled => Some(StableState::Disabled),
            PrivacyState::Enabled { .. } => Some(StableState::Enabled),
            _ => None,
        }
    }

    pub(super) fn is_transitioning(&self) -> bool {
        matches!(self, PrivacyState::Transitioning { .. })
    }

    pub(super) fn is_quarantined(&self) -> bool {
        matches!(self, PrivacyState::Quarantined { .. })
    }

    pub(super) fn protected_count(&self) -> usize {
        match self {
            PrivacyState::Enabled { protected, .. } => protected.len(),
            _ => 0,
        }
    }

    pub(super) fn state_name(&self) -> &'static str {
        match self {
            PrivacyState::Disabled => "disabled",
            PrivacyState::Enabled { .. } => "enabled",
            PrivacyState::Transitioning { .. } => "transitioning",
            PrivacyState::Quarantined { .. } => "quarantined",
        }
    }

    pub(super) fn quarantined_reason_name(&self) -> Option<&'static str> {
        match self {
            PrivacyState::Quarantined { reason, .. } => Some(reason.name()),
            _ => None,
        }
    }
}

pub(super) struct Inner {
    pub(super) state: PrivacyState,
    pub(super) slot: TokenSlot,
    pub(super) next_transition_id: u64,
    /// 对账单飞标记：与过渡共用同一状态机，不设第二份状态
    pub(super) reconciling: bool,
}

/// 过渡对外结果
#[derive(Debug)]
pub struct PrivacyModeOutcome {
    pub enabled: bool,
    /// 仅开启成功时返回一次的明文凭证
    pub session_token: Option<String>,
    pub generation: Generation,
    pub idempotent: bool,
}

/// 状态快照（状态查询用）
pub struct PrivacyStatusSnapshot {
    pub state: &'static str,
    pub slot: &'static str,
    pub protected_count: usize,
    pub quarantined_reason: Option<&'static str>,
}
