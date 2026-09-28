/*
 * controller/privacy_controller.rs — 防截屏隐私保护控制器
 *
 * 职责：
 *   - 窗口捕获排除（防截屏）的模式切换：整体成功或整体失败，失败必还原
 *   - 授权凭证槽位：关闭需凭证，成功后即失效、失败后可重试、不可无授权签发
 *   - 启动序列：保护默认开启（每次启动自动施加，无需手动），先于窗口可见生效；
 *     会话内显式关闭仅本次会话有效，重启回到默认开启
 *   - 隔离与对账：还原失败进入隔离，对账按失败前的稳定状态全窗口重扫收敛
 *   - 审计：模式变更、隔离、对账、采纳均写防篡改审计链（含结构化扩展块）
 *
 * 设计约束：
 *   - 单一真相源：状态机与凭证槽位在同一把锁下，窗口清单与隔离原因均由状态派生
 *   - 锁只覆盖首尾两段（选路/落状态），系统调用在锁外或阻塞池执行
 *   - 过渡身份单调递增：过期任务只写审计、不覆盖新状态，并释放其未决租约
 *   - 隔离是纯运行时状态，不持久化（进程退出后窗口亲和性随之消失）
 *
 * 依赖方向：controller → security / security_commands / util（分层单向依赖）
 */

use crate::controller::types::{PrivacyModeResult, PrivacyStatusResult};
use crate::util::audit_log::{AuditEventType, AuditExtensions, AuditResult};
use crate::util::rate_limiter::SlidingWindowLimiter;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tauri::{Manager, State};

/* ====================================================================== *
 *  常量与错误分类                                                         *
 * ====================================================================== */

/// 过渡卡死判定阈值：过渡任务跑在阻塞池，正常耗时为毫秒级；
/// 超过该阈值仍停在过渡态视为任务异常终止，由下一次状态读取收尸转入隔离
const STUCK_THRESHOLD: Duration = Duration::from_secs(30);

/// 限流：开启较严（防连点与前端缺陷），关闭宽松（不得卡住用户关闭操作），
/// 采纳与对账低频；状态查询只读幂等，不限流。
const ENABLE_MAX_PER_MINUTE: usize = 10;
const DISABLE_MAX_PER_MINUTE: usize = 60;
const ADOPT_MAX_PER_MINUTE: usize = 10;
const RECONCILE_MAX_PER_MINUTE: usize = 5;

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
                format!("窗口保护回读不匹配（期望 0x{:X}，实际 0x{:X}）", expected, actual)
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
enum SlotState {
    Empty,
    PendingAdoption { generation: Generation },
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
    state: SlotState,
    next_generation: Generation,
    next_lease_id: u64,
}

fn digest_of(plaintext: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hasher.finalize().into()
}

impl TokenSlot {
    fn new() -> Self {
        TokenSlot {
            state: SlotState::Empty,
            next_generation: 1,
            next_lease_id: 1,
        }
    }

    /// 槽位状态名（供状态查询）
    fn state_name(&self) -> &'static str {
        match self.state {
            SlotState::Empty => "empty",
            SlotState::PendingAdoption { .. } => "pending_adoption",
            SlotState::Active { .. } => "active",
        }
    }

    fn current_generation(&self) -> Option<Generation> {
        match self.state {
            SlotState::Empty => None,
            SlotState::PendingAdoption { generation } => Some(generation),
            SlotState::Active { generation, .. } => Some(generation),
        }
    }

    /// 签发新凭证（仅空态允许）；明文只在此次返回中出现
    fn rotate(&mut self) -> Result<(String, Generation), PrivacyError> {
        if !matches!(self.state, SlotState::Empty) {
            return Err(PrivacyError::TokenInvariantViolation);
        }
        Ok(self.issue())
    }

    fn issue(&mut self) -> (String, Generation) {
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
    fn verify(&mut self, plaintext: &str) -> Result<Lease, PrivacyError> {
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
    fn commit(&mut self, lease: &Lease) -> Result<(), PrivacyError> {
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
    fn release(&mut self, lease: &Lease) {
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
    fn mark_pending_adoption(&mut self) -> Generation {
        let generation = self.next_generation;
        self.next_generation += 1;
        self.state = SlotState::PendingAdoption { generation };
        generation
    }

    /// 采纳：待采纳转为生效并签发新明文；旧世代立即失效
    fn adopt(&mut self) -> Result<(String, Generation), PrivacyError> {
        if matches!(self.state, SlotState::PendingAdoption { .. }) {
            return Ok(self.issue());
        }
        if matches!(self.state, SlotState::Active { .. }) {
            return Err(PrivacyError::AlreadyAdopted);
        }
        Err(PrivacyError::NotRestored)
    }

    fn reset_to_empty(&mut self) {
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
    app: tauri::AppHandle,
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
        crate::security_commands::audit::write_audit_with_extensions(
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
    fn name(&self) -> &'static str {
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
    label: String,
    hwnd: isize,
    original: u32,
}

#[derive(Debug)]
enum PrivacyState {
    Disabled,
    Enabled {
        generation: Generation,
        protected: Vec<WindowTarget>,
    },
    Transitioning {
        transition_id: u64,
        target: bool,
        previous: StableState,
        started_at: Instant,
    },
    Quarantined {
        previous: StableState,
        reason: QuarantineReason,
        /// 仅还原失败路径非空：未能回到原值的窗口现场（对账不依赖它，只入审计）
        stuck: Vec<WindowSnapshot>,
    },
}

impl PrivacyState {
    fn stable(&self) -> Option<StableState> {
        match self {
            PrivacyState::Disabled => Some(StableState::Disabled),
            PrivacyState::Enabled { .. } => Some(StableState::Enabled),
            _ => None,
        }
    }

    fn is_transitioning(&self) -> bool {
        matches!(self, PrivacyState::Transitioning { .. })
    }

    fn is_quarantined(&self) -> bool {
        matches!(self, PrivacyState::Quarantined { .. })
    }

    fn protected_count(&self) -> usize {
        match self {
            PrivacyState::Enabled { protected, .. } => protected.len(),
            _ => 0,
        }
    }

    fn state_name(&self) -> &'static str {
        match self {
            PrivacyState::Disabled => "disabled",
            PrivacyState::Enabled { .. } => "enabled",
            PrivacyState::Transitioning { .. } => "transitioning",
            PrivacyState::Quarantined { .. } => "quarantined",
        }
    }

    fn quarantined_reason_name(&self) -> Option<&'static str> {
        match self {
            PrivacyState::Quarantined { reason, .. } => Some(reason.name()),
            _ => None,
        }
    }
}

struct Inner {
    state: PrivacyState,
    slot: TokenSlot,
    next_transition_id: u64,
    /// 对账单飞标记：与过渡共用同一状态机，不设第二份状态
    reconciling: bool,
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

/* ====================================================================== *
 *  协调器                                                                 *
 * ====================================================================== */

pub struct PrivacyCoordinator {
    inner: Mutex<Inner>,
    ops: Arc<dyn AffinityOps>,
    audit: Arc<dyn AuditSink>,
}

impl PrivacyCoordinator {
    pub fn new(audit: Arc<dyn AuditSink>) -> Self {
        Self::with_ops(Arc::new(Win32AffinityOps), audit)
    }

    pub fn with_ops(ops: Arc<dyn AffinityOps>, audit: Arc<dyn AuditSink>) -> Self {
        PrivacyCoordinator {
            inner: Mutex::new(Inner {
                state: PrivacyState::Disabled,
                slot: TokenSlot::new(),
                next_transition_id: 0,
                reconciling: false,
            }),
            ops,
            audit,
        }
    }

    /// 取锁（锁中毒即取回内部数据继续：状态机自身是自洽的，
    /// 中毒只说明前一个持锁任务 panic，不应让整个保护能力失效）
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 卡死收尸：过渡任务若异常终止而未落状态，状态机会停在过渡态；
    /// 在下一次读取或操作时转入隔离（不做后台轮询），并写审计留痕
    fn reap_stuck(&self, inner: &mut Inner) {
        let orphaned = match &inner.state {
            PrivacyState::Transitioning {
                transition_id,
                started_at,
                ..
            } if started_at.elapsed() > STUCK_THRESHOLD => Some(*transition_id),
            _ => None,
        };
        if let Some(orphaned_id) = orphaned {
            if let PrivacyState::Transitioning { previous, .. } = &inner.state {
                let previous = *previous;
                inner.state = PrivacyState::Quarantined {
                    previous,
                    reason: QuarantineReason::StuckInTransition,
                    stuck: Vec::new(),
                };
            }
            log::error!(
                "[privacy] 过渡任务卡死（身份 {}），转入隔离等待对账",
                orphaned_id
            );
            self.audit.write(
                AuditEventType::PrivacyQuarantine,
                AuditResult::Failure,
                "过渡任务卡死，窗口真实状态未知，进入隔离".into(),
                AuditExtensions::default().transition(orphaned_id),
            );
        }
    }

    /// 合法状态组合校验：已启用 ↔ 槽位非空；已关闭 ↔ 槽位为空。
    /// 违反即隔离——不允许在"界面显示已保护、实际无凭证可关闭"的矛盾状态下继续。
    fn enforce_consistency_locked(inner: &mut Inner) -> Result<(), PrivacyError> {
        let consistent = match (&inner.state, inner.slot.state_name()) {
            (PrivacyState::Enabled { .. }, slot) => slot != "empty",
            (PrivacyState::Disabled, slot) => slot == "empty",
            // 过渡中与隔离态由各自流程收口
            _ => true,
        };
        if consistent {
            return Ok(());
        }
        inner.state = PrivacyState::Quarantined {
            previous: StableState::Disabled,
            reason: QuarantineReason::TokenInvariantViolation,
            stuck: Vec::new(),
        };
        Err(PrivacyError::Quarantined)
    }

    /// 状态快照（只读；内联卡死收尸与组合校验）
    pub fn status(&self) -> PrivacyStatusSnapshot {
        let mut inner = self.lock();
        self.reap_stuck(&mut inner);
        let _ = Self::enforce_consistency_locked(&mut inner);
        PrivacyStatusSnapshot {
            state: inner.state.state_name(),
            slot: inner.slot.state_name(),
            protected_count: inner.state.protected_count(),
            quarantined_reason: inner.state.quarantined_reason_name(),
        }
    }

    /// 过渡：单飞由状态机的过渡变体承担；系统调用在锁外执行；
    /// 提交前校验过渡身份，过期任务不覆盖新状态且释放其未决租约
    pub fn transition(
        &self,
        target: bool,
        token: Option<&str>,
        targets: &[WindowTarget],
    ) -> Result<PrivacyModeOutcome, PrivacyError> {
        // ---------- 首段：锁内校验并占位 ----------
        let (lease, previous, my_id) = {
            let mut inner = self.lock();
            self.reap_stuck(&mut inner);
            Self::enforce_consistency_locked(&mut inner)?;

            if inner.state.is_transitioning() {
                return Err(PrivacyError::Busy);
            }
            if inner.state.is_quarantined() {
                return Err(PrivacyError::Quarantined);
            }

            let previous = match inner.state.stable() {
                Some(stable) => stable,
                None => return Err(PrivacyError::Busy),
            };

            // 幂等短路：状态已是目标值，不重复施加系统调用
            if (previous == StableState::Enabled) == target {
                return Ok(PrivacyModeOutcome {
                    enabled: previous == StableState::Enabled,
                    session_token: None,
                    generation: inner.slot.current_generation().unwrap_or(0),
                    idempotent: true,
                });
            }

            if targets.is_empty() {
                return Err(PrivacyError::NoTargetWindow);
            }

            // 关闭路径需要凭证：校验即占位，不消费
            let lease = if target {
                None
            } else {
                let provided = token.ok_or(PrivacyError::TokenMissing)?;
                Some(inner.slot.verify(provided)?)
            };

            inner.next_transition_id += 1;
            let my_id = inner.next_transition_id;
            inner.state = PrivacyState::Transitioning {
                transition_id: my_id,
                target,
                previous,
                started_at: Instant::now(),
            };
            (lease, previous, my_id)
        };
        // ---------- 锁已释放 ----------

        // ---------- 中段：锁外执行系统调用 ----------
        let target_value = if target {
            self.ops.protection_value()
        } else {
            crate::security::window_affinity::WDA_NONE
        };
        let apply_result = self.apply_atomic(targets, target_value);

        // ---------- 尾段：锁内提交、释放或隔离 ----------
        let mut inner = self.lock();

        let still_mine = matches!(
            &inner.state,
            PrivacyState::Transitioning { transition_id, .. } if *transition_id == my_id
        );
        if !still_mine {
            // 身份被取代（看门狗判死或对账接手）：只写审计、不碰状态；
            // 同时必须释放未决租约，否则凭证将永久悬挂而无法重试
            if let Some(lease) = &lease {
                inner.slot.release(lease);
            }
            self.audit.write(
                AuditEventType::PrivacyModeChange,
                AuditResult::Failure,
                "过渡被新的状态变更取代，未提交任何状态".into(),
                AuditExtensions::default().transition(my_id),
            );
            return Err(PrivacyError::TransitionSuperseded);
        }

        match apply_result {
            Ok(success) => {
                if target {
                    match inner.slot.rotate() {
                        Ok((plaintext, generation)) => {
                            inner.state = PrivacyState::Enabled {
                                generation,
                                protected: success.applied,
                            };
                            self.audit.write(
                                AuditEventType::PrivacyModeChange,
                                AuditResult::Success,
                                "防截屏保护已启用".into(),
                                AuditExtensions::default()
                                    .transition(my_id)
                                    .generation(generation)
                                    .readback(success.readback),
                            );
                            Ok(PrivacyModeOutcome {
                                enabled: true,
                                session_token: Some(plaintext),
                                generation,
                                idempotent: false,
                            })
                        }
                        Err(cause) => {
                            inner.state = PrivacyState::Quarantined {
                                previous,
                                reason: QuarantineReason::TokenInvariantViolation,
                                stuck: Vec::new(),
                            };
                            self.audit.write(
                                AuditEventType::PrivacyQuarantine,
                                AuditResult::Failure,
                                format!(
                                    "开启成功后签发凭证失败，进入隔离（{}）",
                                    cause.detail()
                                ),
                                AuditExtensions::default().transition(my_id),
                            );
                            Err(PrivacyError::Quarantined)
                        }
                    }
                } else {
                    let committed = match &lease {
                        Some(lease) => inner.slot.commit(lease).is_ok(),
                        None => false,
                    };
                    if committed {
                        let generation = lease.map(|l| l.generation).unwrap_or(0);
                        let lease_id = lease.map(|l| l.id).unwrap_or(0);
                        inner.state = PrivacyState::Disabled;
                        self.audit.write(
                            AuditEventType::PrivacyModeChange,
                            AuditResult::Success,
                            "防截屏保护已关闭，凭证已消费".into(),
                            AuditExtensions::default()
                                .transition(my_id)
                                .lease(lease_id, generation)
                                .readback(success.readback),
                        );
                        Ok(PrivacyModeOutcome {
                            enabled: false,
                            session_token: None,
                            generation,
                            idempotent: false,
                        })
                    } else {
                        inner.state = PrivacyState::Quarantined {
                            previous,
                            reason: QuarantineReason::TokenInvariantViolation,
                            stuck: Vec::new(),
                        };
                        self.audit.write(
                            AuditEventType::PrivacyQuarantine,
                            AuditResult::Failure,
                            "关闭已生效但凭证提交失败，进入隔离".into(),
                            AuditExtensions::default().transition(my_id),
                        );
                        Err(PrivacyError::Quarantined)
                    }
                }
            }

            Err(failure) => {
                let stuck_count = failure.stuck.len();
                if failure.rollback_failed {
                    // 现场清单只入审计：其余窗口在还原本上前可能从未被保护，
                    // 记录标签便于人工核对，不参与后续对账取舍
                    log::error!(
                        "[privacy] 还原失败的窗口: {:?}",
                        failure
                            .stuck
                            .iter()
                            .map(|snapshot| snapshot.label.as_str())
                            .collect::<Vec<_>>()
                    );
                    inner.state = PrivacyState::Quarantined {
                        previous,
                        reason: QuarantineReason::RollbackFailed,
                        stuck: failure.stuck,
                    };
                    self.audit.write(
                        AuditEventType::PrivacyQuarantine,
                        AuditResult::Failure,
                        format!("保护失败且还原失败，进入隔离（{}）", failure.cause.detail()),
                        AuditExtensions::default()
                            .transition(my_id)
                            .rollback(false)
                            .stuck_windows(stuck_count),
                    );
                    Err(PrivacyError::Quarantined)
                } else {
                    inner.state = match previous {
                        StableState::Disabled => PrivacyState::Disabled,
                        StableState::Enabled => PrivacyState::Enabled {
                            generation: inner.slot.current_generation().unwrap_or(0),
                            protected: targets.to_vec(),
                        },
                    };
                    if let Some(lease) = &lease {
                        inner.slot.release(lease);
                    }
                    self.audit.write(
                        AuditEventType::PrivacyModeChange,
                        AuditResult::Failure,
                        format!("保护失败，已还原到变更前状态（{}）", failure.cause.detail()),
                        AuditExtensions::default()
                            .transition(my_id)
                            .rollback(true),
                    );
                    Err(PrivacyError::RolledBack {
                        cause: Box::new(failure.cause),
                    })
                }
            }
        }
    }

    /// 采纳：待采纳 → 生效，签发新凭证返回前端
    ///
    /// 只接受稳定态：隔离态仅对账可达、过渡中没有可接管的稳定会话；
    /// 显式拒绝而非依赖"槽位恰好不是待采纳"的隐含兜底，
    /// 保证任何状态下都不会签发无主凭证。
    pub fn adopt(&self) -> Result<(String, Generation), PrivacyError> {
        let mut inner = self.lock();
        self.reap_stuck(&mut inner);
        Self::enforce_consistency_locked(&mut inner)?;

        if inner.state.is_transitioning() {
            return Err(PrivacyError::Busy);
        }
        if inner.state.is_quarantined() {
            return Err(PrivacyError::Quarantined);
        }

        let (plaintext, generation) = inner.slot.adopt()?;
        if let PrivacyState::Enabled {
            generation: state_generation,
            ..
        } = &mut inner.state
        {
            *state_generation = generation;
        }
        self.audit.write(
            AuditEventType::PrivacyModeChange,
            AuditResult::Success,
            "保护会话已由前端接管".into(),
            AuditExtensions::default().generation(generation).adoption(),
        );
        Ok((plaintext, generation))
    }

    /// 启动期施加初始保护
    ///
    /// 运行于 setup 钩子（此时前端命令尚未开始派发），因此直接持锁完成，
    /// 不引入过渡身份；成功即把槽位置为待采纳，由前端挂载后采纳取得凭证。
    pub fn startup_protect(&self, targets: &[WindowTarget]) -> Result<Generation, PrivacyError> {
        let mut inner = self.lock();
        if inner.state.stable() != Some(StableState::Disabled) {
            return Err(PrivacyError::Busy);
        }
        if inner.slot.state_name() != "empty" {
            return Err(PrivacyError::TokenInvariantViolation);
        }
        let target_value = self.ops.protection_value();

        match self.apply_atomic(targets, target_value) {
            Ok(success) => {
                let generation = inner.slot.mark_pending_adoption();
                inner.state = PrivacyState::Enabled {
                    generation,
                    protected: success.applied,
                };
                self.audit.write(
                    AuditEventType::PrivacyModeChange,
                    AuditResult::Success,
                    "启动保护已生效，等待前端接管".into(),
                    AuditExtensions::default()
                        .generation(generation)
                        .readback(success.readback),
                );
                Ok(generation)
            }
            Err(failure) => {
                let stuck_count = failure.stuck.len();
                if failure.rollback_failed {
                    inner.state = PrivacyState::Quarantined {
                        previous: StableState::Enabled,
                        reason: QuarantineReason::RollbackFailed,
                        stuck: failure.stuck,
                    };
                    self.audit.write(
                        AuditEventType::PrivacyQuarantine,
                        AuditResult::Failure,
                        format!(
                            "启动保护失败且还原失败，进入隔离（{}）",
                            failure.cause.detail()
                        ),
                        AuditExtensions::default()
                            .rollback(false)
                            .stuck_windows(stuck_count),
                    );
                    Err(PrivacyError::Quarantined)
                } else {
                    // 已还原：状态保持关闭，界面如实显示未保护，用户可手动开启
                    self.audit.write(
                        AuditEventType::PrivacyModeChange,
                        AuditResult::Failure,
                        format!(
                            "启动保护失败，已还原到未保护状态（{}）",
                            failure.cause.detail()
                        ),
                        AuditExtensions::default().rollback(true),
                    );
                    Err(PrivacyError::RolledBack {
                        cause: Box::new(failure.cause),
                    })
                }
            }
        }
    }

    /// 对账：隔离 → 按失败前的稳定状态收敛
    ///
    /// 一律全窗口重扫：还原失败路径的失败清单只说明哪些窗口未能回到原值，
    /// 其余窗口在还原成功前可能从未被保护，按清单对账会漏掉这些窗口。
    pub fn reconcile(&self, targets: &[WindowTarget]) -> Result<PrivacyModeOutcome, PrivacyError> {
        // ---------- 首段：锁内占位（对账同样单飞） ----------
        let previous = {
            let mut inner = self.lock();
            self.reap_stuck(&mut inner);
            if inner.reconciling {
                return Err(PrivacyError::Busy);
            }
            let previous = match &inner.state {
                PrivacyState::Quarantined { previous, .. } => *previous,
                _ => return Err(PrivacyError::NotQuarantined),
            };
            inner.reconciling = true;
            previous
        };

        // ---------- 中段：锁外全窗口重扫 ----------
        let target_value = if previous == StableState::Enabled {
            self.ops.protection_value()
        } else {
            crate::security::window_affinity::WDA_NONE
        };
        let result = self.force_to_baseline(targets, target_value);

        // ---------- 尾段：锁内落状态 ----------
        let mut inner = self.lock();
        inner.reconciling = false;

        match result {
            Ok(()) => {
                let outcome = match previous {
                    StableState::Disabled => {
                        inner.slot.reset_to_empty();
                        inner.state = PrivacyState::Disabled;
                        PrivacyModeOutcome {
                            enabled: false,
                            session_token: None,
                            generation: 0,
                            idempotent: false,
                        }
                    }
                    StableState::Enabled => {
                        let generation = inner.slot.mark_pending_adoption();
                        inner.state = PrivacyState::Enabled {
                            generation,
                            protected: targets.to_vec(),
                        };
                        PrivacyModeOutcome {
                            enabled: true,
                            session_token: None,
                            generation,
                            idempotent: false,
                        }
                    }
                };
                self.audit.write(
                    AuditEventType::PrivacyReconcile,
                    AuditResult::Success,
                    if previous == StableState::Enabled {
                        "对账完成：保护已重新加固，等待前端再次接管".into()
                    } else {
                        "对账完成：残留保护已清除".into()
                    },
                    AuditExtensions::default()
                        .reconcile(previous == StableState::Enabled)
                        .readback(target_value),
                );
                Ok(outcome)
            }
            Err(cause) => {
                if let PrivacyState::Quarantined { reason, .. } = &mut inner.state {
                    *reason = QuarantineReason::ReconcileFailed;
                }
                self.audit.write(
                    AuditEventType::PrivacyReconcile,
                    AuditResult::Failure,
                    format!("对账失败，仍处于隔离（{}）", cause.detail()),
                    AuditExtensions::default().reconcile(previous == StableState::Enabled),
                );
                Err(cause)
            }
        }
    }

    /// 原子应用：快照 → 逐个设置并回读 → 任一步失败逆序还原
    ///
    /// 所有失败路径统一走还原逻辑（不使用提前返回的错误传播），
    /// 还原以各自快照的原值为准（可能是"仅监视器"，而非"无保护"）。
    fn apply_atomic(&self, targets: &[WindowTarget], value: u32) -> Result<ApplySuccess, ApplyFailure> {
        if targets.is_empty() {
            return Err(ApplyFailure {
                cause: PrivacyError::NoTargetWindow,
                rollback_failed: false,
                stuck: Vec::new(),
            });
        }

        // 快照阶段：此时尚无副作用，失败直接返回，无需还原
        let mut snapshots = Vec::with_capacity(targets.len());
        for target in targets {
            match self.ops.get(target.hwnd) {
                Ok(original) => snapshots.push(WindowSnapshot {
                    label: target.label.clone(),
                    hwnd: target.hwnd,
                    original,
                }),
                Err(message) => {
                    return Err(ApplyFailure {
                        cause: PrivacyError::Affinity(message),
                        rollback_failed: false,
                        stuck: Vec::new(),
                    })
                }
            }
        }

        let mut applied: Vec<usize> = Vec::with_capacity(snapshots.len());
        for index in 0..snapshots.len() {
            let snapshot = &snapshots[index];
            let step = self
                .ops
                .set(snapshot.hwnd, value)
                .and_then(|_| self.ops.get(snapshot.hwnd));

            match step {
                Ok(actual) if actual == value => applied.push(index),
                Ok(actual) => {
                    let (restored, stuck) = self.rollback_to_snapshot(&snapshots, &applied);
                    return Err(ApplyFailure {
                        cause: PrivacyError::VerifyMismatch {
                            expected: value,
                            actual,
                        },
                        rollback_failed: !restored,
                        stuck,
                    });
                }
                Err(message) => {
                    let (restored, stuck) = self.rollback_to_snapshot(&snapshots, &applied);
                    return Err(ApplyFailure {
                        cause: PrivacyError::Affinity(message),
                        rollback_failed: !restored,
                        stuck,
                    });
                }
            }
        }

        Ok(ApplySuccess {
            applied: snapshots
                .iter()
                .map(|snapshot| WindowTarget {
                    label: snapshot.label.clone(),
                    hwnd: snapshot.hwnd,
                })
                .collect(),
            readback: value,
        })
    }

    /// 逆序还原到快照原值；返回（是否全部还原, 未能还原的现场）
    fn rollback_to_snapshot(
        &self,
        snapshots: &[WindowSnapshot],
        applied: &[usize],
    ) -> (bool, Vec<WindowSnapshot>) {
        let mut restored_all = true;
        let mut stuck = Vec::new();
        for &index in applied.iter().rev() {
            let snapshot = &snapshots[index];
            let restored = if self.ops.set(snapshot.hwnd, snapshot.original).is_ok() {
                match self.ops.get(snapshot.hwnd) {
                    Ok(actual) => actual == snapshot.original,
                    Err(_) => false,
                }
            } else {
                false
            };
            if !restored {
                restored_all = false;
                stuck.push(snapshot.clone());
            }
        }
        (restored_all, stuck)
    }

    /// 全窗口强制到目标取值并逐窗口回读校验（对账专用）
    fn force_to_baseline(&self, targets: &[WindowTarget], value: u32) -> Result<(), PrivacyError> {
        if targets.is_empty() {
            return Err(PrivacyError::NoTargetWindow);
        }
        for target in targets {
            let step = self.ops.set(target.hwnd, value).and_then(|_| self.ops.get(target.hwnd));
            match step {
                Ok(actual) if actual == value => {}
                Ok(actual) => {
                    return Err(PrivacyError::VerifyMismatch {
                        expected: value,
                        actual,
                    })
                }
                Err(message) => return Err(PrivacyError::Affinity(message)),
            }
        }
        Ok(())
    }
}

struct ApplySuccess {
    applied: Vec<WindowTarget>,
    readback: u32,
}

struct ApplyFailure {
    cause: PrivacyError,
    rollback_failed: bool,
    stuck: Vec<WindowSnapshot>,
}

/* ====================================================================== *
 *  窗口目标收集                                                           *
 * ====================================================================== */

/// 收集当前全部 WebView 窗口作为保护目标
///
/// 任一窗口取句柄失败即整体失败：静默跳过会造成"保护成功但该窗口裸奔"的假象。
pub fn collect_targets(app: &tauri::AppHandle) -> Result<Vec<WindowTarget>, PrivacyError> {
    let mut targets = Vec::new();
    for (label, window) in app.webview_windows() {
        match window.hwnd() {
            Ok(hwnd) => targets.push(WindowTarget {
                label,
                hwnd: hwnd.0 as isize,
            }),
            Err(e) => {
                return Err(PrivacyError::Affinity(format!(
                    "窗口 '{}' 获取句柄失败: {}",
                    label, e
                )))
            }
        }
    }
    // 应用顺序确定化（便于审计与复现），与窗口枚举顺序无关
    targets.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(targets)
}

/* ====================================================================== *
 *  启动序列                                                               *
 * ====================================================================== */

/// 启动序列结果
pub enum StartupOutcome {
    /// 保护已生效（槽位待采纳，前端挂载后接管）
    Protected { generation: Generation },
    /// 未保护：保护尝试失败且已还原（保护默认开启，不存在"按用户意图跳过"）
    Unprotected,
    /// 还原失败（窗口取值未知）：需要用户驱动对账后才可显示主窗口
    NeedsRecovery,
}

/// 启动序列：在窗口可见前施加保护并回读
///
/// 防截屏是默认开启的应用级保护：**每次启动一律自动施加，不依赖任何持久化
/// 意图，也不需要用户手动开启**；用户在当前会话内显式关闭后仅本次会话有效，
/// 重启回到默认开启。恰好在 `setup` 钩子内执行：Tauri 在钩子之前按配置建窗
/// （此时窗口已存在但不可见），而前端命令要等钩子返回后才开始派发，
/// 因此不存在与前端查询并发的竞态。
pub fn startup_engage(app: &tauri::AppHandle, coordinator: &PrivacyCoordinator) -> StartupOutcome {
    let targets = match collect_targets(app) {
        Ok(targets) => targets,
        Err(cause) => {
            log::error!("[privacy] 启动保护失败：{}", cause.detail());
            coordinator.audit.write(
                AuditEventType::PrivacyModeChange,
                AuditResult::Failure,
                format!("启动保护未生效（{}），按未保护进入", cause.detail()),
                AuditExtensions::default(),
            );
            return StartupOutcome::Unprotected;
        }
    };

    match coordinator.startup_protect(&targets) {
        Ok(generation) => StartupOutcome::Protected { generation },
        Err(PrivacyError::RolledBack { cause }) => {
            log::warn!("[privacy] 启动保护失败，已还原：{}", cause.detail());
            StartupOutcome::Unprotected
        }
        Err(PrivacyError::Quarantined) => StartupOutcome::NeedsRecovery,
        Err(other) => {
            log::error!("[privacy] 启动保护未生效：{}", other.detail());
            StartupOutcome::Unprotected
        }
    }
}

/// 启动恢复对话框：还原失败时窗口取值未知，显示任何窗口都可能呈现
/// "看起来受保护、实际未受保护"，因此只给"重试对账 / 退出"两个出口。
/// 返回 true 表示对账成功（可以显示主窗口），false 表示用户选择退出。
pub fn run_startup_recovery_dialog(
    app: &tauri::AppHandle,
    coordinator: &PrivacyCoordinator,
) -> bool {
    let message = "防截屏保护未能启用，且窗口保护状态无法还原。\n\n\
                   选择\"重试\"将重新加固保护并进入应用；\n\
                   选择\"取消\"将退出应用（不显示任何窗口）。";
    loop {
        if !native_retry_dialog(message) {
            return false;
        }
        let targets = match collect_targets(app) {
            Ok(targets) => targets,
            Err(cause) => {
                log::error!("[privacy] 恢复对账前收集窗口失败：{}", cause.detail());
                continue;
            }
        };
        match coordinator.reconcile(&targets) {
            Ok(outcome) => {
                log::info!("[privacy] 恢复对账成功（enabled={}）", outcome.enabled);
                return true;
            }
            Err(cause) => {
                log::error!("[privacy] 恢复对账失败：{}", cause.detail());
            }
        }
    }
}

/// 原生"重试 / 取消"对话框；返回 true 表示用户选择重试
#[cfg(target_os = "windows")]
fn native_retry_dialog(message: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDRETRY, MB_ICONWARNING, MB_RETRYCANCEL, MB_SETFOREGROUND, MB_TOPMOST,
    };

    fn to_wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let text = to_wide(message);
    let caption = to_wide("Verthys 防截屏保护");
    let result = unsafe {
        MessageBoxW(
            None,
            PCWSTR(text.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_RETRYCANCEL | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
        )
    };
    result == IDRETRY
}

#[cfg(not(target_os = "windows"))]
fn native_retry_dialog(_message: &str) -> bool {
    false
}

/* ====================================================================== *
 *  Tauri 命令                                                             *
 * ====================================================================== */

static ENABLE_LIMITER: Mutex<SlidingWindowLimiter> =
    Mutex::new(SlidingWindowLimiter::new(Duration::from_secs(60), ENABLE_MAX_PER_MINUTE));
static DISABLE_LIMITER: Mutex<SlidingWindowLimiter> =
    Mutex::new(SlidingWindowLimiter::new(Duration::from_secs(60), DISABLE_MAX_PER_MINUTE));
static ADOPT_LIMITER: Mutex<SlidingWindowLimiter> =
    Mutex::new(SlidingWindowLimiter::new(Duration::from_secs(60), ADOPT_MAX_PER_MINUTE));
static RECONCILE_LIMITER: Mutex<SlidingWindowLimiter> =
    Mutex::new(SlidingWindowLimiter::new(Duration::from_secs(60), RECONCILE_MAX_PER_MINUTE));

/// 取用限流器名额；超限返回 false
fn take_rate_limit(slot: &'static Mutex<SlidingWindowLimiter>) -> Result<bool, String> {
    let mut limiter = slot
        .lock()
        .map_err(|e| format!("频率限制器锁中毒: {}", e))?;
    Ok(limiter.check_and_record())
}

/// 设置防截屏保护（窗口捕获排除）
///
/// - 开启：整体成功或整体失败，成功后返回一次性会话凭证
/// - 关闭：需传入开启时获得的凭证；失败后凭证保留，可立即重试
/// - 关闭成功即消费凭证；重复关闭由幂等短路直接成功返回
#[tauri::command]
pub async fn set_privacy_mode(
    app: tauri::AppHandle,
    coordinator: State<'_, Arc<PrivacyCoordinator>>,
    enabled: bool,
    auth_token: Option<String>,
) -> Result<PrivacyModeResult, String> {
    let limiter = if enabled {
        &ENABLE_LIMITER
    } else {
        &DISABLE_LIMITER
    };
    if !take_rate_limit(limiter)? {
        let max = if enabled {
            ENABLE_MAX_PER_MINUTE
        } else {
            DISABLE_MAX_PER_MINUTE
        };
        let cause = PrivacyError::RateLimited {
            max_per_minute: max,
        };
        log::warn!("[privacy] 频率超限，拒绝 set_privacy_mode({})", enabled);
        coordinator
            .audit
            .write(
                AuditEventType::PrivacyModeChange,
                AuditResult::Denied,
                cause.detail(),
                AuditExtensions::default(),
            );
        return Ok(PrivacyModeResult::error(cause.code(), cause.detail()));
    }

    let coordinator_arc = Arc::clone(coordinator.inner());
    let app_for_task = app.clone();
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let targets = collect_targets(&app_for_task)?;
        coordinator_arc.transition(enabled, auth_token.as_deref(), &targets)
    })
    .await
    .map_err(|e| format!("隐私模式过渡任务异常: {}", e))?;

    match outcome {
        Ok(result) => Ok(PrivacyModeResult::success_with_token(
            result.enabled,
            result.session_token.unwrap_or_default(),
        )),
        Err(cause) => {
            // 凭证类拒绝必须留审计（无授权关闭尝试是安全事件）；
            // 过渡类失败的审计已在状态机内完成，不重复记
            if matches!(
                cause,
                PrivacyError::TokenInvalid
                    | PrivacyError::TokenMissing
                    | PrivacyError::LeaseHeld
                    | PrivacyError::LeaseExpired
            ) {
                coordinator.audit.write(
                    AuditEventType::PrivacyModeChange,
                    AuditResult::Denied,
                    cause.detail(),
                    AuditExtensions::default(),
                );
            }
            Ok(PrivacyModeResult::error(cause.code(), cause.detail()))
        }
    }
}

/// 查询防截屏保护状态（只读幂等，不限流）
#[tauri::command]
pub fn get_privacy_status(
    coordinator: State<'_, Arc<PrivacyCoordinator>>,
) -> PrivacyStatusResult {
    let snapshot = coordinator.status();
    PrivacyStatusResult {
        state: snapshot.state.to_string(),
        slot: snapshot.slot.to_string(),
        protected_count: snapshot.protected_count,
        quarantined_reason: snapshot.quarantined_reason.map(|reason| reason.to_string()),
    }
}

/// 采纳保护会话：把启动恢复/对账后的待采纳状态转为生效并取得凭证
#[tauri::command]
pub fn adopt_privacy_session(
    coordinator: State<'_, Arc<PrivacyCoordinator>>,
) -> Result<PrivacyModeResult, String> {
    if !take_rate_limit(&ADOPT_LIMITER)? {
        let cause = PrivacyError::RateLimited {
            max_per_minute: ADOPT_MAX_PER_MINUTE,
        };
        return Ok(PrivacyModeResult::error(cause.code(), cause.detail()));
    }

    match coordinator.adopt() {
        Ok((plaintext, _generation)) => {
            Ok(PrivacyModeResult::success_with_token(true, &plaintext))
        }
        Err(PrivacyError::AlreadyAdopted) => {
            // 重复采纳不是失败：会话已由其他挂载点接管，前端按"忽略"处理
            Ok(PrivacyModeResult::success(true))
        }
        Err(cause) => Ok(PrivacyModeResult::error(cause.code(), cause.detail())),
    }
}

/// 隔离对账：按失败前的稳定状态全窗口重扫收敛
///
/// 对账是破坏性低频操作，限流更严；仅在隔离状态下可达，收敛目标取失败前的稳定状态。
#[tauri::command]
pub async fn reconcile_privacy(
    app: tauri::AppHandle,
    coordinator: State<'_, Arc<PrivacyCoordinator>>,
) -> Result<PrivacyModeResult, String> {
    if !take_rate_limit(&RECONCILE_LIMITER)? {
        let cause = PrivacyError::RateLimited {
            max_per_minute: RECONCILE_MAX_PER_MINUTE,
        };
        return Ok(PrivacyModeResult::error(cause.code(), cause.detail()));
    }

    let coordinator_arc = Arc::clone(coordinator.inner());
    let app_for_task = app.clone();
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let targets = collect_targets(&app_for_task)?;
        coordinator_arc.reconcile(&targets)
    })
    .await
    .map_err(|e| format!("隐私对账任务异常: {}", e))?;

    match outcome {
        Ok(result) => {
            // 对账至启用时槽位回待采纳，前端随后采纳取得新凭证
            Ok(PrivacyModeResult::success(result.enabled))
        }
        Err(cause) => Ok(PrivacyModeResult::error(cause.code(), cause.detail())),
    }
}

/* ====================================================================== *
 *  单元测试                                                               *
 *                                                                        *
 *  协调器通过注入的亲和性出口与审计出口做确定性测试：                         *
 *  窗口读写、失败注入、并发过渡、卡死收尸、对账重扫全部可在无窗口环境下复现。     *
 * ====================================================================== */

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Condvar;
    use std::thread;

    /* ---------------- 假原语 ---------------- */

    /// 阻塞闸门：用于把过渡/对账挂在系统调用中途，构造并发与取代场景
    struct Gate {
        open: Mutex<bool>,
        condvar: Condvar,
    }

    impl Gate {
        fn new() -> Self {
            Gate {
                open: Mutex::new(false),
                condvar: Condvar::new(),
            }
        }

        fn wait(&self) {
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.condvar.wait(open).unwrap();
            }
        }

        fn open(&self) {
            let mut open = self.open.lock().unwrap();
            *open = true;
            self.condvar.notify_all();
        }
    }

    /// 可控窗口亲和性假实现
    struct FakeOps {
        state: Mutex<HashMap<isize, u32>>,
        fail_set: Mutex<HashSet<isize>>,
        fail_set_value: Mutex<HashSet<(isize, u32)>>,
        fail_get: Mutex<HashSet<isize>>,
        ignore_set: Mutex<HashSet<isize>>,
        set_log: Mutex<Vec<(isize, u32)>>,
        protection: u32,
        block_hwnd: Mutex<Option<isize>>,
        gate: Gate,
    }

    impl FakeOps {
        fn new(entries: &[(isize, u32)], protection: u32) -> Self {
            let mut state = HashMap::new();
            for (hwnd, value) in entries {
                state.insert(*hwnd, *value);
            }
            FakeOps {
                state: Mutex::new(state),
                fail_set: Mutex::new(HashSet::new()),
                fail_set_value: Mutex::new(HashSet::new()),
                fail_get: Mutex::new(HashSet::new()),
                ignore_set: Mutex::new(HashSet::new()),
                set_log: Mutex::new(Vec::new()),
                protection,
                block_hwnd: Mutex::new(None),
                gate: Gate::new(),
            }
        }

        fn block_on(&self, hwnd: isize) {
            *self.block_hwnd.lock().unwrap() = Some(hwnd);
        }

        fn open_gate(&self) {
            self.gate.open();
        }

        fn fail_set_on(&self, hwnd: isize) {
            self.fail_set.lock().unwrap().insert(hwnd);
        }

        /// 只让"写回指定取值"失败：用于构造"设置成功但还原失败"的场景
        fn fail_set_value_on(&self, hwnd: isize, value: u32) {
            self.fail_set_value.lock().unwrap().insert((hwnd, value));
        }

        fn fail_get_on(&self, hwnd: isize) {
            self.fail_get.lock().unwrap().insert(hwnd);
        }

        fn ignore_set_on(&self, hwnd: isize) {
            self.ignore_set.lock().unwrap().insert(hwnd);
        }

        fn value_of(&self, hwnd: isize) -> u32 {
            *self.state.lock().unwrap().get(&hwnd).unwrap_or(&0)
        }

        fn set_calls(&self) -> Vec<(isize, u32)> {
            self.set_log.lock().unwrap().clone()
        }

        fn clear_set_log(&self) {
            self.set_log.lock().unwrap().clear();
        }
    }

    impl AffinityOps for FakeOps {
        fn get(&self, hwnd: isize) -> Result<u32, String> {
            if self.fail_get.lock().unwrap().contains(&hwnd) {
                return Err("注入：读取失败".into());
            }
            Ok(self.value_of(hwnd))
        }

        fn set(&self, hwnd: isize, value: u32) -> Result<(), String> {
            self.set_log.lock().unwrap().push((hwnd, value));
            if self.block_hwnd.lock().unwrap().is_some_and(|v| v == hwnd) {
                self.gate.wait();
            }
            if self.fail_set.lock().unwrap().contains(&hwnd) {
                return Err("注入：设置失败".into());
            }
            if self
                .fail_set_value
                .lock()
                .unwrap()
                .contains(&(hwnd, value))
            {
                return Err("注入：该取值的写入失败".into());
            }
            if !self.ignore_set.lock().unwrap().contains(&hwnd) {
                self.state.lock().unwrap().insert(hwnd, value);
            }
            Ok(())
        }

        fn protection_value(&self) -> u32 {
            self.protection
        }
    }

    /* ---------------- 假审计出口 ---------------- */

    struct RecordedEvent {
        detail: String,
        extensions: AuditExtensions,
    }

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<RecordedEvent>>,
    }

    impl RecordingSink {
        fn count(&self) -> usize {
            self.events.lock().unwrap().len()
        }

        fn details(&self) -> Vec<String> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .map(|event| event.detail.clone())
                .collect()
        }

        fn last_extensions(&self) -> AuditExtensions {
            let events = self.events.lock().unwrap();
            events
                .last()
                .map(|event| event.extensions.clone())
                .unwrap_or_default()
        }
    }

    impl AuditSink for RecordingSink {
        fn write(
            &self,
            _event: AuditEventType,
            _result: AuditResult,
            detail: String,
            extensions: AuditExtensions,
        ) {
            self.events.lock().unwrap().push(RecordedEvent {
                detail,
                extensions,
            });
        }
    }

    /* ---------------- 构建辅助 ---------------- */

    const WIN_A: isize = 0x1001;
    const WIN_B: isize = 0x1002;

    fn build(
        entries: &[(isize, u32)],
        protection: u32,
    ) -> (Arc<PrivacyCoordinator>, Arc<FakeOps>, Arc<RecordingSink>) {
        let ops = Arc::new(FakeOps::new(entries, protection));
        let sink = Arc::new(RecordingSink::default());
        let coordinator = Arc::new(PrivacyCoordinator::with_ops(ops.clone(), sink.clone()));
        (coordinator, ops, sink)
    }

    fn targets() -> Vec<WindowTarget> {
        vec![
            WindowTarget {
                label: "main".into(),
                hwnd: WIN_A,
            },
            WindowTarget {
                label: "viewer".into(),
                hwnd: WIN_B,
            },
        ]
    }

    /// 把状态机强行置为过渡态（构造卡死与被取代场景）
    fn force_transitioning(coordinator: &PrivacyCoordinator, elapsed_secs: u64) {
        let mut inner = coordinator.lock();
        inner.next_transition_id += 1;
        inner.state = PrivacyState::Transitioning {
            transition_id: inner.next_transition_id,
            target: false,
            previous: StableState::Enabled,
            started_at: Instant::now() - Duration::from_secs(elapsed_secs),
        };
    }

    /// 把状态机强行置为隔离态（构造对账场景）
    fn force_quarantine(
        coordinator: &PrivacyCoordinator,
        previous: StableState,
        stuck: Vec<WindowSnapshot>,
    ) {
        let mut inner = coordinator.lock();
        inner.state = PrivacyState::Quarantined {
            previous,
            reason: QuarantineReason::RollbackFailed,
            stuck,
        };
    }

    fn enable(coordinator: &PrivacyCoordinator, targets: &[WindowTarget]) -> String {
        let outcome = coordinator
            .transition(true, None, targets)
            .expect("开启应成功");
        outcome.session_token.expect("开启应返回凭证")
    }

    /* ---------------- 凭证槽位 ---------------- */

    #[test]
    fn test_slot_rotate_only_from_empty() {
        let mut slot = TokenSlot::new();
        assert!(slot.rotate().is_ok());
        assert_eq!(slot.rotate().unwrap_err(), PrivacyError::TokenInvariantViolation);
    }

    #[test]
    fn test_slot_consumed_token_cannot_be_reused() {
        let mut slot = TokenSlot::new();
        let (token, _) = slot.rotate().unwrap();
        let lease = slot.verify(&token).unwrap();
        assert!(slot.commit(&lease).is_ok());
        assert_eq!(slot.state_name(), "empty");
        assert_eq!(slot.verify(&token).unwrap_err(), PrivacyError::TokenInvalid);
    }

    #[test]
    fn test_slot_release_allows_retry_with_same_generation() {
        let mut slot = TokenSlot::new();
        let (token, generation) = slot.rotate().unwrap();
        let lease = slot.verify(&token).unwrap();
        slot.release(&lease);

        let retry = slot.verify(&token).expect("释放后应可重试");
        assert_eq!(retry.generation, generation, "释放不改变世代");
        assert!(slot.commit(&retry).is_ok());
    }

    #[test]
    fn test_slot_lease_held_is_distinct_error() {
        let mut slot = TokenSlot::new();
        let (token, _) = slot.rotate().unwrap();
        let _lease = slot.verify(&token).unwrap();
        assert_eq!(slot.verify(&token).unwrap_err(), PrivacyError::LeaseHeld);
    }

    #[test]
    fn test_slot_cross_generation_commit_expired() {
        let mut slot = TokenSlot::new();
        let (token, _) = slot.rotate().unwrap();
        let lease = slot.verify(&token).unwrap();
        slot.mark_pending_adoption();
        slot.adopt().unwrap();
        assert_eq!(slot.commit(&lease).unwrap_err(), PrivacyError::LeaseExpired);
    }

    #[test]
    fn test_slot_adopt_semantics() {
        let mut slot = TokenSlot::new();
        assert_eq!(slot.adopt().unwrap_err(), PrivacyError::NotRestored);

        slot.mark_pending_adoption();
        let (token, _) = slot.adopt().expect("待采纳应可采纳");
        assert_eq!(slot.state_name(), "active");
        assert_eq!(slot.adopt().unwrap_err(), PrivacyError::AlreadyAdopted);
        assert!(slot.verify(&token).is_ok());
    }

    #[test]
    fn test_slot_generation_monotonic_across_empty() {
        let mut slot = TokenSlot::new();
        let (token, first) = slot.rotate().unwrap();
        let lease = slot.verify(&token).unwrap();
        slot.commit(&lease).unwrap();

        let (_, second) = slot.rotate().unwrap();
        assert!(second > first, "世代号跨空态不得回退");
    }

    /* ---------------- 原子应用与回滚 ---------------- */

    #[test]
    fn test_enable_applies_and_issues_token() {
        let (coordinator, ops, _sink) = build(&[(WIN_A, 0), (WIN_B, 0)], 0x11);
        let token = enable(&coordinator, &targets());

        assert!(!token.is_empty());
        assert_eq!(ops.value_of(WIN_A), 0x11);
        assert_eq!(ops.value_of(WIN_B), 0x11);
        let snapshot = coordinator.status();
        assert_eq!(snapshot.state, "enabled");
        assert_eq!(snapshot.slot, "active");
        assert_eq!(snapshot.protected_count, 2);
    }

    #[test]
    fn test_enable_idempotent_when_already_enabled() {
        let (coordinator, ops, _sink) = build(&[(WIN_A, 0), (WIN_B, 0)], 0x11);
        let target = targets();
        let _ = enable(&coordinator, &target);
        ops.clear_set_log();

        let outcome = coordinator.transition(true, None, &target).unwrap();
        assert!(outcome.idempotent);
        assert!(outcome.session_token.is_none(), "幂等短路不签发新凭证");
        assert!(ops.set_calls().is_empty(), "幂等短路不重复施加系统调用");
    }

    #[test]
    fn test_enable_failure_restores_snapshot_original() {
        // 窗口 A 原值为"仅监视器"：还原必须回到该实际取值，而不是"无保护"
        let (coordinator, ops, _sink) = build(&[(WIN_A, 0x01), (WIN_B, 0)], 0x11);
        ops.fail_set_on(WIN_B);

        let error = coordinator.transition(true, None, &targets()).unwrap_err();
        assert_eq!(error.code(), "PRIVACY_ROLLED_BACK");
        assert_eq!(ops.value_of(WIN_A), 0x01, "还原到快照原值");
        assert_eq!(coordinator.status().state, "disabled");
    }

    #[test]
    fn test_verify_mismatch_rolls_back() {
        // 窗口 B 的设置静默无效：回读不匹配必须触发还原
        let (coordinator, ops, sink) = build(&[(WIN_A, 0), (WIN_B, 0)], 0x11);
        ops.ignore_set_on(WIN_B);

        let error = coordinator.transition(true, None, &targets()).unwrap_err();
        assert_eq!(error.code(), "PRIVACY_ROLLED_BACK");
        assert_eq!(ops.value_of(WIN_A), 0x00);
        assert!(
            sink.details().iter().any(|d| d.contains("已还原")),
            "还原必须留审计"
        );
    }

    #[test]
    fn test_rollback_failure_quarantines_with_stuck() {
        let (coordinator, ops, sink) = build(&[(WIN_A, 0), (WIN_B, 0)], 0x11);
        ops.fail_set_on(WIN_B);
        // A 的保护设置成功，但"写回原值"失败 → 还原失败，窗口现场不可信
        ops.fail_set_value_on(WIN_A, 0x00);

        let error = coordinator.transition(true, None, &targets()).unwrap_err();
        assert_eq!(error.code(), "PRIVACY_QUARANTINED");

        let snapshot = coordinator.status();
        assert_eq!(snapshot.state, "quarantined");
        assert_eq!(snapshot.quarantined_reason, Some("rollback_failed"));
        assert_eq!(sink.last_extensions().stuck_windows, Some(1));
    }

    /* ---------------- 关闭路径 ---------------- */

    #[test]
    fn test_disable_consumes_token_and_clears() {
        let (coordinator, ops, _sink) = build(&[(WIN_A, 0), (WIN_B, 0)], 0x11);
        let target = targets();
        let token = enable(&coordinator, &target);

        let outcome = coordinator
            .transition(false, Some(&token), &target)
            .expect("关闭应成功");
        assert!(!outcome.enabled);
        assert_eq!(ops.value_of(WIN_A), 0);
        let snapshot = coordinator.status();
        assert_eq!(snapshot.state, "disabled");
        assert_eq!(snapshot.slot, "empty");

        // 已关闭状态下重复关闭：幂等短路直接成功，不产生错误
        let again = coordinator.transition(false, None, &target).unwrap();
        assert!(again.idempotent);
    }

    #[test]
    fn test_disable_failure_releases_lease_and_retry_works() {
        let (coordinator, ops, _sink) = build(&[(WIN_A, 0), (WIN_B, 0)], 0x11);
        let target = targets();
        let token = enable(&coordinator, &target);

        ops.fail_set_on(WIN_A);
        let error = coordinator
            .transition(false, Some(&token), &target)
            .unwrap_err();
        assert_eq!(error.code(), "PRIVACY_ROLLED_BACK");
        assert_eq!(coordinator.status().state, "enabled");
        assert_eq!(coordinator.status().slot, "active", "失败后槽位保留供重试");
        assert_eq!(ops.value_of(WIN_B), 0x11, "还原后引擎窗口仍受保护");

        // 同一凭证立即重试成功（历史缺陷：校验即消费导致必须重启）
        ops.fail_set.lock().unwrap().clear();
        let outcome = coordinator
            .transition(false, Some(&token), &target)
            .expect("失败后可重试");
        assert!(!outcome.enabled);
    }

    #[test]
    fn test_disable_requires_valid_token() {
        let (coordinator, _ops, _sink) = build(&[(WIN_A, 0)], 0x11);
        let target = vec![WindowTarget {
            label: "main".into(),
            hwnd: WIN_A,
        }];
        let token = enable(&coordinator, &target);

        assert_eq!(
            coordinator.transition(false, None, &target).unwrap_err(),
            PrivacyError::TokenMissing
        );
        assert_eq!(
            coordinator
                .transition(false, Some("wrong-token"), &target)
                .unwrap_err(),
            PrivacyError::TokenInvalid
        );
        assert!(coordinator
            .transition(false, Some(&token), &target)
            .is_ok());
    }

    /* ---------------- 并发、看门狗与取代 ---------------- */

    #[test]
    fn test_concurrent_transition_returns_busy() {
        let (coordinator, _ops, _sink) = build(&[(WIN_A, 0)], 0x11);
        force_transitioning(&coordinator, 0);
        assert_eq!(
            coordinator
                .transition(true, None, &targets())
                .unwrap_err(),
            PrivacyError::Busy
        );
    }

    #[test]
    fn test_watchdog_reaps_stuck_transition_to_quarantine() {
        let (coordinator, _ops, sink) = build(&[(WIN_A, 0)], 0x11);
        force_transitioning(&coordinator, 60);

        let snapshot = coordinator.status();
        assert_eq!(snapshot.state, "quarantined");
        assert_eq!(snapshot.quarantined_reason, Some("stuck_in_transition"));
        assert!(
            sink.details().iter().any(|d| d.contains("卡死")),
            "收尸必须留审计"
        );
    }

    #[test]
    fn test_superseded_transition_does_not_override_and_releases_lease() {
        let (coordinator, ops, sink) = build(&[(WIN_A, 0), (WIN_B, 0)], 0x11);
        let target = targets();
        let token = enable(&coordinator, &target);
        ops.clear_set_log();
        ops.block_on(WIN_A);

        let thread_coordinator = Arc::clone(&coordinator);
        let thread_token = token.clone();
        let thread_target = target.clone();
        let worker = thread::spawn(move || {
            thread_coordinator.transition(false, Some(&thread_token), &thread_target)
        });

        // 等待过渡进入系统调用，然后把它的起始时刻推老并触发收尸
        while ops.set_calls().is_empty() {
            thread::sleep(Duration::from_millis(5));
        }
        {
            let mut inner = coordinator.lock();
            if let PrivacyState::Transitioning { started_at, .. } = &mut inner.state {
                *started_at = Instant::now() - Duration::from_secs(60);
            }
        }
        assert_eq!(coordinator.status().state, "quarantined");

        ops.open_gate();
        let error = worker.join().unwrap().unwrap_err();
        assert_eq!(error, PrivacyError::TransitionSuperseded);

        // 状态未被过期任务覆盖；未决租约已释放，凭证可再次校验
        assert_eq!(coordinator.status().state, "quarantined");
        {
            let mut inner = coordinator.lock();
            match &mut inner.state {
                PrivacyState::Quarantined { .. } => {}
                other => panic!("状态被过期任务覆盖: {}", other.state_name()),
            }
            let lease = inner
                .slot
                .verify(&token)
                .expect("取代路径必须释放未决租约");
            inner.slot.release(&lease);
        }
        assert!(sink
            .details()
            .iter()
            .any(|d| d.contains("取代")));
    }

    /* ---------------- 隔离与对账 ---------------- */

    #[test]
    fn test_reconcile_rescans_all_windows() {
        let (coordinator, ops, sink) = build(&[(WIN_A, 0), (WIN_B, 0)], 0x11);
        let _ = enable(&coordinator, &targets());
        force_quarantine(
            &coordinator,
            StableState::Enabled,
            vec![WindowSnapshot {
                label: "viewer".into(),
                hwnd: WIN_B,
                original: 0,
            }],
        );
        ops.clear_set_log();

        let outcome = coordinator.reconcile(&targets()).expect("对账应成功");
        assert!(outcome.enabled);

        // 全窗口重扫：未列入失败清单的窗口同样被重新加固
        let calls = ops.set_calls();
        assert!(calls.iter().any(|(hwnd, value)| *hwnd == WIN_A && *value == 0x11));
        assert!(calls.iter().any(|(hwnd, value)| *hwnd == WIN_B && *value == 0x11));
        assert_eq!(ops.value_of(WIN_A), 0x11);

        let snapshot = coordinator.status();
        assert_eq!(snapshot.state, "enabled");
        assert_eq!(snapshot.slot, "pending_adoption", "对账后等待前端再次接管");
        assert!(sink.details().iter().any(|d| d.contains("对账完成")));
    }

    #[test]
    fn test_reconcile_to_disabled_clears_residue_and_slot() {
        let (coordinator, ops, _sink) = build(&[(WIN_A, 0x11), (WIN_B, 0x11)], 0x11);
        force_quarantine(&coordinator, StableState::Disabled, Vec::new());
        // 隔离前的槽位残留：对账到关闭必须清空
        coordinator.lock().slot.mark_pending_adoption();

        let outcome = coordinator.reconcile(&targets()).expect("对账应成功");
        assert!(!outcome.enabled);
        assert_eq!(ops.value_of(WIN_A), 0);
        assert_eq!(ops.value_of(WIN_B), 0);
        let snapshot = coordinator.status();
        assert_eq!(snapshot.state, "disabled");
        assert_eq!(snapshot.slot, "empty");
    }

    #[test]
    fn test_reconcile_not_quarantined_returns_error() {
        let (coordinator, _ops, _sink) = build(&[(WIN_A, 0)], 0x11);
        assert_eq!(
            coordinator.reconcile(&targets()).unwrap_err(),
            PrivacyError::NotQuarantined
        );
    }

    #[test]
    fn test_reconcile_concurrent_second_returns_busy() {
        let (coordinator, ops, _sink) = build(&[(WIN_A, 0x11), (WIN_B, 0x11)], 0x11);
        force_quarantine(&coordinator, StableState::Enabled, Vec::new());
        ops.block_on(WIN_A);

        let thread_coordinator = Arc::clone(&coordinator);
        let worker = thread::spawn(move || thread_coordinator.reconcile(&targets()));

        while ops.set_calls().is_empty() {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            coordinator.reconcile(&targets()).unwrap_err(),
            PrivacyError::Busy,
            "对账同样单飞"
        );

        ops.open_gate();
        assert!(worker.join().unwrap().is_ok());
    }

    #[test]
    fn test_reconcile_failure_keeps_quarantine() {
        let (coordinator, ops, sink) = build(&[(WIN_A, 0x11)], 0x11);
        force_quarantine(&coordinator, StableState::Enabled, Vec::new());
        ops.fail_set_on(WIN_A);

        let error = coordinator.reconcile(&targets()).unwrap_err();
        assert_eq!(error.code(), "PRIVACY_TEMPORARY_FAILURE");
        let snapshot = coordinator.status();
        assert_eq!(snapshot.state, "quarantined");
        assert_eq!(snapshot.quarantined_reason, Some("reconcile_failed"));
        assert!(sink.details().iter().any(|d| d.contains("对账失败")));
    }

    /* ---------------- 启动序列与采纳 ---------------- */

    #[test]
    fn test_startup_protect_marks_pending_adoption() {
        let (coordinator, ops, sink) = build(&[(WIN_A, 0), (WIN_B, 0)], 0x11);
        let generation = coordinator.startup_protect(&targets()).expect("启动保护应成功");

        assert_eq!(ops.value_of(WIN_A), 0x11);
        let snapshot = coordinator.status();
        assert_eq!(snapshot.state, "enabled");
        assert_eq!(snapshot.slot, "pending_adoption");
        assert_eq!(sink.last_extensions().generation, Some(generation));

        let (token, adopted) = coordinator.adopt().expect("采纳应成功");
        assert!(adopted >= generation);
        assert!(!token.is_empty());
        assert_eq!(coordinator.status().slot, "active");
    }

    #[test]
    fn test_adopt_requires_pending_state() {
        let (coordinator, _ops, _sink) = build(&[(WIN_A, 0)], 0x11);
        assert_eq!(coordinator.adopt().unwrap_err(), PrivacyError::NotRestored);

        coordinator.startup_protect(&targets()).unwrap();
        coordinator.adopt().unwrap();
        assert_eq!(
            coordinator.adopt().unwrap_err(),
            PrivacyError::AlreadyAdopted
        );
    }

    #[test]
    fn test_adopt_rejects_transitioning_and_quarantined() {
        let (coordinator, _ops, _sink) = build(&[(WIN_A, 0)], 0x11);
        coordinator.startup_protect(&targets()).unwrap();

        force_transitioning(&coordinator, 0);
        assert_eq!(
            coordinator.adopt().unwrap_err(),
            PrivacyError::Busy,
            "过渡中没有可接管的稳定会话，采纳必须被拒绝"
        );

        force_quarantine(&coordinator, StableState::Enabled, Vec::new());
        assert_eq!(
            coordinator.adopt().unwrap_err(),
            PrivacyError::Quarantined,
            "隔离态仅对账可达，采纳必须被拒绝"
        );
    }

    #[test]
    fn test_startup_protect_failure_rolls_back_to_unprotected() {
        let (coordinator, ops, _sink) = build(&[(WIN_A, 0), (WIN_B, 0)], 0x11);
        ops.fail_set_on(WIN_B);

        let error = coordinator.startup_protect(&targets()).unwrap_err();
        assert_eq!(error.code(), "PRIVACY_ROLLED_BACK");
        let snapshot = coordinator.status();
        assert_eq!(snapshot.state, "disabled", "已还原：如实显示未保护");
        assert_eq!(snapshot.slot, "empty");
    }

    #[test]
    fn test_startup_protect_rollback_failure_quarantines() {
        let (coordinator, ops, _sink) = build(&[(WIN_A, 0), (WIN_B, 0)], 0x11);
        ops.fail_set_on(WIN_B);
        ops.fail_set_value_on(WIN_A, 0x00);

        assert_eq!(
            coordinator.startup_protect(&targets()).unwrap_err(),
            PrivacyError::Quarantined
        );
        let snapshot = coordinator.status();
        assert_eq!(snapshot.state, "quarantined");
        assert_eq!(snapshot.quarantined_reason, Some("rollback_failed"));
    }

    /* ---------------- 合法状态组合 ---------------- */

    #[test]
    fn test_consistency_violation_quarantines() {
        let (coordinator, _ops, _sink) = build(&[(WIN_A, 0)], 0x11);
        {
            let mut inner = coordinator.lock();
            inner.state = PrivacyState::Enabled {
                generation: 7,
                protected: Vec::new(),
            };
            inner.slot.reset_to_empty();
        }
        let snapshot = coordinator.status();
        assert_eq!(snapshot.state, "quarantined");
        assert_eq!(snapshot.quarantined_reason, Some("token_invariant_violation"));
    }
}