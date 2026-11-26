/*
 * 隐私保护协调器
 *
 * 职责边界：模式切换（整体成功或整体失败）、开启时签发一次性凭证、
 * 关闭时校验并消费凭证、过渡世代校验、隔离进入与对账收敛。系统调用在
 * 锁外或阻塞池执行，锁只覆盖首尾两段状态读写。
 */

use crate::util::audit_log::{AuditEventType, AuditExtensions, AuditResult};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use super::*;
/* ====================================================================== *
 *  协调器                                                                 *
 * ====================================================================== */

pub struct PrivacyCoordinator {
    pub(super) inner: Mutex<Inner>,
    pub(super) ops: Arc<dyn AffinityOps>,
    pub(super) audit: Arc<dyn AuditSink>,
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
    pub(super) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 卡死收尸：过渡任务若异常终止而未落状态，状态机会停在过渡态；
    /// 在下一次读取或操作时转入隔离（不做后台轮询），并写审计留痕
    pub(super) fn reap_stuck(&self, inner: &mut Inner) {
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
    pub(super) fn enforce_consistency_locked(inner: &mut Inner) -> Result<(), PrivacyError> {
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
                                format!("开启成功后签发凭证失败，进入隔离（{}）", cause.detail()),
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
                        AuditExtensions::default().transition(my_id).rollback(true),
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
    pub(super) fn apply_atomic(
        &self,
        targets: &[WindowTarget],
        value: u32,
    ) -> Result<ApplySuccess, ApplyFailure> {
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
    pub(super) fn rollback_to_snapshot(
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
    pub(super) fn force_to_baseline(&self, targets: &[WindowTarget], value: u32) -> Result<(), PrivacyError> {
        if targets.is_empty() {
            return Err(PrivacyError::NoTargetWindow);
        }
        for target in targets {
            let step = self
                .ops
                .set(target.hwnd, value)
                .and_then(|_| self.ops.get(target.hwnd));
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

pub(super) struct ApplySuccess {
    applied: Vec<WindowTarget>,
    readback: u32,
}

pub(super) struct ApplyFailure {
    cause: PrivacyError,
    rollback_failed: bool,
    stuck: Vec<WindowSnapshot>,
}
