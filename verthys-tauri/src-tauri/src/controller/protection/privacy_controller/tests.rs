/*
 * privacy_controller 单元测试
 *
 * 通过注入的亲和性出口与审计出口做确定性测试：窗口读写、失败注入、
 * 并发过渡、卡死收尸与对账重扫均可在无窗口环境下复现。
 */
use super::*;
use crate::util::audit_log::{AuditEventType, AuditExtensions, AuditResult};
use std::sync::{Arc, Mutex};
use std::time::Instant;
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
        if self.fail_set_value.lock().unwrap().contains(&(hwnd, value)) {
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
        self.events
            .lock()
            .unwrap()
            .push(RecordedEvent { detail, extensions });
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
    assert_eq!(
        slot.rotate().unwrap_err(),
        PrivacyError::TokenInvariantViolation
    );
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

    // 同一凭证立即重试成功（校验不消费凭证）
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
    assert!(coordinator.transition(false, Some(&token), &target).is_ok());
}

/* ---------------- 并发、看门狗与取代 ---------------- */

#[test]
fn test_concurrent_transition_returns_busy() {
    let (coordinator, _ops, _sink) = build(&[(WIN_A, 0)], 0x11);
    force_transitioning(&coordinator, 0);
    assert_eq!(
        coordinator.transition(true, None, &targets()).unwrap_err(),
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
        let lease = inner.slot.verify(&token).expect("取代路径必须释放未决租约");
        inner.slot.release(&lease);
    }
    assert!(sink.details().iter().any(|d| d.contains("取代")));
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
    assert!(calls
        .iter()
        .any(|(hwnd, value)| *hwnd == WIN_A && *value == 0x11));
    assert!(calls
        .iter()
        .any(|(hwnd, value)| *hwnd == WIN_B && *value == 0x11));
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
    let generation = coordinator
        .startup_protect(&targets())
        .expect("启动保护应成功");

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
    assert_eq!(
        snapshot.quarantined_reason,
        Some("token_invariant_violation")
    );
}
