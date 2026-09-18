/*
 * state/key_lifecycle.rs — 密钥生命周期状态机 + 指数冷却失败计数器
 *
 *
 * 架构定位：状态层（state）密钥生命周期模块
 *   - 不依赖任何上层模块（controller / service / repository）
 *   - 仅依赖 std::sync（Mutex）与 std::time（Instant）
 *   - 通过 AppState 持有，控制器通过 AppState 访问
 *
 * 第 5.7 项 — 密钥状态机：
 *   AppState 维护密钥生命周期状态（NoKey / Locked / Unlocked）：
 *     - NoKey:    初始状态，未派生任何密钥
 *     - Locked:   已派生 GMK 但未验证（或已锁定），worker 内存无可用 GMK
 *     - Unlocked: GMK 已验证，worker 内存持有可用 GMK
 *
 *   状态转移规则：
 *     - derive_global_key: 仅 NoKey → Locked（已存在密钥拒绝重复派生）
 *     - verify_global_key: 仅 Locked → Unlocked（未派生拒绝验证）
 *     - clear_global_key:  Unlocked → Locked（lockAll 时调用）
 *     - worker_destroy:    Any → NoKey（worker 销毁，密钥随之消失）
 *
 *   状态不匹配返回 ErrorCode::KeyStateMismatch，防止非法操作序列。
 *
 * 第 5.3 项 — verify_global_key 入口失败计数器：
 *   - 基于 Instant（monotonic clock），不受系统时间篡改影响
 *   - 连续失败 5 次触发指数冷却：2^(failures - 5) 秒（2s/4s/8s/16s/32s 上限 60s）
 *   - 冷却期内拒绝 verify_global_key 请求，返回 ErrorCode::RateLimited
 *   - 成功验证重置计数器
 *   - 与 brute_force.rs 联动（阶段 7）：阶段 7 将本计数器状态持久化到 DPAPI，
 *     并与 BruteForceGuard 共享失败计数（连续 10 次触发界面锁定，累计 20 次清空索引）
 *
 * CI 红线：
 *   - 状态机转移必须原子（持锁期间完成检查 + 转移）
 *   - 冷却时间计算基于 monotonic clock，不受系统时间篡改影响
 *   - 失败计数不输出日志（防侧信道泄露当前状态）
 */

use std::sync::Mutex;
use std::time::{Duration, Instant};

/* ------------------------------------------------------------------ *
 * 第 5.7 项：密钥生命周期状态枚举                                     *
 * ------------------------------------------------------------------ */

/// 密钥生命周期状态（第 5.7 项）
///
/// 表示 worker 子进程中全局主密钥 GMK 的当前状态。
/// 所有密钥操作必须匹配当前状态，否则返回 KeyStateMismatch。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLifecycleState {
    /// 初始状态：未派生任何密钥
    ///
    /// 仅允许 derive_global_key（→ Locked）。
    /// verify_global_key / clear_global_key / derive_subkey 均拒绝。
    NoKey,
    /// 已派生但未验证（或已锁定）：worker 内存无可用 GMK
    ///
    /// 仅允许 verify_global_key（→ Unlocked）。
    /// derive_global_key 拒绝（已存在密钥）。
    /// clear_global_key 允许（保持 Locked，无副作用）。
    Locked,
    /// 已验证：worker 内存持有可用 GMK
    ///
    /// 仅允许 clear_global_key（→ Locked）与 derive_subkey。
    /// derive_global_key 拒绝（已存在密钥）。
    /// verify_global_key 拒绝（已验证无需重复）。
    Unlocked,
}

impl KeyLifecycleState {
    /// 状态名称（用于日志，不含敏感信息）
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyLifecycleState::NoKey => "NoKey",
            KeyLifecycleState::Locked => "Locked",
            KeyLifecycleState::Unlocked => "Unlocked",
        }
    }
}

impl std::fmt::Display for KeyLifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/* ------------------------------------------------------------------ *
 * 第 5.3 项：指数冷却失败计数器                                       *
 * ------------------------------------------------------------------ */

/// 触发冷却的连续失败次数阈值（第 5.3 项：超 5 次指数冷却）
const COOLDOWN_THRESHOLD: u32 = 5;

/// 冷却时间上限（60 秒，防止指数膨胀过长阻塞用户）
const COOLDOWN_MAX_SECS: u64 = 60;

/// 冷却时间基数（2 秒，指数底数）
const COOLDOWN_BASE_SECS: u64 = 2;

/// 计算指数冷却时长（第 5.3 项）
///
/// 公式：cooldown = min(COOLDOWN_BASE_SECS * 2^(excess - 1), COOLDOWN_MAX_SECS)
///
/// 超阈值次数与冷却时长对照：
///   excess=1 → 2s
///   excess=2 → 4s
///   excess=3 → 8s
///   excess=4 → 16s
///   excess=5 → 32s
///   excess=6+ → 60s（上限）
fn compute_cooldown(excess_failures: u32) -> Duration {
    if excess_failures == 0 {
        return Duration::ZERO;
    }
    // 2^(excess_failures - 1) 防溢出：excess_failures ≤ 30 时安全
    // 使用 1u64 << exponent 计算 2^exponent（而非 2u64 << exponent，后者等于 2^(exponent+1)）
    let exponent = excess_failures.saturating_sub(1).min(30);
    let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
    let secs = COOLDOWN_BASE_SECS
        .saturating_mul(multiplier)
        .min(COOLDOWN_MAX_SECS);
    Duration::from_secs(secs)
}

/* ------------------------------------------------------------------ *
 * KeyLifecycle — 密钥生命周期状态机 + 失败计数器                      *
 * ------------------------------------------------------------------ */

/// 密钥生命周期状态机（第 5.7 项 + 第 5.3 项）
///
/// 持有当前密钥状态 + verify_global_key 失败计数器 + 冷却截止时间。
/// 通过 AppState 持有，控制器通过 AppState::lock_key_lifecycle() 访问。
///
/// 线程安全：
///   - inner: Mutex 保护，短暂持锁（状态检查 + 转移原子完成）
///   - 冷却时间基于 Instant（monotonic clock），不受系统时间篡改影响
///
/// 中毒处理（第 11.5 项）：
///   Mutex 中毒时 into_inner() 取出废弃，重置为默认状态（NoKey + 零计数），
///   记录严重告警。由 AppState::lock_key_lifecycle() 统一处理。
pub struct KeyLifecycle {
    inner: Mutex<KeyLifecycleInner>,
}

struct KeyLifecycleInner {
    /// 当前密钥状态
    state: KeyLifecycleState,
    /// verify_global_key 连续失败次数（成功后重置为 0）
    consecutive_failures: u32,
    /// 冷却截止时间（None=未冷却，Some=冷却至该时刻）
    cooldown_until: Option<Instant>,
}

impl Default for KeyLifecycleInner {
    fn default() -> Self {
        KeyLifecycleInner {
            state: KeyLifecycleState::NoKey,
            consecutive_failures: 0,
            cooldown_until: None,
        }
    }
}

/// verify 操作的预检查结果（第 5.3 项）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyCheckResult {
    /// 允许尝试验证
    Allow,
    /// 冷却中，剩余秒数
    Cooldown(u64),
}

/// verify 操作的结果反馈（第 5.3 项）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyAttemptResult {
    /// 验证成功（状态已转移为 Unlocked，计数器已重置）
    Success,
    /// 验证失败但未触发冷却
    Failure,
    /// 验证失败并触发冷却（剩余冷却秒数）
    FailureCooldown(u64),
}

impl KeyLifecycle {
    /// 创建新的密钥生命周期状态机（初始状态 NoKey）
    pub fn new() -> Self {
        KeyLifecycle {
            inner: Mutex::new(KeyLifecycleInner::default()),
        }
    }

    /// 获取当前密钥状态（第 5.7 项）
    pub fn current_state(&self) -> KeyLifecycleState {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.state
    }

    /* ----------------------------------------------------------------
     * 第 5.7 项：状态转移方法                                          *
     *                                                                *
     * 每个方法持锁期间完成：检查当前状态 → 转移到新状态。               *
     * 状态不匹配返回 Err(错误消息)，调用方映射到 ErrorCode。           *
     * ---------------------------------------------------------------- */

    /// 尝试转移到 Locked 状态（derive_global_key 调用）
    ///
    /// 仅 NoKey → Locked 允许。
    /// 已存在密钥（Locked/Unlocked）拒绝重复派生，返回 KeyStateMismatch。
    ///
    /// 返回：
    ///   - Ok(()): 转移成功
    ///   - Err(msg): 状态不匹配（当前状态非 NoKey）
    pub fn transition_to_locked(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match inner.state {
            KeyLifecycleState::NoKey => {
                inner.state = KeyLifecycleState::Locked;
                // 派生成功也重置失败计数（新密钥，旧失败计数无意义）
                inner.consecutive_failures = 0;
                inner.cooldown_until = None;
                Ok(())
            }
            _ => Err(format!(
                "密钥状态不匹配：derive_global_key 仅允许 NoKey 状态，当前为 {}",
                inner.state
            )),
        }
    }

    /// 尝试转移到 Unlocked 状态（verify_global_key 成功时调用）
    ///
    /// 仅 Locked → Unlocked 允许。
    /// NoKey 拒绝（未派生），Unlocked 拒绝（已验证）。
    ///
    /// 返回：
    ///   - Ok(()): 转移成功
    ///   - Err(msg): 状态不匹配
    pub fn transition_to_unlocked(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match inner.state {
            KeyLifecycleState::Locked => {
                inner.state = KeyLifecycleState::Unlocked;
                // 验证成功重置失败计数（第 5.3 项）
                inner.consecutive_failures = 0;
                inner.cooldown_until = None;
                Ok(())
            }
            KeyLifecycleState::NoKey => Err(
                "密钥状态不匹配：verify_global_key 仅允许 Locked 状态，当前为 NoKey（未派生密钥）"
                    .into(),
            ),
            KeyLifecycleState::Unlocked => Err(
                "密钥状态不匹配：verify_global_key 仅允许 Locked 状态，当前为 Unlocked（已验证）"
                    .into(),
            ),
        }
    }

    /// 尝试转移到 Locked 状态（clear_global_key / lockAll 调用）
    ///
    /// Unlocked → Locked 允许。
    /// NoKey / Locked 允许（无副作用，保持原状态）。
    ///
    /// clear_global_key 是幂等操作，任何状态调用都成功。
    pub fn transition_to_locked_from_unlocked(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.state == KeyLifecycleState::Unlocked {
            inner.state = KeyLifecycleState::Locked;
        }
        // NoKey / Locked 状态保持不变（幂等）
    }

    /// ★ 企业级根治：协调密钥存在状态（reconciliation）
    ///
    /// 用于修正 worker 进程内 probe 与前端迁移后重新校验之间的状态不同步。
    ///
    /// 背景：
    ///   verthys_unlock 时 worker 进程内 probe 通过 find_first_lid_by_type(0x10)
    ///   搜索全局密钥记录。但 TYPE_GLOBAL_KEY(0x10) 与旧 TYPE_ACCOUNT(0x10) 冲突，
    ///   probe 可能命中账户记录 → has_global_key 误判 → key_lifecycle 状态错误。
    ///
    ///   前端 migrateRecordTypes 将旧账户记录重写为 0x02 后重新校验，
    ///   得到正确结果并调用本方法修正后端状态机。
    ///
    /// 转移规则（仅在 NoKey ↔ Locked 之间安全转换）：
    ///   - has_global_key=true  && 当前 NoKey   → Locked（前端确认存在全局密钥记录）
    ///   - has_global_key=false && 当前 Locked  → NoKey（前端确认无全局密钥记录）
    ///   - has_global_key=false && 当前 Unlocked → NoKey（异常 reconciliation，安全降级）
    ///   - 状态已匹配 → 无操作（幂等）
    ///   - has_global_key=true && 当前 Locked/Unlocked → 无操作（已有密钥，保持不变）
    ///
    /// 安全边界：
    ///   - 仅在 initUnlock 关键路径调用（verthysReady=true 之前）
    ///   - 不涉及密钥材料，不接触 worker，仅修正状态机
    ///   - 重置失败计数器（reconciliation 意味着状态被纠正，旧计数无意义）
    pub fn reconcile_key_presence(&self, has_global_key: bool) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if has_global_key {
            // 前端确认存在全局密钥 → NoKey 转 Locked（Locked/Unlocked 保持不变）
            if inner.state == KeyLifecycleState::NoKey {
                inner.state = KeyLifecycleState::Locked;
                inner.consecutive_failures = 0;
                inner.cooldown_until = None;
            }
        } else {
            // 前端确认无全局密钥 → 任何状态转 NoKey
            inner.state = KeyLifecycleState::NoKey;
            inner.consecutive_failures = 0;
            inner.cooldown_until = None;
        }
    }

    /// 重置为 NoKey 状态（worker_destroy 调用）
    ///
    /// 任何状态 → NoKey。worker 销毁后密钥随之消失。
    /// 同时重置失败计数器。
    pub fn reset_to_no_key(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.state = KeyLifecycleState::NoKey;
        inner.consecutive_failures = 0;
        inner.cooldown_until = None;
    }

    /* ----------------------------------------------------------------
     * 第 5.3 项：verify_global_key 失败计数器 + 指数冷却               *
     * ---------------------------------------------------------------- */

    /// 预检查是否允许尝试 verify_global_key（第 5.3 项）
    ///
    /// 在调用 worker 验证前检查：
    ///   1. 当前状态必须为 Locked（否则由 transition 方法拒绝）
    ///   2. 不在冷却期内（否则返回 Cooldown）
    ///
    /// 返回：
    ///   - Allow: 允许尝试验证
    ///   - Cooldown(secs): 冷却中，剩余秒数
    pub fn check_verify_allowed(&self) -> VerifyCheckResult {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(until) = inner.cooldown_until {
            let now = Instant::now();
            if now < until {
                let remaining = (until - now).as_secs();
                return VerifyCheckResult::Cooldown(remaining);
            }
            // 冷却期已过，允许尝试（cooldown_until 由 record_* 清理）
        }

        VerifyCheckResult::Allow
    }

    /// 记录 verify_global_key 成功（第 5.3 项）
    ///
    /// 重置失败计数器 + 转移状态为 Unlocked。
    /// 调用方在 worker 验证成功后调用。
    pub fn record_verify_success(&self) -> Result<(), String> {
        // transition_to_unlocked 内部会重置计数器
        self.transition_to_unlocked()
    }

    /// 记录 verify_global_key 失败（第 5.3 项）
    ///
    /// 递增失败计数，超阈值触发指数冷却。
    /// 调用方在 worker 验证失败后调用。
    ///
    /// 返回：
    ///   - Failure: 失败但未触发冷却
    ///   - FailureCooldown(secs): 失败并触发冷却（剩余冷却秒数）
    pub fn record_verify_failure(&self) -> VerifyAttemptResult {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        inner.consecutive_failures += 1;

        // 超阈值触发指数冷却
        if inner.consecutive_failures > COOLDOWN_THRESHOLD {
            let excess = inner.consecutive_failures - COOLDOWN_THRESHOLD;
            let cooldown = compute_cooldown(excess);
            inner.cooldown_until = Some(Instant::now() + cooldown);
            return VerifyAttemptResult::FailureCooldown(cooldown.as_secs());
        }

        VerifyAttemptResult::Failure
    }

    /// 获取当前连续失败次数（用于 UI 展示与日志）
    pub fn consecutive_failures(&self) -> u32 {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.consecutive_failures
    }

    /// 获取冷却剩余秒数（未冷却返回 0）
    pub fn remaining_cooldown_secs(&self) -> u64 {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(until) = inner.cooldown_until {
            let now = Instant::now();
            if now < until {
                return (until - now).as_secs();
            }
        }
        0
    }
}

impl Default for KeyLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

/* ------------------------------------------------------------------ *
 * 单元测试                                                            *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state_no_key() {
        let lifecycle = KeyLifecycle::new();
        assert_eq!(lifecycle.current_state(), KeyLifecycleState::NoKey);
    }

    #[test]
    fn test_transition_no_key_to_locked() {
        let lifecycle = KeyLifecycle::new();
        assert!(lifecycle.transition_to_locked().is_ok());
        assert_eq!(lifecycle.current_state(), KeyLifecycleState::Locked);
    }

    #[test]
    fn test_derive_rejects_when_already_locked() {
        let lifecycle = KeyLifecycle::new();
        lifecycle.transition_to_locked().unwrap();

        // Locked 状态拒绝重复 derive
        let result = lifecycle.transition_to_locked();
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_rejects_when_unlocked() {
        let lifecycle = KeyLifecycle::new();
        lifecycle.transition_to_locked().unwrap();
        lifecycle.transition_to_unlocked().unwrap();

        // Unlocked 状态拒绝 derive
        let result = lifecycle.transition_to_locked();
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_when_no_key() {
        let lifecycle = KeyLifecycle::new();

        // NoKey 状态拒绝 verify
        let result = lifecycle.transition_to_unlocked();
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_when_already_unlocked() {
        let lifecycle = KeyLifecycle::new();
        lifecycle.transition_to_locked().unwrap();
        lifecycle.transition_to_unlocked().unwrap();

        // Unlocked 状态拒绝重复 verify
        let result = lifecycle.transition_to_unlocked();
        assert!(result.is_err());
    }

    #[test]
    fn test_clear_transitions_unlocked_to_locked() {
        let lifecycle = KeyLifecycle::new();
        lifecycle.transition_to_locked().unwrap();
        lifecycle.transition_to_unlocked().unwrap();
        assert_eq!(lifecycle.current_state(), KeyLifecycleState::Unlocked);

        lifecycle.transition_to_locked_from_unlocked();
        assert_eq!(lifecycle.current_state(), KeyLifecycleState::Locked);
    }

    #[test]
    fn test_clear_idempotent_when_no_key() {
        let lifecycle = KeyLifecycle::new();
        lifecycle.transition_to_locked_from_unlocked();
        assert_eq!(lifecycle.current_state(), KeyLifecycleState::NoKey);
    }

    #[test]
    fn test_reset_to_no_key() {
        let lifecycle = KeyLifecycle::new();
        lifecycle.transition_to_locked().unwrap();
        lifecycle.transition_to_unlocked().unwrap();

        lifecycle.reset_to_no_key();
        assert_eq!(lifecycle.current_state(), KeyLifecycleState::NoKey);
    }

    #[test]
    fn test_verify_check_allowed_initially() {
        let lifecycle = KeyLifecycle::new();
        assert_eq!(lifecycle.check_verify_allowed(), VerifyCheckResult::Allow);
    }

    #[test]
    fn test_cooldown_after_5_failures() {
        let lifecycle = KeyLifecycle::new();
        lifecycle.transition_to_locked().unwrap();

        // 前 5 次失败不触发冷却
        for _ in 0..COOLDOWN_THRESHOLD {
            assert_eq!(
                lifecycle.record_verify_failure(),
                VerifyAttemptResult::Failure
            );
        }

        // 第 6 次失败触发冷却（2s）
        let result = lifecycle.record_verify_failure();
        match result {
            VerifyAttemptResult::FailureCooldown(secs) => assert_eq!(secs, 2),
            _ => panic!("expected cooldown"),
        }

        // 冷却期内拒绝
        assert!(matches!(
            lifecycle.check_verify_allowed(),
            VerifyCheckResult::Cooldown(_)
        ));
    }

    #[test]
    fn test_cooldown_exponential() {
        let lifecycle = KeyLifecycle::new();
        lifecycle.transition_to_locked().unwrap();

        // 6 次失败：2s 冷却
        for _ in 0..6 {
            lifecycle.record_verify_failure();
        }
        let result = lifecycle.record_verify_failure(); // 第 7 次
        match result {
            VerifyAttemptResult::FailureCooldown(secs) => assert_eq!(secs, 4),
            _ => panic!("expected 4s cooldown"),
        }
    }

    #[test]
    fn test_cooldown_capped_at_60s() {
        let lifecycle = KeyLifecycle::new();
        lifecycle.transition_to_locked().unwrap();

        // 大量失败次数（excess = 30+），冷却应被限制在 60s
        for _ in 0..40 {
            lifecycle.record_verify_failure();
        }
        let result = lifecycle.record_verify_failure();
        match result {
            VerifyAttemptResult::FailureCooldown(secs) => assert!(secs <= COOLDOWN_MAX_SECS),
            _ => panic!("expected cooldown"),
        }
    }

    #[test]
    fn test_success_resets_failures() {
        let lifecycle = KeyLifecycle::new();
        lifecycle.transition_to_locked().unwrap();

        // 累积失败
        for _ in 0..3 {
            lifecycle.record_verify_failure();
        }
        assert_eq!(lifecycle.consecutive_failures(), 3);

        // 成功重置
        lifecycle.record_verify_success().unwrap();
        assert_eq!(lifecycle.consecutive_failures(), 0);
        assert_eq!(lifecycle.current_state(), KeyLifecycleState::Unlocked);
    }

    #[test]
    fn test_compute_cooldown_formula() {
        // 0 次超阈值：无冷却
        assert_eq!(compute_cooldown(0), Duration::ZERO);

        // 1 次超阈值：2s
        assert_eq!(compute_cooldown(1), Duration::from_secs(2));

        // 2 次超阈值：4s
        assert_eq!(compute_cooldown(2), Duration::from_secs(4));

        // 3 次超阈值：8s
        assert_eq!(compute_cooldown(3), Duration::from_secs(8));

        // 5 次超阈值：32s
        assert_eq!(compute_cooldown(5), Duration::from_secs(32));

        // 6 次超阈值：60s（上限）
        assert_eq!(compute_cooldown(6), Duration::from_secs(60));

        // 100 次超阈值：60s（上限）
        assert_eq!(compute_cooldown(100), Duration::from_secs(60));
    }
}
