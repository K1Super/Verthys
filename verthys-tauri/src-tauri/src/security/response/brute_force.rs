/*
 * brute_force.rs — 登录暴力拦截（熔断机制）
 *
 * 机制边界：
 *   1. 仅锁定级：连续失败达到阈值即锁定一段时间，无清空/索引销毁级。
 *   2. total_failures 是审计计数：只增不减（饱和），不参与任何闸门判定。
 *   3. 尝试门禁在认证之前执行：按口令域（unlock / global_key / derive）
 *      限制最小尝试间隔；check() 为纯查询，供前端展示，不消耗尝试额度。
 *   4. 每次认证失败都计数（限流不吞掉失败计数）；认证成功无条件重置
 *      连续失败与锁定，累计审计计数保留。
 *   5. 持久化由调用方（security_commands::persistence）用 DPAPI 加密完成，
 *      本模块只负责状态导入导出。
 */

use std::sync::Mutex;
use std::time::{Duration, Instant};

/* ---------- 默认常量 ---------- */
/// 连续失败 10 次触发界面锁定
const DEFAULT_LOCK_THRESHOLD: u32 = 10;
/// 界面锁定时长：10 分钟
const DEFAULT_LOCK_DURATION_SECS: u64 = 10 * 60;
/// 锁定时间随机抖动：±2 分钟
const DEFAULT_LOCK_JITTER_SECS: u64 = 120;
/// 同一口令域的最小尝试间隔：1 秒
const DEFAULT_RATE_LIMIT_MS: u64 = 1000;

/// 持久化状态结构版本：2
pub const STATE_SCHEMA_VERSION: u32 = 2;

/* ==================================================================== *
 *  可配置策略对象                                                       *
 * ==================================================================== */

/// 暴力拦截配置策略
#[derive(Debug, Clone)]
pub struct BruteForceConfig {
    /// 连续失败阈值（触发界面锁定）
    pub lock_threshold: u32,
    /// 锁定基础时长（秒）
    pub lock_duration_secs: u64,
    /// 锁定时间随机抖动范围（±秒，增加时序攻击难度）
    pub lock_jitter_secs: u64,
    /// 同一口令域的最小尝试间隔（毫秒，0 = 不限速）
    pub rate_limit_ms: u64,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            lock_threshold: DEFAULT_LOCK_THRESHOLD,
            lock_duration_secs: DEFAULT_LOCK_DURATION_SECS,
            lock_jitter_secs: DEFAULT_LOCK_JITTER_SECS,
            rate_limit_ms: DEFAULT_RATE_LIMIT_MS,
        }
    }
}

/* ==================================================================== *
 *  持久化状态结构                                                       *
 * ==================================================================== */

/// 暴力拦截持久化状态（DPAPI 加密存储由上层完成）
///
/// 用于跨进程重启后恢复连续失败与锁定，防止攻击者通过重启重置锁定。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BruteForcePersistedState {
    /// 状态结构版本
    pub schema_version: u32,
    /// 连续失败次数（成功解锁后重置为 0）
    pub consecutive_failures: u32,
    /// 累计失败次数（仅审计，不参与闸门判定）
    pub total_failures: u32,
    /// 锁定剩余秒数（0 = 未锁定）
    pub lock_remaining_secs: u64,
}

/* ==================================================================== *
 *  内部状态                                                             *
 * ==================================================================== */

/// 尝试门禁的口令域：各域的最小尝试间隔独立计时，失败计数共享。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptDomain {
    /// 容器口令解锁
    Unlock,
    /// 全局主密钥验证
    GlobalKey,
    /// 密钥派生类命令
    Derive,
}

impl AttemptDomain {
    fn index(self) -> usize {
        match self {
            AttemptDomain::Unlock => 0,
            AttemptDomain::GlobalKey => 1,
            AttemptDomain::Derive => 2,
        }
    }
}

const ATTEMPT_DOMAIN_COUNT: usize = 3;

/// 暴力拦截状态
pub struct BruteForceGuard {
    inner: Mutex<BruteForceState>,
    config: BruteForceConfig,
}

#[derive(Default)]
struct BruteForceState {
    /// 连续失败次数（成功解锁或触发锁定后重置为 0）
    consecutive_failures: u32,
    /// 累计失败次数（仅审计，只增不减）
    total_failures: u32,
    /// 锁定截止时间（None = 未锁定）
    lock_until: Option<Instant>,
    /// 各口令域最近一次放行尝试时间（不持久化，进程级）
    last_attempt: [Option<Instant>; ATTEMPT_DOMAIN_COUNT],
}

/* ==================================================================== *
 *  结果枚举                                                             *
 * ==================================================================== */

/// 暴力拦截判定结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BruteForceCheck {
    /// 允许尝试解锁
    Allow,
    /// 界面锁定中，剩余秒数
    Locked(u64),
    /// 同一口令域的尝试间隔不足（仅 begin_attempt 返回），携带剩余毫秒
    RateLimited { retry_after_ms: u64 },
}

/// 失败记录结果（用于调用方审计）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptResult {
    /// 已计数，未触发锁定
    Failure,
    /// 已计数并触发界面锁定（锁定秒数）
    FailureLocked(u64),
    /// 锁定期间拒绝记录，计数不变（剩余锁定秒数）
    Frozen(u64),
}

/* ==================================================================== *
 *  辅助：安全随机数（用于锁定时间抖动）                                    *
 * ==================================================================== */

#[cfg(target_os = "windows")]
fn secure_random_u64() -> u64 {
    use windows::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut buf = [0u8; 8];
    let _ = unsafe { BCryptGenRandom(None, &mut buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    u64::from_le_bytes(buf)
}

#[cfg(not(target_os = "windows"))]
fn secure_random_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// 生成 [0, 2*max_secs] 范围内的随机值（用于 ±jitter 计算）
fn random_jitter(max_secs: u64) -> u64 {
    if max_secs == 0 {
        return 0;
    }
    secure_random_u64() % (2 * max_secs + 1)
}

/* ==================================================================== *
 *  BruteForceGuard 实现                                                 *
 * ==================================================================== */

impl BruteForceGuard {
    pub fn new() -> Self {
        BruteForceGuard {
            inner: Mutex::new(BruteForceState::default()),
            config: BruteForceConfig::default(),
        }
    }

    /// 使用自定义配置创建
    #[allow(dead_code)]
    pub fn with_config(config: BruteForceConfig) -> Self {
        BruteForceGuard {
            inner: Mutex::new(BruteForceState::default()),
            config,
        }
    }

    /// 清理已到期的锁定；返回仍在生效的剩余秒数。
    fn active_lock_remaining(state: &mut BruteForceState) -> Option<u64> {
        if let Some(until) = state.lock_until {
            let now = Instant::now();
            if now < until {
                return Some((until - now).as_secs());
            }
            /* 锁定期已过，清理 */
            state.lock_until = None;
        }
        None
    }

    /// 纯查询：当前是否处于锁定状态。
    ///
    /// 不更新时间戳、不消耗尝试额度，供前端预检/状态展示使用。
    /// 已到期的锁定会被清理（幂等）。
    pub fn check(&self) -> BruteForceCheck {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match Self::active_lock_remaining(&mut state) {
            Some(secs) => BruteForceCheck::Locked(secs),
            None => BruteForceCheck::Allow,
        }
    }

    /// 认证前尝试门禁：锁定检查 + 该口令域的最小尝试间隔。
    ///
    /// 放行时才记录本次尝试时间；被拒绝的调用不消耗额度。
    pub fn begin_attempt(&self, domain: AttemptDomain) -> BruteForceCheck {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(secs) = Self::active_lock_remaining(&mut state) {
            return BruteForceCheck::Locked(secs);
        }

        if self.config.rate_limit_ms > 0 {
            if let Some(last) = state.last_attempt[domain.index()] {
                let elapsed_ms = Instant::now().duration_since(last).as_millis() as u64;
                if elapsed_ms < self.config.rate_limit_ms {
                    return BruteForceCheck::RateLimited {
                        retry_after_ms: self.config.rate_limit_ms - elapsed_ms,
                    };
                }
            }
        }

        state.last_attempt[domain.index()] = Some(Instant::now());
        BruteForceCheck::Allow
    }

    /// 记录一次口令验证成功：无条件重置连续失败与锁定。
    ///
    /// 累计审计计数保留；本方法不受任何速率限制。
    pub fn record_success(&self) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        state.consecutive_failures = 0;
        state.lock_until = None;
    }

    /// 记录一次口令验证失败，返回触发的动作。
    ///
    /// 锁定期间完全冻结：返回 Frozen(remaining_secs)，不递增任何计数。
    /// 锁定计数按连续失败判定；累计计数饱和递增且仅用于审计。
    pub fn record_failure(&self) -> AttemptResult {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        /* 锁定期间完全冻结 */
        if let Some(remaining) = Self::active_lock_remaining(&mut state) {
            log::warn!(
                "[brute_force] 锁定期间 record_failure 被冻结（剩余 {} 秒），\
                 计数不变 (consecutive={}, total={})",
                remaining,
                state.consecutive_failures,
                state.total_failures
            );
            return AttemptResult::Frozen(remaining);
        }

        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.total_failures = state.total_failures.saturating_add(1);

        /* 连续失败阈值检查：触发界面锁定 */
        if state.consecutive_failures >= self.config.lock_threshold {
            let jitter = random_jitter(self.config.lock_jitter_secs);
            let actual_lock_secs = self
                .config
                .lock_duration_secs
                .saturating_sub(self.config.lock_jitter_secs)
                .saturating_add(jitter);

            state.lock_until = Some(Instant::now() + Duration::from_secs(actual_lock_secs));
            /* 重置连续计数，进入锁定期 */
            state.consecutive_failures = 0;
            log::warn!(
                "[brute_force] 触发界面锁定（{} 秒，jitter={}）",
                actual_lock_secs,
                jitter
            );
            return AttemptResult::FailureLocked(actual_lock_secs);
        }

        AttemptResult::Failure
    }

    /* ------------------------------------------------------------------ *
     * DPAPI 持久化支持                                                    *
     * ------------------------------------------------------------------ */

    /// 导出暴力拦截状态（用于 DPAPI 持久化）
    pub fn export_state(&self) -> BruteForcePersistedState {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let lock_remaining_secs = if let Some(until) = state.lock_until {
            let now = Instant::now();
            if now < until {
                (until - now).as_secs()
            } else {
                0
            }
        } else {
            0
        };

        BruteForcePersistedState {
            schema_version: STATE_SCHEMA_VERSION,
            consecutive_failures: state.consecutive_failures,
            total_failures: state.total_failures,
            lock_remaining_secs,
        }
    }

    /// 导入暴力拦截状态（从 DPAPI 解密后恢复）
    ///
    /// 只接受当前 schema，其他版本反序列化失败时由上层丢弃。
    pub fn import_state(&self, persisted: &BruteForcePersistedState) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        state.consecutive_failures = persisted.consecutive_failures;
        state.total_failures = persisted.total_failures;

        /* 重建 lock_until：从当前时刻起算剩余秒数（保守：关闭期间不衰减） */
        if persisted.lock_remaining_secs > 0 {
            state.lock_until =
                Some(Instant::now() + Duration::from_secs(persisted.lock_remaining_secs));
        } else {
            state.lock_until = None;
        }

        log::info!(
            "[brute_force] 状态已从持久化恢复 (schema={}, consecutive={}, total={}, lock_remaining={}s)",
            persisted.schema_version,
            state.consecutive_failures,
            state.total_failures,
            persisted.lock_remaining_secs
        );
    }

    /// 获取当前连续失败次数（用于 UI 展示）
    pub fn consecutive_failures(&self) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .consecutive_failures
    }

    /// 获取累计失败次数（仅审计）
    pub fn total_failures(&self) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .total_failures
    }

    /// 获取锁定剩余秒数（未锁定返回 0）
    pub fn remaining_lock_secs(&self) -> u64 {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(until) = state.lock_until {
            let now = Instant::now();
            if now < until {
                return (until - now).as_secs();
            }
        }
        0
    }

    /// 获取当前配置（只读）
    #[allow(dead_code)]
    pub fn config(&self) -> &BruteForceConfig {
        &self.config
    }

    /// 测试辅助：强制解除锁定（仅测试用）
    #[cfg(test)]
    fn force_unlock(&self) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.lock_until = None;
    }
}

impl Default for BruteForceGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试辅助：创建无尝试节流的守卫（便于快速调用）
    fn test_guard() -> BruteForceGuard {
        BruteForceGuard::with_config(BruteForceConfig {
            rate_limit_ms: 0,
            ..Default::default()
        })
    }

    #[test]
    fn test_allow_initial() {
        let guard = BruteForceGuard::new();
        assert_eq!(guard.check(), BruteForceCheck::Allow);
    }

    #[test]
    fn test_success_resets_consecutive() {
        let guard = test_guard();
        guard.record_failure();
        guard.record_failure();
        assert_eq!(guard.consecutive_failures(), 2);
        guard.record_success();
        assert_eq!(guard.consecutive_failures(), 0);
    }

    #[test]
    fn test_lock_after_10_failures() {
        let guard = test_guard();
        for _ in 0..9 {
            assert_eq!(guard.record_failure(), AttemptResult::Failure);
        }
        /* 第 10 次触发锁定 */
        let result = guard.record_failure();
        assert!(matches!(result, AttemptResult::FailureLocked(_)));
        let remaining = match guard.check() {
            BruteForceCheck::Locked(s) => s,
            other => panic!("期望处于锁定状态，实际: {:?}", other),
        };
        let base = DEFAULT_LOCK_DURATION_SECS;
        let jitter = DEFAULT_LOCK_JITTER_SECS;
        assert!(
            remaining <= base + jitter && remaining >= base - jitter - 5,
            "锁定剩余时间应在 {}~{} 秒附近，实际 {} 秒",
            base - jitter,
            base + jitter,
            remaining
        );
    }

    #[test]
    fn test_frozen_during_lock() {
        let guard = test_guard();
        for _ in 0..10 {
            guard.record_failure();
        }
        assert!(matches!(guard.check(), BruteForceCheck::Locked(_)));
        let total_before = guard.total_failures();
        let result = guard.record_failure();
        assert!(matches!(result, AttemptResult::Frozen(_)));
        assert_eq!(guard.total_failures(), total_before);
    }

    #[test]
    fn test_total_failures_never_triggers_lock() {
        /* 累计失败只审计：多轮锁定后仍可继续尝试，无清空级 */
        let guard = BruteForceGuard::with_config(BruteForceConfig {
            rate_limit_ms: 0,
            lock_duration_secs: 0,
            lock_jitter_secs: 0,
            ..Default::default()
        });
        for _ in 0..60 {
            guard.record_failure();
            assert!(matches!(
                guard.check(),
                BruteForceCheck::Allow | BruteForceCheck::Locked(0)
            ));
        }
        assert_eq!(guard.total_failures(), 60);
        assert_eq!(guard.check(), BruteForceCheck::Allow);
    }

    #[test]
    fn test_every_failure_counts_despite_rate_limit() {
        /* 尝试节流只限制调用入口，不吞掉失败计数 */
        let guard = BruteForceGuard::with_config(BruteForceConfig {
            rate_limit_ms: 500,
            ..Default::default()
        });
        assert_eq!(guard.record_failure(), AttemptResult::Failure);
        assert_eq!(guard.record_failure(), AttemptResult::Failure);
        assert_eq!(guard.consecutive_failures(), 2);
        assert_eq!(guard.total_failures(), 2);
    }

    #[test]
    fn test_success_not_rate_limited() {
        let guard = BruteForceGuard::with_config(BruteForceConfig {
            rate_limit_ms: 500,
            ..Default::default()
        });
        guard.record_failure();
        guard.record_failure();
        guard.record_success();
        assert_eq!(guard.consecutive_failures(), 0);
        /* 审计计数保留 */
        assert_eq!(guard.total_failures(), 2);
    }

    #[test]
    fn test_begin_attempt_rate_limits_per_domain() {
        let guard = BruteForceGuard::with_config(BruteForceConfig {
            rate_limit_ms: 50,
            ..Default::default()
        });

        assert_eq!(
            guard.begin_attempt(AttemptDomain::Unlock),
            BruteForceCheck::Allow
        );
        let second = guard.begin_attempt(AttemptDomain::Unlock);
        assert!(
            matches!(second, BruteForceCheck::RateLimited { retry_after_ms } if retry_after_ms <= 50),
            "同一域应被节流，实际: {:?}",
            second
        );
        /* 不同域独立计时 */
        assert_eq!(
            guard.begin_attempt(AttemptDomain::GlobalKey),
            BruteForceCheck::Allow
        );

        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(
            guard.begin_attempt(AttemptDomain::Unlock),
            BruteForceCheck::Allow
        );
    }

    #[test]
    fn test_check_is_pure_query() {
        /* check() 不得消耗尝试额度 */
        let guard = BruteForceGuard::with_config(BruteForceConfig {
            rate_limit_ms: 50,
            ..Default::default()
        });
        assert_eq!(
            guard.begin_attempt(AttemptDomain::Unlock),
            BruteForceCheck::Allow
        );
        assert_eq!(guard.check(), BruteForceCheck::Allow);
        assert_eq!(guard.check(), BruteForceCheck::Allow);
        assert!(matches!(
            guard.begin_attempt(AttemptDomain::Unlock),
            BruteForceCheck::RateLimited { .. }
        ));
    }

    #[test]
    fn test_begin_attempt_denied_while_locked() {
        let guard = test_guard();
        for _ in 0..10 {
            guard.record_failure();
        }
        assert!(matches!(
            guard.begin_attempt(AttemptDomain::Unlock),
            BruteForceCheck::Locked(_)
        ));
    }

    #[test]
    fn test_lock_expires_and_allows_again() {
        let guard = BruteForceGuard::with_config(BruteForceConfig {
            rate_limit_ms: 0,
            lock_duration_secs: 0,
            lock_jitter_secs: 0,
            ..Default::default()
        });
        for _ in 0..10 {
            guard.record_failure();
        }
        guard.force_unlock();
        assert_eq!(guard.check(), BruteForceCheck::Allow);
        /* 锁定触发时连续计数已重置，可重新累计 */
        assert_eq!(guard.consecutive_failures(), 0);
    }

    #[test]
    fn test_export_import_roundtrip() {
        let guard = test_guard();
        for _ in 0..5 {
            guard.record_failure();
        }
        let exported = guard.export_state();
        assert_eq!(exported.total_failures, 5);
        assert_eq!(exported.schema_version, STATE_SCHEMA_VERSION);

        let guard2 = BruteForceGuard::new();
        guard2.import_state(&exported);
        assert_eq!(guard2.total_failures(), 5);
        assert_eq!(guard2.consecutive_failures(), 5);
    }
}
