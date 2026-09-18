/*
 * brute_force.rs — 登录暴力拦截（熔断机制）（SECURITY.md 企业级重写版）
 *
 * SECURITY.md 修复要点：
 *   1. 持久化加密状态，与设备身份绑定（第 13.2.2 项已实现 DPAPI 持久化）
 *   2. 锁定期间完全冻结记录接口 — record_failure 在锁定或 PurgeRequired 状态下
 *      直接返回当前状态，不递增任何计数
 *   3. 累计失败计数不可逆 — total_failures 永不因 clear_purge 或 record_success
 *      而减少；purge 触发后需额外 PURGE_THRESHOLD 次失败才会再次触发
 *   4. 调用速率限制 — record_failure / record_success 实施固定窗口限流
 *      （每秒最多一次调用），防止自动化脚本快速堆积计数
 *   5. 可配置策略与多级响应 — 阈值、锁定时间、熔断阈值抽取为配置对象；
 *      锁定时间随机化（±jitter）以增加时序攻击难度；
 *      purge 状态 24 小时后自动解除（但计数器保留）
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
/// 累计失败 20 次触发清空索引 + 完整性校验
const DEFAULT_PURGE_THRESHOLD: u32 = 20;
/// 速率限制：每秒最多一次调用
const DEFAULT_RATE_LIMIT_MS: u64 = 1000;
/// purge 自动解除时间窗口：24 小时
const DEFAULT_PURGE_AUTO_CLEAR_SECS: u64 = 24 * 60 * 60;

/* ==================================================================== *
 *  SECURITY.md 第 5 项：可配置策略对象                                    *
 * ==================================================================== */

/// 暴力拦截配置策略（SECURITY.md 第 5 项：可配置阈值与多级响应）
#[derive(Debug, Clone)]
pub struct BruteForceConfig {
    /// 连续失败阈值（触发界面锁定）
    pub lock_threshold: u32,
    /// 锁定基础时长（秒）
    pub lock_duration_secs: u64,
    /// 锁定时间随机抖动范围（±秒，增加时序攻击难度）
    pub lock_jitter_secs: u64,
    /// 累计失败阈值（触发清空索引 + 完整性校验）
    pub purge_threshold: u32,
    /// 速率限制间隔（毫秒，两次调用间最小间隔）
    pub rate_limit_ms: u64,
    /// purge 自动解除时间窗口（秒，0=不自动解除）
    pub purge_auto_clear_secs: u64,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            lock_threshold: DEFAULT_LOCK_THRESHOLD,
            lock_duration_secs: DEFAULT_LOCK_DURATION_SECS,
            lock_jitter_secs: DEFAULT_LOCK_JITTER_SECS,
            purge_threshold: DEFAULT_PURGE_THRESHOLD,
            rate_limit_ms: DEFAULT_RATE_LIMIT_MS,
            purge_auto_clear_secs: DEFAULT_PURGE_AUTO_CLEAR_SECS,
        }
    }
}

/* ==================================================================== *
 *  持久化状态结构（第 13.2.2 项）                                         *
 * ==================================================================== */

/// 第 13.2.2 项：暴力拦截持久化状态（DPAPI 加密存储）
///
/// 用于跨进程重启后恢复暴力拦截状态，防止攻击者通过重启重置失败计数。
/// lock_until (Instant) 转换为 lock_remaining_secs (u64) 以支持序列化。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BruteForcePersistedState {
    /// 连续失败次数（成功解锁后重置为 0）
    pub consecutive_failures: u32,
    /// 累计失败次数（不重置，用于触发更高级别响应）
    pub total_failures: u32,
    /// 锁定剩余秒数（0 = 未锁定）
    pub lock_remaining_secs: u64,
    /// 是否已触发清空索引
    pub purge_triggered: bool,
    /// SECURITY.md 第 3 项：上次 purge 触发时的 total_failures 值
    /// （用于实现"需额外 PURGE_THRESHOLD 次失败才会再次触发"）
    #[serde(default)]
    pub last_purge_total: u32,
}

/* ==================================================================== *
 *  内部状态                                                              *
 * ==================================================================== */

/// 暴力拦截状态
pub struct BruteForceGuard {
    inner: Mutex<BruteForceState>,
    config: BruteForceConfig,
}

#[derive(Default)]
struct BruteForceState {
    /// 连续失败次数（成功解锁后重置为 0）
    consecutive_failures: u32,
    /// SECURITY.md 第 3 项：累计失败次数（永不重置，只增不减）
    total_failures: u32,
    /// 锁定截止时间（None=未锁定，Some=锁定至该时刻）
    lock_until: Option<Instant>,
    /// 是否已触发清空索引（避免重复触发）
    purge_triggered: bool,
    /// SECURITY.md 第 3 项：上次 purge 触发时的 total_failures 值
    /// 下次 purge 需要 total_failures - last_purge_total >= purge_threshold
    last_purge_total: u32,
    /// SECURITY.md 第 3 项：purge 触发时间（用于 24 小时自动解除）
    purge_triggered_at: Option<Instant>,
    /// SECURITY.md 第 4 项：上次 record_failure / record_success 调用时间（速率限制）
    last_record_time: Option<Instant>,
}

/* ==================================================================== *
 *  结果枚举                                                              *
 * ==================================================================== */

/// 暴力拦截判定结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BruteForceCheck {
    /// 允许尝试解锁
    Allow,
    /// 界面锁定中，剩余秒数
    Locked(u64),
    /// 需要清空索引并触发完整性校验
    PurgeRequired,
}

/// 解锁尝试结果（用于调用方报告）
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum AttemptResult {
    /// 尝试成功，重置失败计数
    Success,
    /// 尝试失败，但未触发熔断
    Failure,
    /// 尝试失败并触发界面锁定（剩余锁定秒数）
    FailureLocked(u64),
    /// 尝试失败并触发清空索引
    FailurePurgeRequired,
    /// SECURITY.md 第 4 项：调用速率超限（拒绝记录，计数不变）
    RateLimited,
    /// SECURITY.md 第 2 项：锁定期间或 PurgeRequired 状态下拒绝记录
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
 *  BruteForceGuard 实现                                                  *
 * ==================================================================== */

impl BruteForceGuard {
    pub fn new() -> Self {
        BruteForceGuard {
            inner: Mutex::new(BruteForceState::default()),
            config: BruteForceConfig::default(),
        }
    }

    /// SECURITY.md 第 5 项：使用自定义配置创建
    #[allow(dead_code)]
    pub fn with_config(config: BruteForceConfig) -> Self {
        BruteForceGuard {
            inner: Mutex::new(BruteForceState::default()),
            config,
        }
    }

    /// 检查当前是否允许尝试解锁
    ///
    /// SECURITY.md 第 5 项：purge 状态在 purge_auto_clear_secs 后自动解除
    /// （但 total_failures 保留，last_purge_total 不变）
    pub fn check(&self) -> BruteForceCheck {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        /* 检查是否处于锁定状态 */
        if let Some(until) = state.lock_until {
            let now = Instant::now();
            if now < until {
                let remaining = (until - now).as_secs();
                return BruteForceCheck::Locked(remaining);
            }
            /* 锁定期已过，清理 lock_until */
            state.lock_until = None;
        }

        /* SECURITY.md 第 5 项：检查 purge 是否已过自动解除窗口 */
        if state.purge_triggered {
            if let Some(triggered_at) = state.purge_triggered_at {
                if self.config.purge_auto_clear_secs > 0 {
                    let elapsed = Instant::now().duration_since(triggered_at);
                    if elapsed.as_secs() >= self.config.purge_auto_clear_secs {
                        log::info!(
                            "[brute_force] purge 已过 {} 小时自动解除窗口，自动清除（total_failures={} 保留）",
                            self.config.purge_auto_clear_secs / 3600,
                            state.total_failures
                        );
                        state.purge_triggered = false;
                        state.purge_triggered_at = None;
                        /* 注意：total_failures 和 last_purge_total 不重置 */
                    }
                }
            }
        }

        /* 检查是否仍需要清空索引 */
        if state.purge_triggered {
            return BruteForceCheck::PurgeRequired;
        }

        BruteForceCheck::Allow
    }

    /// SECURITY.md 第 4 项：检查速率限制
    ///
    /// 返回 true 表示通过（可以记录），false 表示被限流。
    fn check_rate_limit(state: &mut BruteForceState, rate_limit_ms: u64) -> bool {
        if rate_limit_ms == 0 {
            return true;
        }
        if let Some(last) = state.last_record_time {
            let elapsed = Instant::now().duration_since(last);
            if elapsed.as_millis() < rate_limit_ms as u128 {
                return false;
            }
        }
        state.last_record_time = Some(Instant::now());
        true
    }

    /// 记录一次解锁成功
    ///
    /// SECURITY.md 第 3 项：total_failures 不重置（累计计数不可逆）
    /// SECURITY.md 第 4 项：速率限制
    pub fn record_success(&self) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        /* SECURITY.md 第 4 项：速率限制 */
        if !Self::check_rate_limit(&mut state, self.config.rate_limit_ms) {
            log::warn!("[brute_force] record_success 被速率限制拒绝");
            return;
        }

        state.consecutive_failures = 0;
        state.lock_until = None;
        /* SECURITY.md 第 3 项：total_failures 不重置（累计计数不可逆） */
    }

    /// 记录一次解锁失败，返回触发的动作
    ///
    /// SECURITY.md 第 2 项：锁定期间完全冻结记录接口
    ///   - 若处于锁定状态，返回 Frozen(remaining_secs)，不递增任何计数
    ///   - 若处于 PurgeRequired 状态，返回 Frozen(0)，不递增任何计数
    ///
    /// SECURITY.md 第 3 项：累计失败计数不可逆
    ///   - total_failures 只增不减
    ///   - purge 触发后需额外 PURGE_THRESHOLD 次失败才会再次触发
    ///
    /// SECURITY.md 第 4 项：速率限制
    ///   - 每秒最多一次调用，超限返回 RateLimited
    ///
    /// SECURITY.md 第 5 项：锁定时间随机化
    ///   - 实际锁定时长 = lock_duration_secs ± lock_jitter_secs
    pub fn record_failure(&self) -> AttemptResult {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        /* SECURITY.md 第 2 项：锁定期间完全冻结 */
        if let Some(until) = state.lock_until {
            let now = Instant::now();
            if now < until {
                let remaining = (until - now).as_secs();
                log::warn!(
                    "[brute_force] 第 2 项：锁定期间 record_failure 被冻结（剩余 {} 秒），\
                     计数不变 (consecutive={}, total={})",
                    remaining,
                    state.consecutive_failures,
                    state.total_failures
                );
                return AttemptResult::Frozen(remaining);
            }
            /* 锁定期已过，清理 */
            state.lock_until = None;
        }

        /* SECURITY.md 第 2 项：PurgeRequired 状态下完全冻结 */
        if state.purge_triggered {
            log::warn!(
                "[brute_force] 第 2 项：PurgeRequired 状态下 record_failure 被冻结，\
                 计数不变 (consecutive={}, total={})",
                state.consecutive_failures,
                state.total_failures
            );
            return AttemptResult::Frozen(0);
        }

        /* SECURITY.md 第 4 项：速率限制 */
        if !Self::check_rate_limit(&mut state, self.config.rate_limit_ms) {
            log::warn!(
                "[brute_force] 第 4 项：record_failure 被速率限制拒绝（间隔 < {}ms）",
                self.config.rate_limit_ms
            );
            return AttemptResult::RateLimited;
        }

        state.consecutive_failures += 1;
        state.total_failures += 1;

        /* SECURITY.md 第 3 项：累计阈值检查
         * purge 仅在 total_failures - last_purge_total >= purge_threshold 时触发
         * 这确保 clear_purge 后需要额外 purge_threshold 次失败才会再次触发 */
        let failures_since_last_purge = state.total_failures - state.last_purge_total;
        if failures_since_last_purge >= self.config.purge_threshold {
            state.purge_triggered = true;
            state.purge_triggered_at = Some(Instant::now());
            /* SECURITY.md 第 3 项：更新 last_purge_total 为当前 total_failures，
             * 确保 clear_purge 后需要额外 purge_threshold 次失败才会再次触发 */
            state.last_purge_total = state.total_failures;
            state.consecutive_failures = 0;
            state.lock_until = None;
            log::warn!(
                "[brute_force] 触发清空索引（total={}, since_last_purge={}）",
                state.total_failures,
                failures_since_last_purge
            );
            return AttemptResult::FailurePurgeRequired;
        }

        /* 连续失败阈值检查：触发界面锁定 */
        if state.consecutive_failures >= self.config.lock_threshold {
            /* SECURITY.md 第 5 项：锁定时间随机化 */
            let jitter = random_jitter(self.config.lock_jitter_secs);
            let actual_lock_secs = self.config.lock_duration_secs + jitter
                - self.config.lock_jitter_secs; /* [duration - jitter, duration + jitter] */

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

    /// 清除熔断状态（PurgeRequired 处理完成后调用）
    ///
    /// SECURITY.md 第 3 项：累计失败计数不可逆
    ///   - 清除 purge_triggered、consecutive_failures、lock_until
    ///   - **不重置** total_failures（累计计数永久保留）
    ///   - **不重置** last_purge_total（确保下次 purge 需额外 PURGE_THRESHOLD 次失败）
    pub fn clear_purge(&self) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let total = state.total_failures;
        state.purge_triggered = false;
        state.purge_triggered_at = None;
        state.consecutive_failures = 0;
        state.lock_until = None;
        /* SECURITY.md 第 3 项：total_failures 和 last_purge_total 不重置 */

        log::info!(
            "[brute_force] 第 3 项：clear_purge 已清除熔断状态（total_failures={} 保留，\
             last_purge_total={} 保留）",
            total,
            state.last_purge_total
        );
    }

    /* ------------------------------------------------------------------ *
     * 第 13.2.2 项：DPAPI 持久化支持                                      *
     * ------------------------------------------------------------------ */

    /// 第 13.2.2 项：导出暴力拦截状态（用于 DPAPI 持久化）
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
            consecutive_failures: state.consecutive_failures,
            total_failures: state.total_failures,
            lock_remaining_secs,
            purge_triggered: state.purge_triggered,
            last_purge_total: state.last_purge_total,
        }
    }

    /// 第 13.2.2 项：导入暴力拦截状态（从 DPAPI 解密后恢复）
    pub fn import_state(&self, persisted: &BruteForcePersistedState) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        state.consecutive_failures = persisted.consecutive_failures;
        state.total_failures = persisted.total_failures;
        state.purge_triggered = persisted.purge_triggered;
        state.last_purge_total = persisted.last_purge_total;

        /* 重建 lock_until：从当前时刻起算剩余秒数 */
        if persisted.lock_remaining_secs > 0 {
            state.lock_until = Some(
                Instant::now() + Duration::from_secs(persisted.lock_remaining_secs),
            );
        } else {
            state.lock_until = None;
        }

        /* 重建 purge_triggered_at：假设刚触发（保守估计） */
        state.purge_triggered_at = if persisted.purge_triggered {
            Some(Instant::now())
        } else {
            None
        };

        log::info!(
            "[brute_force] 第 13.2.2 项：状态已从持久化恢复 \
             (consecutive={}, total={}, lock_remaining={}s, purge={}, last_purge_total={})",
            state.consecutive_failures,
            state.total_failures,
            persisted.lock_remaining_secs,
            state.purge_triggered,
            state.last_purge_total
        );
    }

    /// 获取当前连续失败次数（用于 UI 展示）
    pub fn consecutive_failures(&self) -> u32 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).consecutive_failures
    }

    /// 获取累计失败次数（用于 UI 展示）
    pub fn total_failures(&self) -> u32 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).total_failures
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

    /// SECURITY.md 第 5 项：获取当前配置（只读）
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

    /// 测试辅助：创建无速率限制的守卫（便于快速调用）
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
        /* check() 的剩余秒数因 as_secs() 截断可能比基础时长少 */
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
        /* SECURITY.md 第 2 项：锁定期间完全冻结记录接口 */
        let guard = test_guard();
        for _ in 0..10 {
            guard.record_failure();
        }
        /* 已锁定 */
        assert!(matches!(guard.check(), BruteForceCheck::Locked(_)));
        let total_before = guard.total_failures();
        /* 锁定期间调用 record_failure 应被冻结 */
        let result = guard.record_failure();
        assert!(matches!(result, AttemptResult::Frozen(_)));
        /* 计数不变 */
        assert_eq!(guard.total_failures(), total_before);
    }

    #[test]
    fn test_frozen_during_purge() {
        /* SECURITY.md 第 2 项：PurgeRequired 状态下完全冻结记录接口 */
        let guard = test_guard();
        /* 触发 purge（20 次失败） */
        for _ in 0..10 {
            guard.record_failure();
        }
        guard.force_unlock(); /* 测试辅助：解除锁定 */
        for _ in 0..10 {
            guard.record_failure();
        }
        assert_eq!(guard.check(), BruteForceCheck::PurgeRequired);
        /* PurgeRequired 状态下调用 record_failure 应被冻结 */
        let total_before = guard.total_failures();
        let result = guard.record_failure();
        assert_eq!(result, AttemptResult::Frozen(0));
        assert_eq!(guard.total_failures(), total_before);
    }

    #[test]
    fn test_total_failures_not_reset_by_clear_purge() {
        /* SECURITY.md 第 3 项：累计失败计数不可逆 */
        let guard = test_guard();
        for _ in 0..10 {
            guard.record_failure();
        }
        guard.force_unlock();
        for _ in 0..10 {
            guard.record_failure();
        }
        assert_eq!(guard.total_failures(), 20);
        assert_eq!(guard.check(), BruteForceCheck::PurgeRequired);

        guard.clear_purge();
        /* total_failures 保留 */
        assert_eq!(guard.total_failures(), 20);
        /* purge 状态已清除 */
        assert_eq!(guard.check(), BruteForceCheck::Allow);
    }

    #[test]
    fn test_purge_requires_additional_threshold_after_clear() {
        /* SECURITY.md 第 3 项：clear_purge 后需额外 PURGE_THRESHOLD 次失败才会再次触发 */
        let guard = test_guard();
        /* 第一次触发 purge（20 次） */
        for _ in 0..10 {
            guard.record_failure();
        }
        guard.force_unlock();
        for _ in 0..10 {
            guard.record_failure();
        }
        assert_eq!(guard.check(), BruteForceCheck::PurgeRequired);
        guard.clear_purge();

        /* 再 19 次失败不应触发 purge（total=39, since_last_purge=19 < 20） */
        for _ in 0..10 {
            guard.record_failure();
        }
        guard.force_unlock();
        for _ in 0..9 {
            guard.record_failure();
        }
        assert_eq!(guard.check(), BruteForceCheck::Allow);

        /* 第 40 次（since_last_purge=20）触发 purge */
        let result = guard.record_failure();
        assert_eq!(result, AttemptResult::FailurePurgeRequired);
    }

    #[test]
    fn test_rate_limiting() {
        /* SECURITY.md 第 4 项：调用速率限制 */
        let config = BruteForceConfig {
            rate_limit_ms: 500, /* 500ms 间隔便于测试 */
            ..Default::default()
        };
        let guard = BruteForceGuard::with_config(config);

        /* 第一次调用成功 */
        let r1 = guard.record_failure();
        assert_eq!(r1, AttemptResult::Failure);

        /* 立即第二次调用应被限流 */
        let r2 = guard.record_failure();
        assert_eq!(r2, AttemptResult::RateLimited);

        /* 等待 600ms 后调用应成功 */
        std::thread::sleep(std::time::Duration::from_millis(600));
        let r3 = guard.record_failure();
        assert_eq!(r3, AttemptResult::Failure);
    }

    #[test]
    fn test_export_import_roundtrip() {
        let guard = test_guard();
        for _ in 0..5 {
            guard.record_failure();
        }
        let exported = guard.export_state();
        assert_eq!(exported.total_failures, 5);

        let guard2 = BruteForceGuard::new();
        guard2.import_state(&exported);
        assert_eq!(guard2.total_failures(), 5);
        assert_eq!(guard2.consecutive_failures(), 5);
    }
}
