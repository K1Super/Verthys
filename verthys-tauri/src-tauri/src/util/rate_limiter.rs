/*
 * util/rate_limiter.rs — 滑动窗口频率限制组件
 *
 * 架构定位：工具层（util）有状态组件
 *   - 不依赖任何上层模块（controller / service / repository）
 *   - 不输出日志：拒绝事件由调用方记录审计（日志与审计留在命令层）
 *
 * 为什么共用同一组件、按实例分离：
 *   隐私模式的开启与关闭、凭据采纳、隔离对账以及剪贴板清空与守卫，
 *   可容忍的频率完全不同。共用同一实现保证窗口清理与边界判定行为一致；
 *   按用途分离实例保证互不牵连——一个方向的连击不会锁住另一个方向
 *   （历史缺陷：开启与关闭共用一个桶，连击开启会连带锁死关闭操作）。
 */

use std::time::{Duration, Instant};

/// 滑动窗口频率限制器
///
/// 窗口内至多允许 `max_calls` 次；超出窗口的旧记录在检查时清理，
/// 不引入定时器、不引入后台任务。
pub struct SlidingWindowLimiter {
    window: Duration,
    max_calls: usize,
    timestamps: Vec<Instant>,
}

impl SlidingWindowLimiter {
    /// 创建限制器（窗口时长 + 窗口内允许次数）
    ///
    /// 常量构造：使限流器可作为静态实例初始化（无运行期注册表、无惰性初始化开销）
    pub const fn new(window: Duration, max_calls: usize) -> Self {
        SlidingWindowLimiter {
            window,
            max_calls,
            timestamps: Vec::new(),
        }
    }

    /// 检查本次调用是否允许，允许则记录当前时刻
    ///
    /// 返回 false 时不记录，调用方可如实回报"频率受限"并可稍后重试。
    pub fn check_and_record(&mut self) -> bool {
        let now = Instant::now();
        self.timestamps.retain(|&t| now.duration_since(t) < self.window);

        if self.timestamps.len() >= self.max_calls {
            return false;
        }
        self.timestamps.push(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> SlidingWindowLimiter {
        SlidingWindowLimiter::new(Duration::from_secs(60), 3)
    }

    #[test]
    fn test_allows_within_limit_then_rejects() {
        let mut l = limiter();
        for i in 0..3 {
            assert!(l.check_and_record(), "第 {} 次应被允许", i + 1);
        }
        assert!(!l.check_and_record(), "超出上限应被拒绝");
    }

    #[test]
    fn test_rejected_call_is_not_recorded() {
        let mut l = limiter();
        for _ in 0..3 {
            assert!(l.check_and_record());
        }
        assert!(!l.check_and_record());
        // 拒绝不占额度：窗口内名额仍为已用满状态
        assert_eq!(l.timestamps.len(), 3);
    }

    #[test]
    fn test_expired_entries_are_cleaned() {
        let mut l = limiter();
        for _ in 0..3 {
            assert!(l.check_and_record());
        }
        let old = Instant::now() - Duration::from_secs(120);
        l.timestamps.iter_mut().for_each(|t| *t = old);
        assert!(l.check_and_record(), "过期时间戳清理后应允许新调用");
    }

    #[test]
    fn test_instances_are_independent() {
        let mut a = limiter();
        let mut b = limiter();
        for _ in 0..3 {
            assert!(a.check_and_record());
        }
        assert!(!a.check_and_record());
        assert!(b.check_and_record(), "另一实例不应受牵连");
        assert!(!a.check_and_record(), "a 的名额不应因 b 的调用而恢复");
    }
}