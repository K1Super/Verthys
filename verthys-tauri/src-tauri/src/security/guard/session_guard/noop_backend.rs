/*
 * 非 Windows 平台后端（降级策略）
 *
 * 非 Windows 平台返回错误但不阻止应用启动。
 */

use std::sync::atomic::{AtomicBool, Ordering};

use super::types::SessionGuardBackend;

pub struct NoopBackend {
    high_security: AtomicBool,
}

impl NoopBackend {
    pub fn new(high_security: bool) -> Self {
        NoopBackend {
            high_security: AtomicBool::new(high_security),
        }
    }
}

impl SessionGuardBackend for NoopBackend {
    fn start(&mut self) -> Result<(), String> {
        log::warn!("[session_guard] 非 Windows 平台不支持会话守卫");
        Err("session_guard: 非 Windows 平台不支持".into())
    }

    fn stop(&mut self) {}

    fn set_high_security(&self, enabled: bool) {
        self.high_security.store(enabled, Ordering::SeqCst);
    }

    fn is_running(&self) -> bool {
        false
    }
}
