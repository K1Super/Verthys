/*
 * SessionGuard — 公共 API
 *
 * 组合平台后端（WindowsBackend / NoopBackend），对外暴露会话守卫的
 * 生命周期与高安全模式开关；Drop 时停止监听。
 */

use std::sync::Arc;

use super::types::{SessionGuardBackend, SessionLockReason};

/// 智能会话自动锁屏守卫
///
/// 设计要点：
/// - mpsc 通道传递事件，不依赖全局裸指针
/// - RAII 窗口封装，无全局状态
/// - catch_unwind 防止 panic 跨 FFI
/// - 平台抽象层 + 降级策略
/// - 实例级高安全标志
/// - 看门狗自动恢复
pub struct SessionGuard {
    backend: Backend,
    #[allow(dead_code)]
    on_lock: Arc<dyn Fn(SessionLockReason) + Send + Sync>,
    #[allow(dead_code)]
    on_unlock: Arc<dyn Fn() + Send + Sync>,
    high_security_mode: bool,
}

#[cfg(target_os = "windows")]
type Backend = super::win_backend::WindowsBackend;

#[cfg(not(target_os = "windows"))]
type Backend = super::noop_backend::NoopBackend;

impl SessionGuard {
    /// 创建会话守卫
    ///
    /// 回调存储为 Arc<dyn Fn()>，可跨 start/stop 周期复用。
    pub fn new(
        on_lock: Box<dyn Fn(SessionLockReason) + Send + Sync>,
        on_unlock: Box<dyn Fn() + Send + Sync>,
    ) -> Self {
        let on_lock: Arc<dyn Fn(SessionLockReason) + Send + Sync> = Arc::from(on_lock);
        let on_unlock: Arc<dyn Fn() + Send + Sync> = Arc::from(on_unlock);

        SessionGuard {
            #[cfg(target_os = "windows")]
            backend: super::win_backend::WindowsBackend::new(
                on_lock.clone(),
                on_unlock.clone(),
                false,
            ),
            #[cfg(not(target_os = "windows"))]
            backend: super::noop_backend::NoopBackend::new(false),
            on_lock,
            on_unlock,
            high_security_mode: false,
        }
    }

    /// 替换锁定/解锁回调（保留运行状态与高安全开关）
    ///
    /// 启动期以 no-op 占位，避免 SecurityState 构建阶段依赖 AppHandle；
    /// lib.rs setup 完成后经本方法安装真实回调。若守卫正在运行，先停止
    /// 旧后端再以新回调重启，保证事件处理路径立即切换到真实锁库序列。
    pub fn replace_callbacks(
        &mut self,
        on_lock: Box<dyn Fn(SessionLockReason) + Send + Sync>,
        on_unlock: Box<dyn Fn() + Send + Sync>,
    ) -> Result<(), String> {
        let was_running = self.backend.is_running();
        if was_running {
            self.backend.stop();
        }

        let on_lock: Arc<dyn Fn(SessionLockReason) + Send + Sync> = Arc::from(on_lock);
        let on_unlock: Arc<dyn Fn() + Send + Sync> = Arc::from(on_unlock);
        self.on_lock = on_lock.clone();
        self.on_unlock = on_unlock.clone();

        #[cfg(target_os = "windows")]
        {
            self.backend = super::win_backend::WindowsBackend::new(
                on_lock,
                on_unlock,
                self.high_security_mode,
            );
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.backend = super::noop_backend::NoopBackend::new(self.high_security_mode);
        }

        if was_running {
            self.backend.start()?;
        }
        Ok(())
    }

    /// 设置高安全模式（实例级，非全局）
    pub fn set_high_security_mode(&mut self, enabled: bool) {
        self.high_security_mode = enabled;
        self.backend.set_high_security(enabled);
    }

    /// 启动会话守卫
    #[cfg(target_os = "windows")]
    pub fn start(&mut self) -> Result<(), String> {
        self.backend.start()
    }

    #[cfg(not(target_os = "windows"))]
    pub fn start(&mut self) -> Result<(), String> {
        self.backend.start()
    }

    /// 停止会话守卫
    pub fn stop(&mut self) {
        self.backend.stop();
    }

    /// 查询是否正在运行
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.backend.is_running()
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.stop();
    }
}
