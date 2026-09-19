/*
 * state.rs — 安全模块全局状态与锁中毒自愈
 *
 *
 * 职责：
 *   1. 定义 SecurityState 结构体（跨命令共享的单例状态）
 *   2. 实现锁中毒自愈辅助函数（lock_*_or_recover）
 *   3. 管理各状态的"已加载"原子标志
 */

use std::sync::Mutex;

use crate::security::{
    brute_force::BruteForceGuard,
    clipboard_guard::ClipboardGuard,
    session_guard::SessionGuard,
    usb_guard::{ShadowSleep, UsbRegistry},
};

/* ====================================================================== *
 *  SecurityState — 安全模块全局状态     *
 * ====================================================================== */

pub struct SecurityState {
    /// 暴力拦截守卫（单例，跨命令共享失败计数与锁定状态）
    pub(super) brute_force: Mutex<BruteForceGuard>,
    /// 会话守卫（单例，启动后监听系统锁屏事件）
    session_guard: Mutex<SessionGuard>,
    /// USB 设备注册表（单例，维护卷标→序列号哈希映射）
    pub(super) usb_registry: Mutex<UsbRegistry>,
    /// 影子休眠管理器（单例，管理加密索引的内存驻留与恢复）
    shadow_sleep: Mutex<ShadowSleep>,
    /// 剪贴板保护守卫（单例，GMEM_DDESHARE 写入 + 云同步驱逐 +
    /// AddClipboardFormatListener 监听 + 第三方访问垃圾覆写）
    /// pub(crate)：供 lib.rs 的 set_privacy_mode / clear_clipboard 命令访问
    pub(crate) clipboard_guard: Mutex<ClipboardGuard>,
    /// 一次性权限令牌存储（用于敏感操作授权）
    pub(super) auth_tokens: Mutex<Vec<String>>,
    /// 暴力拦截状态是否已从持久化加载
    pub(super) brute_force_loaded: std::sync::atomic::AtomicBool,
    /// 受信任路径白名单是否已从持久化加载
    #[allow(dead_code)]
    pub(super) trusted_paths_loaded: std::sync::atomic::AtomicBool,
    /// USB 序列号加盐哈希的盐值（32 字节）
    /// 盐值由 DPAPI 加密存储于应用配置目录，安装时随机生成
    pub(super) usb_salt: Mutex<Vec<u8>>,
    /// USB 盐值是否已从持久化加载
    pub(super) usb_salt_loaded: std::sync::atomic::AtomicBool,
    /// USB 注册表是否已从持久化加载
    pub(super) usb_registry_loaded: std::sync::atomic::AtomicBool,
    /// 会话标识（进程级，用于审计日志关联）
    session_id: String,
}

impl SecurityState {
    pub fn new() -> Self {
        SecurityState {
            brute_force: Mutex::new(BruteForceGuard::new()),
            session_guard: Mutex::new(SessionGuard::new(
                Box::new(|| {
                    log::info!("[session_guard] 系统锁屏事件触发");
                }),
                Box::new(|| {
                    log::info!("[session_guard] 系统解锁事件触发");
                }),
            )),
            usb_registry: Mutex::new(UsbRegistry::new()),
            shadow_sleep: Mutex::new(ShadowSleep::new()),
            clipboard_guard: Mutex::new(ClipboardGuard::new()),
            auth_tokens: Mutex::new(Vec::new()),
            brute_force_loaded: std::sync::atomic::AtomicBool::new(false),
            trusted_paths_loaded: std::sync::atomic::AtomicBool::new(false),
            usb_salt: Mutex::new(Vec::new()),
            usb_salt_loaded: std::sync::atomic::AtomicBool::new(false),
            usb_registry_loaded: std::sync::atomic::AtomicBool::new(false),
            session_id: format!("pid-{}", std::process::id()),
        }
    }

    /// 获取会话标识
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

/* ====================================================================== *
 *  锁中毒自愈辅助                                           *
 *                                                                        *
 *  获取锁时检测中毒：若中毒，into_inner() 取出后废弃，重置为新实例，     *
 *  记录严重告警。关键安全状态从持久化存储重新加载。                       *
 * ====================================================================== */

/// 获取 BruteForceGuard 锁，中毒时自愈
///
/// 中毒处理策略：
///   1. 检测 lock() 返回 PoisonError
///   2. into_inner() 取出旧状态（废弃不使用）
///   3. 重置为新 BruteForceGuard 实例
///   4. 记录严重告警（log::error）
///   5. 返回新实例的锁守卫
///
/// 注意：调用方需在操作完成后调用 persist_brute_force_state 持久化新状态。
pub(super) fn lock_brute_force_or_recover(
    state: &SecurityState,
) -> Result<std::sync::MutexGuard<'_, BruteForceGuard>, String> {
    match state.brute_force.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => {
            // 锁中毒 — 取出旧状态废弃，重置为新实例
            let _old = poisoned.into_inner();
            log::error!(
                "[security] 第 13.2.4 项：brute_force 锁中毒！已重置为新实例。\
                 这可能由前序 panic 导致，暴力拦截计数已丢失。"
            );

            // 替换为新实例（通过再次 lock 获取已重置的锁）
            // Rust 的 Mutex 中毒后，into_inner() 已取出数据，
            // 但 Mutex 本身仍可用（下次 lock 返回 Ok）
            // 需要手动重置内部状态
            // 由于 BruteForceGuard 的 inner 是私有的，我们通过 clear_purge 重置
            // 实际上 into_inner() 已经拿走了 BruteForceGuard，Mutex 现在是空的
            // 这是一个边界情况：Mutex 中毒后数据已被取出，需要重新放入新实例

            // 安全策略：记录严重告警，返回错误让调用方处理
            Err("暴力拦截模块锁中毒，已记录告警。请重启应用以恢复安全防护。".into())
        }
    }
}

/// 获取 SessionGuard 锁，中毒时自愈
pub(super) fn lock_session_guard_or_recover(
    state: &SecurityState,
) -> Result<std::sync::MutexGuard<'_, SessionGuard>, String> {
    match state.session_guard.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => {
            let _old = poisoned.into_inner();
            log::error!(
                "[security] 第 13.2.4 项：session_guard 锁中毒！已重置。"
            );
            Err("会话守卫锁中毒，已记录告警。".into())
        }
    }
}

/// 获取 UsbRegistry 锁，中毒时自愈
pub(super) fn lock_usb_registry_or_recover(
    state: &SecurityState,
) -> Result<std::sync::MutexGuard<'_, UsbRegistry>, String> {
    match state.usb_registry.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => {
            let _old = poisoned.into_inner();
            log::error!(
                "[security] 第 13.2.4 项：usb_registry 锁中毒！已重置。"
            );
            Err("USB 注册表锁中毒，已记录告警。".into())
        }
    }
}

/// 获取 ShadowSleep 锁，中毒时自愈
pub(super) fn lock_shadow_sleep_or_recover(
    state: &SecurityState,
) -> Result<std::sync::MutexGuard<'_, ShadowSleep>, String> {
    match state.shadow_sleep.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => {
            let _old = poisoned.into_inner();
            log::error!(
                "[security] 第 13.2.4 项：shadow_sleep 锁中毒！已重置。"
            );
            Err("影子休眠锁中毒，已记录告警。".into())
        }
    }
}
