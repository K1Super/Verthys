/*
 * state/verthys_session.rs — Verthys 会话 RAII 守卫与预热令牌
 *
 *
 * 架构定位：状态层（state）会话管理模块
 *   - 依赖 security::file_lock（VerthysFileLock 跨进程独占锁）
 *   - 依赖 util::crypto（ct_eq 常量时间比较）
 *   - 依赖 util::random（CSPRNG 令牌生成）
 *   - 提供 VerthysSessionGuard RAII + PreheatToken 一次性凭证
 *
 * 第 16.2 项 — VerthysSessionGuard RAII：
 *   原 verthys_unlock / verthys_lock 手工 file_lock 移入移出，异常路径可能遗漏释放。
 *   新设计：VerthysSessionGuard 构造时获取文件锁 + 记录会话路径，
 *   Drop 时自动释放文件锁。AppState 持 Option<VerthysSessionGuard>，
 *   命令通过 with_session 访问。
 *
 * 第 16.3 项 — PreheatToken 一次性凭证：
 *   原 prefetch_done: AtomicBool 可被前端无凭据重复触发，安全意义不足。
 *   新设计：verthys_preheat 返回随机签名令牌（32 字节 CSPRNG），
 *   verthys_unlock 必须携带令牌才启用零拷贝路径。令牌一次性消费 + 超时失效。
 *
 * CI 红线：
 *   - 令牌比较使用常量时间（ct_eq），防时序攻击
 *   - 令牌内容不输出日志
 *   - 文件锁获取失败返回 Err，不降级
 */

use crate::security::file_lock::VerthysFileLock;
use crate::util::crypto::ct_eq;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// 预热令牌超时时间（30 秒）
///
/// 用户选择文件后 30 秒内未解锁，令牌失效，需重新预热。
const PREHEAT_TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

/* ------------------------------------------------------------------ *
 * 第 16.2 项：VerthysSessionGuard — RAII 会话守卫                        *
 * ------------------------------------------------------------------ */

/// Verthys 会话 RAII 守卫（第 16.2 项）
///
/// 构造时获取 .verthys 文件独占锁，记录会话路径与 ID。
/// Drop 时自动释放文件锁，确保异常路径不遗漏。
///
/// AppState 持有 `Option<VerthysSessionGuard>`：
///   - verthys_unlock 成功后创建（Some）
///   - verthys_lock / 进程退出时销毁（None）
///
/// 所有需要访问 verthys 文件的命令通过此守卫获取会话路径，
/// 不再直接操作 verthys_file_lock。
pub struct VerthysSessionGuard {
    /// .verthys 文件跨进程独占锁（Drop 自动释放 LockFileEx）
    #[allow(dead_code)]
    file_lock: VerthysFileLock,
    /// 当前会话绑定的 .verthys 文件路径（会话期间不可更改）
    verthys_path: String,
    /// 会话 ID（用于审计日志关联）
    session_id: String,
    /// 解锁时间戳（用于会话超时检测）
    unlocked_at: Instant,
}

impl VerthysSessionGuard {
    /// 创建会话守卫（获取文件锁）
    ///
    /// 在 verthys_unlock 成功后调用：
    ///   1. 对 .verthys 文件获取独占锁（LockFileEx）
    ///   2. 记录会话路径与 ID
    ///
    /// # 错误
    /// 文件锁获取失败返回 Err，verthys_unlock 应据此回滚。
    pub fn new(verthys_path: &str, session_id: &str) -> Result<Self, String> {
        let file_lock = VerthysFileLock::lock_exclusive(verthys_path).map_err(|e| {
            log::error!(
                "[VerthysSessionGuard] 获取文件锁失败: {}",
                crate::util::path::sanitize_path(verthys_path)
            );
            e
        })?;

        log::info!(
            "[VerthysSessionGuard] 会话守卫已创建 (session={})",
            session_id
        );

        Ok(VerthysSessionGuard {
            file_lock,
            verthys_path: verthys_path.to_string(),
            session_id: session_id.to_string(),
            unlocked_at: Instant::now(),
        })
    }

    /// 获取当前会话绑定的 .verthys 文件路径
    pub fn verthys_path(&self) -> &str {
        &self.verthys_path
    }

    /// 获取会话 ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// 获取解锁后经过的时间
    pub fn elapsed(&self) -> Duration {
        self.unlocked_at.elapsed()
    }

    /// 释放文件锁并返回所有权（用于显式释放场景）
    ///
    /// 正常流程不需要调用此方法，Drop 时会自动释放。
    /// 仅在需要提前释放锁的场景使用。
    pub fn release(self) {
        // 显式 drop 表明意图：释放文件锁
        drop(self);
    }
}

impl Drop for VerthysSessionGuard {
    fn drop(&mut self) {
        log::info!(
            "[VerthysSessionGuard] 会话守卫释放 (session={}, elapsed={}ms)",
            self.session_id,
            self.unlocked_at.elapsed().as_millis()
        );
        // file_lock Drop 自动调用 UnlockFile + CloseHandle
    }
}

/* ------------------------------------------------------------------ *
 * 第 16.3 项：PreheatToken — 一次性预热凭证                             *
 * ------------------------------------------------------------------ */

/// 预热令牌（第 16.3 项）
///
/// verthys_preheat 成功后生成，包含 32 字节 CSPRNG 随机签名。
/// verthys_unlock 必须携带匹配的令牌才启用零拷贝路径。
///
/// 安全特性：
///   - 一次性消费：使用后立即失效（AtomicBool 标记）
///   - 超时失效：30 秒后自动失效
///   - 常量时间比较：令牌校验使用 ct_eq 防时序攻击
///   - 不输出日志：令牌内容不记录到任何日志
pub struct PreheatToken {
    /// 32 字节随机签名（CSPRNG 生成）
    signature: [u8; 32],
    /// 创建时间（用于超时检测）
    created_at: Instant,
    /// 是否已消费（一次性使用标志）
    consumed: AtomicBool,
}

impl PreheatToken {
    /// 生成新的预热令牌
    ///
    /// 使用 CSPRNG 生成 32 字节随机签名。
    /// 令牌创建后 30 秒内有效，使用后立即失效。
    pub fn new() -> Result<Self, String> {
        let mut signature = [0u8; 32];
        crate::util::random::fill_random_bytes(&mut signature);

        Ok(PreheatToken {
            signature,
            created_at: Instant::now(),
            consumed: AtomicBool::new(false),
        })
    }

    /// 验证并消费令牌（一次性）
    ///
    /// 流程：
    ///   1. 检查是否已消费（AtomicBool compare_exchange）
    ///   2. 检查是否超时（30 秒）
    ///   3. 常量时间比较签名
    ///
    /// 验证成功后标记为已消费，后续验证必定失败。
    ///
    /// # 返回
    ///   - Ok(true): 令牌有效且已消费，启用零拷贝
    ///   - Ok(false): 令牌无效/超时/已消费，不启用零拷贝
    pub fn verify_and_consume(&self, provided: &[u8]) -> bool {
        // 1. 检查是否已消费
        if self.consumed.load(Ordering::SeqCst) {
            return false;
        }

        // 2. 检查超时
        if self.created_at.elapsed() > PREHEAT_TOKEN_TIMEOUT {
            return false;
        }

        // 3. 常量时间比较签名
        if !ct_eq(&self.signature, provided) {
            return false;
        }

        // 4. 标记为已消费（compare_exchange 确保只消费一次）
        self.consumed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// 检查令牌是否已过期（不消费）
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > PREHEAT_TOKEN_TIMEOUT
    }

    /// 检查令牌是否已消费
    pub fn is_consumed(&self) -> bool {
        self.consumed.load(Ordering::SeqCst)
    }

    /// 获取签名引用（仅供内部序列化传递，不输出日志）
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

impl std::fmt::Debug for PreheatToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不输出签名内容，仅输出状态
        f.debug_struct("PreheatToken")
            .field("consumed", &self.consumed.load(Ordering::SeqCst))
            .field("expired", &self.is_expired())
            .finish()
    }
}

/* ------------------------------------------------------------------ *
 * PreheatTokenStore — Mutex 保护的令牌存储                              *
 * ------------------------------------------------------------------ */

/// 预热令牌存储（第 16.3 项）
///
/// Mutex 保护的 Option<PreheatToken>，支持：
///   - store: 存储新令牌（替换旧令牌）
///   - take_and_verify: 取出并验证令牌（一次性消费）
///   - clear: 清除令牌
///   - is_valid: 检查是否存在有效令牌
pub struct PreheatTokenStore {
    token: std::sync::Mutex<Option<PreheatToken>>,
}

impl PreheatTokenStore {
    pub fn new() -> Self {
        PreheatTokenStore {
            token: std::sync::Mutex::new(None),
        }
    }

    /// 存储新令牌（替换旧令牌）
    ///
    /// verthys_preheat 成功后调用。旧令牌被丢弃（Drop）。
    pub fn store(&self, new_token: PreheatToken) {
        let mut guard = self.token.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(new_token);
    }

    /// 取出并验证令牌（一次性消费）
    ///
    /// verthys_unlock 调用。验证成功后令牌被消费，后续调用返回 false。
    ///
    /// # 返回
    ///   - Some(true): 令牌有效且已消费
    ///   - Some(false): 令牌存在但无效/超时/已消费
    ///   - None: 无令牌（未预热或已清除）
    pub fn verify_and_consume(&self, provided: &[u8]) -> Option<bool> {
        let guard = self.token.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().map(|t| t.verify_and_consume(provided))
    }

    /// 清除令牌
    pub fn clear(&self) {
        let mut guard = self.token.lock().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }

    /// 检查是否存在有效（未过期、未消费）的令牌
    pub fn has_valid_token(&self) -> bool {
        let guard = self.token.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .map(|t| !t.is_consumed() && !t.is_expired())
            .unwrap_or(false)
    }
}

impl Default for PreheatTokenStore {
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
    fn test_preheat_token_new() {
        let token = PreheatToken::new().unwrap();
        assert!(!token.is_consumed());
        assert!(!token.is_expired());
    }

    #[test]
    fn test_preheat_token_verify_and_consume() {
        let token = PreheatToken::new().unwrap();
        let sig = token.signature().to_vec();

        // 第一次验证应成功
        assert!(token.verify_and_consume(&sig));

        // 第二次验证应失败（已消费）
        assert!(!token.verify_and_consume(&sig));
        assert!(token.is_consumed());
    }

    #[test]
    fn test_preheat_token_wrong_signature() {
        let token = PreheatToken::new().unwrap();
        let wrong_sig = [0u8; 32];

        // 错误签名应失败
        assert!(!token.verify_and_consume(&wrong_sig));
        assert!(!token.is_consumed()); // 未消费，仍可重试
    }

    #[test]
    fn test_preheat_token_store() {
        let store = PreheatTokenStore::new();

        // 初始无令牌
        assert!(!store.has_valid_token());
        assert_eq!(store.verify_and_consume(&[0u8; 32]), None);

        // 存储令牌
        let token = PreheatToken::new().unwrap();
        let sig = token.signature().to_vec();
        store.store(token);

        assert!(store.has_valid_token());

        // 验证并消费
        assert_eq!(store.verify_and_consume(&sig), Some(true));

        // 再次验证应返回 Some(false)（已消费）
        assert_eq!(store.verify_and_consume(&sig), Some(false));

        // 清除
        store.clear();
        assert!(!store.has_valid_token());
    }

    #[test]
    fn test_preheat_token_store_replace() {
        let store = PreheatTokenStore::new();

        let token1 = PreheatToken::new().unwrap();
        let sig1 = token1.signature().to_vec();
        store.store(token1);

        // 替换为新令牌
        let token2 = PreheatToken::new().unwrap();
        let sig2 = token2.signature().to_vec();
        store.store(token2);

        // 旧令牌签名应无效
        assert_eq!(store.verify_and_consume(&sig1), Some(false));

        // 新令牌签名应有效
        assert_eq!(store.verify_and_consume(&sig2), Some(true));
    }
}
