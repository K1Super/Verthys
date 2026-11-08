/*
 * state/verthys_session.rs — Verthys 会话 RAII 守卫
 *
 *
 * 架构定位：状态层（state）会话管理模块
 *   - 依赖 security::file_lock（VerthysFileLock 跨进程独占锁）
 *   - 提供 VerthysSessionGuard RAII
 *
 * VerthysSessionGuard RAII：
 *   构造时获取共享读哨兵锁 + 记录会话路径，Drop 时自动释放。
 *   锁语义红线：worker 容器句柄以 FILE_SHARE_READ 单写者语义存活
 *   （C 层跨进程互斥），本进程以 GENERIC_WRITE 打开同文件会被内核以
 *   SHARING_VIOLATION 拒绝——守卫只能挂共享读锁（GENERIC_READ），
 *   跨实例单写者互斥由 C 层容器句柄承担，本锁仅作进程内会话哨兵。
 *   原 verthys_unlock / verthys_lock 手工 file_lock 移入移出，异常路径可能遗漏释放。
 *   新设计：VerthysSessionGuard 构造时获取哨兵锁 + 记录会话路径，
 *   Drop 时自动释放文件锁。AppState 持 Option<VerthysSessionGuard>，
 *   命令通过 with_session 访问。
 *
 * CI 红线：
 *   - 文件锁获取失败返回 Err，不降级
 */

use crate::security::file_lock::VerthysFileLock;
use std::time::{Duration, Instant};

/* ------------------------------------------------------------------ *
 * VerthysSessionGuard — RAII 会话守卫                        *
 * ------------------------------------------------------------------ */

/// Verthys 会话 RAII 守卫
///
/// 构造时获取 .verthys 文件共享读哨兵锁，记录会话路径与 ID。
/// Drop 时自动释放文件锁，确保异常路径不遗漏。
///
/// 哨兵锁为共享读锁：worker 容器句柄存续期间（FILE_SHARE_READ
/// 单写者语义）以写访问打开同文件会被内核拒绝，故本守卫不得
/// 使用独占锁；跨实例写互斥由 C 层容器锁承担。
///
/// AppState 持有 `Option<VerthysSessionGuard>`：
///   - verthys_unlock 成功后创建（Some）
///   - verthys_lock / 进程退出时销毁（None）
///
/// 所有需要访问 verthys 文件的命令通过此守卫获取会话路径，
/// 不再直接操作 verthys_file_lock。
pub struct VerthysSessionGuard {
    /// .verthys 文件共享读哨兵锁（Drop 自动释放 LockFileEx）
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
    /// 创建会话守卫（获取共享读哨兵锁）
    ///
    /// 在 verthys_unlock 成功后调用：
    ///   1. 对 .verthys 文件获取共享读锁（LockFileEx，GENERIC_READ 句柄，
    ///      与 worker 的 FILE_SHARE_READ 容器句柄共享模式兼容）
    ///   2. 记录会话路径与 ID
    ///
    /// # 错误
    /// 文件锁获取失败返回 Err，verthys_unlock 应据此回滚。
    pub fn new(verthys_path: &str, session_id: &str) -> Result<Self, String> {
        let file_lock = VerthysFileLock::lock_shared(verthys_path).inspect_err(|_| {
            log::error!(
                "[VerthysSessionGuard] 获取哨兵锁失败: {}",
                crate::util::path::sanitize_path(verthys_path)
            );
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
