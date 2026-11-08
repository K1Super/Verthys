/*
 * commands/brute_force.rs — 暴力拦截命令
 *
 *
 * 职责：
 *   暴力拦截 Tauri 命令实现：
 *     - security_brute_check：查询当前是否允许尝试解锁（纯查询）
 *     - security_brute_status：获取暴力拦截状态快照
 *
 * 计数与重置由服务端口令类命令入口权威执行；本模块只提供只读查询。
 */

use tauri::State;

use crate::security::brute_force::BruteForceCheck;

use crate::security_commands::persistence::ensure_brute_force_loaded;
use crate::security_commands::responses::{BruteForceCheckResponse, BruteForceStatus};
use crate::security_commands::state::{lock_brute_force_or_recover, SecurityState};

/// 检查当前是否允许尝试解锁（纯查询，不消耗尝试额度）
#[tauri::command]
pub fn security_brute_check(
    app: tauri::AppHandle,
    state: State<SecurityState>,
) -> Result<BruteForceCheckResponse, String> {
    // 首次访问时从持久化加载状态
    ensure_brute_force_loaded(&app, &state);

    let guard = lock_brute_force_or_recover(&state)?;
    Ok(match guard.check() {
        BruteForceCheck::Allow => BruteForceCheckResponse::Allow,
        BruteForceCheck::Locked(secs) => BruteForceCheckResponse::Locked {
            remaining_secs: secs,
        },
        /* check() 为纯查询，永远不会返回 RateLimited；此处仅为穷尽匹配 */
        BruteForceCheck::RateLimited { .. } => BruteForceCheckResponse::Allow,
    })
}

/// 获取暴力拦截状态快照
#[tauri::command]
pub fn security_brute_status(
    app: tauri::AppHandle,
    state: State<SecurityState>,
) -> Result<BruteForceStatus, String> {
    // 首次访问时从持久化加载状态
    ensure_brute_force_loaded(&app, &state);

    let guard = lock_brute_force_or_recover(&state)?;
    Ok(BruteForceStatus {
        consecutive_failures: guard.consecutive_failures(),
        total_failures: guard.total_failures(),
        remaining_lock_secs: guard.remaining_lock_secs(),
    })
}
