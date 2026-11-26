/*
 * 隐私保护 Tauri 命令
 *
 * 职责边界：模式设置、状态查询、会话采纳与对账四个命令入口，以及
 * 每类操作的独立限流器。状态查询只读幂等，不限流。
 */

use crate::controller::types::{PrivacyModeResult, PrivacyStatusResult};
use crate::util::audit_log::{AuditEventType, AuditExtensions, AuditResult};
use crate::util::rate_limiter::SlidingWindowLimiter;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::State;

use super::*;
/* ====================================================================== *
 *  Tauri 命令                                                             *
 * ====================================================================== */

static ENABLE_LIMITER: Mutex<SlidingWindowLimiter> = Mutex::new(SlidingWindowLimiter::new(
    Duration::from_secs(60),
    ENABLE_MAX_PER_MINUTE,
));
static DISABLE_LIMITER: Mutex<SlidingWindowLimiter> = Mutex::new(SlidingWindowLimiter::new(
    Duration::from_secs(60),
    DISABLE_MAX_PER_MINUTE,
));
static ADOPT_LIMITER: Mutex<SlidingWindowLimiter> = Mutex::new(SlidingWindowLimiter::new(
    Duration::from_secs(60),
    ADOPT_MAX_PER_MINUTE,
));
static RECONCILE_LIMITER: Mutex<SlidingWindowLimiter> = Mutex::new(SlidingWindowLimiter::new(
    Duration::from_secs(60),
    RECONCILE_MAX_PER_MINUTE,
));

/// 取用限流器名额；超限返回 false
fn take_rate_limit(slot: &'static Mutex<SlidingWindowLimiter>) -> Result<bool, String> {
    let mut limiter = slot
        .lock()
        .map_err(|e| format!("频率限制器锁中毒: {}", e))?;
    Ok(limiter.check_and_record())
}

/// 设置防截屏保护（窗口捕获排除）
///
/// - 开启：整体成功或整体失败，成功后返回一次性会话凭证
/// - 关闭：需传入开启时获得的凭证；失败后凭证保留，可立即重试
/// - 关闭成功即消费凭证；重复关闭由幂等短路直接成功返回
#[tauri::command]
pub async fn set_privacy_mode(
    app: tauri::AppHandle,
    coordinator: State<'_, Arc<PrivacyCoordinator>>,
    enabled: bool,
    auth_token: Option<String>,
) -> Result<PrivacyModeResult, String> {
    let limiter = if enabled {
        &ENABLE_LIMITER
    } else {
        &DISABLE_LIMITER
    };
    if !take_rate_limit(limiter)? {
        let max = if enabled {
            ENABLE_MAX_PER_MINUTE
        } else {
            DISABLE_MAX_PER_MINUTE
        };
        let cause = PrivacyError::RateLimited {
            max_per_minute: max,
        };
        log::warn!("[privacy] 频率超限，拒绝 set_privacy_mode({})", enabled);
        coordinator.audit.write(
            AuditEventType::PrivacyModeChange,
            AuditResult::Denied,
            cause.detail(),
            AuditExtensions::default(),
        );
        return Ok(PrivacyModeResult::error(cause.code(), cause.detail()));
    }

    let coordinator_arc = Arc::clone(coordinator.inner());
    let app_for_task = app.clone();
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let targets = collect_targets(&app_for_task)?;
        coordinator_arc.transition(enabled, auth_token.as_deref(), &targets)
    })
    .await
    .map_err(|e| format!("隐私模式过渡任务异常: {}", e))?;

    match outcome {
        Ok(result) => Ok(PrivacyModeResult::success_with_token(
            result.enabled,
            result.session_token.unwrap_or_default(),
        )),
        Err(cause) => {
            // 凭证类拒绝必须留审计（无授权关闭尝试是安全事件）；
            // 过渡类失败的审计已在状态机内完成，不重复记
            if matches!(
                cause,
                PrivacyError::TokenInvalid
                    | PrivacyError::TokenMissing
                    | PrivacyError::LeaseHeld
                    | PrivacyError::LeaseExpired
            ) {
                coordinator.audit.write(
                    AuditEventType::PrivacyModeChange,
                    AuditResult::Denied,
                    cause.detail(),
                    AuditExtensions::default(),
                );
            }
            Ok(PrivacyModeResult::error(cause.code(), cause.detail()))
        }
    }
}

/// 查询防截屏保护状态（只读幂等，不限流）
#[tauri::command]
pub fn get_privacy_status(coordinator: State<'_, Arc<PrivacyCoordinator>>) -> PrivacyStatusResult {
    let snapshot = coordinator.status();
    PrivacyStatusResult {
        state: snapshot.state.to_string(),
        slot: snapshot.slot.to_string(),
        protected_count: snapshot.protected_count,
        quarantined_reason: snapshot.quarantined_reason.map(|reason| reason.to_string()),
    }
}

/// 采纳保护会话：把启动恢复/对账后的待采纳状态转为生效并取得凭证
#[tauri::command]
pub fn adopt_privacy_session(
    coordinator: State<'_, Arc<PrivacyCoordinator>>,
) -> Result<PrivacyModeResult, String> {
    if !take_rate_limit(&ADOPT_LIMITER)? {
        let cause = PrivacyError::RateLimited {
            max_per_minute: ADOPT_MAX_PER_MINUTE,
        };
        return Ok(PrivacyModeResult::error(cause.code(), cause.detail()));
    }

    match coordinator.adopt() {
        Ok((plaintext, _generation)) => Ok(PrivacyModeResult::success_with_token(true, &plaintext)),
        Err(PrivacyError::AlreadyAdopted) => {
            // 重复采纳不是失败：会话已由其他挂载点接管，前端按"忽略"处理
            Ok(PrivacyModeResult::success(true))
        }
        Err(cause) => Ok(PrivacyModeResult::error(cause.code(), cause.detail())),
    }
}

/// 隔离对账：按失败前的稳定状态全窗口重扫收敛
///
/// 对账是破坏性低频操作，限流更严；仅在隔离状态下可达，收敛目标取失败前的稳定状态。
#[tauri::command]
pub async fn reconcile_privacy(
    app: tauri::AppHandle,
    coordinator: State<'_, Arc<PrivacyCoordinator>>,
) -> Result<PrivacyModeResult, String> {
    if !take_rate_limit(&RECONCILE_LIMITER)? {
        let cause = PrivacyError::RateLimited {
            max_per_minute: RECONCILE_MAX_PER_MINUTE,
        };
        return Ok(PrivacyModeResult::error(cause.code(), cause.detail()));
    }

    let coordinator_arc = Arc::clone(coordinator.inner());
    let app_for_task = app.clone();
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let targets = collect_targets(&app_for_task)?;
        coordinator_arc.reconcile(&targets)
    })
    .await
    .map_err(|e| format!("隐私对账任务异常: {}", e))?;

    match outcome {
        Ok(result) => {
            // 对账至启用时槽位回待采纳，前端随后采纳取得新凭证
            Ok(PrivacyModeResult::success(result.enabled))
        }
        Err(cause) => Ok(PrivacyModeResult::error(cause.code(), cause.detail())),
    }
}
