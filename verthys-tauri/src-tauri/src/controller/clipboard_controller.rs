/*
 * controller/clipboard_controller.rs — 剪贴板安全清空控制器
 *
 * 职责：事务式安全清空剪贴板（多轮随机覆写 + 重试），失败返回明确错误码。
 *
 * 归属说明：剪贴板监听（外部写入即清空）随安全档位启停，归属安全命令层；
 * 本控制器只承担"清空"这一显式动作。剪贴板能力不再与窗口捕获排除（防截屏）
 * 联动——两者失败模式与恢复手段完全不同，耦合会让"整体成败"语义失效，
 * 并把剪贴板故障误报成防截屏的"部分保护"。
 *
 * 依赖方向：controller → security / security_commands / util（分层单向依赖）
 */

use crate::controller::types::ClipboardResult;
use crate::util::audit_log::{AuditEventType, AuditResult};
use crate::util::rate_limiter::SlidingWindowLimiter;
use std::sync::Mutex;
use std::time::Duration;

// ===== 频率限制（清空操作） =====

/// 清空剪贴板：窗口 60 秒，上限 10 次
const CLEAR_MAX_PER_MINUTE: usize = 10;

static CLEAR_CLIPBOARD_LIMITER: Mutex<SlidingWindowLimiter> = Mutex::new(
    SlidingWindowLimiter::new(Duration::from_secs(60), CLEAR_MAX_PER_MINUTE),
);

// ===== 审计日志辅助 =====

/// 写入剪贴板审计事件
///
/// 委托安全命令共享写入器：HMAC 密钥派生进程级缓存、审计链格式与
/// 落盘路径全局唯一（本控制器不重复维护第二套派生逻辑）。
fn write_clipboard_audit(
    app: &tauri::AppHandle,
    event_type: AuditEventType,
    result: AuditResult,
    detail: Option<String>,
) {
    // 全限定路径调用（分层单向依赖约束：引用不落 use 声明）
    crate::security_commands::audit::write_audit_with_extensions(
        app,
        &format!("pid-{}", std::process::id()),
        event_type,
        result,
        None,
        detail,
        crate::util::audit_log::AuditExtensions::default(),
    );
}

// ===== Tauri 命令 =====

/// 事务式安全清空剪贴板（多轮随机覆写 + 重试）
///
/// # 行为
/// - 调用底层 `ClipboardGuard::transactional_clear()` 执行擦除。
/// - 失败时返回明确的错误码（`CLIPBOARD_LOCKED` / `TEMPORARY_FAILURE` / `INTERNAL`）。
/// - 受频率限制（10 次/分钟），超限返回 `RATE_LIMITED`。
/// - 每次清空均记录审计日志。
#[tauri::command]
pub async fn clear_clipboard(app: tauri::AppHandle) -> Result<ClipboardResult, String> {
    {
        let mut limiter = CLEAR_CLIPBOARD_LIMITER
            .lock()
            .map_err(|e| format!("频率限制器锁中毒: {}", e))?;
        if !limiter.check_and_record() {
            log::warn!(
                "[clear_clipboard] 频率超限（>{}次/60秒），拒绝",
                CLEAR_MAX_PER_MINUTE
            );
            write_clipboard_audit(
                &app,
                AuditEventType::ClipboardClear,
                AuditResult::Denied,
                Some(format!(
                    "RATE_LIMITED: clear_clipboard 超过 {}次/60秒",
                    CLEAR_MAX_PER_MINUTE
                )),
            );
            return Ok(ClipboardResult::error(
                "RATE_LIMITED",
                format!("操作过于频繁，每分钟最多 {} 次", CLEAR_MAX_PER_MINUTE),
            ));
        }
    }

    let clear_result = tokio::task::spawn_blocking(|| {
        crate::security::clipboard_guard::ClipboardGuard::transactional_clear()
    })
    .await
    .map_err(|e| format!("事务式清空任务异常: {}", e))?;

    let result = match clear_result {
        Ok(()) => ClipboardResult::success(),
        Err(e) => {
            log::error!("[clear_clipboard] 事务式清空失败: {}", e);
            let code = if e.contains("OpenClipboard") {
                "CLIPBOARD_LOCKED"
            } else if e.contains("CLIPBOARD_LOCK poisoned") {
                "INTERNAL"
            } else {
                "TEMPORARY_FAILURE"
            };
            ClipboardResult::error(code, format!("剪贴板清空失败: {}", e))
        }
    };

    write_clipboard_audit(
        &app,
        AuditEventType::ClipboardClear,
        if result.ok {
            AuditResult::Success
        } else {
            AuditResult::Failure
        },
        if result.ok {
            None
        } else {
            Some(format!("error_code={:?}", result.error_code))
        },
    );

    Ok(result)
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_result_success() {
        let r = ClipboardResult::success();
        assert!(r.ok);
        assert!(r.error_code.is_none());
        assert!(!r.detail.is_empty());
    }

    #[test]
    fn test_clipboard_result_error() {
        let r = ClipboardResult::error("CLIPBOARD_LOCKED", "剪贴板被占用");
        assert!(!r.ok);
        assert_eq!(r.error_code.as_deref(), Some("CLIPBOARD_LOCKED"));
        assert_eq!(r.detail, "剪贴板被占用");
    }

    #[test]
    fn test_clear_limiter_rejects_over_limit() {
        let mut limiter = SlidingWindowLimiter::new(Duration::from_secs(60), 2);
        assert!(limiter.check_and_record());
        assert!(limiter.check_and_record());
        assert!(!limiter.check_and_record());
    }
}