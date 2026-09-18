/*
 * @file controller/clipboard_controller.rs
 * @brief 隐私模式与剪贴板保护控制器 - 防截屏联动与安全清空
 *
 * 本模块提供隐私模式的启用/关闭、剪贴板事务式安全清空、状态持久化恢复及审计日志能力。
 * 隐私模式启用时，对所有 WebView 窗口应用防截屏保护，并启动剪贴板监听守护。
 *
 * =============================================================================
 * 核心功能
 * =============================================================================
 * - 隐私模式开关：对全部窗口动态应用防截屏，联动剪贴板监听，返回结构化结果。
 * - 剪贴板安全清空：多轮随机覆写 + 重试，失败时返回明确错误码。
 * - 状态持久化：隐私模式状态经 DPAPI 加密存储于本地，启动时自动恢复。
 * - 会话令牌：启用时生成一次性令牌，关闭时需验证授权，防止无凭据关闭。
 * - 频率限制：关键操作（清空/模式切换）受 10 次/分钟滑动窗口限制。
 * - 审计日志：每次操作变更、监听事件均写入防篡改审计链。
 *
 * =============================================================================
 * 安全与合规约束
 * =============================================================================
 * - 防截屏不绑定固定窗口名，遍历所有 WebView 动态应用。
 * - 剪贴板监听启动失败不阻断防截屏，以“部分保护”状态回退。
 * - 状态文件 DPAPI 加密，绑定本机，离机失效。
 * - 会话令牌使用 CSPRNG 生成，关闭时需验证，一次性消费。
 * - 错误消息脱敏，不包含路径、密钥等敏感信息。
 * - 所有操作均有审计日志，支持异常溯源。
 *
 * =============================================================================
 * 依赖方向
 * =============================================================================
 * controller → security / security_commands / util（分层单向依赖）
 */

use crate::controller::types::{ClipboardResult, PrivacyModeResult};
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::Manager;

// ===== 频率限制器（滑动窗口） =====

/// 滑动窗口频率限制，用于清空剪贴板和模式切换操作。
/// 窗口 60 秒，上限 10 次，超限拒绝并记录审计。
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const RATE_LIMIT_MAX_CALLS: usize = 10;

struct RateLimiter {
    timestamps: Vec<Instant>,
}

impl RateLimiter {
    const fn new() -> Self {
        RateLimiter { timestamps: Vec::new() }
    }

    /// 检查是否允许本次调用，若允许则记录当前时间戳。
    /// 超出窗口的旧记录在检查时自动清理。
    fn check_and_record(&mut self) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        self.timestamps.retain(|&t| now.duration_since(t) < window);

        if self.timestamps.len() >= RATE_LIMIT_MAX_CALLS {
            return false;
        }
        self.timestamps.push(now);
        true
    }
}

static CLEAR_CLIPBOARD_RATE_LIMITER: Mutex<RateLimiter> = Mutex::new(RateLimiter::new());
static SET_PRIVACY_MODE_RATE_LIMITER: Mutex<RateLimiter> = Mutex::new(RateLimiter::new());

// ===== 审计日志辅助 =====

fn get_audit_log_path(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    app.path()
        .app_config_dir()
        .inspect_err(|e| log::warn!("[clipboard_audit] 获取配置目录失败，跳过审计写入: {}", e))
        .ok()
        .map(|dir| dir.join("audit.log"))
}

fn get_audit_hmac_key() -> Option<[u8; 32]> {
    use crate::infrastructure::device_fingerprint::get_device_fingerprint;
    use crate::util::crypto::pbkdf2_derive_default;

    let fingerprint = get_device_fingerprint().ok()?;
    const AUDIT_SALT: &[u8] = b"verthys_audit_log_hmac_salt_v1";
    pbkdf2_derive_default(fingerprint.as_bytes(), AUDIT_SALT).ok()
}

fn write_clipboard_audit(
    app: &tauri::AppHandle,
    event_type: AuditEventType,
    result: AuditResult,
    detail: Option<String>,
) {
    let (Some(log_path), Some(hmac_key)) = (get_audit_log_path(app), get_audit_hmac_key()) else {
        return;
    };
    let session_id = format!("pid-{}", std::process::id());
    let event = AuditEvent::new(event_type, &session_id, "user", result);
    let event = match detail {
        Some(d) => event.with_detail(d),
        None => event,
    };

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[clipboard_audit] 写入审计事件失败（不阻塞业务）: {}", e);
    }
}

// ===== 隐私模式状态持久化（DPAPI） =====

#[derive(serde::Serialize, serde::Deserialize)]
struct PrivacyModeState {
    enabled: bool,
    partial_protection: bool,
    timestamp: u64,
}

fn get_privacy_mode_file(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    app.path()
        .app_config_dir()
        .inspect_err(|e| log::warn!("[privacy_mode] 获取配置目录失败: {}", e))
        .ok()
        .map(|dir| dir.join(".privacy_mode"))
}

fn persist_privacy_mode(
    app: &tauri::AppHandle,
    enabled: bool,
    partial_protection: bool,
) -> Result<(), String> {
    use crate::util::crypto::dpapi_protect;

    let state = PrivacyModeState {
        enabled,
        partial_protection,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let json = serde_json::to_vec(&state)
        .map_err(|e| format!("序列化隐私模式状态失败: {}", e))?;
    let encrypted = dpapi_protect(&json, Some("verthys_privacy_mode"))?;

    let file_path = get_privacy_mode_file(app)
        .ok_or_else(|| "获取配置目录失败".to_string())?;

    let tmp_path = file_path.with_extension("privacy_mode.tmp");
    std::fs::write(&tmp_path, &encrypted)
        .map_err(|e| format!("写入临时文件失败: {}", e))?;
    std::fs::rename(&tmp_path, &file_path)
        .map_err(|e| format!("重命名状态文件失败: {}", e))?;

    log::info!(
        "[privacy_mode] 状态已持久化 (enabled={}, partial={})",
        enabled,
        partial_protection
    );
    Ok(())
}

fn load_privacy_mode(app: &tauri::AppHandle) -> Option<PrivacyModeState> {
    use crate::util::crypto::dpapi_unprotect;

    let file_path = get_privacy_mode_file(app)?;
    if !file_path.exists() {
        return None;
    }
    let encrypted = std::fs::read(&file_path).ok()?;
    let plain = dpapi_unprotect(&encrypted).ok()?;
    serde_json::from_slice(&plain).ok()
}

fn clear_privacy_mode_state(app: &tauri::AppHandle) {
    if let Some(file_path) = get_privacy_mode_file(app) {
        let _ = std::fs::remove_file(&file_path);
    }
}

// ===== 全窗口防截屏应用（不绑定窗口名） =====

/// 对所有 WebView 窗口应用或取消防截屏保护。
/// 返回 (成功数, 失败数)，调用方据此判断是否全部成功。
fn apply_privacy_to_all_windows(
    app: &tauri::AppHandle,
    enabled: bool,
) -> (usize, usize) {
    let windows = app.webview_windows();
    if windows.is_empty() {
        log::warn!("[privacy_mode] 未找到任何 webview 窗口");
        return (0, 0);
    }

    let (mut success, mut fail) = (0, 0);
    for (label, window) in windows {
        match window.hwnd() {
            Ok(hwnd) if crate::security::set_window_privacy(hwnd.0 as isize, enabled) => success += 1,
            Ok(_) => {
                fail += 1;
                log::warn!("[privacy_mode] 窗口 '{}' 防截屏设置失败", label);
            }
            Err(e) => {
                fail += 1;
                log::warn!("[privacy_mode] 窗口 '{}' 获取 HWND 失败: {}", label, e);
            }
        }
    }
    (success, fail)
}

// ===== 会话令牌（用于关闭隐私模式授权） =====

/// 启用时生成随机会话令牌，存储于进程级单例；关闭时需验证令牌。
/// 令牌在验证通过后一次性消费，防止重复使用。
static PRIVACY_SESSION_TOKEN: Mutex<Option<String>> = Mutex::new(None);

fn generate_session_token() -> String {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };
        let mut buf = [0u8; 32];
        let status = unsafe { BCryptGenRandom(None, &mut buf[..], BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if status.0 >= 0 {
            return buf.iter().map(|b| format!("{:02x}", b)).collect();
        }
        log::warn!(
            "[privacy_mode] BCryptGenRandom 失败 (NTSTATUS=0x{:08X})，回退到 SHA-256 熵源",
            status.0 as u32
        );
    }

    // 回退：SHA-256(进程ID + 纳秒时间戳 + 线程ID)
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    let pid = std::process::id();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tid = format!("{:?}", std::thread::current().id());

    let mut hasher = Sha256::new();
    hasher.update(b"verthys_privacy_session_token_v1");
    hasher.update(pid.to_le_bytes());
    hasher.update(ts.to_le_bytes());
    hasher.update(tid.as_bytes());
    let hash = hasher.finalize();

    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

fn store_session_token(token: String) {
    if let Ok(mut guard) = PRIVACY_SESSION_TOKEN.lock() {
        *guard = Some(token);
    }
}

/// 验证并消费会话令牌（一次性使用）
fn verify_and_consume_session_token(auth_token: Option<&str>) -> bool {
    // 注意：此函数返回 bool，不能使用 ? 运算符（? 要求返回 Option/Result）。
    // 改用显式 match 提前返回 false。
    let token = match auth_token {
        Some(t) => t,
        None => return false,
    };
    let mut guard = match PRIVACY_SESSION_TOKEN.lock().ok() {
        Some(g) => g,
        None => return false,
    };
    let stored = match guard.as_ref() {
        Some(s) => s,
        None => return false,
    };
    if crate::util::crypto::ct_eq(token.as_bytes(), stored.as_bytes()) {
        *guard = None;
        return true;
    }
    false
}

fn clear_session_token() {
    if let Ok(mut guard) = PRIVACY_SESSION_TOKEN.lock() {
        *guard = None;
    }
}

// ===== Tauri 命令 =====

/// 设置隐私模式（防截屏 + 剪贴板保护联动）
///
/// # 行为
/// - 启用时：遍历所有窗口应用防截屏，启动剪贴板监听，生成会话令牌。
/// - 关闭时：验证会话令牌，移除防截屏，停止监听，清除令牌。
/// - 若剪贴板监听启动失败，仍保持防截屏，返回“部分保护”状态。
/// - 所有结果（成功/部分/失败）均携带结构化信息，并记录审计日志。
///
/// # 频率限制
/// 同一操作 60 秒内最多 10 次，超限返回 `RATE_LIMITED`。
///
/// # 持久化
/// 启用或关闭后，状态自动经 DPAPI 加密保存，供下次启动恢复。
#[tauri::command]
pub async fn set_privacy_mode(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::security_commands::SecurityState>,
    enabled: bool,
    auth_token: Option<String>,
) -> Result<PrivacyModeResult, String> {
    // 频率限制
    {
        let mut limiter = SET_PRIVACY_MODE_RATE_LIMITER
            .lock()
            .map_err(|e| format!("频率限制器锁中毒: {}", e))?;
        if !limiter.check_and_record() {
            log::warn!(
                "[privacy_mode] 频率超限（>{}次/{}秒），拒绝 set_privacy_mode({})",
                RATE_LIMIT_MAX_CALLS,
                RATE_LIMIT_WINDOW_SECS,
                enabled
            );
            write_clipboard_audit(
                &app,
                AuditEventType::ClipboardModeChange,
                AuditResult::Denied,
                Some(format!(
                    "RATE_LIMITED: set_privacy_mode({}) 超过 {}次/{}秒",
                    enabled, RATE_LIMIT_MAX_CALLS, RATE_LIMIT_WINDOW_SECS
                )),
            );
            return Ok(PrivacyModeResult::error(
                "RATE_LIMITED",
                format!("操作过于频繁，每分钟最多 {} 次", RATE_LIMIT_MAX_CALLS),
            ));
        }
    }

    // 关闭时需验证会话令牌
    if !enabled && !verify_and_consume_session_token(auth_token.as_deref()) {
        log::warn!("[privacy_mode] 关闭隐私模式会话令牌验证失败，拒绝");
        write_clipboard_audit(
            &app,
            AuditEventType::ClipboardModeChange,
            AuditResult::Denied,
            Some("PERMISSION_DENIED: 关闭隐私模式会话令牌不匹配或缺失".into()),
        );
        return Ok(PrivacyModeResult::error(
            "PERMISSION_DENIED",
            "关闭隐私模式需要有效授权令牌",
        ));
    }

    // 剪贴板监听联动
    let mut monitor_failed = false;
    if let Ok(mut guard) = state.clipboard_guard.lock() {
        if enabled {
            guard.set_high_security_mode(true);
            if let Err(e) = guard.start_monitoring() {
                log::error!("[privacy_mode] 剪贴板监听启动失败: {}", e);
                monitor_failed = true;
            }
        } else {
            guard.stop_monitoring();
            guard.set_high_security_mode(false);
        }
    } else {
        log::error!("[privacy_mode] 剪贴板守卫锁获取失败");
        if enabled {
            monitor_failed = true;
        }
    }

    // 防截屏应用到所有窗口
    let (success_count, fail_count) = apply_privacy_to_all_windows(&app, enabled);

    // 生成会话令牌（启用时）
    let session_token = if enabled { Some(generate_session_token()) } else { None };

    // 构建结构化结果
    let result = if success_count == 0 && fail_count == 0 {
        PrivacyModeResult::error("INTERNAL", "未找到可应用防截屏的窗口")
    } else if enabled && monitor_failed {
        PrivacyModeResult::partial_with_token(
            true,
            "CLIPBOARD_MONITOR_FAILED",
            "防截屏已启用，但剪贴板监听启动失败，处于部分保护状态",
            session_token.clone().unwrap_or_default(),
        )
    } else if success_count > 0 && fail_count > 0 {
        let token = session_token.clone().unwrap_or_default();
        if enabled {
            PrivacyModeResult::partial_with_token(
                enabled,
                "TEMPORARY_FAILURE",
                format!(
                    "防截屏已应用于 {}/{} 个窗口，{} 个失败",
                    success_count,
                    success_count + fail_count,
                    fail_count
                ),
                token,
            )
        } else {
            PrivacyModeResult::partial(
                enabled,
                "TEMPORARY_FAILURE",
                format!(
                    "防截屏已移除于 {}/{} 个窗口，{} 个失败",
                    success_count,
                    success_count + fail_count,
                    fail_count
                ),
            )
        }
    } else if success_count > 0 {
        if let Some(ref token) = session_token {
            PrivacyModeResult::success_with_token(enabled, token)
        } else {
            PrivacyModeResult::success(enabled)
        }
    } else {
        PrivacyModeResult::error("TEMPORARY_FAILURE", "防截屏设置失败（SetWindowDisplayAffinity 调用失败）")
    };

    // 存储/清除会话令牌
    if result.ok && enabled {
        if let Some(ref token) = session_token {
            store_session_token(token.clone());
        }
    } else if result.ok && !enabled {
        clear_session_token();
    }

    // 持久化状态（仅成功或部分保护）
    if result.ok {
        if let Err(e) = persist_privacy_mode(&app, enabled, result.partial_protection) {
            log::warn!("[privacy_mode] 状态持久化失败: {}", e);
        }
    }

    // 审计日志
    let audit_result = if result.ok {
        if result.partial_protection { AuditResult::Failure } else { AuditResult::Success }
    } else {
        AuditResult::Failure
    };
    let audit_detail = if result.partial_protection {
        Some(format!("partial_protection: enabled={}, error_code={:?}", enabled, result.error_code))
    } else if !result.ok {
        Some(format!("failed: error_code={:?}", result.error_code))
    } else {
        None
    };
    write_clipboard_audit(&app, AuditEventType::ClipboardModeChange, audit_result, audit_detail);

    if result.ok {
        let monitor_detail = if enabled {
            if monitor_failed {
                Some("clipboard monitor start FAILED (partial protection)".into())
            } else {
                Some("clipboard monitor started".into())
            }
        } else {
            Some("clipboard monitor stopped".into())
        };
        write_clipboard_audit(
            &app,
            AuditEventType::ClipboardMonitorEvent,
            if monitor_failed { AuditResult::Failure } else { AuditResult::Success },
            monitor_detail,
        );
    }

    Ok(result)
}

/// 事务式安全清空剪贴板（多轮随机覆写 + 重试）
///
/// # 行为
/// - 调用底层 `ClipboardGuard::transactional_clear()` 执行擦除。
/// - 失败时返回明确的错误码（`CLIPBOARD_LOCKED` / `TEMPORARY_FAILURE` / `INTERNAL`）。
/// - 受频率限制（10 次/分钟），超限返回 `RATE_LIMITED`。
/// - 每次清空均记录审计日志。
#[tauri::command]
pub async fn clear_clipboard(
    app: tauri::AppHandle,
) -> Result<ClipboardResult, String> {
    // 频率限制
    {
        let mut limiter = CLEAR_CLIPBOARD_RATE_LIMITER
            .lock()
            .map_err(|e| format!("频率限制器锁中毒: {}", e))?;
        if !limiter.check_and_record() {
            log::warn!(
                "[clear_clipboard] 频率超限（>{}次/{}秒），拒绝",
                RATE_LIMIT_MAX_CALLS,
                RATE_LIMIT_WINDOW_SECS
            );
            write_clipboard_audit(
                &app,
                AuditEventType::ClipboardClear,
                AuditResult::Denied,
                Some(format!(
                    "RATE_LIMITED: clear_clipboard 超过 {}次/{}秒",
                    RATE_LIMIT_MAX_CALLS, RATE_LIMIT_WINDOW_SECS
                )),
            );
            return Ok(ClipboardResult::error(
                "RATE_LIMITED",
                format!("操作过于频繁，每分钟最多 {} 次", RATE_LIMIT_MAX_CALLS),
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
        if result.ok { AuditResult::Success } else { AuditResult::Failure },
        if result.ok { None } else { Some(format!("error_code={:?}", result.error_code)) },
    );

    Ok(result)
}

/// 启动时恢复持久化的隐私模式状态
///
/// 从 DPAPI 加密的状态文件读取上次的隐私模式状态（启用/部分保护），
/// 若状态为启用则自动重新应用防截屏并启动剪贴板监听。
/// 恢复过程中生成新的会话令牌，旧令牌失效。
/// 该命令应在应用 setup 阶段调用。
#[tauri::command]
pub async fn restore_privacy_mode(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::security_commands::SecurityState>,
) -> Result<PrivacyModeResult, String> {
    let saved_state = load_privacy_mode(&app);

    match saved_state {
        Some(s) if s.enabled => {
            log::info!(
                "[privacy_mode] 检测到持久化的隐私模式状态 (enabled={}, partial={})，开始恢复",
                s.enabled,
                s.partial_protection
            );

            let mut monitor_failed = false;
            if let Ok(mut guard) = state.clipboard_guard.lock() {
                guard.set_high_security_mode(true);
                if let Err(e) = guard.start_monitoring() {
                    log::error!("[privacy_mode] 恢复剪贴板监听失败: {}", e);
                    monitor_failed = true;
                }
            }

            let (success_count, fail_count) = apply_privacy_to_all_windows(&app, true);

            let token = generate_session_token();
            store_session_token(token.clone());

            let result = if monitor_failed || fail_count > 0 {
                PrivacyModeResult::partial_with_token(
                    true,
                    "CLIPBOARD_MONITOR_FAILED",
                    format!(
                        "隐私模式已恢复（部分保护）：防截屏 {}/{} 窗口成功，监听={}",
                        success_count,
                        success_count + fail_count,
                        if monitor_failed { "失败" } else { "成功" }
                    ),
                    token,
                )
            } else {
                PrivacyModeResult::success_with_token(true, token)
            };

            write_clipboard_audit(
                &app,
                AuditEventType::ClipboardModeChange,
                if result.partial_protection { AuditResult::Failure } else { AuditResult::Success },
                Some(format!("restored from persisted state (partial={})", result.partial_protection)),
            );

            Ok(result)
        }
        Some(_) => {
            log::info!("[privacy_mode] 持久化状态为已关闭，无需恢复");
            Ok(PrivacyModeResult::success(false))
        }
        None => {
            log::info!("[privacy_mode] 无持久化状态，跳过恢复");
            Ok(PrivacyModeResult::success(false))
        }
    }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new();
        for i in 0..RATE_LIMIT_MAX_CALLS {
            assert!(limiter.check_and_record(), "第 {} 次调用应被允许", i + 1);
        }
        assert!(!limiter.check_and_record(), "超限调用应被拒绝");
    }

    #[test]
    fn test_rate_limiter_expires_old_entries() {
        let mut limiter = RateLimiter::new();
        for _ in 0..RATE_LIMIT_MAX_CALLS {
            assert!(limiter.check_and_record());
        }
        let old = Instant::now() - Duration::from_secs(120);
        limiter.timestamps.iter_mut().for_each(|t| *t = old);
        assert!(limiter.check_and_record(), "过期时间戳清理后应允许新调用");
    }

    #[test]
    fn test_verify_and_consume_session_token() {
        assert!(!verify_and_consume_session_token(None));
        assert!(!verify_and_consume_session_token(Some("")));
        assert!(!verify_and_consume_session_token(Some("wrong")));

        let token = generate_session_token();
        store_session_token(token.clone());
        assert!(verify_and_consume_session_token(Some(&token)));
        assert!(!verify_and_consume_session_token(Some(&token))); // 已消费
        clear_session_token();
    }

    #[test]
    fn test_generate_session_token_uniqueness() {
        let t1 = generate_session_token();
        let t2 = generate_session_token();
        assert_ne!(t1, t2);
        assert_eq!(t1.len(), 64);
    }

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
    fn test_privacy_mode_result_success() {
        let r = PrivacyModeResult::success(true);
        assert!(r.ok);
        assert!(r.enabled);
        assert!(!r.partial_protection);
        assert!(r.error_code.is_none());
        assert!(r.session_token.is_none());

        let r = PrivacyModeResult::success(false);
        assert!(r.ok);
        assert!(!r.enabled);
        assert!(!r.partial_protection);
    }

    #[test]
    fn test_privacy_mode_result_success_with_token() {
        let r = PrivacyModeResult::success_with_token(true, "abc");
        assert!(r.ok);
        assert!(r.enabled);
        assert_eq!(r.session_token.as_deref(), Some("abc"));

        let r = PrivacyModeResult::success_with_token(false, "abc");
        assert!(r.session_token.is_none());
    }

    #[test]
    fn test_privacy_mode_result_partial() {
        let r = PrivacyModeResult::partial(
            true,
            "CLIPBOARD_MONITOR_FAILED",
            "部分保护",
        );
        assert!(r.ok);
        assert!(r.enabled);
        assert!(r.partial_protection);
        assert_eq!(r.error_code.as_deref(), Some("CLIPBOARD_MONITOR_FAILED"));
        assert!(r.session_token.is_none());
    }

    #[test]
    fn test_privacy_mode_result_partial_with_token() {
        let r = PrivacyModeResult::partial_with_token(
            true,
            "CLIPBOARD_MONITOR_FAILED",
            "部分保护",
            "token",
        );
        assert!(r.ok);
        assert!(r.enabled);
        assert!(r.partial_protection);
        assert_eq!(r.session_token.as_deref(), Some("token"));
    }

    #[test]
    fn test_privacy_mode_result_error() {
        let r = PrivacyModeResult::error("RATE_LIMITED", "频率超限");
        assert!(!r.ok);
        assert!(!r.enabled);
        assert!(!r.partial_protection);
        assert_eq!(r.error_code.as_deref(), Some("RATE_LIMITED"));
    }

    #[test]
    fn test_privacy_mode_state_serialization() {
        let state = PrivacyModeState {
            enabled: true,
            partial_protection: false,
            timestamp: 1234567890,
        };
        let json = serde_json::to_vec(&state).unwrap();
        let decoded: PrivacyModeState = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.enabled, state.enabled);
        assert_eq!(decoded.partial_protection, state.partial_protection);
        assert_eq!(decoded.timestamp, state.timestamp);
    }
}