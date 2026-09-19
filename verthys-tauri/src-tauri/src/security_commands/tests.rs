/*
 * tests.rs — 安全命令模块集成测试
 *
 *
 * 职责：
 *   验证 SecurityResult 构造、auth_token 生成/存储/消费、
 *   BruteForcePersistedState 序列化、BruteForceGuard 导入导出往返、
 *   base64 编解码往返、ShadowSleep 真实 txid。
 *
 *   测试体保持与原 security_commands.rs 中的实现一致（零行为变更）。
 */

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::security::brute_force::{BruteForceConfig, BruteForceGuard, BruteForcePersistedState};
use crate::security::usb_guard::ShadowSleep;

use super::auth::{generate_auth_token, store_auth_token, verify_and_consume_auth_token};
use super::responses::SecurityResult;
use super::state::SecurityState;

#[test]
fn test_security_result_success() {
    let r = SecurityResult::success("操作成功");
    assert!(r.ok);
    assert_eq!(r.detail, "操作成功");
    assert!(r.error_code.is_none());
}

#[test]
fn test_security_result_error() {
    let r = SecurityResult::error("PERMISSION_DENIED", "缺少授权令牌");
    assert!(!r.ok);
    assert_eq!(r.error_code.as_deref(), Some("PERMISSION_DENIED"));
    assert_eq!(r.detail, "缺少授权令牌");
}

#[test]
fn test_auth_token_generation_uniqueness() {
    let t1 = generate_auth_token();
    let t2 = generate_auth_token();
    assert_ne!(t1, t2, "两次生成的令牌应不同");
    assert_eq!(t1.len(), 64, "令牌应为 64 字符 hex（32 字节）");
    assert!(t1.chars().all(|c| c.is_ascii_hexdigit()), "令牌应为 hex 字符");
}

#[test]
fn test_auth_token_store_and_consume() {
    let state = SecurityState::new();

    // 无令牌 → 验证失败
    assert!(!verify_and_consume_auth_token(&state, None));
    assert!(!verify_and_consume_auth_token(&state, Some("")));
    assert!(!verify_and_consume_auth_token(&state, Some("wrong_token")));

    // 存储令牌后验证
    let token = generate_auth_token();
    store_auth_token(&state, token.clone());

    // 正确令牌 → 验证通过并消费
    assert!(verify_and_consume_auth_token(&state, Some(&token)));

    // 二次使用同一令牌 → 拒绝（一次性消费）
    assert!(!verify_and_consume_auth_token(&state, Some(&token)));
}

#[test]
fn test_brute_force_persisted_state_serde() {
    let state = BruteForcePersistedState {
        consecutive_failures: 5,
        total_failures: 10,
        lock_remaining_secs: 300,
        purge_triggered: false,
        last_purge_total: 0,
    };

    let json = serde_json::to_string(&state).unwrap();
    let restored: BruteForcePersistedState = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.consecutive_failures, 5);
    assert_eq!(restored.total_failures, 10);
    assert_eq!(restored.lock_remaining_secs, 300);
    assert!(!restored.purge_triggered);
}

#[test]
fn test_brute_force_export_import_roundtrip() {
    // 测试中禁用速率限制
    let guard = BruteForceGuard::with_config(BruteForceConfig {
        rate_limit_ms: 0,
        ..Default::default()
    });

    // 模拟 5 次失败
    for _ in 0..5 {
        guard.record_failure();
    }

    // 导出状态
    let exported = guard.export_state();
    assert_eq!(exported.consecutive_failures, 5);
    assert_eq!(exported.total_failures, 5);

    // 创建新守卫并导入状态
    let guard2 = BruteForceGuard::new();
    guard2.import_state(&exported);
    assert_eq!(guard2.consecutive_failures(), 5);
    assert_eq!(guard2.total_failures(), 5);
}

#[test]
fn test_base64_encode_decode_roundtrip() {
    let original = b"Hello, Verthys! Shadow sleep index data.";
    let encoded = STANDARD.encode(original);
    let decoded = STANDARD.decode(&encoded).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_shadow_sleep_status_real_txid() {
    let mut shadow = ShadowSleep::new();

    // 未处于影子休眠时 txid = 0
    assert_eq!(shadow.current_txid(), 0);
    assert!(!shadow.is_in_shadow_sleep());

    // 进入影子休眠
    shadow.enter_shadow_sleep(vec![1, 2, 3], 12345, 30);
    assert!(shadow.is_in_shadow_sleep());
    // 返回真实 txid（非 0）
    assert_eq!(shadow.current_txid(), 12345);

    // 恢复后 txid 归零
    shadow.try_recover(12345);
    assert_eq!(shadow.current_txid(), 0);
}
