/*
 * key_controller 单元测试
 *
 * 覆盖输入校验边界、超时常量绑定、生命周期状态转移与冷却、
 * 密钥操作互斥的串行化行为。
 */

use super::op_lock::acquire_key_op;
use super::validation::{
    decode_and_validate_b64, validate_password_complexity, validate_password_length,
    BASE64_DECODED_MAX_BYTES,
};
use super::{CLEAR_TIMEOUT, DERIVE_VERIFY_TIMEOUT};
use crate::constants::timeout::DEFAULT as TIMEOUT_CONFIG;
use crate::state::{AppState, KeyLifecycleState, VerifyCheckResult};

// ===== 单元测试 =====

#[test]
fn test_validate_password_length_ok() {
    assert!(validate_password_length("short").is_ok());
    assert!(validate_password_length(&"a".repeat(512)).is_ok());
}

#[test]
fn test_validate_password_length_too_long() {
    let result = validate_password_length(&"a".repeat(513));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("过长"));
}

#[test]
fn test_validate_password_complexity_short() {
    let result = validate_password_complexity("abc");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("长度不足"));
}

#[test]
fn test_validate_password_complexity_ok() {
    assert!(validate_password_complexity("password123").is_ok());
}

#[test]
fn test_validate_password_complexity_too_long() {
    let result = validate_password_complexity(&"a".repeat(513));
    assert!(result.is_err());
}

#[test]
fn test_decode_and_validate_b64_ok() {
    let result = decode_and_validate_b64("dGVzdA==");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), b"test");
}

#[test]
fn test_decode_and_validate_b64_invalid() {
    let result = decode_and_validate_b64("!!!invalid_base64!!!");
    assert!(result.is_err());
}

#[test]
fn test_decode_and_validate_b64_too_large() {
    let large_data = vec![0u8; BASE64_DECODED_MAX_BYTES + 1];
    let large_b64 = crate::util::base64::base64_encode(&large_data);
    let result = decode_and_validate_b64(&large_b64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("过大"));
}

#[test]
fn test_key_lifecycle_state_transitions() {
    let lifecycle = crate::state::KeyLifecycle::new();
    assert_eq!(lifecycle.current_state(), KeyLifecycleState::NoKey);
    assert!(lifecycle.transition_to_locked().is_ok());
    assert_eq!(lifecycle.current_state(), KeyLifecycleState::Locked);
    assert!(lifecycle.transition_to_unlocked().is_ok());
    assert_eq!(lifecycle.current_state(), KeyLifecycleState::Unlocked);
    lifecycle.transition_to_locked_from_unlocked();
    assert_eq!(lifecycle.current_state(), KeyLifecycleState::Locked);
}

#[test]
fn test_key_lifecycle_cooldown_integration() {
    let lifecycle = crate::state::KeyLifecycle::new();
    lifecycle.transition_to_locked().unwrap();

    for _ in 0..5 {
        assert_eq!(
            lifecycle.record_verify_failure(),
            crate::state::VerifyAttemptResult::Failure
        );
        assert_eq!(lifecycle.check_verify_allowed(), VerifyCheckResult::Allow);
    }

    let result = lifecycle.record_verify_failure();
    assert!(matches!(
        result,
        crate::state::VerifyAttemptResult::FailureCooldown(2)
    ));

    assert!(matches!(
        lifecycle.check_verify_allowed(),
        VerifyCheckResult::Cooldown(_)
    ));
}

#[test]
fn test_timeout_constants() {
    assert_eq!(DERIVE_VERIFY_TIMEOUT, TIMEOUT_CONFIG.derive_verify);
    assert_eq!(CLEAR_TIMEOUT, TIMEOUT_CONFIG.clipboard_op);
}

#[test]
fn key_op_mutex_serializes_key_commands() {
    let state = AppState::new();
    let guard = acquire_key_op(&state, "first").expect("首次获取必须成功");
    assert!(
        acquire_key_op(&state, "second").is_none(),
        "并发密钥操作必须被拒绝"
    );
    drop(guard);
    assert!(
        acquire_key_op(&state, "third").is_some(),
        "释放后必须可再次获取"
    );
}
