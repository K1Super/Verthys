/*
 * scan_controller 单元测试
 *
 * 覆盖 shm_name 白名单、批次计数校验、会话状态机与超时常量一致性。
 */
use super::*;
use super::shared::{validate_batch_count, validate_shm_name};
use crate::state::ScanSessionState;

#[test]
fn test_validate_shm_name_valid() {
    // 合法 shm_name
    assert!(validate_shm_name("verthys_scan_3f7a9b2e1c").is_ok());
    assert!(validate_shm_name("abc123_-XYZ").is_ok());
    assert!(validate_shm_name("a").is_ok());
}

#[test]
fn test_validate_shm_name_invalid() {
    // 非法 shm_name
    assert!(validate_shm_name("").is_err()); // 空
    assert!(validate_shm_name("path/with/slash").is_err()); // 斜杠
    assert!(validate_shm_name("with space").is_err()); // 空格
    assert!(validate_shm_name("with..dots").is_err()); // 点号
    assert!(validate_shm_name("中文").is_err()); // 非 ASCII
    assert!(validate_shm_name(&"a".repeat(65)).is_err()); // 超长
    assert!(validate_shm_name("../../etc/passwd").is_err()); // 路径穿越
}

#[test]
fn test_validate_batch_count_match() {
    // 记录数一致
    assert!(validate_batch_count(0, 0).is_ok());
    assert!(validate_batch_count(100, 100).is_ok());
    assert!(validate_batch_count(10000, 10000).is_ok());
}

#[test]
fn test_validate_batch_count_mismatch() {
    // 记录数不一致（数据损坏）
    assert!(validate_batch_count(99, 100).is_err());
    assert!(validate_batch_count(101, 100).is_err());
    assert!(validate_batch_count(0, 1).is_err());
    assert!(validate_batch_count(1, 0).is_err());
}

#[test]
fn test_scan_session_state_allow_next() {
    // 状态机检查
    assert!(ScanSessionState::Active.allow_next());
    assert!(!ScanSessionState::Failed.allow_next());
    assert!(!ScanSessionState::Closed.allow_next());
}

#[test]
fn test_scan_timeouts_match_timeout_config() {
    // 常量与 TimeoutConfig 默认值一致
    use crate::constants::timeout::DEFAULT as TC;
    assert_eq!(SCAN_OPEN_TIMEOUT, TC.scan_open);
    assert_eq!(SCAN_NEXT_TIMEOUT, TC.scan_next);
    assert_eq!(SCAN_CLOSE_TIMEOUT, TC.scan_close);
    assert_eq!(SCAN_PREFETCH_TIMEOUT, TC.scan_prefetch);
    assert_eq!(PREFETCH_SHUTDOWN_TIMEOUT, TC.scan_prefetch_shutdown);
}
