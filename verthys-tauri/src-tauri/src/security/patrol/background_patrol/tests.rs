/*
 * background_patrol/tests.rs — 单元测试
 */

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::security::module_whitelist::{SignatureStatus, UnknownModule};

use super::os::normalize_key;
use super::patrol::{severity_for_signature, ThreatSeverity};
use super::persistence::{compute_hmac, is_supported_state_schema, SerializablePatrolState};
use super::state::{HashBaselineManager, PatrolState};
use super::watchdog::{
    compute_dynamic_interval, generate_random_u64, sample_random, sleep_with_heartbeat,
};
use super::{
    CONSECUTIVE_TRIGGER_THRESHOLD, PATROL_MAX_INTERVAL_SECS, PATROL_MIN_INTERVAL_SECS,
    PATROL_STATE_SCHEMA_VERSION, RING_BUFFER_MAX_ENTRIES,
};

#[test]
fn test_normalize_key() {
    assert_eq!(
        normalize_key(r"\\?\C:\Windows\System32\test.dll"),
        "c:\\windows\\system32\\test.dll"
    );
    assert_eq!(
        normalize_key("C:/Windows/test.dll"),
        "c:\\windows\\test.dll"
    );
    assert_eq!(normalize_key("C:\\Windows\\"), "c:\\windows");
}

#[test]
fn test_patrol_state_record_and_trigger() {
    let mut state = PatrolState::new("c:\\app".to_string());
    let module = UnknownModule {
        name: "evil.dll".to_string(),
        path: "C:\\temp\\evil.dll".to_string(),
        reason: "未知路径".to_string(),
    };

    // 第一次：计数 1，不触发
    let triggered = state.record(std::slice::from_ref(&module));
    assert!(triggered.is_empty());
    assert_eq!(state.patrol_count, 1);

    // 第二次：计数 2，不触发
    let triggered = state.record(std::slice::from_ref(&module));
    assert!(triggered.is_empty());

    // 第三次：计数 3，触发
    let triggered = state.record(std::slice::from_ref(&module));
    assert_eq!(triggered.len(), 1);
    assert_eq!(triggered[0].name, "evil.dll");

    // 第四次：已触发过，不再触发
    let triggered = state.record(std::slice::from_ref(&module));
    assert!(triggered.is_empty());
}

#[test]
fn test_patrol_state_consecutive_break() {
    let mut state = PatrolState::new("c:\\app".to_string());
    let module = UnknownModule {
        name: "evil.dll".to_string(),
        path: "C:\\temp\\evil.dll".to_string(),
        reason: "未知路径".to_string(),
    };

    // 出现两次
    state.record(std::slice::from_ref(&module));
    state.record(std::slice::from_ref(&module));

    // 中断（未出现）
    state.record(&[]);

    // 再次出现：计数应从 1 重新开始
    let triggered = state.record(std::slice::from_ref(&module));
    assert!(triggered.is_empty());
}

#[test]
fn test_patrol_state_serialization_roundtrip() {
    let mut state = PatrolState::new("c:\\app".to_string());
    let module = UnknownModule {
        name: "evil.dll".to_string(),
        path: "C:\\temp\\evil.dll".to_string(),
        reason: "未知路径".to_string(),
    };
    state.record(&[module]);
    state.patrol_count = 42;

    let serialized = state.to_serialized();
    let restored = PatrolState::from_serialized(serialized);

    assert_eq!(restored.patrol_count, 42);
    assert_eq!(restored.counts.len(), 1);
    assert_eq!(restored.install_dir, "c:\\app");
}

/// 签名分级：只有签名无效才允许进入应急管线。
#[test]
fn test_signature_severity_only_invalid_is_hard() {
    assert_eq!(
        severity_for_signature(SignatureStatus::Invalid),
        ThreatSeverity::Hard
    );
    assert_eq!(
        severity_for_signature(SignatureStatus::Valid),
        ThreatSeverity::Soft
    );
    assert_eq!(
        severity_for_signature(SignatureStatus::ValidRevocationUnknown),
        ThreatSeverity::Soft
    );
}

/// 不支持的 schema 状态必须被丢弃：schema<2 的 counts/triggered 记录了
/// “路径即威胁”语义下的误报（如 mdnsNSP.dll），不可用于压制或触发。
#[test]
fn test_legacy_state_schema_is_rejected() {
    assert!(!is_supported_state_schema(0));
    assert!(!is_supported_state_schema(1));
    assert!(is_supported_state_schema(PATROL_STATE_SCHEMA_VERSION));

    // 无 schema_version / reported_soft 字段的 JSON 可反序列化，
    // 默认 schema=0，从而走“丢弃重建”分支。
    let legacy: SerializablePatrolState = serde_json::from_str(
        r#"{"counts":{"c:\\temp\\evil.dll":3},"triggered":["c:\\temp\\evil.dll"],
               "patrol_count":13,"install_dir":"c:\\app","baseline_version":0}"#,
    )
    .expect("旧状态 JSON 必须可解析");
    assert_eq!(legacy.schema_version, 0);
    assert!(legacy.reported_soft.is_empty());
    assert!(!is_supported_state_schema(legacy.schema_version));
}

/// 软告警不进入连续计数、不触发熔断，且同一路径只审计一次。
#[test]
fn test_soft_suspects_do_not_count_or_trigger() {
    let mut state = PatrolState::new("c:\\app".to_string());
    let signed_module = UnknownModule {
        name: "mdnsNSP.dll".to_string(),
        path: "C:\\Program Files\\Bonjour\\mdnsNSP.dll".to_string(),
        reason: "未知路径".to_string(),
    };

    // 连续多轮出现软告警：不得进入 counts/triggered
    for _ in 0..(CONSECUTIVE_TRIGGER_THRESHOLD + 2) {
        let newly = state.record_soft(std::slice::from_ref(&signed_module));
        let expected_first = state.reported_soft.len() == 1 && newly.len() == 1;
        assert!(newly.is_empty() || expected_first, "软告警只允许首次上报");
    }
    assert!(state.counts.is_empty(), "软告警不得进入硬威胁计数");
    assert!(state.triggered.is_empty(), "软告警不得写入已触发集合");
    assert_eq!(state.patrol_count, 0, "软告警不得推进巡检计数");

    // 硬威胁计数不受软告警影响
    let mut hard = signed_module.clone();
    hard.reason = "未签名".to_string();
    let triggered: Vec<UnknownModule> = (0..CONSECUTIVE_TRIGGER_THRESHOLD)
        .flat_map(|_| state.record(std::slice::from_ref(&hard)))
        .collect();
    assert_eq!(triggered.len(), 1);
    assert_eq!(state.counts.len(), 1);
}

/// 软告警集合必须有界，攻击者不能靠海量路径撑爆持久化状态。
#[test]
fn test_soft_suspect_set_is_bounded() {
    let mut state = PatrolState::new("c:\\app".to_string());
    for i in 0..(RING_BUFFER_MAX_ENTRIES + 40) {
        let module = UnknownModule {
            name: format!("signed_{}.dll", i),
            path: format!("C:\\Vendor\\signed_{}.dll", i),
            reason: "未知路径".to_string(),
        };
        state.record_soft(&[module]);
    }
    assert!(state.reported_soft.len() <= RING_BUFFER_MAX_ENTRIES);
}

#[test]
fn test_compute_hmac() {
    let key = [0u8; 32];
    let hmac1 = compute_hmac(&key, "test data").unwrap();
    let hmac2 = compute_hmac(&key, "test data").unwrap();
    let hmac3 = compute_hmac(&key, "different data").unwrap();

    assert_eq!(hmac1, hmac2); // 相同输入应产生相同 HMAC
    assert_ne!(hmac1, hmac3); // 不同输入应产生不同 HMAC
    assert!(!hmac1.is_empty());
}

#[test]
fn test_dynamic_interval_range() {
    // 动态间隔应在合理范围内
    for _ in 0..100 {
        let interval = compute_dynamic_interval();
        assert!(interval >= PATROL_MIN_INTERVAL_SECS);
        assert!(interval <= PATROL_MAX_INTERVAL_SECS * 2);
    }
}

/// 防回退：睡眠期必须推进心跳。仅在巡检前后报活时，长睡（动态间隔
/// 可达 80 秒）会跨越看门狗静默阈值，被误判为线程死亡而重复重启，
/// 造成巡检线程累积泄漏与巡检频次翻倍。
#[test]
fn test_sleep_with_heartbeat_advances_beat() {
    let stop = AtomicBool::new(false);
    let hb = AtomicU64::new(0);
    sleep_with_heartbeat(&stop, &hb, 1);
    assert!(
        hb.load(Ordering::SeqCst) > 0,
        "睡眠期心跳未推进，看门狗将误判长睡为线程死亡"
    );

    // 停止标志置位时立即返回且不刷新心跳
    let stop_set = AtomicBool::new(true);
    let hb_idle = AtomicU64::new(0);
    sleep_with_heartbeat(&stop_set, &hb_idle, 3);
    assert_eq!(
        hb_idle.load(Ordering::SeqCst),
        0,
        "停止标志置位后不得再刷新心跳"
    );
}

#[test]
fn test_generate_random_u64() {
    let r1 = generate_random_u64();
    let r2 = generate_random_u64();
    // 随机 u64 无可靠不变式可断言（全域合法、两值相等是极低概率事件），
    // 本用例意图即验证函数不 panic
    let _ = (r1, r2);
}

#[test]
fn test_ring_buffer_eviction() {
    let mut state = PatrolState::new("c:\\app".to_string());

    // 插入超过上限的模块
    for i in 0..(RING_BUFFER_MAX_ENTRIES + 50) {
        let module = UnknownModule {
            name: format!("mod_{}.dll", i),
            path: format!("C:\\temp\\mod_{}.dll", i),
            reason: "未知路径".to_string(),
        };
        state.record(&[module]);
    }

    // counts 不应超过上限
    assert!(state.counts.len() <= RING_BUFFER_MAX_ENTRIES);
}

#[test]
fn test_hash_baseline_manager() {
    let manager = HashBaselineManager::new();

    // 初始状态：基线为 None
    assert!(manager.get_snapshot().is_none());

    // 轮询构建结果（尚未构建）
    manager.poll_build_result();
    assert!(manager.get_snapshot().is_none());
}

/// 防回退：抽样必须不重不漏、数量受 k 约束，且 k >= len 时返回全量。
#[test]
fn test_sample_random_bounds_and_uniqueness() {
    let items: Vec<u32> = (0..50).collect();

    // k < len：恰好 k 个、无重复、均来自原集合
    let picked = sample_random(&items, 3);
    assert_eq!(picked.len(), 3);
    let unique: std::collections::HashSet<u32> = picked.iter().copied().collect();
    assert_eq!(unique.len(), 3);
    assert!(picked.iter().all(|v| *v < 50));

    // k >= len：全量副本
    let all = sample_random(&items, 50);
    assert_eq!(all.len(), 50);
    let all_more = sample_random(&items, 60);
    assert_eq!(all_more.len(), 50);

    // 空集合：空结果
    let empty: Vec<u32> = Vec::new();
    assert!(sample_random(&empty, 3).is_empty());
}
