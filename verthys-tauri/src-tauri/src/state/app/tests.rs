/* ------------------------------------------------------------------ *
 * 单元测试                                                            *
 * ------------------------------------------------------------------ */

use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::util::contracts::VerthysRecordEntry;

use super::types::now_ms;
use super::*;

#[test]
fn test_app_state_new() {
    let state = AppState::new();
    assert!(!state.has_session());
    assert_eq!(state.get_pending_io_count(), 0);
    assert!(!state.init_lock.load(Ordering::SeqCst));
    assert_eq!(state.scan_lock_acquired_ms.load(Ordering::SeqCst), 0);
    assert_eq!(
        state.scan_summary_lock_acquired_ms.load(Ordering::SeqCst),
        0
    );
}

#[test]
fn test_session_epoch_rejects_stale_clear() {
    let state = AppState::new();
    assert_eq!(state.session_epoch(), 0);
    let stale = state.session_epoch();
    // 会话变更（此处为销毁路径的空状态变更）必须推进代际
    state.set_session(None);
    assert_eq!(state.session_epoch(), stale + 1);
    assert!(
        !state.clear_session_if_epoch(stale),
        "旧代际的延迟命令必须被拒绝，不得清空当前会话"
    );

    let current = state.session_epoch();
    assert!(
        state.clear_session_if_epoch(current),
        "当前代际必须允许清空"
    );
    assert_eq!(
        state.session_epoch(),
        current,
        "无会话可清空时不得无意义推进代际"
    );
}

#[test]
fn test_init_lock_acquire_release() {
    let state = AppState::new();
    assert!(state.try_acquire_init_lock());
    assert!(!state.try_acquire_init_lock()); // 已持有，再次获取失败
    state.release_init_lock();
    assert!(state.try_acquire_init_lock()); // 释放后可再次获取
    state.release_init_lock();
}

#[test]
fn test_init_lock_guard_raii() {
    let state = AppState::new();
    // InitLockGuard 是 RAII 释放守卫：调用方先获取锁，guard 确保 Drop 时释放
    assert!(state.try_acquire_init_lock());
    assert!(state.init_lock.load(Ordering::SeqCst));
    {
        let _guard = InitLockGuard { state: &state };
        // guard 存在期间，锁应保持持有
        assert!(state.init_lock.load(Ordering::SeqCst));
    }
    // guard drop 后应自动释放
    assert!(!state.init_lock.load(Ordering::SeqCst));
}

#[test]
fn test_io_barrier_begin_end() {
    let state = AppState::new();
    assert_eq!(state.get_pending_io_count(), 0);

    state.begin_io();
    assert_eq!(state.get_pending_io_count(), 1);

    state.begin_io();
    assert_eq!(state.get_pending_io_count(), 2);

    state.end_io();
    assert_eq!(state.get_pending_io_count(), 1);

    state.end_io();
    assert_eq!(state.get_pending_io_count(), 0);
}

#[tokio::test]
async fn test_wait_io_complete_fast_path() {
    // 无待处理 IO 时应立即返回 true
    let state = AppState::new();
    let result = state.wait_io_complete(Duration::from_secs(1)).await;
    assert!(result);
}

#[tokio::test]
async fn test_wait_io_complete_notify() {
    // begin_io 后 wait_io_complete 应等待，
    // end_io 通知后应立即返回 true
    let state = std::sync::Arc::new(AppState::new());
    state.begin_io();

    let state_clone = state.clone();
    let handle = tokio::spawn(async move {
        // 短暂等待后 end_io，触发 notify_one
        tokio::time::sleep(Duration::from_millis(50)).await;
        state_clone.end_io();
    });

    let result = state.wait_io_complete(Duration::from_secs(2)).await;
    assert!(result);
    handle.await.unwrap();
}

#[tokio::test]
async fn test_wait_io_complete_timeout() {
    // IO 未完成且超时应返回 false
    let state = AppState::new();
    state.begin_io();

    let result = state.wait_io_complete(Duration::from_millis(100)).await;
    assert!(!result);

    // 清理
    state.end_io();
}

#[test]
fn test_lock_scan_state_timestamp() {
    // 锁定时记录时间戳，释放时清零
    let state = AppState::new();

    assert_eq!(state.scan_lock_acquired_ms.load(Ordering::SeqCst), 0);

    {
        let _guard = state.lock_scan_state();
        // 锁定后时间戳应非零
        assert!(state.scan_lock_acquired_ms.load(Ordering::SeqCst) > 0);
    }

    // guard drop 后时间戳应清零
    assert_eq!(state.scan_lock_acquired_ms.load(Ordering::SeqCst), 0);
}

#[test]
fn test_lock_scan_summary_state_timestamp() {
    let state = AppState::new();

    assert_eq!(
        state.scan_summary_lock_acquired_ms.load(Ordering::SeqCst),
        0
    );

    {
        let _guard = state.lock_scan_summary_state();
        assert!(state.scan_summary_lock_acquired_ms.load(Ordering::SeqCst) > 0);
    }

    assert_eq!(
        state.scan_summary_lock_acquired_ms.load(Ordering::SeqCst),
        0
    );
}

#[test]
fn test_lock_scan_state_access() {
    // 验证 TimedMutexGuard 可以像 MutexGuard 一样使用
    let state = AppState::new();

    // 初始状态为 None
    {
        let guard = state.lock_scan_state();
        assert!(guard.is_none());
    }

    // 设置为 Some 后验证可访问
    {
        let mut guard = state.lock_scan_state();
        *guard = Some(ScanPipelineState::<VerthysRecordEntry> {
            shm_name: "test_shm".to_string(),
            current_buffer: None,
            exhausted: true,
            prefetch_task: None,
            pending_reply: None,
            session_state: crate::state::ScanSessionState::Active,
        });
    }

    // 验证值已存储
    {
        let guard = state.lock_scan_state();
        assert!(guard.is_some());
        let scan = guard.as_ref().unwrap();
        assert_eq!(scan.shm_name, "test_shm");
        assert!(scan.exhausted);
    }
}

#[test]
fn test_lock_verthys_file() {
    // verthys_file_lock 中毒恢复
    let state = AppState::new();

    {
        let guard = state.lock_verthys_file();
        assert!(guard.is_none());
    }

    {
        let mut guard = state.lock_verthys_file();
        *guard = None; // 模拟设置（实际由 verthys_unlock 设置）
    }
}

#[test]
fn test_check_lock_timestamps_no_warning() {
    // 未持锁时 check 不应告警或重置
    let state = AppState::new();
    state.check_lock_timestamps();
    // 无 panic 即通过
}

#[test]
fn test_check_lock_timestamps_stale() {
    // 模拟锁持有超 30s（设置旧时间戳），check 应尝试 try_lock 重置
    let state = AppState::new();

    // 设置一个 60s 前的时间戳
    let old_ts = now_ms().saturating_sub(60_000);
    state.scan_lock_acquired_ms.store(old_ts, Ordering::SeqCst);

    // 因为没有真正持有锁（只是设置了时间戳），try_lock 应成功
    state.check_lock_timestamps();

    // 时间戳应被清零
    assert_eq!(state.scan_lock_acquired_ms.load(Ordering::SeqCst), 0);
}

#[test]
fn test_timed_mutex_guard_deref_chain() {
    // 验证 TimedMutexGuard 的 Deref 链可以访问 Option 的方法
    let state = AppState::new();

    {
        let mut guard = state.lock_scan_state();
        // as_mut() 通过 DerefMut → MutexGuard → Option
        assert!(guard.as_mut().is_none());

        // 设置值
        *guard = Some(ScanPipelineState::<VerthysRecordEntry> {
            shm_name: "deref_test".to_string(),
            current_buffer: None,
            exhausted: false,
            prefetch_task: None,
            pending_reply: None,
            session_state: crate::state::ScanSessionState::Active,
        });
    }

    {
        let guard = state.lock_scan_state();
        // as_ref() 通过 Deref → MutexGuard → Option
        let scan = guard.as_ref().expect("should be Some");
        assert_eq!(scan.shm_name, "deref_test");
        assert!(!scan.exhausted);
    }
}

#[test]
fn test_data_plane_job_serial_cancel_and_stale_cleanup() {
    let state = AppState::new();

    // 空 job_id 直接被拒
    assert!(state.try_begin_data_plane_job("").is_err());

    let cancel = state
        .try_begin_data_plane_job("job-a")
        .expect("首个任务应占用成功");
    assert!(!cancel.load(Ordering::SeqCst));

    // 已有任务时串行拒绝，不得覆盖原槽位
    assert!(state.try_begin_data_plane_job("job-b").is_err());
    assert_eq!(state.data_plane_job_id().as_deref(), Some("job-a"));

    // job_id 不匹配时取不到取消标志
    assert!(state.data_plane_job_cancel_flag("job-b").is_none());
    let same = state
        .data_plane_job_cancel_flag("job-a")
        .expect("当前任务标志应可达");
    same.store(true, Ordering::SeqCst);
    assert!(cancel.load(Ordering::SeqCst), "取消标志应共享同一原子位");

    // 旧 job 的收尾不得清掉当前任务的槽位
    state.finish_data_plane_job("job-b");
    assert_eq!(state.data_plane_job_id().as_deref(), Some("job-a"));

    // 匹配的 job_id 才能释放槽位
    state.finish_data_plane_job("job-a");
    assert!(state.data_plane_job_id().is_none());
    assert!(state.try_begin_data_plane_job("job-c").is_ok());
}
