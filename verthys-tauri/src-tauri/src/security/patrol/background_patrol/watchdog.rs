/*
 * 看门狗与巡检主循环
 *
 * 看门狗每 5 秒检查巡检线程心跳，发现线程退出立即重启。
 * 连续重启失败 3 次后强制触发应急熔断（直接销毁 Worker 会话）。
 *
 * 巡检主循环使用动态频率（10~40 秒随机抖动 + 系统空闲时间结合），
 * 以 catch_unwind 包裹单次巡检，并在睡眠期逐拍推进心跳。
 */

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tauri::AppHandle;

use crate::util::audit_log::{AuditEventType, AuditResult};

use super::emergency::{execute_backend_circuit_breaker, write_patrol_audit};
use super::os::{get_system_idle_secs, now_ms, sanitize_path, set_current_thread_priority_lowest};
use super::patrol::{run_one_patrol, PatrolContext};
use super::persistence::PatrolPersistence;
use super::state::{HashBaselineManager, PatrolState};
use super::{
    ACTIVE_THRESHOLD_SECS, HEARTBEAT_BEAT_SECS, HEARTBEAT_TIMEOUT_SECS, IDLE_THRESHOLD_SECS,
    PATROL_MAX_INTERVAL_SECS, PATROL_MIN_INTERVAL_SECS, WATCHDOG_CHECK_SECS,
    WATCHDOG_MAX_RESTART_FAILURES,
};

// 说明：看门狗线程所需的全局安全上下文（应用句柄、巡检状态、基线管理器、
// 停止标志、心跳、安装目录、持久化、重启计数），每个参数为独立的安全
// 监控职责，打包会掩盖熔断链路的数据流，故豁免参数数量检查。
#[allow(clippy::too_many_arguments)]
pub(super) fn watchdog_loop(
    app: AppHandle,
    state: Arc<Mutex<PatrolState>>,
    baseline_manager: Arc<HashBaselineManager>,
    stop_flag: Arc<AtomicBool>,
    heartbeat: Arc<AtomicU64>,
    install_dir: String,
    persistence: Arc<Option<PatrolPersistence>>,
    restart_count: Arc<AtomicU32>,
) {
    log::info!("[background_patrol][看门狗] 看门狗线程已启动");

    while !stop_flag.load(Ordering::SeqCst) {
        // 分段睡眠（每秒检查停止标志）
        for _ in 0..WATCHDOG_CHECK_SECS {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }

        // 检查心跳
        let last_heartbeat = heartbeat.load(Ordering::SeqCst);
        let now = now_ms();
        let elapsed_secs = now.saturating_sub(last_heartbeat) / 1000;

        if elapsed_secs > HEARTBEAT_TIMEOUT_SECS {
            log::error!(
                "[background_patrol][看门狗] 巡检线程心跳超时（{}s > {}s 阈值），\
                 视为已死，尝试重启",
                elapsed_secs,
                HEARTBEAT_TIMEOUT_SECS
            );

            // 写入审计日志
            write_patrol_audit(
                &app,
                AuditEventType::PatrolWatchdog,
                AuditResult::Failure,
                Some(format!(
                    "巡检线程心跳超时 {}s，尝试重启（第 {} 次）",
                    elapsed_secs,
                    restart_count.load(Ordering::SeqCst) + 1
                )),
            );

            // 尝试重启巡检线程
            let current_failures = restart_count.fetch_add(1, Ordering::SeqCst) + 1;

            if current_failures > WATCHDOG_MAX_RESTART_FAILURES {
                // 连续重启失败上限：强制触发应急熔断
                log::error!(
                    "[background_patrol][看门狗] 连续重启失败 {} 次（上限 {}），\
                     强制触发应急熔断！",
                    current_failures,
                    WATCHDOG_MAX_RESTART_FAILURES
                );

                write_patrol_audit(
                    &app,
                    AuditEventType::PatrolEmergency,
                    AuditResult::Failure,
                    Some(format!(
                        "看门狗连续重启失败 {} 次，强制销毁 Worker 会话",
                        current_failures
                    )),
                );

                // 强制触发应急熔断
                execute_backend_circuit_breaker(&app, "watchdog_restart_failure");

                // 重置计数，避免无限告警
                restart_count.store(0, Ordering::SeqCst);
                continue;
            }

            // 重启巡检线程
            let ctx = PatrolContext {
                app: app.clone(),
                state: state.clone(),
                baseline_manager: baseline_manager.clone(),
                stop_flag: stop_flag.clone(),
                heartbeat: heartbeat.clone(),
                install_dir: install_dir.clone(),
                persistence: persistence.clone(),
                restart_count: restart_count.clone(),
            };

            // 更新心跳以避免看门狗在重启期间再次触发
            heartbeat.store(now_ms(), Ordering::SeqCst);

            match thread::Builder::new()
                .name("verthys-module-patrol".into())
                .spawn(move || {
                    patrol_loop(ctx);
                }) {
                Ok(_) => {
                    log::info!(
                        "[background_patrol][看门狗] 巡检线程已重启（第 {} 次重启）",
                        current_failures
                    );
                    write_patrol_audit(
                        &app,
                        AuditEventType::PatrolWatchdog,
                        AuditResult::Success,
                        Some(format!("巡检线程已重启（第 {} 次）", current_failures)),
                    );
                }
                Err(e) => {
                    log::error!("[background_patrol][看门狗] 巡检线程重启失败: {}", e);
                }
            }
        } else {
            // 心跳正常，重置重启计数
            if restart_count.load(Ordering::SeqCst) > 0 {
                log::info!("[background_patrol][看门狗] 巡检线程心跳恢复正常，重置重启计数");
                restart_count.store(0, Ordering::SeqCst);
            }
        }
    }

    log::info!("[background_patrol][看门狗] 看门狗线程退出");
}

/// 分段睡眠并逐拍推进心跳（每拍检查停止标志）。
///
/// 心跳只有在睡眠期持续推进，看门狗才能把"长睡"（动态间隔最长 80 秒）
/// 与"线程卡死"区分开：仅在巡检前后报活会让长睡跨越静默阈值，
/// 触发误判重启并泄漏巡检线程。
pub(super) fn sleep_with_heartbeat(stop_flag: &AtomicBool, heartbeat: &AtomicU64, secs: u64) {
    for _ in 0..secs {
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }
        heartbeat.store(now_ms(), Ordering::SeqCst);
        thread::sleep(Duration::from_secs(HEARTBEAT_BEAT_SECS));
    }
}

pub(super) fn patrol_loop(ctx: PatrolContext) {
    // 设置线程优先级为 THREAD_PRIORITY_LOWEST
    set_current_thread_priority_lowest();

    log::info!(
        "[background_patrol] 巡检线程就绪，install_dir={}",
        sanitize_path(&ctx.install_dir)
    );

    // 在后台构建哈希基线
    ctx.baseline_manager.try_build_async();

    while !ctx.stop_flag.load(Ordering::SeqCst) {
        // 更新心跳
        ctx.heartbeat.store(now_ms(), Ordering::SeqCst);

        // 档位门控：模块巡检（矩阵中性能档关闭、自定义档由用户开关决定）。
        // 关闭时保持线程与看门狗存活，仅跳过扫描本体与副作用；
        // 门控读取应用侧策略位镜像（权威源为 C 运行时投影）。
        if !crate::security::app_feature_gate::enabled(
            crate::security::app_feature_gate::FEAT_MODULE_PATROL,
        ) {
            sleep_with_heartbeat(&ctx.stop_flag, &ctx.heartbeat, compute_dynamic_interval());
            continue;
        }

        // catch_unwind 包裹单次巡检
        let patrol_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            run_one_patrol(&ctx);
        }));

        if let Err(payload) = patrol_result {
            log::error!(
                "[background_patrol] 巡检过程中 panic 已捕获（线程不退出）: {:?}",
                payload
            );
            write_patrol_audit(
                &ctx.app,
                AuditEventType::PatrolWatchdog,
                AuditResult::Failure,
                Some("巡检过程中 panic 已捕获（catch_unwind）".into()),
            );
        }

        // 更新心跳（巡检完成后）
        ctx.heartbeat.store(now_ms(), Ordering::SeqCst);

        // 动态频率计算
        let sleep_secs = compute_dynamic_interval();
        log::debug!("[background_patrol] 下次巡检间隔: {}s", sleep_secs);

        // 分段睡眠（每拍检查停止标志并推进心跳）
        sleep_with_heartbeat(&ctx.stop_flag, &ctx.heartbeat, sleep_secs);
    }

    log::info!("[background_patrol] 巡检线程退出");
}

/*
 * 动态频率计算
 *
 * 基于随机抖动（10~40 秒）且与系统空闲时间结合的动态巡检。
 * - 系统活跃（空闲 < 30s）：使用最小间隔 10-15s（高频巡检）
 * - 系统空闲 > 5 分钟：间隔翻倍 20-80s（低频省 CPU）
 * - 中间状态：标准 10-40s 随机抖动
 */

pub(super) fn compute_dynamic_interval() -> u64 {
    let idle_secs = get_system_idle_secs();

    // 生成随机抖动基数（10~40 秒）
    let base = PATROL_MIN_INTERVAL_SECS
        + (generate_random_u64() % (PATROL_MAX_INTERVAL_SECS - PATROL_MIN_INTERVAL_SECS + 1));

    let interval = if idle_secs < ACTIVE_THRESHOLD_SECS {
        // 系统活跃：使用最小间隔（高频巡检，覆盖攻击窗口）
        PATROL_MIN_INTERVAL_SECS + (generate_random_u64() % 6) // 10-15s
    } else if idle_secs > IDLE_THRESHOLD_SECS {
        // 系统空闲：间隔翻倍（低频省 CPU）
        base * 2
    } else {
        // 中间状态：标准随机抖动
        base
    };

    // 确保不超过上限的 2 倍（空闲模式上限）
    interval.min(PATROL_MAX_INTERVAL_SECS * 2)
}

/// 生成随机 u64（使用 getrandom crate）
pub(super) fn generate_random_u64() -> u64 {
    let mut buf = [0u8; 8];
    if getrandom::getrandom(&mut buf).is_ok() {
        u64::from_le_bytes(buf)
    } else {
        // 回退：使用系统时间作为伪随机源
        now_ms()
    }
}

/// 随机抽取 k 个元素（部分 Fisher-Yates，不改变原切片顺序）
///
/// k >= len 时返回全量副本。随机源与巡检抖动共用 generate_random_u64
/// （getrandom 失败时内部降级为时间伪随机，抽样不中断）。
pub(super) fn sample_random<T: Clone>(items: &[T], k: usize) -> Vec<T> {
    if items.len() <= k {
        return items.to_vec();
    }
    let mut indices: Vec<usize> = (0..items.len()).collect();
    for i in 0..k {
        let j = i + (generate_random_u64() % ((items.len() - i) as u64)) as usize;
        indices.swap(i, j);
    }
    indices[..k].iter().map(|&i| items[i].clone()).collect()
}
