/*
 * 巡检线程管理器与单次巡检
 *
 * BackgroundPatrol 持有停止标志、巡检线程句柄、看门狗线程句柄与心跳时间戳，
 * 随应用生命周期存活，Drop 时停止所有线程。
 *
 * 单次巡检顺序：轻量路径扫描 → 哈希基线验证 → 完整校验抽样 → 更新环形缓冲
 * → 持久化状态 → 对新达阈值的模块触发应急信号。
 */

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use tauri::AppHandle;

use crate::security::module_whitelist::{
    self, check_module_against_baseline, module_signature_status, BaselineCheck, HashBaseline,
    SignatureStatus, UnknownModule,
};
use crate::util::audit_log::{AuditEventType, AuditResult};

use super::emergency::{trigger_emergency_signal, write_patrol_audit};
use super::os::{
    apply_process_mitigation_policies, enumerate_loaded_module_paths, now_ms, sanitize_path,
};
use super::persistence::{compute_state_fingerprint, PatrolPersistence};
use super::state::{HashBaselineManager, PatrolState};
use super::watchdog::{patrol_loop, sample_random, watchdog_loop};
use super::{
    CONSECUTIVE_TRIGGER_THRESHOLD, HEARTBEAT_TIMEOUT_SECS, INTEGRITY_SAMPLE_PER_ROUND,
    PATROL_FORCE_PERSIST_INTERVAL, PATROL_MAX_INTERVAL_SECS, PATROL_MIN_INTERVAL_SECS,
    WATCHDOG_CHECK_SECS,
};

/// 巡检威胁分级。
///
/// - `Hard`：未签名/签名无效，或无可信签名的系统目录哈希失配 → 进入
///   连续检测管线，达到阈值触发应急熔断；
/// - `Soft`：签名链有效（含吊销状态暂不可达）但路径未知 / 哈希变化，
///   或无法核验（文件不可读）→ 仅记录审计与日志，绝不销毁 Worker 会话。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ThreatSeverity {
    Hard,
    Soft,
}

/// 依据签名结论分级：只有“签名无效”才构成注入/劫持的硬证据。
pub(super) fn severity_for_signature(status: SignatureStatus) -> ThreatSeverity {
    if status.is_signed() {
        ThreatSeverity::Soft
    } else {
        ThreatSeverity::Hard
    }
}

/// 后台模块巡检线程管理器（含看门狗）。
///
/// 持有停止标志、巡检线程句柄、看门狗线程句柄、心跳时间戳。
/// 通过 app.manage() 注册后随应用生命周期存活，Drop 时自动停止所有线程。
pub struct BackgroundPatrol {
    /// 停止标志（巡检线程 + 看门狗线程均轮询）
    stop_flag: Arc<AtomicBool>,
    /// 巡检线程句柄
    thread: Mutex<Option<JoinHandle<()>>>,
    /// 看门狗线程句柄
    watchdog_thread: Mutex<Option<JoinHandle<()>>>,
    /// 巡检线程心跳时间戳（Unix 毫秒，由看门狗监控）
    #[allow(dead_code)]
    heartbeat: Arc<AtomicU64>,
    /// 看门狗重启计数
    restart_count: Arc<AtomicU32>,
}

/// 线程间共享的巡检上下文
pub(super) struct PatrolContext {
    /// Tauri AppHandle（用于发送应急事件 + 访问 AppState）
    pub(super) app: AppHandle,
    /// 巡检状态
    pub(super) state: Arc<Mutex<PatrolState>>,
    /// 哈希基线管理器
    pub(super) baseline_manager: Arc<HashBaselineManager>,
    /// 停止标志
    pub(super) stop_flag: Arc<AtomicBool>,
    /// 心跳时间戳
    pub(super) heartbeat: Arc<AtomicU64>,
    /// 安装目录
    pub(super) install_dir: String,
    /// 持久化管理器
    pub(super) persistence: Arc<Option<PatrolPersistence>>,
    /// 看门狗重启计数
    #[allow(dead_code)]
    pub(super) restart_count: Arc<AtomicU32>,
}

impl BackgroundPatrol {
    /// 启动后台巡检线程 + 看门狗线程。
    ///
    /// - app: Tauri AppHandle（Clone，传入线程用于发送应急事件 + 访问 AppState）
    /// - install_dir: 安装目录（模块白名单基准前缀，主 EXE 所在目录）
    pub fn start(app: AppHandle, install_dir: String) -> Self {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let heartbeat = Arc::new(AtomicU64::new(now_ms()));
        let restart_count = Arc::new(AtomicU32::new(0));

        // 加载持久化状态
        let persistence = Arc::new(PatrolPersistence::new(&app));
        let initial_state = persistence
            .as_ref()
            .as_ref()
            .and_then(PatrolPersistence::load)
            .map(PatrolState::from_serialized)
            .unwrap_or_else(|| PatrolState::new(install_dir.clone()));

        let state = Arc::new(Mutex::new(initial_state));
        let baseline_manager = Arc::new(HashBaselineManager::new());

        // 进程完整性监控
        apply_process_mitigation_policies();

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

        // 启动巡检线程
        let patrol_handle = thread::Builder::new()
            .name("verthys-module-patrol".into())
            .spawn(move || {
                patrol_loop(ctx);
            })
            .expect("spawn verthys-module-patrol thread");

        // 启动看门狗线程
        let watchdog_stop = stop_flag.clone();
        let watchdog_heartbeat = heartbeat.clone();
        let watchdog_restart_count = restart_count.clone();
        let watchdog_app = app.clone();
        let watchdog_state = state.clone();
        let watchdog_persistence = persistence.clone();
        let watchdog_baseline = baseline_manager.clone();
        let watchdog_install_dir = install_dir.clone();

        let watchdog_handle = thread::Builder::new()
            .name("verthys-patrol-watchdog".into())
            .spawn(move || {
                watchdog_loop(
                    watchdog_app,
                    watchdog_state,
                    watchdog_baseline,
                    watchdog_stop,
                    watchdog_heartbeat,
                    watchdog_install_dir,
                    watchdog_persistence,
                    watchdog_restart_count,
                );
            })
            .expect("spawn verthys-patrol-watchdog thread");

        log::info!(
            "[background_patrol] 巡检线程 + 看门狗已启动（动态间隔 {}-{}s，阈值 {} 次连续，\
             看门狗检查间隔 {}s，心跳超时 {}s）",
            PATROL_MIN_INTERVAL_SECS,
            PATROL_MAX_INTERVAL_SECS,
            CONSECUTIVE_TRIGGER_THRESHOLD,
            WATCHDOG_CHECK_SECS,
            HEARTBEAT_TIMEOUT_SECS
        );

        BackgroundPatrol {
            stop_flag,
            thread: Mutex::new(Some(patrol_handle)),
            watchdog_thread: Mutex::new(Some(watchdog_handle)),
            heartbeat,
            restart_count,
        }
    }

    /// 优雅停止巡检线程 + 看门狗线程
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);

        // 等待巡检线程退出
        if let Ok(mut guard) = self.thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
        // 等待看门狗线程退出
        if let Ok(mut guard) = self.watchdog_thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }

        log::info!(
            "[background_patrol] 巡检线程 + 看门狗已停止（总重启次数: {}）",
            self.restart_count.load(Ordering::SeqCst)
        );
    }

    /// 查询是否仍在运行
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        !self.stop_flag.load(Ordering::SeqCst)
    }
}

impl Drop for BackgroundPatrol {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 执行单次巡检
///
/// 1. 轻量扫描：路径白名单匹配
/// 2. 哈希基线验证：系统目录模块哈希匹配
/// 3. 完整校验抽样：受信位置模块签名随机复核（门控内）
/// 4. 更新环形缓冲
/// 5. 持久化状态
/// 6. 对新达阈值的模块触发应急信号
pub(super) fn run_one_patrol(ctx: &PatrolContext) {
    // 轮询哈希基线构建结果
    ctx.baseline_manager.poll_build_result();

    // 轻量扫描：仅路径白名单匹配
    let unknowns = module_whitelist::patrol_modules_paths_only(&ctx.install_dir);

    // 哈希基线验证
    /* 威胁分级：路径不在白名单只说明“来源未知”，不构成注入证据。
     * 第三方软件（NVIDIA Overlay、Bonjour mDNS 命名空间提供程序等）会把
     * 自身签名的 DLL 注入到所有进程；这些模块路径天然不在白名单内。
     * 因此先做 Authenticode 核验：
     *   - 签名有效（含吊销状态不可达）→ 软告警，仅审计，不熔断；
     *   - 未签名/签名无效             → 硬威胁，进入连续检测管线。
     * 硬威胁连续 3 轮才销毁 Worker 会话，避免用户在解锁/重绑/轮换
     * 过程中被强制中断。 */
    let mut hard_threats: Vec<UnknownModule> = Vec::new();
    let mut soft_suspects: Vec<UnknownModule> = Vec::new();

    for m in unknowns {
        match severity_for_signature(module_signature_status(&m.path)) {
            ThreatSeverity::Hard => hard_threats.push(m),
            ThreatSeverity::Soft => soft_suspects.push(m),
        }
    }

    if let Some(baseline) = ctx.baseline_manager.get_snapshot() {
        let (mut hard_hash_threats, mut soft_hash_suspects) =
            check_hash_baseline_violations(&baseline, &ctx.heartbeat);
        if !hard_hash_threats.is_empty() || !soft_hash_suspects.is_empty() {
            log::warn!(
                "[background_patrol] 哈希基线核验：{} 个硬威胁，{} 个软告警",
                hard_hash_threats.len(),
                soft_hash_suspects.len()
            );
        }
        hard_threats.append(&mut hard_hash_threats);
        soft_suspects.append(&mut soft_hash_suspects);
    }

    // 完整校验抽样复核
    // 对受信位置（非系统目录）的已加载模块随机抽样做签名复核；
    // 签名失效与"未知路径 / 哈希基线不匹配"同为威胁类别，进入同一
    // 连续检测管线（去重 + 连续阈值后才升级应急，单轮失败仅记录）。
    if crate::security::app_feature_gate::enabled(
        crate::security::app_feature_gate::FEAT_INTEGRITY_CHECK,
    ) {
        let candidates = module_whitelist::trusted_signable_module_paths(&ctx.install_dir);
        for (name, path) in sample_random(&candidates, INTEGRITY_SAMPLE_PER_ROUND) {
            // 抽样期间推进心跳（签名核验可能联网检查吊销，耗时不可控）
            ctx.heartbeat.store(now_ms(), Ordering::SeqCst);
            if !module_whitelist::verify_signature(&path) {
                log::warn!(
                    "[background_patrol] 完整校验抽样：模块 {} 签名失效（受信位置）: {}",
                    name,
                    sanitize_path(&path)
                );
                hard_threats.push(UnknownModule {
                    name,
                    path,
                    reason: "签名失效（完整校验抽样）".to_string(),
                });
            }
        }
    }

    let (triggered, newly_soft) = {
        let mut st = match ctx.state.lock() {
            Ok(g) => g,
            Err(e) => {
                log::error!("[background_patrol] 状态锁中毒，跳过本次巡检: {}", e);
                return;
            }
        };

        if !hard_threats.is_empty() || !soft_suspects.is_empty() {
            log::warn!(
                "[background_patrol] 巡检 #{} 发现 {} 个硬威胁、{} 个软告警",
                st.patrol_count + 1,
                hard_threats.len(),
                soft_suspects.len()
            );
            for m in hard_threats.iter().chain(soft_suspects.iter()) {
                log::warn!(
                    "[background_patrol]   - {} [{}]: {}",
                    m.name,
                    m.reason,
                    sanitize_path(&m.path)
                );
            }
        } else {
            log::debug!(
                "[background_patrol] 巡检 #{} 未发现未知模块",
                st.patrol_count + 1
            );
        }

        let triggered = st.record(&hard_threats);
        let newly_soft = st.record_soft(&soft_suspects);
        (triggered, newly_soft)
    };

    // 持久化状态
    // 空闲治理：状态指纹比对跳过 — 安全关键状态（counts/triggered/
    //   install_dir/baseline_version）未变化时跳过序列化 + DPAPI 加密 +
    //   临时文件写入 + rename 的完整持久化链路；每 FORCE_PERSIST_INTERVAL
    //   次巡检强制落盘一次，patrol_count 漂移丢失上界受控。
    {
        let mut st = match ctx.state.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Some(ref persistence) = *ctx.persistence {
            let serialized = st.to_serialized();
            let fingerprint = compute_state_fingerprint(&serialized);
            if fingerprint != st.last_persist_fingerprint
                || st.patrols_since_persist >= PATROL_FORCE_PERSIST_INTERVAL
            {
                persistence.save(&serialized);
                st.last_persist_fingerprint = fingerprint;
                st.patrols_since_persist = 0;
            } else {
                st.patrols_since_persist += 1;
            }
        }
    }

    // 对本次新达阈值的硬威胁模块逐个触发应急信号
    for m in &triggered {
        trigger_emergency_signal(ctx, m);
    }

    // 软告警仅审计留痕（每个模块每个会话只记一次），绝不熔断
    for m in &newly_soft {
        report_soft_suspect(ctx, m);
    }
}

/// 记录软告警模块：签名有效但来源路径未知 / 系统哈希随更新变化。
///
/// 这类模块由第三方软件正常注入，属误报高发区；只写日志与审计，
/// 不销毁 Worker 会话、不触发前端应急事件。
fn report_soft_suspect(ctx: &PatrolContext, module: &UnknownModule) {
    log::warn!(
        "[background_patrol][软告警] 模块 {} 签名有效但来源未知（仅记录，不熔断）: {} 原因={}",
        module.name,
        sanitize_path(&module.path),
        module.reason
    );

    write_patrol_audit(
        &ctx.app,
        AuditEventType::PatrolSuspect,
        AuditResult::Success,
        Some(format!(
            "已签名第三方模块: 模块={} 原因={}（仅记录，不熔断）",
            module.name, module.reason
        )),
    );
}

/// 检查系统目录模块的哈希基线违规，返回 (硬威胁, 软告警)。
///
/// 枚举当前进程已加载的系统目录模块，对每个模块计算 SHA-256 并与基线比较。
/// 失配不等于“被替换”：Windows Update 在进程运行期间替换磁盘文件同样会
/// 造成失配，而进程内仍是旧映像。因此失配时再做一次 Authenticode 核验：
///   - 签名有效 → 软告警（系统更新或多版本并存，仅审计）；
///   - 签名无效 → 硬威胁（疑似被替换为同路径恶意模块）；
///   - 文件不可读（已删除/权限不足）→ 软告警（无法判定，不制造误熔断）。
///
/// 扫描期间按模块推进心跳（heartbeat）：整轮哈希扫描可能跨越看门狗静默
/// 阈值，持续报告存活才能让看门狗区分"长扫描"与"真卡死"。
fn check_hash_baseline_violations(
    baseline: &HashBaseline,
    heartbeat: &AtomicU64,
) -> (Vec<UnknownModule>, Vec<UnknownModule>) {
    let mut hard_threats = Vec::new();
    let mut soft_suspects = Vec::new();

    // 获取当前进程模块列表（仅路径，不做白名单匹配）
    // 复用 module_whitelist 的枚举逻辑，但这里我们只需要路径
    let modules = enumerate_loaded_module_paths();

    for (name, path) in modules {
        heartbeat.store(now_ms(), Ordering::SeqCst);
        // 仅验证系统目录下的模块（基线仅包含系统目录）
        match check_module_against_baseline(&path, baseline) {
            BaselineCheck::Match | BaselineCheck::NotInBaseline => {
                // 哈希匹配 / 非系统目录模块，跳过
            }
            BaselineCheck::Mismatch => {
                if severity_for_signature(module_signature_status(&path)) == ThreatSeverity::Hard {
                    log::error!(
                        "[background_patrol] 哈希基线违规：系统模块 {} 哈希不匹配且签名无效（疑似被替换）",
                        sanitize_path(&path)
                    );
                    hard_threats.push(UnknownModule {
                        name,
                        path,
                        reason: "哈希基线不匹配且签名无效（系统模块疑似被替换）".to_string(),
                    });
                } else {
                    log::warn!(
                        "[background_patrol] 系统模块 {} 哈希不匹配但签名有效（可能为系统更新），仅记录",
                        sanitize_path(&path)
                    );
                    soft_suspects.push(UnknownModule {
                        name,
                        path,
                        reason: "哈希基线不匹配（签名有效，可能为系统更新）".to_string(),
                    });
                }
            }
            BaselineCheck::Unreadable => {
                log::warn!(
                    "[background_patrol] 系统模块 {} 无法读取哈希（文件已删除或权限不足），仅记录",
                    sanitize_path(&path)
                );
                soft_suspects.push(UnknownModule {
                    name,
                    path,
                    reason: "无法计算哈希（文件不可读，可能已被更新）".to_string(),
                });
            }
        }
    }

    (hard_threats, soft_suspects)
}
