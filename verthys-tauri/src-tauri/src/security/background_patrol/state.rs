/*
 * 巡检状态与哈希基线管理
 *
 * PatrolState 跟踪每个未知模块的连续检测次数（环形缓冲区 + 持久化支持）。
 * 系统目录模块哈希基线在后台线程惰性构建，避免阻塞巡检启动；
 * 基线构建完成后缓存于 manager 内部状态。
 */

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;

use crate::security::module_whitelist::{build_system_baseline, HashBaseline, UnknownModule};

use super::os::normalize_key;
use super::persistence::{compute_state_fingerprint, SerializablePatrolState};
use super::{CONSECUTIVE_TRIGGER_THRESHOLD, PATROL_STATE_SCHEMA_VERSION, RING_BUFFER_MAX_ENTRIES};

/// 巡检内部状态：跟踪每个未知模块的连续检测次数。
pub(super) struct PatrolState {
    /// 模块路径（规范化小写）→ 连续检测次数
    pub(super) counts: HashMap<String, u32>,
    /// 插入顺序队列（最旧在队首），用于环形缓冲淘汰
    order: VecDeque<String>,
    /// 已触发过应急信号的模块路径集合（避免同一模块重复触发）
    pub(super) triggered: HashSet<String>,
    /// 已记录过审计的软告警模块路径（签名有效但路径未知/哈希变化）
    pub(super) reported_soft: HashSet<String>,
    /// 安装目录（白名单基准前缀）
    pub(super) install_dir: String,
    /// 已执行巡检总次数
    pub(super) patrol_count: u64,
    /// 基线版本标识
    baseline_version: u64,
    /// 空闲治理：上次实际落盘的状态指纹（不变则跳过磁盘持久化）
    pub(super) last_persist_fingerprint: u64,
    /// 空闲治理：自上次实际落盘以来的巡检次数（周期性强制落盘兜底）
    pub(super) patrols_since_persist: u32,
}

impl PatrolState {
    pub(super) fn new(install_dir: String) -> Self {
        PatrolState {
            counts: HashMap::new(),
            order: VecDeque::new(),
            triggered: HashSet::new(),
            reported_soft: HashSet::new(),
            install_dir,
            patrol_count: 0,
            baseline_version: 0,
            last_persist_fingerprint: 0,
            patrols_since_persist: 0,
        }
    }

    /// 从持久化状态恢复
    pub(super) fn from_serialized(s: SerializablePatrolState) -> Self {
        let order: VecDeque<String> = s.counts.keys().cloned().collect();
        // 恢复时以已加载状态计算指纹，避免启动后首次巡检的无谓重写
        let fingerprint = compute_state_fingerprint(&s);
        PatrolState {
            counts: s.counts,
            order,
            triggered: s.triggered,
            reported_soft: s.reported_soft,
            install_dir: s.install_dir,
            patrol_count: s.patrol_count,
            baseline_version: s.baseline_version,
            last_persist_fingerprint: fingerprint,
            patrols_since_persist: 0,
        }
    }

    /// 转换为可序列化状态
    pub(super) fn to_serialized(&self) -> SerializablePatrolState {
        SerializablePatrolState {
            schema_version: PATROL_STATE_SCHEMA_VERSION,
            counts: self.counts.clone(),
            triggered: self.triggered.clone(),
            reported_soft: self.reported_soft.clone(),
            patrol_count: self.patrol_count,
            install_dir: self.install_dir.clone(),
            baseline_version: self.baseline_version,
        }
    }

    /// 记录本次巡检测到的未知模块，返回"本次新达到阈值且尚未触发过"的模块列表。
    pub(super) fn record(&mut self, unknowns: &[UnknownModule]) -> Vec<UnknownModule> {
        self.patrol_count += 1;

        let current_paths: HashSet<String> =
            unknowns.iter().map(|m| normalize_key(&m.path)).collect();

        // 1) 连续中断检测：已跟踪但本次未出现 → 移除
        let broken: Vec<String> = self
            .counts
            .keys()
            .filter(|k| !current_paths.contains(*k))
            .cloned()
            .collect();
        for k in &broken {
            self.counts.remove(k);
        }

        // 2) 递增/新增本次检测到的模块
        let mut newly_triggered: Vec<UnknownModule> = Vec::new();
        for m in unknowns {
            let key = normalize_key(&m.path);
            let entry = self.counts.entry(key.clone()).or_insert(0);
            *entry += 1;

            if *entry == 1 {
                self.order.push_back(key.clone());
            }

            if *entry >= CONSECUTIVE_TRIGGER_THRESHOLD && !self.triggered.contains(&key) {
                self.triggered.insert(key);
                newly_triggered.push(m.clone());
            }
        }

        // 3) 环形缓冲淘汰
        self.evict_if_needed();

        newly_triggered
    }

    /// 记录软告警模块，返回"首次出现、尚未审计过"的模块列表。
    ///
    /// 软告警不参与连续计数、不触发应急熔断；仅用于审计留痕。集合有界，
    /// 超过容量后整体清空重建（软告警没有安全决策作用，允许重复记录）。
    pub(super) fn record_soft(&mut self, suspects: &[UnknownModule]) -> Vec<UnknownModule> {
        if suspects.is_empty() {
            return Vec::new();
        }
        if self.reported_soft.len() >= RING_BUFFER_MAX_ENTRIES {
            self.reported_soft.clear();
        }

        let mut newly_reported: Vec<UnknownModule> = Vec::new();
        for m in suspects {
            let key = normalize_key(&m.path);
            if self.reported_soft.insert(key) {
                newly_reported.push(m.clone());
            }
        }
        newly_reported
    }

    /// 环形缓冲淘汰
    fn evict_if_needed(&mut self) {
        while self.counts.len() > RING_BUFFER_MAX_ENTRIES {
            let mut removed = false;
            while let Some(front) = self.order.pop_front() {
                if self.counts.remove(&front).is_some() {
                    removed = true;
                    break;
                }
            }
            if !removed {
                let excess = self.counts.len().saturating_sub(RING_BUFFER_MAX_ENTRIES);
                let keys: Vec<String> = self.counts.keys().take(excess).cloned().collect();
                for k in keys {
                    self.counts.remove(&k);
                }
                break;
            }
        }
    }
}

/// 哈希基线状态（惰性初始化）
struct HashBaselineState {
    /// 基线数据（None = 尚未构建完成）
    baseline: Option<HashBaseline>,
    /// 构建中标志（防止重复构建）
    building: bool,
    /// 构建失败次数（连续失败后放弃）
    failure_count: u32,
}

impl HashBaselineState {
    const fn new() -> Self {
        HashBaselineState {
            baseline: None,
            building: false,
            failure_count: 0,
        }
    }
}

/// 哈希基线管理器（线程安全）
pub(super) struct HashBaselineManager {
    state: Mutex<HashBaselineState>,
}

impl HashBaselineManager {
    pub(super) fn new() -> Self {
        HashBaselineManager {
            state: Mutex::new(HashBaselineState::new()),
        }
    }

    /// 尝试获取基线快照（如果已构建完成）
    ///
    /// 返回 Some(baseline) 表示基线可用，None 表示尚未构建或构建失败。
    /// 调用方应在此返回 None 时跳过哈希验证（降级为仅路径信任）。
    pub(super) fn get_snapshot(&self) -> Option<HashBaseline> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.baseline.clone()
    }

    /// 在后台线程构建基线（非阻塞）
    ///
    /// 如果基线已存在或正在构建中，此函数为空操作。
    /// 构建失败会递增 failure_count，连续失败 3 次后放弃。
    pub(super) fn try_build_async(&self) {
        let should_build = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.baseline.is_some() || state.building {
                false
            } else if state.failure_count >= 3 {
                log::warn!(
                    "[background_patrol] 哈希基线构建连续失败 {} 次，放弃构建",
                    state.failure_count
                );
                false
            } else {
                state.building = true;
                true
            }
        };

        if !should_build {
            return;
        }

        // 在独立线程中构建基线（避免阻塞巡检线程）
        // 基线数据通过 Clone 返回到 manager，不持有外部引用
        let manager_state = self.clone_baseline_marker();
        thread::Builder::new()
            .name("verthys-hash-baseline".into())
            .spawn(move || {
                log::info!("[background_patrol] 开始构建系统目录哈希基线...");
                let start = std::time::Instant::now();

                let baseline = build_system_baseline();
                let elapsed = start.elapsed();

                // 通过全局通道回传结果
                // 由于无法直接持有 manager 引用，使用全局静态 OnceLock 通道
                BASELINE_BUILD_RESULT
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .replace(baseline);
                BASELINE_BUILD_DONE.store(true, Ordering::SeqCst);

                log::info!(
                    "[background_patrol] 哈希基线构建完成：{} 个模块，耗时 {}ms",
                    BASELINE_BUILD_RESULT
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .as_ref()
                        .map(|b| b.len())
                        .unwrap_or(0),
                    elapsed.as_millis()
                );

                let _ = manager_state; // 消费标记
            })
            .ok();
    }

    /// 检查后台构建是否完成，如果完成则将结果移入 manager
    pub(super) fn poll_build_result(&self) {
        if !BASELINE_BUILD_DONE.load(Ordering::SeqCst) {
            return;
        }

        let baseline = {
            let mut result = BASELINE_BUILD_RESULT
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            result.take()
        };

        if let Some(b) = baseline {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.baseline = Some(b);
            state.building = false;
            BASELINE_BUILD_DONE.store(false, Ordering::SeqCst); // 重置标志供下次构建
        }
    }

    /// 辅助：创建基线标记（用于线程间同步的语义占位）
    fn clone_baseline_marker(&self) -> BaselineBuildMarker {
        BaselineBuildMarker
    }
}

/// 基线构建标记（语义占位类型）
struct BaselineBuildMarker;

/// 全局基线构建结果通道（线程间传递构建好的基线）
static BASELINE_BUILD_RESULT: Mutex<Option<HashBaseline>> = Mutex::new(None);
static BASELINE_BUILD_DONE: AtomicBool = AtomicBool::new(false);
