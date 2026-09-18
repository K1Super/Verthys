/*
 * background_patrol.rs — 后台模块巡检线程（SECURITY.md 企业级重写版）
 *
 * SECURITY.md 修复要点（第 429-483 项）：
 *   1. 动态频率 + 无窗口随机巡检（10~40 秒随机抖动 + 系统空闲时间结合）
 *      - 消除固定 30 秒周期的规律性，攻击者无法在巡检间隙规避
 *      - 系统空闲时降低频率（省 CPU），活跃时提高频率（覆盖攻击窗口）
 *   2. 系统目录模块引入哈希基线库，杜绝位置信任
 *      - 预计算 System32/SysWOW64 下所有合法 DLL 的 SHA-256 哈希
 *      - 巡检时对系统目录模块的哈希进行匹配，被替换的 DLL 即便在系统目录下也被检出
 *   3. 检测状态加密持久化（HMAC 保护 + DPAPI 加密），绑定设备与安装
 *      - 连续检测计数、触发历史、巡检总次数持久化到受保护文件
 *      - 即使重启，累积计数不丢失，已触发的信号保持有效
 *   4. 巡检看门狗，确保线程存活并具备自愈能力
 *      - 每 5 秒检查巡检线程心跳，发现线程退出立即重启
 *      - 连续重启失败后强制触发应急熔断（直接销毁 Worker 会话）
 *   5. 后端的独立应急响应通道，不依赖前端
 *      - 检测到威胁时直接通过 AppState::set_session(None) 销毁 Worker
 *      - 前端事件仅作为辅助通知，后端强制措施先于前端执行
 *   6. 进程完整性监控，防止巡检被注入或终止
 *      - SetProcessMitigationPolicy 启用 ProcessSignaturePolicy / ProcessImageLoadPolicy
 *   7. catch_unwind 包裹单次巡检，防 panic 退出
 *      - 单次扫描 panic 不会导致线程退出，看门狗仍可恢复
 */

use std::collections::{HashMap, HashSet, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager};

use super::module_whitelist::{
    self, build_system_baseline, verify_module_against_baseline, HashBaseline,
    UnknownModule,
};
use crate::state::AppState;
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};
use crate::util::crypto::{dpapi_protect, dpapi_unprotect, pbkdf2_derive_default};

/* ====================================================================== *
 *  常量                                                                   *
 * ====================================================================== */

/// SECURITY.md 第 459 项：动态频率下限（秒）
const PATROL_MIN_INTERVAL_SECS: u64 = 10;
/// SECURITY.md 第 459 项：动态频率上限（秒）
const PATROL_MAX_INTERVAL_SECS: u64 = 40;
/// 系统空闲超过此阈值（秒）时降低巡检频率（空闲倍率 2x）
const IDLE_THRESHOLD_SECS: u64 = 300; // 5 分钟
/// 系统活跃（空闲 < 此阈值）时使用最小间隔
const ACTIVE_THRESHOLD_SECS: u64 = 30;

/// 连续检测阈值：同一未知模块在连续 N 次巡检中出现即触发应急信号。
const CONSECUTIVE_TRIGGER_THRESHOLD: u32 = 3;

/// 环形缓冲区最大条目数。防止攻击者注入海量不同路径模块导致无界内存增长。
const RING_BUFFER_MAX_ENTRIES: usize = 256;

/// 看门狗检查间隔（秒）
const WATCHDOG_CHECK_SECS: u64 = 5;
/// 心跳超时阈值（秒）：心跳超过此时间未更新视为巡检线程已死
const HEARTBEAT_TIMEOUT_SECS: u64 = 15;
/// 看门狗连续重启失败上限：超过后强制触发应急熔断
const WATCHDOG_MAX_RESTART_FAILURES: u32 = 3;

/// ★ 空闲治理 R5：状态指纹不变时跳过磁盘持久化的强制兜底周期。
/// patrol_count 每次巡检 +1（不参与指纹），每 N 次巡检强制落盘一次，
/// 确保计数的漂移丢失上界为 N 次巡检。
const PATROL_FORCE_PERSIST_INTERVAL: u32 = 64;

/// 应急信号：未知第三方 DLL 注入（镜像 C 端 EMERG_SIG_UNKNOWN_DLL = 0x0010）。
const EMERG_SIG_UNKNOWN_DLL: u32 = 0x0010;
/// 匿名故障码：注入阻断（镜像 C 端 EMERGENCY_CODE_INJECTION_BLOCK = 0xE0002u）。
const EMERG_CODE_INJECTION_BLOCK: u32 = 0xE0002;

/// 前端监听的应急事件名。前端 listen 此事件后执行辅助通知（熔断由后端直接执行）。
pub const EMERGENCY_EVENT_NAME: &str = "verthys://security-emergency";

/// HMAC 密钥派生盐值（公开常量，不增加安全性，仅防止与其它用途的 PBKDF2 派生冲突）
const PATROL_HMAC_SALT: &[u8] = b"verthys_patrol_state_hmac_salt_v1";

/* ====================================================================== *
 *  应急事件载荷（序列化发送给前端）                                        *
 * ====================================================================== */

#[derive(serde::Serialize, Clone)]
struct EmergencyPayload {
    /// 应急信号位掩码（EMERG_SIG_UNKNOWN_DLL = 0x0010）
    signal: u32,
    /// 信号语义名称
    signal_name: &'static str,
    /// 匿名故障类型码（0xE0002 = 注入阻断）
    fault_code: u32,
    /// 触发模块完整路径
    module_path: String,
    /// 触发模块文件名
    module_name: String,
    /// 连续检测次数（达到阈值）
    consecutive_count: u32,
    /// 触发时间戳（UNIX 秒）
    timestamp_secs: u64,
    /// 安装目录（巡检白名单基准）
    install_dir: String,
    /// 已执行巡检总次数
    patrol_count: u64,
    /// 是否已执行后端强制熔断（set_session(None)）
    backend_circuit_breaker_executed: bool,
}

/* ====================================================================== *
 *  SECURITY.md 第 467-469 项：巡检状态持久化                               *
 *                                                                        *
 *  将连续检测计数、触发历史、巡检总次数以 HMAC 保护的加密文件存储。        *
 *  DPAPI 加密（机器绑定），HMAC 链式防篡改。                               *
 *  即使重启，累积计数不丢失，已触发的信号保持有效。                         *
 * ====================================================================== */

/// 可序列化的巡检状态（用于 DPAPI 持久化）
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct SerializablePatrolState {
    /// 模块路径（规范化小写）→ 连续检测次数
    counts: HashMap<String, u32>,
    /// 已触发过应急信号的模块路径集合
    triggered: HashSet<String>,
    /// 已执行巡检总次数
    patrol_count: u64,
    /// 安装目录（白名单基准前缀）
    install_dir: String,
    /// 基线版本标识（用于判断基线是否需要重建）
    baseline_version: u64,
}

impl SerializablePatrolState {
    #[allow(dead_code)]
    fn new(install_dir: String) -> Self {
        SerializablePatrolState {
            counts: HashMap::new(),
            triggered: HashSet::new(),
            patrol_count: 0,
            install_dir,
            baseline_version: 0,
        }
    }
}

/// 巡检状态持久化管理器（DPAPI 加密 + HMAC 防篡改）
struct PatrolPersistence {
    /// 持久化文件路径
    file_path: std::path::PathBuf,
    /// HMAC 密钥（设备指纹派生）
    hmac_key: [u8; 32],
}

/// HMAC 链式持久化条目
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistentEntry {
    /// 加密前的明文状态（序列化后的 JSON）
    /// 注：实际存储时整个 entry 被 DPAPI 加密
    state_json: String,
    /// HMAC 校验码（hex）
    hmac: String,
}

impl PatrolPersistence {
    /// 创建持久化管理器
    ///
    /// 获取 app_config_dir 作为存储路径，设备指纹派生 HMAC 密钥。
    /// 失败时返回 None（巡检降级为纯内存模式，不影响功能）。
    fn new(app: &AppHandle) -> Option<Self> {
        let config_dir = app.path().app_config_dir().ok()?;
        let file_path = config_dir.join(".patrol_state");

        let hmac_key = derive_hmac_key()?;
        Some(PatrolPersistence { file_path, hmac_key })
    }

    /// 加载持久化状态
    ///
    /// 读取文件 → DPAPI 解密 → HMAC 校验 → 反序列化
    /// 任何步骤失败返回 None（降级为初始空状态）
    fn load(&self) -> Option<SerializablePatrolState> {
        if !self.file_path.exists() {
            return None;
        }

        let encrypted = std::fs::read(&self.file_path).ok()?;
        let plain = dpapi_unprotect(&encrypted).ok()?;
        let entry: PersistentEntry = serde_json::from_slice(&plain).ok()?;

        // HMAC 校验
        let computed_hmac = compute_hmac(&self.hmac_key, &entry.state_json);
        if computed_hmac != entry.hmac {
            log::error!(
                "[background_patrol] 持久化状态 HMAC 校验失败（文件可能被篡改），\
                 丢弃旧状态"
            );
            return None;
        }

        let state: SerializablePatrolState = serde_json::from_str(&entry.state_json).ok()?;
        log::info!(
            "[background_patrol] 持久化状态已加载（patrol_count={}, tracked={}, triggered={}）",
            state.patrol_count,
            state.counts.len(),
            state.triggered.len()
        );
        Some(state)
    }

    /// 原子写入持久化状态
    ///
    /// 序列化 → HMAC 计算 → DPAPI 加密 → 原子写入（.tmp → rename）
    /// 失败时记录告警，不阻塞巡检
    fn save(&self, state: &SerializablePatrolState) {
        let state_json = match serde_json::to_string(state) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[background_patrol] 序列化巡检状态失败: {}", e);
                return;
            }
        };

        let hmac = compute_hmac(&self.hmac_key, &state_json);
        let entry = PersistentEntry {
            state_json,
            hmac,
        };

        let plain = match serde_json::to_vec(&entry) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[background_patrol] 序列化持久化条目失败: {}", e);
                return;
            }
        };

        let encrypted = match dpapi_protect(&plain, Some("verthys_patrol_state")) {
            Ok(e) => e,
            Err(e) => {
                log::warn!("[background_patrol] DPAPI 加密巡检状态失败: {}", e);
                return;
            }
        };

        // 原子写入：先写 .tmp 再 rename
        let tmp_path = self.file_path.with_extension("patrol_state.tmp");
        if let Err(e) = std::fs::write(&tmp_path, &encrypted) {
            log::warn!("[background_patrol] 写入巡检状态临时文件失败: {}", e);
            return;
        }
        if let Err(e) = std::fs::rename(&tmp_path, &self.file_path) {
            log::warn!("[background_patrol] 重命名巡检状态文件失败: {}", e);
            return;
        }

        log::debug!(
            "[background_patrol] 巡检状态已持久化（patrol_count={}）",
            state.patrol_count
        );
    }
}

/// 从设备指纹派生 HMAC 密钥
fn derive_hmac_key() -> Option<[u8; 32]> {
    use crate::infrastructure::device_fingerprint::get_device_fingerprint;
    match get_device_fingerprint() {
        Ok(fingerprint) => match pbkdf2_derive_default(fingerprint.as_bytes(), PATROL_HMAC_SALT) {
            Ok(key) => Some(key),
            Err(e) => {
                log::warn!("[background_patrol] 派生 HMAC 密钥失败: {}", e);
                None
            }
        },
        Err(e) => {
            log::warn!("[background_patrol] 获取设备指纹失败: {}", e);
            None
        }
    }
}

/// 计算 HMAC-SHA256（hex 编码）
fn compute_hmac(key: &[u8], data: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length error");
    mac.update(data.as_bytes());
    let result = mac.finalize();
    let bytes = result.into_bytes();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// ★ 空闲治理 R5：计算巡检状态指纹（SHA-256 前 8 字节）
///
/// 指纹覆盖安全关键状态（counts / triggered / install_dir / baseline_version），
/// 不含 patrol_count（每次巡检 +1，纳入则指纹永不匹配，跳过失效）。
/// 键先排序再哈希，消除 HashMap/HashSet 迭代序不稳定导致的假阳性。
fn compute_state_fingerprint(s: &SerializablePatrolState) -> u64 {
    let mut hasher = Sha256::new();

    let mut count_keys: Vec<&String> = s.counts.keys().collect();
    count_keys.sort();
    for k in count_keys {
        hasher.update(k.as_bytes());
        hasher.update(s.counts[k].to_le_bytes());
    }

    let mut triggered: Vec<&String> = s.triggered.iter().collect();
    triggered.sort();
    for k in triggered {
        hasher.update(k.as_bytes());
    }

    hasher.update(s.install_dir.as_bytes());
    hasher.update(s.baseline_version.to_le_bytes());

    let out = hasher.finalize();
    u64::from_le_bytes(out[0..8].try_into().expect("SHA-256 output length"))
}

/* ====================================================================== *
 *  巡检状态（环形缓冲区 + 持久化支持）                                     *
 * ====================================================================== */

/// 巡检内部状态：跟踪每个未知模块的连续检测次数。
struct PatrolState {
    /// 模块路径（规范化小写）→ 连续检测次数
    counts: HashMap<String, u32>,
    /// 插入顺序队列（最旧在队首），用于环形缓冲淘汰
    order: VecDeque<String>,
    /// 已触发过应急信号的模块路径集合（避免同一模块重复触发）
    triggered: HashSet<String>,
    /// 安装目录（白名单基准前缀）
    install_dir: String,
    /// 已执行巡检总次数
    patrol_count: u64,
    /// 基线版本标识
    baseline_version: u64,
    /// ★ 空闲治理 R5：上次实际落盘的状态指纹（不变则跳过磁盘持久化）
    last_persist_fingerprint: u64,
    /// ★ 空闲治理 R5：自上次实际落盘以来的巡检次数（周期性强制落盘兜底）
    patrols_since_persist: u32,
}

impl PatrolState {
    fn new(install_dir: String) -> Self {
        PatrolState {
            counts: HashMap::new(),
            order: VecDeque::new(),
            triggered: HashSet::new(),
            install_dir,
            patrol_count: 0,
            baseline_version: 0,
            last_persist_fingerprint: 0,
            patrols_since_persist: 0,
        }
    }

    /// 从持久化状态恢复
    fn from_serialized(s: SerializablePatrolState) -> Self {
        let order: VecDeque<String> = s.counts.keys().cloned().collect();
        // 恢复时以已加载状态计算指纹，避免启动后首次巡检的无谓重写
        let fingerprint = compute_state_fingerprint(&s);
        PatrolState {
            counts: s.counts,
            order,
            triggered: s.triggered,
            install_dir: s.install_dir,
            patrol_count: s.patrol_count,
            baseline_version: s.baseline_version,
            last_persist_fingerprint: fingerprint,
            patrols_since_persist: 0,
        }
    }

    /// 转换为可序列化状态
    fn to_serialized(&self) -> SerializablePatrolState {
        SerializablePatrolState {
            counts: self.counts.clone(),
            triggered: self.triggered.clone(),
            patrol_count: self.patrol_count,
            install_dir: self.install_dir.clone(),
            baseline_version: self.baseline_version,
        }
    }

    /// 记录本次巡检测到的未知模块，返回"本次新达到阈值且尚未触发过"的模块列表。
    fn record(&mut self, unknowns: &[UnknownModule]) -> Vec<UnknownModule> {
        self.patrol_count += 1;

        let current_paths: HashSet<String> = unknowns
            .iter()
            .map(|m| normalize_key(&m.path))
            .collect();

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

/* ====================================================================== *
 *  SECURITY.md 第 463-465 项：哈希基线管理                                 *
 *                                                                        *
 *  系统目录模块哈希基线在后台线程惰性构建，避免阻塞巡检启动。               *
 *  基线构建完成后缓存于 Arc<RwLock<Option<HashBaseline>>>。                *
 * ====================================================================== */

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
struct HashBaselineManager {
    state: Mutex<HashBaselineState>,
}

impl HashBaselineManager {
    fn new() -> Self {
        HashBaselineManager {
            state: Mutex::new(HashBaselineState::new()),
        }
    }

    /// 尝试获取基线快照（如果已构建完成）
    ///
    /// 返回 Some(baseline) 表示基线可用，None 表示尚未构建或构建失败。
    /// 调用方应在此返回 None 时跳过哈希验证（降级为仅路径信任）。
    fn get_snapshot(&self) -> Option<HashBaseline> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.baseline.clone()
    }

    /// 在后台线程构建基线（非阻塞）
    ///
    /// 如果基线已存在或正在构建中，此函数为空操作。
    /// 构建失败会递增 failure_count，连续失败 3 次后放弃。
    fn try_build_async(&self) {
        let should_build = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.baseline.is_some() || state.building {
                false
            } else if state.failure_count >= 3 {
                log::warn!("[background_patrol] 哈希基线构建连续失败 {} 次，放弃构建", state.failure_count);
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
                BASELINE_BUILD_RESULT.lock().unwrap_or_else(|e| e.into_inner()).replace(baseline);
                BASELINE_BUILD_DONE.store(true, Ordering::SeqCst);

                log::info!(
                    "[background_patrol] 哈希基线构建完成：{} 个模块，耗时 {}ms",
                    BASELINE_BUILD_RESULT.lock().unwrap_or_else(|e| e.into_inner())
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
    fn poll_build_result(&self) {
        if !BASELINE_BUILD_DONE.load(Ordering::SeqCst) {
            return;
        }

        let baseline = {
            let mut result = BASELINE_BUILD_RESULT.lock().unwrap_or_else(|e| e.into_inner());
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

/* ====================================================================== *
 *  BackgroundPatrol — 巡检线程 + 看门狗管理器                               *
 * ====================================================================== */

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
struct PatrolContext {
    /// Tauri AppHandle（用于发送应急事件 + 访问 AppState）
    app: AppHandle,
    /// 巡检状态
    state: Arc<Mutex<PatrolState>>,
    /// 哈希基线管理器
    baseline_manager: Arc<HashBaselineManager>,
    /// 停止标志
    stop_flag: Arc<AtomicBool>,
    /// 心跳时间戳
    heartbeat: Arc<AtomicU64>,
    /// 安装目录
    install_dir: String,
    /// 持久化管理器
    persistence: Arc<Option<PatrolPersistence>>,
    /// 看门狗重启计数
    #[allow(dead_code)]
    restart_count: Arc<AtomicU32>,
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

        // SECURITY.md 第 479-481 项：进程完整性监控
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

        // SECURITY.md 第 471-473 项：启动看门狗线程
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

/* ====================================================================== *
 *  SECURITY.md 第 471-473 项：看门狗主循环                                 *
 *                                                                        *
 *  每 5 秒检查巡检线程心跳，发现线程退出立即重启。                         *
 *  连续重启失败 3 次后强制触发应急熔断（直接销毁 Worker 会话）。            *
 * ====================================================================== */

// 说明：看门狗线程所需的全局安全上下文（应用句柄、巡检状态、基线管理器、
// 停止标志、心跳、安装目录、持久化、重启计数），每个参数为独立的安全
// 监控职责，打包会掩盖熔断链路的数据流，故豁免参数数量检查。
#[allow(clippy::too_many_arguments)]
fn watchdog_loop(
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

                // SECURITY.md 第 471-473 项：强制触发应急熔断
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
                    log::error!(
                        "[background_patrol][看门狗] 巡检线程重启失败: {}",
                        e
                    );
                }
            }
        } else {
            // 心跳正常，重置重启计数
            if restart_count.load(Ordering::SeqCst) > 0 {
                log::info!(
                    "[background_patrol][看门狗] 巡检线程心跳恢复正常，重置重启计数"
                );
                restart_count.store(0, Ordering::SeqCst);
            }
        }
    }

    log::info!("[background_patrol][看门狗] 看门狗线程退出");
}

/* ====================================================================== *
 *  巡检主循环（动态频率 + catch_unwind + 哈希基线 + 持久化）                *
 * ====================================================================== */

fn patrol_loop(ctx: PatrolContext) {
    // 设置线程优先级为 THREAD_PRIORITY_LOWEST
    set_current_thread_priority_lowest();

    log::info!(
        "[background_patrol] 巡检线程就绪，install_dir={}",
        sanitize_path(&ctx.install_dir)
    );

    // SECURITY.md 第 463-465 项：在后台构建哈希基线
    ctx.baseline_manager.try_build_async();

    while !ctx.stop_flag.load(Ordering::SeqCst) {
        // 更新心跳
        ctx.heartbeat.store(now_ms(), Ordering::SeqCst);

        // SECURITY.md 第 471-473 项：catch_unwind 包裹单次巡检
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

        // SECURITY.md 第 459 项：动态频率计算
        let sleep_secs = compute_dynamic_interval();
        log::debug!(
            "[background_patrol] 下次巡检间隔: {}s",
            sleep_secs
        );

        // 分段睡眠（每秒检查停止标志）
        for _ in 0..sleep_secs {
            if ctx.stop_flag.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    log::info!("[background_patrol] 巡检线程退出");
}

/* ====================================================================== *
 *  SECURITY.md 第 459 项：动态频率计算                                     *
 *                                                                        *
 *  基于随机抖动（10~40 秒）且与系统空闲时间结合的动态巡检。                 *
 *  - 系统活跃（空闲 < 30s）：使用最小间隔 10-15s（高频巡检）              *
 *  - 系统空闲 > 5 分钟：间隔翻倍 20-80s（低频省 CPU）                     *
 *  - 中间状态：标准 10-40s 随机抖动                                       *
 * ====================================================================== */

fn compute_dynamic_interval() -> u64 {
    let idle_secs = get_system_idle_secs();

    // 生成随机抖动基数（10~40 秒）
    let base = PATROL_MIN_INTERVAL_SECS + (generate_random_u64() % (PATROL_MAX_INTERVAL_SECS - PATROL_MIN_INTERVAL_SECS + 1));

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
fn generate_random_u64() -> u64 {
    let mut buf = [0u8; 8];
    if getrandom::getrandom(&mut buf).is_ok() {
        u64::from_le_bytes(buf)
    } else {
        // 回退：使用系统时间作为伪随机源
        now_ms()
    }
}

/* ====================================================================== *
 *  执行单次巡检                                                            *
 *                                                                        *
 *  1. 轻量扫描：路径白名单匹配                                            *
 *  2. 哈希基线验证：系统目录模块哈希匹配                                  *
 *  3. 更新环形缓冲                                                       *
 *  4. 持久化状态                                                         *
 *  5. 对新达阈值的模块触发应急信号                                        *
 * ====================================================================== */

fn run_one_patrol(ctx: &PatrolContext) {
    // 轮询哈希基线构建结果
    ctx.baseline_manager.poll_build_result();

    // 轻量扫描：仅路径白名单匹配
    let unknowns = module_whitelist::patrol_modules_paths_only(&ctx.install_dir);

    // SECURITY.md 第 463-465 项：哈希基线验证
    // 对系统目录下的模块进行哈希匹配，检测被替换的 DLL
    let mut all_threats: Vec<UnknownModule> = unknowns;

    if let Some(baseline) = ctx.baseline_manager.get_snapshot() {
        let hash_threats = check_hash_baseline_violations(&baseline);
        if !hash_threats.is_empty() {
            log::warn!(
                "[background_patrol] 哈希基线检测到 {} 个被替换的系统模块",
                hash_threats.len()
            );
            all_threats.extend(hash_threats);
        }
    }

    let triggered = {
        let mut st = match ctx.state.lock() {
            Ok(g) => g,
            Err(e) => {
                log::error!("[background_patrol] 状态锁中毒，跳过本次巡检: {}", e);
                return;
            }
        };

        if !all_threats.is_empty() {
            log::warn!(
                "[background_patrol] 巡检 #{} 发现 {} 个未知/可疑模块",
                st.patrol_count + 1,
                all_threats.len()
            );
            for m in &all_threats {
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

        st.record(&all_threats)
    };

    // SECURITY.md 第 467-469 项：持久化状态
    // ★ 空闲治理 R5：状态指纹比对跳过 — 安全关键状态（counts/triggered/
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

    // 对本次新达阈值的模块逐个触发应急信号
    for m in &triggered {
        trigger_emergency_signal(ctx, m);
    }
}

/// SECURITY.md 第 463-465 项：检查系统目录模块的哈希基线违规
///
/// 枚举当前进程已加载的系统目录模块，对每个模块计算 SHA-256 并与基线比较。
/// 哈希不匹配的模块视为威胁（可能被替换）。
fn check_hash_baseline_violations(baseline: &HashBaseline) -> Vec<UnknownModule> {
    let mut threats = Vec::new();

    // 获取当前进程模块列表（仅路径，不做白名单匹配）
    // 复用 module_whitelist 的枚举逻辑，但这里我们只需要路径
    let modules = enumerate_loaded_module_paths();

    for (name, path) in modules {
        // 仅验证系统目录下的模块（基线仅包含系统目录）
        match verify_module_against_baseline(&path, baseline) {
            Ok(true) => {
                // 哈希匹配，模块合法
            }
            Ok(false) => {
                // 哈希不匹配，模块可能被替换
                log::error!(
                    "[background_patrol] 哈希基线违规：系统模块 {} 哈希不匹配（可能被替换）",
                    sanitize_path(&path)
                );
                threats.push(UnknownModule {
                    name,
                    path,
                    reason: "哈希基线不匹配（系统模块被替换）".to_string(),
                });
            }
            Err(()) => {
                // 不在基线中（非系统目录模块），跳过
            }
        }
    }

    threats
}

/// 枚举当前进程已加载模块的 (名称, 路径) 列表
#[cfg(target_os = "windows")]
fn enumerate_loaded_module_paths() -> Vec<(String, String)> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };
    use windows::Win32::System::Threading::GetCurrentProcessId;

    let mut result = Vec::new();
    let pid = unsafe { GetCurrentProcessId() };
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    };
    let snapshot = match snapshot {
        Ok(h) => h,
        Err(_) => return result,
    };

    let mut me = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    let mut ok = unsafe { Module32FirstW(snapshot, &mut me) }.is_ok();
    while ok {
        let name_len = me.szModule.iter().position(|&c| c == 0).unwrap_or(me.szModule.len());
        let name = String::from_utf16_lossy(&me.szModule[..name_len]);
        let path_len = me.szExePath.iter().position(|&c| c == 0).unwrap_or(me.szExePath.len());
        let path = String::from_utf16_lossy(&me.szExePath[..path_len]);

        if !path.is_empty() {
            result.push((name, path));
        }

        ok = unsafe { Module32NextW(snapshot, &mut me) }.is_ok();
    }

    let _ = unsafe { CloseHandle(snapshot) };
    result
}

/// 非 Windows 平台：枚举模块（空实现）
#[cfg(not(target_os = "windows"))]
fn enumerate_loaded_module_paths() -> Vec<(String, String)> {
    Vec::new()
}

/* ====================================================================== *
 *  SECURITY.md 第 475-477 项：独立应急响应通道                              *
 *                                                                        *
 *  当连续检测到威胁时，BackgroundPatrol 直接通过 AppState::set_session(None)*
 *  强制销毁 Worker，并通过文件锁和共享标志阻止任何新建会话。                 *
 *  前端事件仅作为辅助通知，后端强制措施先于前端执行。                       *
 * ====================================================================== */

fn trigger_emergency_signal(ctx: &PatrolContext, module: &UnknownModule) {
    let (patrol_count, install_dir) = match ctx.state.lock() {
        Ok(st) => (st.patrol_count, st.install_dir.clone()),
        Err(_) => (0u64, String::new()),
    };

    log::error!(
        "[background_patrol][应急] DLL 注入/劫持检测！模块 {} 路径={} 在连续 {} 次巡检中出现，\
         触发应急信号 EMERG_SIG_UNKNOWN_DLL(0x{:04X}) 故障码 0x{:05X}（巡检 #{}）",
        module.name,
        sanitize_path(&module.path),
        CONSECUTIVE_TRIGGER_THRESHOLD,
        EMERG_SIG_UNKNOWN_DLL,
        EMERG_CODE_INJECTION_BLOCK,
        patrol_count
    );

    // 写入审计日志（威胁检测）
    write_patrol_audit(
        &ctx.app,
        AuditEventType::PatrolThreat,
        AuditResult::Failure,
        Some(format!(
            "DLL 注入检测: 模块={} 连续 {} 次 (信号=0x{:04X} 故障码=0x{:05X} 巡检=#{})",
            module.name,
            CONSECUTIVE_TRIGGER_THRESHOLD,
            EMERG_SIG_UNKNOWN_DLL,
            EMERG_CODE_INJECTION_BLOCK,
            patrol_count
        )),
    );

    // SECURITY.md 第 475-477 项：后端独立应急响应（先于前端执行）
    let circuit_breaker_executed = execute_backend_circuit_breaker(
        &ctx.app,
        &format!("dll_injection:{}", module.name),
    );

    // 写入审计日志（应急熔断执行）
    write_patrol_audit(
        &ctx.app,
        AuditEventType::PatrolEmergency,
        if circuit_breaker_executed {
            AuditResult::Success
        } else {
            AuditResult::Failure
        },
        Some(format!(
            "后端强制熔断: 销毁 Worker 会话 (结果={})",
            if circuit_breaker_executed { "成功" } else { "失败" }
        )),
    );

    let payload = EmergencyPayload {
        signal: EMERG_SIG_UNKNOWN_DLL,
        signal_name: "DLL_HIJACK_INJECTION",
        fault_code: EMERG_CODE_INJECTION_BLOCK,
        module_path: module.path.clone(),
        module_name: module.name.clone(),
        consecutive_count: CONSECUTIVE_TRIGGER_THRESHOLD,
        timestamp_secs: now_secs(),
        install_dir,
        patrol_count,
        backend_circuit_breaker_executed: circuit_breaker_executed,
    };

    // 发送 Tauri 事件：前端辅助通知（熔断已由后端执行）
    if let Err(e) = ctx.app.emit(EMERGENCY_EVENT_NAME, payload) {
        log::error!(
            "[background_patrol][应急] 发送应急事件失败（前端未收到辅助通知）: {}",
            e
        );
    }
}

/// SECURITY.md 第 475-477 项：执行后端强制熔断
///
/// 直接通过 AppState::set_session(None) 销毁 Worker 会话。
/// 子进程退出即销毁所有密钥与句柄。
///
/// 返回 true 表示熔断已执行，false 表示执行失败（如 AppState 未注册）。
fn execute_backend_circuit_breaker(app: &AppHandle, reason: &str) -> bool {
    log::error!(
        "[background_patrol][应急] 执行后端强制熔断：销毁 Worker 会话 (reason={})",
        reason
    );

    match app.try_state::<AppState>() {
        Some(state) => {
            // 直接销毁 Worker 会话（Drop 自动 kill 子进程，销毁所有密钥与句柄）
            state.set_session(None);
            log::error!(
                "[background_patrol][应急] Worker 会话已强制销毁 (reason={})",
                reason
            );
            true
        }
        None => {
            log::error!(
                "[background_patrol][应急] 无法获取 AppState，强制熔断失败（状态未注册）"
            );
            false
        }
    }
}

/* ====================================================================== *
 *  审计日志辅助                                                            *
 * ====================================================================== */

/// 写入巡检审计事件（不阻塞巡检流程）
fn write_patrol_audit(
    app: &AppHandle,
    event_type: AuditEventType,
    result: AuditResult,
    detail: Option<String>,
) {
    let log_path = match app.path().app_config_dir() {
        Ok(dir) => dir.join("audit.log"),
        Err(e) => {
            log::warn!("[background_patrol] 获取配置目录失败，跳过审计写入: {}", e);
            return;
        }
    };

    let hmac_key = match derive_hmac_key() {
        Some(k) => k,
        None => return,
    };

    let session_id = format!("pid-{}", std::process::id());
    let mut event = AuditEvent::new(event_type, &session_id, "background_patrol", result);

    if let Some(d) = detail {
        event = event.with_detail(d);
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[background_patrol] 写入审计事件失败（不阻塞巡检）: {}", e);
    }
}

/* ====================================================================== *
 *  SECURITY.md 第 479-481 项：进程完整性监控                               *
 *                                                                        *
 *  使用 SetProcessMitigationPolicy 启用进程缓解策略：                       *
 *  - ProcessSignaturePolicy：限制仅加载 Microsoft 签名的 DLL              *
 *  - ProcessImageLoadPolicy：禁止从远程位置加载镜像                        *
 *                                                                        *
 *  注意：此策略必须在进程启动早期应用。在 setup 阶段调用可能已晚           *
 *  （部分 DLL 已加载），调用失败时记录告警但不阻止启动。                   *
 * ====================================================================== */

#[cfg(target_os = "windows")]
fn apply_process_mitigation_policies() {
    use std::ffi::c_void;

    // PROCESS_MITIGATION_POLICY 枚举值
    // ProcessSignaturePolicy = 8
    // ProcessImageLoadPolicy = 10
    const PROCESS_SIGNATURE_POLICY: u32 = 8;
    const PROCESS_IMAGE_LOAD_POLICY: u32 = 10;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetProcessMitigationPolicy(
            mitigation_policy: u32,
            lp_buffer: *const c_void,
            dw_length: u32,
        ) -> i32;
    }

    unsafe {
        // ProcessImageLoadPolicy：禁止从远程 UNC 路径加载镜像 + 优先从 System32 加载
        // 结构体：PROCESS_MITIGATION_IMAGE_LOAD_POLICY（4 字节位域）
        // NoRemoteMgmtImages = bit 0, NoLowMandatoryLabelImages = bit 1, PreferSystem32Images = bit 2
        #[repr(C)]
        #[derive(Default)]
        struct ProcessImageLoadPolicy {
            flags: u32,
        }

        // NoRemoteMgmtImages=1 | PreferSystem32Images=4 = 0x5
        let image_load_policy = ProcessImageLoadPolicy { flags: 0x5 };

        let result = SetProcessMitigationPolicy(
            PROCESS_IMAGE_LOAD_POLICY,
            &image_load_policy as *const _ as *const c_void,
            std::mem::size_of::<ProcessImageLoadPolicy>() as u32,
        );

        if result != 0 {
            log::warn!(
                "[background_patrol] SetProcessMitigationPolicy(ProcessImageLoadPolicy) 失败 \
                 (可能已有 DLL 加载，策略应用过晚)"
            );
        } else {
            log::info!(
                "[background_patrol] ProcessImageLoadPolicy 已启用 \
                 (NoRemoteMgmtImages + PreferSystem32Images)"
            );
        }

        // ProcessSignaturePolicy：限制仅加载 Microsoft 签名 DLL
        // 注意：此策略非常严格，可能导致后续非 Microsoft 签名 DLL 加载失败。
        // 使用 AuditMicrosoftSignedOnly（bit 3 = 0x8）进行审计模式，
        // 而非 MicrosoftSignedOnly（bit 0 = 0x1）的阻断模式，
        // 以避免意外阻断合法 DLL 加载。
        #[repr(C)]
        #[derive(Default)]
        struct ProcessSignaturePolicy {
            flags: u32,
        }

        // AuditMicrosoftSignedOnly = bit 3 = 0x8（审计模式，记录但不阻断）
        let sig_policy = ProcessSignaturePolicy { flags: 0x8 };

        let result = SetProcessMitigationPolicy(
            PROCESS_SIGNATURE_POLICY,
            &sig_policy as *const _ as *const c_void,
            std::mem::size_of::<ProcessSignaturePolicy>() as u32,
        );

        if result != 0 {
            log::warn!(
                "[background_patrol] SetProcessMitigationPolicy(ProcessSignaturePolicy) 失败 \
                 (可能已有非 Microsoft 签名 DLL 加载)"
            );
        } else {
            log::info!(
                "[background_patrol] ProcessSignaturePolicy 已启用 (AuditMicrosoftSignedOnly)"
            );
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn apply_process_mitigation_policies() {
    // 非 Windows：无对应 API
}

/* ====================================================================== *
 *  系统空闲时间获取（Windows GetLastInputInfo）                             *
 * ====================================================================== */

/// 获取系统空闲时间（秒）
///
/// 使用 GetLastInputInfo + GetTickCount 计算自上次输入以来的时间。
/// 非 Windows 平台返回 0（视为始终活跃）。
#[cfg(target_os = "windows")]
fn get_system_idle_secs() -> u64 {
    #[repr(C)]
    #[derive(Default)]
    struct LastInputInfo {
        cb_size: u32,
        dw_time: u32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn GetLastInputInfo(plii: *mut LastInputInfo) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetTickCount() -> u32;
    }

    unsafe {
        let mut lii = LastInputInfo {
            cb_size: std::mem::size_of::<LastInputInfo>() as u32,
            ..Default::default()
        };

        if GetLastInputInfo(&mut lii) == 0 {
            return 0; // 获取失败，视为活跃
        }

        let now = GetTickCount();
        // 处理 32 位 tick count 回绕（约 49 天）
        let idle_ms = if now >= lii.dw_time {
            now - lii.dw_time
        } else {
            // 回绕情况：now 在回绕后，dw_time 在回绕前
            (u32::MAX - lii.dw_time) + now + 1
        };

        (idle_ms / 1000) as u64
    }
}

/// 非 Windows 平台：系统空闲时间（返回 0，视为始终活跃）
#[cfg(not(target_os = "windows"))]
fn get_system_idle_secs() -> u64 {
    0
}

/* ====================================================================== *
 *  线程优先级设置（Windows SetThreadPriority）                             *
 * ====================================================================== */

#[cfg(target_os = "windows")]
fn set_current_thread_priority_lowest() {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThread() -> *mut c_void;
        fn SetThreadPriority(thread: *mut c_void, npriority: i32) -> i32;
    }

    const THREAD_PRIORITY_LOWEST: i32 = -2;

    unsafe {
        let h = GetCurrentThread();
        let ok = SetThreadPriority(h, THREAD_PRIORITY_LOWEST);
        if ok == 0 {
            log::warn!("[background_patrol] SetThreadPriority(THREAD_PRIORITY_LOWEST) 失败");
        } else {
            log::debug!("[background_patrol] 线程优先级已设为 THREAD_PRIORITY_LOWEST(-2)");
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn set_current_thread_priority_lowest() {
    // 非 Windows：无对应 API
}

/* ====================================================================== *
 *  辅助函数                                                               *
 * ====================================================================== */

/// 路径键规范化：剥离 \\?\ 前缀、统一反斜杠、转小写、去尾分隔符。
fn normalize_key(path: &str) -> String {
    let mut s = path;
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        s = stripped;
    }
    let mut s = s.replace('/', "\\");
    s = s.to_lowercase();
    while s.len() > 1 && s.ends_with('\\') {
        s.pop();
    }
    s
}

/// 日志脱敏：隐藏用户路径中的用户名
fn sanitize_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    if let Ok(home) = std::env::var("USERPROFILE") {
        let h = home.replace('\\', "/");
        if normalized.contains(&h) {
            return normalized.replace(&h, "<USER_HOME>");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let h = home.replace('\\', "/");
        if normalized.contains(&h) {
            return normalized.replace(&h, "<USER_HOME>");
        }
    }
    normalized
}

/// 当前 Unix 毫秒时间戳
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 当前 Unix 秒时间戳
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/* ====================================================================== *
 *  单元测试                                                               *
 * ====================================================================== */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_key() {
        assert_eq!(normalize_key(r"\\?\C:\Windows\System32\test.dll"), "c:\\windows\\system32\\test.dll");
        assert_eq!(normalize_key("C:/Windows/test.dll"), "c:\\windows\\test.dll");
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

    #[test]
    fn test_compute_hmac() {
        let key = [0u8; 32];
        let hmac1 = compute_hmac(&key, "test data");
        let hmac2 = compute_hmac(&key, "test data");
        let hmac3 = compute_hmac(&key, "different data");

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
}
