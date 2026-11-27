/*
 * 巡检状态持久化
 *
 * 将连续检测计数、触发历史、巡检总次数以 HMAC 保护的加密文件存储。
 * DPAPI 加密（机器绑定），HMAC 链式防篡改。
 * 即使重启，累积计数不丢失，已触发的信号保持有效。
 */

use std::collections::{HashMap, HashSet};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};

use crate::util::crypto::{dpapi_protect, dpapi_unprotect, pbkdf2_derive_default};

use super::{PATROL_HMAC_SALT, PATROL_STATE_SCHEMA_VERSION};

/// 持久化状态模式是否受支持
pub(super) fn is_supported_state_schema(version: u32) -> bool {
    version >= PATROL_STATE_SCHEMA_VERSION
}

/// 可序列化的巡检状态（用于 DPAPI 持久化）
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub(super) struct SerializablePatrolState {
    /// 状态模式版本（默认 0 = 引入分级前的旧格式）
    #[serde(default)]
    pub(super) schema_version: u32,
    /// 模块路径（规范化小写）→ 连续检测次数（仅硬威胁）
    pub(super) counts: HashMap<String, u32>,
    /// 已触发过应急信号的模块路径集合（仅硬威胁）
    pub(super) triggered: HashSet<String>,
    /// 已记录过审计的软告警模块路径（避免每轮巡检重复写审计）
    #[serde(default)]
    pub(super) reported_soft: HashSet<String>,
    /// 已执行巡检总次数
    pub(super) patrol_count: u64,
    /// 安装目录（白名单基准前缀）
    pub(super) install_dir: String,
    /// 基线版本标识（用于判断基线是否需要重建）
    pub(super) baseline_version: u64,
}

impl SerializablePatrolState {
    #[allow(dead_code)]
    pub(super) fn new(install_dir: String) -> Self {
        SerializablePatrolState {
            schema_version: PATROL_STATE_SCHEMA_VERSION,
            counts: HashMap::new(),
            triggered: HashSet::new(),
            reported_soft: HashSet::new(),
            patrol_count: 0,
            install_dir,
            baseline_version: 0,
        }
    }
}

/// 巡检状态持久化管理器（DPAPI 加密 + HMAC 防篡改）
pub(super) struct PatrolPersistence {
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
    pub(super) fn new(app: &AppHandle) -> Option<Self> {
        let config_dir = app.path().app_config_dir().ok()?;
        let file_path = config_dir.join(".patrol_state");

        let hmac_key = derive_hmac_key()?;
        Some(PatrolPersistence {
            file_path,
            hmac_key,
        })
    }

    /// 加载持久化状态
    ///
    /// 读取文件 → DPAPI 解密 → HMAC 校验 → 反序列化
    /// 任何步骤失败返回 None（降级为初始空状态）
    pub(super) fn load(&self) -> Option<SerializablePatrolState> {
        if !self.file_path.exists() {
            return None;
        }

        let encrypted = std::fs::read(&self.file_path).ok()?;
        let plain = dpapi_unprotect(&encrypted).ok()?;
        let entry: PersistentEntry = serde_json::from_slice(&plain).ok()?;

        // HMAC 校验（计算失败与篡改同为拒绝：降级空状态）
        let computed_hmac = compute_hmac(&self.hmac_key, &entry.state_json).ok()?;
        if computed_hmac != entry.hmac {
            log::error!(
                "[background_patrol] 持久化状态 HMAC 校验失败（文件可能被篡改），\
                 丢弃旧状态"
            );
            return None;
        }

        let state: SerializablePatrolState = serde_json::from_str(&entry.state_json).ok()?;
        if !is_supported_state_schema(state.schema_version) {
            log::info!(
                "[background_patrol] 持久化状态为旧语义（schema={} < {}），\
                 丢弃并重建：旧版按“路径即威胁”记录的误报计数不再适用",
                state.schema_version,
                PATROL_STATE_SCHEMA_VERSION
            );
            return None;
        }
        log::info!(
            "[background_patrol] 持久化状态已加载（patrol_count={}, tracked={}, triggered={}, soft={}）",
            state.patrol_count,
            state.counts.len(),
            state.triggered.len(),
            state.reported_soft.len()
        );
        Some(state)
    }

    /// 原子写入持久化状态
    ///
    /// 序列化 → HMAC 计算 → DPAPI 加密 → 原子写入（.tmp → rename）
    /// 失败时记录告警，不阻塞巡检
    pub(super) fn save(&self, state: &SerializablePatrolState) {
        let state_json = match serde_json::to_string(state) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[background_patrol] 序列化巡检状态失败: {}", e);
                return;
            }
        };

        let hmac = match compute_hmac(&self.hmac_key, &state_json) {
            Ok(h) => h,
            Err(e) => {
                log::warn!("[background_patrol] 计算状态 HMAC 失败，跳过持久化: {}", e);
                return;
            }
        };
        let entry = PersistentEntry { state_json, hmac };

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
pub(super) fn derive_hmac_key() -> Option<[u8; 32]> {
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
/// 密钥被后端拒绝时返回 Err（调用方按各自降级语义处置，不 panic）
pub(super) fn compute_hmac(key: &[u8], data: &str) -> Result<String, String> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| "HMAC key rejected by backend".to_string())?;
    mac.update(data.as_bytes());
    let result = mac.finalize();
    let bytes = result.into_bytes();
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

/// 空闲治理：计算巡检状态指纹（SHA-256 前 8 字节）
///
/// 指纹覆盖安全关键状态（counts / triggered / install_dir / baseline_version），
/// 不含 patrol_count（每次巡检 +1，纳入则指纹永不匹配，跳过失效）。
/// 键先排序再哈希，消除 HashMap/HashSet 迭代序不稳定导致的假阳性。
pub(super) fn compute_state_fingerprint(s: &SerializablePatrolState) -> u64 {
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

    let mut reported_soft: Vec<&String> = s.reported_soft.iter().collect();
    reported_soft.sort();
    for k in reported_soft {
        hasher.update(k.as_bytes());
    }

    hasher.update(s.install_dir.as_bytes());
    hasher.update(s.baseline_version.to_le_bytes());

    let out = hasher.finalize();
    u64::from_le_bytes(out[0..8].try_into().expect("SHA-256 output length"))
}
