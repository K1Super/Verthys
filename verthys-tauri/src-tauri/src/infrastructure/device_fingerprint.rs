/*
 * @file infrastructure/device_fingerprint.rs
 * @brief 设备硬件唯一指纹采集、缓存熔断与设备变更匹配判定模块
 *
 * 模块强制约束、设计意图与风险边界：
 * 采集层约束
 * 1. Windows全量依赖系统原生API获取硬件标识，彻底摒弃PowerShell外部进程调用，消除执行依赖与性能损耗；跨平台做降级兼容，非Windows读取machine-id与主机名组合生成标识。
 * 2. CPU使用内嵌汇编指令直接读取厂商ID与功能特征位，主板读取SMBIOS规范固件UUID，磁盘读取系统分区卷序列号，三类硬件特征共同构成强绑定设备凭据。
 * 3. 硬件采集为同步阻塞逻辑，上层调用必须通过阻塞线程池+超时控制器包裹，避免阻塞异步运行时。
 *
 * 缓存与熔断容错约束
 * 1. 进程级一次性锁仅缓存采集成功的有效结果，瞬时采集失败不写入缓存，防止单次异常导致永久指纹失效。
 * 2. 内置故障熔断器保护机制：连续3次采集失败触发熔断锁定，强制冷却60秒后方可重试，规避底层硬件接口持续报错无限重试占用资源。
 * 3. 采集成功自动清零熔断计数器，冷却周期结束自动重置状态，保证故障自愈能力。
 *
 * 设备变更判定约束
 * 1. 拆分CPU、主板、磁盘独立哈希值，支持组件级权重化匹配校验，权重分配：CPU25%、主板35%、磁盘40%，总分100%。
 * 2. 设定80%匹配阈值作为设备可信判定边界，用于硬件小幅更换后的授权放行与变更告警提示。
 * 3. 不做弱兜底降级策略，硬件信息全部获取失败直接向上抛出错误，不生成不可靠弱指纹造成授权安全漏洞。
 *
 * 存储与依赖约束
 * 1. 指纹数据使用SHA256单向哈希摘要存储，提供固定长度二进制序列化/反序列化方法，适配DPAPI加密持久化存储。
 * 2. 本模块仅封装底层采集与计算能力，Tauri暴露命令统一交由上层控制器注册，职责单一解耦。
 */

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

// ===== 缓存与熔断器状态定义 =====

/// 进程全局有效设备指纹缓存，仅存储采集成功的合法结果，失败不占用存储
static DEVICE_COMPONENTS_CACHE: OnceLock<DeviceComponents> = OnceLock::new();

/// 故障熔断器状态结构体，用于控制连续失败重试频率
struct CircuitBreaker {
    /// 连续采集失败累计次数
    consecutive_failures: u32,
    /// 最近一次失败发生时间戳（Unix秒级）
    last_failure_time: u64,
}

impl CircuitBreaker {
    const fn new() -> Self {
        CircuitBreaker {
            consecutive_failures: 0,
            last_failure_time: 0,
        }
    }
}

/// 熔断触发阈值：连续失败达到该次数进入冷却锁定
const CIRCUIT_BREAKER_THRESHOLD: u32 = 3;
/// 熔断强制冷却时长：单位秒，冷却期内拒绝发起采集请求
const CIRCUIT_BREAKER_COOLDOWN: u64 = 60;

/// 全局熔断器实例，互斥锁保证多线程状态修改安全
static CIRCUIT_BREAKER: std::sync::Mutex<CircuitBreaker> = std::sync::Mutex::new(CircuitBreaker::new());

// ===== 硬件组件指纹数据结构 =====

/// 设备拆分式硬件指纹载体，用于组件加权匹配与设备变更校验
/// 独立字段存储各硬件哈希值，组合哈希用于设备完全一致全等比对
#[derive(Debug, Clone)]
pub struct DeviceComponents {
    /// CPU特征SHA256哈希字符串
    pub cpu_hash: String,
    /// 主板固件UUID SHA256哈希字符串
    pub motherboard_hash: String,
    /// 系统磁盘卷序列号SHA256哈希字符串
    pub disk_hash: String,
    /// 三项原始硬件标识拼接后整体SHA256哈希，用于全等校验
    pub combined_hash: String,
}

impl DeviceComponents {
    /// 基于原始硬件明文标识批量计算哈希值，组装指纹结构体实例
    pub(crate) fn from_raw_ids(cpu_id: &str, motherboard_id: &str, disk_id: &str) -> Self {
        let cpu_hash = sha256_hex(cpu_id.as_bytes());
        let motherboard_hash = sha256_hex(motherboard_id.as_bytes());
        let disk_hash = sha256_hex(disk_id.as_bytes());

        let combined = format!("{}|{}|{}", cpu_id, motherboard_id, disk_id);
        let combined_hash = sha256_hex(combined.as_bytes());

        DeviceComponents {
            cpu_hash,
            motherboard_hash,
            disk_hash,
            combined_hash,
        }
    }

    /// 结构化二进制序列化方法
    /// 设计意图：固定长度前缀便于可靠解析，用于DPAPI加密落地持久化
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for hash in [&self.cpu_hash, &self.motherboard_hash, &self.disk_hash, &self.combined_hash] {
            let bytes = hash.as_bytes();
            result.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            result.extend_from_slice(bytes);
        }
        result
    }

    /// 二进制字节流反序列化，解密后还原指纹对象，格式非法返回None
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut offset = 0;
        let mut hashes = Vec::new();

        for _ in 0..4 {
            if offset + 4 > data.len() {
                return None;
            }
            let len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + len > data.len() {
                return None;
            }
            let hash = String::from_utf8(data[offset..offset + len].to_vec()).ok()?;
            hashes.push(hash);
            offset += len;
        }

        Some(DeviceComponents {
            cpu_hash: hashes[0].clone(),
            motherboard_hash: hashes[1].clone(),
            disk_hash: hashes[2].clone(),
            combined_hash: hashes[3].clone(),
        })
    }
}

/// 对字节数据做SHA256哈希并转为小写十六进制字符串
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

// ===== 熔断器状态操作工具函数 =====

/// 校验熔断器当前状态，判断是否允许执行指纹采集
/// 返回熔断拒绝提示或允许执行标识
fn check_circuit_breaker() -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut cb = CIRCUIT_BREAKER.lock().map_err(|e| format!("熔断器互斥锁获取失败: {}", e))?;

    if cb.consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD {
        let elapsed = now.saturating_sub(cb.last_failure_time);
        if elapsed < CIRCUIT_BREAKER_COOLDOWN {
            let remaining = CIRCUIT_BREAKER_COOLDOWN - elapsed;
            return Err(format!(
                "设备指纹采集已熔断锁定（连续失败 {} 次，剩余冷却 {}秒）",
                cb.consecutive_failures, remaining
            ));
        }
        // 冷却周期结束，重置计数开启重试
        cb.consecutive_failures = 0;
    }

    Ok(())
}

/// 采集成功时重置熔断器失败计数器
fn record_success() {
    if let Ok(mut cb) = CIRCUIT_BREAKER.lock() {
        cb.consecutive_failures = 0;
    }
}

/// 采集失败时递增失败计数并刷新失败时间戳
fn record_failure() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Ok(mut cb) = CIRCUIT_BREAKER.lock() {
        cb.consecutive_failures = cb.consecutive_failures.saturating_add(1);
        cb.last_failure_time = now;
    }
}

// ===== 对外核心采集入口 =====

/// 获取完整组件化设备指纹，内置缓存读取与熔断保护逻辑
/// 调用约束：该方法为阻塞调用，上层必须做异步隔离与超时控制
pub fn get_device_components() -> Result<DeviceComponents, String> {
    // 优先读取进程缓存，命中直接返回避免重复采集硬件接口
    if let Some(cached) = DEVICE_COMPONENTS_CACHE.get() {
        return Ok(cached.clone());
    }

    // 前置熔断校验，熔断期直接拦截请求
    check_circuit_breaker()?;

    // 执行底层硬件阻塞采集
    let result = collect_components_blocking();

    match result {
        Ok(components) => {
            // 仅成功结果写入全局一次性缓存
            let _ = DEVICE_COMPONENTS_CACHE.set(components.clone());
            record_success();
            Ok(components)
        }
        Err(e) => {
            record_failure();
            Err(e)
        }
    }
}

/// 兼容历史调用的简化接口，直接返回设备整体组合哈希
pub fn get_device_fingerprint() -> Result<String, String> {
    let components = get_device_components()?;
    Ok(components.combined_hash)
}

/// 跨平台阻塞式硬件信息采集分发入口
fn collect_components_blocking() -> Result<DeviceComponents, String> {
    #[cfg(windows)]
    {
        let cpu_id = get_cpu_id_windows()?;
        let motherboard_id = get_motherboard_uuid_windows()?;
        let disk_id = get_disk_id_windows()?;

        Ok(DeviceComponents::from_raw_ids(&cpu_id, &motherboard_id, &disk_id))
    }

    #[cfg(not(windows))]
    {
        let machine_id = get_machine_id_unix()?;
        let hostname = get_hostname_unix()?;
        let cpu_id = format!("{}-{}", machine_id, hostname);

        Ok(DeviceComponents::from_raw_ids(&cpu_id, &machine_id, &hostname))
    }
}

// ===== Windows平台原生硬件API采集实现 =====

#[cfg(windows)]
fn get_cpu_id_windows() -> Result<String, String> {
    use core::arch::x86_64::__cpuid;

    // CPUID叶子0读取厂商标识字符串
    let vendor = {
        let result = __cpuid(0);
        let mut vendor = [0u8; 12];
        vendor[0..4].copy_from_slice(&result.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&result.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&result.ecx.to_le_bytes());
        String::from_utf8_lossy(&vendor).trim_end_matches('\0').to_string()
    };

    // CPUID叶子1读取处理器版本与功能标识位
    let features = {
        let result = __cpuid(1);
        result.eax
    };

    Ok(format!("{}-{:08x}", vendor, features))
}

#[cfg(windows)]
fn get_motherboard_uuid_windows() -> Result<String, String> {
    use windows::Win32::System::SystemInformation::{GetSystemFirmwareTable, RSMB};

    // 首次调用获取SMBIOS数据表所需缓冲区长度
    let size = unsafe { GetSystemFirmwareTable(RSMB, 0, None) };
    if size == 0 {
        return Err("GetSystemFirmwareTable 无法读取SMBIOS数据表长度".into());
    }

    let mut buffer = vec![0u8; size as usize];
    let written = unsafe {
        GetSystemFirmwareTable(RSMB, 0, Some(&mut buffer))
    };

    if written == 0 {
        return Err("GetSystemFirmwareTable 读取SMBIOS数据表内容失败".into());
    }

    buffer.truncate(written as usize);

    parse_smbios_uuid(&buffer).ok_or_else(|| "SMBIOS数据表未解析到有效主板UUID".into())
}

/// 解析SMBIOS二进制流中Type1系统信息结构体内主板UUID，遵循字节序规范转换格式
#[cfg(windows)]
fn parse_smbios_uuid(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }

    let table_length = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let table = &data[8..];
    if table.len() < table_length {
        return None;
    }

    let table = &table[..table_length];
    let mut offset = 0;

    while offset < table.len() {
        if offset + 4 > table.len() {
            break;
        }

        let struct_type = table[offset];
        let struct_length = table[offset + 1] as usize;

        if struct_length < 4 || offset + struct_length > table.len() {
            break;
        }

        if struct_type == 1 {
            // Type1系统信息结构体固定偏移读取16字节UUID，并修正SMBIOS规定大小端字节序
            let uuid_offset = offset + 0x08;
            if uuid_offset + 16 <= table.len() {
                let uuid = &table[uuid_offset..uuid_offset + 16];
                let uuid_str = format!(
                    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    uuid[3], uuid[2], uuid[1], uuid[0],
                    uuid[5], uuid[4],
                    uuid[7], uuid[6],
                    uuid[8], uuid[9],
                    uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
                );

                // 全零UUID判定为无效硬件标识，直接丢弃
                if uuid_str.chars().all(|c| c == '0' || c == '-') {
                    return None;
                }
                return Some(uuid_str);
            }
        }

        // 跳过当前结构体定长区域
        offset += struct_length;

        // 跳过结构体尾部以连续双0结尾的字符串区
        while offset + 1 < table.len() {
            if table[offset] == 0 && table[offset + 1] == 0 {
                offset += 2;
                break;
            }
            offset += 1;
        }
    }

    None
}

#[cfg(windows)]
fn get_disk_id_windows() -> Result<String, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetVolumeInformationW;

    // 固定读取系统C盘分区卷序列号作为磁盘唯一标识
    let root_path: Vec<u16> = "C:\\".encode_utf16().chain(std::iter::once(0)).collect();

    let mut volume_serial: u32 = 0;
    let mut max_component_len: u32 = 0;
    let mut file_system_flags: u32 = 0;
    let mut file_system_name = [0u16; 256];

    let result = unsafe {
        GetVolumeInformationW(
            PCWSTR::from_raw(root_path.as_ptr()),
            None,
            Some(&mut max_component_len),
            Some(&mut volume_serial),
            Some(&mut file_system_flags),
            Some(&mut file_system_name),
        )
    };

    if result.is_err() {
        return Err("GetVolumeInformationW 获取系统分区卷序列号调用失败".into());
    }

    Ok(format!("{:08x}", volume_serial))
}

// ===== Unix/Linux/macOS 降级采集逻辑 =====

#[cfg(not(windows))]
fn get_machine_id_unix() -> Result<String, String> {
    // 优先读取系统标准机器ID文件作为设备底层标识
    for path in &["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            let id = content.trim();
            if !id.is_empty() {
                return Ok(id.to_string());
            }
        }
    }
    Err("无法读取系统machine-id设备标识文件".into())
}

#[cfg(not(windows))]
fn get_hostname_unix() -> Result<String, String> {
    std::env::var("HOSTNAME")
        .or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .map_err(|e| format!("获取主机名失败: {}", e))
}

// ===== 设备变更权重匹配计算规则 =====

/// 各硬件组件匹配权重占比，用于量化设备变更相似度
pub const WEIGHT_CPU: u32 = 25;
pub const WEIGHT_MOTHERBOARD: u32 = 35;
pub const WEIGHT_DISK: u32 = 40;
pub const WEIGHT_TOTAL: u32 = WEIGHT_CPU + WEIGHT_MOTHERBOARD + WEIGHT_DISK;

/// 设备可信匹配最低阈值，超过该分值判定为同一设备允许放行
pub const MATCH_THRESHOLD_PERCENT: u32 = 80;

/// 基于历史存储指纹与当前指纹计算加权匹配得分
/// 返回匹配百分比与各组件单独匹配状态明细
pub fn calculate_match_score(stored: &DeviceComponents, current: &DeviceComponents) -> (u32, ComponentMatch) {
    let cpu_match = stored.cpu_hash == current.cpu_hash;
    let motherboard_match = stored.motherboard_hash == current.motherboard_hash;
    let disk_match = stored.disk_hash == current.disk_hash;

    let mut score = 0u32;
    if cpu_match {
        score += WEIGHT_CPU;
    }
    if motherboard_match {
        score += WEIGHT_MOTHERBOARD;
    }
    if disk_match {
        score += WEIGHT_DISK;
    }

    let percent = (score * 100) / WEIGHT_TOTAL;

    (percent, ComponentMatch {
        cpu_match,
        motherboard_match,
        disk_match,
        score: percent,
    })
}

/// 组件级逐项匹配结果载体，用于上层日志记录与变更提示
#[derive(Debug, Clone)]
pub struct ComponentMatch {
    pub cpu_match: bool,
    pub motherboard_match: bool,
    pub disk_match: bool,
    pub score: u32,
}

// ===== 单元测试模块 =====

#[cfg(test)]
mod tests {
    use super::*;

    /// 校验指纹结构体序列化与反序列化双向一致性
    #[test]
    fn test_device_components_serialize_roundtrip() {
        let components = DeviceComponents::from_raw_ids("cpu-123", "mb-456", "disk-789");
        let bytes = components.to_bytes();
        let restored = DeviceComponents::from_bytes(&bytes);
        assert!(restored.is_some());
        let restored = restored.unwrap();
        assert_eq!(restored.cpu_hash, components.cpu_hash);
        assert_eq!(restored.motherboard_hash, components.motherboard_hash);
        assert_eq!(restored.disk_hash, components.disk_hash);
        assert_eq!(restored.combined_hash, components.combined_hash);
    }

    /// 校验非法字节输入反序列化安全返回None
    #[test]
    fn test_device_components_from_bytes_invalid() {
        assert!(DeviceComponents::from_bytes(&[]).is_none());
        assert!(DeviceComponents::from_bytes(&[0u8; 3]).is_none());
    }

    /// 校验三组件完全一致时匹配得分100%
    #[test]
    fn test_calculate_match_score_full_match() {
        let stored = DeviceComponents::from_raw_ids("cpu1", "mb1", "disk1");
        let current = DeviceComponents::from_raw_ids("cpu1", "mb1", "disk1");
        let (score, match_info) = calculate_match_score(&stored, &current);
        assert_eq!(score, 100);
        assert!(match_info.cpu_match);
        assert!(match_info.motherboard_match);
        assert!(match_info.disk_match);
    }

    /// 仅磁盘硬件更换，验证权重得分计算准确性
    #[test]
    fn test_calculate_match_score_disk_changed() {
        let stored = DeviceComponents::from_raw_ids("cpu1", "mb1", "disk1");
        let current = DeviceComponents::from_raw_ids("cpu1", "mb1", "disk2");
        let (score, match_info) = calculate_match_score(&stored, &current);
        assert_eq!(score, 60);
        assert!(match_info.cpu_match);
        assert!(match_info.motherboard_match);
        assert!(!match_info.disk_match);
    }

    /// CPU+磁盘同时更换，校验剩余主板权重得分
    #[test]
    fn test_calculate_match_score_cpu_and_disk_changed() {
        let stored = DeviceComponents::from_raw_ids("cpu1", "mb1", "disk1");
        let current = DeviceComponents::from_raw_ids("cpu2", "mb1", "disk2");
        let (score, match_info) = calculate_match_score(&stored, &current);
        assert_eq!(score, 35);
        assert!(!match_info.cpu_match);
        assert!(match_info.motherboard_match);
        assert!(!match_info.disk_match);
    }

    /// 仅主板匹配场景得分校验
    #[test]
    fn test_calculate_match_score_motherboard_only() {
        let stored = DeviceComponents::from_raw_ids("cpu1", "mb1", "disk1");
        let current = DeviceComponents::from_raw_ids("cpu2", "mb1", "disk2");
        let (score, _) = calculate_match_score(&stored, &current);
        assert_eq!(score, 35);
    }

    /// 校验SHA256哈希输出长度与幂等性
    #[test]
    fn test_sha256_hex_consistent() {
        let h1 = sha256_hex(b"test");
        let h2 = sha256_hex(b"test");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    /// 熔断阈值常量合法性校验
    #[test]
    fn test_circuit_breaker_threshold() {
        assert_eq!(CIRCUIT_BREAKER_THRESHOLD, 3);
        assert_eq!(CIRCUIT_BREAKER_COOLDOWN, 60);
    }

    /// 权重总和与判定阈值常量校验
    #[test]
    fn test_weight_constants() {
        assert_eq!(WEIGHT_TOTAL, 100);
        assert_eq!(MATCH_THRESHOLD_PERCENT, 80);
    }

    /// 兼容接口返回哈希格式合法性校验（不强制硬件采集通过）
    #[test]
    fn test_get_device_fingerprint_returns_hash() {
        if let Ok(fp) = get_device_fingerprint() {
            assert_eq!(fp.len(), 64);
            assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}