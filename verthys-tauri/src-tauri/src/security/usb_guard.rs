/*
 * security/usb_guard.rs — 移动存储安全强化（SECURITY.md 企业级重写版）
 *
 * 用户需求（四、移动存储安全强化）：
 *   1. U 盘/移动硬盘接入时，读取磁盘序列号（IOCTL_STORAGE_QUERY_PROPERTY）并做哈希记录。
 *   2. 若后续插入的盘体序列号不一致但卷标相同，判定为克隆外设，拒绝加载并告警。
 *   3. 影子休眠策略：强制拔出外设时，索引进入"影子休眠"，加密驻留内存
 *      （普通 30 分钟，高安全 5 分钟）；重新接入且 TxID 匹配则毫秒级无缝恢复；
 *      超时则自动零化（3 轮覆写 0x00→0xFF→0x00）。
 *
 * SECURITY.md 修复要点：
 *   1. 实施基于持久化白名单的显式信任模型 — 废除"首次自动注册"逻辑，
 *      UsbRegistry 仅包含管理员预先授权的卷标-哈希对，未注册设备一律拒绝
 *   2. 使用 RAII 安全擦除容器 — SecuredBuffer 封装 Zeroizing<Vec<u8>>，
 *      Drop 时自动 zeroize，消除 purge 窗口期
 *   3. 按规范正确处理序列号字符串 — 仅 trim_end 空格和 null，保留前导字符
 *   4. 采用两步 IOCTL 动态分配缓冲区 — 先查询所需大小再分配，兼容所有设备
 *   5. 序列号哈希加盐 — HMAC-SHA256(salt, serial)，盐值 DPAPI 加密存储
 *   6. 增加注册表容量限制与审计 — 上限 100 条，超限拒绝并告警
 *   7. 影子休眠增加自动定时器 — 内部专用线程到期自动 purge
 *
 * 设计要点：
 *   - 仅存储序列号的 HMAC-SHA256 哈希（加盐），永不保存原始序列号
 *   - 盘符 → 物理磁盘号映射（IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS），
 *     再打开 \\.\PhysicalDriveN 查询 STORAGE_DEVICE_DESCRIPTOR
 *   - SecuredBuffer 使用 zeroize crate 自动安全擦除，替代手动 volatile 覆写
 *   - ShadowSleep 内部启动专用定时器线程，到期自动 purge
 *   - 非 Windows 平台空实现（返回错误），保证跨平台编译通过
 */

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/* ================================================================== *
 * Windows 平台：常量与自定义结构体（windows crate 未导出这些 IOCTL 结构） *
 * ================================================================== */

#[cfg(target_os = "windows")]
const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;

/// IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS：获取卷所在物理磁盘号
#[cfg(target_os = "windows")]
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x00560000;

/// STORAGE_PROPERTY_ID::StorageDeviceProperty
#[cfg(target_os = "windows")]
const STORAGE_DEVICE_PROPERTY: u32 = 0;

/// STORAGE_QUERY_TYPE::PropertyStandardQuery
#[cfg(target_os = "windows")]
const PROPERTY_STANDARD_QUERY: u32 = 0;

/// GENERIC_READ 访问掩码（0x80000000）
#[cfg(target_os = "windows")]
const GENERIC_READ: u32 = 0x80000000;

/// STORAGE_PROPERTY_QUERY（windows crate 未导出，需自定义）
#[cfg(target_os = "windows")]
#[repr(C)]
struct StoragePropertyQuery {
    property_id: u32,
    query_type: u32,
    additional_parameters: [u8; 1],
}

/// STORAGE_DEVICE_DESCRIPTOR（windows crate 未导出，需自定义）
/// 固定部分布局（与 Windows SDK ntddstor.h 一致）：
///   +0  Version(u32)            +4  Size(u32)
///   +8  DeviceType(u8)          +9  RemovableMedia(u8)
///   +10 CommandQueueing(u8)     +11 BusType(u8, STORAGE_BUS_TYPE)
///   +12 VendorIdOffset(u32)     +16 ProductIdOffset(u32)
///   +20 ProductRevisionOffset(u32)  +24 SerialNumberOffset(u32)
///   +28 RawPropertiesLength(u32)    +32 RawDeviceProperties[u8;1]
/// 序列号为以偏移量指向的 null 结尾 ASCII 字串（偏移相对描述符首字节）。
#[cfg(target_os = "windows")]
#[repr(C)]
struct StorageDeviceDescriptor {
    version: u32,
    size: u32,
    device_type: u8,
    removable_media: u8,
    command_queueing: u8,
    bus_type: u8,
    vendor_id_offset: u32,
    product_id_offset: u32,
    product_revision_offset: u32,
    serial_number_offset: u32,
    raw_properties_length: u32,
    raw_device_properties: [u8; 1],
}

/// VOLUME_DISK_EXTENTS：将盘符映射到物理磁盘号
/// 仅包含固定头部 + 1 个 extent，动态分配时按所需大小分配
#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct DiskExtent {
    disk_number: u32,
    _padding: u32,
    starting_offset: i64,
    extent_length: i64,
}

/// VOLUME_DISK_EXTENTS 固定头部（不含 extents 数组）
#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct VolumeDiskExtentsHeader {
    number_of_disk_extents: u32,
    _padding: u32,
}

/* ================================================================== *
 * SECURITY.md 第 2 项：SecuredBuffer — RAII 安全擦除容器                  *
 *                                                                        *
 *  封装 Zeroizing<Vec<u8>>，Drop 时自动 zeroize，消除 purge 窗口期。     *
 *  替代手动 volatile 覆写循环，无论正常退出还是 panic 展开，敏感数据     *
 *  都在内存被释放前已不可读。                                            *
 * ================================================================== */

/// RAII 安全擦除缓冲区
///
/// 内部使用 `Zeroizing<Vec<u8>>`，在 Drop 时自动调用 `zeroize()` 清零内存。
/// 用于封装影子休眠的加密索引等敏感数据，确保无论正常退出还是 panic，
/// 敏感数据都在内存释放前被安全擦除。
pub struct SecuredBuffer(Zeroizing<Vec<u8>>);

impl SecuredBuffer {
    #![allow(dead_code)]
    /// 从 Vec<u8> 创建 SecuredBuffer
    pub fn new(data: Vec<u8>) -> Self {
        Self(Zeroizing::new(data))
    }

    /// 返回内部字节切片的引用
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// 返回长度
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 消费 SecuredBuffer，返回内部的 Vec<u8>
    ///
    /// 注意：返回的 Vec 不再受 Zeroizing 保护，调用方应自行确保安全擦除，
    /// 或尽快编码后丢弃。原始 Zeroizing 在 Drop 时仍会 zeroize 其内部内存。
    pub fn into_vec(self) -> Vec<u8> {
        // Zeroizing 实现 Deref<Target=Vec<u8>>，clone 后原始 Zeroizing 在 Drop 时 zeroize
        self.0.to_vec()
    }
}

/* ================================================================== *
 * 1. USB 设备序列号读取（SECURITY.md 第 3/4/5 项）                       *
 * ================================================================== */

/// 读取磁盘序列号并计算加盐 HMAC-SHA256 哈希
///
/// SECURITY.md 修复要点：
///   - 第 3 项：仅 trim_end 空格和 null 字符，保留前导字符
///   - 第 4 项：两步 IOCTL 动态分配缓冲区（先查询所需大小再分配）
///   - 第 5 项：使用 HMAC-SHA256(salt, serial) 替代纯 SHA-256，
///              盐值由调用方传入（DPAPI 加密存储于应用配置目录）
///
/// 流程：
///   1. 盘符 → 卷设备句柄 → IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS → 物理磁盘号
///   2. 打开 \\.\PhysicalDriveN → IOCTL_STORAGE_QUERY_PROPERTY(StorageDeviceProperty)
///   3. 从 STORAGE_DEVICE_DESCRIPTOR.SerialNumberOffset 读取 null 结尾 ASCII 序列号
///   4. trim_end 空格和 null 字符（SECURITY.md 第 3 项）
///   5. HMAC-SHA256(salt, serial) → 返回 hex 字串
///   6. 原始序列号在函数栈上即被丢弃（短生命周期）
#[cfg(target_os = "windows")]
pub fn read_device_serial(drive_letter: char, salt: &[u8]) -> Result<String, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    // 1. 盘符 → 物理磁盘号
    let disk_number = get_physical_disk_number(drive_letter)?;

    // 2. 打开 \\.\PhysicalDriveN
    let physical_path: Vec<u16> = format!("\\\\.\\PhysicalDrive{}", disk_number)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(physical_path.as_ptr()),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| format!("打开物理磁盘失败: {}", e))?;

    // 3. IOCTL_STORAGE_QUERY_PROPERTY 查询设备属性
    let query = StoragePropertyQuery {
        property_id: STORAGE_DEVICE_PROPERTY,
        query_type: PROPERTY_STANDARD_QUERY,
        additional_parameters: [0],
    };

    // SECURITY.md 第 4 项：两步 IOCTL 动态分配缓冲区
    // 步骤 1：传入空缓冲区查询所需大小
    let mut required_size: u32 = 0;
    let _ = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const StoragePropertyQuery as *const std::ffi::c_void),
            std::mem::size_of::<StoragePropertyQuery>() as u32,
            None, // 无输出缓冲区
            0,
            Some(&mut required_size as *mut u32),
            None,
        )
    };

    // required_size 为 0 时回退到默认大小（极罕见，某些驱动不支持大小查询）
    let out_size = if required_size == 0 {
        8192u32
    } else {
        // 确保至少能容纳固定头部
        let min_size = std::mem::size_of::<StorageDeviceDescriptor>() as u32;
        required_size.max(min_size)
    };

    // 步骤 2：分配精确大小的缓冲区并执行实际查询
    let mut out_buffer: Vec<u8> = vec![0u8; out_size as usize];
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const StoragePropertyQuery as *const std::ffi::c_void),
            std::mem::size_of::<StoragePropertyQuery>() as u32,
            Some(out_buffer.as_mut_ptr() as *mut std::ffi::c_void),
            out_buffer.len() as u32,
            Some(&mut bytes_returned as *mut u32),
            None,
        )
    };

    // 无论查询成功与否，句柄必须关闭
    let _ = unsafe { CloseHandle(handle) };

    result.map_err(|e| format!("IOCTL_STORAGE_QUERY_PROPERTY 查询失败: {}", e))?;

    if (bytes_returned as usize) < std::mem::size_of::<StorageDeviceDescriptor>() {
        return Err("存储设备描述符返回数据不足".to_string());
    }

    // 4. 解析 SerialNumberOffset
    let descriptor: &StorageDeviceDescriptor =
        unsafe { &*(out_buffer.as_ptr() as *const StorageDeviceDescriptor) };

    let serial_offset = descriptor.serial_number_offset as usize;
    if serial_offset == 0 {
        return Err("该设备未提供序列号（SerialNumberOffset=0）".to_string());
    }
    if serial_offset >= bytes_returned as usize {
        return Err("序列号偏移超出返回数据范围".to_string());
    }

    // 5. 读取 null 结尾的 ASCII 序列号
    let returned = bytes_returned as usize;
    let serial_bytes: Vec<u8> = out_buffer[serial_offset..returned]
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .collect();

    if serial_bytes.is_empty() {
        return Err("序列号为空".to_string());
    }

    // SECURITY.md 第 3 项：仅移除尾部空格和 null 字符，保留前导字符
    // USB 规范中序列号字段为右填充空格，正确处理是 trim_end 而非 trim
    let serial = String::from_utf8_lossy(&serial_bytes)
        .trim_end_matches(|c: char| c.is_whitespace() || c == '\0')
        .to_string();
    if serial.is_empty() {
        return Err("序列号清理后为空".to_string());
    }

    // 6. SECURITY.md 第 5 项：HMAC-SHA256(salt, serial) 加盐哈希
    // 使用安装唯一盐值，即使数据库泄露也无法进行设备关联（彩虹表攻击无效）
    let hash = crate::util::crypto::hmac_sign(salt, serial.as_bytes());
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(hex)
}

/// 盘符 → 物理磁盘号映射
///
/// SECURITY.md 第 4 项：两步 IOCTL 动态分配缓冲区
/// 先查询所需大小，再分配精确缓冲区，兼容多分区动态卷。
#[cfg(target_os = "windows")]
fn get_physical_disk_number(drive_letter: char) -> Result<u32, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    let letter = drive_letter.to_ascii_uppercase();
    if !letter.is_ascii_alphabetic() {
        return Err(format!("无效的盘符: {}", drive_letter));
    }

    let volume_path: Vec<u16> = format!("\\\\.\\{}:", letter)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(volume_path.as_ptr()),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| format!("打开卷设备失败: {}", e))?;

    // SECURITY.md 第 4 项：两步 IOCTL — 先查询所需缓冲区大小
    let mut required_size: u32 = 0;
    let _ = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            None,
            0,
            None, // 无输出缓冲区，仅查询大小
            0,
            Some(&mut required_size as *mut u32),
            None,
        )
    };

    // 所需大小为 0 时回退到默认（单 extent 大小）
    let header_size = std::mem::size_of::<VolumeDiskExtentsHeader>() as u32;
    let extent_size = std::mem::size_of::<DiskExtent>() as u32;
    let default_size = header_size + extent_size; // 单 extent

    let buf_size = if required_size == 0 {
        default_size
    } else {
        required_size.max(default_size)
    };

    // 分配动态缓冲区
    let mut extents_buf: Vec<u8> = vec![0u8; buf_size as usize];
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            None,
            0,
            Some(extents_buf.as_mut_ptr() as *mut std::ffi::c_void),
            extents_buf.len() as u32,
            Some(&mut bytes_returned as *mut u32),
            None,
        )
    };

    let _ = unsafe { CloseHandle(handle) };

    result.map_err(|e| format!("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 查询失败: {}", e))?;

    if bytes_returned == 0 {
        return Err("卷磁盘扩展信息返回数据为空".to_string());
    }

    // 解析头部
    if (bytes_returned as usize) < std::mem::size_of::<VolumeDiskExtentsHeader>() {
        return Err("卷磁盘扩展信息返回数据不足".to_string());
    }

    let header: &VolumeDiskExtentsHeader =
        unsafe { &*(extents_buf.as_ptr() as *const VolumeDiskExtentsHeader) };

    if header.number_of_disk_extents == 0 {
        return Err("未找到磁盘扩展信息".to_string());
    }

    // 解析第一个 extent（取第一个物理磁盘号）
    let extent_offset = std::mem::size_of::<VolumeDiskExtentsHeader>();
    if extent_offset + std::mem::size_of::<DiskExtent>() > bytes_returned as usize {
        return Err("磁盘扩展信息数据不完整".to_string());
    }

    let extent: &DiskExtent = unsafe {
        &*(extents_buf.as_ptr().add(extent_offset) as *const DiskExtent)
    };

    Ok(extent.disk_number)
}

/// 非 Windows 平台：空实现
#[cfg(not(target_os = "windows"))]
pub fn read_device_serial(_drive_letter: char, _salt: &[u8]) -> Result<String, String> {
    Err("read_device_serial 仅支持 Windows 平台".to_string())
}

/* ================================================================== *
 * 2. 克隆外设检测（SECURITY.md 第 1/6 项）                               *
 *                                                                        *
 *  SECURITY.md 第 1 项：废除"首次自动注册"逻辑                            *
 *    - UsbRegistry 仅包含管理员预先授权的卷标-哈希对                      *
 *    - 未注册设备一律拒绝（返回 Unknown），触发安全审计事件              *
 *  SECURITY.md 第 6 项：注册表容量限制（默认 100 条）                     *
 *    - 达到上限时拒绝新注册并记录告警                                    *
 * ================================================================== */

/// USB 注册表容量上限（SECURITY.md 第 6 项）
const USB_REGISTRY_MAX_ENTRIES: usize = 100;

/// 克隆检测结果（SECURITY.md 第 1 项：废除"首次自动注册"）
///
/// 替代原 bool 返回值，明确区分三种状态：
///   - Trusted：卷标已知且序列号哈希匹配 → 合法设备
///   - Clone：卷标已知但序列号哈希不匹配 → 克隆外设
///   - Unknown：卷标未知 → 未注册设备，拒绝访问并触发审计
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum CloneCheckResult {
    /// 卷标已知且序列号哈希匹配 — 合法设备
    Trusted,
    /// 卷标已知但序列号哈希不匹配 — 克隆外设
    Clone,
    /// 卷标未知 — 未注册设备（SECURITY.md：拒绝并触发审计事件）
    Unknown,
}

/// USB 设备注册表：维护"卷标 → 序列号哈希"映射，用于克隆外设检测
///
/// SECURITY.md 第 1 项：基于持久化白名单的显式信任模型
///   - 废除"首次自动注册"逻辑
///   - 仅包含管理员预先授权的卷标-哈希对
///   - 未注册设备一律拒绝（返回 CloneCheckResult::Unknown）
///   - 所有注册表内容从 DPAPI 加密的持久化存储加载
///
/// SECURITY.md 第 6 项：注册表容量限制
///   - 最大 100 条，达到上限时拒绝新注册并记录告警
pub struct UsbRegistry {
    /// 卷标 → 序列号哈希（HMAC-SHA256 hex）
    known_devices: HashMap<String, String>,
    /// 最大条目数（默认 USB_REGISTRY_MAX_ENTRIES）
    max_entries: usize,
}

impl UsbRegistry {
    #![allow(dead_code)]
    pub fn new() -> Self {
        Self {
            known_devices: HashMap::new(),
            max_entries: USB_REGISTRY_MAX_ENTRIES,
        }
    }

    /// 注册已知设备（卷标 + 序列号哈希）
    ///
    /// SECURITY.md 第 6 项：注册表容量限制
    /// 返回 Ok(()) 表示注册成功，Err(msg) 表示已达容量上限。
    pub fn register_device(&mut self, volume_label: &str, serial_hash: &str) -> Result<(), String> {
        if self.known_devices.len() >= self.max_entries && !self.known_devices.contains_key(volume_label) {
            log::warn!(
                "[usb_guard] SECURITY.md 第 6 项：USB 注册表已达上限 ({} 条)，\
                 拒绝注册新设备: label={}",
                self.max_entries,
                volume_label
            );
            return Err(format!(
                "USB 注册表已达上限 ({} 条)，拒绝注册新设备",
                self.max_entries
            ));
        }
        self.known_devices
            .insert(volume_label.to_string(), serial_hash.to_string());
        Ok(())
    }

    /// 检测克隆外设
    ///
    /// SECURITY.md 第 1 项：废除"首次自动注册"逻辑
    ///   - 卷标已知且序列号哈希匹配 → CloneCheckResult::Trusted
    ///   - 卷标已知但序列号哈希不匹配 → CloneCheckResult::Clone
    ///   - 卷标未知 → CloneCheckResult::Unknown（拒绝访问，不自动注册）
    pub fn check_clone(&self, volume_label: &str, serial_hash: &str) -> CloneCheckResult {
        match self.known_devices.get(volume_label) {
            Some(existing_hash) => {
                if crate::util::crypto::ct_eq(
                    existing_hash.as_bytes(),
                    serial_hash.as_bytes(),
                ) {
                    // 合法设备：卷标 + 序列号哈希双因子匹配
                    CloneCheckResult::Trusted
                } else {
                    // 克隆外设：卷标相同但盘体序列号不一致
                    CloneCheckResult::Clone
                }
            }
            None => {
                // SECURITY.md 第 1 项：卷标未知 — 拒绝访问，不自动注册
                CloneCheckResult::Unknown
            }
        }
    }

    /// 检查卷标是否已注册
    pub fn is_registered(&self, volume_label: &str) -> bool {
        self.known_devices.contains_key(volume_label)
    }

    /// 移除已注册设备
    pub fn unregister_device(&mut self, volume_label: &str) -> bool {
        self.known_devices.remove(volume_label).is_some()
    }

    /// 清空所有已注册设备
    pub fn clear(&mut self) {
        self.known_devices.clear();
    }

    /// 已注册设备数量
    pub fn len(&self) -> usize {
        self.known_devices.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.known_devices.is_empty()
    }

    /// SECURITY.md 第 1 项：导出已注册设备（用于 DPAPI 加密持久化）
    pub fn export_devices(&self) -> Vec<(String, String)> {
        self.known_devices
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// SECURITY.md 第 1 项：导入已注册设备（从 DPAPI 解密后恢复）
    ///
    /// 合并持久化的设备到当前注册表（幂等：不产生重复项）。
    /// 超出容量上限的条目被跳过。
    pub fn import_devices(&mut self, devices: &[(String, String)]) {
        for (label, hash) in devices {
            if self.known_devices.len() >= self.max_entries
                && !self.known_devices.contains_key(label)
            {
                log::warn!(
                    "[usb_guard] 导入设备时达到容量上限，跳过: label={}",
                    label
                );
                break;
            }
            self.known_devices
                .insert(label.clone(), hash.clone());
        }
    }
}

impl Default for UsbRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/* ================================================================== *
 * 3. 影子休眠管理（SECURITY.md 第 2/7 项）                               *
 *                                                                        *
 *  SECURITY.md 第 2 项：使用 RAII 安全擦除容器                            *
 *    - 加密索引封装在 SecuredBuffer（Zeroizing<Vec<u8>>）中              *
 *    - purge 仅需丢弃容器，Drop 时自动 zeroize                           *
 *    - 移除手动 volatile 覆写循环                                       *
 *                                                                        *
 *  SECURITY.md 第 7 项：影子休眠增加自动定时器                            *
 *    - 内部启动专用线程，到期自动执行 purge                              *
 *    - 不再依赖外部调用 try_recover 检查超时                             *
 * ================================================================== */

/// 影子休眠内部状态（受 Arc<Mutex> 保护，供定时器线程访问）
struct ShadowSleepInner {
    /// 加密的内存索引快照（SecuredBuffer，Drop 时自动 zeroize）
    encrypted_index: Option<SecuredBuffer>,
    /// 事务 ID，用于恢复时匹配
    txid: u64,
    /// 休眠截止时间
    shadow_deadline: Option<Instant>,
}

/// 影子休眠：外设强制拔出后，加密索引驻留内存一段时间，支持毫秒级无缝恢复
///
/// SECURITY.md 修复要点：
///   - 第 2 项：加密索引使用 SecuredBuffer（Zeroizing），Drop 时自动 zeroize
///   - 第 7 项：内部专用线程到期自动 purge，不依赖外部轮询
///
/// 字段：
///   - inner: Arc<Mutex<ShadowSleepInner>> — 共享状态（定时器线程可访问）
///   - timer_handle: 定时器线程句柄
///   - timer_stop: 定时器停止标志
pub struct ShadowSleep {
    /// 共享内部状态（Arc<Mutex> 允许定时器线程独立访问）
    inner: Arc<Mutex<ShadowSleepInner>>,
    /// 定时器线程句柄（None=无活跃定时器）
    timer_handle: Option<JoinHandle<()>>,
    /// 定时器停止标志（true 时定时器线程退出）
    timer_stop: Arc<AtomicBool>,
}

impl ShadowSleep {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ShadowSleepInner {
                encrypted_index: None,
                txid: 0,
                shadow_deadline: None,
            })),
            timer_handle: None,
            timer_stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 进入影子休眠
    ///
    /// 参数：
    ///   - encrypted_index：加密的内存索引快照
    ///   - txid：事务 ID（恢复时需匹配）
    ///   - timeout_min：超时分钟数（普通模式 30 分钟，高安全模式 5 分钟）
    ///
    /// SECURITY.md 第 2 项：加密索引封装在 SecuredBuffer 中
    /// SECURITY.md 第 7 项：启动内部定时器线程，到期自动 purge
    ///
    /// 若已有休眠数据，先 purge 旧的（避免敏感数据泄露堆积）
    pub fn enter_shadow_sleep(&mut self, encrypted_index: Vec<u8>, txid: u64, timeout_min: u64) {
        // 若已有休眠数据，先 purge 旧的（避免泄露）
        self.stop_timer_and_join();
        self.purge_internal();

        // 写入新的休眠数据
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.encrypted_index = Some(SecuredBuffer::new(encrypted_index));
            inner.txid = txid;
            inner.shadow_deadline = Some(Instant::now() + Duration::from_secs(timeout_min * 60));
        }

        // SECURITY.md 第 7 项：启动自动 purge 定时器线程
        self.timer_stop.store(false, Ordering::SeqCst);
        let inner_clone = self.inner.clone();
        let stop_clone = self.timer_stop.clone();
        self.timer_handle = thread::Builder::new()
            .name("verthys-shadow-timer".into())
            .spawn(move || {
                shadow_timer_loop(inner_clone, stop_clone);
            })
            .ok();
    }

    /// 尝试恢复
    ///
    /// 返回值：
    ///   - Some(Vec<u8>)：txid 匹配且未超时 → 返回加密索引，清除休眠状态
    ///   - None：已超时（已 purge）/ txid 不匹配 / 未处于影子休眠
    pub fn try_recover(&mut self, txid: u64) -> Option<Vec<u8>> {
        // 停止定时器（恢复成功或失败都不再需要定时器）
        self.stop_timer_and_join();

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let deadline = match inner.shadow_deadline {
            Some(d) => d,
            None => return None, // 未处于影子休眠
        };

        // 超时检查：超时则自动零化
        if Instant::now() > deadline {
            inner.encrypted_index = None;
            inner.txid = 0;
            inner.shadow_deadline = None;
            return None;
        }

        // txid 匹配检查：匹配则取出加密索引并清除休眠状态
        if txid == inner.txid {
            let buf = inner.encrypted_index.take().map(|sb| sb.into_vec());
            inner.txid = 0;
            inner.shadow_deadline = None;
            buf
        } else {
            // txid 不匹配：保持休眠状态，等待正确 txid
            // 重新启动定时器（因为停止了）
            drop(inner);
            self.restart_timer();
            None
        }
    }

    /// 安全擦除加密索引
    ///
    /// SECURITY.md 第 2 项：使用 SecuredBuffer（Zeroizing），Drop 时自动 zeroize
    /// 移除手动 volatile 覆写循环，消除 take() 与覆写之间的窗口期
    pub fn purge(&mut self) {
        self.stop_timer_and_join();
        self.purge_internal();
    }

    /// 内部 purge（不停止定时器，供 enter_shadow_sleep / try_recover 调用）
    fn purge_internal(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // SecuredBuffer 的 Drop 会自动 zeroize
        inner.encrypted_index = None;
        inner.txid = 0;
        inner.shadow_deadline = None;
    }

    /// 查询是否处于影子休眠
    pub fn is_in_shadow_sleep(&self) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.encrypted_index.is_some() && inner.shadow_deadline.is_some()
    }

    /// 第 13.2.8 项：查询当前影子休眠的事务 ID（真实 txid）
    ///
    /// 返回当前影子休眠的 txid；未处于影子休眠时返回 0。
    pub fn current_txid(&self) -> u64 {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.encrypted_index.is_some() && inner.shadow_deadline.is_some() {
            inner.txid
        } else {
            0
        }
    }

    /// 停止定时器并等待线程退出（带 2 秒超时）
    fn stop_timer_and_join(&mut self) {
        self.timer_stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.timer_handle.take() {
            // 等待定时器线程退出（最多 2 秒）
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if handle.is_finished() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                // 线程未退出（极罕见），泄漏句柄以防 UAF
                log::warn!("[shadow_sleep] 定时器线程 2s 内未退出，泄漏句柄");
            }
        }
    }

    /// 重新启动定时器（try_recover txid 不匹配时调用）
    fn restart_timer(&mut self) {
        let deadline = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            match inner.shadow_deadline {
                Some(d) => d,
                None => return,
            }
        };
        self.timer_stop.store(false, Ordering::SeqCst);
        let inner_clone = self.inner.clone();
        let stop_clone = self.timer_stop.clone();
        self.timer_handle = thread::Builder::new()
            .name("verthys-shadow-timer".into())
            .spawn(move || {
                shadow_timer_loop_with_deadline(inner_clone, stop_clone, deadline);
            })
            .ok();
    }
}

impl Default for ShadowSleep {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ShadowSleep {
    fn drop(&mut self) {
        // 停止定时器线程并 purge 数据
        self.stop_timer_and_join();
        self.purge_internal();
    }
}

/* ================================================================== *
 *  SECURITY.md 第 7 项：影子休眠自动定时器线程                            *
 *                                                                        *
 *  专用线程定期检查截止时间，到期自动锁定 inner 并执行 purge。            *
 *  不再依赖外部调用 try_recover 检查超时，避免敏感数据驻留超时。          *
 * ================================================================== */

/// 定时器线程主循环（从 inner 中读取 deadline）
fn shadow_timer_loop(inner: Arc<Mutex<ShadowSleepInner>>, stop: Arc<AtomicBool>) {
    // 读取截止时间
    let deadline = {
        let inner = inner.lock().unwrap_or_else(|e| e.into_inner());
        match inner.shadow_deadline {
            Some(d) => d,
            None => return, // 无截止时间，直接退出
        }
    };
    shadow_timer_loop_with_deadline(inner, stop, deadline);
}

/// 定时器线程主循环（使用指定的 deadline）
fn shadow_timer_loop_with_deadline(
    inner: Arc<Mutex<ShadowSleepInner>>,
    stop: Arc<AtomicBool>,
    deadline: Instant,
) {
    loop {
        // 检查停止标志
        if stop.load(Ordering::SeqCst) {
            return;
        }

        // 检查是否已超时
        let now = Instant::now();
        if now >= deadline {
            // 到期：锁定 inner 并执行 purge
            let mut inner = inner.lock().unwrap_or_else(|e| e.into_inner());
            // 再次检查是否仍有数据（可能已被 try_recover/purge 取走）
            if inner.encrypted_index.is_some() {
                log::info!(
                    "[shadow_sleep] SECURITY.md 第 7 项：定时器到期，自动 purge 加密索引"
                );
                // SecuredBuffer 的 Drop 会自动 zeroize
                inner.encrypted_index = None;
                inner.txid = 0;
                inner.shadow_deadline = None;
            }
            return;
        }

        // 计算剩余时间，最多睡眠 1 秒
        let remaining = deadline - now;
        let sleep_dur = std::cmp::min(remaining, Duration::from_secs(1));
        std::thread::sleep(sleep_dur);
    }
}
