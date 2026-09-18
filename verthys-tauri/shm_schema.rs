/*
 * shm_schema.rs — 共享内存 (SHM) 协议契约（worker ↔ 主进程同源定义）
 *
 *    "" 第 14.1 项 / 第 14.4 项
 *
 * ★ 同源定义策略（替代 bindgen 解析 C 头文件）：
 *   经源码核验，verthys-worker 为 Rust crate（非 C 源码），主进程与 worker 均为 Rust。
 *   采用 `include!()` 宏方式使两 crate 共享同一份源文件，达到与 bindgen 同等的
 *   "单一定义源"效果，且避免 C FFI 边界与跨语言结构体布局风险。
 *
 *   - 主进程：`infrastructure/shm_schema.rs` 通过 `include!` 引入本文件
 *   - worker：`shm_schema.rs` 通过 `include!` 引入本文件
 *   - 修改本文件后，两 crate 同步重编译，根治版本分化
 *
 * 编译期校验（第 14.4 项）：
 *   - `const_assert_eq!(SHM_HEADER_SIZE, size_of::<ShmHeader>())`
 *   - `const_assert_eq!(SHM_ENTRY_SIZE, size_of::<ShmEntry>())`
 *   - `const_assert_eq!(SHM_SUMMARY_ENTRY_SIZE, size_of::<ShmSummaryEntry>())`
 *
 * 头部布局（64 字节）：
 *   [0..4]   magic: u32
 *   [4..8]   version: u32
 *   [8..16]  record_count: u64
 *   [16..24] total_name_bytes: u64
 *   [24..32] total_data_bytes: u64
 *   [32..36] exhausted: u32
 *   [36..40] error_code: u32
 *   [40..64] reserved (24 字节，全零保留扩展)
 *
 * 全量扫描索引条目布局（40 字节/条）：
 *   [0..8]   lid: u64
 *   [8..12]  rtype: u32
 *   [12..16] name_len: u32
 *   [16..24] data_len: u64
 *   [24..32] name_offset: u64  (相对共享内存起始的绝对偏移)
 *   [32..40] data_offset: u64
 *
 * 摘要扫描索引条目布局（80 字节/条，8 字节对齐）：
 *   [0..8]   lid: u64
 *   [8..12]  rtype: u32
 *   [12..16] name_len: u32
 *   [16..24] data_size: u64
 *   [24..32] physical_offset: u64
 *   [32..40] name_offset: u64
 *   [40..72] merkle_leaf: [u8; 32]
 *   [72..80] created_time: u64  ★ Phase 2G
 *
 * CI 红线：
 *   - 严禁在本文件中引入任何外部 crate（保持 include! 上下文纯净）
 *   - 严禁修改已发布版本的字段偏移（仅可扩展 reserved 区）
 *   - 修改布局必须同步递增 SHM_VERSION
 */

// SHM 协议契约（include! 引入，无外部依赖）
//
// 本文件由主进程 `infrastructure/shm_schema.rs` 与 worker `shm_schema.rs`
// 共同 `include!`，确保两端结构体布局与常量严格一致。
//
// 注意：本文件通过 include! 宏引入，不能使用 `//!` 内部文档注释
//       和 `#![...]` 内部属性（仅 crate/module 根可用）。
//       dead_code 警告由各 include 站点按需添加 #[allow(dead_code)] 抑制。

use std::mem::size_of;

// ===== 全量扫描 SHM 常量 =====
/// 共享内存魔数 "VSMM"（全量扫描，0x56='V' 0x53='S' 0x4D='M' 0x4D='M'）
pub const SHM_MAGIC: u32 = 0x56534D4D;
/// SHM 协议版本（修改布局时递增）
pub const SHM_VERSION: u32 = 1;
/// 头部 64 字节
pub const SHM_HEADER_SIZE: usize = 64;
/// 每条全量记录索引 40 字节
pub const SHM_ENTRY_SIZE: usize = 40;
/// 默认共享内存大小 8MB
pub const SHM_DEFAULT_SIZE: usize = 8 * 1024 * 1024;
/// 共享内存最大大小（reader 边界校验用）
pub const SHM_MAX_SIZE: usize = 8 * 1024 * 1024;

// ===== 摘要扫描 SHM 常量 =====
/// 摘要扫描共享内存魔数 "VSUM"（区别于全量扫描 VSMM）
pub const SHM_SUMMARY_MAGIC: u32 = 0x5653554D;
/// 每条摘要记录索引 80 字节（含 merkle_leaf 内联 + created_time）
pub const SHM_SUMMARY_ENTRY_SIZE: usize = 80;
/// 摘要扫描默认共享内存大小 4MB
pub const SHM_SUMMARY_DEFAULT_SIZE: usize = 4 * 1024 * 1024;
/// 摘要扫描共享内存最大大小（reader 边界校验用）
pub const SHM_SUMMARY_MAX_SIZE: usize = 4 * 1024 * 1024;

// ===== 编译期常量断言宏（等价 const_assert_eq!）=====
/// 编译期常量相等断言（无需外部 crate）
///
/// 利用 Rust 1.65+ 在 const 上下文支持 `panic!` 的特性，
/// 在 const 块中直接断言，失败时编译错误。
///
/// 注意：const fn 中仅支持 `panic!("字面量")` 形式，不支持格式化参数。
/// 失败时编译器会给出 E0080 错误并定位到调用处，足以定位不匹配的常量。
const fn const_assert_eq(a: usize, b: usize) {
    // Rust 1.65+ 支持 const 上下文中的 panic（仅字面量形式）
    // 不等时 panic 触发编译错误（E0080: evaluation of constant value failed）
    if a != b {
        panic!("const_assert_eq failed: layout size mismatch");
    }
}

/// SHM 头部结构（64 字节，#[repr(C)] 保证 ABI 稳定）
///
/// 主进程与 worker 通过此结构解析头部字段，
/// 替代裸指针偏移读取（提升可读性 + 编译期类型校验）。
///
/// 注意：使用 `#[repr(C)]`（非 packed），所有字段自然对齐无 padding。
/// 编译期 `const_assert_eq(SHM_HEADER_SIZE, size_of::<ShmHeader>())` 确保
/// 任何字段修改若引入 padding 将触发编译错误。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmHeader {
    /// 魔数（SHM_MAGIC 或 SHM_SUMMARY_MAGIC）
    pub magic: u32,
    /// 协议版本
    pub version: u32,
    /// 本批记录数
    pub record_count: u64,
    /// 名称区总字节数
    pub total_name_bytes: u64,
    /// 数据区总字节数（摘要扫描恒为 0）
    pub total_data_bytes: u64,
    /// 是否已遍历结束（0/1）
    pub exhausted: u32,
    /// 错误码（worker 写入，主进程读取）
    pub error_code: u32,
    /// 保留扩展区（24 字节，全零）
    pub reserved: [u8; 24],
}

/// 全量扫描索引条目（40 字节，#[repr(C)] 保证 ABI 稳定）
///
/// 字段自然对齐无 padding，编译期 size_of 校验确保布局稳定。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmEntry {
    pub lid: u64,
    pub rtype: u32,
    pub name_len: u32,
    pub data_len: u64,
    pub name_offset: u64,
    pub data_offset: u64,
}

/// 摘要扫描索引条目（80 字节，#[repr(C)] 保证 ABI 稳定）
///
/// 字段自然对齐无 padding，编译期 size_of 校验确保布局稳定。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmSummaryEntry {
    pub lid: u64,
    pub rtype: u32,
    pub name_len: u32,
    pub data_size: u64,
    pub physical_offset: u64,
    pub name_offset: u64,
    pub merkle_leaf: [u8; 32],
    pub created_time: u64,
}

// ===== 编译期布局校验（第 14.4 项）=====
// 任何修改 ShmHeader / ShmEntry / ShmSummaryEntry 布局的行为，
// 若未同步更新 SHM_HEADER_SIZE / SHM_ENTRY_SIZE / SHM_SUMMARY_ENTRY_SIZE，
// 将在此处触发编译错误，根治版本分化。
const _: () = {
    const_assert_eq(SHM_HEADER_SIZE, size_of::<ShmHeader>());
    const_assert_eq(SHM_ENTRY_SIZE, size_of::<ShmEntry>());
    const_assert_eq(SHM_SUMMARY_ENTRY_SIZE, size_of::<ShmSummaryEntry>());
};

// ===== SHM 名称校验白名单（第 2.6 项）=====
/// SHM 名称合法字符集：字母、数字、下划线、连字符
///
/// worker 创建共享内存时使用 `verthys_scan_<random_hex>` 格式，
/// 主进程通过此白名单校验 `shm_name` 参数，防止路径注入。
pub const SHM_NAME_MAX_LEN: usize = 64;

/// 校验 SHM 名称是否合法（^[a-zA-Z0-9_\-]{1,64}$）
///
/// worker 创建的共享内存名称形如 `verthys_scan_3f7a9b2e1c`，
/// 主进程接收前端/控制器传入的 shm_name 时必须先调此函数校验，
/// 防止恶意构造的名称导致 OpenFileMappingW 行为异常。
pub fn is_valid_shm_name(name: &str) -> bool {
    if name.is_empty() || name.len() > SHM_NAME_MAX_LEN {
        return false;
    }
    name.bytes().all(|b| {
        (b'a'..=b'z').contains(&b)
            || (b'A'..=b'Z').contains(&b)
            || (b'0'..=b'9').contains(&b)
            || b == b'_'
            || b == b'-'
    })
}

// ===== 头部字段运行时校验（第 14.4 项）=====
/// 运行时校验头部 entry_size 字段
///
/// worker 在头部 reserved 区可写入 entry_size（用于运行时布局一致性校验）。
/// 主进程读取后调此函数校验，不匹配则判定为 SHM_CORRUPTED。
///
/// 当前 reserved 区未使用，返回 true（预留接口）。
pub fn validate_header_entry_size(_header: &ShmHeader, _expected: usize) -> bool {
    // 预留：未来 worker 在 reserved[0..8] 写入 entry_size 时启用
    true
}
