/*
 * @file constants.rs
 * @brief 全局常量定义 - 按领域拆分子模块，提供编译期配置与共享常量
 *
 * 本模块汇集所有编译期常量，按功能领域划分为 state、shm、timeout 三个子模块。
 * 所有常量均为零成本抽象，不包含函数或运行时状态，可被任意分层模块安全引用。
 *
 * =============================================================================
 * 设计原则
 * =============================================================================
 * 1. 同源定义：SHM 常量与 verthys-worker 进程共享同一份源码（通过 include! 引入），
 *    确保主/子进程结构体布局与常量严格一致，根治版本分化。
 * 2. 版本策略：状态文件 magic 前缀与版本号分离，支持平滑迁移，旧版
 *    magic 保留作为迁移回退标识。
 * 3. 超时特化：按操作类型分别配置超时（初始化、IPC、派生、迁移等），避免单一
 *    全局超时导致长流程误判或短操作等待过长。
 * 4. 向后兼容：顶层重导出保持旧版导入路径（`constants::CONST_NAME`）有效，
 *    降低阶段迁移对现有代码的冲击；废弃常量标注 `#[deprecated]` 引导新代码迁移。
 *
 * =============================================================================
 * 安全与合规约束
 * =============================================================================
 * - SHM 常量在编译期通过 const_assert_eq! 校验结构体大小，任何布局变更
 *   若未同步常量将导致编译失败。
 * - 状态文件迁移时，旧版 magic 仅用于只读回退，写操作始终使用新版纯前缀。
 * - 超时配置值依据操作预期耗时设定，防止过短导致误报或过长阻塞用户操作。
 * - 不依赖任何外部 crate 的运行时功能，仅使用 std::time::Duration 等原生类型。
 *
 * =============================================================================
 * 维护说明
 * =============================================================================
 * - 新增常量时按领域归入对应子模块，避免顶层污染。
 * - 修改超时值前应评估操作实际耗时分布，并同步更新文档说明。
 * - 废弃常量标注 `#[deprecated]` 并在注释中指明替代做法，保留至少一个
 *   主版本周期后移除。
 */

// ===== 状态文件常量 =====

/// 状态文件常量（verthys_state 文件的 magic 与版本）
///
/// 设计目的：
/// - 将 magic 前缀与版本号分离，使版本升级无需变更 magic 字符串，
///   简化前向兼容与迁移判断。
/// - 保留旧版 magic 常量，供 verthys_state 读取时作为迁移触发条件。
///
/// 约束：
/// - 写操作始终使用 `STATE_MAGIC` + `STATE_VERSION` 组合。
/// - 迁移函数负责将旧版格式转换为当前格式，不破坏原有数据。
pub mod state {
    /// 状态文件 magic 纯前缀（不含版本号）。
    /// 当前版本为 2，版本号独立存储。
    pub const STATE_MAGIC: &str = "VERTHYS_STATE";

    /// 当前状态文件版本号。
    /// 与 magic 分离，允许在不改变 magic 的情况下升级格式。
    pub const STATE_VERSION: u32 = 2;
}

// ===== 共享内存常量 =====

/// 共享内存常量（与 worker 进程同源定义）
///
/// 本模块从 `infrastructure::shm_schema` 重导出所有 SHM 协议常量与结构体，
/// 该模块通过 `include!` 引入项目根目录下的共享源文件，确保主进程与
/// worker 使用同一份定义。
///
/// 安全约束：
/// - 常量与结构体布局在编译期通过 `const_assert_eq!` 校验，防止版本分化。
/// - 提供 `is_valid_shm_name` 和 `validate_header_entry_size` 等辅助函数，
///   用于运行时输入校验。
pub mod shm {
    pub use crate::infrastructure::shm_schema::{
        is_valid_shm_name, validate_header_entry_size, ShmEntry, ShmHeader, ShmSummaryEntry,
        SHM_DEFAULT_SIZE, SHM_ENTRY_SIZE, SHM_HEADER_SIZE, SHM_MAGIC, SHM_MAX_SIZE,
        SHM_NAME_MAX_LEN, SHM_SUMMARY_DEFAULT_SIZE, SHM_SUMMARY_ENTRY_SIZE, SHM_SUMMARY_MAGIC,
        SHM_SUMMARY_MAX_SIZE, SHM_VERSION,
    };
}

// ===== 超时配置 =====

/// 操作特化超时配置
///
/// 替代单一全局超时，按操作类型分别定义超时阈值，避免短操作等待过长
/// 或长操作因超时不足而失败。
///
/// 约束：
/// - 所有超时值使用 `Duration` 类型，便于计算与调试。
/// - 默认值通过 `TimeoutConfig::default()` 获取，可扩展为通过 Tauri
///   管理状态注入自定义配置（未来支持）。
pub mod timeout {
    use std::time::Duration;

    #[derive(Debug, Clone, Copy)]
    #[allow(dead_code)]
    pub struct TimeoutConfig {
        /// Worker 初始化总超时（包含 spawn、就绪、DLL 加载）
        pub init: Duration,
        /// 单次 IPC 请求-响应往返超时
        pub ipc: Duration,
        /// 密钥派生/验证超时（PBKDF2/Argon2 计算密集）
        pub derive_verify: Duration,
        /// 路径预检超时（磁盘空间/权限检查）
        pub preflight: Duration,
        /// 剪贴板清空/占用重试超时
        pub clipboard_op: Duration,
        /// scan_open 操作超时
        pub scan_open: Duration,
        /// scan_next 操作超时
        pub scan_next: Duration,
        /// scan_close 操作超时
        pub scan_close: Duration,
        /// 预取任务内部单批超时
        pub scan_prefetch: Duration,
        /// 预取任务 shutdown 等待超时
        pub scan_prefetch_shutdown: Duration,
    }

    impl Default for TimeoutConfig {
        fn default() -> Self {
            DEFAULT
        }
    }

    /// 默认超时配置（常量值）
    ///
    /// 各数值基于操作预期耗时设定：
    /// - init: 30s（覆盖冷启动 + 加载器延迟）
    /// - ipc: 10s（正常网络/管道往返）
    /// - derive_verify: 15s（支持 Argon2id 安全预设）
    /// - preflight: 5s（磁盘 I/O 轻量检查）
    /// - clipboard_op: 2s（清空剪贴板重试）
    /// - scan_*: 60s/30s（扫描操作延迟敏感性低）
    pub const DEFAULT: TimeoutConfig = TimeoutConfig {
        init: Duration::from_secs(30),
        ipc: Duration::from_secs(10),
        derive_verify: Duration::from_secs(15),
        preflight: Duration::from_secs(5),
        clipboard_op: Duration::from_secs(2),
        scan_open: Duration::from_secs(60),
        scan_next: Duration::from_secs(60),
        scan_close: Duration::from_secs(30),
        scan_prefetch: Duration::from_secs(60),
        scan_prefetch_shutdown: Duration::from_secs(2),
    };
}

// ===== 导入单写者通道常量 =====

/// 照片导入批量写入约束（与前端导入常量表严格对齐）
///
/// 通道超时三层结构各自独立：命令层发送、响应层等待、写者线程心跳，
/// 三者共同保证端到端延迟有上界（超时必返回明确错误）。
pub mod import_writer {
    use std::time::Duration;

    use crate::infrastructure::shm_schema::{PB_IPC_MAX_PAYLOAD_BYTES, PB_MAX_CHUNKS_PER_IPC};

    /// 命令层向写者通道发送的超时（通道背压满时兜底）
    pub const WRITER_SEND_TIMEOUT: Duration = Duration::from_secs(5);
    /// 响应层等待写者命令完成的超时
    pub const WRITER_CMD_TIMEOUT: Duration = Duration::from_secs(60);
    /// 写者线程心跳超时阈值（毫秒，超过判定写者卡死触发重建）
    pub const WRITER_HEARTBEAT_TIMEOUT_MS: u64 = 15_000;
    /// 心跳看门狗巡检周期（毫秒）
    pub const WRITER_HEARTBEAT_SWEEP_MS: u64 = 5_000;
    /// 单条 IPC 载荷上限（字节，与前端同一跨层预算取值）
    pub const MAX_IPC_PAYLOAD_BYTES: usize = PB_IPC_MAX_PAYLOAD_BYTES as usize;
    /// 单批次记录数硬上限
    pub const MAX_BATCH_RECORDS: usize = 512;
    /// 单条外置 chunk 分批 IPC 的 chunk 数硬上限（与前端同一跨层预算取值）
    pub const MAX_CHUNKS_PER_IPC: usize = PB_MAX_CHUNKS_PER_IPC as usize;
    /// 单条记录名称长度上限（UTF-8 字节，与实现侧 `name.len()` 按字节比较的口径一致）
    pub const MAX_RECORD_NAME_LEN: usize = 1024;
    /// 单条记录内容哈希长度上限（字符）
    pub const MAX_RECORD_HASH_LEN: usize = 256;
}

// ===== 照片记录类型常量 =====

/// 照片记录类型值（与前端加密层同值）
///
/// meta 记录由前端加密后携带 rtype 提交；外置块记录由主进程单写者
/// 写入，类型值在此单源定义，禁止控制层散落字面量。
pub mod record_types {
    /// 照片数据块记录类型值（外置加密块记录）
    pub const TYPE_PHOTO_CHUNK: u32 = 5;
    /// 照片缩略图记录类型值（索引瘦身布局的独立缩略图记录）
    pub const TYPE_PHOTO_THUMB: u32 = 7;
    /// 照片块集记录类型值（索引瘦身布局：逐块引用与逐块哈希）
    pub const TYPE_PHOTO_CHUNK_SET: u32 = 9;
}

// ===== 导出流式写入常量 =====

/// 单文件流式导出约束（与前端导出常量表严格对齐）
///
/// 分块上界保证单次追加在内存与带宽上可控；总量上界为单文件流式导出
/// 的硬性安全边界，防止失控写入耗尽磁盘；暂存文件残留按龄清理，避免
/// 崩溃遗留堆积。
pub mod export_stream {
    use std::time::Duration;

    /// 单次流式追加（append_user_file_chunk）的载荷字节上界
    pub const WRITE_FILE_CHUNK_BYTES: usize = 4 * 1024 * 1024;
    /// 单文件流式导出累计写入字节硬上限
    pub const MAX_EXPORT_SINGLE_BYTES: u64 = 512 * 1024 * 1024;
    /// 暂存文件残留清理阈值（创建新流时清理修改时间早于该阈值的残留）
    pub const STALE_TEMP_MAX_AGE: Duration = Duration::from_secs(24 * 3600);
}

// ===== 顶层重导出（向后兼容） =====

// 保持旧版 `use crate::constants::*` 导入方式有效，降低阶段迁移影响。
// 新代码应直接引用子模块（如 `constants::state::STATE_MAGIC`），
// 后续主版本将移除顶层重导出。

#[allow(unused_imports)]
pub use shm::{
    is_valid_shm_name, validate_header_entry_size, ShmEntry, ShmHeader, ShmSummaryEntry,
    SHM_DEFAULT_SIZE, SHM_ENTRY_SIZE, SHM_HEADER_SIZE, SHM_MAGIC, SHM_MAX_SIZE, SHM_NAME_MAX_LEN,
    SHM_SUMMARY_DEFAULT_SIZE, SHM_SUMMARY_ENTRY_SIZE, SHM_SUMMARY_MAGIC, SHM_SUMMARY_MAX_SIZE,
    SHM_VERSION,
};
#[allow(unused_imports)]
pub use state::{STATE_MAGIC, STATE_VERSION};
#[allow(unused_imports)]
pub use timeout::{TimeoutConfig, DEFAULT as TIMEOUT_DEFAULT};

// ===== 废弃常量 =====

/// 已废弃的单一超时常量。
///
/// 此常量已被 `TimeoutConfig` 替代，新代码应使用 `TimeoutConfig::default().init`
/// 或对应操作的特定超时字段。
#[deprecated(since = "2.6.1", note = "使用 TimeoutConfig::default().init 替代")]
#[allow(dead_code)]
pub const VERTHYS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
