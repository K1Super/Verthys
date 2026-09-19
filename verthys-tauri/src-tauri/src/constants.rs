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
 * 2. 版本策略：状态文件 magic 前缀与版本号分离，支持 v1→v2 平滑迁移，旧版
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

    /// 旧版 magic 常量（v1 格式）。
    /// 仅在迁移模块中作为读回退标识，不参与写操作。
    #[allow(dead_code)]
    pub const STATE_LEGACY_MAGIC_V1: &str = "VERTHYS_STATE_v1";

    /// 旧版版本号（v1）。
    #[allow(dead_code)]
    pub const STATE_LEGACY_VERSION_V1: u32 = 1;
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
        SHM_MAGIC,
        SHM_VERSION,
        SHM_HEADER_SIZE,
        SHM_ENTRY_SIZE,
        SHM_DEFAULT_SIZE,
        SHM_MAX_SIZE,
        SHM_SUMMARY_MAGIC,
        SHM_SUMMARY_ENTRY_SIZE,
        SHM_SUMMARY_DEFAULT_SIZE,
        SHM_SUMMARY_MAX_SIZE,
        SHM_NAME_MAX_LEN,
        ShmHeader,
        ShmEntry,
        ShmSummaryEntry,
        is_valid_shm_name,
        validate_header_entry_size,
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

// ===== 顶层重导出（向后兼容） =====

// 保持旧版 `use crate::constants::*` 导入方式有效，降低阶段迁移影响。
// 新代码应直接引用子模块（如 `constants::state::STATE_MAGIC`），
// 后续主版本将移除顶层重导出。

#[allow(unused_imports)]
pub use state::{STATE_MAGIC, STATE_VERSION, STATE_LEGACY_MAGIC_V1, STATE_LEGACY_VERSION_V1};
#[allow(unused_imports)]
pub use shm::{
    SHM_MAGIC, SHM_VERSION, SHM_HEADER_SIZE, SHM_ENTRY_SIZE, SHM_DEFAULT_SIZE, SHM_MAX_SIZE,
    SHM_SUMMARY_MAGIC, SHM_SUMMARY_ENTRY_SIZE, SHM_SUMMARY_DEFAULT_SIZE, SHM_SUMMARY_MAX_SIZE,
    SHM_NAME_MAX_LEN, ShmHeader, ShmEntry, ShmSummaryEntry,
    is_valid_shm_name, validate_header_entry_size,
};
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