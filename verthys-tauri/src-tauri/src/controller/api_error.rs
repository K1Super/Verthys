/*
 * @file controller/api_error.rs
 * @brief API 错误码与响应信封 - 统一前端交互契约
 *
 * 本模块定义所有 API 响应的标准信封格式（ApiResponse<T>）及错误码体系（ErrorCode），
 * 确保前端与后端之间的通信契约清晰、类型安全、版本可控。
 *
 * =============================================================================
 * 设计原则
 * =============================================================================
 * 1. 操作特化响应：每个 API 操作定义专用的响应数据类型（如 ScanOpenResponse），
 *    避免使用扁平通用结构，提升前端类型推导准确性与可维护性。
 * 2. 错误信息脱敏：错误消息（message）仅包含用户可读的泛化描述，不得包含
 *    路径、密码、密钥、内部状态等敏感信息。详细信息（details）字段仅用于
 *    日志记录，通过 `#[serde(skip)]` 确保不序列化到前端。
 * 3. 版本标识：所有响应信封携带 `api_version: "2.0"`，便于前端进行协议兼容判断。
 * 4. TypeScript 绑定：通过 `ts-rs` 宏自动生成 TypeScript 类型定义，保证前后端
 *    类型同步，减少手写绑定代码。
 *
 * =============================================================================
 * 安全约束（CI 门禁强制）
 * =============================================================================
 * - 所有错误消息不得包含本地路径、文件名称、注册表项、密钥片段或密码。
 * - `details` 字段可用于记录内部错误堆栈或调试上下文，但不得序列化到响应体。
 * - 错误码命名统一采用 `SCREAMING_SNAKE_CASE`，便于前端解析。
 *
 * =============================================================================
 * 使用规范
 * =============================================================================
 * - 控制器层所有公开接口应返回 `ApiResponse<T>`，其中 `T` 为对应操作的专用响应类型。
 * - 服务层或基础设施层返回的原始错误应通过 `ApiError::with_details` 转换为
 *   标准错误，同时将内部错误上下文写入 `details` 供日志记录。
 * - 前端应根据 `ok` 字段判断成功/失败，并根据 `code` 字段进行差异化处理
 *   （如 `DEVICE_MISMATCH` 引导恢复流程）。
 */

use serde::{Deserialize, Serialize};
use ts_rs::TS;

// ===== 错误码枚举 =====

/// API 错误码枚举，涵盖所有可预见的业务异常。
///
/// 每个变体对应一种明确的错误类别，前端根据 `code` 字段执行特定逻辑。
/// 错误码的字符串表示与序列化名称一致（SCREAMING_SNAKE_CASE），
/// 通过 `serde(rename_all = "SCREAMING_SNAKE_CASE")` 保证前后端一致。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[ts(export, export_to = "bindings/")]
pub enum ErrorCode {
    // ===== Worker / DLL 相关 =====
    /// DLL 文件未找到
    DllNotFound,
    /// DLL 完整性校验失败（哈希不匹配）
    IntegrityFailed,
    /// 系统依赖缺失（如 VC++ 运行库）
    DependencyMissing,
    /// Worker 子进程启动超时
    SpawnTimeout,
    /// Worker 就绪信号等待超时
    ReadyTimeout,
    /// Worker 仍在初始化中（init 请求遇 Initializing 状态）
    StillInitializing,
    /// 共享内存数据损坏（magic 不匹配 / 越界 / 字段异常）
    ShmCorrupted,
    /// 安全核心二进制架构不匹配（如 32-bit worker 与 64-bit DLL）
    BinaryArchMismatch,
    /// 安全核心二进制加载失败（加载器级失败：缺失依赖 / 二进制损坏 / SxS 解析失败）
    BinaryLoadFailed,

    // ===== 路径 / 权限相关 =====
    /// 路径无效（含非法字符 / 超长 / 相对路径 / 目录遍历）
    InvalidPath,
    /// 权限拒绝（路径不在白名单 / 无写权限）
    PermissionDenied,
    /// 文件过大（超过配置阈值）
    FileTooLarge,
    /// 磁盘空间不足
    DiskSpaceInsufficient,
    /// 磁盘空间查询失败（无法获取剩余空间）
    DiskSpaceUnknown,

    // ===== 频率限制 / 熔断 =====
    /// 操作频率超限（剪贴板 / 爆破计数 / 批次断档）
    RateLimited,

    // ===== 剪贴板相关 =====
    /// 剪贴板监听启动失败
    ClipboardMonitorFailed,

    // ===== 设备绑定相关 =====
    /// 设备指纹不匹配
    DeviceMismatch,
    /// 设备未绑定（首次运行）
    DeviceUnbound,
    /// 设备部分匹配（部分硬件变更，触发有限恢复模式）
    DevicePartialMatch,

    // ===== Verthys 状态相关 =====
    /// 加密库已锁定（需先解锁）
    VerthysLocked,
    /// 加密库未初始化（需先创建/初始化密钥）
    VerthysNotInitialized,
    /// 状态文件损坏或缺失（需恢复模式）
    StateCorrupted,

    // ===== 密钥 / 密码相关 =====
    /// 密码错误（派生/验证失败）
    InvalidPassword,
    /// 密码复杂度不足
    PasswordComplexityInsufficient,
    /// 密钥状态不匹配（如 derive 时已存在密钥）
    KeyStateMismatch,

    // ===== 通用错误 =====
    /// 临时性故障（I/O 抖动 / 资源占用），可重试
    TemporaryFailure,
    /// 内部错误（未分类）
    Internal,
}

impl ErrorCode {
    /// 返回错误码的字符串标识（与序列化名称一致）。
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::DllNotFound => "DLL_NOT_FOUND",
            ErrorCode::IntegrityFailed => "INTEGRITY_FAILED",
            ErrorCode::DependencyMissing => "DEPENDENCY_MISSING",
            ErrorCode::SpawnTimeout => "SPAWN_TIMEOUT",
            ErrorCode::ReadyTimeout => "READY_TIMEOUT",
            ErrorCode::StillInitializing => "STILL_INITIALIZING",
            ErrorCode::ShmCorrupted => "SHM_CORRUPTED",
            ErrorCode::BinaryArchMismatch => "BINARY_ARCH_MISMATCH",
            ErrorCode::BinaryLoadFailed => "BINARY_LOAD_FAILED",
            ErrorCode::InvalidPath => "INVALID_PATH",
            ErrorCode::PermissionDenied => "PERMISSION_DENIED",
            ErrorCode::FileTooLarge => "FILE_TOO_LARGE",
            ErrorCode::DiskSpaceInsufficient => "DISK_SPACE_INSUFFICIENT",
            ErrorCode::DiskSpaceUnknown => "DISK_SPACE_UNKNOWN",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::ClipboardMonitorFailed => "CLIPBOARD_MONITOR_FAILED",
            ErrorCode::DeviceMismatch => "DEVICE_MISMATCH",
            ErrorCode::DeviceUnbound => "DEVICE_UNBOUND",
            ErrorCode::DevicePartialMatch => "DEVICE_PARTIAL_MATCH",
            ErrorCode::VerthysLocked => "VERTHYS_LOCKED",
            ErrorCode::VerthysNotInitialized => "VERTHYS_NOT_INITIALIZED",
            ErrorCode::StateCorrupted => "STATE_CORRUPTED",
            ErrorCode::InvalidPassword => "INVALID_PASSWORD",
            ErrorCode::PasswordComplexityInsufficient => "PASSWORD_COMPLEXITY_INSUFFICIENT",
            ErrorCode::KeyStateMismatch => "KEY_STATE_MISMATCH",
            ErrorCode::TemporaryFailure => "TEMPORARY_FAILURE",
            ErrorCode::Internal => "INTERNAL",
        }
    }

    /// 返回默认的用户可读错误消息（已脱敏，不含敏感信息）。
    pub fn default_message(&self) -> &'static str {
        match self {
            ErrorCode::DllNotFound => "加密库文件未找到",
            ErrorCode::IntegrityFailed => "加密库完整性校验失败",
            ErrorCode::DependencyMissing => "系统依赖缺失",
            ErrorCode::SpawnTimeout => "安全子进程启动超时",
            ErrorCode::ReadyTimeout => "安全子进程就绪超时",
            ErrorCode::StillInitializing => "安全子进程仍在初始化中，请稍后重试",
            ErrorCode::ShmCorrupted => "共享内存数据损坏",
            ErrorCode::BinaryArchMismatch => "安全核心二进制架构不匹配，请重新构建",
            ErrorCode::BinaryLoadFailed => "安全核心二进制加载失败，请重新构建或安装依赖",
            ErrorCode::InvalidPath => "路径无效",
            ErrorCode::PermissionDenied => "权限不足",
            ErrorCode::FileTooLarge => "文件过大",
            ErrorCode::DiskSpaceInsufficient => "磁盘空间不足",
            ErrorCode::DiskSpaceUnknown => "无法获取磁盘空间信息",
            ErrorCode::RateLimited => "操作过于频繁，请稍后重试",
            ErrorCode::ClipboardMonitorFailed => "剪贴板监听启动失败",
            ErrorCode::DeviceMismatch => "设备指纹不匹配",
            ErrorCode::DeviceUnbound => "设备未绑定",
            ErrorCode::DevicePartialMatch => "设备部分匹配，需恢复验证",
            ErrorCode::VerthysLocked => "加密库已锁定",
            ErrorCode::VerthysNotInitialized => "加密库未初始化",
            ErrorCode::StateCorrupted => "状态文件损坏",
            ErrorCode::InvalidPassword => "密码错误",
            ErrorCode::PasswordComplexityInsufficient => "密码复杂度不足",
            ErrorCode::KeyStateMismatch => "密钥状态不匹配",
            ErrorCode::TemporaryFailure => "临时性故障，请重试",
            ErrorCode::Internal => "内部错误",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ===== API 错误结构 =====

/// API 错误结构，包含错误码、脱敏消息和内部详情。
///
/// - `code`：错误码，前端据此进行逻辑分支。
/// - `message`：用户可读的脱敏描述，不含任何敏感信息。
/// - `details`：内部详细错误上下文（如堆栈、路径哈希等），仅用于日志记录，
///   通过 `#[serde(skip)]` 不序列化到前端响应，防止信息泄露。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct ApiError {
    /// 错误码
    pub code: ErrorCode,
    /// 用户可读的脱敏消息
    pub message: String,
    /// 内部详情（仅日志记录，不序列化到前端）
    #[serde(skip)]
    pub details: Option<String>,
}

impl ApiError {
    /// 创建标准错误，自动填充默认脱敏消息。
    pub fn new(code: ErrorCode) -> Self {
        let message = code.default_message().to_string();
        ApiError {
            code,
            message,
            details: None,
        }
    }

    /// 创建自定义消息的错误（仍须保证脱敏）。
    pub fn with_message(code: ErrorCode, message: impl Into<String>) -> Self {
        let message = message.into();
        ApiError {
            code,
            message,
            details: None,
        }
    }

    /// 创建带内部详情的错误，详情不发送至前端。
    pub fn with_details(
        code: ErrorCode,
        message: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        let message = message.into();
        let details = details.into();
        ApiError {
            code,
            message,
            details: Some(details),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

// ===== 统一 API 响应信封 =====

/// API 协议版本标识（用于前端兼容性判断）。
pub const API_VERSION: &str = "2.0";

/// 统一 API 响应信封，泛型参数 `T` 为操作专用的数据负载类型。
///
/// 结构：
/// - `api_version`：固定为 `"2.0"`，便于前端识别协议版本。
/// - `ok`：布尔值，表示操作成功与否。
/// - `data`：成功时的数据负载，失败时为 `None`。
/// - `error`：失败时的错误信息，成功时为 `None`。
///
/// 前端应根据 `ok` 字段决定从 `data` 或 `error` 中获取信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub api_version: &'static str,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl<T> ApiResponse<T> {
    /// 创建成功响应，携带数据负载。
    pub fn success(data: T) -> Self {
        ApiResponse {
            api_version: API_VERSION,
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    /// 创建空成功响应（无数据）。
    pub fn success_empty() -> Self {
        ApiResponse {
            api_version: API_VERSION,
            ok: true,
            data: None,
            error: None,
        }
    }

    /// 创建错误响应。
    pub fn error(err: ApiError) -> Self {
        ApiResponse {
            api_version: API_VERSION,
            ok: false,
            data: None,
            error: Some(err),
        }
    }

    /// 根据错误码快捷创建错误响应（自动填充默认消息）。
    pub fn from_error_code(code: ErrorCode) -> Self {
        Self::error(ApiError::new(code))
    }
}

// ===== 各操作特化响应类型 =====
//
// 以下每个类型对应一个具体 API 操作的数据负载，确保前端获得精确的字段提示。
// 这些类型会在控制器层序列化后返回。

/// `scan_open` 操作的响应数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOpenResponse {
    /// 共享内存名称（仅主进程内部使用，不返回前端）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shm_name: Option<String>,
    /// 共享内存总大小（字节）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shm_size: Option<u64>,
    /// 本次返回的记录数
    pub record_count: u64,
    /// 是否已完成全部遍历
    pub exhausted: bool,
}

/// `scan_next` 操作的响应数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanNextResponse {
    /// 本次返回的记录数
    pub record_count: u64,
    /// 是否已完成全部遍历
    pub exhausted: bool,
}

/// `derive_global_key` 操作的响应数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeriveKeyResponse {
    /// 派生是否成功
    pub derived: bool,
}

/// `verify_global_key` 操作的响应数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyKeyResponse {
    /// 验证是否成功（密码正确）
    pub verified: bool,
}

/// `verthys_unlock` 操作的响应数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockResponse {
    /// 解锁是否成功
    pub unlocked: bool,
}

/// `enumerate_records` 操作的响应数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumerateResponse {
    /// 记录列表
    pub records: Vec<crate::controller::types::VerthysRecordEntry>,
    /// 本批最后一条记录的 ID（0 表示无记录）
    pub last_id: u64,
    /// 是否已遍历完毕
    pub exhausted: bool,
}