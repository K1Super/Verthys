/*
 * 运维与启动诊断 DTO
 *
 * 职责边界：路径预检结果、诊断信息与初始化状态查询结果；均只携带错误码/
 * 哈希标识，不携带路径明文。
 */

use super::*;
use ts_rs::TS;
// ===== PreflightResult（错误码脱敏，不携带路径）=====

/// 路径预检结果（错误码脱敏，不携带路径）
///
/// 失败时仅返回标准化错误码 + 无路径提示，不泄露路径。
///   错误码取值：INVALID_PATH / PERMISSION_DENIED / DISK_SPACE_INSUFFICIENT
///   / DISK_SPACE_UNKNOWN / TEMPORARY_FAILURE
/// 详细路径与错误原因仅写入后端日志（经 sanitize_path 脱敏）。
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct PreflightResult {
    pub ok: bool,
    pub error: Option<String>,
    /// 标准化错误码（前端据此差异化处理，不含路径信息）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// 目标路径是否位于系统保护目录（不透传路径到前端）
    pub is_system_protected: bool,
    pub file_exists: bool,
    /// 磁盘剩余空间（MB）
    #[ts(type = "number")]
    pub disk_space_mb: u64,
    /// 是否自动创建了目录
    pub dir_created: bool,
}

// ===== DiagInfo（仅存在性/哈希标识，不含路径）=====

/// 诊断信息（仅存在性与哈希标识，不含 worker/dll 路径与工作目录）
///
/// 不返回路径字段，避免通过诊断接口泄露本地目录结构。
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct DiagInfo {
    /// worker 可执行文件是否存在
    pub worker_exists: bool,
    /// DLL 文件是否存在
    pub dll_exists: bool,
    /// worker 是否运行中
    pub worker_running: bool,
    /// DLL SHA-256 哈希前 16 字符（完整性诊断用）
    ///
    /// 从 build.rs 生成的 dll_hash.rs 读取，用于诊断 DLL 完整性。
    /// 空字符串表示 DLL 未找到或哈希未生成（开发模式）。
    pub dll_hash: String,
    /// worker 进程 PID（运行中时有值）
    pub worker_pid: Option<u32>,
}

// ===== InitStatusResult（使用 InitStatus 枚举）=====

/// 初始化状态查询结果
///
/// status 为字符串形式，status_enum 为类型安全枚举，两者并存以保持兼容。
#[derive(serde::Serialize, TS)]
#[ts(export, export_to = "bindings/")]
pub struct InitStatusResult {
    /// 状态字符串（取值见下）
    ///
    /// 取值："none" | "ready" | "broken" | "initializing" | "maintenance"
    pub status: String,
    /// 状态枚举（类型安全形式）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_enum: Option<InitStatus>,
    /// 加密库路径（ready 时有值，脱敏后返回）
    pub verthys_path: Option<String>,
    /// 状态文件描述
    pub detail: String,
}
