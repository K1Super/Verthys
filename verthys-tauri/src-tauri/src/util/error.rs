/*
 * util/error.rs — 项目统一错误枚举
 *
 *    "分层异常捕获与日志输出职责矩阵"
 *
 * 设计原则：
 *   - 底层（工具/持久）遇到错误时包装为 VerthysError 并向上传播（? 操作符）
 *   - 中间层（服务/控制器）捕获特定业务异常，转换为具有业务语义的 VerthysError
 *   - 顶层（入口）注册 panic 钩子，构造 JSON 致命错误日志并投递至管道
 *
 * CI 红线：本文件严禁引用上层模块，严禁包含任何日志输出。
 */

use std::fmt;

/// 项目统一错误枚举
///
/// 所有分层错误均统一转换为此枚举变体。
/// 底层包装原始系统错误，中间层附加业务语义，顶层仅记录致命错误。
#[derive(Debug)]
pub enum VerthysError {
    // ===== 系统级错误（底层包装） =====
    /// IO 错误（文件读写、管道通信等）
    Io(std::io::Error),
    /// Windows API 错误（HRESULT 或 GetLastError 返回值）
    WindowsApi(i32, String),
    /// C FFI 调用返回非零错误码
    FfiError(i32, String),
    /// 内存分配失败
    OutOfMemory,
    /// 序列化/反序列化失败
    Serialization(String),

    // ===== 业务级错误（中间层转换） =====
    /// 用户密码错误
    InvalidPassword,
    /// 数据完整性校验失败
    IntegrityCheckFailed,
    /// 容器格式错误
    InvalidFormat(String),
    /// 加密库已锁定
    VerthysLocked,
    /// 加密库未初始化
    VerthysNotInitialized,
    /// 记录不存在
    RecordNotFound(u64),
    /// 容器已满
    VerthysFull,
    /// 检测到回滚攻击
    RollbackDetected,
    /// 应急熔断已触发
    EmergencyTriggered,
    /// 设备指纹不匹配
    DeviceBindingMismatch,

    // ===== IPC 通信错误 =====
    /// Worker 子进程通信失败
    WorkerCommFailed(String),
    /// Worker 子进程超时
    WorkerTimeout,
    /// 共享内存映射失败
    ShmMappingFailed(String),

    // ===== 通用错误 =====
    /// 无效参数
    InvalidArgument(String),
    /// 状态错误（操作时序不正确）
    InvalidState(String),
    /// 内部错误
    Internal(String),
}

impl fmt::Display for VerthysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerthysError::Io(e) => write!(f, "IO 错误: {}", e),
            VerthysError::WindowsApi(code, msg) => write!(f, "Windows API 错误 [{}]: {}", code, msg),
            VerthysError::FfiError(code, msg) => write!(f, "FFI 调用失败 [{}]: {}", code, msg),
            VerthysError::OutOfMemory => write!(f, "内存分配失败"),
            VerthysError::Serialization(msg) => write!(f, "序列化失败: {}", msg),
            VerthysError::InvalidPassword => write!(f, "密码错误"),
            VerthysError::IntegrityCheckFailed => write!(f, "数据完整性校验失败"),
            VerthysError::InvalidFormat(msg) => write!(f, "容器格式错误: {}", msg),
            VerthysError::VerthysLocked => write!(f, "加密库已锁定"),
            VerthysError::VerthysNotInitialized => write!(f, "加密库未初始化"),
            VerthysError::RecordNotFound(id) => write!(f, "记录不存在: LID={}", id),
            VerthysError::VerthysFull => write!(f, "容器已满"),
            VerthysError::RollbackDetected => write!(f, "检测到回滚攻击"),
            VerthysError::EmergencyTriggered => write!(f, "应急熔断已触发"),
            VerthysError::DeviceBindingMismatch => write!(f, "设备指纹不匹配"),
            VerthysError::WorkerCommFailed(msg) => write!(f, "Worker 通信失败: {}", msg),
            VerthysError::WorkerTimeout => write!(f, "Worker 超时"),
            VerthysError::ShmMappingFailed(msg) => write!(f, "共享内存映射失败: {}", msg),
            VerthysError::InvalidArgument(msg) => write!(f, "无效参数: {}", msg),
            VerthysError::InvalidState(msg) => write!(f, "状态错误: {}", msg),
            VerthysError::Internal(msg) => write!(f, "内部错误: {}", msg),
        }
    }
}

impl std::error::Error for VerthysError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VerthysError::Io(e) => Some(e),
            _ => None,
        }
    }
}

// ===== From 转换实现（底层错误包装） =====

impl From<std::io::Error> for VerthysError {
    fn from(e: std::io::Error) -> Self {
        VerthysError::Io(e)
    }
}

impl From<serde_json::Error> for VerthysError {
    fn from(e: serde_json::Error) -> Self {
        VerthysError::Serialization(e.to_string())
    }
}

impl From<std::str::Utf8Error> for VerthysError {
    fn from(e: std::str::Utf8Error) -> Self {
        VerthysError::Serialization(format!("UTF-8 解码失败: {}", e))
    }
}

impl From<String> for VerthysError {
    fn from(s: String) -> Self {
        VerthysError::Internal(s)
    }
}

impl From<&str> for VerthysError {
    fn from(s: &str) -> Self {
        VerthysError::Internal(s.to_string())
    }
}

/// 便捷 Result 类型别名
pub type VerthysResult<T> = Result<T, VerthysError>;
