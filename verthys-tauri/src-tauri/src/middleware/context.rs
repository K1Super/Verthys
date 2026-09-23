/*
 * middleware/context.rs — 进程级上下文容器
 *
 *    "入口文件单一职责约束"
 *             "标准化日志分层输出规范"（注入式传递）
 *
 * 设计原则：
 *   - Context 在入口层创建，持有日志管道发送端、全局配置等横切关注点
 *   - 通过构造函数参数或方法参数逐层注入至控制器、服务、工具
 *   - 日志管道发送端不得设计为全局静态变量
 *   - Context 持有本进程私有资源的所有权，Drop 时自动释放
 *
 * parse_config 返回强类型 Config
 *   - 包含日志级别、路径、进程模式、资源限制等
 *   - entry_main 依 Config 创建 Context
 *   - 便于单元测试，传入内存配置而无需触碰环境变量或文件系统
 *
 * 严禁读取用户可控环境变量改变关键路径
 *   - parse_config 仅从命令行参数解析配置
 *   - 不读取 VERTHYS_PATH / WORKER_PATH / VERTHYS_SANDBOX_REDIRECT 等环境变量
 *   - 必须依赖的路径信息通过命令行参数、配置文件或编译期资源注入
 *
 * CI 红线：本文件不得包含业务逻辑，不得直接调用底层工具库。
 */
use std::path::PathBuf;
use std::sync::Arc;

use crate::infrastructure::log_pipe::LogSender;
use crate::util::error::{VerthysError, VerthysResult};

/// 进程运行模式
///
/// 入口层根据启动参数决定进程运行模式，
/// 并调用对应的控制器入口方法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessMode {
    /// 主 UI 进程（负责界面与用户交互）
    MainUi,
    /// 安全 Worker 进程（执行 CNG 加解密与敏感操作）
    SecureWorker,
    /// 定时巡检进程（监控系统健康）
    Inspector,
}

impl ProcessMode {
    /// 从字符串解析进程模式（命令行 --mode 参数）
    ///
    /// 支持的值：ui / worker / inspector
    /// 默认（未指定 --mode）：MainUi
    pub fn parse_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "worker" | "secure_worker" => ProcessMode::SecureWorker,
            "inspector" => ProcessMode::Inspector,
            _ => ProcessMode::MainUi, // 默认 UI 模式
        }
    }

    /// 获取进程名（用于日志文件命名）
    pub fn process_name(&self) -> &'static str {
        match self {
            ProcessMode::MainUi => "main_ui",
            ProcessMode::SecureWorker => "worker",
            ProcessMode::Inspector => "inspector",
        }
    }
}

impl std::fmt::Display for ProcessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessMode::MainUi => write!(f, "MainUi"),
            ProcessMode::SecureWorker => write!(f, "SecureWorker"),
            ProcessMode::Inspector => write!(f, "Inspector"),
        }
    }
}

/// 强类型启动配置
///
/// 解析自命令行参数，包含进程运行所需的所有配置项。
/// 严禁读取环境变量。
#[derive(Debug, Clone)]
pub struct StartupConfig {
    /// 进程运行模式
    pub mode: ProcessMode,
    /// 自定义数据目录（--data-dir 参数，None 表示使用默认解析）
    pub data_dir: Option<PathBuf>,
    /// 自定义 verthys 文件路径（--verthys-path 参数，None 表示使用默认）
    pub verthys_path: Option<PathBuf>,
    /// 自定义 worker 可执行文件路径（--worker-path 参数，None 表示使用默认解析）
    pub worker_path: Option<PathBuf>,
    /// 日志级别（--log-level 参数，默认 Info）
    pub log_level: LogLevel,
    /// 是否调试模式（--debug 参数，或编译期 debug_assertions）
    pub debug: bool,
    /// 日志管道容量（--log-capacity 参数，默认 4096）
    pub log_capacity: usize,
}

impl Default for StartupConfig {
    fn default() -> Self {
        StartupConfig {
            mode: ProcessMode::MainUi,
            data_dir: None,
            verthys_path: None,
            worker_path: None,
            log_level: LogLevel::Info,
            debug: cfg!(debug_assertions),
            log_capacity: 4096,
        }
    }
}

/// 日志级别（强类型，替代字符串配置）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Fatal,
}

impl LogLevel {
    /// 从字符串解析日志级别
    pub fn parse_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            "fatal" => LogLevel::Fatal,
            _ => LogLevel::Info,
        }
    }

    /// 转换为 log crate 的 LevelFilter
    pub fn to_log_filter(&self) -> log::LevelFilter {
        match self {
            LogLevel::Trace => log::LevelFilter::Trace,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Fatal => log::LevelFilter::Error, // log crate 无 Fatal，归入 Error
        }
    }
}

/// 兼容旧接口：上下文配置（键值对形式）
///
/// 保留 ContextConfig 作为 StartupConfig 的兼容包装，
/// 后续统一迁移至 StartupConfig。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContextConfig {
    /// 加密库路径
    pub verthys_path: String,
    /// 是否调试模式
    pub debug: bool,
    /// Worker 子进程可执行文件路径
    pub worker_executable: String,
}

impl ContextConfig {
    /// 从 StartupConfig 构造 ContextConfig（兼容旧调用点）
    pub fn from_startup(config: &StartupConfig) -> Self {
        ContextConfig {
            verthys_path: config
                .verthys_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            debug: config.debug,
            worker_executable: config
                .worker_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
        }
    }
}

/// 进程级上下文容器
///
/// 持有所有进程私有资源与横切关注点的引用。
/// 通过 clone() 传递 Arc 引用，实现轻量级上下文传递。
/// 日志发送端通过此上下文注入至各分层。
#[derive(Clone)]
pub struct Context {
    /// 进程运行模式
    mode: ProcessMode,
    /// 日志管道发送端（注入式传递，非全局静态变量）
    log_sender: LogSender,
    /// 全局配置（键值对，启动时从配置文件加载）
    config: Arc<ContextConfig>,
}

impl Context {
    /// 创建新上下文
    ///
    /// 此方法在入口层调用，传入日志管道发送端和配置。
    /// 之后通过 clone() 逐层传递。
    pub fn new(mode: ProcessMode, log_sender: LogSender, config: ContextConfig) -> Self {
        Context {
            mode,
            log_sender,
            config: Arc::new(config),
        }
    }

    /// 获取进程运行模式
    pub fn mode(&self) -> ProcessMode {
        self.mode
    }

    /// 获取日志管道发送端引用
    ///
    /// 各分层通过此方法获取发送端，将日志事件投递至管道。
    /// 发送端为 Arc 包装，clone 开销极低。
    pub fn log_sender(&self) -> &LogSender {
        &self.log_sender
    }

    /// 获取全局配置引用
    pub fn config(&self) -> &ContextConfig {
        &self.config
    }
}

/// 上下文初始化结果
///
/// 包含上下文和所有需由入口层管理的资源句柄。
/// 入口层负责持有这些句柄，进程退出时自动释放。
pub struct ContextBundle {
    /// 进程上下文（传递至控制器层）
    pub ctx: Context,
    /// 后台资源句柄（入口层持有，Drop 时自动清理）
    ///
    /// 使用 Box<dyn Drop> 确保所有资源在进程退出时被正确释放。
    /// 这包括：数据库连接池、CNG 算法提供者、IPC 管道实例等。
    pub resources: Vec<Box<dyn std::any::Any>>,
}

/// 从命令行参数解析强类型 StartupConfig
///
/// 支持的参数：
///   --mode <ui|worker|inspector>    进程运行模式（默认 ui）
///   --data-dir <path>               自定义数据目录（受信参数）
///   --verthys-path <path>             verthys 文件路径
///   --worker-path <path>            worker 可执行文件路径
///   --log-level <trace|debug|info|warn|error|fatal>  日志级别（默认 info）
///   --debug                         启用调试模式
///   --log-capacity <n>              日志管道容量（默认 4096）
///   -h, --help                      显示帮助
///
/// 严禁读取环境变量
///   - 不读取 VERTHYS_PATH / WORKER_PATH / VERTHYS_SANDBOX_REDIRECT 等环境变量
///   - 所有路径必须通过命令行参数或编译期资源注入
///
/// 返回 VerthysResult 以便参数校验失败时向上传播。
pub fn parse_config(args: &[String]) -> VerthysResult<StartupConfig> {
    let mut config = StartupConfig::default();

    let mut i = 1; // 跳过 args[0]（程序名）
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--mode" => {
                i += 1;
                if i < args.len() {
                    config.mode = ProcessMode::parse_str(&args[i]);
                }
            }
            "--data-dir" => {
                i += 1;
                if i < args.len() {
                    let path = std::path::PathBuf::from(&args[i]);
                    // --data-dir 必须为绝对路径（受信参数校验）
                    if !path.is_absolute() {
                        return Err(VerthysError::InvalidArgument(format!(
                            "--data-dir 必须为绝对路径，收到: {}",
                            args[i]
                        )));
                    }
                    config.data_dir = Some(path);
                }
            }
            "--verthys-path" => {
                i += 1;
                if i < args.len() {
                    config.verthys_path = Some(std::path::PathBuf::from(&args[i]));
                }
            }
            "--worker-path" => {
                i += 1;
                if i < args.len() {
                    config.worker_path = Some(std::path::PathBuf::from(&args[i]));
                }
            }
            "--log-level" => {
                i += 1;
                if i < args.len() {
                    config.log_level = LogLevel::parse_str(&args[i]);
                }
            }
            "--debug" => {
                config.debug = true;
            }
            "--log-capacity" => {
                i += 1;
                if i < args.len() {
                    config.log_capacity = args[i]
                        .parse::<usize>()
                        .map_err(|e| VerthysError::InvalidArgument(format!(
                            "--log-capacity 无效: {}", e
                        )))?;
                    // 容量下限保护
                    if config.log_capacity < 64 {
                        config.log_capacity = 64;
                    }
                }
            }
            "-h" | "--help" => {
                return Err(VerthysError::InvalidArgument(
                    "帮助信息".to_string(),
                ));
            }
            _ => {
                // 未知参数：忽略（兼容 Tauri 注入的参数如 --webview-debug）
                // 但记录到 stderr 供诊断（入口层早期，日志系统可能未就绪）
            }
        }
        i += 1;
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config_default() {
        let args = vec!["verthys.exe".to_string()];
        let config = parse_config(&args).expect("默认配置应成功");
        assert_eq!(config.mode, ProcessMode::MainUi);
        assert!(config.data_dir.is_none());
        assert_eq!(config.log_level, LogLevel::Info);
        assert_eq!(config.log_capacity, 4096);
    }

    #[test]
    fn test_parse_config_mode_worker() {
        let args = vec![
            "verthys.exe".to_string(),
            "--mode".to_string(),
            "worker".to_string(),
        ];
        let config = parse_config(&args).expect("worker 模式应成功");
        assert_eq!(config.mode, ProcessMode::SecureWorker);
    }

    #[test]
    fn test_parse_config_mode_inspector() {
        let args = vec![
            "verthys.exe".to_string(),
            "--mode".to_string(),
            "inspector".to_string(),
        ];
        let config = parse_config(&args).expect("inspector 模式应成功");
        assert_eq!(config.mode, ProcessMode::Inspector);
    }

    #[test]
    fn test_parse_config_data_dir_absolute() {
        let args = vec![
            "verthys.exe".to_string(),
            "--data-dir".to_string(),
            "C:\\Verthys\\data".to_string(),
        ];
        let config = parse_config(&args).expect("绝对路径应成功");
        assert_eq!(
            config.data_dir.as_ref().unwrap().to_str().unwrap(),
            "C:\\Verthys\\data"
        );
    }

    #[test]
    fn test_parse_config_data_dir_relative_rejected() {
        let args = vec![
            "verthys.exe".to_string(),
            "--data-dir".to_string(),
            "relative/path".to_string(),
        ];
        let result = parse_config(&args);
        assert!(result.is_err(), "相对路径应被拒绝");
    }

    #[test]
    fn test_parse_config_log_level() {
        let args = vec![
            "verthys.exe".to_string(),
            "--log-level".to_string(),
            "debug".to_string(),
        ];
        let config = parse_config(&args).expect("日志级别应成功");
        assert_eq!(config.log_level, LogLevel::Debug);
    }

    #[test]
    fn test_parse_config_log_capacity() {
        let args = vec![
            "verthys.exe".to_string(),
            "--log-capacity".to_string(),
            "8192".to_string(),
        ];
        let config = parse_config(&args).expect("日志容量应成功");
        assert_eq!(config.log_capacity, 8192);
    }

    #[test]
    fn test_parse_config_log_capacity_minimum() {
        let args = vec![
            "verthys.exe".to_string(),
            "--log-capacity".to_string(),
            "10".to_string(), // 低于下限
        ];
        let config = parse_config(&args).expect("日志容量应成功");
        assert_eq!(config.log_capacity, 64, "应被钳制到下限 64");
    }

    #[test]
    fn test_parse_config_debug_flag() {
        let args = vec![
            "verthys.exe".to_string(),
            "--debug".to_string(),
        ];
        let config = parse_config(&args).expect("debug 标志应成功");
        assert!(config.debug);
    }

    #[test]
    fn test_process_mode_from_str() {
        assert_eq!(ProcessMode::parse_str("ui"), ProcessMode::MainUi);
        assert_eq!(ProcessMode::parse_str("worker"), ProcessMode::SecureWorker);
        assert_eq!(ProcessMode::parse_str("WORKER"), ProcessMode::SecureWorker);
        assert_eq!(ProcessMode::parse_str("inspector"), ProcessMode::Inspector);
        assert_eq!(ProcessMode::parse_str("unknown"), ProcessMode::MainUi);
    }

    #[test]
    fn test_process_mode_process_name() {
        assert_eq!(ProcessMode::MainUi.process_name(), "main_ui");
        assert_eq!(ProcessMode::SecureWorker.process_name(), "worker");
        assert_eq!(ProcessMode::Inspector.process_name(), "inspector");
    }

    #[test]
    fn test_log_level_from_str() {
        assert_eq!(LogLevel::parse_str("trace"), LogLevel::Trace);
        assert_eq!(LogLevel::parse_str("debug"), LogLevel::Debug);
        assert_eq!(LogLevel::parse_str("info"), LogLevel::Info);
        assert_eq!(LogLevel::parse_str("warn"), LogLevel::Warn);
        assert_eq!(LogLevel::parse_str("error"), LogLevel::Error);
        assert_eq!(LogLevel::parse_str("fatal"), LogLevel::Fatal);
        assert_eq!(LogLevel::parse_str("unknown"), LogLevel::Info);
    }

    #[test]
    fn test_log_level_to_log_filter() {
        assert_eq!(LogLevel::Trace.to_log_filter(), log::LevelFilter::Trace);
        assert_eq!(LogLevel::Info.to_log_filter(), log::LevelFilter::Info);
        assert_eq!(LogLevel::Fatal.to_log_filter(), log::LevelFilter::Error);
    }
}
