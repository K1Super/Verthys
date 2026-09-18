/*
 * @file entry_template.rs
 * @brief 入口文件单一职责模板 - 进程初始化的标准骨架
 *
 * 本模板定义进程入口函数 `entry_main` 的标准结构，展示合法职责范围与边界。
 * 实际项目中的 main.rs / lib.rs 应遵循此模式，确保入口层职责单一、可测试。
 *
 * =============================================================================
 * 入口文件合法职责（六项唯一允许行为）
 * =============================================================================
 * 1. 全局执行环境初始化（设置时区、字符集、堆分配器）
 * 2. 解析并校验命令行参数与配置文件，构造强类型启动参数对象
 * 3. 创建进程级别上下文容器（Context），挂载日志发送端、全局配置
 * 4. 创建本进程私有核心资源句柄（数据库连接池、IPC管道、CNG提供者等），
 *    并通过 ProcessGuard 注册，确保退出时自动释放
 * 5. 根据启动参数决定进程运行模式，调用对应的控制器入口方法
 * 6. 注册全局异常兜底钩子（panic hook）
 *
 * =============================================================================
 * 严格禁止的行为（CI 红线）
 * =============================================================================
 * - 在入口函数内编写加解密、文件 I/O、网络通信、数据解析转换等具体算法实现
 * - 直接调用底层工具库而不通过服务层接口
 * - 使用 println! / eprintln! 或直接日志输出（调试临时代码除外，上线前移除）
 * - 在入口中捕获异常并执行业务补偿（重试、回滚），应下沉至服务层
 *
 * =============================================================================
 * 资源管理
 * =============================================================================
 * - 进程级资源（日志管道、取消令牌、文件锁）通过 ProcessGuard 注册，
 *   确保进程退出时按注册逆序自动清理。
 * - 日志管道在 Drop 时自动调用 flush_and_shutdown，防止日志丢失。
 * - 取消令牌在 Drop 时触发 cancel，通知异步任务优雅终止。
 *
 * =============================================================================
 * 依赖方向
 * =============================================================================
 * 入口层仅依赖基础设施（infrastructure）和中间件（middleware），
 * 不依赖具体业务控制器（controller），避免入口层与业务逻辑耦合。
 */

#![allow(dead_code)]

use crate::infrastructure::app_paths::AppPaths;
use crate::infrastructure::console_handler;
use crate::infrastructure::log_pipe::{LogDaemon, LogEntry, LogLevel};
use crate::infrastructure::process_guard::{DropResource, ProcessGuard};
use crate::middleware::context::{Context, ProcessMode, StartupConfig};
use crate::middleware::panic_hook;
use crate::util::error::VerthysResult;

/// 进程入口函数模板，展示六项合法职责的完整流程。
///
/// # 执行顺序
/// 1. 全局环境初始化（由调用方在 main 提前执行）
/// 2. 解析命令行参数 → 构造 StartupConfig
/// 3. 解析应用数据目录 → 创建 AppPaths
/// 4. 创建日志管道（LogDaemon）→ 获取 LogSender
/// 5. 注册 panic hook（使用日志发送端）
/// 6. 注册控制台信号处理器（关联 CancellationToken）
/// 7. 创建 ProcessGuard，注册 LogDaemon 和 CancellationToken 资源
/// 8. 构建 Context，传入 LogSender、配置等
/// 9. 根据运行模式调用对应控制器入口
/// 10. 触发取消令牌，等待优雅退出
/// 11. 函数返回，ProcessGuard Drop 自动清理所有资源
///
/// # 错误处理
/// - 解析失败、路径无效等错误通过 `VerthysResult` 向上传播，
///   由调用方（main）捕获并输出友好错误信息后退出。
///
/// # 注意
/// 此函数不应包含任何业务逻辑分支或算法实现，仅做流程编排。
pub fn entry_main(mode: ProcessMode) -> VerthysResult<()> {
    // ===== 步骤 1: 全局执行环境初始化 =====
    // 实际项目中已在 main.rs 第一行调用 install_minimal

    // ===== 步骤 2: 解析并校验命令行参数 =====
    let args: Vec<String> = std::env::args().collect();
    let config: StartupConfig = crate::middleware::context::parse_config(&args)?;

    // ===== 步骤 3: 创建进程级上下文容器 =====
    // 解析应用数据目录（支持便携模式），确保目录存在
    let app_paths = AppPaths::resolve(config.data_dir.as_deref());
    app_paths.ensure_dirs().ok();

    let log_path = app_paths.log_path(mode.process_name());
    let log_daemon = LogDaemon::new(config.log_capacity, log_path);
    let log_sender = log_daemon.sender();

    // 记录进程启动事件（入口层唯一允许的日志输出）
    let _ = log_sender.send_allow_drop(LogEntry::new(
        LogLevel::Info,
        "entry",
        format!(
            "进程启动: mode={:?} pid={} data_dir_source={:?}",
            mode,
            std::process::id(),
            app_paths.source
        ),
    ));

    // ===== 升级 panic hook =====
    panic_hook::upgrade(log_sender.clone());

    // ===== 注册控制台信号处理器（CancellationToken） =====
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    if let Err(e) = console_handler::register_shutdown_token(shutdown_token.clone()) {
        log_sender.warn("entry", format!("控制台信号处理器注册失败: {}", e));
    }

    // ===== 步骤 4: 创建核心资源句柄并注册到 ProcessGuard =====
    let mut guard = ProcessGuard::new();

    // 注册 LogDaemon（确保退出时 flush）
    guard.register_rust(Box::new(LogDaemonResource {
        daemon: log_daemon.clone(),
    }));
    // 注册 CancellationToken
    guard.register_rust(Box::new(CancellationTokenResource {
        token: shutdown_token.clone(),
    }));

    // 构建 Context
    let context_config = crate::middleware::context::ContextConfig::from_startup(&config);
    let ctx = Context::new(mode, log_sender.clone(), context_config);

    // ===== 步骤 5: 根据运行模式调用对应的控制器入口 =====
    match mode {
        ProcessMode::MainUi => run_main_ui(ctx)?,
        ProcessMode::SecureWorker => run_secure_worker(ctx)?,
        ProcessMode::Inspector => run_inspector(ctx)?,
    }

    // ===== 触发优雅退出 =====
    shutdown_token.cancel();

    // ===== 进程退出：ProcessGuard 自动释放所有资源 =====
    drop(guard);

    Ok(())
}

/// 主 UI 进程入口（控制器层实际逻辑）
fn run_main_ui(ctx: Context) -> VerthysResult<()> {
    ctx.log_sender().info("entry", "主UI进程启动完成");
    Ok(())
}

/// 安全 Worker 进程入口（执行句柄继承自检）
fn run_secure_worker(ctx: Context) -> VerthysResult<()> {
    // 子进程启动后必须自检句柄继承标志，防止父进程意外传递可继承句柄。
    crate::infrastructure::handle_factory::validate_no_inherited_handles()
        .map_err(|e| crate::util::error::VerthysError::Internal(e))?;

    ctx.log_sender().info("entry", "安全Worker进程启动完成");
    Ok(())
}

/// 定时巡检进程入口
fn run_inspector(ctx: Context) -> VerthysResult<()> {
    ctx.log_sender().info("entry", "定时巡检进程启动完成");
    Ok(())
}

// ===== ProcessGuard 资源包装器 =====

/// LogDaemon 资源包装器，确保进程退出前 flush 所有日志。
struct LogDaemonResource {
    daemon: LogDaemon,
}

impl DropResource for LogDaemonResource {
    fn name(&self) -> &str {
        "LogDaemon"
    }

    fn cleanup(&mut self) {
        let _ = self.daemon.flush_and_shutdown(std::time::Duration::from_secs(3));
    }
}

/// CancellationToken 资源包装器，确保 Drop 时触发取消信号。
struct CancellationTokenResource {
    token: tokio_util::sync::CancellationToken,
}

impl DropResource for CancellationTokenResource {
    fn name(&self) -> &str {
        "CancellationToken"
    }

    fn cleanup(&mut self) {
        self.token.cancel();
    }
}