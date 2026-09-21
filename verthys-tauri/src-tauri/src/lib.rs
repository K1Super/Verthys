/*
 * @file lib.rs
 * @brief Tauri 应用主入口 - 进程模式派发与资源生命周期管理
 *
 * 本文件是 Verthys 桌面的根入口，负责根据运行模式（主 UI / Worker / 巡检）
 * 初始化进程级基础设施，派发控制权至对应的业务模块。
 * 入口层遵循单一职责原则，仅做环境配置、参数解析、资源注册与流程编排，
 * 不包含任何业务逻辑实现。
 *
 * =============================================================================
 * 架构约束
 * =============================================================================
 * 1. 分层隔离：本文件仅依赖 infrastructure、middleware 及 controller 层公开接口，
 *    不依赖具体业务实现细节（如 util 内部函数）。
 * 2. 资源管理：进程级资源（日志管道、取消令牌）通过 ProcessGuard 注册，
 *    确保进程退出时按逆序自动清理。
 * 3. 模式派发：通过 --mode 参数决定启动模式，分离 UI 进程与安全 Worker 进程，
 *    Worker 模式跳过 WebView 初始化，缩小攻击面。
 * 4. 敏感操作下沉：所有加解密、密钥派生、容器操作由 verthys-worker 子进程执行，
 *    主进程永不加载 DLL 或持有 VerthysHandle。
 *
 * =============================================================================
 * 入口文件合法职责（六项）
 * =============================================================================
 * 1. 全局执行环境初始化（时区、字符集、堆分配器）—— 在 main.rs 完成
 * 2. 解析并校验命令行参数，构造强类型启动参数对象
 * 3. 创建进程级上下文容器（Context），挂载日志发送端、全局配置
 * 4. 创建本进程私有核心资源句柄（日志管道、取消令牌），通过 ProcessGuard 注册
 * 5. 根据启动参数决定运行模式，调用对应的控制器入口方法
 * 6. 注册全局异常兜底钩子（panic hook）
 *
 * =============================================================================
 * 依赖方向
 * =============================================================================
 * entry → controller → service → repository → util
 * entry → middleware → infrastructure → util
 * 中间件层与基础设施层为横切关注点，由入口层注入。
 *
 * =============================================================================
 * 安全红线（CI 强制）
 * =============================================================================
 * - 入口层不得编写加解密、文件 I/O、网络通信等具体算法实现。
 * - 不得直接调用底层工具库而不通过服务层接口。
 * - 日志输出必须通过 LogSender，不得使用 println! / eprintln!。
 * - 异常补偿逻辑必须下沉至服务层，入口仅做错误传播与进程退出。
 *
 * =============================================================================
 * 版本与兼容
 * =============================================================================
 * - 保留 run() 函数作为 run_ui() 的兼容别名，以支持旧调用点。
 * - 新增进程模式（Worker / Inspector）通过 --mode 参数区分。
 * - 数据目录解析不依赖环境变量修改，仅从受信命令行参数获取。
 */

mod worker;
mod security;
mod security_commands;
mod state;
mod constants;

// ==== 强制分层架构 ====
#[allow(dead_code)]
pub mod util;
#[allow(dead_code)]
pub mod infrastructure;
#[allow(dead_code)]
pub mod middleware;
#[allow(dead_code)]
pub mod repository;
#[allow(dead_code)]
pub mod service;
#[allow(dead_code)]
pub mod controller;
#[allow(dead_code)]
pub mod entry_template;

// 启动资源哈希校验：由 build.rs 生成 dist 目录 SHA-256 清单
mod resource_hashes {
    include!(concat!(env!("OUT_DIR"), "/resource_hashes.rs"));
}

// DLL 完整性校验：由 build.rs 生成 verthys.dll SHA-256 哈希
mod dll_hash {
    include!(concat!(env!("OUT_DIR"), "/dll_hash.rs"));
}

use state::AppState;
use tauri::{Emitter, Manager};

// 控制器命令引用
use controller::clipboard_controller::*;
use controller::device_controller::*;
use controller::diag_controller::*;
use controller::file_controller::*;
use controller::key_controller::*;
use controller::preflight_controller::*;
use controller::scan_controller::*;
use controller::verthys_controller::*;
use controller::verthys_batch_controller::*;
use controller::worker_controller::*;

// 入口层基础设施引用
use infrastructure::app_paths::{AppPaths, PathSource};
use infrastructure::console_handler;
use infrastructure::log_pipe::{LogDaemon, LogSender};
use infrastructure::process_guard::ProcessGuard;
use middleware::context::ProcessMode;
use middleware::panic_hook;

/* ------------------------------------------------------------------ *
 * 关闭流程硬超时（企业级数据安全优先，根治"退出后数据丢失"）            *
 * ------------------------------------------------------------------ *
 * 45000ms 覆盖 lockAll 内部 40s 安全网 + 5s 余量，确保：
 *   1. waitForFlush（22s）：pending 删除/写入全部落盘（v1 唯一持久化路径）
 *   2. verthysLockPersist（12s）：v1 原子落盘 + 文件锁释放
 *   3. securitySessionStop / verthysLock / workerDestroy：清理 worker
 * 窗口已在 CloseRequested 第一行隐藏（Rust 原生调用），用户无感知；
 * lockAll 提前完成则前端 exit(0) 立即退出，不空等满 45s。
 * 超时（极罕见，仅当 worker 卡死）后后端强制 app_handle.exit(0)。 */
const CLOSE_HARD_TIMEOUT_MS: u64 = 45000;

/* ------------------------------------------------------------------ *
 * 日志桥接器：将 log crate 宏重定向至异步日志管道                       *
 * ------------------------------------------------------------------ */

/// 将 `log` crate 的宏（info! / warn! 等）桥接至异步日志管道。
///
/// 实现 `log::Log` trait，使所有通过 `log` 宏输出的日志（包括依赖库的）
/// 均进入 `LogSender`，统一走异步队列，避免直接输出到 stderr。
/// 该桥接器在入口层初始化，与日志管道同生命周期。
struct LogPipeBridge {
    sender: std::sync::Arc<std::sync::Mutex<Option<LogSender>>>,
}
impl log::Log for LogPipeBridge {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if let Ok(guard) = self.sender.lock() {
            if let Some(sender) = guard.as_ref() {
                use infrastructure::log_pipe::{LogLevel, LogEntry};
                let entry = LogEntry::new(
                    match record.level() {
                        log::Level::Error => LogLevel::Error,
                        log::Level::Warn => LogLevel::Warn,
                        log::Level::Info => LogLevel::Info,
                        log::Level::Debug => LogLevel::Debug,
                        log::Level::Trace => LogLevel::Trace,
                    },
                    record.target(),
                    record.args().to_string(),
                );
                let _ = sender.send_allow_drop(entry);
            }
        }
    }
    fn flush(&self) {}
}

// ===== 模式派发入口 =====

/// 兼容旧接口：运行主 UI 进程。
///
/// 保留以维持旧调用点兼容性，内部直接调用 `run_ui()`。
pub fn run() {
    run_ui();
}

/// 启动主 UI 进程（带 WebView）。
///
/// 入口点，由 `main.rs` 在 `--mode` 默认或显式指定为 `ui` 时调用。
pub fn run_ui() {
    run_process(ProcessMode::MainUi);
}

/// 启动安全 Worker 进程（无 WebView）。
///
/// 跳过 UI 初始化，仅启动 IPC 服务，用于执行敏感操作。
pub fn run_worker() {
    run_process(ProcessMode::SecureWorker);
}

/// 启动定时巡检进程。
///
/// 独立进程执行系统健康监控与清理任务。
pub fn run_inspector() {
    run_process(ProcessMode::Inspector);
}

/// 通用进程初始化流程，根据模式派发。
///
/// 所有进程模式共享的初始化步骤：
/// 1. 解析命令行参数。
/// 2. 解析应用数据目录（AppPaths）。
/// 3. 创建日志管道（LogDaemon）并获取发送端。
/// 4. 升级 panic hook（使用日志管道）。
/// 5. 桥接 `log` 宏至日志管道。
/// 6. 注册控制台信号处理器（CancellationToken）。
/// 7. 创建 ProcessGuard，注册日志管道与取消令牌。
/// 8. 执行资源完整性校验（release 模式阻断启动，dev 模式警告）。
/// 9. 按模式调用对应的运行函数。
///
/// 模式分支：
/// - MainUi：启动 Tauri 应用（含 WebView）。
/// - SecureWorker：进入 IPC 主循环（无 WebView）。
/// - Inspector：进入定时巡检循环。
fn run_process(mode: ProcessMode) {
    // 命令行参数解析
    let args: Vec<String> = std::env::args().collect();
    let config = match middleware::context::parse_config(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[VERTHYS] 启动参数校验失败: {}", e);
            std::process::exit(1);
        }
    };

    // 应用数据目录解析（支持便携模式，不修改环境变量）
    let app_paths = AppPaths::resolve(config.data_dir.as_deref());
    if let Err(e) = app_paths.ensure_dirs() {
        eprintln!("[VERTHYS] 数据目录创建失败（将降级日志）: {}", e);
    }

    // 创建日志管道
    let log_path = app_paths.log_path(mode.process_name());
    let log_daemon = LogDaemon::new(config.log_capacity, log_path);
    let log_sender = log_daemon.sender();

    // 记录启动事件（入口层唯一允许的日志调用）
    log_sender.info(
        "entry",
        format!(
            "进程启动: mode={} pid={} data_dir_source={:?} data_dir={}",
            mode,
            std::process::id(),
            app_paths.source,
            app_paths.data_dir.display()
        ),
    );
    if app_paths.source == PathSource::ExeDirFallback {
        log_sender.warn(
            "entry",
            "数据目录回退到 <exe_dir>/data（LocalAppData 不可用或只读介质）",
        );
    }

    // 升级 panic hook
    panic_hook::upgrade(log_sender.clone());

    // 桥接 log 宏
    let log_bridge = LogPipeBridge {
        sender: std::sync::Arc::new(std::sync::Mutex::new(Some(log_sender.clone()))),
    };
    let _ = log::set_logger(Box::leak(Box::new(log_bridge)));
    log::set_max_level(config.log_level.to_log_filter());

    // 注册控制台信号处理器（取消令牌）
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    if let Err(e) = console_handler::register_shutdown_token(shutdown_token.clone()) {
        log_sender.warn("entry", format!("控制台信号处理器注册失败: {}", e));
    }

    // 进程资源守卫：注册日志管道与取消令牌，确保退出时自动清理
    let mut guard = ProcessGuard::new();
    guard.register_rust(Box::new(LogDaemonResource {
        daemon: log_daemon.clone(),
    }));
    guard.register_rust(Box::new(CancellationTokenResource {
        token: shutdown_token.clone(),
    }));

    // 前端资源完整性校验（release 模式强制阻断）
    if let Err(e) = infrastructure::resource_guard::verify_resource_hashes() {
        if !cfg!(debug_assertions) {
            log_sender.error("entry", format!("资源完整性校验失败，拒绝启动: {}", e));
            std::process::exit(1);
        } else {
            log_sender.warn("entry", format!("资源完整性校验失败（dev模式警告）: {}", e));
        }
    }

    // 构建上下文配置
    let context_config = middleware::context::ContextConfig::from_startup(&config);
    let _ctx = middleware::context::Context::new(mode, log_sender.clone(), context_config);

    // 按模式派发
    match mode {
        ProcessMode::MainUi => run_main_ui(log_sender, shutdown_token, guard, log_daemon),
        ProcessMode::SecureWorker => run_secure_worker(log_sender, guard, log_daemon),
        ProcessMode::Inspector => run_inspector_proc(log_sender, guard, log_daemon),
    }
}

/// 主 UI 进程运行逻辑：启动 Tauri 应用并注册命令。
///
/// 在 Tauri 应用启动前设置 WebView2 硬件加速环境变量；
/// 通过 `app.run` 事件循环处理 `ExitRequested` 事件，
/// 确保在运行时仍存活时安全销毁 WorkerSession，避免孤儿进程。
///
/// # 资源生命周期
/// - `ProcessGuard` 持有的资源（取消令牌、日志管道）在函数返回时由 Drop 逆序释放。
/// - `AppState` 中的 WorkerSession 在 `ExitRequested` 时显式销毁。
fn run_main_ui(
    log_sender: LogSender,
    shutdown_token: tokio_util::sync::CancellationToken,
    _guard: ProcessGuard,
    _log_daemon: LogDaemon,
) {
    // 设置 WebView2 硬件加速参数（在 WebView2 实例启动前生效）
    #[cfg(windows)]
    {
        std::env::set_var(
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
            "--enable-gpu-rasterization --enable-zero-copy --ignore-gpu-blocklist",
        );
    }

    // 构建 Tauri 应用
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .manage(AppState::new())
        .manage(security_commands::SecurityState::new())
        /* ===== ★ 企业级关闭响应优化：窗口级事件处理器 =====
         *
         * 根因：旧实现前端 `await getCurrentWindow().hide()` 为 IPC 往返，
         *   后端事件循环繁忙时 hide() 的 IPC 被排队 → 窗口实际隐藏延迟数秒。
         *
         * 做法：CloseRequested 在 Rust 后端直接处理（零 IPC 延迟）：
         *   1. api.prevent_close() — 阻止默认关闭（窗口销毁会终止 WebView JS 引擎）
         *   2. window.hide() — Rust 原生调用 Win32 ShowWindow(SW_HIDE)，微秒级
         *   3. emit("verthys://cleanup-and-exit") — 通知前端 JS 执行 lockAll 异步清理
         *   4. tokio::spawn 45s 超时兜底 — 前端卡死时强制 app_handle.exit(0)
         *
         * 效果：窗口在用户点击关闭按钮的瞬间消失（微秒级），
         *   lockAll 在后台异步执行（数据落盘），完成后前端调用 exit(0) 退出进程。
         *   后端 45s 超时确保进程必然退出（防 worker 卡死导致僵尸进程）。
         */
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // 1. 阻止默认关闭（防止 WebView 销毁终止 JS 引擎，导致 lockAll 无法执行）
                api.prevent_close();

                // 2. 立即隐藏窗口（Rust 原生调用，零 IPC 延迟，微秒级）
                let _ = window.hide();

                // 3. 通知前端执行异步清理（lockAll: waitForFlush → 清空缓存 → verthysLockPersist → 销毁 worker）
                let _ = window.app_handle().emit("verthys://cleanup-and-exit", ());

                // 4. 后端 45s 超时兜底：前端 JS 卡死时强制退出进程
                //    覆盖 lockAll 内部 40s 安全网 + 5s 余量
                let app_handle = window.app_handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        CLOSE_HARD_TIMEOUT_MS,
                    ))
                    .await;
                    log::warn!(
                        "[close] 关闭超时 {}ms，前端未自行退出，后端强制终止进程",
                        CLOSE_HARD_TIMEOUT_MS
                    );
                    app_handle.exit(0);
                });
            }
        })
        .setup({
            let shutdown_token_clone = shutdown_token.clone();
            move |app| {
                let app_handle = app.handle().clone();
                let install_dir = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string()))
                    .unwrap_or_default();
                let patrol = security::background_patrol::BackgroundPatrol::start(
                    app_handle.clone(),
                    install_dir,
                );
                app.manage(patrol);
                // 启动锁持有时间监控任务（死锁兜底）
                AppState::spawn_lock_monitor(app_handle, shutdown_token_clone);
                Ok(())
            }
        })
        .invoke_handler(tauri::generate_handler![
            diag_info,
            log_fatal,
            verthys_preflight,
            verthys_init_status,
            worker_init,
            worker_destroy,
            verthys_preheat,
            verthys_unlock,
            verthys_create,
            verthys_lock,
            verthys_lock_persist,
            verthys_flush,
            verthys_verify_disk_persist,
            verthys_add_record,
            verthys_get_record,
            verthys_enumerate_records,
            verthys_enumerate_records_stream,
            // ★ 照片导入异步批处理流水线（WAL + 批量 IPC + 检查点）
            verthys_import_begin,
            verthys_add_records_batch,
            verthys_import_end,
            verthys_import_checkpoint,
            verthys_wal_recover,
            verthys_scan_open,
            verthys_scan_next,
            verthys_scan_close,
            verthys_scan_abort,
            verthys_scan_summary_open,
            verthys_scan_summary_next,
            verthys_scan_summary_close,
            verthys_scan_summary_abort,
            verthys_delete_record,
            verthys_delete_records,
            verthys_get_summary_count,
            verthys_has_record_by_type,
            verthys_export,
            verthys_import,
            verthys_change_password,
            // ★ 防御闭环状态查询（7 路径 × 4 状态实时透传）
            verthys_security_status,
            verthys_derive_global_key,
            verthys_verify_global_key,
            verthys_derive_subkey,
            verthys_clear_global_key,
            verthys_reconcile_key_presence,
            set_privacy_mode,
            clear_clipboard,
            restore_privacy_mode,
            read_file_bytes,
            write_file_bytes,
            read_user_file,
            write_user_file,
            get_device_fingerprint,
            set_device_binding,
            check_device_binding,
            security_commands::security_brute_check,
            security_commands::security_brute_record_failure,
            security_commands::security_brute_record_success,
            security_commands::security_brute_clear_purge,
            security_commands::security_brute_status,
            security_commands::security_session_start,
            security_commands::security_session_stop,
            security_commands::security_session_set_high_security,
            security_commands::security_module_patrol,
            security_commands::security_add_trusted_path,
            security_commands::security_clear_trusted_paths,
            security_commands::security_cleanup_recent,
            security_commands::security_secure_delete,
            security_commands::security_cleanup_crash_residue,
            security_commands::security_harden_private_dir,
            security_commands::security_usb_read_serial,
            security_commands::security_usb_register_device,
            security_commands::security_usb_check_clone,
            security_commands::security_usb_shadow_sleep,
            security_commands::security_usb_try_recover,
            security_commands::security_usb_purge,
            security_commands::security_usb_shadow_status,
            security_commands::security_get_preset_config,
            security_commands::security_generate_auth_token,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    let log_sender_for_exit = log_sender.clone();
    let shutdown_token_for_exit = shutdown_token.clone();

    // 事件循环：在退出请求时主动销毁 WorkerSession，防止孤儿进程
    app.run(move |app_handle, event| match event {
        tauri::RunEvent::ExitRequested { .. } => {
            let app_state = app_handle.state::<AppState>();
            if app_state.has_session() {
                log_sender_for_exit.info(
                    "entry",
                    "应用退出请求：显式销毁 worker session（防止孤儿进程）",
                );
                app_state.set_session(None);
            }
        }
        tauri::RunEvent::Exit => {
            log_sender_for_exit.info("entry", "主 UI 进程准备退出，触发优雅关闭");
            shutdown_token_for_exit.cancel();
        }
        _ => {}
    });

    // ProcessGuard 在此函数返回时 Drop，逆序释放资源
}

/// 安全 Worker 进程运行逻辑：无 WebView，仅 IPC 服务。
///
/// 启动后执行句柄继承自检，若失败则退出。
/// 后续进入无限循环等待 IPC 指令，实际交互由 `WorkerSession` Actor 处理。
fn run_secure_worker(
    log_sender: LogSender,
    _guard: ProcessGuard,
    _log_daemon: LogDaemon,
) {
    log_sender.info("entry", "安全 Worker 进程启动");

    if let Err(e) = infrastructure::handle_factory::validate_no_inherited_handles() {
        log_sender.error("entry", format!("子进程句柄继承自检失败: {}", e));
        std::process::exit(1);
    }

    log_sender.info("entry", "安全 Worker 进程启动完成，等待 IPC 指令");

    // TODO：接入 WorkerSession Actor 主循环
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

/// 定时巡检进程运行逻辑。
///
/// 独立进程循环执行系统健康监控、模块白名单、USB 检测等任务。
fn run_inspector_proc(
    log_sender: LogSender,
    _guard: ProcessGuard,
    _log_daemon: LogDaemon,
) {
    log_sender.info("entry", "定时巡检进程启动");
    loop {
        // TODO：接入安全巡检逻辑
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

// ===== ProcessGuard 资源包装器 =====

/// 日志管道资源包装器，用于 ProcessGuard。
///
/// Drop 时触发 `flush_and_shutdown`，确保日志在进程退出前排空。
struct LogDaemonResource {
    daemon: LogDaemon,
}

impl infrastructure::process_guard::DropResource for LogDaemonResource {
    fn name(&self) -> &str {
        "LogDaemon"
    }

    fn cleanup(&mut self) {
        let _ = self.daemon.flush_and_shutdown(std::time::Duration::from_secs(3));
    }
}

/// 取消令牌资源包装器，用于 ProcessGuard。
///
/// Drop 时调用 `cancel()`，触发所有监听取消令牌的任务退出。
struct CancellationTokenResource {
    token: tokio_util::sync::CancellationToken,
}

impl infrastructure::process_guard::DropResource for CancellationTokenResource {
    fn name(&self) -> &str {
        "CancellationToken"
    }

    fn cleanup(&mut self) {
        self.token.cancel();
    }
}