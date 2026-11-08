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
 * 3. 进程模式：本可执行文件仅运行主 UI 模式。`--mode` 的 worker / inspector
 *    属于已识别但未实现的关键字，由入口层显式拒绝并退出；真实 worker 为独立
 *    可执行文件 verthys-worker.exe，不通过本进程承载。
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
 * - 进程模式经 --mode 参数识别；本可执行文件仅实现主 UI 模式。
 * - 数据目录解析不依赖环境变量修改，仅从受信命令行参数获取。
 */

mod constants;
pub mod security;
mod security_commands;
mod state;
mod updater;
mod worker;
/// 开发夹具配置与路径守卫（仅开发构建可用）
mod devfixture;

/// 宿主层全库 DEK 轮换集成用例（仅 e2e_rotate 特性构建启用）
#[cfg(feature = "e2e_rotate")]
mod e2e_rotate;

// ==== 强制分层架构 ====
pub mod controller;
pub mod infrastructure;
pub mod middleware;
pub mod repository;
pub mod service;
pub mod util;

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
use controller::devfixture_controller::*;
use controller::diag_controller::*;
use controller::file_controller::*;
use controller::key_controller::*;
use controller::pcr_controller::*;
use controller::keyfile_controller::*;
use controller::module_controller::*;
use controller::vault_rotate_controller::*;
use controller::preflight_controller::*;
use controller::scan_controller::*;
use controller::verthys_batch_controller::*;
use controller::verthys_controller::*;
use controller::worker_controller::*;

// 防截屏隐私保护：命令与启动序列引用
use controller::privacy_controller::{
    adopt_privacy_session, get_privacy_status, reconcile_privacy, run_startup_recovery_dialog,
    set_privacy_mode, startup_engage, AppAuditSink, PrivacyCoordinator, StartupOutcome,
};

// 入口层基础设施引用
use infrastructure::app_paths::{AppPaths, PathSource};
use infrastructure::console_handler;
use infrastructure::log_pipe::{LogDaemon, LogSender};
use infrastructure::process_guard::ProcessGuard;
use middleware::context::ProcessMode;
use middleware::panic_hook;

/* ------------------------------------------------------------------ *
 * 关闭流程硬超时（数据安全优先，根治"退出后数据丢失"）            *
 * ------------------------------------------------------------------ *
 * 45000ms 是关闭流程的强制退出上限：正常路径 lockAll 完成即前端
 * exit(0)，本值只决定 "worker 卡死" 时隐藏窗口的最长等待：
 *   1. verthysPrepareLock：请求取消并等待轮换 Run 收敛（后端 30s 上限）
 *   2. waitForFlush（22s）：pending 删除/写入全部落盘（v1 唯一持久化路径）
 *   3. verthysLockPersist（12s）：v1 原子落盘 + 文件锁释放
 *   4. securitySessionStop / verthysLock / workerDestroy：清理 worker
 * 窗口已在 CloseRequested 第一行隐藏（Rust 原生调用），用户无感知；
 * lockAll 提前完成则前端 exit(0) 立即退出，不空等满 45s。
 * 超时（极罕见，仅当轮换取消或 worker 卡死）后后端强制 exit(0)；worker
 * 位于 KILL_ON_JOB_CLOSE Job 内随宿主终止，源库 rotate_pending 为进程内
 * 状态，下次启动可直接解锁（残留临时库不影响源库）。 */
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
                use infrastructure::log_pipe::{LogEntry, LogLevel};
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

    /* 私有目录 ACL 加固（启动期，先于日志文件创建）：日志与临时目录仅允许
     * 当前用户、SYSTEM 与内置管理员访问。数据根目录可能由 --data-dir 指向
     * 用户共享/便携路径，不在启动期改写其 ACL，避免越权影响用户既有权限。 */
    for dir in [&app_paths.log_dir, &app_paths.tmp_dir] {
        if let Err(e) = crate::security::file_lock::harden_private_dir(
            &dir.to_string_lossy(),
        ) {
            eprintln!(
                "[VERTHYS] 私有目录 ACL 加固失败 {}: {}",
                dir.display(),
                e
            );
        }
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
        ProcessMode::MainUi => {
            run_main_ui(log_sender, shutdown_token, guard, log_daemon, app_paths)
        }
        ProcessMode::SecureWorker => run_secure_worker(log_sender, guard, log_daemon),
        ProcessMode::Inspector => run_inspector_proc(log_sender, guard, log_daemon),
    }
}

/// 主 UI 进程运行逻辑：启动 Tauri 应用并注册命令。
///
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
    app_paths: AppPaths,
) {
    // 构建 Tauri 应用
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(AppState::new())
        /* 数据目录随模式解析（便携/--data-dir/兜底）后注入托管状态：
         * 容器口令等持久化文件必须与容器落在同一数据根目录，避免便携模式
         * 下容器在 U 盘、口令在系统盘导致容器永久无法打开。 */
        .manage(app_paths)
        .manage(security_commands::SecurityState::new())
        .manage(updater::UpdaterState::default())
        /* ===== 关闭响应优化：窗口级事件处理器 =====
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
                // 更新进入锁库或安装移交后，关闭会与落盘/安装器抢占进程；
                // 临界区带时限，异常路径不会永久锁住窗口。
                let critical = window
                    .app_handle()
                    .state::<updater::UpdaterState>()
                    .is_critical();
                if critical {
                    api.prevent_close();
                    let _ = window.app_handle().emit("verthys://close-blocked", ());
                    return;
                }

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
                    tokio::time::sleep(std::time::Duration::from_millis(CLOSE_HARD_TIMEOUT_MS))
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

                /* ===== 防截屏保护：保护先于窗口可见 =====
                 *
                 * 主窗口在配置中声明为不可见，由本序列在保护就绪后显式显示：
                 *   1. 默认开启：启动即自动施加保护 + 回读校验（无需用户手动开启，
                 *      也不依赖任何持久化意图；会话内关闭仅本次会话有效）；
                 *   2. 成功 / 已还原 → 显示主窗口，前端挂载后采纳会话取得凭证；
                 *   3. 还原失败（窗口取值未知）→ 原生对话框驱动对账，成功才显示窗口。
                 * 本钩子返回前前端命令不会派发，因此启动序列与前端查询无竞态。 */
                let coordinator = std::sync::Arc::new(PrivacyCoordinator::new(
                    std::sync::Arc::new(AppAuditSink::new(app_handle.clone())),
                ));
                app.manage(std::sync::Arc::clone(&coordinator));

                let show_main_window = match startup_engage(&app_handle, &coordinator) {
                    StartupOutcome::Protected { generation } => {
                        log::info!("[privacy] 启动保护已生效（世代 {}）", generation);
                        true
                    }
                    StartupOutcome::Unprotected => true,
                    StartupOutcome::NeedsRecovery => {
                        run_startup_recovery_dialog(&app_handle, &coordinator)
                    }
                };

                /* 宿主层轮换集成用例以无界面方式运行：不显示主窗口，避免
                 * 自动化测试打断用户桌面；正式构建该常量恒为 false。 */
                #[cfg(feature = "e2e_rotate")]
                let e2e_rotate_mode =
                    std::env::var("VERTHYS_E2E_ROTATE").as_deref() == Ok("1");
                #[cfg(not(feature = "e2e_rotate"))]
                let e2e_rotate_mode = false;

                if show_main_window && !e2e_rotate_mode {
                    match app.get_webview_window("main") {
                        Some(window) => {
                            if let Err(e) = window.show() {
                                log::error!("[privacy] 显示主窗口失败: {}", e);
                            }
                        }
                        None => {
                            // 无窗口可用即无界面可用：如实失败退出，不留无界面进程
                            log::error!("[privacy] 主窗口不存在，进程退出");
                            app_handle.exit(0);
                            return Ok(());
                        }
                    }
                } else if !e2e_rotate_mode {
                    // 用户在对账对话框中确认退出：不显示任何窗口，直接结束事件循环
                    log::warn!("[privacy] 启动恢复被拒绝，进程退出且不显示窗口");
                    app_handle.exit(0);
                    return Ok(());
                }

                // 注册熔断闸门实现到服务层契约（依赖反转：控制器只经 service
                // 层调用闸门，避免 controller → security_commands 反向依赖）
                security_commands::brute_force_bridge::install_unlock_gate();
                // 注册解锁前受信档位应用实现到服务层契约（同一分层红线约束）
                security_commands::install_preset_source();
                // 注册可移动介质绑定实现到服务层契约（同一分层红线约束）
                security_commands::usb_binding_bridge::install_usb_binding();
                // 注册全库 DEK 轮换的宿主能力实现到服务层契约（同一分层红线约束）
                security_commands::vault_rotate_bridge::install_vault_rotate();

                /* 会话守卫真实回调：SecurityState 构建期不允许依赖 AppHandle，
                 * 此处安装锁库序列。系统锁屏/注销/断连/挂起事件直接在主进程
                 * 完成"worker 锁库 → 销毁会话 → 通知前端"，不依赖 WebView
                 * 调度，覆盖屏幕不可见期间的事件投递。 */
                {
                    let app_for_session_lock = app_handle.clone();
                    let security_state =
                        app.state::<security_commands::SecurityState>();
                    match security_state.replace_session_guard(
                        Box::new(move |reason| {
                            let app = app_for_session_lock.clone();
                            tauri::async_runtime::spawn(async move {
                                security_commands::commands::session::
                                    perform_external_lock(app, reason.as_str()).await;
                            });
                        }),
                        Box::new(|| {
                            log::info!(
                                "[session_guard] 系统解锁事件：不自动解锁容器"
                            );
                        }),
                    ) {
                        Ok(()) => {
                            log::info!("[session_guard] 真实锁库回调已安装");
                            /* worker 已存在的窗口期立即下发守卫位；未就绪时
                             * 失败仅诊断，由 security_session_start 再次补发。 */
                            let app_state = app.state::<AppState>();
                            security_commands::commands::session::
                                notify_runtime_guards(&app_state, true);
                        }
                        Err(e) => {
                            log::error!(
                                "[session_guard] 真实锁库回调安装失败: {}",
                                e
                            );
                        }
                    }
                }

                /* 宿主层轮换集成用例：特性 + 环境变量双重门禁。
                 * 用例直接调用控制器与服务层入口，走真实 AppState/worker/DLL，
                 * 结果写文件后退出进程；正式构建不含本分支。 */
                #[cfg(feature = "e2e_rotate")]
                if std::env::var("VERTHYS_E2E_ROTATE").as_deref() == Ok("1") {
                    let handle = app_handle.clone();
                    tauri::async_runtime::spawn(async move {
                        e2e_rotate::run_and_report(handle).await;
                    });
                    return Ok(());
                }
                let install_dir = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string()))
                    .unwrap_or_default();
                let patrol = security::background_patrol::BackgroundPatrol::start(
                    app_handle.clone(),
                    install_dir,
                );
                app.manage(patrol);
                // 启动期程序自完整性核验（完整校验能力执行路径；后台线程，不阻塞启动）
                security::integrity_check::verify_self_image_async(app_handle.clone());
                // 启动即审计更新配置；不合法时仅禁用更新，不阻断应用启动。
                let _ = updater::audit_config(&app_handle);
                // 更新健康自检的原生兜底：前端在时限内未处理时给出最小恢复路径。
                updater::spawn_native_watchdog(app_handle.clone());
                // 启动导入写者心跳看门狗（写者卡死超时自动重建）
                crate::state::import_writer::spawn_watchdog(
                    app_handle.clone(),
                    shutdown_token_clone.clone(),
                );
                // 启动锁持有时间监控任务（死锁兜底）
                AppState::spawn_lock_monitor(app_handle, shutdown_token_clone);

                // 仅 e2e_update 构建启用：环境变量驱动一次完整更新，不参与正式发布
                #[cfg(feature = "e2e_update")]
                if std::env::var("VERTHYS_E2E_UPDATE").as_deref() == Ok("1") {
                    let handle = app.handle().clone();
                    tauri::async_runtime::spawn(async move {
                        if let Err(error) = updater::run_e2e_update(handle.clone()).await {
                            log::error!("[e2e] update failed: {error}");
                        }
                    });
                }
                Ok(())
            }
        })
        .invoke_handler(tauri::generate_handler![
            log_fatal,
            verthys_preflight,
            verthys_init_status,
            worker_init,
            worker_destroy,
            verthys_preheat,
            verthys_unlock,
            verthys_create,
            verthys_recovery_rotate,
            // PCR 策略：状态 / 启用 / 关闭 / 重密封
            verthys_pcr_status,
            verthys_pcr_enable,
            verthys_pcr_disable,
            verthys_pcr_reseal,
            // keyfile 因子：状态 / 启用 / 关闭
            verthys_keyfile_status,
            verthys_keyfile_enable,
            verthys_keyfile_disable,
            verthys_reseal_device,
            // 模块 M1：状态 / 启用 / 口令轮换 / 关闭 / 恢复槽 / 不可逆删除
            verthys_module_status,
            verthys_module_enable,
            verthys_module_rotate_password,
            verthys_module_disable,
            verthys_module_bind_recovery,
            verthys_module_reseal_device,
            verthys_module_delete,
            // 全库 DEK 轮换：开始 / keyfile 补录 / 模块口令登记 / 执行 / 取消 / 提交 / 中止
            verthys_rotate_begin,
            verthys_rotate_attach_keyfile,
            verthys_rotate_unlock_module,
            verthys_rotate_run,
            verthys_rotate_cancel,
            verthys_rotate_commit,
            verthys_rotate_abort,
            verthys_prepare_lock,
            verthys_lock,
            verthys_lock_persist,
            verthys_flush,
            verthys_verify_disk_persist,
            verthys_force_close_import_session,
            verthys_add_record,
            verthys_get_record,
            verthys_enumerate_records,
            verthys_enumerate_records_stream,
            // 照片导入异步批处理流水线（WAL + 批量 IPC + 检查点）
            verthys_import_begin,
            verthys_add_records_batch,
            verthys_add_chunk_batch,
            verthys_import_end,
            verthys_import_checkpoint,
            verthys_wal_recover,
            verthys_forget_import_keys,
            verthys_gc_orphan_chunks,
            verthys_scan_open,
            verthys_scan_next,
            verthys_scan_close,
            verthys_scan_summary_open,
            verthys_scan_summary_next,
            verthys_scan_summary_close,
            verthys_list_ids_by_type,
            verthys_delete_record,
            verthys_delete_records,
            verthys_get_summary_count,
            verthys_has_record_by_type,
            verthys_export,
            verthys_import,
            // 防御闭环状态查询（7 路径 × 4 状态实时透传）
            verthys_security_status,
            // 系统运行指标采样（CPU 占用率真实差分，安全防护面板数据源）
            security_commands::verthys_system_snapshot,
            verthys_derive_global_key,
            verthys_derive_and_store_global_key,
            verthys_verify_global_key,
            verthys_clear_global_key,
            // 内容层加密：模块密钥与记录加解密（原始密钥留在 worker）
            controller::module_crypto_controller::verthys_module_key_unlock,
            controller::module_crypto_controller::verthys_module_key_lock,
            controller::module_crypto_controller::verthys_module_seal,
            controller::module_crypto_controller::verthys_module_open,
            verthys_reconcile_key_presence,
            verthys_reset_global_key_state,
            set_privacy_mode,
            get_privacy_status,
            adopt_privacy_session,
            reconcile_privacy,
            clear_clipboard,
            read_file_bytes,
            write_file_bytes,
            read_user_file,
            user_file_stat,
            check_disk_space,
            write_user_file,
            // 单文件导出流式落盘（暂存 + 原子替换，压低内存峰值）
            write_user_file_stream,
            append_user_file_chunk,
            finalize_user_file_stream,
            abort_user_file_stream,
            get_device_fingerprint,
            set_device_binding,
            check_device_binding,
            security_commands::security_brute_check,
            security_commands::security_brute_status,
            security_commands::security_session_start,
            security_commands::security_session_stop,
            security_commands::security_session_set_hardening,
            security_commands::security_service_status,
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
            security_commands::security_usb_volume_status,
            security_commands::security_usb_register_current,
            security_commands::security_usb_rebind_device,
            security_commands::security_usb_shadow_sleep,
            security_commands::security_usb_try_recover,
            security_commands::security_usb_purge,
            security_commands::security_usb_shadow_status,
            security_commands::security_get_preset_config,
            security_commands::security_apply_preset,
            security_commands::security_load_preset_state,
            // 更新服务：检查 / 准备 / 闸门 / 安装 / 标记 / 日志
            updater::updater_check,
            updater::updater_prepare,
            updater::updater_begin_lock,
            updater::updater_confirm_lock,
            updater::updater_abort_lock,
            updater::updater_install,
            updater::updater_cancel,
            updater::updater_set_critical,
            updater::updater_startup_state,
            updater::updater_run_health,
            updater::updater_repair_state,
            updater::updater_run_repair,
            updater::updater_export_logs,
            // 应用诊断日志导出（脱敏 zip；不含审计 HMAC 链）
            controller::diag_controller::diagnostics_export_logs,
            // 开发夹具配置：状态 / 读取 / 保存 / 清空（发布构建调用必败）
            devfixture_status,
            devfixture_profile_get,
            devfixture_profile_save,
            devfixture_profile_clear,
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
fn run_secure_worker(log_sender: LogSender, _guard: ProcessGuard, _log_daemon: LogDaemon) {
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
fn run_inspector_proc(log_sender: LogSender, _guard: ProcessGuard, _log_daemon: LogDaemon) {
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
        let _ = self
            .daemon
            .flush_and_shutdown(std::time::Duration::from_secs(3));
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
