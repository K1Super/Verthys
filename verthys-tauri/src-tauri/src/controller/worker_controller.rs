/*
 * @file controller/worker_controller.rs
 * @brief Worker 子进程生命周期控制器 - 启动、监控与销毁
 *
 * 本模块管理 verthys-worker 子进程的完整生命周期，包括启动前的预检（架构一致性、
 * 依赖可用性、DLL 完整性）、异步启动（超时控制）、就绪检测（区分加载器级失败
 * 与应用层崩溃）、健康监控（定期存活检查）及优雅销毁（等待 IO 完成）。
 *
 * =============================================================================
 * 核心设计
 * =============================================================================
 * - 状态机驱动：进程状态遵循 Uninitialized → Initializing → Ready → ShuttingDown
 *   → Failed/Uninitialized 转移，非法状态转换返回错误。
 * - 预检缓存：应用启动时执行一次预检（DLL 哈希、依赖扫描、架构校验），
 *   结果缓存于 AppState，避免每次初始化重复开销。
 * - 并发控制：通过 InitLock 确保同一时刻仅一个初始化流程执行；若已有初始化
 *   进行中，后续请求通过 watch 通道等待最终状态（最长 3 秒）。
 * - 异步超时：spawn 阶段超时 15 秒，就绪等待超时 5 秒，超时后强制终止子进程
 *   并回收资源。
 * - 失败分类：就绪检测失败时，根据退出码和 stderr 区分“加载器级失败”
 *   （缺失依赖/架构损坏）与“应用层崩溃”，返回不同错误码以指导排查。
 * - 健康检查：后台线程每 10 秒检查 Ready 状态进程是否存活，异常自动转移至 Failed。
 * - 安全销毁：销毁前等待所有挂起 IO 完成（防止持久化中断），状态机转 ShuttingDown，
 *   终止子进程后回到 Uninitialized。
 *
 * =============================================================================
 * 安全约束
 * =============================================================================
 * - 所有路径记录经 sanitize_path 脱敏，防止泄露本地文件结构。
 * - 错误消息不含路径、密码或内部状态，仅对前端暴露通用描述。
 * - 启动前必须通过架构一致性校验（worker.exe 与 verthys.dll 同为 x86_64），
 *   否则提前拒绝，避免静默加载失败。
 * - 预检阶段执行二进制导入依赖扫描，若缺失 VC++ 运行库等依赖，提前拦截。
 * - 任何超时或异常均立即 kill 子进程并 wait 回收，杜绝僵尸进程。
 *
 * =============================================================================
 * 依赖方向
 * =============================================================================
 * controller → state / infrastructure / worker / constants / util
 */

use crate::controller::api_error::ErrorCode;
use crate::controller::types::VerthysResponse;
use crate::infrastructure::path_resolver::{
    check_binary_dependencies, resolve_dll_path, resolve_worker_path, verify_binary_architecture,
    verify_dll_integrity,
};
use crate::state::{AppState, InitLockGuard, SetupCache, WorkerLifecycleState};
use crate::util::path::sanitize_path;
use crate::worker::{WorkerSession, kill_orphan_workers};
use std::time::Duration;
use tauri::State;

/// Worker 初始化期间可能发生的内部错误类型。
///
/// 该枚举用于将失败原因分类并映射为前端的 `ErrorCode`，同时生成脱敏的用户消息。
/// 所有路径、内部状态均不暴露到外界。
#[derive(Debug)]
pub enum WorkerInitError {
    /// 加密库文件（verthys.dll）未找到
    DllNotFound,
    /// DLL 完整性校验失败（SHA-256 哈希不匹配）
    IntegrityViolation,
    /// 系统依赖缺失（如 VC++ 运行库）
    DependencyMissing,
    /// 子进程启动超时（spawn 阶段）
    SpawnTimeout,
    /// 就绪信号等待超时（ready 阶段）
    ReadyTimeout,
    /// 二进制架构不一致（worker 与 DLL 位数不同或非 x86_64）
    BinaryArchMismatch,
    /// 加载器级失败：子进程在 main 执行前被 Windows 加载器终止。
    /// 特征为退出码 0 且无 stderr，由缺失依赖、损坏或 SxS 解析失败引起。
    BinaryLoadFailed,
    /// 状态机不匹配（如重复初始化或恢复次数超限）
    StateMismatch(String),
    /// 其他未分类的内部错误
    Internal(String),
}

impl WorkerInitError {
    /// 映射为前端可用的错误码。
    fn to_error_code(&self) -> ErrorCode {
        match self {
            WorkerInitError::DllNotFound => ErrorCode::DllNotFound,
            WorkerInitError::IntegrityViolation => ErrorCode::IntegrityFailed,
            WorkerInitError::DependencyMissing => ErrorCode::DependencyMissing,
            WorkerInitError::SpawnTimeout => ErrorCode::SpawnTimeout,
            WorkerInitError::ReadyTimeout => ErrorCode::ReadyTimeout,
            WorkerInitError::BinaryArchMismatch => ErrorCode::BinaryArchMismatch,
            WorkerInitError::BinaryLoadFailed => ErrorCode::BinaryLoadFailed,
            WorkerInitError::StateMismatch(_) => ErrorCode::KeyStateMismatch,
            WorkerInitError::Internal(_) => ErrorCode::Internal,
        }
    }

    /// 生成脱敏的用户可读消息（不含路径、密码或内部细节）。
    fn to_message(&self) -> String {
        match self {
            WorkerInitError::DllNotFound => "安全核心文件未找到".into(),
            WorkerInitError::IntegrityViolation => "安全核心完整性校验失败".into(),
            WorkerInitError::DependencyMissing => "系统依赖缺失".into(),
            WorkerInitError::SpawnTimeout => "安全子进程启动超时".into(),
            WorkerInitError::ReadyTimeout => "安全子进程就绪超时".into(),
            WorkerInitError::BinaryArchMismatch => {
                "安全核心二进制架构不匹配（32/64位），请重新构建 verthys-worker".into()
            }
            WorkerInitError::BinaryLoadFailed => {
                "安全核心二进制加载失败（可能缺失依赖或二进制损坏），请重新构建".into()
            }
            WorkerInitError::StateMismatch(msg) => msg.clone(),
            WorkerInitError::Internal(_) => "安全核心启动失败".into(),
        }
    }
}

/// 应用启动时执行预检，结果缓存供后续 `worker_init` 使用。
///
/// 该函数在 Tauri setup 钩子中调用，执行 DLL 完整性校验、依赖预检
/// 和二进制架构一致性校验，避免每次初始化重复耗时。
/// 若预检失败，返回对应的 `WorkerInitError`，由调用方记录日志并决定是否继续。
///
/// # 参数
/// - `app`：Tauri 应用句柄，用于解析路径。
///
/// # 返回
/// - `Ok(SetupCache)`：缓存结果，包含 worker 路径和 DLL 路径。
/// - `Err(WorkerInitError)`：预检失败的具体原因。
pub fn perform_setup_preflight(app: &tauri::AppHandle) -> Result<SetupCache, WorkerInitError> {
    // 1. 解析 worker 可执行文件路径
    let worker_exe = resolve_worker_path(app).map_err(|e| {
        log::error!("[setup_preflight] 解析 worker 路径失败: {}", e);
        WorkerInitError::Internal(format!("resolve_worker_path: {}", e))
    })?;

    if !std::path::Path::new(&worker_exe).exists() {
        log::error!(
            "[setup_preflight] verthys-worker 不存在: {}",
            sanitize_path(&worker_exe)
        );
        return Err(WorkerInitError::DllNotFound);
    }

    // 2. 解析加密库 DLL 路径
    let dll_path = resolve_dll_path(app).map_err(|e| {
        log::error!("[setup_preflight] 解析 DLL 路径失败: {}", e);
        WorkerInitError::Internal(format!("resolve_dll_path: {}", e))
    })?;

    if !std::path::Path::new(&dll_path).exists() {
        log::error!(
            "[setup_preflight] verthys.dll 不存在: {}",
            sanitize_path(&dll_path)
        );
        return Err(WorkerInitError::DllNotFound);
    }

    // 3. 架构一致性校验（前置门禁）
    //    必须在 spawn 前完成，防止 32-bit worker 加载 64-bit DLL 导致的静默失败。
    verify_binary_architecture(&worker_exe, &dll_path).map_err(|e| {
        log::error!("[setup_preflight] 二进制架构校验失败: {}", e);
        WorkerInitError::BinaryArchMismatch
    })?;

    // 4. 依赖预检：解析导入表，按加载器搜索顺序确认全部依赖可访问。
    //    缺失任一依赖将导致加载器级失败，必须提前拦截。
    check_binary_dependencies(&worker_exe, &dll_path).map_err(|e| {
        log::error!("[setup_preflight] 二进制依赖预检失败: {}", e);
        WorkerInitError::DependencyMissing
    })?;

    // 5. DLL 完整性校验（SHA-256）
    verify_dll_integrity(&dll_path).map_err(|e| {
        log::error!("[setup_preflight] DLL 完整性校验失败: {}", e);
        WorkerInitError::IntegrityViolation
    })?;

    log::info!(
        "[setup_preflight] 预检通过: worker={}, dll={}",
        sanitize_path(&worker_exe),
        sanitize_path(&dll_path)
    );

    Ok(SetupCache {
        worker_exe,
        dll_path,
        integrity_verified: true,
        dependencies_checked: true,
    })
}

/// 初始化 worker 子进程（加载 DLL 并建立 IPC 连接）。
///
/// 该命令由前端调用，负责启动 verthys-worker.exe，等待其就绪，并建立通信会话。
/// 过程中具备超时控制、状态机约束和并发保护。
///
/// # 行为
/// 1. 尝试获取初始化锁，同一时刻仅一个请求可执行实际启动；
///    若已有初始化进行中，则通过 watch 通道等待最终状态（最长 3 秒）。
/// 2. 从缓存或现场执行预检（DLL 完整性、依赖、架构）。
/// 3. 异步 spawn 子进程，超时 15 秒。
/// 4. 等待就绪信号，超时 5 秒；超时或失败则终止子进程。
/// 5. 成功后将状态机转移至 Ready，缓存会话。
///
/// # 错误处理
/// 任何失败均记录详细日志，并返回脱敏的 VerthysResponse（错误码 + 通用消息）。
/// 内部错误分类已在 `WorkerInitError` 中定义。
///
/// # 参数
/// - `_dll_path`：忽略（前端仍传递但强制后端解析）。
/// - 其他参数由 Tauri 自动注入。
///
/// # 返回
/// - `Ok(VerthysResponse)`：成功时 ok=true，失败时包含错误码与消息。
#[tauri::command]
pub async fn worker_init(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    _dll_path: String, // 忽略前端传入，强制后端解析
) -> Result<VerthysResponse, String> {
    // 并发锁防重：仅第一个请求执行，其他等待或拒绝
    if !state.try_acquire_init_lock() {
        // 初始化进行中不拒绝，等待状态变更
        let current = state.worker_lifecycle.current_state().await;
        if current.is_initializing() {
            // watch 等待 Ready/Failed（最长 3s）
            match state.worker_lifecycle.wait_for_ready_or_failed().await {
                Ok(WorkerLifecycleState::Ready) => {
                    return Ok(VerthysResponse::ok("worker_init"));
                }
                Ok(WorkerLifecycleState::Failed { reason, .. }) => {
                    return Ok(VerthysResponse::err("worker_init", &reason));
                }
                _ => {
                    return Ok(VerthysResponse::err("worker_init", "安全子进程仍在初始化中，请稍后重试"));
                }
            }
        }
        return Ok(VerthysResponse::err("worker_init", "初始化流程进行中，拒绝并发请求"));
    }

    // 确保锁在函数退出时释放
    let _guard = InitLockGuard { state: &state };

    // 修复：启动新 worker 前杀死所有残留孤儿 verthys-worker 进程
    //   根因：上次应用异常退出（强杀/崩溃）遗留的孤儿 worker 持有 verthys 文件锁/
    //   共享内存/状态文件锁 → 状态文件损坏 → 新 worker 启动后 scan 操作崩溃。
    //   在初始化锁保护下执行，确保仅一次清理。
    kill_orphan_workers();

    // 状态机检查 — 尝试转移到 Initializing
    let transition_result = state
        .worker_lifecycle
        .with_lock(|lc| lc.transition_to_initializing())
        .await;

    if let Err(msg) = transition_result {
        // 状态不匹配（如恢复次数超限）
        let err = WorkerInitError::StateMismatch(msg);
        state
            .worker_lifecycle
            .with_lock(|lc| {
                lc.transition_to_failed(err.to_message());
            })
            .await;
        return Ok(VerthysResponse::err("worker_init", &err.to_message()));
    }

    // 如果已有会话，先销毁
    if state.has_session() {
        state.set_session(None);
    }

    // 从 setup 缓存取预检结果（无缓存则现场执行）
    let setup_cache = {
        let cached = state
            .worker_lifecycle
            .with_lock(|lc| lc.setup_cache().cloned())
            .await;

        match cached {
            Some(cache) if cache.is_valid() => {
                log::debug!("[worker_init] 使用 setup 缓存（跳过重复预检）");
                cache
            }
            _ => {
                log::info!("[worker_init] setup 缓存无效或不存在，现场执行预检");
                match perform_setup_preflight(&app) {
                    Ok(cache) => {
                        // 缓存结果
                        state
                            .worker_lifecycle
                            .with_lock(|lc| {
                                lc.set_setup_cache(cache.clone());
                            })
                            .await;
                        cache
                    }
                    Err(e) => {
                        let msg = e.to_message();
                        state
                            .worker_lifecycle
                            .with_lock(|lc| {
                                lc.transition_to_failed(&msg);
                            })
                            .await;
                        return Ok(VerthysResponse::err("worker_init", &msg));
                    }
                }
            }
        }
    };

    let worker_exe = setup_cache.worker_exe.clone();
    let dll_path = setup_cache.dll_path.clone();

    // spawn 超时 15 秒
    const SPAWN_TIMEOUT: Duration = Duration::from_secs(15);

    log::info!(
        "[worker_init] 开始启动子进程（超时 {}s）",
        SPAWN_TIMEOUT.as_secs()
    );

    let spawn_result = tokio::time::timeout(
        SPAWN_TIMEOUT,
        tokio::task::spawn_blocking(move || WorkerSession::spawn(&worker_exe, &dll_path)),
    )
    .await;

    let session = match spawn_result {
        // 超时
        Err(_) => {
            log::error!(
                "[worker_init] worker spawn 超时（{}s）",
                SPAWN_TIMEOUT.as_secs()
            );
            state
                .worker_lifecycle
                .with_lock(|lc| {
                    lc.transition_to_failed("spawn 超时");
                })
                .await;
            return Ok(VerthysResponse::err(
                "worker_init",
                &WorkerInitError::SpawnTimeout.to_message(),
            ));
        }
        // spawn_blocking 任务 panic
        Ok(Err(e)) => {
            log::error!("[worker_init] spawn task join error: {}", e);
            state
                .worker_lifecycle
                .with_lock(|lc| {
                    lc.transition_to_failed("spawn 任务异常");
                })
                .await;
            return Ok(VerthysResponse::err(
                "worker_init",
                "安全核心启动失败",
            ));
        }
        // WorkerSession::spawn 失败
        Ok(Ok(Err(e))) => {
            log::error!("[worker_init] WorkerSession::spawn 失败: {}", e);
            state
                .worker_lifecycle
                .with_lock(|lc| {
                    lc.transition_to_failed("spawn 失败");
                })
                .await;
            return Ok(VerthysResponse::err("worker_init", "安全核心启动失败"));
        }
        // 成功
        Ok(Ok(Ok(session))) => session,
    };

    // 等待就绪信号（超时 5 秒）
    log::info!("[worker_init] 等待 worker 就绪信号（超时 5s）");

    let ready_result = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking({
            let session = session.clone();
            move || session.wait_for_ready_signal()
        }),
    )
    .await;

    match ready_result {
        Ok(Ok(Ok(()))) => {
            // 就绪检测通过
            log::info!("[worker_init] 子进程启动成功且就绪检测通过");
            state.set_session(Some(session));

            // 转移到 Ready 状态
            state
                .worker_lifecycle
                .with_lock(|lc| {
                    lc.transition_to_ready().ok();
                })
                .await;

            Ok(VerthysResponse::ok("worker_init"))
        }
        Ok(Ok(Err(e))) => {
            // wait_for_ready_signal 返回错误：子进程在就绪前退出（管道关闭/崩溃）
            // 区分加载器级失败与普通崩溃，给出可操作的错误码而非笼统的"就绪超时"。
            let err = classify_ready_failure(&e);
            log::error!(
                "[worker_init] 就绪检测失败（{}）: {}",
                err.to_error_code().as_str(),
                e
            );
            session.kill();

            let msg = err.to_message();
            state
                .worker_lifecycle
                .with_lock(|lc| {
                    lc.transition_to_failed(&msg);
                })
                .await;

            Ok(VerthysResponse::err("worker_init", &msg))
        }
        Ok(Err(join_e)) => {
            // spawn_blocking 任务 panic
            log::error!("[worker_init] 就绪检测任务异常: {}", join_e);
            session.kill();
            let msg = WorkerInitError::Internal("ready task".into()).to_message();
            state
                .worker_lifecycle
                .with_lock(|lc| {
                    lc.transition_to_failed(&msg);
                })
                .await;
            Ok(VerthysResponse::err("worker_init", &msg))
        }
        Err(_) => {
            // 5s 超时：子进程仍在运行但未发出就绪信号
            log::error!("[worker_init] 就绪信号超时（5s），终止子进程");
            session.kill();
            let msg = WorkerInitError::ReadyTimeout.to_message();
            state
                .worker_lifecycle
                .with_lock(|lc| {
                    lc.transition_to_failed(&msg);
                })
                .await;
            Ok(VerthysResponse::err("worker_init", &msg))
        }
    }
}

/// 就绪检测失败分类器。
///
/// 根据 `wait_for_ready_signal` 返回的错误字符串，判断失败属于
/// “加载器级失败”还是“应用层崩溃”。
///
/// 加载器级失败特征：子进程在 main() 执行前被操作系统加载器终止，
/// 通常退出码为 0 且无 stderr 输出，表示缺失依赖或二进制损坏。
/// 此类错误返回 `BinaryLoadFailed`，引导用户重建或检查环境。
///
/// 否则视为应用层崩溃，返回 `Internal`，错误消息透传诊断信息。
///
/// # 参数
/// - `err_msg`：来自 `diagnose_exit` 构造的完整错误描述。
///
/// # 返回
/// 对应的 `WorkerInitError` 变体。
fn classify_ready_failure(err_msg: &str) -> WorkerInitError {
    // 加载器级失败特征：exit code 0 且无 stderr 段
    let is_loader_failure = err_msg.contains("exit: code 0") && !err_msg.contains("| stderr:");
    if is_loader_failure {
        WorkerInitError::BinaryLoadFailed
    } else {
        WorkerInitError::Internal(err_msg.to_string())
    }
}

/// 销毁 worker 子进程并清理状态。
///
/// 该命令由前端调用（通常为退出或重新初始化前），执行以下操作：
/// 1. 状态机转移至 ShuttingDown。
/// 2. 等待任何进行中的 IO 操作完成（最长 2 秒）。
/// 3. 终止子进程（通过 Drop WorkerSession 自动 kill）。
/// 4. 状态机回到 Uninitialized。
///
/// # 返回
/// `VerthysResponse` 表示操作成功（即使子进程已不存在也视为成功）。
#[tauri::command]
pub async fn worker_destroy(state: State<'_, AppState>) -> Result<VerthysResponse, String> {
    state
        .worker_lifecycle
        .with_lock(|lc| {
            lc.transition_to_shutting_down().ok();
        })
        .await;

    if state.has_session() {
        let _ = state.wait_io_complete(Duration::from_secs(2)).await;
        state.set_session(None);
    }

    // 修复：worker 销毁后 GMK 已从内存消失，重置密钥生命周期为 NoKey
    //
    // 原缺陷：worker_destroy 仅销毁子进程会话，不触碰 key_lifecycle 状态机。
    // 若销毁前状态为 Locked/Unlocked，销毁后状态仍残留。后续若不经过
    // verthys_unlock（其内部已有 reset_to_no_key 逻辑）而直接调用
    // verthys_derive_global_key / verthys_verify_global_key，状态机校验将基于
    // 已失效的旧状态做出错误判定：
    //   - 残留 Locked → derive_global_key 拒绝（要求 NoKey）→ 初始化按钮失效
    //   - 残留 Unlocked → verify_global_key 拒绝（要求 Locked）→ 验证按钮失效
    //   - 残留 NoKey → verify_global_key 拒绝（要求 Locked）→ 验证按钮失效
    //
    // 修复：worker 销毁即重置为 NoKey，与"worker 内存无 GMK"的物理事实一致。
    // 后续 verthys_unlock 会根据 has_global_key 再次设置正确状态。
    state.key_lifecycle.reset_to_no_key();

    state
        .worker_lifecycle
        .with_lock(|lc| {
            lc.transition_to_uninitialized();
        })
        .await;

    log::info!("[worker_destroy] worker 子进程已销毁，key_lifecycle 已重置为 NoKey");
    Ok(VerthysResponse::ok("worker_destroy"))
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_init_error_mapping() {
        let err = WorkerInitError::DllNotFound;
        assert_eq!(err.to_error_code(), ErrorCode::DllNotFound);
        assert!(!err.to_message().is_empty());

        let err = WorkerInitError::SpawnTimeout;
        assert_eq!(err.to_error_code(), ErrorCode::SpawnTimeout);

        let err = WorkerInitError::ReadyTimeout;
        assert_eq!(err.to_error_code(), ErrorCode::ReadyTimeout);

        let err = WorkerInitError::BinaryArchMismatch;
        assert_eq!(err.to_error_code(), ErrorCode::BinaryArchMismatch);
        assert!(!err.to_message().is_empty());

        let err = WorkerInitError::BinaryLoadFailed;
        assert_eq!(err.to_error_code(), ErrorCode::BinaryLoadFailed);
        assert!(!err.to_message().is_empty());
    }

    #[test]
    fn test_worker_init_error_message_sanitized() {
        let err = WorkerInitError::Internal("/secret/path/to/dll".into());
        let msg = err.to_message();
        assert!(!msg.contains("/secret/path"));
    }

    #[test]
    fn test_classify_ready_failure_loader_failure() {
        let msg = "worker 就绪检测失败: 子进程已崩溃 — worker exited (exit: code 0) PID=1234";
        let err = classify_ready_failure(msg);
        assert_eq!(err.to_error_code(), ErrorCode::BinaryLoadFailed);
    }

    #[test]
    fn test_classify_ready_failure_app_crash() {
        let msg = "worker 就绪检测失败: 子进程已崩溃 — worker exited (exit: code 1) PID=1234";
        let err = classify_ready_failure(msg);
        assert_eq!(err.to_error_code(), ErrorCode::Internal);
    }

    #[test]
    fn test_classify_ready_failure_with_stderr() {
        let msg = "worker 就绪检测失败: 子进程已崩溃 — worker exited (exit: code 0) PID=1234 | stderr: PANIC at ...";
        let err = classify_ready_failure(msg);
        assert_eq!(err.to_error_code(), ErrorCode::Internal);
    }
}