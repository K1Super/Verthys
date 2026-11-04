/*
 * security_commands/vault_rotate_bridge.rs — 全库 DEK 轮换的宿主能力桥接
 *
 * 职责：
 *   把 service::vault_rotate 声明的宿主能力契约（解锁闸门、口令保管、
 *   路径授权、worker 转发、流式进度、会话哨兵锁重建）接到本应用的
 *   具体实现。控制器因此只依赖 service 层，不触碰 state / worker。
 *
 * 语义约定：
 *   - 口令只在本桥接层读取并交给 worker 请求；不落盘、不写日志。
 *   - 提交成功后源文件被原子替换，会话哨兵锁必须重建到新文件；重建
 *     失败仅告警，不回滚已完成的提交（回滚会破坏轮换结果）。
 */

use tauri::{AppHandle, Manager};

use crate::controller::verthys_controller::{load_container_password, require_unlocked};
use crate::infrastructure::handle_factory;
use crate::service::vault_rotate::{self, HostHooks, RotateCancelSignal, RotateProgress};
use crate::state::{AppState, VerthysSessionGuard};
use std::time::Duration;

/// 注册全库轮换的宿主能力实现（应用启动阶段调用一次）。
pub(crate) fn install_vault_rotate() {
    vault_rotate::install(HostHooks {
        require_unlocked: adapter_require_unlocked,
        load_password: adapter_load_password,
        authorize_path: adapter_authorize_path,
        session_path: adapter_session_path,
        send: adapter_send,
        send_with_progress: adapter_send_with_progress,
        refresh_session: refresh_session_guard,
        create_cancel: create_cancel_signal,
        signal_cancel,
        close_cancel,
    });
}

fn adapter_require_unlocked(app: &AppHandle, op: &str) -> Result<(), String> {
    let state = app.state::<AppState>();
    require_unlocked(app, &state, op)
}

fn adapter_load_password(app: &AppHandle) -> Result<zeroize::Zeroizing<String>, String> {
    load_container_password(app)
}

fn adapter_authorize_path(
    app: &AppHandle,
    op: &str,
    mode: &str,
    path: &str,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    state.authorize_worker_path(op, mode, path)
}

fn adapter_session_path(app: &AppHandle) -> Option<String> {
    app.state::<AppState>().verthys_session_path()
}

fn adapter_send(app: &AppHandle, json: &str, timeout: Duration) -> Result<String, String> {
    app.state::<AppState>().send_with_timeout(json, timeout)
}

fn adapter_send_with_progress(
    app: &AppHandle,
    json: &str,
    progress_cb: &dyn Fn(&RotateProgress),
) -> Result<String, String> {
    /* worker 层进度类型与 service 契约视图字段一致；此处做一次显式映射，
     * 避免 service 直接依赖 worker 模块（分层白名单不含 worker）。 */
    let cb = |p: &crate::worker::RotateProgress| {
        let view = RotateProgress {
            stage: p.stage,
            modules_ready: p.modules_ready,
            records: p.records,
            files: p.files,
            chunks: p.chunks,
            bytes: p.bytes,
        };
        progress_cb(&view);
    };
    app.state::<AppState>()
        .send_with_rotate_progress(json, &cb)
}

/// 创建轮换取消命名事件（auto-reset；名称含进程 ID + 随机 nonce）。
#[cfg(windows)]
fn create_cancel_signal() -> Result<RotateCancelSignal, String> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("取消信号随机名生成失败: {}", e))?;
    let hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
    let name = format!(
        "Local\\VerthysRotateCancel-{}-{}",
        std::process::id(),
        hex
    );
    let handle = handle_factory::create_named_non_inheritable_event(&name)?;
    Ok(RotateCancelSignal {
        name,
        handle: handle.0 as isize,
    })
}

#[cfg(not(windows))]
fn create_cancel_signal() -> Result<RotateCancelSignal, String> {
    Err("轮换取消仅支持 Windows".to_string())
}

/// 置位取消事件（worker 在 Run 前/进度回调中检查）。
#[cfg(windows)]
fn signal_cancel(signal: &RotateCancelSignal) -> Result<(), String> {
    use windows::Win32::Foundation::HANDLE;
    handle_factory::signal_event(HANDLE(signal.handle as *mut core::ffi::c_void))
}

#[cfg(not(windows))]
fn signal_cancel(_signal: &RotateCancelSignal) -> Result<(), String> {
    Err("轮换取消仅支持 Windows".to_string())
}

/// 关闭取消事件句柄。
#[cfg(windows)]
fn close_cancel(signal: RotateCancelSignal) {
    use windows::Win32::Foundation::HANDLE;
    handle_factory::close_event(HANDLE(signal.handle as *mut core::ffi::c_void));
}

#[cfg(not(windows))]
fn close_cancel(_signal: RotateCancelSignal) {}

/// 提交成功后重建会话哨兵锁。
///
/// 先创建新 guard 再替换：创建失败时旧 guard 保持原样（不会把状态置空）。
/// 失败重试 2 次后返回错误，由控制器写入审计降级标记；提交本身不回滚。
fn refresh_session_guard(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let path = match state.verthys_session_path() {
        Some(p) => p,
        None => return Err("会话路径不可用".to_string()),
    };
    let session_id = {
        let guard = state.lock_verthys_session();
        match guard.as_ref() {
            Some(s) => s.session_id().to_string(),
            None => return Err("会话哨兵锁不存在".to_string()),
        }
    };

    let mut last_err = String::new();
    for attempt in 0u32..3u32 {
        match VerthysSessionGuard::new(&path, &session_id) {
            Ok(new_guard) => {
                let mut guard = state.lock_verthys_session();
                *guard = Some(new_guard);
                log::info!("[vault_rotate] 提交后已重建会话哨兵锁");
                return Ok(());
            }
            Err(e) => {
                last_err = e.to_string();
                if attempt < 2u32 {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
    log::warn!(
        "[vault_rotate] 提交后重建会话哨兵锁失败（不回滚已完成的提交）: {} | {}",
        crate::util::path::sanitize_path(&path),
        last_err
    );
    Err(last_err)
}
