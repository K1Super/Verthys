/*
 * 流式导出落盘
 *
 * 职责边界：暂存文件分帧追加、fsync 后 rename 原子替换、取消清理与过期
 * 暂存回收。目标文件任何时刻要么是旧完整版、要么是新完整版，不存在部分
 * 写入的最终文件。
 */

use crate::constants::export_stream::{
    MAX_EXPORT_SINGLE_BYTES, STALE_TEMP_MAX_AGE, WRITE_FILE_CHUNK_BYTES,
};
use crate::controller::api_error::ErrorCode;
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::constants::command_names::cmd;
use crate::state::file_streams::FileStreamState;
use crate::util::audit_log::{AuditEventType, AuditResult};
use crate::util::path::sanitize_path;
use std::fs::OpenOptions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::ipc::{InvokeBody, Request};
use tauri::State;

use super::*;
// ===== 流式写入（write/append/finalize/abort） =====
//
// 单文件导出（.venc 容器，可达数百 MB）若沿用一次全量原子写入，
// 峰值内存为容器字节数；流式写入将数据分帧落盘至暂存文件，最终
// fsync + rename 原子替换，既压低内存峰值又保证目标文件任何时刻
// 要么是旧完整版、要么是新完整版，不存在部分写入的最终文件。

/// 生成流式会话标识（32 字符小写 hex，熵 128 bit）。
///
/// hex 字符集保证标识可经 HTTP 请求头（append 命令 x-stream-id）安全
/// 传输；熵值使枚举无效标识不可行（无效标识仅触发 STREAM_NOT_FOUND）。
pub(super) fn generate_stream_id() -> String {
    let mut buf = [0u8; 16];
    crate::util::random::fill_random_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 暂存文件命名契约：只清理本应用生成且带固定前缀的暂存。
///
/// 目标目录可能同时存放其他程序的文件；仅凭 `.venc.tmp` 后缀判定
/// 会误删同目录内不属于本应用的临时文件。
const STREAM_TEMP_PREFIX: &str = ".verthys-";
const STREAM_TEMP_SUFFIX: &str = ".tmp";

fn is_stream_temp_name(name: &std::ffi::OsStr) -> bool {
    let s = name.to_string_lossy();
    s.len() > STREAM_TEMP_PREFIX.len() + STREAM_TEMP_SUFFIX.len()
        && s.starts_with(STREAM_TEMP_PREFIX)
        && s.ends_with(STREAM_TEMP_SUFFIX)
}

/// 清理目录内的流式暂存残留（修改时间早于清理阈值的 `.venc.tmp` 文件）。
///
/// 崩溃/强杀会遗留未 finalize 的暂存文件；暂存永远不会被 rename 到目标
/// （finalize 在 rename 前注销会话），残留是纯磁盘垃圾。创建新流时对
/// 目标所在目录执行按龄清理，等价于启动清理的惰性化，不影响新鲜残留
/// （可能属于并发活跃会话）。
pub(super) fn cleanup_stale_stream_temps(dir: &std::path::Path) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_temp = path
            .file_name()
            .map(is_stream_temp_name)
            .unwrap_or(false);
        if !is_temp {
            continue;
        }
        let stale = match std::fs::metadata(&path) {
            Ok(meta) => match meta.modified() {
                Ok(modified) => match modified.elapsed() {
                    Ok(age) => age >= STALE_TEMP_MAX_AGE,
                    Err(_) => false,
                },
                Err(_) => false,
            },
            Err(_) => false,
        };
        if stale {
            log::info!(
                "[file_stream] 清理暂存残留: {}",
                sanitize_path(&path.to_string_lossy())
            );
            if let Err(e) = std::fs::remove_file(&path) {
                log::warn!("[file_stream] 清理暂存残留失败: {}", e);
            }
        }
    }
}

/// 导出写盘审计：与流式写入命令共用同一写审计口径。
///
/// 原生导出直接复用阻塞核心，不经过 `write_user_file_stream` 命令层，
/// 因此由调用方在 create/finalize/abort 边界显式记账。
pub(crate) fn audit_export_event(
    app: &tauri::AppHandle,
    path: &str,
    ok: bool,
    size: Option<u64>,
    detail: Option<String>,
) {
    write_file_audit(
        app,
        AuditEventType::FileWrite,
        path,
        if ok {
            AuditResult::Success
        } else {
            AuditResult::Failure
        },
        size,
        detail,
    );
}

/// 创建流式写入会话（阻塞核心）：目标校验 + 暂存独占创建。
///
/// 返回会话标识与会话状态（尚未注册进会话表，由命令层在短临界区内
/// 完成注册）。暂存文件使用 create_new 独占创建：同目标并发的第二个
/// 会话创建必然失败，从根上排除双写同一暂存路径。
pub(crate) fn stream_create_blocking(target: &str) -> Result<(String, Arc<Mutex<FileStreamState>>), String> {
    let canonical = resolve_user_file_target(target, "stream_create")?;

    // 暂存路径：与目标同级、本应用专属前缀，finalize rename 后即消失。
    // 前缀参与独占创建与按龄清理，二者只作用于本应用生成的暂存。
    let file_name = match canonical.file_name() {
        Some(n) => n.to_os_string(),
        None => {
            log::warn!("[stream_create] 目标路径缺少文件名");
            return Err(ErrorCode::InvalidPath.default_message().to_string());
        }
    };
    let mut temp_name = std::ffi::OsString::from(STREAM_TEMP_PREFIX);
    temp_name.push(&file_name);
    temp_name.push(STREAM_TEMP_SUFFIX);
    let temp_path = canonical.with_file_name(temp_name);
    let parent = match temp_path.parent() {
        Some(p) => p.to_path_buf(),
        None => {
            log::warn!("[stream_create] 暂存路径无父目录");
            return Err(ErrorCode::InvalidPath.default_message().to_string());
        }
    };
    cleanup_stale_stream_temps(&parent);

    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .map_err(|e| {
            log::warn!(
                "[stream_create] 创建暂存文件失败（同目标并发会话或残留未过期）: {}",
                e
            );
            ErrorCode::TemporaryFailure.default_message().to_string()
        })?;

    log::debug!(
        "[stream_create] 暂存文件: {}",
        sanitize_path(&temp_path.to_string_lossy())
    );

    let stream_id = generate_stream_id();
    let state = FileStreamState::new(file, temp_path, canonical);
    Ok((stream_id, Arc::new(Mutex::new(state))))
}

/// 追加数据块（阻塞核心）：单块上限 + 累计总量上限 + 写入暂存。
///
/// 会话指针由调用方从会话表克隆取得；会话状态锁覆盖「句柄写入 + 计数
/// 更新」，保证同会话追加严格串行。
pub(crate) fn stream_append_blocking(entry: &Arc<Mutex<FileStreamState>>, data: &[u8]) -> Result<(), String> {
    if data.len() > WRITE_FILE_CHUNK_BYTES {
        log::warn!(
            "[append_user_file_chunk] 单块超限: {} bytes > {}",
            data.len(),
            WRITE_FILE_CHUNK_BYTES
        );
        return Err(ErrorCode::FileTooLarge.default_message().to_string());
    }

    let mut state = match entry.lock() {
        Ok(s) => s,
        Err(poisoned) => {
            log::error!("[append_user_file_chunk] 会话状态锁中毒");
            let s = poisoned.into_inner();
            return Err(if s.is_active() {
                ErrorCode::Internal.default_message().to_string()
            } else {
                ErrorCode::StreamNotFound.default_message().to_string()
            });
        }
    };

    if state.appends_closed() {
        log::warn!("[append_user_file_chunk] 会话追加入口已关闭，拒绝写入");
        return Err(ErrorCode::StreamNotFound.default_message().to_string());
    }

    let next_bytes = state.bytes_written().saturating_add(data.len() as u64);
    if next_bytes > MAX_EXPORT_SINGLE_BYTES {
        log::warn!(
            "[append_user_file_chunk] 累计超限: {} bytes > {}",
            next_bytes,
            MAX_EXPORT_SINGLE_BYTES
        );
        return Err(ErrorCode::FileTooLarge.default_message().to_string());
    }

    state.append(data).map_err(|e| {
        log::warn!("[append_user_file_chunk] 写入暂存失败: {}", e);
        ErrorCode::TemporaryFailure.default_message().to_string()
    })
}

/// 终结流式会话（阻塞核心）：同步落盘 → 关闭句柄 → 原子替换目标。
///
/// 调用方已从会话表移除会话取得独占所有权；持有全局写互斥执行，与
/// 原子写入路径互斥避免 rename 交错。rename 失败时清理暂存并报错，
/// 目标文件保持旧完整版不变。
pub(crate) fn stream_finalize_blocking(
    entry: Arc<Mutex<FileStreamState>>,
    cancel: Option<&AtomicBool>,
) -> Result<u64, String> {
    let cancelled = || cancel.is_some_and(|flag| flag.load(Ordering::SeqCst));
    let _write_guard = WRITE_MUTEX.lock().map_err(|e| {
        log::error!("[finalize_user_file_stream] 写互斥锁中毒: {}", e);
        ErrorCode::Internal.default_message().to_string()
    })?;

    let (temp, target, total) = {
        let mut state = match entry.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.appends_closed() {
            let temp = state.temp_path().clone();
            state.close_handle();
            drop(state);
            let _ = std::fs::remove_file(&temp);
            log::error!(
                "[finalize_user_file_stream] 追加结果未确认，拒绝落盘"
            );
            return Err("追加结果未确认，已拒绝落盘，请重新导出".to_string());
        }
        state.close_appends();
        if let Err(e) = state.sync_all() {
            log::warn!("[finalize_user_file_stream] fsync 失败: {}", e);
            return Err(ErrorCode::Internal.default_message().to_string());
        }
        let temp = state.temp_path().clone();
        let target = state.target_path().clone();
        let total = state.bytes_written();
        drop(state);
        (temp, target, total)
    };
    // state 守卫已释放但句柄仍被 Arc 持有：rename 前显式关闭暂存句柄。
    // 正常独占消费路径下 Arc 强引用唯一，直接消费取得所有权；存在在途
    // append 克隆时以 close_handle 兜底关闭。
    match Arc::try_unwrap(entry) {
        Ok(mutex) => {
            let _ = mutex.into_inner();
        }
        Err(arc) => {
            if let Ok(mut state) = arc.lock() {
                state.close_handle();
            }
        }
    }

    /* 超时取消检查位于 rename 之前：spawn_blocking 不会随 timeout 中止，
     * 没有此检查时前端已收到超时错误，目标文件仍会被替换。 */
    if cancelled() {
        let _ = std::fs::remove_file(&temp);
        log::warn!("[finalize_user_file_stream] 已取消：暂存已清理，目标未替换");
        return Err("落盘已取消".to_string());
    }

    if let Err(e) = std::fs::rename(&temp, &target) {
        log::error!("[finalize_user_file_stream] rename 失败: {}", e);
        let _ = std::fs::remove_file(&temp);
        return Err(ErrorCode::Internal.default_message().to_string());
    }

    log::info!("[finalize_user_file_stream] 流式落盘完成: {} bytes", total);
    Ok(total)
}

/// 中止流式会话（阻塞核心）：关闭句柄并删除暂存，目标文件不触碰。
///
/// 暂存不存在（NotFound）视为清理已完成；其余删除失败上报，
/// 残留交由下次创建流时的按龄清理兜底。
pub(crate) fn stream_abort_blocking(entry: Arc<Mutex<FileStreamState>>) -> Result<(), String> {
    let temp = {
        let state = match entry.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.close_appends();
        let temp = state.temp_path().clone();
        drop(state);
        temp
    };
    // 独占消费路径下直接销毁会话关闭句柄；存在在途 append 克隆时
    // 等其完成后以 close_handle 关闭，保证删除前句柄已释放
    match Arc::try_unwrap(entry) {
        Ok(mutex) => {
            let _ = mutex.into_inner();
        }
        Err(arc) => {
            if let Ok(mut state) = arc.lock() {
                state.close_handle();
            }
        }
    }

    match std::fs::remove_file(&temp) {
        Ok(()) => {
            log::info!("[abort_user_file_stream] 会话已中止，暂存已清理");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log::info!("[abort_user_file_stream] 会话已中止（暂存已不存在）");
            Ok(())
        }
        Err(e) => {
            log::warn!("[abort_user_file_stream] 清理暂存失败: {}", e);
            Err(ErrorCode::TemporaryFailure.default_message().to_string())
        }
    }
}

/// 从 `x-stream-id` 请求头解码会话标识并做字符集校验。
///
/// 前端以原始二进制体直传块字节（raw body 与 JSON 参数互斥），会话
/// 标识仅能经请求头传递；标识为 32 位小写 hex，预检失败直接拒绝，
/// 防止畸形输入进入会话表查询路径。
pub(super) fn decode_stream_id_header(request: &Request<'_>) -> Result<String, String> {
    let raw = request
        .headers()
        .get("x-stream-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let valid = !raw.is_empty()
        && raw.len() <= 64
        && raw
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    if !valid {
        log::warn!("[append_user_file_chunk] 会话标识缺失或畸形");
        return Err(ErrorCode::StreamNotFound.default_message().to_string());
    }
    Ok(raw.to_string())
}

/// 创建流式写入会话（单文件导出流式落盘入口）。
///
/// 通过数据域解锁闸门后，校验目标路径（与原子写入同链）并独占创建
/// 暂存文件，会话注册进程内表。返回会话标识供后续 append/finalize/
/// abort 使用；同目标并发创建第二个会话将以暂存冲突拒绝。
#[tauri::command]
pub async fn write_user_file_stream(
    app: tauri::AppHandle,
    state: State<'_, crate::state::AppState>,
    path: String,
) -> Result<String, String> {
    require_unlocked(&app, &state, cmd::WRITE_USER_FILE_STREAM)?;
    log::info!(
        "[write_user_file_stream] 创建流式写入会话: {}",
        sanitize_path(&path)
    );

    let path_clone = path.clone();
    let create_result = tokio::time::timeout(
        USER_FILE_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || stream_create_blocking(&path_clone)),
    )
    .await;

    match create_result {
        Err(_) => {
            log::error!(
                "[write_user_file_stream] 创建超时（{}s）",
                USER_FILE_OP_TIMEOUT.as_secs()
            );
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &path,
                AuditResult::Failure,
                None,
                Some(format!("创建会话超时 {}s", USER_FILE_OP_TIMEOUT.as_secs())),
            );
            Err(ErrorCode::TemporaryFailure.default_message().to_string())
        }
        Ok(Err(e)) => {
            log::error!("[write_user_file_stream] spawn_blocking 异常: {}", e);
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &path,
                AuditResult::Failure,
                None,
                Some(format!("任务异常: {}", e)),
            );
            Err(ErrorCode::Internal.default_message().to_string())
        }
        Ok(Ok(Err(e))) => {
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &path,
                AuditResult::Failure,
                None,
                Some(e.clone()),
            );
            Err(e)
        }
        Ok(Ok(Ok((stream_id, entry)))) => {
            // 注册进会话表（短临界区，仅指针插入）
            let mut table = state.lock_file_streams();
            table.insert(stream_id.clone(), entry);
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &path,
                AuditResult::Success,
                None,
                None,
            );
            Ok(stream_id)
        }
    }
}

/// 向流式会话追加原始数据块（二进制 IPC）。
///
/// 块字节经请求体直传（`InvokeBody::Raw`），会话标识经 `x-stream-id`
/// 请求头传递（raw body 与 JSON 参数互斥）。单块与累计总量双重上限，
/// 越界拒绝且会话保持可用（调用方可中止后重试或改用多文件模式）。
#[tauri::command]
pub async fn append_user_file_chunk(
    app: tauri::AppHandle,
    state: State<'_, crate::state::AppState>,
    request: Request<'_>,
) -> Result<(), String> {
    require_unlocked(&app, &state, cmd::APPEND_USER_FILE_CHUNK)?;

    let stream_id = decode_stream_id_header(&request)?;
    let data: Vec<u8> = match request.body() {
        InvokeBody::Raw(bytes) => bytes.clone(),
        _ => {
            log::warn!("[append_user_file_chunk] 请求体非原始二进制");
            return Err(ErrorCode::InvalidPath.default_message().to_string());
        }
    };
    if data.is_empty() {
        log::warn!("[append_user_file_chunk] 拒绝空数据块");
        return Err(ErrorCode::InvalidPath.default_message().to_string());
    }

    // 取会话指针（不注销：追加失败后会话仍须可被中止清理；
    // 注意追加在字节层不幂等 —— write_all 半途出错时已写入的字节不回滚，
    // 失败路径必须走 abort 丢弃整个暂存，不得重试同一数据块）
    let entry = {
        let table = state.lock_file_streams();
        match table.get(&stream_id) {
            Some(entry) => Arc::clone(entry),
            None => {
                log::warn!("[append_user_file_chunk] 会话不存在或已结束");
                write_file_audit(
                    &app,
                    AuditEventType::FileWrite,
                    &stream_id,
                    AuditResult::Failure,
                    None,
                    Some("会话不存在".into()),
                );
                return Err(ErrorCode::StreamNotFound.default_message().to_string());
            }
        }
    };

    let mark_entry = Arc::clone(&entry);
    let append_result = tokio::time::timeout(
        USER_FILE_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || stream_append_blocking(&entry, &data)),
    )
    .await;

    match append_result {
        Err(_) => {
            log::error!(
                "[append_user_file_chunk] 追加超时（{}s），关闭追加入口",
                USER_FILE_OP_TIMEOUT.as_secs()
            );
            /* 超时只放弃等待：阻塞写入可能仍在进行，结果不可确认。
             * 在返回错误前关闭追加入口，确保后续块与 finalize 都被拒绝，
             * 绝不把未知尾部字节带入最终文件。 */
            let _ = tokio::task::spawn_blocking(move || {
                let state = match mark_entry.lock() {
                    Ok(s) => s,
                    Err(poisoned) => poisoned.into_inner(),
                };
                state.close_appends();
            })
            .await;
            Err("追加结果未确认，请中止本次导出并重新执行".to_string())
        }
        Ok(Err(e)) => {
            log::error!("[append_user_file_chunk] spawn_blocking 异常: {}", e);
            Err(ErrorCode::Internal.default_message().to_string())
        }
        Ok(Ok(Err(e))) => Err(e),
        Ok(Ok(Ok(()))) => Ok(()),
    }
}

/// 终结流式会话：同步落盘暂存并原子替换目标文件。
///
/// 一次性消费会话（从表移除取得独占所有权），并发 finalize/abort 仅
/// 一个成功。任何失败路径均保证目标文件未被部分写入。
#[tauri::command]
pub async fn finalize_user_file_stream(
    app: tauri::AppHandle,
    state: State<'_, crate::state::AppState>,
    stream_id: String,
) -> Result<(), String> {
    require_unlocked(&app, &state, cmd::FINALIZE_USER_FILE_STREAM)?;

    let entry = {
        let mut table = state.lock_file_streams();
        match table.remove(&stream_id) {
            Some(entry) => entry,
            None => {
                log::warn!("[finalize_user_file_stream] 会话不存在或已结束");
                write_file_audit(
                    &app,
                    AuditEventType::FileWrite,
                    &stream_id,
                    AuditResult::Failure,
                    None,
                    Some("会话不存在".into()),
                );
                return Err(ErrorCode::StreamNotFound.default_message().to_string());
            }
        }
    };

    /* 超时只放弃等待；取消标志确保阻塞任务不会在命令返回失败后继续
     * rename 替换目标。 */
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_task = cancel.clone();
    let finalize_result = tokio::time::timeout(
        USER_FILE_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            stream_finalize_blocking(entry, Some(cancel_for_task.as_ref()))
        }),
    )
    .await;

    match finalize_result {
        Err(_) => {
            cancel.store(true, Ordering::SeqCst);
            log::error!(
                "[finalize_user_file_stream] 落盘超时（{}s），已请求取消",
                USER_FILE_OP_TIMEOUT.as_secs()
            );
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &stream_id,
                AuditResult::Failure,
                None,
                Some("落盘超时：已请求取消，结果未确认".into()),
            );
            Err("落盘结果未确认，请核对导出文件".to_string())
        }
        Ok(Err(e)) => {
            log::error!("[finalize_user_file_stream] spawn_blocking 异常: {}", e);
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &stream_id,
                AuditResult::Failure,
                None,
                Some(format!("任务异常: {}", e)),
            );
            Err(ErrorCode::Internal.default_message().to_string())
        }
        Ok(Ok(Err(e))) => {
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &stream_id,
                AuditResult::Failure,
                None,
                Some(e.clone()),
            );
            Err(e)
        }
        Ok(Ok(Ok(total))) => {
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &stream_id,
                AuditResult::Success,
                Some(total),
                None,
            );
            Ok(())
        }
    }
}

/// 中止流式会话：删除暂存文件，目标文件不触碰。
///
/// 幂等语义：会话不存在视为已中止（返回成功）。供导出失败路径与用户
/// 取消路径调用，保证暂存不残留。
#[tauri::command]
pub async fn abort_user_file_stream(
    app: tauri::AppHandle,
    state: State<'_, crate::state::AppState>,
    stream_id: String,
) -> Result<(), String> {
    require_unlocked(&app, &state, cmd::ABORT_USER_FILE_STREAM)?;

    let entry = {
        let mut table = state.lock_file_streams();
        table.remove(&stream_id)
    };

    let entry = match entry {
        None => {
            log::info!("[abort_user_file_stream] 会话不存在，视为已中止");
            return Ok(());
        }
        Some(entry) => entry,
    };

    let abort_result = tokio::time::timeout(
        USER_FILE_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || stream_abort_blocking(entry)),
    )
    .await;

    match abort_result {
        Err(_) => {
            log::error!(
                "[abort_user_file_stream] 清理超时（{}s）",
                USER_FILE_OP_TIMEOUT.as_secs()
            );
            Err(ErrorCode::TemporaryFailure.default_message().to_string())
        }
        Ok(Err(e)) => {
            log::error!("[abort_user_file_stream] spawn_blocking 异常: {}", e);
            Err(ErrorCode::Internal.default_message().to_string())
        }
        Ok(Ok(Err(e))) => Err(e),
        Ok(Ok(Ok(()))) => Ok(()),
    }
}
