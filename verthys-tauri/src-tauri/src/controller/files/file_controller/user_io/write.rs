/*
 * 用户授权文件写入
 *
 * 职责边界：临时文件 + fsync + rename 原子替换用户选择位置，全局写互斥，
 * 取消标志在 rename 前生效，保证目标文件不被部分写入的内容替换。
 */

use super::super::audit::write_file_audit;
use super::super::sandbox::decode_x_path_header;
use super::super::{READ_CHUNK_SIZE, USER_FILE_OP_TIMEOUT, WRITE_MUTEX};
use super::path_guard::resolve_user_file_target;
use crate::constants::export_stream::USER_FILE_SIZE_LIMIT;
use crate::controller::api_error::ErrorCode;
use crate::util::audit_log::{AuditEventType, AuditResult};
use crate::util::path::sanitize_path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::ipc::{InvokeBody, Request};

/// 同步执行用户授权的原子写入（跳过白名单，拒绝系统关键目录）。
///
/// 与 `write_file_blocking` 的差异：
///   - 跳过白名单校验（用户已通过对话框显式授权保存位置）
///   - 增加系统关键目录拒绝（防止覆盖 C:\Windows 等系统文件）
///   - 同样执行 validate_path_input 字符级校验、canonicalize（解析父目录符号链接）、
///     原子写入、fsync 与全局写互斥
pub(in super::super) fn write_user_file_blocking(
    path: &str,
    data: &[u8],
    cancel: Option<&AtomicBool>,
) -> Result<u64, String> {
    let cancelled = || cancel.is_some_and(|flag| flag.load(Ordering::SeqCst));

    // 全局写互斥
    let _write_guard = WRITE_MUTEX.lock().map_err(|e| {
        log::error!("[write_user_file] 写互斥锁中毒: {}", e);
        ErrorCode::Internal.default_message().to_string()
    })?;
    if cancelled() {
        return Err("写入已取消".to_string());
    }
    use std::io::Write;

    // 目标解析：字符校验 + canonicalize + 系统关键目录拒绝
    let canonical = resolve_user_file_target(path, "write_user_file")?;

    // 4. 大小检查（原始字节直传，无需 Base64 解码）
    let data_size = data.len() as u64;

    if data_size > USER_FILE_SIZE_LIMIT {
        log::warn!(
            "[write_user_file] 数据过大: {} bytes > {} bytes",
            data_size,
            USER_FILE_SIZE_LIMIT
        );
        return Err(ErrorCode::FileTooLarge.default_message().to_string());
    }

    // 5. 生成临时文件
    let mut random_bytes = [0u8; 8];
    crate::util::random::fill_random_bytes(&mut random_bytes);
    let random_suffix: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let temp_path = canonical.with_extension(format!("tmp.{}", random_suffix));

    log::debug!(
        "[write_user_file] 临时文件: {}",
        sanitize_path(&temp_path.to_string_lossy())
    );

    // 6. 写入临时文件 + fsync
    let write_result = (|| -> Result<(), String> {
        let mut file = std::fs::File::create(&temp_path).map_err(|e| {
            log::warn!("[write_user_file] 创建临时文件失败: {}", e);
            ErrorCode::PermissionDenied.default_message().to_string()
        })?;

        for chunk in data.chunks(READ_CHUNK_SIZE) {
            file.write_all(chunk).map_err(|e| {
                log::warn!("[write_user_file] 写入临时文件失败: {}", e);
                ErrorCode::Internal.default_message().to_string()
            })?;
        }

        file.sync_all().map_err(|e| {
            log::warn!("[write_user_file] fsync 失败: {}", e);
            ErrorCode::Internal.default_message().to_string()
        })?;

        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }

    /* 超时取消检查必须在 rename 之前：timeout 只放弃等待，spawn_blocking
     * 不会被中止；没有此检查时前端已收到超时错误，文件仍会被替换。 */
    if cancelled() {
        let _ = std::fs::remove_file(&temp_path);
        log::warn!("[write_user_file] 已取消：暂存已清理，目标文件未替换");
        return Err("写入已取消".to_string());
    }

    // 7. rename 原子替换
    if let Err(e) = std::fs::rename(&temp_path, &canonical) {
        log::error!("[write_user_file] rename 失败: {}", e);
        let _ = std::fs::remove_file(&temp_path);
        return Err(ErrorCode::Internal.default_message().to_string());
    }

    log::info!(
        "[write_user_file] 原子写入成功: {} bytes | {}",
        data_size,
        sanitize_path(path)
    );

    Ok(data_size)
}

/// 将原始二进制数据原子写入用户通过对话框选择的位置（二进制 IPC）。
///
/// 与 read_user_file 配套，用于导出功能写入用户选择的保存位置。
///   安全策略与 read_user_file 一致（跳过白名单 + 拒绝系统关键目录 + 其他安全检查）。
///
/// 二进制传输协议（Tauri v2 raw IPC）：
///   - 路径经 `x-path` 请求头传递（前端 `encodeURIComponent` 百分号编码，
///     兼容中文/空格/特殊字符路径；raw body 与 JSON args 互斥）
///   - 文件字节经请求体直传（`InvokeBody::Raw`），零 base64 编解码
#[tauri::command]
pub async fn write_user_file(app: tauri::AppHandle, request: Request<'_>) -> Result<(), String> {
    // x-path 头百分号解码（前端 encodeURIComponent 编码，兼容中文路径）
    let path = decode_x_path_header(&request)?;
    log::info!(
        "[write_user_file] 开始写入用户选择位置: {}",
        sanitize_path(&path)
    );

    let path_in = path.clone();
    // 从请求体提取原始字节（Request 为借用类型，clone 一次后 move 进 'static 闭包；
    // 原始字节直传，省去 base64 字符串分配与解码）
    let data: Vec<u8> = match request.body() {
        InvokeBody::Raw(bytes) => bytes.clone(),
        _ => {
            log::warn!("[write_user_file] 请求体非原始二进制");
            return Err(ErrorCode::InvalidPath.default_message().to_string());
        }
    };
    /* 超时只放弃等待，不中止 spawn_blocking；取消标志让阻塞任务在 rename
     * 前自杀，避免“前端失败、文件已被替换”。 */
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_task = cancel.clone();
    let write_result = tokio::time::timeout(
        USER_FILE_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            write_user_file_blocking(&path_in, &data, Some(cancel_for_task.as_ref()))
        }),
    )
    .await;

    match write_result {
        Err(_) => {
            cancel.store(true, Ordering::SeqCst);
            log::error!(
                "[write_user_file] 写入超时（{}s），已请求取消 | {}",
                USER_FILE_OP_TIMEOUT.as_secs(),
                sanitize_path(&path)
            );
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &path,
                AuditResult::Failure,
                None,
                Some(format!(
                    "超时 {}s：已请求取消，结果未确认",
                    USER_FILE_OP_TIMEOUT.as_secs()
                )),
            );
            Err("写入结果未确认，请核对目标文件".to_string())
        }
        Ok(Err(e)) => {
            log::error!("[write_user_file] spawn_blocking 异常: {}", e);
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
        Ok(Ok(Ok(size))) => {
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &path,
                AuditResult::Success,
                Some(size),
                None,
            );
            Ok(())
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
    }
}
