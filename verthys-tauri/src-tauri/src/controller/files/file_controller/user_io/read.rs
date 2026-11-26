/*
 * 用户授权文件读取
 *
 * 职责边界：分片与整文件读取共用同一条校验链（字符级校验、canonicalize、
 * 系统关键目录拒绝、大小上限）；分片越界或字节数不足即报错，不静默截断。
 */

use super::super::audit::write_file_audit;
use super::super::{READ_CHUNK_SIZE, USER_FILE_CHUNK_OP_TIMEOUT, USER_FILE_OP_TIMEOUT};
use super::path_guard::is_system_critical_path;
use crate::constants::export_stream::{USER_FILE_SIZE_LIMIT, WRITE_FILE_CHUNK_BYTES};
use crate::controller::api_error::ErrorCode;
use crate::util::audit_log::{AuditEventType, AuditResult};
use crate::util::path::sanitize_path;
use tauri::ipc::Response;

/// 同步读取用户通过对话框选择的文件（跳过白名单，拒绝系统关键目录）。
///
/// 读取形态由参数决定：
///   - `offset` / `length` 均缺省：整文件读取（行为不变）；
///   - 两者同时给出：读取 `[offset, offset + length)` 分片。
///
/// 分片形态的契约（越界即报错，禁止静默截断）：
///   - 参数必须成对给出——只给其一即拒绝，避免"缺省长度=读到末尾"
///     之类的隐式语义掩盖源文件长度变化；
///   - `length` 必须大于 0 且不超过流式写入分片上界；
///   - `offset` 不得越过文件长度，`offset + length` 不得越过文件末尾；
///   - 实际读出字节数必须恰为 `length`（读取期间源文件被截断即报错）。
///
/// 与 `read_file_blocking` 的差异：
///   - 跳过白名单校验（用户已通过对话框显式授权）
///   - 增加系统关键目录拒绝（防止读取 C:\Windows 等系统文件）
///   - 同样执行 validate_path_input 字符级校验、canonicalize 与文件大小限制
pub(in super::super) fn read_user_file_range_blocking(
    path: &str,
    offset: Option<u64>,
    length: Option<u64>,
) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};

    // 1. 字符级校验（防路径注入、目录遍历、保留设备名）
    crate::util::path::validate_path_input(path).map_err(|e| {
        log::warn!(
            "[read_user_file] 路径校验失败: {} | {}",
            sanitize_path(path),
            e
        );
        ErrorCode::InvalidPath.default_message().to_string()
    })?;

    // 2. canonicalize 解析符号链接（文件必须存在）
    let canonical = std::fs::canonicalize(path).map_err(|e| {
        log::warn!(
            "[read_user_file] 路径解析失败: {} | {}",
            sanitize_path(path),
            e
        );
        ErrorCode::InvalidPath.default_message().to_string()
    })?;

    // 3. 系统关键目录拒绝
    if is_system_critical_path(&canonical) {
        log::warn!(
            "[read_user_file] 拒绝读取系统关键目录: {}",
            sanitize_path(path)
        );
        return Err(ErrorCode::PermissionDenied.default_message().to_string());
    }

    // 4. 大小检查
    let metadata = std::fs::metadata(&canonical).map_err(|e| {
        log::warn!("[read_user_file] 获取文件元数据失败: {}", e);
        ErrorCode::InvalidPath.default_message().to_string()
    })?;
    let file_size = metadata.len();
    if file_size > USER_FILE_SIZE_LIMIT {
        log::warn!(
            "[read_user_file] 文件过大: {} bytes > {} bytes | {}",
            file_size,
            USER_FILE_SIZE_LIMIT,
            sanitize_path(path)
        );
        return Err(ErrorCode::FileTooLarge.default_message().to_string());
    }

    // 5. 读取
    let file = std::fs::File::open(&canonical).map_err(|e| {
        log::warn!("[read_user_file] 打开文件失败: {}", e);
        ErrorCode::InvalidPath.default_message().to_string()
    })?;

    match (offset, length) {
        (None, None) => {
            let mut reader = std::io::BufReader::new(file);
            let mut all_bytes = Vec::with_capacity(file_size as usize);
            let mut chunk = vec![0u8; READ_CHUNK_SIZE];

            loop {
                let n = reader.read(&mut chunk).map_err(|e| {
                    log::warn!("[read_user_file] 读取文件失败: {}", e);
                    ErrorCode::Internal.default_message().to_string()
                })?;
                if n == 0 {
                    break;
                }
                all_bytes.extend_from_slice(&chunk[..n]);
            }

            log::info!(
                "[read_user_file] 读取成功: {} bytes（整文件） | {}",
                all_bytes.len(),
                sanitize_path(path)
            );
            Ok(all_bytes)
        }
        (Some(offset), Some(length)) => {
            if length == 0 {
                log::warn!("[read_user_file] 拒绝空分片请求: {}", sanitize_path(path));
                return Err("分片长度必须大于 0".to_string());
            }
            if length > WRITE_FILE_CHUNK_BYTES as u64 {
                log::warn!(
                    "[read_user_file] 分片长度超限: {} > {} | {}",
                    length,
                    WRITE_FILE_CHUNK_BYTES,
                    sanitize_path(path)
                );
                return Err(format!("分片长度超过上限 {} 字节", WRITE_FILE_CHUNK_BYTES));
            }
            let end = offset.checked_add(length);
            let in_range = matches!(end, Some(end) if offset <= file_size && end <= file_size);
            if !in_range {
                log::warn!(
                    "[read_user_file] 读取范围越界: offset={} length={} size={} | {}",
                    offset,
                    length,
                    file_size,
                    sanitize_path(path)
                );
                return Err(format!(
                    "读取范围越界（偏移 {} + 长度 {} 超出文件 {} 字节）",
                    offset, length, file_size
                ));
            }

            let mut file = file;
            file.seek(SeekFrom::Start(offset)).map_err(|e| {
                log::warn!("[read_user_file] 定位失败: {}", e);
                ErrorCode::Internal.default_message().to_string()
            })?;
            let mut buf = vec![0u8; length as usize];
            file.read_exact(&mut buf).map_err(|e| {
                log::warn!(
                    "[read_user_file] 分片读取失败（可能被并发截断）: offset={} length={} | {}",
                    offset,
                    length,
                    e
                );
                format!("读取字节数不足（要求 {} 字节）", length)
            })?;

            log::info!(
                "[read_user_file] 读取成功: {} bytes（offset={}） | {}",
                length,
                offset,
                sanitize_path(path)
            );
            Ok(buf)
        }
        _ => {
            log::warn!(
                "[read_user_file] 分片参数不完整（offset/length 必须成对）: {}",
                sanitize_path(path)
            );
            Err("分片参数不完整：offset 与 length 必须同时提供".to_string())
        }
    }
}

/// 读取用户通过对话框显式选择的文件并返回原始二进制内容（二进制 IPC）。
///
/// 用户通过 Tauri 文件对话框 open() 选择的文件已获得明确授权，白名单不适用
///   （用户可能选择 D:\、E:\、网络位置等非 home_dir 路径）。
///   本命令跳过白名单校验，但仍执行：
///   - validate_path_input 字符级校验（防路径注入、目录遍历、保留设备名）
///   - canonicalize（解析符号链接，确保路径真实）
///   - 系统关键目录拒绝（C:\Windows、C:\Program Files 等）
///   - 文件大小限制（2GB）
///   - 超时控制（整文件 120s；分片 15s）
///   - 审计日志
///
/// 读取形态：
///   - `offset` / `length` 缺省 → 整文件读取（返回全部字节）；
///   - 两者同时给出 → 读取分片，越界/长度不符即报错，不静默截断。
///
/// 返回 `tauri::ipc::Response` → 前端 invoke 直接收到 ArrayBuffer，
/// 消除 base64 编码 1.33× 内存放大与编解码 CPU 开销。
///
/// 安全边界：调用方必须确保 path 来自用户通过 Tauri dialog open() 显式选择的路径。
#[tauri::command]
pub async fn read_user_file(
    app: tauri::AppHandle,
    path: String,
    offset: Option<u64>,
    length: Option<u64>,
) -> Result<Response, String> {
    let chunked = offset.is_some() || length.is_some();
    let op_timeout = if chunked {
        USER_FILE_CHUNK_OP_TIMEOUT
    } else {
        USER_FILE_OP_TIMEOUT
    };
    let mode = if chunked {
        format!(
            "分片 offset={} length={}",
            offset.map(|v| v.to_string()).unwrap_or_default(),
            length.map(|v| v.to_string()).unwrap_or_default()
        )
    } else {
        "整文件".to_string()
    };
    log::info!(
        "[read_user_file] 开始读取用户选择文件: {}（{}）",
        sanitize_path(&path),
        mode
    );

    let path_clone = path.clone();
    let read_result = tokio::time::timeout(
        op_timeout,
        tokio::task::spawn_blocking(move || {
            read_user_file_range_blocking(&path_clone, offset, length)
        }),
    )
    .await;

    match read_result {
        Err(_) => {
            log::error!(
                "[read_user_file] 读取超时（{}s，{}）| {}",
                op_timeout.as_secs(),
                mode,
                sanitize_path(&path)
            );
            write_file_audit(
                &app,
                AuditEventType::FileRead,
                &path,
                AuditResult::Failure,
                None,
                Some(format!("超时 {}s", op_timeout.as_secs())),
            );
            Err(ErrorCode::TemporaryFailure.default_message().to_string())
        }
        Ok(Err(e)) => {
            log::error!("[read_user_file] spawn_blocking 异常: {}", e);
            write_file_audit(
                &app,
                AuditEventType::FileRead,
                &path,
                AuditResult::Failure,
                None,
                Some(format!("任务异常: {}", e)),
            );
            Err(ErrorCode::Internal.default_message().to_string())
        }
        Ok(Ok(Ok(bytes))) => {
            write_file_audit(
                &app,
                AuditEventType::FileRead,
                &path,
                AuditResult::Success,
                Some(bytes.len() as u64),
                Some(mode),
            );
            Ok(Response::new(bytes))
        }
        Ok(Ok(Err(e))) => {
            write_file_audit(
                &app,
                AuditEventType::FileRead,
                &path,
                AuditResult::Failure,
                None,
                Some(e.clone()),
            );
            Err(e)
        }
    }
}
