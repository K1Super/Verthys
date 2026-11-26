/*
 * 沙箱白名单读写
 *
 * 职责边界：白名单构建、路径校验、分块读取、临时文件 + fsync + rename 的
 * 原子写入，以及对应的二进制 IPC 命令。所有路径必须 canonicalize 后落在
 * 白名单基目录内，阻断目录遍历与符号链接绕过。
 */

use crate::controller::api_error::ErrorCode;
use crate::util::audit_log::{AuditEventType, AuditResult};
use crate::util::path::sanitize_path;
use crate::util::sandbox::resolve_and_validate;
#[cfg(test)]
use crate::util::sandbox::SandboxError;
use tauri::ipc::{InvokeBody, Request, Response};
use tauri::Manager;

use super::*;
// ===== 白名单构建 =====

/// 构建文件操作白名单基目录列表。
///
/// 包含应用数据、配置、文档、图片、下载、用户主目录和桌面目录，所有文件
/// 操作必须位于这些目录内。若白名单为空，则所有操作均被拒绝。
pub(super) fn build_whitelist(app: &tauri::AppHandle) -> Vec<String> {
    let mut whitelist = Vec::new();

    if let Ok(data_dir) = app.path().app_data_dir() {
        if let Some(s) = data_dir.to_str() {
            whitelist.push(s.to_string());
        }
    }
    if let Ok(config_dir) = app.path().app_config_dir() {
        if let Some(s) = config_dir.to_str() {
            whitelist.push(s.to_string());
        }
    }
    if let Ok(doc_dir) = app.path().document_dir() {
        if let Some(s) = doc_dir.to_str() {
            whitelist.push(s.to_string());
        }
    }
    if let Ok(pic_dir) = app.path().picture_dir() {
        if let Some(s) = pic_dir.to_str() {
            whitelist.push(s.to_string());
        }
    }
    if let Ok(dl_dir) = app.path().download_dir() {
        if let Some(s) = dl_dir.to_str() {
            whitelist.push(s.to_string());
        }
    }

    // 用户主目录与桌面同为白名单基目录：
    //   - home_dir 覆盖桌面/文档/下载等全部用户子目录
    //   - desktop_dir 显式覆盖桌面（home_dir 获取失败时仍可用）
    // 用户通过 dialog open() 显式选择的文件已获得授权，白名单信任主目录
    // 范围内的路径；系统目录（C:\Windows 等）与路径遍历（../）仍被拒绝。
    if let Ok(home_dir) = app.path().home_dir() {
        if let Some(s) = home_dir.to_str() {
            whitelist.push(s.to_string());
        }
    }
    if let Ok(desktop_dir) = app.path().desktop_dir() {
        if let Some(s) = desktop_dir.to_str() {
            whitelist.push(s.to_string());
        }
    }

    whitelist
}

/// 将沙箱校验错误映射为前端可用的错误码（脱敏）。
#[cfg(test)]
pub(super) fn sandbox_error_to_code(err: &SandboxError) -> ErrorCode {
    match err {
        SandboxError::InvalidPath(_) => ErrorCode::InvalidPath,
        SandboxError::ResolveFailed(_) => ErrorCode::InvalidPath,
        SandboxError::NotInWhitelist => ErrorCode::PermissionDenied,
    }
}

// ===== 流式读取实现 =====

/// 同步读取文件并返回原始字节（二进制 IPC：去 base64 化）。
///
/// 内部执行路径校验、大小检查、分块读取，错误通过 Result 返回。
/// 所有错误消息已脱敏，仅用于日志。
pub(super) fn read_file_blocking(path: &str, whitelist: &[String]) -> Result<Vec<u8>, String> {
    use std::io::Read;

    // 沙箱校验
    let whitelist_refs: Vec<&str> = whitelist.iter().map(|s| s.as_str()).collect();
    let canonical = resolve_and_validate(path, &whitelist_refs).map_err(|e| {
        log::warn!(
            "[read_file_bytes] 沙箱校验失败: {} | {}",
            sanitize_path(path),
            e
        );
        ErrorCode::InvalidPath.default_message().to_string()
    })?;

    // 大小检查
    let metadata = std::fs::metadata(&canonical).map_err(|e| {
        log::warn!("[read_file_bytes] 获取文件元数据失败: {}", e);
        ErrorCode::InvalidPath.default_message().to_string()
    })?;
    let file_size = metadata.len();
    if file_size > FILE_SIZE_LIMIT {
        log::warn!(
            "[read_file_bytes] 文件过大: {} bytes > {} bytes | {}",
            file_size,
            FILE_SIZE_LIMIT,
            sanitize_path(path)
        );
        return Err(ErrorCode::FileTooLarge.default_message().to_string());
    }

    // 分块读取
    let file = std::fs::File::open(&canonical).map_err(|e| {
        log::warn!("[read_file_bytes] 打开文件失败: {}", e);
        ErrorCode::InvalidPath.default_message().to_string()
    })?;

    let mut reader = std::io::BufReader::new(file);
    let mut all_bytes = Vec::with_capacity(file_size as usize);
    let mut chunk = vec![0u8; READ_CHUNK_SIZE];

    loop {
        let n = reader.read(&mut chunk).map_err(|e| {
            log::warn!("[read_file_bytes] 读取文件失败: {}", e);
            ErrorCode::Internal.default_message().to_string()
        })?;
        if n == 0 {
            break;
        }
        all_bytes.extend_from_slice(&chunk[..n]);
    }

    log::info!(
        "[read_file_bytes] 读取成功: {} bytes | {}",
        file_size,
        sanitize_path(path)
    );

    Ok(all_bytes)
}

// ===== 原子写入实现 =====

/// 同步执行原子写入，返回写入字节数。
///
/// 流程：
/// - 获取全局写互斥锁。
/// - 沙箱校验目标路径（若目标不存在，则校验父目录）。
/// - 检查原始字节大小（二进制 IPC：去 base64 化）。
/// - 生成临时文件（同目录，随机后缀）。
/// - 写入数据，fsync 刷盘。
/// - rename 原子替换。
/// - 失败时清理临时文件。
pub(super) fn write_file_blocking(path: &str, data: &[u8], whitelist: &[String]) -> Result<u64, String> {
    // 全局写互斥
    let _write_guard = WRITE_MUTEX.lock().map_err(|e| {
        log::error!("[write_file_bytes] 写互斥锁中毒: {}", e);
        ErrorCode::Internal.default_message().to_string()
    })?;
    use std::io::Write;

    // 沙箱校验（若目标不存在，则校验父目录）
    let whitelist_refs: Vec<&str> = whitelist.iter().map(|s| s.as_str()).collect();
    let canonical = match resolve_and_validate(path, &whitelist_refs) {
        Ok(c) => c,
        Err(e) => {
            if e.contains("路径解析失败") || e.contains("ResolveFailed") {
                let parent = std::path::Path::new(path)
                    .parent()
                    .ok_or_else(|| ErrorCode::InvalidPath.default_message().to_string())?;
                let parent_str = parent
                    .to_str()
                    .ok_or_else(|| ErrorCode::InvalidPath.default_message().to_string())?;
                let parent_canonical =
                    resolve_and_validate(parent_str, &whitelist_refs).map_err(|_| {
                        log::warn!(
                            "[write_file_bytes] 父目录沙箱校验失败 | {}",
                            sanitize_path(path)
                        );
                        ErrorCode::PermissionDenied.default_message().to_string()
                    })?;
                let file_name = std::path::Path::new(path)
                    .file_name()
                    .ok_or_else(|| ErrorCode::InvalidPath.default_message().to_string())?;
                parent_canonical.join(file_name)
            } else {
                log::warn!(
                    "[write_file_bytes] 沙箱校验失败: {} | {}",
                    e,
                    sanitize_path(path)
                );
                return Err(ErrorCode::InvalidPath.default_message().to_string());
            }
        }
    };

    // 大小检查（原始字节直传，无需 Base64 解码）
    let data_size = data.len() as u64;

    if data_size > FILE_SIZE_LIMIT {
        log::warn!(
            "[write_file_bytes] 数据过大: {} bytes > {} bytes",
            data_size,
            FILE_SIZE_LIMIT
        );
        return Err(ErrorCode::FileTooLarge.default_message().to_string());
    }

    // 生成临时文件
    let mut random_bytes = [0u8; 8];
    crate::util::random::fill_random_bytes(&mut random_bytes);
    let random_suffix: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let temp_path = canonical.with_extension(format!("tmp.{}", random_suffix));

    log::debug!(
        "[write_file_bytes] 临时文件: {}",
        sanitize_path(&temp_path.to_string_lossy())
    );

    // 写入临时文件 + fsync
    let write_result = (|| -> Result<(), String> {
        let mut file = std::fs::File::create(&temp_path).map_err(|e| {
            log::warn!("[write_file_bytes] 创建临时文件失败: {}", e);
            ErrorCode::PermissionDenied.default_message().to_string()
        })?;

        for chunk in data.chunks(READ_CHUNK_SIZE) {
            file.write_all(chunk).map_err(|e| {
                log::warn!("[write_file_bytes] 写入临时文件失败: {}", e);
                ErrorCode::Internal.default_message().to_string()
            })?;
        }

        file.sync_all().map_err(|e| {
            log::warn!("[write_file_bytes] fsync 失败: {}", e);
            ErrorCode::Internal.default_message().to_string()
        })?;

        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }

    // rename 原子替换
    if let Err(e) = std::fs::rename(&temp_path, &canonical) {
        log::error!("[write_file_bytes] rename 失败: {}", e);
        let _ = std::fs::remove_file(&temp_path);
        return Err(ErrorCode::Internal.default_message().to_string());
    }

    log::info!(
        "[write_file_bytes] 原子写入成功: {} bytes | {}",
        data_size,
        sanitize_path(path)
    );

    Ok(data_size)
}

// ===== Tauri 命令 =====

/// 读取文件并返回原始二进制内容（二进制 IPC：去 base64 化）。
///
/// 用于前端导入照片等场景。受沙箱、大小限制、超时控制，
/// 所有错误已脱敏，仅返回通用错误码。
/// 返回 `tauri::ipc::Response` → 前端 invoke 直接收到 ArrayBuffer，
/// 消除 base64 编码带来的 1.33× 内存放大与编解码 CPU 开销。
#[tauri::command]
pub async fn read_file_bytes(app: tauri::AppHandle, path: String) -> Result<Response, String> {
    log::info!("[read_file_bytes] 开始读取: {}", sanitize_path(&path));

    let whitelist = build_whitelist(&app);
    if whitelist.is_empty() {
        log::error!("[read_file_bytes] 白名单为空，拒绝所有文件操作");
        write_file_audit(
            &app,
            AuditEventType::FileRead,
            &path,
            AuditResult::Failure,
            None,
            Some("白名单为空".into()),
        );
        return Err(ErrorCode::PermissionDenied.default_message().to_string());
    }

    let path_clone = path.clone();
    let whitelist_clone = whitelist.clone();
    let read_result = tokio::time::timeout(
        FILE_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || read_file_blocking(&path_clone, &whitelist_clone)),
    )
    .await;

    match read_result {
        Err(_) => {
            log::error!(
                "[read_file_bytes] 读取超时（{}s）| {}",
                FILE_OP_TIMEOUT.as_secs(),
                sanitize_path(&path)
            );
            write_file_audit(
                &app,
                AuditEventType::FileRead,
                &path,
                AuditResult::Failure,
                None,
                Some(format!("超时 {}s", FILE_OP_TIMEOUT.as_secs())),
            );
            Err(ErrorCode::TemporaryFailure.default_message().to_string())
        }
        Ok(Err(e)) => {
            log::error!("[read_file_bytes] spawn_blocking 异常: {}", e);
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
                None,
                None,
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

/// 从 `x-path` 请求头解码目标路径（百分号解码，中文路径兼容）。
///
/// HTTP 头值仅允许可见 ASCII，前端对路径整体 `encodeURIComponent` 编码后传输
/// （中文/空格/`#`/`%` 等全部转 `%XX`）。解码核心为 [`decode_percent_path`]。
pub(super) fn decode_x_path_header(request: &Request<'_>) -> Result<String, String> {
    let raw = request
        .headers()
        .get("x-path")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if raw.is_empty() {
        log::warn!("[x-path] 缺少 x-path 请求头");
        return Err(ErrorCode::InvalidPath.default_message().to_string());
    }

    decode_percent_path(raw)
}

/// 严格百分号解码（纯函数，供单元测试覆盖）。
///
///   1. `%` 后必须紧跟两位十六进制数字（畸形序列如 `%ZZ` 直接拒绝，不留原样）
///   2. 解码字节流必须是合法 UTF-8
///   3. 解码结果为空 → 拒绝
///
/// 解码后的路径仍走完整安全链（validate_path_input / canonicalize /
/// 白名单或系统关键目录拒绝），编码层不承载任何安全语义。
pub(super) fn decode_percent_path(raw: &str) -> Result<String, String> {
    let invalid_path = || ErrorCode::InvalidPath.default_message().to_string();

    // 严格 %XX 校验（percent_decode_str 对无效序列惰性保留原样，须前置校验拦截）
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex_ok = i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit();
            if !hex_ok {
                log::warn!("[x-path] 畸形百分号编码（位置 {}）", i);
                return Err(invalid_path());
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| {
            log::warn!("[x-path] 解码后非合法 UTF-8");
            invalid_path()
        })?;

    if decoded.is_empty() {
        log::warn!("[x-path] 解码后路径为空");
        return Err(invalid_path());
    }

    Ok(decoded.into_owned())
}

/// 将原始二进制数据原子写入文件（二进制 IPC：去 base64 化）。
///
/// 用于前端导出加密文件。保证写入原子性，防止写入过程中断导致文件损坏。
/// 受沙箱、大小限制、超时和写入互斥控制。
///
/// 二进制传输协议（Tauri v2 raw IPC）：
///   - 路径经 `x-path` 请求头传递（前端 `encodeURIComponent` 百分号编码，
///     兼容中文/空格/特殊字符路径；raw body 与 JSON args 互斥）
///   - 文件字节经请求体直传（`InvokeBody::Raw`），零 base64 编解码
#[tauri::command]
pub async fn write_file_bytes(app: tauri::AppHandle, request: Request<'_>) -> Result<(), String> {
    // x-path 头百分号解码（前端 encodeURIComponent 编码，兼容中文路径）
    let path = decode_x_path_header(&request)?;
    log::info!("[write_file_bytes] 开始写入: {}", sanitize_path(&path));

    let whitelist = build_whitelist(&app);
    if whitelist.is_empty() {
        log::error!("[write_file_bytes] 白名单为空，拒绝所有文件操作");
        write_file_audit(
            &app,
            AuditEventType::FileWrite,
            &path,
            AuditResult::Failure,
            None,
            Some("白名单为空".into()),
        );
        return Err(ErrorCode::PermissionDenied.default_message().to_string());
    }

    let path_clone = path.clone();
    let whitelist_clone = whitelist.clone();
    // 从请求体提取原始字节（Request 为借用类型，clone 一次后 move 进 'static 闭包；
    // 原始字节直传，省去 base64 字符串分配与解码）
    let data: Vec<u8> = match request.body() {
        InvokeBody::Raw(bytes) => bytes.clone(),
        _ => {
            log::warn!("[write_file_bytes] 请求体非原始二进制");
            return Err(ErrorCode::InvalidPath.default_message().to_string());
        }
    };
    let write_result = tokio::time::timeout(
        FILE_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            write_file_blocking(&path_clone, &data, &whitelist_clone)
        }),
    )
    .await;

    match write_result {
        Err(_) => {
            log::error!(
                "[write_file_bytes] 写入超时（{}s）| {}",
                FILE_OP_TIMEOUT.as_secs(),
                sanitize_path(&path)
            );
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &path,
                AuditResult::Failure,
                None,
                Some(format!("超时 {}s", FILE_OP_TIMEOUT.as_secs())),
            );
            Err(ErrorCode::TemporaryFailure.default_message().to_string())
        }
        Ok(Err(e)) => {
            log::error!("[write_file_bytes] spawn_blocking 异常: {}", e);
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
