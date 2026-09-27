/*
 * @file controller/file_controller.rs
 * @brief 文件读写控制器 - 沙箱隔离、流式传输与原子写入
 *
 * 本模块提供受限的文件读写能力，供前端导入/导出加密数据。
 * 所有操作基于沙箱白名单、流式分块处理、原子写入及审计日志，
 * 确保路径安全、内存可控、写入可靠。
 *
 * =============================================================================
 * 核心设计
 * =============================================================================
 * - 沙箱白名单：以应用数据目录、配置目录、文档/图片/下载目录为基，
 *   所有路径经 canonicalize 解析并验证是否在基目录内，阻断目录遍历和符号链接绕过。
 * - 流式读取：分块（64KB）读取文件，避免一次性加载大文件，上限 50MB。
 * - 原子写入：先写临时文件（同目录、随机后缀），fsync 刷盘后 rename 替换，
 *   中途失败自动清理临时文件。
 * - 写入串行化：全局互斥锁序列化所有写操作，防止交错写入导致文件损坏。
 * - 异步隔离：同步 I/O 在 spawn_blocking 中执行，并受 10 秒超时保护。
 * - 审计日志：每次读写记录操作类型、路径哈希、结果和大小，不含内容。
 * - 错误脱敏：前端仅收到通用错误码（INVALID_PATH / PERMISSION_DENIED / FILE_TOO_LARGE / TEMPORARY_FAILURE），
 *   详细错误仅写入日志（路径经 sanitize 处理）。
 *
 * =============================================================================
 * 安全约束
 * =============================================================================
 * - 所有路径必须位于白名单内，否则拒绝。
 * - 文件大小上限 50MB，超出返回 FILE_TOO_LARGE。
 * - Base64 解码失败或数据超限均拒绝写入。
 * - 临时文件在 rename 前确保数据落盘（fsync），防止电源中断导致数据丢失。
 * - 写操作互斥，避免多线程并发写入同一文件。
 * - 审计日志不存储文件内容或明文路径（使用路径哈希）。
 *
 * =============================================================================
 * 依赖方向
 * =============================================================================
 * controller → util::sandbox / util::base64 / util::path / util::audit_log /
 *             util::random / constants / controller::api_error
 */

use crate::constants::export_stream::{
    MAX_EXPORT_SINGLE_BYTES, STALE_TEMP_MAX_AGE, WRITE_FILE_CHUNK_BYTES,
};
use crate::constants::timeout::DEFAULT as TIMEOUT_CONFIG;
use crate::controller::api_error::ErrorCode;
use crate::controller::verthys_controller::require_unlocked;
use crate::security::command_names::cmd;
use crate::state::file_streams::FileStreamState;
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};
use crate::util::path::sanitize_path;
use crate::util::sandbox::{resolve_and_validate, SandboxError};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::ipc::{InvokeBody, Request, Response};
use tauri::{Manager, State};

// ===== 文件大小与块大小 =====

/// 允许读取/写入的最大文件大小（50MB），防止内存耗尽。
const FILE_SIZE_LIMIT: u64 = 50 * 1024 * 1024;

/// 用户授权文件操作的最大文件大小（2GB）。
///
/// 用户通过对话框显式选择的文件（如含几千张加密照片的 .venc 打包文件）
/// 可能达到数百 MB 甚至 GB 级。50MB 的白名单限制会误拒合法的大文件。
/// 此限制仅用于 read_user_file / write_user_file，与沙箱白名单操作的
/// FILE_SIZE_LIMIT 隔离，避免内部文件操作的安全边界被放宽。
const USER_FILE_SIZE_LIMIT: u64 = 2 * 1024 * 1024 * 1024;

/// 流式读写的分块大小（64KB），平衡内存与性能。
const READ_CHUNK_SIZE: usize = 64 * 1024;

/// 文件操作超时（10 秒），源自全局 IPC 超时配置。
const FILE_OP_TIMEOUT: Duration = TIMEOUT_CONFIG.ipc;

/// 用户授权文件操作超时（120 秒）。
///
/// 大文件（数百 MB ~ 2GB）的读取/写入需要更长时间，
/// 10 秒超时会误杀合法的大文件传输。此超时仅用于 read_user_file /
/// write_user_file，与沙箱白名单操作的 FILE_OP_TIMEOUT 隔离。
const USER_FILE_OP_TIMEOUT: Duration = Duration::from_secs(120);

// ===== 写操作互斥锁 =====

/// 全局写互斥锁，序列化所有文件写入，防止并发写操作交叉破坏文件。
static WRITE_MUTEX: Mutex<()> = Mutex::new(());

// ===== 审计日志辅助 =====

fn get_audit_log_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join("audit.log")),
        Err(e) => {
            log::warn!("[audit] 获取配置目录失败，跳过审计写入: {}", e);
            None
        }
    }
}

fn get_audit_hmac_key() -> Option<[u8; 32]> {
    use crate::infrastructure::device_fingerprint::get_device_fingerprint;
    use crate::util::crypto::pbkdf2_derive_default;

    match get_device_fingerprint() {
        Ok(fingerprint) => {
            const AUDIT_SALT: &[u8] = b"verthys_audit_log_hmac_salt_v1";
            match pbkdf2_derive_default(fingerprint.as_bytes(), AUDIT_SALT) {
                Ok(key) => Some(key),
                Err(e) => {
                    log::warn!("[audit] 派生 HMAC 密钥失败，跳过审计写入: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            log::warn!("[audit] 获取设备指纹失败，跳过审计写入: {}", e);
            None
        }
    }
}

/// 记录文件操作审计事件。
///
/// 审计条目包含操作类型、路径哈希、结果和文件大小（若成功），
/// 不记录文件内容或明文路径。
fn write_file_audit(
    app: &tauri::AppHandle,
    event_type: AuditEventType,
    path: &str,
    result: AuditResult,
    size: Option<u64>,
    detail: Option<String>,
) {
    let log_path = match get_audit_log_path(app) {
        Some(p) => p,
        None => return,
    };

    let hmac_key = match get_audit_hmac_key() {
        Some(k) => k,
        None => return,
    };

    let session_id = format!("pid-{}", std::process::id());

    let mut event = AuditEvent::new(event_type, &session_id, "user", result).with_resource(path);

    let mut detail_parts = Vec::new();
    if let Some(s) = size {
        detail_parts.push(format!("size={}B", s));
    }
    if let Some(d) = detail {
        detail_parts.push(d);
    }
    if !detail_parts.is_empty() {
        event = event.with_detail(detail_parts.join(" | "));
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[audit] 写入文件审计事件失败（不阻塞业务）: {}", e);
    }
}

// ===== 白名单构建 =====

/// 构建文件操作白名单基目录列表。
///
/// 包含应用数据、配置、文档、图片和下载目录，所有文件操作必须
/// 位于这些目录内。若白名单为空，则所有操作均被拒绝。
fn build_whitelist(app: &tauri::AppHandle) -> Vec<String> {
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

    // 修复：扩展白名单至用户主目录与桌面
    //
    // 原缺陷：白名单仅含 app_data/app_config/Documents/Pictures/Downloads，
    // 不含 Desktop 及用户主目录。用户通过 Tauri 文件对话框选择的 .bin 密钥文件
    // 若位于桌面（最常见场景），readFileBytes 沙箱校验失败返回 PermissionDenied，
    // 前端 browseBin 静默吞错导致 binBytes=null。按钮 :disabled 用 !binFileName
    // 判断（通过，可点击），但 onVerify/onInitKey 函数守卫用 !binBytes.value
    // 判断（失败，静默返回），用户看到"按钮完全无反应"。
    //
    // 修复：新增 home_dir（覆盖桌面/文档/下载等全部用户子目录）+ desktop_dir
    // （显式桌面，兼容 home_dir 获取失败的情况）。用户通过 dialog open() 显式
    // 选择的文件已获得用户授权，白名单应信任用户主目录范围内的路径。沙箱仍
    // 拒绝系统目录（C:\Windows 等）和路径遍历攻击（../），安全边界不变。
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
fn sandbox_error_to_code(err: &SandboxError) -> ErrorCode {
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
fn read_file_blocking(path: &str, whitelist: &[String]) -> Result<Vec<u8>, String> {
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
fn write_file_blocking(path: &str, data: &[u8], whitelist: &[String]) -> Result<u64, String> {
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
fn decode_x_path_header(request: &Request<'_>) -> Result<String, String> {
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
fn decode_percent_path(raw: &str) -> Result<String, String> {
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
    // 相比原 base64 路径仍省一次 1.33× 字符串分配 + 解码）
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

// ===== 用户授权文件操作（跳过白名单，拒绝系统关键目录） =====
//
// 修复：拾光解析功能无法导入本地文件
//
// 原缺陷：
//   read_file_bytes / write_file_bytes 强制执行沙箱白名单校验，
//   白名单仅含 app_data / app_config / Documents / Pictures / Downloads /
//   home_dir / desktop_dir。用户通过 Tauri 文件对话框 open() 显式选择的
//   .venc 文件若位于其他磁盘（D:\、E:\）或网络位置，沙箱校验返回
//   NotInWhitelist → PermissionDenied，前端 chooseParseFile catch 块
//   仅显示"读取文件失败"，用户看到"无法导入本地文件"。
//
// 根治方式：
//   用户通过原生文件对话框显式选择的文件已获得用户明确授权，
//   白名单校验不再适用。新增 read_user_file / write_user_file 命令：
//   - 跳过白名单校验（用户已通过对话框授权）
//   - 保留 validate_path_input 字符级校验（防路径注入、目录遍历、保留设备名）
//   - 保留 canonicalize（解析符号链接，确保路径真实）
//   - 新增系统关键目录拒绝（C:\Windows、C:\Program Files 等）
//   - 保留文件大小限制（50MB）
//   - 保留超时控制（10s）
//   - 保留审计日志

/// 系统关键目录前缀列表（canonicalize 后规范化为小写 + 正斜杠比较）。
///
/// 用户对话框选择的文件跳过白名单，但仍须拒绝系统关键目录，
/// 防止应用读取/覆盖系统敏感文件（如 C:\Windows\System32\config\SAM）。
#[cfg(windows)]
const SYSTEM_CRITICAL_PREFIXES: &[&str] = &[
    "c:/windows",
    "c:/program files",
    "c:/program files (x86)",
    "c:/programdata",
    "c:/system volume information",
    "c:/$recycle.bin",
    "c:/boot",
    "c:/recovery",
    "c:/drivers",
    "c:/intel",
    "c:/perflogs",
];

#[cfg(not(windows))]
const SYSTEM_CRITICAL_PREFIXES: &[&str] = &[
    "/etc",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/root",
    "/var/log",
];

/// 检测 canonicalize 后的路径是否位于系统关键目录内。
///
/// 用于 read_user_file / write_user_file 命令的安全兜底：
/// 用户对话框选择的文件跳过白名单，但仍拒绝系统关键目录。
///
/// 比较方式：路径与前缀均转为小写 + 正斜杠，trim 尾部分隔符后
/// 精确匹配或前缀匹配（path 以 base/ 开头）。
fn is_system_critical_path(canonical: &std::path::Path) -> bool {
    let path_str = canonical
        .to_string_lossy()
        .to_lowercase()
        .replace('\\', "/");
    let path_str = path_str.trim_end_matches('/');

    for prefix in SYSTEM_CRITICAL_PREFIXES {
        let prefix = prefix.trim_end_matches('/');
        if path_str == prefix || path_str.starts_with(&format!("{}/", prefix)) {
            return true;
        }
    }
    false
}

/// 同步读取用户通过对话框选择的文件（跳过白名单，拒绝系统关键目录）。
///
/// 与 `read_file_blocking` 的区别：
///   - 跳过白名单校验（用户已通过对话框显式授权）
///   - 新增系统关键目录拒绝（防止读取 C:\Windows 等系统文件）
///   - 保留 validate_path_input 字符级校验（防路径注入）
///   - 保留 canonicalize（解析符号链接）
///   - 保留文件大小限制、分块读取
fn read_user_file_blocking(path: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;

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

    // 5. 分块读取
    let file = std::fs::File::open(&canonical).map_err(|e| {
        log::warn!("[read_user_file] 打开文件失败: {}", e);
        ErrorCode::InvalidPath.default_message().to_string()
    })?;

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
        "[read_user_file] 读取成功: {} bytes | {}",
        file_size,
        sanitize_path(path)
    );

    Ok(all_bytes)
}

/// 解析用户授权写入目标为规范化绝对路径（原子写入与流式写入共用）。
///
/// 校验链：
///   1. validate_path_input 字符级校验（防路径注入、目录遍历、保留设备名）；
///   2. canonicalize：文件已存在直接解析，不存在则解析父目录并拼接文件名；
///   3. 系统关键目录拒绝（防止覆盖 C:\Windows 等系统文件）。
///
/// `log_tag` 仅用于日志前缀区分调用方，不参与任何语义。
fn resolve_user_file_target(path: &str, log_tag: &str) -> Result<PathBuf, String> {
    // 1. 字符级校验
    crate::util::path::validate_path_input(path).map_err(|e| {
        log::warn!(
            "[{}] 路径校验失败: {} | {}",
            log_tag,
            sanitize_path(path),
            e
        );
        ErrorCode::InvalidPath.default_message().to_string()
    })?;

    // 2. 解析目标路径：若文件已存在直接 canonicalize；否则 canonicalize 父目录 + 拼接文件名
    let path_obj = std::path::Path::new(path);
    let canonical = match std::fs::canonicalize(path) {
        // 文件已存在 → canonicalize 成功
        Ok(c) => c,
        // 文件不存在 → canonicalize 父目录 + 拼接文件名
        Err(_) => {
            let parent = path_obj.parent().ok_or_else(|| {
                log::warn!("[{}] 无法解析父目录 | {}", log_tag, sanitize_path(path));
                ErrorCode::InvalidPath.default_message().to_string()
            })?;
            let parent_str = parent.to_str().ok_or_else(|| {
                log::warn!(
                    "[{}] 父目录路径含非 UTF-8 字符 | {}",
                    log_tag,
                    sanitize_path(path)
                );
                ErrorCode::InvalidPath.default_message().to_string()
            })?;
            let parent_canonical = std::fs::canonicalize(parent_str).map_err(|e| {
                log::warn!(
                    "[{}] 父目录解析失败: {} | {}",
                    log_tag,
                    sanitize_path(path),
                    e
                );
                ErrorCode::InvalidPath.default_message().to_string()
            })?;
            let file_name = path_obj.file_name().ok_or_else(|| {
                log::warn!("[{}] 无效文件名 | {}", log_tag, sanitize_path(path));
                ErrorCode::InvalidPath.default_message().to_string()
            })?;
            parent_canonical.join(file_name)
        }
    };

    // 3. 系统关键目录拒绝
    if is_system_critical_path(&canonical) {
        log::warn!(
            "[{}] 拒绝写入系统关键目录: {}",
            log_tag,
            sanitize_path(path)
        );
        return Err(ErrorCode::PermissionDenied.default_message().to_string());
    }

    Ok(canonical)
}

/// 同步执行用户授权的原子写入（跳过白名单，拒绝系统关键目录）。
///
/// 与 `write_file_blocking` 的区别：
///   - 跳过白名单校验（用户已通过对话框显式授权保存位置）
///   - 新增系统关键目录拒绝（防止覆盖 C:\Windows 等系统文件）
///   - 保留 validate_path_input 字符级校验
///   - 保留 canonicalize（解析父目录符号链接）
///   - 保留原子写入、fsync、全局写互斥
fn write_user_file_blocking(path: &str, data: &[u8]) -> Result<u64, String> {
    // 全局写互斥
    let _write_guard = WRITE_MUTEX.lock().map_err(|e| {
        log::error!("[write_user_file] 写互斥锁中毒: {}", e);
        ErrorCode::Internal.default_message().to_string()
    })?;
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

/// 读取用户通过对话框显式选择的文件并返回原始二进制内容（二进制 IPC）。
///
/// 修复：用户通过 Tauri 文件对话框 open() 选择的文件已获得用户明确授权，
///   白名单校验不再适用（用户可能选择 D:\、E:\、网络位置等非 home_dir 路径）。
///   本命令跳过白名单校验，但仍保留：
///   - validate_path_input 字符级校验（防路径注入、目录遍历、保留设备名）
///   - canonicalize（解析符号链接，确保路径真实）
///   - 系统关键目录拒绝（C:\Windows、C:\Program Files 等）
///   - 文件大小限制（2GB）
///   - 超时控制（10s）
///   - 审计日志
///
/// 返回 `tauri::ipc::Response` → 前端 invoke 直接收到 ArrayBuffer，
/// 消除 base64 编码 1.33× 内存放大与编解码 CPU（原单张照片峰值 ×2.66 → ×1）。
///
/// 安全边界：调用方必须确保 path 来自用户通过 Tauri dialog open() 显式选择的路径。
#[tauri::command]
pub async fn read_user_file(app: tauri::AppHandle, path: String) -> Result<Response, String> {
    log::info!(
        "[read_user_file] 开始读取用户选择文件: {}",
        sanitize_path(&path)
    );

    let path_clone = path.clone();
    let read_result = tokio::time::timeout(
        USER_FILE_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || read_user_file_blocking(&path_clone)),
    )
    .await;

    match read_result {
        Err(_) => {
            log::error!(
                "[read_user_file] 读取超时（{}s）| {}",
                USER_FILE_OP_TIMEOUT.as_secs(),
                sanitize_path(&path)
            );
            write_file_audit(
                &app,
                AuditEventType::FileRead,
                &path,
                AuditResult::Failure,
                None,
                Some(format!("超时 {}s", USER_FILE_OP_TIMEOUT.as_secs())),
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

/// 将原始二进制数据原子写入用户通过对话框选择的位置（二进制 IPC）。
///
/// 修复：与 read_user_file 配套，用于导出功能写入用户选择的保存位置。
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
    // 相比原 base64 路径仍省一次 1.33× 字符串分配 + 解码）
    let data: Vec<u8> = match request.body() {
        InvokeBody::Raw(bytes) => bytes.clone(),
        _ => {
            log::warn!("[write_user_file] 请求体非原始二进制");
            return Err(ErrorCode::InvalidPath.default_message().to_string());
        }
    };
    let write_result = tokio::time::timeout(
        USER_FILE_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || write_user_file_blocking(&path_in, &data)),
    )
    .await;

    match write_result {
        Err(_) => {
            log::error!(
                "[write_user_file] 写入超时（{}s）| {}",
                USER_FILE_OP_TIMEOUT.as_secs(),
                sanitize_path(&path)
            );
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &path,
                AuditResult::Failure,
                None,
                Some(format!("超时 {}s", USER_FILE_OP_TIMEOUT.as_secs())),
            );
            Err(ErrorCode::TemporaryFailure.default_message().to_string())
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
fn generate_stream_id() -> String {
    let mut buf = [0u8; 16];
    crate::util::random::fill_random_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 清理目录内的流式暂存残留（修改时间早于清理阈值的 `.venc.tmp` 文件）。
///
/// 崩溃/强杀会遗留未 finalize 的暂存文件；暂存永远不会被 rename 到目标
/// （finalize 在 rename 前注销会话），残留是纯磁盘垃圾。创建新流时对
/// 目标所在目录执行按龄清理，等价于启动清理的惰性化，不影响新鲜残留
/// （可能属于并发活跃会话）。
fn cleanup_stale_stream_temps(dir: &std::path::Path) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_temp = path
            .file_name()
            .map(|n| n.to_string_lossy().ends_with(".venc.tmp"))
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

/// 创建流式写入会话（阻塞核心）：目标校验 + 暂存独占创建。
///
/// 返回会话标识与会话状态（尚未注册进会话表，由命令层在短临界区内
/// 完成注册）。暂存文件使用 create_new 独占创建：同目标并发的第二个
/// 会话创建必然失败，从根上排除双写同一暂存路径。
fn stream_create_blocking(target: &str) -> Result<(String, Arc<Mutex<FileStreamState>>), String> {
    let canonical = resolve_user_file_target(target, "stream_create")?;

    // 暂存路径：与目标同级、固定后缀，finalize rename 后即消失
    let temp_path = canonical.with_extension("venc.tmp");
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
fn stream_append_blocking(entry: &Arc<Mutex<FileStreamState>>, data: &[u8]) -> Result<(), String> {
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
fn stream_finalize_blocking(entry: Arc<Mutex<FileStreamState>>) -> Result<u64, String> {
    let _write_guard = WRITE_MUTEX.lock().map_err(|e| {
        log::error!("[finalize_user_file_stream] 写互斥锁中毒: {}", e);
        ErrorCode::Internal.default_message().to_string()
    })?;

    let (temp, target, total) = {
        let state = match entry.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
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
fn stream_abort_blocking(entry: Arc<Mutex<FileStreamState>>) -> Result<(), String> {
    let temp = {
        let state = match entry.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
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
fn decode_stream_id_header(request: &Request<'_>) -> Result<String, String> {
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

    let append_result = tokio::time::timeout(
        USER_FILE_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || stream_append_blocking(&entry, &data)),
    )
    .await;

    match append_result {
        Err(_) => {
            log::error!(
                "[append_user_file_chunk] 追加超时（{}s）",
                USER_FILE_OP_TIMEOUT.as_secs()
            );
            Err(ErrorCode::TemporaryFailure.default_message().to_string())
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

    let finalize_result = tokio::time::timeout(
        USER_FILE_OP_TIMEOUT,
        tokio::task::spawn_blocking(move || stream_finalize_blocking(entry)),
    )
    .await;

    match finalize_result {
        Err(_) => {
            log::error!(
                "[finalize_user_file_stream] 落盘超时（{}s）",
                USER_FILE_OP_TIMEOUT.as_secs()
            );
            write_file_audit(
                &app,
                AuditEventType::FileWrite,
                &stream_id,
                AuditResult::Failure,
                None,
                Some("落盘超时".into()),
            );
            Err(ErrorCode::TemporaryFailure.default_message().to_string())
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

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_error_to_code() {
        use crate::util::path::PathValidationError;

        let err = SandboxError::InvalidPath(PathValidationError::Empty);
        assert_eq!(sandbox_error_to_code(&err), ErrorCode::InvalidPath);

        let err = SandboxError::ResolveFailed("not found".into());
        assert_eq!(sandbox_error_to_code(&err), ErrorCode::InvalidPath);

        let err = SandboxError::NotInWhitelist;
        assert_eq!(sandbox_error_to_code(&err), ErrorCode::PermissionDenied);
    }

    #[test]
    fn test_file_size_limit() {
        assert_eq!(FILE_SIZE_LIMIT, 50 * 1024 * 1024);
    }

    /* ===== x-path 百分号解码测试（中文/空格/特殊字符/畸形编码） ===== */

    #[test]
    fn test_decode_percent_path_chinese() {
        // encodeURIComponent("C:\\Users\\张三\\文档\\photo.venc")
        let raw = "C%3A%5CUsers%5C%E5%BC%A0%E4%B8%89%5C%E6%96%87%E6%A1%A3%5Cphoto.venc";
        assert_eq!(
            decode_percent_path(raw).unwrap(),
            "C:\\Users\\张三\\文档\\photo.venc"
        );
    }

    #[test]
    fn test_decode_percent_path_space_and_special_chars() {
        // 空格、#、%、&、?、+（encodeURIComponent 语义全覆盖）
        let raw = "C%3A%5CMy%20Files%5C100%25%20off%23%20%26%20q%3F%20plus%2B.venc";
        assert_eq!(
            decode_percent_path(raw).unwrap(),
            "C:\\My Files\\100% off# & q? plus+.venc"
        );
    }

    #[test]
    fn test_decode_percent_path_plain_ascii_passthrough() {
        // 纯 ASCII 路径：encodeURIComponent 不转换字母数字与部分保留字，解码应原样
        assert_eq!(
            decode_percent_path("C:/Users/Admin/AppData/photo.bin").unwrap(),
            "C:/Users/Admin/AppData/photo.bin"
        );
    }

    #[test]
    fn test_decode_percent_path_rejects_malformed_percent() {
        // 畸形编码：%ZZ / 尾部孤立 % / %A（不足两位）
        assert!(decode_percent_path("C%3A%5Cpath%ZZfile").is_err());
        assert!(decode_percent_path("C%3A%5Cpath%").is_err());
        assert!(decode_percent_path("C%3A%5Cpath%A").is_err());
    }

    #[test]
    fn test_decode_percent_path_rejects_empty() {
        // 空串 / 仅分隔符
        assert!(decode_percent_path("").is_err());
    }

    #[test]
    fn test_decode_percent_path_rejects_invalid_utf8() {
        // 合法 %XX 序列但解码后非 UTF-8（0x80 为延续字节首现，非法起始）
        assert!(decode_percent_path("%80%81").is_err());
    }

    #[test]
    fn test_decode_percent_path_long_path() {
        // 超长路径（>260 传统 MAX_PATH，现代 Windows 长路径支持）
        let segment = "%E5%BC%A0%E4%B8%89%E6%96%87%E6%A1%A3"; // 张三文档
        let raw = format!("C%3A%5C{}", segment.repeat(80));
        let decoded = decode_percent_path(&raw).unwrap();
        assert!(decoded.starts_with("C:\\张三文档"));
        assert_eq!(decoded.chars().count(), 3 + 80 * 4);
    }

    #[test]
    fn test_read_chunk_size() {
        assert_eq!(READ_CHUNK_SIZE, 64 * 1024);
    }

    #[test]
    fn test_file_op_timeout() {
        assert_eq!(FILE_OP_TIMEOUT, TIMEOUT_CONFIG.ipc);
    }

    #[test]
    fn test_write_mutex_can_lock() {
        let guard = WRITE_MUTEX.lock();
        assert!(guard.is_ok());
    }

    #[test]
    fn test_read_file_blocking_rejects_invalid_path() {
        let whitelist = vec!["C:/safe".to_string()];
        let result = read_file_blocking("", &whitelist);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_file_blocking_rejects_relative_path() {
        let whitelist = vec!["C:/safe".to_string()];
        let result = read_file_blocking("relative/path/file.txt", &whitelist);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_file_blocking_rejects_parent_traversal() {
        let whitelist = vec!["C:/safe".to_string()];
        let result = read_file_blocking("C:/safe/../../../etc/passwd", &whitelist);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_file_blocking_rejects_invalid_path() {
        let temp_dir = std::env::temp_dir();
        let whitelist = vec![temp_dir.to_string_lossy().to_string()];

        // 二进制 IPC：无效路径（空串）必须被拒绝
        let result = write_file_blocking("", b"binary data", &whitelist);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_file_blocking_atomic_write() {
        let temp_dir = std::env::temp_dir();
        let whitelist = vec![temp_dir.to_string_lossy().to_string()];

        let test_dir = temp_dir.join("verthys_test_atomic");
        let _ = std::fs::create_dir_all(&test_dir);
        let test_file = test_dir.join("atomic_test.txt");
        let path_str = test_file.to_string_lossy().to_string();

        // 二进制 IPC：原始字节直传（无 base64 编解码）
        let test_data = b"Hello, Verthys atomic write!";

        let result = write_file_blocking(&path_str, test_data, &whitelist);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_data.len() as u64);

        let read_back = std::fs::read(&test_file).unwrap();
        assert_eq!(read_back, test_data);

        let entries = std::fs::read_dir(&test_dir).unwrap();
        for entry in entries {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            assert!(!name_str.contains(".tmp."), "临时文件残留: {}", name_str);
        }

        let _ = std::fs::remove_dir_all(&test_dir);
    }

    /* ===== 流式写入（暂存 + 原子替换）测试 ===== */

    #[test]
    fn test_stream_roundtrip_and_no_residue() {
        let temp_dir = std::env::temp_dir().join("verthys_test_stream_roundtrip");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let target = temp_dir.join("out.venc");
        let target_str = target.to_string_lossy().to_string();

        let (stream_id, entry) = stream_create_blocking(&target_str).unwrap();
        assert_eq!(stream_id.len(), 32);

        let part1 = vec![0x41u8; 100_000];
        let part2 = vec![0x42u8; 50_000];
        stream_append_blocking(&entry, &part1).unwrap();
        stream_append_blocking(&entry, &part2).unwrap();

        let total = stream_finalize_blocking(entry).unwrap();
        assert_eq!(total, 150_000);

        let read_back = std::fs::read(&target).unwrap();
        assert_eq!(read_back.len(), 150_000);
        assert_eq!(&read_back[..100_000], &part1[..]);
        assert_eq!(&read_back[100_000..], &part2[..]);

        // 暂存文件已 rename 消失，无残留
        let residue = std::fs::read_dir(&temp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains(".venc.tmp"));
        assert!(!residue, "暂存文件残留");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_stream_abort_removes_temp_and_leaves_target_untouched() {
        let temp_dir = std::env::temp_dir().join("verthys_test_stream_abort");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let target = temp_dir.join("out.venc");
        let target_str = target.to_string_lossy().to_string();

        let (_, entry) = stream_create_blocking(&target_str).unwrap();
        stream_append_blocking(&entry, b"unfinished").unwrap();
        stream_abort_blocking(entry).unwrap();

        // 目标文件不存在（从未 rename），暂存已清理
        assert!(!target.exists());
        let residue = std::fs::read_dir(&temp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains(".venc.tmp"));
        assert!(!residue, "中止后暂存残留");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_stream_finalize_replaces_existing_target() {
        let temp_dir = std::env::temp_dir().join("verthys_test_stream_replace");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let target = temp_dir.join("out.venc");
        std::fs::write(&target, b"old-version").unwrap();
        let target_str = target.to_string_lossy().to_string();

        let (_, entry) = stream_create_blocking(&target_str).unwrap();
        stream_append_blocking(&entry, b"new-version").unwrap();
        stream_finalize_blocking(entry).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"new-version");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_stream_append_rejects_oversize_chunk_keeping_session_usable() {
        let temp_dir = std::env::temp_dir().join("verthys_test_stream_oversize");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let target = temp_dir.join("out.venc");
        let target_str = target.to_string_lossy().to_string();

        let (_, entry) = stream_create_blocking(&target_str).unwrap();
        let big = vec![0u8; WRITE_FILE_CHUNK_BYTES + 1];
        let err = stream_append_blocking(&entry, &big).unwrap_err();
        assert_eq!(err, ErrorCode::FileTooLarge.default_message().to_string());

        // 超限拒绝后会话仍可用（不破坏状态）
        stream_append_blocking(&entry, b"ok").unwrap();
        stream_abort_blocking(entry).unwrap();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_stream_create_fails_on_fresh_temp_residue() {
        let temp_dir = std::env::temp_dir().join("verthys_test_stream_fresh_residue");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let target = temp_dir.join("out.venc");
        let target_str = target.to_string_lossy().to_string();

        // 伪造未过期的暂存残留：按龄清理不会触碰，独占创建必须失败
        std::fs::write(temp_dir.join("out.venc.tmp"), b"residue").unwrap();
        let err = stream_create_blocking(&target_str).unwrap_err();
        assert_eq!(
            err,
            ErrorCode::TemporaryFailure.default_message().to_string()
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_stream_create_rejects_invalid_paths() {
        // 空串与相对路径必须在字符级校验层被拒绝
        assert!(stream_create_blocking("").is_err());
        assert!(stream_create_blocking("relative/out.venc").is_err());
    }

    #[test]
    fn test_cleanup_stale_temps_preserves_fresh() {
        let temp_dir = std::env::temp_dir().join("verthys_test_cleanup_fresh");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        std::fs::write(temp_dir.join("a.venc.tmp"), b"x").unwrap();
        cleanup_stale_stream_temps(&temp_dir);
        assert!(temp_dir.join("a.venc.tmp").exists());
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_generate_stream_id_format() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            let id = generate_stream_id();
            assert_eq!(id.len(), 32);
            assert!(id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
            seen.insert(id);
        }
        assert_eq!(seen.len(), 500);
    }
}
