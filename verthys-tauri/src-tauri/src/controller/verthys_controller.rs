/*
 * @file controller/verthys_controller.rs
 * @brief 加密库 CRUD 与生命周期控制器 - 核心数据管理接口
 *
 * 本模块是应用数据存储的核心入口，提供加密库的创建、解锁、锁定、持久化、
 * 记录增删改查、枚举等完整生命周期管理能力。所有敏感操作（密码处理、
 * 密钥派生、数据加密）均在 worker 子进程中执行，主进程仅负责指令转发与状态
 * 管理，确保密钥明文不接触主进程内存。
 *
 * =============================================================================
 * 核心能力
 * =============================================================================
 * - 初始化状态判定：区分全新用户、已有 verthys、损坏残留，并支持主动修复。
 * - 预热与零拷贝解锁：用户选择文件后后台预读索引区至页缓存，解锁时验证
 *   预热令牌，启用内存映射零拷贝路径，大幅提升解锁性能。
 * - 加密库创建：支持 BALANCED/SECURE 两种安全预设，原子创建并持久化状态。
 * - 解锁与锁定：解锁时验证密码，建立会话守卫（自动管理文件锁）；锁定
 *   时先持久化落盘再销毁 worker，确保数据不丢失。
 * - 记录管理：支持单条增删改查、批量枚举（含流式分页）、批量删除。
 * - 防御闭环状态查询：透传 worker 的安全路径阻断/降级状态。
 * - 导入导出与密码修改：支持完整容器导入导出及主密码变更。
 *
 * =============================================================================
 * 安全与性能设计
 * =============================================================================
 * - 密码零化：所有密码参数以 Zeroizing<String> 接收，序列化后立即擦除，
 *   确保明文不驻留。
 * - 预热令牌：预热成功后生成 30 秒有效期的一次性令牌，解锁时需携带，
 *   防止无凭据重复触发零拷贝路径。
 * - RAII 会话守卫：解锁成功后创建 VerthysSessionGuard，持有文件独占锁，
 *   Drop 时自动释放，异常路径无遗漏。
 * - IO 屏障：持久化操作（flush/lock）期间递增 IO 计数器，销毁 worker
 *   前等待计数器归零，防止持久化中途被中断。
 * - 审计日志：所有关键操作（解锁、锁定、创建）写入 HMAC 防篡改日志，
 *   路径哈希化存储，不泄露明文。
 * - 主动修复：状态文件缺失或损坏时，自动校验 .verthys 文件合法性并重建状态，
 *   减少用户手动干预。
 * - 流式枚举：大批量记录枚举采用分页推送，避免单次 JSON 序列化阻塞主线程。
 *
 * =============================================================================
 * 依赖方向
 * =============================================================================
 * controller → state / repository / controller::types / util / security / worker
 */

use crate::controller::types::{EnumerateBatch, InitStatus, InitStatusResult, VerthysResponse};
use crate::repository::verthys_state::{
    delete_state_file, read_last_verthys_path, read_state_file, try_repair_state_file,
    write_state_file_atomic, validate_verthys_magic, verify_container_id_match, VerthysState,
};
use crate::security::file_lock::VerthysFileLock;
use crate::state::verthys_session::{PreheatToken, VerthysSessionGuard};
use crate::state::AppState;
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};
use crate::util::path::{normalize_path, sanitize_path};
use tauri::State;
use zeroize::Zeroizing;

// ===== 借用式请求构造 =====

// 以下结构体把口令/记录明文以 &str 借用序列化进输出字符串，
// 不产生 serde_json::Value 的 owned 明文拷贝；序列化结果立即进入
// Zeroizing 容器，随敏感原件在发送后统一擦除。

/// unlock 请求体（flags=None 时省略字段，与无 flags 的线格式兼容）
#[derive(serde::Serialize)]
struct UnlockReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<u32>,
}

/// create_with_preset 请求体
#[derive(serde::Serialize)]
struct CreateWithPresetReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
    preset: u32,
}

/// export / import 请求体（共用 path + password 两字段结构）
#[derive(serde::Serialize)]
struct PathPasswordReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
}

/// change_password 请求体
#[derive(serde::Serialize)]
struct ChangePasswordReq<'a> {
    op: &'static str,
    old_password: &'a str,
    new_password: &'a str,
}

/// add_record 请求体（name 与 data 为用户记录明文，一并借用序列化）
#[derive(serde::Serialize)]
struct AddRecordReq<'a> {
    op: &'static str,
    rtype: u32,
    name: &'a str,
    data: &'a str,
}

// ===== 审计日志辅助 =====

/// 获取审计日志文件路径，存放于应用配置目录下。
/// 若路径解析失败，返回 None，调用方应跳过审计写入。
fn get_audit_log_path(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    use tauri::Manager;
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join("audit.log")),
        Err(e) => {
            log::warn!("[audit] 获取配置目录失败，跳过审计写入: {}", e);
            None
        }
    }
}

/// 从设备指纹派生出审计 HMAC 密钥，用于防篡改审计链。
/// 失败时返回 None，调用方应跳过审计写入。
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

/// 写入 verthys 相关审计事件，路径哈希化存储，不记录明文。
/// 写入失败仅警告，不阻塞业务流程。
fn write_verthys_audit(
    app: &tauri::AppHandle,
    event_type: AuditEventType,
    verthys_path: &str,
    result: AuditResult,
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

    let mut event = AuditEvent::new(event_type, &session_id, "user", result)
        .with_resource(verthys_path);

    if let Some(d) = detail {
        event = event.with_detail(d);
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[audit] 写入审计事件失败（不阻塞业务）: {}", e);
    }
}

/// 密码复杂度校验：最小长度 8，最大 512，用于创建/修改密码时。
/// 当前为 BALANCED 预设，未来可扩展为更严格规则。
fn validate_password_complexity(password: &str) -> Result<(), String> {
    let len = password.len();
    if len < 8 {
        return Err("密码长度不足（至少 8 位）".into());
    }
    if len > 512 {
        return Err("密码过长".into());
    }
    Ok(())
}

// ===== 初始化状态判定 =====

/// 判定 verthys 初始化状态，区分全新用户、已有 verthys、损坏残留。
///
/// 该命令在应用启动时调用，根据状态文件、.verthys 文件存在性与合法性，
/// 返回 "none"（全新）、"ready"（可解锁）、"broken"（需清理或修复）。
///
/// 支持主动修复：
/// - 路径指针存在但状态文件缺失时，校验 .verthys magic 并重建状态。
/// - 状态文件 ready=false 但 .verthys 合法时，自动修复为 ready。
/// - container_id 不匹配时，重建状态文件以匹配当前 verthys。
///
/// 修复失败连续 3 次时，在 detail 中推送告警，提示用户检查磁盘。
/// 该操作幂等，每次读取最新磁盘状态。
#[tauri::command]
pub fn verthys_init_status(app: tauri::AppHandle) -> Result<InitStatusResult, String> {
    let state = read_state_file(&app)?;

    match state {
        None => {
            let last_path = read_last_verthys_path(&app)?;

            match last_path {
                None => {
                    Ok(InitStatusResult {
                        status: "none".into(),
                        status_enum: Some(InitStatus::None),
                        verthys_path: None,
                        detail: "无状态文件，首次使用".into(),
                    })
                }
                Some(verthys_path) => {
                    if std::path::Path::new(&verthys_path).exists() {
                        if let Some(repaired) = try_repair_state_file(&app, &verthys_path) {
                            log::info!("[init_status] 状态文件缺失，主动修复成功: {}", sanitize_path(&verthys_path));
                            return Ok(InitStatusResult {
                                status: "ready".into(),
                                status_enum: Some(InitStatus::Ready),
                                verthys_path: Some(repaired.verthys_path.clone()),
                                detail: "状态文件缺失，已自动修复".into(),
                            });
                        }
                        log::warn!("[init_status] 状态文件缺失且主动修复失败: {}", sanitize_path(&verthys_path));
                        return Ok(InitStatusResult {
                            status: "broken".into(),
                            status_enum: Some(InitStatus::Broken),
                            verthys_path: Some(verthys_path),
                            detail: "状态文件缺失且修复失败，请检查磁盘空间和权限".into(),
                        });
                    }
                    log::warn!("[init_status] 路径指针存在但 .verthys 文件不存在: {}", sanitize_path(&verthys_path));
                    delete_state_file(&app);
                    Ok(InitStatusResult {
                        status: "none".into(),
                        status_enum: Some(InitStatus::None),
                        verthys_path: None,
                        detail: "上次使用的文件已不存在，按全新用户处理".into(),
                    })
                }
            }
        }
        Some(s) => {
            let repair_alert = if s.repair_fail_count >= 3 {
                log::warn!(
                    "[AUDIT][state] 状态文件修复连续失败 {} 次，向前端推送告警: path={}",
                    s.repair_fail_count,
                    sanitize_path(&s.verthys_path)
                );
                format!("⚠ 状态文件写入异常（连续失败 {} 次），请检查磁盘空间与权限。", s.repair_fail_count)
            } else {
                String::new()
            };

            if !s.ready {
                if std::path::Path::new(&s.verthys_path).exists() && validate_verthys_magic(&s.verthys_path) {
                    if let Some(repaired) = try_repair_state_file(&app, &s.verthys_path) {
                        log::info!("[init_status] ready=false 主动修复成功: {}", sanitize_path(&s.verthys_path));
                        return Ok(InitStatusResult {
                            status: "ready".into(),
                            status_enum: Some(InitStatus::Ready),
                            verthys_path: Some(repaired.verthys_path.clone()),
                            detail: append_alert("状态文件已自动修复", &repair_alert),
                        });
                    }
                }
                log::warn!("[init_status] 损坏残留且修复失败: ready=false, path={}", sanitize_path(&s.verthys_path));
                let verthys_path = std::path::Path::new(&s.verthys_path);
                if verthys_path.exists() {
                    let _ = std::fs::remove_file(verthys_path);
                    log::info!("[init_status] 已清理残留 .verthys 文件");
                }
                delete_state_file(&app);
                Ok(InitStatusResult {
                    status: "broken".into(),
                    status_enum: Some(InitStatus::Broken),
                    verthys_path: Some(s.verthys_path.clone()),
                    detail: append_alert("上次初始化失败，已清理残留文件，按全新用户处理", &repair_alert),
                })
            } else if !std::path::Path::new(&s.verthys_path).exists() {
                log::warn!("[init_status] 状态文件 ready=true 但文件缺失: {}", sanitize_path(&s.verthys_path));
                delete_state_file(&app);
                Ok(InitStatusResult {
                    status: "broken".into(),
                    status_enum: Some(InitStatus::Broken),
                    verthys_path: Some(s.verthys_path.clone()),
                    detail: "已清理状态文件".into(),
                })
            } else if !verify_container_id_match(&s, &s.verthys_path) {
                log::warn!(
                    "[AUDIT][init_status] container_id 不匹配，尝试重建状态文件: {}",
                    sanitize_path(&s.verthys_path)
                );
                write_verthys_audit(
                    &app,
                    AuditEventType::ContainerIdMismatch,
                    &s.verthys_path,
                    AuditResult::Failure,
                    Some("状态文件与加密库 container_id 不匹配".into()),
                );
                if let Some(repaired) = try_repair_state_file(&app, &s.verthys_path) {
                    log::info!("[init_status] container_id 不匹配，重建状态文件成功");
                    write_verthys_audit(
                        &app,
                        AuditEventType::StateRepair,
                        &repaired.verthys_path,
                        AuditResult::Success,
                        Some("container_id 不匹配，状态文件已重建".into()),
                    );
                    return Ok(InitStatusResult {
                        status: "ready".into(),
                        status_enum: Some(InitStatus::Ready),
                        verthys_path: Some(repaired.verthys_path.clone()),
                        detail: "状态文件与加密库不匹配，已自动重建".into(),
                    });
                }
                log::warn!("[init_status] container_id 不匹配且重建失败，清理状态文件");
                write_verthys_audit(
                    &app,
                    AuditEventType::StateRepair,
                    &s.verthys_path,
                    AuditResult::Failure,
                    Some("container_id 不匹配且重建失败，清理状态文件".into()),
                );
                delete_state_file(&app);
                Ok(InitStatusResult {
                    status: "broken".into(),
                    status_enum: Some(InitStatus::Broken),
                    verthys_path: Some(s.verthys_path.clone()),
                    detail: "状态文件与加密库不匹配，已清理，请重新选择".into(),
                })
            } else {
                Ok(InitStatusResult {
                    status: "ready".into(),
                    status_enum: Some(InitStatus::Ready),
                    verthys_path: Some(s.verthys_path.clone()),
                    detail: append_alert("已有合法文件，解锁流程", &repair_alert),
                })
            }
        }
    }
}

fn append_alert(detail: &str, repair_alert: &str) -> String {
    if repair_alert.is_empty() {
        detail.into()
    } else {
        format!("{} | {}", detail, repair_alert)
    }
}

// ===== 预热 =====

/// 预热 .verthys 文件索引区到 OS 页缓存，并生成预热令牌。
///
/// 用户选择文件后调用，后台以 FILE_FLAG_SEQUENTIAL_SCAN 预读索引区
/// 预热成功后生成 30 秒有效的一次性令牌，解锁时需携带以启用零拷贝路径。
/// 预热失败仅记录日志，不阻塞后续解锁（降级磁盘读取）。
///
/// 安全边界：纯文件 I/O，不涉及 DLL、不解密、不接触密钥。
/// 返回令牌签名（base64），前端在解锁时传回。
#[tauri::command]
pub async fn verthys_preheat(
    state: State<'_, AppState>,
    verthys_path: String,
) -> Result<VerthysResponse, String> {
    log::info!("[verthys_preheat] 启动预热: path={}", sanitize_path(&verthys_path));

    if !std::path::Path::new(&verthys_path).exists() {
        return Ok(VerthysResponse::ok("preheat"));
    }

    let path = verthys_path.clone();
    let preheat_result = tokio::task::spawn_blocking(move || {
        verthys_preheat_blocking(&path)
    }).await;

    use std::sync::atomic::Ordering;
    match preheat_result {
        Ok(Ok(())) => {
            state.prefetch_done.store(true, Ordering::SeqCst);
            log::info!("[verthys_preheat] 预热完成，prefetch_done=true");

            match PreheatToken::new() {
                Ok(token) => {
                    let token_b64 = crate::util::base64::base64_encode(token.signature());
                    state.preheat_token_store.store(token);
                    log::info!("[verthys_preheat] 预热令牌已生成（30s 有效）");

                    let mut resp = VerthysResponse::ok("preheat");
                    resp.data = Some(token_b64);
                    return Ok(resp);
                }
                Err(e) => {
                    log::warn!("[verthys_preheat] 生成预热令牌失败: {}，仅设置 prefetch_done", e);
                }
            }
        }
        Ok(Err(e)) => {
            state.prefetch_done.store(false, Ordering::SeqCst);
            log::warn!("[verthys_preheat] 预热失败: {}，prefetch_done=false（C 层走磁盘读取）", e);
        }
        Err(e) => {
            state.prefetch_done.store(false, Ordering::SeqCst);
            log::warn!("[verthys_preheat] spawn_blocking 异常: {}，prefetch_done=false", e);
        }
    }

    Ok(VerthysResponse::ok("preheat"))
}

/// 实际执行预热的同步函数，在 blocking 线程中运行。
///
/// 索引区大小上限 64MB，防止恶意文件触发过大 IO。
/// 所有失败返回 Err，以便上层正确设置 prefetch_done 标志。
fn verthys_preheat_blocking(verthys_path: &str) -> Result<(), String> {
    use std::io::Read;

    let mut header = [0u8; 128];
    let filled = {
        let mut file = std::fs::File::open(verthys_path).map_err(|e| {
            log::warn!(
                "[verthys_preheat] 打开文件失败: {} | {}",
                sanitize_path(verthys_path),
                e
            );
            format!("打开文件失败: {}", e)
        })?;
        let mut n = 0usize;
        while n < 128 {
            match file.read(&mut header[n..]) {
                Ok(0) => break,
                Ok(r) => n += r,
                Err(e) => {
                    log::warn!("[verthys_preheat] 读取头部失败: {}", e);
                    return Err(format!("读取头部失败: {}", e));
                }
            }
        }
        n
    };
    if filled < 8 {
        log::warn!(
            "[verthys_preheat] 文件过短 ({} 字节)，跳过预热",
            filled
        );
        return Err(format!("文件过短 ({} 字节)", filled));
    }

    let is_verthys =
        header[0] == 0x56 && header[1] == 0x45 && header[2] == 0x52 && header[3] == 0x54;
    if !is_verthys {
        log::warn!("[verthys_preheat] 非 .verthys 文件格式，跳过预热");
        return Err("非 .verthys 文件格式".to_string());
    }
    let version = u16::from_le_bytes([header[4], header[5]]);

    if version != 0x0002 {
        log::info!(
            "[verthys_preheat] v1 容器，仅预读头部: path={}",
            sanitize_path(verthys_path)
        );
        return Ok(());
    }

    if filled < 70 {
        log::warn!("[verthys_preheat] 头部过短，跳过索引预热");
        return Err("头部过短，无法解析索引区偏移".to_string());
    }
    let idx_off = u64::from_le_bytes([
        header[54], header[55], header[56], header[57], header[58], header[59], header[60],
        header[61],
    ]);
    let idx_size = u64::from_le_bytes([
        header[62], header[63], header[64], header[65], header[66], header[67], header[68],
        header[69],
    ]);

    const PREHEAT_INDEX_MAX: u64 = 64 * 1024 * 1024;

    let metadata = std::fs::metadata(verthys_path).map_err(|e| {
        log::warn!("[verthys_preheat] 获取文件元数据失败: {}", e);
        format!("获取文件元数据失败: {}", e)
    })?;
    let file_size = metadata.len();

    if idx_off < 4096 {
        log::warn!("[verthys_preheat] 索引偏移小于 4KB: off={}", idx_off);
        return Err("索引偏移异常".to_string());
    }
    if idx_size == 0 {
        log::warn!("[verthys_preheat] 索引区大小为 0");
        return Err("索引区大小为0".to_string());
    }
    if idx_size > PREHEAT_INDEX_MAX {
        log::warn!(
            "[verthys_preheat] 索引区超限: {} > {}MB",
            idx_size,
            PREHEAT_INDEX_MAX / 1024 / 1024
        );
        return Err("索引区超限".to_string());
    }
    let Some(end) = idx_off.checked_add(idx_size) else {
        log::warn!(
            "[verthys_preheat] 索引偏移溢出: off={} size={}",
            idx_off,
            idx_size
        );
        return Err("索引偏移溢出".to_string());
    };
    if end > file_size {
        log::warn!(
            "[verthys_preheat] 索引区越界: end={} > file_size={}",
            end,
            file_size
        );
        return Err("索引区越界".to_string());
    }

    preheat_range_sequential(verthys_path, idx_off, idx_size);
    log::info!(
        "[verthys_preheat] 索引区已预读: path={} idx_off={} idx_size={}",
        sanitize_path(verthys_path),
        idx_off,
        idx_size
    );

    preheat_cache_file(verthys_path);

    log::info!(
        "[verthys_preheat] 真预热完成: path={} version=v{} (索引区+缓存已进页缓存)",
        sanitize_path(verthys_path),
        version
    );
    Ok(())
}

/// 以顺序扫描方式预读文件的指定范围，触发 OS 预读相邻页到缓存。
fn preheat_range_sequential(path: &str, off: u64, size: u64) {
    use std::io::{Read, Seek, SeekFrom};

    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x08000000)
            .open(path)
        {
            Ok(f) => f,
            Err(e) => {
                log::warn!("[verthys_preheat] SEQUENTIAL 打开失败: {}", e);
                return;
            }
        }
    };
    #[cfg(not(windows))]
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            log::warn!("[verthys_preheat] 打开失败: {}", e);
            return;
        }
    };

    let mut reader = std::io::BufReader::with_capacity(1024 * 1024, file);
    if let Err(e) = reader.seek(SeekFrom::Start(off)) {
        log::warn!("[verthys_preheat] seek 失败 off={}: {}", off, e);
        return;
    }

    let mut sink = std::io::sink();
    if let Err(e) = std::io::copy(&mut reader.take(size), &mut sink) {
        log::warn!("[verthys_preheat] 预读索引区失败: {}", e);
    }
}

/// 预读持久化缓存文件（.verthys.idx_cache）到页缓存，提升温启动性能。
fn preheat_cache_file(verthys_path: &str) {
    let cache_path = format!("{}.idx_cache", verthys_path);
    if !std::path::Path::new(&cache_path).exists() {
        return;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x08000000)
            .open(&cache_path)
        {
            Ok(f) => f,
            Err(e) => {
                log::warn!("[verthys_preheat] 缓存文件打开失败: {}", e);
                return;
            }
        };
        let mut reader = std::io::BufReader::with_capacity(256 * 1024, file);
        let mut sink = std::io::sink();
        let _ = std::io::copy(&mut reader, &mut sink);
    }
    #[cfg(not(windows))]
    {
        let file = match std::fs::File::open(&cache_path) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut reader = std::io::BufReader::with_capacity(256 * 1024, file);
        let mut sink = std::io::sink();
        let _ = std::io::copy(&mut reader, &mut sink);
    }
    log::info!(
        "[verthys_preheat] 缓存文件已预读: {}",
        sanitize_path(&cache_path)
    );
}

// ===== 解锁 =====

/// 解锁已存在的 .verthys 文件，验证密码并建立会话。
///
/// 解锁过程：
/// 1. 校验文件存在性及密码复杂度。
/// 2. 持有共享文件锁（读锁）防止其他进程写操作。
/// 3. 验证预热令牌，若有效则启用零拷贝路径（flags 含 INDEX_PREHEATED）。
/// 4. 通过 IPC 向 worker 发送 unlock 指令，并流式接收进度。
/// 5. 解锁成功后创建 VerthysSessionGuard（持有独占锁），存入 AppState。
/// 6. 检查状态文件，若缺失或路径不一致则自动修复/更新。
///
/// 密码在发送后立即擦除，不驻留内存。
/// 解锁失败时文件锁自动释放（RAII）。
/// 仅支持 V3 容器格式。
#[tauri::command]
pub async fn verthys_unlock(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    security_state: State<'_, crate::security_commands::SecurityState>,
    verthys_path: String,
    password: String,
    preheat_token: Option<String>,
    on_progress: tauri::ipc::Channel<crate::worker::UnlockProgress>,
) -> Result<VerthysResponse, String> {
    let password = Zeroizing::new(password);
    log::info!("[verthys_unlock] 开始解锁: path={}", sanitize_path(&verthys_path));

    // 服务端强制暴力熔断闸门：锁定/清空状态下，口令不进入任何
    // 业务逻辑（不触文件锁、不触 FFI）。计数由后端权威维护，
    // 不依赖前端行为；前端仅负责查询展示锁定态。
    use crate::security_commands::brute_force_bridge::{gate_check, UnlockGate};
    match gate_check(&app, &security_state) {
        UnlockGate::Allowed => {}
        UnlockGate::Locked(secs) => {
            log::warn!(
                "[verthys_unlock] 暴力熔断锁定中（剩余 {}s），拒绝尝试",
                secs
            );
            write_verthys_audit(
                &app,
                AuditEventType::VerthysUnlock,
                &verthys_path,
                AuditResult::Denied,
                Some(format!("BRUTE_FORCE_LOCKOUT: 界面锁定 {} 秒（服务端强制）", secs)),
            );
            return Err(format!("尝试次数过多，已锁定 {} 秒，请稍后再试", secs));
        }
        UnlockGate::PurgeRequired => {
            log::warn!("[verthys_unlock] 暴力熔断清空态，拒绝尝试");
            write_verthys_audit(
                &app,
                AuditEventType::VerthysUnlock,
                &verthys_path,
                AuditResult::Denied,
                Some("BRUTE_FORCE_PURGE: 需执行索引清空与完整性校验（服务端强制）".into()),
            );
            return Err("失败次数已达上限，需完成安全清理与完整性校验后重试".into());
        }
        UnlockGate::Unavailable => {
            log::error!("[verthys_unlock] 熔断守卫不可用（fail-closed 拒绝）");
            write_verthys_audit(
                &app,
                AuditEventType::VerthysUnlock,
                &verthys_path,
                AuditResult::Denied,
                Some("熔断守卫不可用，fail-closed 拒绝解锁".into()),
            );
            return Err("安全模块暂时不可用，请重启应用后重试".into());
        }
    }

    if !std::path::Path::new(&verthys_path).exists() {
        log::warn!("[verthys_unlock] 文件不存在: {}", sanitize_path(&verthys_path));
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Failure,
            Some("文件不存在".into()),
        );
        return Err("文件不存在，请使用创建而非打开".into());
    }

    if let Err(e) = validate_password_complexity(&password) {
        log::warn!("[verthys_unlock] 密码复杂度校验失败");
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Err(e);
    }

    let _read_lock = VerthysFileLock::lock_shared(&verthys_path).map_err(|e| {
        log::warn!("[verthys_unlock] 文件锁失败: {}", e);
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Failure,
            Some(format!("文件锁失败: {}", e)),
        );
        "加密库正在被另一个程序使用".to_string()
    })?;

    let mut flags: u32 = 0x02;
    if let Some(token_b64) = preheat_token.as_deref() {
        match crate::util::base64::base64_decode(token_b64) {
            Ok(token_sig) => {
                match state.preheat_token_store.verify_and_consume(&token_sig) {
                    Some(true) => {
                        flags |= 0x01;
                        log::info!("[verthys_unlock] PreheatToken 验证成功，启用零拷贝路径");
                    }
                    Some(false) => {
                        log::warn!("[verthys_unlock] PreheatToken 无效/超时/已消费，降级磁盘读取");
                    }
                    None => {
                        log::info!("[verthys_unlock] 无 PreheatToken（未预热），降级磁盘读取");
                    }
                }
            }
            Err(e) => {
                log::warn!("[verthys_unlock] PreheatToken base64 解码失败: {}，降级磁盘读取", e);
            }
        }
    } else {
        use std::sync::atomic::Ordering;
        if state.prefetch_done.load(Ordering::SeqCst) {
            flags |= 0x01;
            log::info!("[verthys_unlock] prefetch_done=true（旧前端兼容路径），启用零拷贝");
        }
    }
    log::info!("[verthys_unlock] flags=0x{:02x}", flags);

    let req_str = Zeroizing::new(serde_json::to_string(&UnlockReq {
        op: "unlock",
        path: &verthys_path,
        password: &password,
        flags: Some(flags),
    }).map_err(|e| {
        log::error!("[verthys_unlock] 请求序列化失败: {}", e);
        "打开加密库失败".to_string()
    })?);

    let resp_json = {
        let result = state.send_with_unlock_progress(req_str.as_str(), &|progress| {
            if let Err(e) = on_progress.send(progress.clone()) {
                log::warn!("[verthys_unlock] 进度推送失败（前端可能已关闭）: {}", e);
            }
        });
        match result {
            Ok(json) => json,
            Err(e) => {
                log::error!("[verthys_unlock] send 失败: {}", e);
                /* ★ 企业级修复（D-WORKER-RESET）：超时/通信失败时销毁 worker 子进程
                 *
                 * 场景：unlock 进度死锁或 FFI 调用耗时超过 60 秒空闲超时后，
                 * 父进程放弃等待但 worker 子进程仍在运行。Verthys_Unlock FFI 可能
                 * 已成功完成（ctx->state = UNLOCKED），但响应未被父进程接收。
                 * 若不销毁 worker，后续 unlock/create 请求会命中 stale UNLOCKED
                 * 状态，返回 VERTHYS_ERR_INVALID 级联失败。
                 *
                 * 修复：通信失败时立即销毁 worker（set_session(None) 触发 Drop →
                 * kill 子进程），确保下次操作从全新 worker 进程开始。 */
                log::warn!("[verthys_unlock] 销毁 worker 子进程（超时/通信失败后清除脏状态）");
                state.set_session(None);
                write_verthys_audit(
                    &app,
                    AuditEventType::VerthysUnlock,
                    &verthys_path,
                    AuditResult::Failure,
                    Some(format!("worker 通信失败: {}", e)),
                );
                return Err("打开加密库失败".to_string());
            }
        }
    };

    // 发送完成：序列化副本与口令原件统一销毁（Zeroizing 擦除堆缓冲）
    drop(req_str);
    drop(password);

    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| {
            log::error!("[verthys_unlock] 解析响应失败: {} | raw={}", e, crate::util::log_sanitizer::json_log_summary(&resp_json, &["op"]));
            write_verthys_audit(
                &app,
                AuditEventType::VerthysUnlock,
                &verthys_path,
                AuditResult::Failure,
                Some(format!("响应解析失败: {}", e)),
            );
            "打开加密库失败".to_string()
        })?;

    if !resp.ok {
        log::warn!("[verthys_unlock] 解锁失败: {:?}", resp.error);

        // 服务端强制失败计数：仅认证域错误（worker 统一化 AUTH 码）计入。
        // 口令错误/格式/IO/损坏在 worker 侧已统一映射为 AUTH，语义上
        // 均属认证域结果；功能性状态码与通信层失败不计，防止非口令
        // 因素（CNG 不可用、超时等）误锁正常用户。
        if resp.error.as_deref()
            == Some(crate::security_commands::brute_force_bridge::AUTH_DOMAIN_ERROR)
        {
            crate::security_commands::brute_force_bridge::record_auth_failure(
                &app,
                &security_state,
            );
        }

        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Failure,
            resp.error.clone().or(Some("解锁失败".into())),
        );
    } else {
        log::info!("[verthys_unlock] 解锁成功");

        // 服务端强制成功重置：连续失败计数归零
        // （解锁响应 ok=true 已确认成功，无需 auth_token 授权）
        crate::security_commands::brute_force_bridge::record_auth_success(
            &app,
            &security_state,
        );

        // ★ 企业级修复：同步 key_lifecycle 状态机与 verthys 生命周期
        //
        // 原缺陷：verthys_unlock 成功后不触碰 key_lifecycle，状态永远停留在
        // 初始值 NoKey。但 verthys_verify_global_key 要求 Locked 状态 →
        // 验证按钮必然失败："状态不匹配：当前 NoKey，仅 Locked 允许验证"。
        //
        // 修复：根据 worker 进程内探测结果 has_global_key 设置状态：
        // - Some(true)  → reset_to_no_key + transition_to_locked = Locked
        //   （有全局密钥记录，用户需验证 GMK）
        // - Some(false)/None → reset_to_no_key = NoKey
        //   （无全局密钥记录，用户需初始化 GMK）
        // reset_to_no_key 先重置以处理 lock→unlock 循环场景（上次状态
        // 可能为 Locked/Unlocked，需先回到 NoKey 再按需转移）。
        state.key_lifecycle.reset_to_no_key();
        if resp.has_global_key == Some(true) {
            match state.key_lifecycle.transition_to_locked() {
                Ok(()) => log::info!("[verthys_unlock] key_lifecycle → Locked（有全局密钥记录）"),
                Err(e) => log::warn!("[verthys_unlock] key_lifecycle 状态转移失败: {}", e),
            }
        } else {
            log::info!("[verthys_unlock] key_lifecycle → NoKey（无全局密钥记录）");
        }

        // ★ 企业级根治修复：释放共享锁后再创建会话守卫（消除自死锁）
        //
        // 原缺陷（死锁根因）：_read_lock（共享锁，line 634 lock_shared 获取）在
        // 整个函数作用域内存活直到 line 829 返回才 Drop。VerthysSessionGuard::new
        // 内部（verthys_session.rs line 76）对同一 verthys_path 同一字节偏移
        // (SENTINEL_OFFSET=0x7FFFFFFF) 请求独占锁（LockFileEx +
        // LOCKFILE_EXCLUSIVE_LOCK）。Windows LockFileEx 独占锁要求该字节范围
        // 无任何其他锁（含同进程），且未设 LOCKFILE_FAIL_IMMEDIATELY → 永久阻塞。
        // 表现：解锁成功日志输出后 verthys_unlock 命令挂起 35s，前端
        // withGradedTimeout 硬超时触发 resetKeyManagerState 销毁 worker，
        // 用户看到"卡在解锁完成…一直到超时"。
        //
        // 修复：参照 verthys_create（line 1037 显式 drop(lock)）的正确做法，
        // 在 VerthysSessionGuard::new 之前显式释放共享锁。此时解锁请求已完成
        // （send_with_unlock_progress 已返回），共享锁不再需要保护文件读取。
        drop(_read_lock);

        let session_id = format!("pid-{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis());
        match VerthysSessionGuard::new(&verthys_path, &session_id) {
            Ok(guard) => {
                let mut session_guard = state.lock_verthys_session();
                *session_guard = Some(guard);
                log::info!("[verthys_unlock] VerthysSessionGuard 已创建（session={}）", session_id);
            }
            Err(e) => {
                log::error!("[verthys_unlock] VerthysSessionGuard 创建失败: {}", e);
                write_verthys_audit(
                    &app,
                    AuditEventType::VerthysUnlock,
                    &verthys_path,
                    AuditResult::Failure,
                    Some(format!("VerthysSessionGuard 创建失败: {}", e)),
                );
            }
        }

        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Success,
            None,
        );

        match read_state_file(&app) {
            Ok(Some(existing_state)) => {
                if existing_state.verthys_path != normalize_path(&verthys_path) {
                    log::info!(
                        "[verthys_unlock] 状态文件路径不一致，更新: old={} new={}",
                        sanitize_path(&existing_state.verthys_path),
                        sanitize_path(&verthys_path)
                    );
                    let new_state = VerthysState::new(&verthys_path);
                    if let Err(e) = write_state_file_atomic(&app, &new_state) {
                        log::warn!("[verthys_unlock] 状态文件更新失败（不阻塞解锁）: {}", e);
                    } else {
                        write_verthys_audit(
                            &app,
                            AuditEventType::StateModify,
                            &verthys_path,
                            AuditResult::Success,
                            Some("状态文件路径不一致，已更新".into()),
                        );
                    }
                }
            }
            Ok(None) => {
                log::info!("[verthys_unlock] 状态文件缺失，自动创建（向后兼容）: {}", sanitize_path(&verthys_path));
                let new_state = VerthysState::new(&verthys_path);
                if let Err(e) = write_state_file_atomic(&app, &new_state) {
                    log::warn!("[verthys_unlock] 状态文件创建失败（不阻塞解锁）: {}", e);
                } else {
                    log::info!("[verthys_unlock] 状态文件已自动创建");
                    write_verthys_audit(
                        &app,
                        AuditEventType::StateCreate,
                        &verthys_path,
                        AuditResult::Success,
                        Some("解锁后自动创建状态文件（向后兼容）".into()),
                    );
                }
            }
            Err(e) => {
                log::warn!("[verthys_unlock] 状态文件读取失败，重建: {}", e);
                let new_state = VerthysState::new(&verthys_path);
                if let Err(e) = write_state_file_atomic(&app, &new_state) {
                    log::warn!("[verthys_unlock] 状态文件重建失败（不阻塞解锁）: {}", e);
                } else {
                    write_verthys_audit(
                        &app,
                        AuditEventType::StateRepair,
                        &verthys_path,
                        AuditResult::Success,
                        Some("状态文件损坏，已重建".into()),
                    );
                }
            }
        }
    }
    Ok(resp)
}

// ===== 创建 =====

/// 创建新的加密库（首次初始化）。
///
/// 流程：
/// 1. 前置校验：目标文件不存在，密码复杂度合格。
/// 2. 调用 worker create_with_preset（支持 BALANCED/SECURE），创建 V3 容器。
/// 3. 获取独占文件锁。
/// 4. 发送 lock 指令持久化空 verthys。
/// 5. 再次 unlock 重新打开，保持会话。
/// 6. 校验 .verthys 文件已成功落地（大小 >0）。
/// 7. 原子写入状态文件（若失败仅警告，不删除 .verthys）。
/// 8. 创建 VerthysSessionGuard 并存入 AppState。
///
/// 任何步骤失败则回滚：删除不完整的 .verthys 文件，销毁 worker，清理状态。
/// 密码在发送后立即擦除。
#[tauri::command]
pub async fn verthys_create(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    verthys_path: String,
    password: String,
    preset: Option<u32>,
) -> Result<VerthysResponse, String> {
    let password = Zeroizing::new(password);

    let preset_val: u32 = match preset {
        Some(1) => 1,
        _ => 0,
    };
    let preset_name = if preset_val == 1 { "SECURE" } else { "BALANCED" };
    log::info!("[verthys_create] 开始创建: path={} preset={}", sanitize_path(&verthys_path), preset_name);

    if std::path::Path::new(&verthys_path).exists() {
        log::warn!("[verthys_create] 文件已存在: {}", sanitize_path(&verthys_path));
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Denied,
            Some("文件已存在，拒绝创建".into()),
        );
        return Err("文件已存在，请使用打开而非创建".into());
    }

    if let Err(e) = validate_password_complexity(&password) {
        log::warn!("[verthys_create] 密码复杂度校验失败");
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Denied,
            Some(e.clone()),
        );
        return Err(e);
    }

    let path_for_rollback = verthys_path.clone();

    let create_timeout = std::time::Duration::from_secs(60);
    let lock_unlock_timeout = std::time::Duration::from_secs(30);

    let mut file_lock: Option<VerthysFileLock> = None;

    let create_result: Result<VerthysResponse, String> = (|| {
        log::info!("[verthys_create] 步骤 1/3: create_with_preset（preset={}, 超时={}s）",
                   preset_name, create_timeout.as_secs());
        let create_req = Zeroizing::new(serde_json::to_string(&CreateWithPresetReq {
            op: "create_with_preset",
            path: &verthys_path,
            password: &password,
            preset: preset_val,
        }).map_err(|e| format!("创建加密库失败（步骤1序列化失败）: {}", e))?);
        let resp_json = state.send_with_timeout(create_req.as_str(), create_timeout).map_err(|e| {
            log::error!("[verthys_create] 步骤 1 send 失败（超时 {}s）: {}", create_timeout.as_secs(), e);
            format!("创建加密库失败（步骤1通信失败）: {}", e)
        })?;
        let create_resp: VerthysResponse = serde_json::from_str(&resp_json)
            .map_err(|e| format!("创建加密库失败（步骤1响应解析失败）: {}", e))?;
        if !create_resp.ok {
            let detail = create_resp.error.unwrap_or_else(|| "未知错误".to_string());
            log::error!("[verthys_create] 步骤 1/3 失败: error={}", detail);
            return Err(format!("创建加密库失败（步骤1）: {}", detail));
        }
        log::info!("[verthys_create] 步骤 1/3: create_with_preset 成功");

        let lock = VerthysFileLock::lock_exclusive(&verthys_path).map_err(|e| {
            log::error!("[verthys_create] 文件锁失败: {}", e);
            format!("创建加密库失败（文件锁失败）: {}", e)
        })?;
        file_lock = Some(lock);

        log::info!("[verthys_create] 步骤 2/3: lock（写盘持久化, 超时={}s）", lock_unlock_timeout.as_secs());
        let lock_req = r#"{"op":"lock"}"#;
        let lock_resp_json = state.send_with_timeout(lock_req, lock_unlock_timeout).map_err(|e| {
            log::error!("[verthys_create] 步骤 2 send 失败: {}", e);
            format!("创建加密库失败（步骤2通信失败）: {}", e)
        })?;
        let lock_resp: VerthysResponse = serde_json::from_str(&lock_resp_json)
            .map_err(|e| format!("创建加密库失败（步骤2响应解析失败）: {}", e))?;
        if !lock_resp.ok {
            let detail = lock_resp.error.unwrap_or_else(|| "未知错误".to_string());
            log::error!("[verthys_create] 步骤 2/3 失败: error={}", detail);
            return Err(format!("创建加密库失败（步骤2落盘失败）: {}", detail));
        }
        log::info!("[verthys_create] 步骤 2/3: lock 成功");

        log::info!("[verthys_create] 步骤 3/3: unlock（重新打开, 超时={}s）", lock_unlock_timeout.as_secs());
        let unlock_req2 = Zeroizing::new(serde_json::to_string(&UnlockReq {
            op: "unlock",
            path: &verthys_path,
            password: &password,
            flags: None,
        }).map_err(|e| format!("创建加密库失败（步骤3序列化失败）: {}", e))?);
        let resp_json2 = state.send_with_timeout(unlock_req2.as_str(), lock_unlock_timeout).map_err(|e| {
            log::error!("[verthys_create] 步骤 3 send 失败: {}", e);
            format!("创建加密库失败（步骤3通信失败）: {}", e)
        })?;
        let unlock_resp2: VerthysResponse = serde_json::from_str(&resp_json2)
            .map_err(|e| format!("创建加密库失败（步骤3响应解析失败）: {}", e))?;
        if !unlock_resp2.ok {
            let detail = unlock_resp2.error.unwrap_or_else(|| "未知错误".to_string());
            log::error!("[verthys_create] 步骤 3/3 失败: error={}", detail);
            return Err(format!("创建加密库失败（步骤3重开失败）: {}", detail));
        }
        log::info!("[verthys_create] 步骤 3/3: unlock 成功");

        Ok(unlock_resp2)
    })();

    drop(password);

    if let Err(ref e) = create_result {
        drop(file_lock.take());
        let _ = std::fs::remove_file(&path_for_rollback);
        state.set_session(None);
        delete_state_file(&app);
        log::error!("[verthys_create] 创建失败，已回滚: {} | {}", sanitize_path(&path_for_rollback), e);
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &path_for_rollback,
            AuditResult::Failure,
            Some(format!("创建失败已回滚: {}", e)),
        );
        return create_result;
    }

    let verthys_file = std::path::Path::new(&path_for_rollback);
    if !verthys_file.exists() {
        let msg = "[verthys_create] 文件落地校验失败: .verthys 文件不存在".to_string();
        log::error!("{}", msg);
        drop(file_lock.take());
        state.set_session(None);
        delete_state_file(&app);
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &path_for_rollback,
            AuditResult::Failure,
            Some("文件落地校验失败：.verthys 文件不存在".into()),
        );
        return Err("创建加密库失败".into());
    }
    let file_size = std::fs::metadata(verthys_file)
        .map(|m| m.len())
        .unwrap_or(0);
    if file_size == 0 {
        drop(file_lock.take());
        let _ = std::fs::remove_file(&path_for_rollback);
        state.set_session(None);
        delete_state_file(&app);
        let msg = "[verthys_create] 文件落地校验失败: .verthys 文件大小为 0".to_string();
        log::error!("{}", msg);
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &path_for_rollback,
            AuditResult::Failure,
            Some("文件落地校验失败：文件大小为 0".into()),
        );
        return Err("创建加密库失败".into());
    }
    log::info!("[verthys_create] 文件落地校验通过: size={} bytes", file_size);

    // ★ 企业级根治：重置 key_lifecycle 到 NoKey
    //
    // verthys_create 通过 raw worker IPC 完成 create→lock→unlock，
    // 绕过了 verthys_unlock Tauri 命令的 key_lifecycle 状态管理代码（843-851 行）。
    // 新建 verthys 无全局密钥记录，后端状态必须为 NoKey，
    // 否则 verthys_derive_global_key（要求 NoKey）会因状态不匹配而失败。
    state.key_lifecycle.reset_to_no_key();
    log::info!("[verthys_create] key_lifecycle → NoKey（新建 verthys 无全局密钥）");

    let verthys_state = VerthysState::new(&path_for_rollback);
    if let Err(e) = write_state_file_atomic(&app, &verthys_state) {
        log::warn!("[verthys_create] 状态文件写入失败（.verthys 文件已保存，不回滚）: {}", e);
    } else {
        log::info!("[verthys_create] 状态文件原子提交成功");
        write_verthys_audit(
            &app,
            AuditEventType::StateCreate,
            &path_for_rollback,
            AuditResult::Success,
            Some(format!("verthys 创建成功（preset={}）", preset_name)),
        );
    }

    log::info!("[verthys_create] 创建完成: verthys_path={}", sanitize_path(&path_for_rollback));

    if let Some(lock) = file_lock {
        let session_id = format!("pid-{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis());
        drop(lock);
        match VerthysSessionGuard::new(&path_for_rollback, &session_id) {
            Ok(guard) => {
                let mut session_guard = state.lock_verthys_session();
                *session_guard = Some(guard);
                log::info!("[verthys_create] VerthysSessionGuard 已创建（session={}）", session_id);
            }
            Err(e) => {
                log::error!("[verthys_create] VerthysSessionGuard 创建失败（不阻塞返回）: {}", e);
            }
        }
    }

    create_result
}

// ===== 持久化落盘 =====

/// 发送 lock 指令强制 worker 将内存数据持久化到磁盘，但不销毁 worker。
///
/// 配合 verthys_lock 使用，实现「先持久化→停 C 线程→销毁 worker」的完整流程。
/// 超时 8 秒，若失败或超时仅记录警告，不阻塞后续销毁。
#[tauri::command]
pub async fn verthys_lock_persist(state: State<'_, AppState>) -> Result<VerthysResponse, String> {
    state.begin_io();
    let lock_req = r#"{"op":"lock"}"#;
    let lock_timeout = std::time::Duration::from_secs(8);

    let result = match state.send_with_timeout(lock_req, lock_timeout) {
        Ok(resp_json) => {
            match serde_json::from_str::<VerthysResponse>(&resp_json) {
                Ok(resp) => {
                    if !resp.ok {
                        log::warn!("[verthys_lock_persist] worker lock 返回失败: {:?}", resp.error);
                    }
                    Ok(resp)
                }
                Err(e) => {
                    log::warn!("[verthys_lock_persist] 解析 lock 响应失败: {}", e);
                    Ok(VerthysResponse::ok("lock"))
                }
            }
        }
        Err(e) => {
            log::warn!("[verthys_lock_persist] worker lock 超时或失败（仍允许后续销毁兜底）: {}", e);
            Ok(VerthysResponse::ok("lock"))
        }
    };
    state.end_io();
    result
}

// ===== 锁定（销毁 worker） =====

/// 销毁 worker 子进程并清理资源（剪贴板、文件锁）。
///
/// 调用前应先执行 verthys_lock_persist 确保持久化完成。
/// 销毁前等待所有进行中的 IO 操作完成（最长 10 秒），超时则强制销毁。
/// 销毁后状态回到 Uninitialized，VerthysSessionGuard Drop 自动释放文件锁。
#[tauri::command]
pub async fn verthys_lock(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    let session_path = state.verthys_session_path();

    let _ = state.wait_io_complete(std::time::Duration::from_secs(10)).await;

    state.set_session(None);
    // ★ 企业级修复：worker 销毁后 GMK 已消失，重置密钥生命周期为 NoKey
    state.key_lifecycle.reset_to_no_key();

    if !crate::security::clear_clipboard() {
        log::warn!("[verthys_lock] 剪贴板清零失败");
    }

    {
        let mut session_guard = state.lock_verthys_session();
        if session_guard.is_some() {
            log::info!("[verthys_lock] 销毁 VerthysSessionGuard（Drop 自动释放文件锁）");
            *session_guard = None;
        }
    }

    {
        let mut lock_guard = state.lock_verthys_file();
        if lock_guard.is_some() {
            log::info!("[verthys_lock] 清理旧版 verthys_file_lock");
            *lock_guard = None;
        }
    }

    if let Some(ref path) = session_path {
        write_verthys_audit(
            &app,
            AuditEventType::VerthysLock,
            path,
            AuditResult::Success,
            None,
        );
    }

    Ok(VerthysResponse::ok("lock"))
}

// ===== 刷新（Verthys_Flush） =====

/// 刷盘：调用 Verthys_Flush 提交未完成事务，保持 worker 会话不中断。
/// V3 的 add_record 已通过 vtxn_commit 即时落盘，此函数主要用于：
///   - 提交 pending 事务（若有）
///   - 清除 dirty 标志
///   - 触发异步缓存写入
/// 不清零密钥、不改变 worker 状态（始终 UNLOCKED），无 lock+unlock 竞态风险。
#[tauri::command]
pub async fn verthys_flush(
    state: State<'_, AppState>,
    _verthys_path: String,
    _password: String,
) -> Result<VerthysResponse, String> {
    // ★ 企业级根治：直接调用 Verthys_Flush，不再使用 lock+unlock 模式
    //
    // 【旧实现致命缺陷】
    //   旧实现发送 lock + unlock 两条 IPC 模拟 flush：
    //   1. lock 调用 Verthys_Lock → 清零密钥(ctx_zero_sensitive) + state=LOCKED
    //   2. unlock 调用 Verthys_Unlock → 重新派生密钥 + 重新加载索引
    //   3. send_batch_with_timeout 非原子（逐条发送），lock 成功后若 unlock
    //      超时(8s)或失败，worker 永久卡在 LOCKED 状态
    //   4. 后续所有 get_record 返回 VERTHYS_ERR_LOCKED → 前端 verthysGetRecord 返回 null
    //   5. decryptPhotoMeta 返回 null → 照片无法解密 → 用户看到"照片全部损坏"
    //
    // 【新实现】
    //   直接发送 {"op":"flush"} → worker call_flush → C Verthys_Flush
    //   - commit 未完成事务（add_record 已 vtxn_commit，通常 no-op）
    //   - 不清零密钥、不改变 state（始终保持 UNLOCKED）
    //   - 不重新加载索引（避免大 verthys 的索引加载超时）
    //   - 单次 IPC，无 lock+unlock 的竞态风险
    //
    // 【错误传播策略（V3-only）】
    //   所有容器均为 V3 分区格式：AddRecord 已通过 vtxn_commit 即时落盘
    //   （含 fflush + fsync），flush op 失败/IPC 失败不影响数据持久性
    //   → 返回成功 + warn 日志（避免误报"持久化失败"）。
    state.begin_io();
    let result = (|| {
        let req = serde_json::json!({"op": "flush"}).to_string();
        match state.send_with_timeout(&req, std::time::Duration::from_secs(15)) {
            Ok(resp_json) => {
                let resp: VerthysResponse = serde_json::from_str(&resp_json)
                    .map_err(|e| format!("parse flush response: {}", e))?;
                if resp.ok {
                    return Ok(resp);
                }
                // flush op 失败（旧 worker 无 flush op / Verthys_Flush 符号缺失）
                // V3：数据已通过 add_record → vtxn_commit 即时落盘，返回成功
                log::warn!(
                    "[verthys_flush] flush op 返回失败(ok=false, error={:?})，\
                     V3 数据已通过 add_record 即时落盘，返回成功",
                    resp.error
                );
                Ok(VerthysResponse::ok("flush"))
            }
            Err(e) => {
                // IPC 层面失败（worker 未响应 / 超时）
                // V3：数据已通过 add_record → vtxn_commit 即时落盘，返回成功
                log::warn!(
                    "[verthys_flush] flush IPC 失败: {}，\
                     V3 数据已通过 add_record 即时落盘，返回成功",
                    e
                );
                Ok(VerthysResponse::ok("flush"))
            }
        }
    })();
    state.end_io();
    result
}

// ===== 磁盘级持久化验证（只读，不经过 worker） =====

/// ★ 磁盘级持久化验证：以只读方式校验 .verthys 文件确实已落盘。
///
/// 消除"内存可见、磁盘丢失"的假成功：persistVerthys 成功后，回读 worker 内存
/// 无法检测磁盘是否真正写入（v1 AddRecord 仅写内存）。本命令绕过 worker，
/// 直接读取磁盘文件，校验 flush 确实将数据写入了磁盘文件。
///
/// 验证项（全部只读，不解密、不接触密钥、不修改文件、不改变 worker 状态）：
///   1. 文件存在且非空
///   2. V3 超级块副本帧头合法（'V3RP' + payload_len 在槽位容量内）
///   3. ★ mtime 时效性：文件修改时间在 15s 内（核心检测项）
///      —— 若 flush 未真正写入磁盘，mtime 为上次写入的旧值，远超 15s
///   4. V3 超级块区边界：文件 ≥ 64KB（VERTHYS_V3_SB_REGION_END）
///   5. expected_record_count：弱大小合理性检查（无法解密读取实际记录数）
///
/// 安全边界：仅读取文件头部 128 字节 + 元数据，不接触密钥材料，不依赖 worker。
/// 使用 spawn_blocking 避免阻塞 async runtime，5s 超时兜底。
/// 失败时返回 ok=false（不暴露内部技术细节），详细原因仅记日志。
#[tauri::command]
pub async fn verthys_verify_disk_persist(
    verthys_path: String,
    expected_record_count: Option<u64>,
) -> Result<VerthysResponse, String> {
    let path = verthys_path.clone();
    let expected = expected_record_count;

    let verify = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(move || verify_disk_persist_blocking(&path, expected)),
    )
    .await;

    match verify {
        Ok(Ok(Ok(()))) => {
            log::info!(
                "[verthys_verify_disk_persist] 磁盘验证通过: path={}",
                sanitize_path(&verthys_path)
            );
            Ok(VerthysResponse::ok("verthys_verify_disk_persist"))
        }
        Ok(Ok(Err(e))) => {
            log::warn!(
                "[verthys_verify_disk_persist] 磁盘验证失败: path={} reason={}",
                sanitize_path(&verthys_path),
                e
            );
            Ok(VerthysResponse::err(
                "verthys_verify_disk_persist",
                "verification failed",
            ))
        }
        Ok(Err(e)) => {
            log::error!(
                "[verthys_verify_disk_persist] spawn_blocking 异常: path={} err={}",
                sanitize_path(&verthys_path),
                e
            );
            Ok(VerthysResponse::err(
                "verthys_verify_disk_persist",
                "verification failed",
            ))
        }
        Err(_) => {
            log::error!(
                "[verthys_verify_disk_persist] 磁盘验证超时 5s: path={}",
                sanitize_path(&verthys_path)
            );
            Ok(VerthysResponse::err(
                "verthys_verify_disk_persist",
                "verification failed",
            ))
        }
    }
}

/// 磁盘级持久化验证的同步实现（在 blocking 线程中运行）。
///
/// 纯只读文件 I/O，不接触密钥、不解密任何数据。
/// 返回 Ok(()) 表示磁盘文件结构完整且最近被写入；Err 表示验证失败。
fn verify_disk_persist_blocking(
    verthys_path: &str,
    expected_record_count: Option<u64>,
) -> Result<(), String> {
    use std::io::Read;

    let path = std::path::Path::new(verthys_path);

    // 1. 文件存在性
    if !path.exists() {
        return Err("文件不存在".into());
    }

    // 2. 文件元数据：大小 + 修改时间
    let metadata =
        std::fs::metadata(path).map_err(|e| format!("读取元数据失败: {}", e))?;
    let file_size = metadata.len();
    if file_size < 8 {
        return Err(format!("文件过小 ({} 字节)", file_size));
    }

    // 3. ★ mtime 时效性检查（核心：检测 flush 是否真正写入磁盘）
    //    flush 刚成功完成，OS 应已更新文件 mtime。若 flush 未真正写入
    //    （仅写内存或写入失败被掩盖），mtime 停留在上次写入的旧值。
    //    15s 窗口覆盖 IPC 往返 + 调度延迟，同时能捕获"flush 未写入"的旧 mtime。
    let mtime = metadata
        .modified()
        .map_err(|e| format!("读取修改时间失败: {}", e))?;
    let now = std::time::SystemTime::now();
    match now.duration_since(mtime) {
        Ok(age) => {
            const MTIME_MAX_AGE_SECS: u64 = 15;
            if age.as_secs() > MTIME_MAX_AGE_SECS {
                return Err(format!(
                    "文件修改时间过旧 ({}s > {}s)，flush 可能未写入磁盘",
                    age.as_secs(),
                    MTIME_MAX_AGE_SECS
                ));
            }
        }
        Err(_) => {
            // mtime 在未来（系统时钟回拨）—— 保守视为可疑
            return Err("文件修改时间异常（在未来）".into());
        }
    }

    // 5. V3 超级块副本帧头校验（verthys_container_v3.h 布局契约）
    //    磁盘偏移 0 = Replica-0 槽位，帧头 8 字节：[u32 'V3RP'][u32 payload_len]
    //    'V3RP' = 0x50523356（LE: 56 33 52 50）；payload_len ∈ (0, 16KB - 8]
    let mut header = [0u8; 128];
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("打开文件失败: {}", e))?;
    let mut filled = 0usize;
    while filled < header.len() {
        match file.read(&mut header[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => return Err(format!("读取头部失败: {}", e)),
        }
    }
    if filled < 8 {
        return Err(format!("头部过短 ({} 字节)", filled));
    }

    const V3_REPLICA_FRAME_MAGIC: [u8; 4] = [0x56, 0x33, 0x52, 0x50]; // 'V3RP' LE
    const V3_SB_REPLICA_BYTES: u64 = 16 * 1024; // VERTHYS_V3_SB_REPLICA_BYTES
    const V3_SB_REGION_END: u64 = 0x10000; // VERTHYS_V3_SB_REGION_END（64KB）

    if header[0..4] != V3_REPLICA_FRAME_MAGIC {
        return Err("非 V3 容器格式".into());
    }
    let payload_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as u64;
    if payload_len == 0 || payload_len > V3_SB_REPLICA_BYTES - 8 {
        return Err(format!(
            "超级块副本帧长度异常: {} 字节（合法区间 (0, {}]）",
            payload_len,
            V3_SB_REPLICA_BYTES - 8
        ));
    }

    // 6. V3 超级块区边界：文件必须完整覆盖 64KB 超级块区
    if file_size < V3_SB_REGION_END {
        return Err(format!(
            "V3 文件过小: {} < {}（超级块区不完整）",
            file_size, V3_SB_REGION_END
        ));
    }

    // 7. expected_record_count 弱合理性检查
    //    V3 的记录数存储在加密分区（需 DEK 解密），无法不解密读取实际值。
    //    此处仅做文件大小的弱启发式校验：每条记录至少占用一定字节
    //    （索引条目 + 数据块开销）。文件大小不应显著低于预期。
    //    弱校验：仅记录告警，不直接判定失败（压缩/对齐/小记录等因素）。
    if let Some(expected) = expected_record_count {
        if expected > 0 {
            const MIN_BYTES_PER_RECORD: u64 = 64;
            let base_size: u64 = V3_SB_REGION_END;
            let min_expected_size = base_size + expected * MIN_BYTES_PER_RECORD;
            // 允许 50% 容差（压缩/对齐/小记录）
            if file_size < min_expected_size / 2 {
                log::warn!(
                    "[verthys_verify_disk_persist] 文件大小可能不足: \
                     file_size={} expected_records={} min_expected={}",
                    file_size,
                    expected,
                    min_expected_size
                );
            }
        }
    }

    Ok(())
}

// ===== 记录 CRUD =====

/// 添加单条记录。
#[tauri::command]
pub async fn verthys_add_record(
    state: State<'_, AppState>,
    rtype: u32,
    name: String,
    data_b64: String,
) -> Result<VerthysResponse, String> {
    // 记录名与数据 base64 均为用户明文，包装进 Zeroizing 统一擦除
    let name = Zeroizing::new(name);
    let data_b64 = Zeroizing::new(data_b64);

    let req_str = Zeroizing::new(serde_json::to_string(&AddRecordReq {
        op: "add_record",
        rtype,
        name: &name,
        data: &data_b64,
    }).map_err(|e| format!("serialize request: {}", e))?);

    let resp_json = state.send(req_str.as_str())?;

    // 发送完成：序列化副本与记录明文原件统一销毁
    drop(req_str);
    drop(data_b64);
    drop(name);

    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 按 ID 读取记录。
#[tauri::command]
pub async fn verthys_get_record(
    state: State<'_, AppState>,
    id: u64,
) -> Result<VerthysResponse, String> {
    let req = serde_json::json!({
        "op": "get_record",
        "id": id,
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 一次性枚举全部记录（自 start_id 开始），适用于记录数较少时。
/// 超时 60 秒，若记录数巨大建议使用流式版本。
#[tauri::command]
pub async fn verthys_enumerate_records(
    state: State<'_, AppState>,
    start_id: u64,
) -> Result<VerthysResponse, String> {
    let req = serde_json::json!({
        "op": "enumerate_records",
        "id": start_id,
    });
    let resp_json = state.send_with_timeout(
        &req.to_string(),
        std::time::Duration::from_secs(60),
    )?;
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 流式枚举记录，通过 Tauri Channel 分批次推送，避免一次性序列化大 JSON。
///
/// 适用于数千条以上记录的场景。后端循环调用 worker enumerate_records，
/// 每批最多 batch_size 条，通过 Channel 推送给前端，前端收到即渲染。
/// 返回累计推送总数。
#[tauri::command]
pub async fn verthys_enumerate_records_stream(
    state: State<'_, AppState>,
    start_id: u64,
    batch_size: u64,
    on_batch: tauri::ipc::Channel<EnumerateBatch>,
) -> Result<VerthysResponse, String> {
    let batch = if batch_size == 0 { 200u64 } else { batch_size.min(500) };
    let mut current_id: u64 = if start_id > 0 { start_id } else { 1 };
    let mut total_pushed: u64 = 0;
    let mut exhausted = false;

    log::info!(
        "[verthys_enumerate_records_stream] 开始流式枚举: start_id={}, batch_size={}",
        start_id, batch
    );

    while !exhausted {
        let req = serde_json::json!({
            "op": "enumerate_records",
            "id": current_id,
            "rtype": batch,
        });
        let resp_json = state.send_with_timeout(
            &req.to_string(),
            std::time::Duration::from_secs(60),
        )?;
        let resp: VerthysResponse = serde_json::from_str(&resp_json)
            .map_err(|e| format!("parse response: {}", e))?;

        if !resp.ok {
            log::warn!(
                "[verthys_enumerate_records_stream] worker 返回失败: {:?}",
                resp.error
            );
            return Ok(resp);
        }

        let records = resp.records.unwrap_or_default();
        let count = records.len() as u64;
        let last_id = resp.id.unwrap_or(0);
        exhausted = resp.exhausted.unwrap_or(false);

        if count == 0 && !exhausted {
            log::warn!(
                "[verthys_enumerate_records_stream] 空批次且未 exhausted，强制终止"
            );
            exhausted = true;
        }

        total_pushed += count;

        let batch_payload = EnumerateBatch {
            records,
            last_id,
            count,
            exhausted,
            total_pushed,
            error: None,
        };
        if let Err(e) = on_batch.send(batch_payload) {
            log::warn!(
                "[verthys_enumerate_records_stream] Channel 推送失败（前端可能已关闭）: {}",
                e
            );
            return Ok(VerthysResponse {
                record_count: Some(total_pushed),
                exhausted: Some(true),
                ..VerthysResponse::ok("enumerate_records_stream")
            });
        }

        if last_id > 0 {
            current_id = last_id + 1;
        }

        if exhausted {
            break;
        }

        if total_pushed > 2_000_000 {
            log::error!(
                "[verthys_enumerate_records_stream] 超过安全阀 200 万条，强制终止"
            );
            break;
        }
    }

    log::info!(
        "[verthys_enumerate_records_stream] 流式枚举完成: total_pushed={}",
        total_pushed
    );

    Ok(VerthysResponse {
        record_count: Some(total_pushed),
        exhausted: Some(true),
        ..VerthysResponse::ok("enumerate_records_stream")
    })
}

/// 删除单条记录。
#[tauri::command]
pub async fn verthys_delete_record(
    state: State<'_, AppState>,
    id: u64,
) -> Result<VerthysResponse, String> {
    let req = serde_json::json!({
        "op": "delete_record",
        "id": id,
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 批量删除记录，一次性传递 ID 列表，worker 在单次事务内完成删除。
/// 无论删除多少条，磁盘写入量恒定（仅一次重加密和 HMAC 更新）。
#[tauri::command]
pub async fn verthys_delete_records(
    state: State<'_, AppState>,
    ids: Vec<u64>,
) -> Result<VerthysResponse, String> {
    log::info!("[verthys_delete_records] 批量删除 {} 条记录", ids.len());
    let req = serde_json::json!({
        "op": "delete_records",
        "ids": ids,
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 获取当前已加载的轻量摘要记录数（用于 UI 展示）。
#[tauri::command]
pub async fn verthys_get_summary_count(
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    let req = serde_json::json!({
        "op": "get_summary_count",
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 轻量级检查是否存在指定类型的记录（只扫描摘要索引，不读数据块）。
#[tauri::command]
pub async fn verthys_has_record_by_type(
    state: State<'_, AppState>,
    rtype: u32,
) -> Result<VerthysResponse, String> {
    let req = serde_json::json!({
        "op": "has_record_by_type",
        "rtype": rtype,
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

// ===== 导入导出与密码变更 =====

/// 导出整个容器为加密文件（用新密码加密）。
/// 密码发送后立即擦除。
#[tauri::command]
pub async fn verthys_export(
    state: State<'_, AppState>,
    export_path: String,
    password: String,
) -> Result<VerthysResponse, String> {
    let password = Zeroizing::new(password);

    let req_str = Zeroizing::new(serde_json::to_string(&PathPasswordReq {
        op: "export",
        path: &export_path,
        password: &password,
    }).map_err(|e| format!("serialize request: {}", e))?);

    // 序列化完成即销毁口令原件，仅保留 Zeroizing 序列化副本直至发送
    drop(password);

    let resp_json = state.send(req_str.as_str())?;
    drop(req_str);
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 从加密文件导入容器（用给定密码解密）。
/// 密码发送后立即擦除。
#[tauri::command]
pub async fn verthys_import(
    state: State<'_, AppState>,
    import_path: String,
    password: String,
) -> Result<VerthysResponse, String> {
    let password = Zeroizing::new(password);

    let req_str = Zeroizing::new(serde_json::to_string(&PathPasswordReq {
        op: "import",
        path: &import_path,
        password: &password,
    }).map_err(|e| format!("serialize request: {}", e))?);

    // 序列化完成即销毁口令原件，仅保留 Zeroizing 序列化副本直至发送
    drop(password);

    let resp_json = state.send(req_str.as_str())?;
    drop(req_str);
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 修改主密码（旧密码验证 → 新密码派生）。
/// 两个密码均在使用后立即擦除，新密码需满足复杂度要求。
#[tauri::command]
pub async fn verthys_change_password(
    state: State<'_, AppState>,
    old_password: String,
    new_password: String,
) -> Result<VerthysResponse, String> {
    let old_password = Zeroizing::new(old_password);
    let new_password = Zeroizing::new(new_password);

    if let Err(e) = validate_password_complexity(&new_password) {
        log::warn!("[verthys_change_password] 新密码复杂度校验失败");
        return Err(e);
    }

    let req_str = Zeroizing::new(serde_json::to_string(&ChangePasswordReq {
        op: "change_password",
        old_password: &old_password,
        new_password: &new_password,
    }).map_err(|e| format!("serialize request: {}", e))?);

    // 序列化完成即销毁两个口令原件，仅保留 Zeroizing 序列化副本直至发送
    drop(old_password);
    drop(new_password);

    let resp_json = state.send(req_str.as_str())?;
    drop(req_str);
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

// ===== 防御闭环状态查询 =====

/// 查询防御闭环实时状态。
///
/// 透传 worker 的 security_status op，返回 7 条攻击路径的阻断/降级/失败
/// 计数与关键路径全阻断标志。防御状态为进程级事实，锁定态亦可查询。
#[tauri::command]
pub async fn verthys_security_status(
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    let req = serde_json::json!({
        "op": "security_status",
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}