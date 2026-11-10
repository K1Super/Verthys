/*
 * @file controller/verthys_controller.rs
 * @brief 加密库 CRUD 与生命周期控制器 - 核心数据管理接口
 *
 * 本模块是应用数据存储的核心入口，提供加密库的创建、解锁、锁定、持久化、
 * 记录增删改查、枚举等完整生命周期管理能力。密钥派生、数据加密等敏感运算
 * 均在 worker 子进程中执行，主进程仅负责指令转发与状态管理：容器口令仅在
 * 转发瞬间以 Zeroizing 字符串存在，派生密钥与记录明文不驻留主进程内存。
 *
 * =============================================================================
 * 核心能力
 * =============================================================================
 * - 初始化状态判定：区分全新用户、已有 verthys、损坏残留，并支持主动修复。
 * - 预热与零拷贝解锁：用户选择文件后后台预读索引区至页缓存，解锁时验证
 *   预热令牌，启用内存映射零拷贝路径，大幅提升解锁性能。
 * - 加密库创建：支持 BALANCED/SECURE 两种安全预设，原子创建并持久化状态。
 * - 解锁与锁定：解锁时由本机保管口令打开容器，建立会话守卫（自动管理文件锁）；锁定
 *   时先持久化落盘再销毁 worker，确保数据不丢失。
 * - 记录管理：支持单条增删改查、批量枚举（含流式分页）、批量删除。
 * - 动态防护状态查询：透传 worker 的安全路径阻断/降级状态。
 * - 导入导出：支持完整容器导出与导入。
 *
 * =============================================================================
 * 安全与性能设计
 * =============================================================================
 * - 口令零化：容器口令由本机保管模块提供，以 Zeroizing<String> 持有，
 *   序列化后立即擦除，确保明文不驻留；导入导出口令同样即时擦除。
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

use crate::constants::import_writer as wconst;
use crate::controller::api_error::ErrorCode;
use crate::controller::types::{EnumerateBatch, InitStatus, InitStatusResult, VerthysResponse};
use crate::repository::container_layout;
use crate::repository::verthys_chunks;
use crate::repository::verthys_state::{
    delete_state_file, read_last_verthys_path, read_state_file, try_repair_state_file,
    validate_verthys_file, write_state_file_atomic, VerthysState,
};
use crate::security::file_lock::VerthysFileLock;
use crate::state::verthys_session::VerthysSessionGuard;
use crate::state::AppState;
use crate::util::audit_log::{append_audit, keyfile_path_tag, AuditEvent, AuditEventType, AuditResult};
use crate::util::path::{normalize_path, sanitize_path};
use std::collections::HashSet;
use std::path::PathBuf;
use tauri::State;
use zeroize::Zeroizing;

// ===== 借用式请求构造 =====

// 以下结构体把口令/记录明文以 &str 借用序列化进输出字符串，
// 不产生 serde_json::Value 的 owned 明文拷贝；序列化结果立即进入
// Zeroizing 容器，随敏感原件在发送后统一擦除。

/// unlock 请求体
#[derive(serde::Serialize)]
struct UnlockReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
}

/// recovery 解锁请求体
#[derive(serde::Serialize)]
struct RecoveryUnlockReq<'a> {
    op: &'static str,
    path: &'a str,
    recovery_code: &'a str,
}

/// 恢复码轮换请求体（当前容器口令由宿主注入）
#[derive(serde::Serialize)]
struct RecoveryRotateReq<'a> {
    op: &'static str,
    password: &'a str,
    old_recovery: &'a str,
}

/// v4_create 请求体
#[derive(serde::Serialize)]
struct V4CreateReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
}

/// keyfile 解锁请求体（库路径 + keyfile 路径）
#[derive(serde::Serialize)]
struct KeyfileUnlockReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
    keyfile_path: &'a str,
}

/// keyfile 创建请求体（库路径 + keyfile 路径）
#[derive(serde::Serialize)]
struct KeyfileCreateReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
    keyfile_path: &'a str,
}

/// export / import 请求体（共用 path + password 两字段结构）
#[derive(serde::Serialize)]
struct PathPasswordReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
}

// ===== 容器口令来源 =====

/// 容器口令读取策略
#[derive(Clone, Copy)]
enum ContainerPasswordPolicy {
    /// 仅接受既有密钥材料：缺失返回 None（解锁与会话内操作）
    ExistingOnly,
    /// 允许生成新密钥材料（仅创建新库）
    CreateIfMissing,
}

/// 本机密钥材料缺失的稳定错误码（前端按码分支，不按文案匹配）
pub(crate) const KEY_MATERIAL_MISSING_CODE: &str = "E_KEY_MATERIAL_MISSING";

/// 本机密钥材料缺失的用户文案（跨命令复用）
pub(crate) const KEY_MATERIAL_MISSING_MESSAGE: &str =
    "本机密钥材料已丢失，无法用普通方式打开该库；请使用恢复码解锁，并在恢复会话中重绑本机设备槽";

/// 读取机器密钥材料主目录与旧位置目录（旧位置仅在迁移/恢复时读取）。
fn container_password_dirs(app: &tauri::AppHandle) -> Result<(PathBuf, Option<PathBuf>), String> {
    use tauri::Manager;
    let paths = app
        .try_state::<crate::infrastructure::app_paths::AppPaths>()
        .ok_or_else(|| "应用数据目录未初始化".to_string())?;
    Ok((
        paths.key_material_dir.clone(),
        paths.legacy_key_material_dir.clone(),
    ))
}

/// 按策略从指定目录读取容器口令（与 Tauri 解耦，便于单元测试）。
///
/// 读取顺序：主位置 → 旧位置迁移 → （仅创建）生成。
/// 主位置损坏时先用旧位置有效副本恢复主位置；两者都不可用则失败关闭，
/// 绝不静默生成新密钥，避免既有容器永久无法打开。
/// 密钥材料不写日志、不进审计，返回值由调用方以 Zeroizing 持有并在使用后擦除。
fn load_container_password_from_dirs(
    primary_dir: &std::path::Path,
    legacy_dir: Option<&std::path::Path>,
    allow_create: bool,
) -> Result<Option<Zeroizing<String>>, String> {
    use crate::util::container_secret;

    match container_secret::load_existing(primary_dir) {
        Ok(Some(password)) => return Ok(Some(password)),
        Ok(None) => {}
        Err(e) => {
            log::error!("[container_secret] 主位置密钥材料不可用: {}", e);
            if let Some(legacy) = legacy_dir {
                if container_secret::exists(legacy) {
                    match container_secret::restore_legacy(legacy, primary_dir) {
                        Ok(password) => {
                            log::warn!("[container_secret] 已从旧位置恢复主密钥材料");
                            return Ok(Some(password));
                        }
                        Err(e2) => {
                            log::error!("[container_secret] 旧位置恢复失败: {}", e2);
                        }
                    }
                }
            }
            return Err("安全存储不可用，无法访问加密库".to_string());
        }
    }

    if let Some(legacy) = legacy_dir {
        if legacy != primary_dir {
            match container_secret::load_existing(legacy) {
                Ok(Some(_)) => match container_secret::migrate_legacy(legacy, primary_dir) {
                    Ok(password) => {
                        log::info!("[container_secret] 旧位置密钥材料已迁移到主位置");
                        return Ok(Some(password));
                    }
                    Err(e) => {
                        log::error!("[container_secret] 密钥材料迁移失败: {}", e);
                        return Err("安全存储不可用，无法访问加密库".to_string());
                    }
                },
                Ok(None) => {}
                Err(e) => {
                    log::error!("[container_secret] 旧位置密钥材料不可用: {}", e);
                    return Err("安全存储不可用，无法访问加密库".to_string());
                }
            }
        }
    }

    if !allow_create {
        return Ok(None);
    }
    container_secret::load_or_create(primary_dir)
        .map(Some)
        .map_err(|e| {
            log::error!("[container_secret] 容器口令不可用: {}", e);
            "安全存储不可用，无法访问加密库".to_string()
        })
}

/// 按策略读取容器口令（宿主入口）。
fn load_container_password_by_policy(
    app: &tauri::AppHandle,
    policy: ContainerPasswordPolicy,
) -> Result<Option<Zeroizing<String>>, String> {
    let (primary_dir, legacy_dir) = container_password_dirs(app)?;
    load_container_password_from_dirs(
        &primary_dir,
        legacy_dir.as_deref(),
        matches!(policy, ContainerPasswordPolicy::CreateIfMissing),
    )
}

/// 读取既有容器口令（解锁/会话内操作）：缺失返回 None，绝不生成。
pub(crate) fn load_existing_container_password(
    app: &tauri::AppHandle,
) -> Result<Option<Zeroizing<String>>, String> {
    load_container_password_by_policy(app, ContainerPasswordPolicy::ExistingOnly)
}

/// 读取或创建容器口令（仅创建新库）。
pub(crate) fn load_or_create_container_password(
    app: &tauri::AppHandle,
) -> Result<Zeroizing<String>, String> {
    load_container_password_by_policy(app, ContainerPasswordPolicy::CreateIfMissing)?
        .ok_or_else(|| "安全存储不可用，无法访问加密库".to_string())
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

/// 审计 HMAC 密钥的进程内缓存（仅缓存成功结果：采集/派生瞬时失败不占缓存，
/// 下次写入仍可自愈重试）。
static AUDIT_HMAC_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// 从设备指纹派生审计 HMAC 密钥（进程内派生一次后复用）。
///
/// 派生含 10 万次 PBKDF2；逐次重派生会让连续审计操作产生可感延迟，
/// 故与其余审计调用点统一走进程内缓存。失败时返回 None，调用方跳过审计写入。
fn get_audit_hmac_key() -> Option<[u8; 32]> {
    use crate::infrastructure::device_fingerprint::get_device_fingerprint;
    use crate::util::crypto::pbkdf2_derive_default;

    if let Some(key) = AUDIT_HMAC_KEY.get() {
        return Some(*key);
    }

    match get_device_fingerprint() {
        Ok(fingerprint) => {
            const AUDIT_SALT: &[u8] = b"verthys_audit_log_hmac_salt_v1";
            match pbkdf2_derive_default(fingerprint.as_bytes(), AUDIT_SALT) {
                Ok(key) => {
                    let _ = AUDIT_HMAC_KEY.set(key);
                    Some(key)
                }
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
pub(crate) fn write_verthys_audit(
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

    let mut event =
        AuditEvent::new(event_type, &session_id, "user", result).with_resource(verthys_path);

    if let Some(d) = detail {
        event = event.with_detail(d);
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[audit] 写入审计事件失败（不阻塞业务）: {}", e);
    }
}

/// 数据域统一容器会话闸门
///
/// 记录数据读写命令必须先经本闸门：容器会话未建立（未解锁或已锁定）
/// 时写入审计 Denied 事件并返回错误文案，命令入口据此直接拒绝而不
/// 触碰 worker。拒绝以 KeyStateMismatch 错误码呈现，与 C 层 LOCKED
/// 同域可区分。
///
/// 判定依据是容器会话（VerthysSessionGuard 存在），而非全局密钥生命
/// 周期状态：记录数据由容器密钥加密保护，解锁容器即获得读写权；模块
/// 密钥等应用层密钥与 GMK 验证状态无关，GMK 授权由密钥命令自身裁决。
pub(crate) fn require_unlocked(
    app: &tauri::AppHandle,
    state: &AppState,
    cmd: &str,
) -> Result<(), String> {
    if state_allows_data_access(state) {
        return Ok(());
    }
    let current = state.key_lifecycle.current_state();
    log::warn!("[gate] {} 被容器会话闸门拒绝（生命周期 {}）", cmd, current);
    write_verthys_audit(
        app,
        AuditEventType::SecurityCommand,
        cmd,
        AuditResult::Denied,
        Some(format!(
            "容器会话未建立，拒绝数据域访问（生命周期 {}）",
            current
        )),
    );
    Err(ErrorCode::KeyStateMismatch.default_message().to_string())
}

/// 数据域访问状态判定（纯函数）：仅容器会话存在（已解锁未锁定）时
/// 允许记录数据读写。与闸门拆分以便无 AppHandle 环境下直接测试状态
/// 策略。
fn state_allows_data_access(state: &AppState) -> bool {
    state.has_verthys_session()
}

/// keyfile 创建目标的前置校验。
///
/// keyfile 是创建流程的附属产物，但目标路径来自前端选择。若目标已存在，
/// C 层 `write_keyfile_file` 会返回 `VTY_E_EXISTS` 且不写入、不删除；宿主
/// 若把该路径当作“本次创建产物”在回滚时删除，就形成了任意文件删除原语。
/// 因此在进入 worker 前必须拒绝任何已存在的目标、错误扩展名与相对路径。
fn validate_keyfile_create_target(
    verthys_path: &str,
    keyfile_path: &str,
) -> Result<(), String> {
    let kf = std::path::Path::new(keyfile_path);
    if !kf.is_absolute() {
        return Err("keyfile 路径必须是绝对路径".into());
    }
    let ext_ok = kf
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("vkf"))
        .unwrap_or(false);
    if !ext_ok {
        return Err("keyfile 路径必须以 .vkf 结尾".into());
    }
    if let Some(parent) = kf.parent() {
        if !parent.is_dir() {
            return Err("keyfile 父目录不存在或不是目录".into());
        }
    } else {
        return Err("keyfile 路径缺少父目录".into());
    }
    if normalize_path(keyfile_path).to_lowercase()
        == normalize_path(verthys_path).to_lowercase()
    {
        return Err("keyfile 路径不能与容器路径相同".into());
    }
    match std::fs::symlink_metadata(kf) {
        Ok(_) => Err("keyfile 目标已存在，拒绝覆盖或删除".into()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("无法检查 keyfile 目标: {}", err)),
    }
}

/// 创建失败回滚：仅当本次流程确实由 C 层创建了 keyfile 时才删除。
///
/// 响应超时/解析失败时调用方必须传 `keyfile_created=false`：宁可留下
/// 孤儿 keyfile，也不删除来源不明的文件。
fn cleanup_created_keyfile(
    keyfile_path: Option<&str>,
    keyfile_created: bool,
) -> Result<(), String> {
    if !keyfile_created {
        return Ok(());
    }
    let Some(kf) = keyfile_path else {
        return Ok(());
    };
    match std::fs::remove_file(kf) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("keyfile 回滚删除失败: {}", err)),
    }
}

/// 容器口令复杂度校验：最小长度 8，最大 512，用于创建/解锁前的前置校验。
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
/// - 路径指针存在但状态文件缺失时，校验 .verthys 文件格式并重建状态。
/// - 状态文件 ready=false 但 .verthys 合法时，自动修复为 ready。
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
                None => Ok(InitStatusResult {
                    status: "none".into(),
                    status_enum: Some(InitStatus::None),
                    verthys_path: None,
                    detail: "无状态文件，首次使用".into(),
                }),
                Some(verthys_path) => {
                    if std::path::Path::new(&verthys_path).exists() {
                        if let Some(repaired) = try_repair_state_file(&app, &verthys_path) {
                            log::info!(
                                "[init_status] 状态文件缺失，主动修复成功: {}",
                                sanitize_path(&verthys_path)
                            );
                            return Ok(InitStatusResult {
                                status: "ready".into(),
                                status_enum: Some(InitStatus::Ready),
                                verthys_path: Some(repaired.verthys_path.clone()),
                                detail: "状态文件缺失，已自动修复".into(),
                            });
                        }
                        log::warn!(
                            "[init_status] 状态文件缺失且主动修复失败: {}",
                            sanitize_path(&verthys_path)
                        );
                        return Ok(InitStatusResult {
                            status: "broken".into(),
                            status_enum: Some(InitStatus::Broken),
                            verthys_path: Some(verthys_path),
                            detail: "状态文件缺失且修复失败，请检查磁盘空间和权限".into(),
                        });
                    }
                    log::warn!(
                        "[init_status] 路径指针存在但 .verthys 文件不存在: {}",
                        sanitize_path(&verthys_path)
                    );
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
                format!(
                    "⚠ 状态文件写入异常（连续失败 {} 次），请检查磁盘空间与权限。",
                    s.repair_fail_count
                )
            } else {
                String::new()
            };

            if !s.ready {
                if std::path::Path::new(&s.verthys_path).exists()
                    && validate_verthys_file(&s.verthys_path)
                {
                    if let Some(repaired) = try_repair_state_file(&app, &s.verthys_path) {
                        log::info!(
                            "[init_status] ready=false 主动修复成功: {}",
                            sanitize_path(&s.verthys_path)
                        );
                        return Ok(InitStatusResult {
                            status: "ready".into(),
                            status_enum: Some(InitStatus::Ready),
                            verthys_path: Some(repaired.verthys_path.clone()),
                            detail: append_alert("状态文件已自动修复", &repair_alert),
                        });
                    }
                }
                log::warn!(
                    "[init_status] 损坏残留且修复失败: ready=false, path={}",
                    sanitize_path(&s.verthys_path)
                );
                let verthys_path = std::path::Path::new(&s.verthys_path);
                if verthys_path.exists() {
                    let _ = std::fs::remove_file(verthys_path);
                    log::info!("[init_status] 已清理残留 .verthys 文件");
                }
                // 残留容器的附属数据一并回收（有界清理：只删已知附属文件，
                // 目录含未知内容时保留目录本体）
                let report = container_layout::cleanup_container_sidecars(&s.verthys_path);
                if report.removed_files > 0 || report.removed_dir {
                    log::info!(
                        "[init_status] 已回收残留附属数据: files={} dir_removed={}",
                        report.removed_files,
                        report.removed_dir
                    );
                }
                delete_state_file(&app);
                Ok(InitStatusResult {
                    status: "broken".into(),
                    status_enum: Some(InitStatus::Broken),
                    verthys_path: Some(s.verthys_path.clone()),
                    detail: append_alert(
                        "上次初始化失败，已清理残留文件，按全新用户处理",
                        &repair_alert,
                    ),
                })
            } else if !std::path::Path::new(&s.verthys_path).exists() {
                log::warn!(
                    "[init_status] 状态文件 ready=true 但文件缺失: {}",
                    sanitize_path(&s.verthys_path)
                );
                delete_state_file(&app);
                Ok(InitStatusResult {
                    status: "broken".into(),
                    status_enum: Some(InitStatus::Broken),
                    verthys_path: Some(s.verthys_path.clone()),
                    detail: "已清理状态文件".into(),
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
mod preheat;
pub use preheat::verthys_preheat;

// ===== 解锁 =====

/// 解锁已存在的 .verthys 文件，使用本机保管口令并建立会话。
///
/// 解锁过程：
/// 1. 校验文件存在性，读取本机容器口令并校验复杂度。
/// 2. 持有共享文件锁（读锁）防止其他进程写操作。
/// 3. 验证预热令牌，若有效则启用零拷贝路径（flags 含 INDEX_PREHEATED）。
/// 4. 应用受信档位到 C 运行时策略层（fail-closed：失败即中止）。
/// 5. 通过 IPC 向 worker 发送 unlock 指令，并流式接收进度。
/// 6. 解锁成功后创建 VerthysSessionGuard（持有独占锁），存入 AppState。
/// 7. 检查状态文件，若缺失或路径不一致则自动修复/更新。
///
/// 容器口令由本机保管模块提供，不来自前端；发送后立即擦除，不驻留内存。
/// 解锁失败时文件锁自动释放（RAII）。
/// 口令解锁 容器；也接受一次性恢复码通道（见 verthys_unlock_recovery）。
///
/// 参数数量即 Tauri IPC 的线格式契约：USB 重绑确认、恢复码与
/// keyfile 路径均为独立可选输入。收拢为结构体会破坏前端调用与
/// 既有测试快照，故保持当前形状。
#[tauri::command]
pub async fn verthys_unlock(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    verthys_path: String,
    usb_rebind_confirmed: Option<bool>,
    recovery_code: Option<String>,
    keyfile_path: Option<String>,
) -> Result<VerthysResponse, String> {
    /* 恢复码通道复用同一命令：不读取本机口令、不走口令熔断计数，
     * 直接交给恢复专用实现；其余参数不参与决定。 */
    if let Some(code) = recovery_code {
        if !code.is_empty() {
            return verthys_unlock_recovery(app, state, verthys_path, code).await;
        }
    }
    log::info!(
        "[verthys_unlock] 开始解锁: path={}",
        sanitize_path(&verthys_path)
    );

    // 服务端强制暴力熔断闸门：锁定/过频状态下，口令不进入任何
    // 业务逻辑（不触文件锁、不触 FFI）。计数由后端权威维护，
    // 不依赖前端行为；前端仅负责查询展示锁定态。
    // 经 service 层契约调用（实现由 security_commands 启动时注册）。
    use crate::service::unlock_gate::{
        gate_check, GateDomain, UnlockGate, E_CNG_UNAVAILABLE, E_RATE_LIMITED,
    };
    match gate_check(&app, GateDomain::Unlock) {
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
                Some(format!(
                    "BRUTE_FORCE_LOCKOUT: 界面锁定 {} 秒（服务端强制）",
                    secs
                )),
            );
            return Ok(VerthysResponse::err_code_retry(
                "unlock",
                E_RATE_LIMITED,
                &format!("尝试次数过多，已锁定 {} 秒，请稍后再试", secs),
                secs,
            ));
        }
        UnlockGate::RateLimited { retry_after_secs } => {
            log::warn!(
                "[verthys_unlock] 最小尝试间隔未满足（剩余 {}s），拒绝尝试",
                retry_after_secs
            );
            write_verthys_audit(
                &app,
                AuditEventType::VerthysUnlock,
                &verthys_path,
                AuditResult::Denied,
                Some(format!(
                    "RATE_LIMITED: 最小尝试间隔未满足（剩余 {} 秒）",
                    retry_after_secs
                )),
            );
            return Ok(VerthysResponse::err_code_retry(
                "unlock",
                E_RATE_LIMITED,
                &format!("请求过于频繁，请 {} 秒后再试", retry_after_secs),
                retry_after_secs,
            ));
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
            return Ok(VerthysResponse::err_code(
                "unlock",
                E_CNG_UNAVAILABLE,
                "安全门禁暂时不可用，请重启应用后重试",
            ));
        }
    }

    if !std::path::Path::new(&verthys_path).exists() {
        log::warn!(
            "[verthys_unlock] 文件不存在: {}",
            sanitize_path(&verthys_path)
        );
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Failure,
            Some("文件不存在".into()),
        );
        return Err("文件不存在，请使用创建而非打开".into());
    }

    // 口令在文件存在性确认之后才读取：空路径/误选路径不应触发口令生成。
    // 普通解锁只接受既有密钥材料：缺失时 fail-closed，绝不生成新密钥；
    // 该失败不属于口令认证失败，不进入熔断计数。
    let password = match load_existing_container_password(&app)? {
        Some(password) => password,
        None => {
            log::warn!("[verthys_unlock] 本机密钥材料缺失，拒绝普通解锁");
            write_verthys_audit(
                &app,
                AuditEventType::VerthysUnlock,
                &verthys_path,
                AuditResult::Denied,
                Some("本机密钥材料缺失，需恢复码解锁".into()),
            );
            return Ok(VerthysResponse::err_code(
                "unlock",
                KEY_MATERIAL_MISSING_CODE,
                KEY_MATERIAL_MISSING_MESSAGE,
            ));
        }
    };

    if let Err(e) = validate_password_complexity(&password) {
        log::warn!("[verthys_unlock] 容器口令复杂度校验失败");
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

    // 解锁前应用受信档位（经服务层契约调用，实现由安全模块启动时注册；
    // fail-closed：失败即中止，禁止降级解锁）
    crate::service::preset_source::apply_persisted_preset_before_unlock(&app, &verthys_path)?;

    // 解锁前介质绑定守卫（经服务层契约调用）：可移动介质的登记/克隆嫌疑
    // 判定；克隆嫌疑且未确认重绑定时中止解锁（fail-closed，明确错误码）。
    // 解锁成功后按返回动作落实登记或重绑定（凭据验证通过为前提）。
    let usb_bind_action = crate::service::usb_binding::pre_unlock_guard(
        &app,
        &verthys_path,
        usb_rebind_confirmed.unwrap_or(false),
    )?;

    // 路径授权：worker 只接受宿主在本次操作前签发的 exact-path 能力。
    /* keyfile 库必须走 v4_unlock_keyfile；两条路径都要授权。
     * keyfile 内容只在 worker/C 进程内读取，主进程与前端只传路径。 */
    let keyfile_path = keyfile_path
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    if let Some(kf) = &keyfile_path {
        if !std::path::Path::new(kf).is_absolute() {
            return Err("keyfile 路径必须是绝对路径".into());
        }
    }
    let unlock_op = if keyfile_path.is_some() {
        "v4_unlock_keyfile"
    } else {
        "unlock"
    };
    state
        .authorize_worker_path(unlock_op, "read", &verthys_path)
        .map_err(|e| {
            log::error!("[verthys_unlock] 路径授权失败: {}", e);
            "打开加密库失败（路径未授权）".to_string()
        })?;

    let req_str = Zeroizing::new(
        match keyfile_path.as_deref() {
            Some(kf) => {
                state
                    .authorize_worker_path(unlock_op, "read", kf)
                    .map_err(|e| {
                        log::error!("[verthys_unlock] keyfile 路径授权失败: {}", e);
                        "打开加密库失败（keyfile 路径未授权）".to_string()
                    })?;
                serde_json::to_string(&KeyfileUnlockReq {
                    op: unlock_op,
                    path: &verthys_path,
                    password: &password,
                    keyfile_path: kf,
                })
            }
            None => serde_json::to_string(&UnlockReq {
                op: unlock_op,
                path: &verthys_path,
                password: &password,
            }),
        }
        .map_err(|e| {
            log::error!("[verthys_unlock] 请求序列化失败: {}", e);
            "打开加密库失败".to_string()
        })?,
    );

    let resp_json = {
        let result = state.send(req_str.as_str());
        match result {
            Ok(json) => json,
            Err(e) => {
                log::error!("[verthys_unlock] send 失败: {}", e);
                /* 通信失败时销毁 worker 子进程
                 *
                 * FFI 调用超时或通信失败后，父进程放弃等待但 worker 子进程
                 * 仍在运行。解锁 FFI 可能已成功完成（ctx->state = UNLOCKED），
                 * 但响应未被父进程接收。不销毁 worker 会让后续 unlock/create
                 * 命中 stale UNLOCKED 状态，返回 VERTHYS_ERR_INVALID 级联失败。
                 *
                 * 因此通信失败时立即销毁 worker（set_session(None) 触发 Drop →
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

    let mut resp: VerthysResponse = serde_json::from_str(&resp_json).map_err(|e| {
        log::error!(
            "[verthys_unlock] 解析响应失败: {} | raw={}",
            e,
            crate::util::log_sanitizer::json_log_summary(&resp_json, &["op"])
        );
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Failure,
            Some(format!("响应解析失败: {}", e)),
        );
        "打开加密库失败".to_string()
    })?;
    resp.adopt_worker_error_code();

    if !resp.ok {
        log::warn!("[verthys_unlock] 解锁失败: {:?}", resp.error);

        // 服务端强制失败计数：仅认证域错误（worker 统一化 AUTH 码）计入。
        // 口令错误/格式/IO/损坏在 worker 侧已统一映射为 AUTH，语义上
        // 均属认证域结果；功能性状态码与通信层失败不计，防止非口令
        // 因素（CNG 不可用、超时等）误锁正常用户。
        if resp.error.as_deref() == Some(crate::service::unlock_gate::AUTH_DOMAIN_ERROR) {
            crate::service::unlock_gate::record_auth_failure(&app);
        }

        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Failure,
            resp.error.clone().or(Some("解锁失败".into())),
        );
        if let Some(kf) = keyfile_path.as_deref() {
            write_verthys_audit(
                &app,
                AuditEventType::KeyfileFactor,
                &verthys_path,
                AuditResult::Failure,
                Some(format!(
                    "action=unlock;path_hash={}",
                    keyfile_path_tag(kf)
                )),
            );
        }
    } else {
        log::info!("[verthys_unlock] 解锁成功");

        if let Some(kf) = keyfile_path.as_deref() {
            write_verthys_audit(
                &app,
                AuditEventType::KeyfileFactor,
                &verthys_path,
                AuditResult::Success,
                Some(format!(
                    "action=unlock;path_hash={}",
                    keyfile_path_tag(kf)
                )),
            );
        }

        // 服务端强制成功重置：连续失败计数归零
        //（解锁响应 ok=true 已确认成功，服务端直调闸门契约，无需会话授权检查）
        crate::service::unlock_gate::record_auth_success(&app);

        // 介质绑定落实：凭据验证通过后登记（首次使用）或改写绑定（重绑定）。
        // 失败只审计，不影响已完成的解锁（加固层，不制造数据不可达）。
        crate::service::usb_binding::post_unlock_commit(&app, &verthys_path, usb_bind_action);

        // 同步 key_lifecycle 状态机与 verthys 生命周期
        //
        // verthys_verify_global_key 要求 Locked 状态，状态停在 NoKey 会让
        // 验证必然失败（"状态不匹配：当前 NoKey，仅 Locked 允许验证"）。
        // 故按 worker 进程内探测结果 has_global_key 设置状态：
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

        drop(_read_lock);

        let session_id = format!(
            "pid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );
        match VerthysSessionGuard::new(&verthys_path, &session_id) {
            Ok(guard) => {
                let mut session_guard = state.lock_verthys_session();
                *session_guard = Some(guard);
                log::info!(
                    "[verthys_unlock] VerthysSessionGuard 已创建（session={}）",
                    session_id
                );
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
                log::info!(
                    "[verthys_unlock] 状态文件缺失，自动创建（向后兼容）: {}",
                    sanitize_path(&verthys_path)
                );
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

/// 恢复码解锁（换机/灾难恢复）。
///
/// 与口令解锁的差异：不读取本机容器口令、不经过口令熔断计数、不做介质
/// 绑定校验；恢复码本身是高熵一次性凭证，成功即建立等价会话。文件锁、
/// 路径授权、会话守卫与状态文件维护仍与口令解锁一致，防止恢复路径成为
/// 绕过单写者约束的后门。
pub(crate) async fn verthys_unlock_recovery(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    verthys_path: String,
    recovery_code: String,
) -> Result<VerthysResponse, String> {
    log::info!(
        "[verthys_unlock_recovery] 开始恢复解锁: path={}",
        sanitize_path(&verthys_path)
    );
    if recovery_code.is_empty() || recovery_code.len() > 256 {
        return Ok(VerthysResponse::err(
            "v4_unlock_recovery",
            "恢复码格式非法",
        ));
    }
    if !std::path::Path::new(&verthys_path).exists() {
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Failure,
            Some("恢复解锁：文件不存在".into()),
        );
        return Ok(VerthysResponse::err(
            "v4_unlock_recovery",
            "文件不存在，请确认路径",
        ));
    }

    let _read_lock = VerthysFileLock::lock_shared(&verthys_path).map_err(|e| {
        log::warn!("[verthys_unlock_recovery] 文件锁失败: {}", e);
        "加密库正在被另一个程序使用".to_string()
    })?;

    state
        .authorize_worker_path("v4_unlock_recovery", "read", &verthys_path)
        .map_err(|e| {
            log::error!("[verthys_unlock_recovery] 路径授权失败: {}", e);
            "恢复解锁失败（路径未授权）".to_string()
        })?;

    let code = Zeroizing::new(recovery_code);
    let req_str = Zeroizing::new(
        serde_json::to_string(&RecoveryUnlockReq {
            op: "v4_unlock_recovery",
            path: &verthys_path,
            recovery_code: code.as_str(),
        })
        .map_err(|e| {
            log::error!("[verthys_unlock_recovery] 请求序列化失败: {}", e);
            "恢复解锁失败".to_string()
        })?,
    );
    let resp_json = Zeroizing::new(
        state
            .send_with_timeout(req_str.as_str(), std::time::Duration::from_secs(120))
            .map_err(|e| {
                log::error!("[verthys_unlock_recovery] send 失败: {}", e);
                "恢复解锁失败（通信失败）".to_string()
            })?,
    );
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("恢复解锁失败（响应解析失败）: {}", e))?;

    if !resp.ok {
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Failure,
            resp.error.clone().or(Some("恢复码解锁失败".into())),
        );
        return Ok(resp);
    }

    log::info!("[verthys_unlock_recovery] 恢复解锁成功");
    write_verthys_audit(
        &app,
        AuditEventType::VerthysUnlock,
        &verthys_path,
        AuditResult::Success,
        Some("恢复码解锁成功".into()),
    );

    /* 与口令解锁一致：废弃的是 C 层 GMK，产品层 global-key 记录仍决定
     * 初始化/验证视图。恢复会话先复位，再按 worker 进程内探测结果推进，
     * 固定停在 NoKey 会让恢复解锁后的验证必然报状态不匹配。 */
    state.key_lifecycle.reset_to_no_key();
    if resp.has_global_key == Some(true) {
        match state.key_lifecycle.transition_to_locked() {
            Ok(()) => log::info!(
                "[verthys_unlock_recovery] key_lifecycle → Locked（有全局密钥记录）"
            ),
            Err(e) => log::warn!(
                "[verthys_unlock_recovery] key_lifecycle 状态转移失败: {}",
                e
            ),
        }
    } else {
        log::info!("[verthys_unlock_recovery] key_lifecycle → NoKey（无全局密钥记录）");
    }

    drop(_read_lock);
    let session_id = format!(
        "pid-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );
    match VerthysSessionGuard::new(&verthys_path, &session_id) {
        Ok(guard) => {
            let mut session_guard = state.lock_verthys_session();
            *session_guard = Some(guard);
            log::info!(
                "[verthys_unlock_recovery] VerthysSessionGuard 已创建（session={}）",
                session_id
            );
        }
        Err(e) => {
            log::error!(
                "[verthys_unlock_recovery] VerthysSessionGuard 创建失败: {}",
                e
            );
            write_verthys_audit(
                &app,
                AuditEventType::VerthysUnlock,
                &verthys_path,
                AuditResult::Failure,
                Some(format!("VerthysSessionGuard 创建失败: {}", e)),
            );
        }
    }

    match read_state_file(&app) {
        Ok(Some(existing_state)) => {
            if existing_state.verthys_path != normalize_path(&verthys_path) {
                let new_state = VerthysState::new(&verthys_path);
                if let Err(e) = write_state_file_atomic(&app, &new_state) {
                    log::warn!(
                        "[verthys_unlock_recovery] 状态文件更新失败（不阻塞解锁）: {}",
                        e
                    );
                }
            }
        }
        Ok(None) => {
            let new_state = VerthysState::new(&verthys_path);
            if let Err(e) = write_state_file_atomic(&app, &new_state) {
                log::warn!(
                    "[verthys_unlock_recovery] 状态文件创建失败（不阻塞解锁）: {}",
                    e
                );
            }
        }
        Err(e) => {
            log::warn!(
                "[verthys_unlock_recovery] 状态文件读取失败，重建: {}",
                e
            );
            let new_state = VerthysState::new(&verthys_path);
            if let Err(e) = write_state_file_atomic(&app, &new_state) {
                log::warn!(
                    "[verthys_unlock_recovery] 状态文件重建失败（不阻塞解锁）: {}",
                    e
                );
            }
        }
    }

    Ok(resp)
}

/// 轮换一次性恢复码（当前容器口令由宿主注入 + 用户提供旧恢复码）。
///
/// 成功响应含新恢复码；宿主不落盘、不写日志，前端展示确认后必须清零。
#[tauri::command]
pub async fn verthys_recovery_rotate(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    old_recovery_code: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "recovery_rotate") {
        return Ok(VerthysResponse::err("v4_recovery_rotate", &msg));
    }
    if old_recovery_code.is_empty() || old_recovery_code.len() > 256 {
        return Ok(VerthysResponse::err(
            "v4_recovery_rotate",
            "旧恢复码格式非法",
        ));
    }
    // 恢复码轮换必须使用既有密钥材料：会话已解锁，密钥材料不应缺失；
    // 缺失说明外部破坏了本机状态，fail-closed，不得生成新密钥。
    let password = match load_existing_container_password(&app)? {
        Some(password) => password,
        None => {
            log::warn!("[verthys_recovery_rotate] 本机密钥材料缺失，拒绝轮换");
            return Ok(VerthysResponse::err_code(
                "v4_recovery_rotate",
                KEY_MATERIAL_MISSING_CODE,
                KEY_MATERIAL_MISSING_MESSAGE,
            ));
        }
    };
    let old_code = Zeroizing::new(old_recovery_code);
    let req_str = Zeroizing::new(
        serde_json::to_string(&RecoveryRotateReq {
            op: "v4_recovery_rotate",
            password: &password,
            old_recovery: old_code.as_str(),
        })
        .map_err(|e| format!("恢复码轮换失败（序列化失败）: {}", e))?,
    );
    let resp_json = Zeroizing::new(
        state
            .send_with_timeout(req_str.as_str(), std::time::Duration::from_secs(60))
            .map_err(|e| format!("恢复码轮换失败（通信失败）: {}", e))?,
    );
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("恢复码轮换失败（响应解析失败）: {}", e))?;
    if resp.ok {
        log::info!("[verthys_recovery_rotate] 恢复码轮换成功");
    } else {
        log::warn!("[verthys_recovery_rotate] 恢复码轮换失败: {:?}", resp.error);
    }
    Ok(resp)
}

// ===== 创建 =====
/// 创建新的加密库（首次初始化）。
///
/// 流程：
/// 1. 前置校验：目标文件不存在，本机容器口令复杂度合格。
/// 2. 调用 worker v4_create 创建 容器并取得一次性恢复码。
/// 3. 发送 lock 指令持久化空 verthys，并释放 worker 侧容器句柄。
/// 4. 获取主进程独占文件锁（会话哨兵锁，防其他 Verthys 实例打开）。
/// 5. 再次 unlock 重新打开，保持会话。
/// 6. 校验 .verthys 文件已成功落地（大小 >0）。
/// 7. 原子写入状态文件（若失败仅警告，不删除 .verthys）。
/// 8. 创建 VerthysSessionGuard 并存入 AppState。
///
/// 锁序红线：worker 容器句柄以 FILE_SHARE_READ 单写者语义存活
/// （C 层跨进程互斥），本进程再以 GENERIC_WRITE 打开同一文件会被
/// 内核以 SHARING_VIOLATION 拒绝——主进程哨兵锁必须在步骤 3
/// worker 释放容器句柄之后获取，否则创建必然失败。
///
/// 任何步骤失败则回滚：删除不完整的 .verthys 文件，销毁 worker，清理状态。
/// 容器口令由本机保管模块提供，发送后立即擦除。
#[tauri::command]
pub async fn verthys_create(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    verthys_path: String,
    preset: Option<u32>,
    keyfile_path: Option<String>,
) -> Result<VerthysResponse, String> {
    let preset_val: u32 = match preset {
        Some(1) => 1,
        _ => 0,
    };
    let preset_name = if preset_val == 1 {
        "SECURE"
    } else {
        "BALANCED"
    };
    /* keyfile 路径只用于传参；文件由 C 层生成/读取，前端不接触字节。 */
    let keyfile_path = keyfile_path
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    if let Some(kf) = &keyfile_path {
        if !std::path::Path::new(kf).is_absolute() {
            return Err("keyfile 路径必须是绝对路径".into());
        }
    }
    log::info!(
        "[verthys_create] 开始创建: path={} preset={} keyfile={}",
        sanitize_path(&verthys_path),
        preset_name,
        keyfile_path.is_some()
    );

    if std::path::Path::new(&verthys_path).exists() {
        log::warn!(
            "[verthys_create] 文件已存在: {}",
            sanitize_path(&verthys_path)
        );
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Denied,
            Some("文件已存在，拒绝创建".into()),
        );
        return Err("文件已存在，请使用打开而非创建".into());
    }

    /* keyfile 目标必须先于 worker 调用校验：目标已存在时 C 层拒绝写入，
     * 宿主若在回滚时无条件删除会把该路径变成任意文件删除原语。 */
    if let Some(kf) = &keyfile_path {
        if let Err(e) = validate_keyfile_create_target(&verthys_path, kf) {
            log::warn!("[verthys_create] keyfile 目标校验失败: {}", e);
            write_verthys_audit(
                &app,
                AuditEventType::KeyfileFactor,
                &verthys_path,
                AuditResult::Denied,
                Some(format!("action=create;{}", e)),
            );
            return Err(e);
        }
    }

    // 首次创建时由本模块生成口令：必须在文件存在性校验之后，
    // 避免重复创建请求产生无用口令文件。仅此路径允许生成新密钥材料。
    let password = load_or_create_container_password(&app)?;

    if let Err(e) = validate_password_complexity(&password) {
        log::warn!("[verthys_create] 容器口令复杂度校验失败");
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
    let keyfile_for_rollback = keyfile_path.clone();

    // 附属数据目录前置保障：目录被同名文件占用、路径超长或不可创建时，
    // 创建流程整体拒绝（不进入 worker 创建，避免产生只带容器的半成品）。
    if let Err(e) = container_layout::ensure_sidecar_dir(&verthys_path) {
        log::warn!(
            "[verthys_create] 附属数据目录不可用: {} | {}",
            e,
            sanitize_path(&verthys_path)
        );
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &verthys_path,
            AuditResult::Denied,
            Some(format!("附属数据目录不可用: {}", e)),
        );
        return Err(format!("创建加密库失败：{}", e));
    }
    log::info!(
        "[verthys_create] 附属数据目录就绪: {}",
        sanitize_path(&container_layout::sidecar_dir_for(&verthys_path).to_string_lossy())
    );

    let create_timeout = std::time::Duration::from_secs(60);
    let lock_unlock_timeout = std::time::Duration::from_secs(30);

    let mut file_lock: Option<VerthysFileLock> = None;
    /* 只有 worker 明确返回创建成功时，keyfile 才是本次流程的产物；
     * 超时/解析失败/创建失败一律保持 false，回滚不得删除未知来源文件。 */
    let mut keyfile_created = false;

    let create_result: Result<VerthysResponse, String> = (|| {
        log::info!(
            "[verthys_create] 步骤 1/3: {}（超时={}s）",
            if keyfile_path.is_some() { "v4_create_keyfile" } else { "v4_create" },
            create_timeout.as_secs()
        );
        let create_op = if keyfile_path.is_some() {
            "v4_create_keyfile"
        } else {
            "v4_create"
        };
        state
            .authorize_worker_path(create_op, "write", &verthys_path)
            .map_err(|e| format!("创建加密库失败（路径未授权）: {}", e))?;
        let create_req = Zeroizing::new(
            match keyfile_path.as_deref() {
                Some(kf) => {
                    state
                        .authorize_worker_path(create_op, "write", kf)
                        .map_err(|e| format!("创建加密库失败（keyfile 路径未授权）: {}", e))?;
                    serde_json::to_string(&KeyfileCreateReq {
                        op: create_op,
                        path: &verthys_path,
                        password: &password,
                        keyfile_path: kf,
                    })
                }
                None => serde_json::to_string(&V4CreateReq {
                    op: create_op,
                    path: &verthys_path,
                    password: &password,
                }),
            }
            .map_err(|e| format!("创建加密库失败（步骤1序列化失败）: {}", e))?,
        );
        let resp_json = state
            .send_with_timeout(create_req.as_str(), create_timeout)
            .map_err(|e| {
                log::error!(
                    "[verthys_create] 步骤 1 send 失败（超时 {}s）: {}",
                    create_timeout.as_secs(),
                    e
                );
                format!("创建加密库失败（步骤1通信失败）: {}", e)
            })?;
        let create_resp: VerthysResponse = serde_json::from_str(&resp_json)
            .map_err(|e| format!("创建加密库失败（步骤1响应解析失败）: {}", e))?;
        if !create_resp.ok {
            let detail = create_resp.error.unwrap_or_else(|| "未知错误".to_string());
            log::error!("[verthys_create] 步骤 1/3 失败: error={}", detail);
            return Err(format!("创建加密库失败（步骤1）: {}", detail));
        }
        log::info!("[verthys_create] 步骤 1/3: v4_create 成功");
        /* C 层只有 keyfile 写入且库创建成功后才返回 OK；此处是
         * “keyfile 确由本次流程创建”的权威时点。 */
        keyfile_created = keyfile_path.is_some();
        /* 恢复码只在本响应中透传一次；缺失即 fail-closed 并回滚，
         * 禁止留下“无法恢复”的库。 */
        let recovery_code = create_resp.recovery_code.clone();
        if recovery_code.as_deref().unwrap_or("").is_empty() {
            return Err("创建加密库失败（缺少一次性恢复码）".to_string());
        }

        /* 容器格式不含预设字段；创建时选择的档位作为运行时防护档应用，
         * 不能静默忽略。切换失败视为创建失败并回滚文件。 */
        if preset_val != 0 {
            let preset_req = Zeroizing::new(
                serde_json::json!({ "op": "switch_preset", "preset": preset_val })
                    .to_string(),
            );
            let preset_resp_json = state
                .send_with_timeout(preset_req.as_str(), lock_unlock_timeout)
                .map_err(|e| format!("创建加密库失败（预设应用通信失败）: {}", e))?;
            let preset_resp: VerthysResponse = serde_json::from_str(&preset_resp_json)
                .map_err(|e| format!("创建加密库失败（预设应用响应解析失败）: {}", e))?;
            if !preset_resp.ok {
                let detail = preset_resp.error.unwrap_or_else(|| "未知错误".to_string());
                return Err(format!("创建加密库失败（预设应用）: {}", detail));
            }
            log::info!("[verthys_create] 运行时预设 {}", preset_name);
        }

        // 锁序：先由 lock 指令让 worker 落盘并释放容器句柄（FILE_SHARE_READ
        // 单写者句柄存续期间，本进程以 GENERIC_WRITE 打开会被内核拒绝），
        // 随后才能在主进程侧获取会话哨兵锁（偏移 2GB，与 C 层超级块锁零重叠）。
        log::info!(
            "[verthys_create] 步骤 2/3: lock（写盘持久化 + 释放 worker 容器句柄, 超时={}s）",
            lock_unlock_timeout.as_secs()
        );
        let lock_req = r#"{"op":"lock"}"#;
        let lock_resp_json = state
            .send_with_timeout(lock_req, lock_unlock_timeout)
            .map_err(|e| {
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

        // 步骤 2.5：主进程会话哨兵锁（worker 容器句柄已释放，共享模式不再冲突）
        let lock = VerthysFileLock::lock_exclusive(&verthys_path).map_err(|e| {
            log::error!("[verthys_create] 文件锁失败: {}", e);
            format!("创建加密库失败（文件锁失败）: {}", e)
        })?;
        file_lock = Some(lock);
        log::info!("[verthys_create] 会话哨兵锁已获取");

        log::info!(
            "[verthys_create] 步骤 3/3: {}（重新打开, 超时={}s）",
            if keyfile_path.is_some() { "v4_unlock_keyfile" } else { "unlock" },
            lock_unlock_timeout.as_secs()
        );
        let unlock_op = if keyfile_path.is_some() {
            "v4_unlock_keyfile"
        } else {
            "unlock"
        };
        state
            .authorize_worker_path(unlock_op, "read", &verthys_path)
            .map_err(|e| format!("创建加密库失败（步骤3路径未授权）: {}", e))?;
        let unlock_req2 = Zeroizing::new(
            match keyfile_path.as_deref() {
                Some(kf) => {
                    state
                        .authorize_worker_path(unlock_op, "read", kf)
                        .map_err(|e| {
                            format!("创建加密库失败（步骤3 keyfile 路径未授权）: {}", e)
                        })?;
                    serde_json::to_string(&KeyfileUnlockReq {
                        op: unlock_op,
                        path: &verthys_path,
                        password: &password,
                        keyfile_path: kf,
                    })
                }
                None => serde_json::to_string(&UnlockReq {
                    op: unlock_op,
                    path: &verthys_path,
                    password: &password,
                }),
            }
            .map_err(|e| format!("创建加密库失败（步骤3序列化失败）: {}", e))?,
        );
        let resp_json2 = state
            .send_with_timeout(unlock_req2.as_str(), lock_unlock_timeout)
            .map_err(|e| {
                log::error!("[verthys_create] 步骤 3 send 失败: {}", e);
                format!("创建加密库失败（步骤3通信失败）: {}", e)
            })?;
        let unlock_resp2: VerthysResponse = serde_json::from_str(&resp_json2)
            .map_err(|e| format!("创建加密库失败（步骤3响应解析失败）: {}", e))?;
        if !unlock_resp2.ok {
            let detail = unlock_resp2.error.unwrap_or_else(|| "未知错误".to_string());
            let retry_secs = unlock_resp2.retry_after_secs.unwrap_or(0);
            log::error!(
                "[verthys_create] 步骤 3/3 失败: error={} retry_after_secs={}",
                detail,
                retry_secs
            );
            /* 0x0A = VERTHYS_ERR_RATE：本地持久熔断处于指数退避窗口，
             * 或机器预算服务拒绝/不可用（未安装、不可达、客户端签名未通过，
             * fail-closed）。创建本身已成功，这里失败的是紧随其后的自检
             * 解锁；直接透出错误码会让用户误以为文件没建成并反复重试。 */
            if detail == "ERR_0000000A" {
                if retry_secs > 0 {
                    return Err(format!(
                        "创建加密库失败（步骤3重开失败）：本机安全退避中，请 {} 秒后重试；本次未保留库文件",
                        retry_secs
                    ));
                }
                return Err("创建加密库失败（步骤3重开失败）：本机安全服务拒绝或不可用。未签名的开发构建请使用 build_dev.ps1 启动；已安装服务时请确认客户端签名与 VerthysSecuritySvc 状态".into());
            }
            return Err(format!("创建加密库失败（步骤3重开失败）: {}", detail));
        }
        log::info!("[verthys_create] 步骤 3/3: unlock 成功");

        let mut final_resp = unlock_resp2;
        final_resp.recovery_code = recovery_code;
        Ok(final_resp)
    })();

    drop(password);

    if let Err(ref e) = create_result {
        drop(file_lock.take());
        let _ = std::fs::remove_file(&path_for_rollback);
        /* 只删除本次流程确实由 C 层创建的 keyfile；已存在目标/超时
         * 响应一律不碰，避免任意文件删除。 */
        if let Err(cleanup_err) = cleanup_created_keyfile(
            keyfile_for_rollback.as_deref(),
            keyfile_created,
        ) {
            log::error!("[verthys_create] {}", cleanup_err);
            if let Some(kf) = keyfile_for_rollback.as_deref() {
                write_verthys_audit(
                    &app,
                    AuditEventType::KeyfileFactor,
                    &path_for_rollback,
                    AuditResult::Failure,
                    Some(format!(
                        "action=create;path_hash={};cleanup=delete_failed",
                        keyfile_path_tag(kf)
                    )),
                );
            }
        }
        state.set_session(None);
        delete_state_file(&app);
        // 附属数据有界清理：只删本次流程可能产生的已知附属文件（state /
        // lock / tmp），目录清空即回收；目录含未知文件时保留目录本体。
        let report = container_layout::cleanup_container_sidecars(&path_for_rollback);
        log::error!(
            "[verthys_create] 创建失败，已回滚: {} | {} | 附属文件清理={} 目录回收={}",
            sanitize_path(&path_for_rollback),
            e,
            report.removed_files,
            report.removed_dir
        );
        write_verthys_audit(
            &app,
            AuditEventType::VerthysUnlock,
            &path_for_rollback,
            AuditResult::Failure,
            Some(format!("创建失败已回滚: {}", e)),
        );
        if let Some(kf) = keyfile_for_rollback.as_deref() {
            write_verthys_audit(
                &app,
                AuditEventType::KeyfileFactor,
                &path_for_rollback,
                AuditResult::Failure,
                Some(format!(
                    "action=create;path_hash={}",
                    keyfile_path_tag(kf)
                )),
            );
        }
        return create_result;
    }

    let verthys_file = std::path::Path::new(&path_for_rollback);
    if !verthys_file.exists() {
        let msg = "[verthys_create] 文件落地校验失败: .verthys 文件不存在".to_string();
        log::error!("{}", msg);
        drop(file_lock.take());
        state.set_session(None);
        delete_state_file(&app);
        let _ = container_layout::cleanup_container_sidecars(&path_for_rollback);
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
        let _ = container_layout::cleanup_container_sidecars(&path_for_rollback);
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
    log::info!(
        "[verthys_create] 文件落地校验通过: size={} bytes",
        file_size
    );

    // verthys_create 通过 raw worker IPC 完成 create→lock→unlock，
    // 不经过 verthys_unlock 命令的 key_lifecycle 状态管理。
    // 新建 verthys 无全局密钥记录，后端状态必须为 NoKey，
    // 否则 verthys_derive_global_key（要求 NoKey）会因状态不匹配而失败。
    state.key_lifecycle.reset_to_no_key();
    log::info!("[verthys_create] key_lifecycle → NoKey（新建 verthys 无全局密钥）");

    let verthys_state = VerthysState::new(&path_for_rollback);
    if let Err(e) = write_state_file_atomic(&app, &verthys_state) {
        log::warn!(
            "[verthys_create] 状态文件写入失败（.verthys 文件已保存，不回滚）: {}",
            e
        );
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

    log::info!(
        "[verthys_create] 创建完成: verthys_path={}",
        sanitize_path(&path_for_rollback)
    );

    /* 审计：keyfile 路径只落域分离哈希，不写明文 */
    if let Some(kf) = keyfile_path.as_deref() {
        write_verthys_audit(
            &app,
            AuditEventType::KeyfileFactor,
            &path_for_rollback,
            AuditResult::Success,
            Some(format!(
                "action=create;path_hash={}",
                keyfile_path_tag(kf)
            )),
        );
    }

    if let Some(lock) = file_lock {
        let session_id = format!(
            "pid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );
        drop(lock);
        match VerthysSessionGuard::new(&path_for_rollback, &session_id) {
            Ok(guard) => {
                let mut session_guard = state.lock_verthys_session();
                *session_guard = Some(guard);
                log::info!(
                    "[verthys_create] VerthysSessionGuard 已创建（session={}）",
                    session_id
                );
            }
            Err(e) => {
                log::error!(
                    "[verthys_create] VerthysSessionGuard 创建失败（不阻塞返回）: {}",
                    e
                );
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
        Ok(resp_json) => match serde_json::from_str::<VerthysResponse>(&resp_json) {
            Ok(resp) => {
                if !resp.ok {
                    log::warn!(
                        "[verthys_lock_persist] worker lock 返回失败: {:?}",
                        resp.error
                    );
                }
                Ok(resp)
            }
            Err(e) => {
                log::warn!("[verthys_lock_persist] 解析 lock 响应失败: {}", e);
                Ok(VerthysResponse::ok("lock"))
            }
        },
        Err(e) => {
            log::warn!(
                "[verthys_lock_persist] worker lock 超时或失败（仍允许后续销毁兜底）: {}",
                e
            );
            Ok(VerthysResponse::ok("lock"))
        }
    };
    state.end_io();
    result
}

// ===== 锁定（销毁 worker） =====

/// 锁定前置闸门：请求取消并等待全库轮换 Run 收敛（后端有界 30s）。
///
/// 前端在任何破坏性锁定步骤（清 GMK / 落盘 / 销毁 worker）之前调用。
/// 失败表示轮换仍在执行，本次锁定必须整体放弃并保留会话与空闲计时；
/// 前端超时结果不能作为安全边界 —— `verthys_lock` / `worker_destroy`
/// 内部仍保留同一闸门与代际校验作为最后防线。
#[tauri::command]
pub async fn verthys_prepare_lock() -> Result<VerthysResponse, String> {
    tauri::async_runtime::spawn_blocking(|| {
        crate::service::vault_rotate::prepare_for_lock(std::time::Duration::from_secs(30))
    })
    .await
    .map_err(|e| format!("锁定闸门执行失败: {e}"))??;
    Ok(VerthysResponse::ok("prepare_lock"))
}

/// 释放无会话归属的锁定资源（代际冲突路径）。
///
/// 只在确认当前没有任何 worker 会话时调用：此时残留的哨兵锁与旧文件锁
/// 不属于任何活动会话，必须回收，否则下一次解锁会命中过期锁。若存在新
/// 会话，这些资源归新会话所有，不得在此释放。
fn release_orphan_lock_resources(state: &AppState) {
    crate::service::vault_rotate::reset_on_lock();
    if let Some(guard) = state.lock_verthys_session().take() {
        log::info!("[verthys_lock] 清理无会话归属的 VerthysSessionGuard");
        drop(guard);
    }
    if let Some(lock_guard) = state.lock_verthys_file().take() {
        log::info!("[verthys_lock] 清理无会话归属的 verthys_file_lock");
        drop(lock_guard);
    }
}

/// 销毁 worker 子进程并清理资源（剪贴板、文件锁）。
///
/// 调用前应先执行 verthys_lock_persist 确保持久化完成。
/// 销毁前等待所有进行中的 IO 操作完成（最长 10 秒），超时则强制销毁。
/// 销毁后状态回到 Uninitialized，VerthysSessionGuard Drop 自动释放文件锁。
///
/// 代际校验：等待轮换收敛与 IO 收敛期间会话可能被替换（新解锁）。命令
/// 入口记录代际，实际销毁前用 `clear_session_if_epoch` 原子校验并清空；
/// 代际已变则返回 `SESSION_SUPERSEDED`，绝不把锁定打在**新会话**上。
#[tauri::command]
pub async fn verthys_lock(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    let session_path = state.verthys_session_path();
    let epoch = state.session_epoch();

    /* 轮换 Run 在 worker 内执行时，锁请求只能排队；直接销毁会话会让
     * worker 继续持有 GMK。先请求取消并等待 Run 收敛（有界），超时则
     * 拒绝本次锁定，避免“已锁定但密钥仍驻留”的假象。等待使用阻塞线程，
     * 不占用异步执行器。 */
    tauri::async_runtime::spawn_blocking(|| {
        crate::service::vault_rotate::prepare_for_lock(std::time::Duration::from_secs(30))
    })
    .await
    .map_err(|e| format!("锁定闸门执行失败: {e}"))??;

    let _ = state
        .wait_io_complete(std::time::Duration::from_secs(10))
        .await;

    /* 检查与销毁在写锁内原子完成：若等待期间已有新会话接管，立即放弃，
     * 后续的密钥生命周期重置、剪贴板清理与文件锁释放都不得执行。 */
    if !state.clear_session_if_epoch(epoch) {
        log::warn!("[verthys_lock] 等待期间会话代际已变更，放弃本次锁定");
        /* 代际已变但当前没有任何会话：说明另一路径（如 worker_destroy）
         * 只清了 worker 会话而未释放哨兵锁。此时补全孤儿清理，避免旧
         * VerthysSessionGuard/文件锁泄漏到下一次解锁；若确有新会话存在，
         * 那些资源归新会话所有，绝不在这里释放。 */
        if !state.has_session() {
            release_orphan_lock_resources(&state);
        }
        return Err(crate::state::SESSION_SUPERSEDED.to_string());
    }

    /* C 层会话销毁会中止轮换作业；宿主侧的取消事件与“可取消”状态
     * 必须同步释放，不能跨会话残留。 */
    crate::service::vault_rotate::reset_on_lock();

    // worker 已随会话销毁，GMK 已消失，重置密钥生命周期为 NoKey
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

    // 痕迹清理（锁定 / 退出时机的执行路径）：清理系统最近记录中指向
    // 本应用文件的条目。fire-and-forget：专用阻塞线程执行（COM 初始化
    // 在任务内完成），失败仅审计 + 告警，不阻塞锁定响应。
    crate::security::trace_cleanup::run_locked_cleanup_async(app.clone());

    Ok(VerthysResponse::ok("lock"))
}

// ===== 刷新（Verthys_Flush） =====

/// 刷盘：调用 Verthys_Flush 提交未完成事务，保持 worker 会话不中断。
/// 的 add_record 已提交 DataRoot，此函数再次执行幂等保存，确保
/// 目录脏状态/待提交段与元数据一致。失败必须向上传播，不得把
/// “未确认落盘”伪装成成功。
/// 不清零密钥、不改变 worker 状态（始终 UNLOCKED），无 lock+unlock 竞态风险。
#[tauri::command]
pub async fn verthys_flush(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "flush") {
        return Ok(VerthysResponse::err("flush", &msg));
    }

    // 直接发送 {"op":"flush"} → worker call_flush → C Verthys_Flush
    //   - commit 未完成事务（add_record 已 vtxn_commit，通常 no-op）
    //   - 不清零密钥、不改变 state（始终保持 UNLOCKED）
    //   - 不重新加载索引（避免大 verthys 的索引加载超时）
    //   - 单次 IPC，无 lock+unlock 的竞态风险
    //
    //   AddRecord 已即时提交，但 flush 负责再次确认 DataRoot/元数据与
    //   目录脏状态一致；flush op 失败或 IPC 失败时必须返回 err，
    //   让上层区分“已确认落盘”与“未确认落盘”，不得吞错报成功。
    state.begin_io();
    let result = (|| {
        let req = serde_json::json!({"op": "flush"}).to_string();
        match state.send_with_timeout(&req, std::time::Duration::from_secs(15)) {
            Ok(resp_json) => match serde_json::from_str::<VerthysResponse>(&resp_json) {
                Ok(resp) => {
                    if !resp.ok {
                        log::warn!(
                            "[verthys_flush] flush op 返回失败: {:?}",
                            resp.error
                        );
                    }
                    Ok(resp)
                }
                Err(e) => {
                    log::error!("[verthys_flush] flush 响应解析失败: {}", e);
                    Ok(VerthysResponse::err("flush", "flush response parse failed"))
                }
            },
            Err(e) => {
                log::error!("[verthys_flush] flush IPC 失败: {}", e);
                Ok(VerthysResponse::err("flush", "flush ipc failed"))
            }
        }
    })();
    state.end_io();
    result
}

// ===== 落盘自查（worker 进程内 C 层持锁句柄） =====

/// 磁盘级落盘校验：由 worker 进程内用 C 层持锁句柄自查盘面结构。
///
/// 为什么不走主进程直接读盘：Windows 字节范围锁为强制锁——容器会话在
/// C 层子进程内以独占方式持有超级块区 [0,64KB)。主进程以
/// `std::fs::File::open` 新开句柄读取该区间恒被 ERROR_LOCK_VIOLATION
/// （os error 33）拒绝，主进程直读必然失败，产生"持久化失败"误报并阻断
/// 解析导入。故校验必须下沉到持有会话句柄的 worker 子进程，
/// 由该进程用 C 层会话持锁句柄完成自查（Verthys_VerifyPersist）。
///
/// 命令名保持不变（前端契约）；结构化字段（status_code/file_size/
/// mtime_ms/header_magic/header_version）随响应同名字段透传，前端据此做
/// 三态判定（OK / 可重试 IO / 结构性失败）。
#[tauri::command]
pub async fn verthys_verify_disk_persist(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：无容器会话时 worker 内无持锁句柄，无从自查
    if let Err(msg) = require_unlocked(&app, &state, "verthys_verify_disk_persist") {
        return Ok(VerthysResponse::err("verthys_verify_disk_persist", &msg));
    }

    state.begin_io();
    let result = (|| {
        let req = serde_json::json!({"op": "verify_persist"}).to_string();
        match state.send_with_timeout(&req, std::time::Duration::from_secs(10)) {
            Ok(resp_json) => {
                // worker 响应含 verify_persist 结构化字段，serde 同名透传
                let resp: VerthysResponse = serde_json::from_str(&resp_json)
                    .map_err(|e| format!("parse verify_persist response: {}", e))?;
                if resp.ok {
                    log::info!(
                        "[verthys_verify_disk_persist] 落盘自查通过: file_size={:?} magic=0x{:08X}",
                        resp.file_size,
                        resp.header_magic.unwrap_or(0)
                    );
                } else {
                    log::warn!(
                        "[verthys_verify_disk_persist] 落盘自查未通过: status_code={:?} detail={:?}",
                        resp.status_code,
                        resp.error
                    );
                }
                Ok(resp)
            }
            Err(e) => {
                log::warn!("[verthys_verify_disk_persist] worker IPC 失败: {}", e);
                Ok(VerthysResponse::err(
                    "verthys_verify_disk_persist",
                    "verification IPC failed",
                ))
            }
        }
    })();
    state.end_io();
    result
}

/// 强制关闭（丢弃）当前活跃的导入会话。
///
/// 语义：异常/中断场景下清理卡住的导入会话，使后续导入可重新 begin。
/// 与 verthys_import_end 的区别：不写 end、不压缩 WAL——会话被直接丢弃，
/// 盘面 WAL 保留，断点续传状态（committed 哈希）在下次 begin 时可恢复。
/// 幂等：无活跃会话时直接返回 ok。
#[tauri::command]
pub async fn verthys_force_close_import_session(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "verthys_force_close_import_session") {
        return Ok(VerthysResponse::err(
            "verthys_force_close_import_session",
            &msg,
        ));
    }

    // 取走并丢弃会话：WalWriter Drop 关闭文件句柄，但不执行 end/压缩，
    // 保留断点续传状态。无会话时 take() 返回 None，幂等。
    let dropped = {
        let mut guard = state.lock_import_session();
        match guard.take() {
            Some(session) => Some(session.import_id.clone()),
            None => None,
        }
    };
    match dropped {
        Some(import_id) => {
            log::warn!(
                "[verthys_force_close_import_session] 强制关闭导入会话 import_id={}（不压缩 WAL，保留续传状态）",
                import_id
            );
        }
        None => {
            log::info!("[verthys_force_close_import_session] 无活跃导入会话，幂等返回");
        }
    }

    Ok(VerthysResponse::ok("verthys_force_close_import_session"))
}

// ===== 记录 CRUD =====

/// 添加单条记录。
#[tauri::command]
pub async fn verthys_add_record(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    rtype: u32,
    name: String,
    data_b64: String,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, "add_record") {
        return Ok(VerthysResponse::err("add_record", &msg));
    }

    // 记录名与数据 base64 均为用户明文，包装进 Zeroizing 统一擦除
    let name = Zeroizing::new(name);
    let data_b64 = Zeroizing::new(data_b64);

    // 写入侧协议护栏：与批量写入路径同一上限（记录载荷 base64 长度）。
    // worker 行协议单行硬上限 16MiB，超限请求会被 worker 侧判定协议异常并
    // 断开连接（worker 失联，后续全部操作级联失败）。此处前置拒绝，把
    // 「超限即断链」的系统级故障收敛为可读的按条错误。
    if name.is_empty() || name.len() > wconst::MAX_RECORD_NAME_LEN {
        log::warn!("[verthys_add_record] 拒绝非法记录名（长度 {}）", name.len());
        return Ok(VerthysResponse::err(
            "add_record",
            "记录名长度非法（空或超上限）",
        ));
    }
    if data_b64.is_empty() || data_b64.len() > wconst::MAX_IPC_PAYLOAD_BYTES {
        log::warn!(
            "[verthys_add_record] 拒绝越限记录载荷: {} 字节（上限 {}）",
            data_b64.len(),
            wconst::MAX_IPC_PAYLOAD_BYTES
        );
        return Ok(VerthysResponse::err(
            "add_record",
            &format!(
                "记录载荷超过单条上限 {} 字节",
                wconst::MAX_IPC_PAYLOAD_BYTES
            ),
        ));
    }

    let req_str = Zeroizing::new(
        serde_json::to_string(&AddRecordReq {
            op: "add_record",
            rtype,
            name: &name,
            data: &data_b64,
        })
        .map_err(|e| format!("serialize request: {}", e))?,
    );

    let resp_json = state.send(req_str.as_str())?;

    // 发送完成：序列化副本与记录明文原件统一销毁
    drop(req_str);
    drop(data_b64);
    drop(name);

    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 按 ID 读取记录。
#[tauri::command]
pub async fn verthys_get_record(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    id: u64,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "get_record") {
        return Ok(VerthysResponse::err("get_record", &msg));
    }

    let req = serde_json::json!({
        "op": "get_record",
        "id": id,
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 一次性枚举全部记录（自 start_id 开始），适用于记录数较少时。
/// 超时 60 秒，若记录数巨大建议使用流式版本。
///
/// 实现：worker 侧 enumerate_records 受响应行字节预算约束（防单行超限
/// 断开协议），单次调用可能只返回预算内的前缀批次，故此处按游标循环
/// 聚合全部批次后一次性返回，对调用方保持「一次调用拿到全量记录」契约。
#[tauri::command]
pub async fn verthys_enumerate_records(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    start_id: u64,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "enumerate_records") {
        return Ok(VerthysResponse::err("enumerate_records", &msg));
    }

    /// 聚合安全阀：与流式枚举同量级（200 万条），防异常游标导致无限循环
    const ENUM_LOOP_SAFETY_LIMIT: usize = 2_000_000;

    let mut current_id: u64 = if start_id > 0 { start_id } else { 1 };
    let mut all_records: Vec<crate::controller::types::VerthysRecordEntry> = Vec::new();
    let mut exhausted = false;

    while !exhausted {
        let req = serde_json::json!({
            "op": "enumerate_records",
            "id": current_id,
        });
        let resp_json =
            state.send_with_timeout(&req.to_string(), std::time::Duration::from_secs(60))?;
        let resp: VerthysResponse =
            serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;

        if !resp.ok {
            log::warn!(
                "[verthys_enumerate_records] worker 返回失败: {:?}",
                resp.error
            );
            return Ok(resp);
        }

        let batch = resp.records.unwrap_or_default();
        let count = batch.len();
        let last_id = resp.id.unwrap_or(0);
        exhausted = resp.exhausted.unwrap_or(false);
        all_records.extend(batch);

        if count == 0 && !exhausted {
            // 空批次且未标注遍历结束：防御性收敛，避免死循环
            log::warn!("[verthys_enumerate_records] 空批次且未 exhausted，强制终止");
            exhausted = true;
        }
        if last_id > 0 {
            current_id = last_id + 1;
        } else if !exhausted {
            log::warn!("[verthys_enumerate_records] 游标无进展且未 exhausted，强制终止");
            exhausted = true;
        }
        if all_records.len() > ENUM_LOOP_SAFETY_LIMIT {
            log::error!(
                "[verthys_enumerate_records] 超过安全阀 {} 条，强制终止",
                ENUM_LOOP_SAFETY_LIMIT
            );
            break;
        }
    }

    log::info!(
        "[verthys_enumerate_records] 枚举完成: total={}",
        all_records.len()
    );

    Ok(VerthysResponse {
        records: Some(all_records),
        exhausted: Some(true),
        ..VerthysResponse::ok("enumerate_records")
    })
}

/// 流式枚举记录，通过 Tauri Channel 分批次推送，避免一次性序列化大 JSON。
///
/// 适用于数千条以上记录的场景。后端循环调用 worker enumerate_records，
/// 每批最多 batch_size 条，通过 Channel 推送给前端，前端收到即渲染。
/// 返回累计推送总数。
#[tauri::command]
pub async fn verthys_enumerate_records_stream(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    start_id: u64,
    batch_size: u64,
    on_batch: tauri::ipc::Channel<EnumerateBatch>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "enumerate_records_stream") {
        return Ok(VerthysResponse::err("enumerate_records_stream", &msg));
    }

    let batch = if batch_size == 0 {
        200u64
    } else {
        batch_size.min(500)
    };
    let mut current_id: u64 = if start_id > 0 { start_id } else { 1 };
    let mut total_pushed: u64 = 0;
    let mut exhausted = false;

    log::info!(
        "[verthys_enumerate_records_stream] 开始流式枚举: start_id={}, batch_size={}",
        start_id,
        batch
    );

    while !exhausted {
        let req = serde_json::json!({
            "op": "enumerate_records",
            "id": current_id,
            "max_count": batch,
        });
        let resp_json =
            state.send_with_timeout(&req.to_string(), std::time::Duration::from_secs(60))?;
        let resp: VerthysResponse =
            serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;

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
            log::warn!("[verthys_enumerate_records_stream] 空批次且未 exhausted，强制终止");
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
            log::error!("[verthys_enumerate_records_stream] 超过安全阀 200 万条，强制终止");
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

/// 批量删除的单次 IPC 超时：基础 15s + 每千条 2s，上限 300s。
///
/// 删除是单事务提交，耗时随记录数增长但远低于线性；上限用于防止
/// worker 挂死时永久阻塞。前端不设超时，等待本命令的真实结果。
const DELETE_BATCH_BASE_TIMEOUT_SECS: u64 = 15;
const DELETE_BATCH_TIMEOUT_PER_1K: u64 = 2;
const DELETE_BATCH_MAX_TIMEOUT_SECS: u64 = 300;

pub(crate) fn delete_batch_timeout(count: usize) -> std::time::Duration {
    let scaled = DELETE_BATCH_BASE_TIMEOUT_SECS
        .saturating_add((count as u64 / 1000).saturating_mul(DELETE_BATCH_TIMEOUT_PER_1K));
    std::time::Duration::from_secs(scaled.min(DELETE_BATCH_MAX_TIMEOUT_SECS))
}

/// 删除单条记录。
#[tauri::command]
pub async fn verthys_delete_record(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    id: u64,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "delete_record") {
        return Ok(VerthysResponse::err("delete_record", &msg));
    }

    let req = serde_json::json!({
        "op": "delete_record",
        "id": id,
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 批量删除记录，一次性传递 ID 列表，worker 在单次事务内完成删除。
///
/// 级联展开：输入通常是索引记录 ID（照片/文件 meta）。其外置块记录
/// （含瘦身布局的缩略图/块集）由外置块台账按 owner 反查补齐，前端无需
/// 为删除逐条解密 meta。台账不可用时退化为仅删除输入 ID 并记录告警，
/// 不阻断用户删除。
#[tauri::command]
pub async fn verthys_delete_records(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    ids: Vec<u64>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, "delete_records") {
        return Ok(VerthysResponse::err("delete_records", &msg));
    }

    let mut all_ids: Vec<u64> = ids.into_iter().filter(|id| *id != 0).collect();
    all_ids.sort_unstable();
    all_ids.dedup();
    if all_ids.is_empty() {
        return Ok(VerthysResponse::ok("delete_records"));
    }

    /* 级联展开：索引记录 → 其外置块。活跃导入会话的台账在写者内存中，
     * 优先读取会话视图；否则加载磁盘台账（spawn_blocking 隔离同步 IO）。 */
    let mut ledger_for_cleanup: Option<verthys_chunks::ChunkLedger> = None;
    if let Some(vpath) = state.verthys_session_path() {
        let owners: HashSet<u64> = all_ids.iter().copied().collect();
        if state.has_import_session() {
            let guard = state.lock_import_session();
            if let Some(session) = guard.as_ref() {
                all_ids.extend(session.chunk_ledger.chunk_ids_for_owners(&owners));
            }
        } else {
            let load_path = vpath.clone();
            match tauri::async_runtime::spawn_blocking(move || {
                verthys_chunks::load_chunk_ledger(&load_path)
            })
            .await
            {
                Ok(Ok(ledger)) => {
                    all_ids.extend(ledger.chunk_ids_for_owners(&owners));
                    ledger_for_cleanup = Some(ledger);
                }
                Ok(Err(e)) => log::warn!(
                    "[verthys_delete_records] 块台账不可用，仅删除输入记录（外置块可能残留）: {}",
                    e
                ),
                Err(e) => log::warn!(
                    "[verthys_delete_records] 块台账加载任务异常，仅删除输入记录: {}",
                    e
                ),
            }
        }
        all_ids.sort_unstable();
        all_ids.dedup();
    }

    let timeout = delete_batch_timeout(all_ids.len());
    log::info!(
        "[verthys_delete_records] 批量删除 {} 条记录（超时 {}s）",
        all_ids.len(),
        timeout.as_secs()
    );
    let req = serde_json::json!({
        "op": "delete_records",
        "ids": all_ids,
    });
    let resp_json = state.send_with_timeout(&req.to_string(), timeout)?;
    let mut resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    if resp.ok {
        resp.processed_count = Some(all_ids.len() as u64);
        /* 删除成功后收敛台账：移除已删除块条目，避免台账随删除无限增长。
         * 落盘失败不改变删除结论（残留条目只影响后续 GC 判定面）。 */
        if let Some(mut ledger) = ledger_for_cleanup {
            if let Some(vpath) = state.verthys_session_path() {
                let removed = ledger.remove_many(&all_ids);
                if removed > 0 {
                    match tauri::async_runtime::spawn_blocking(move || {
                        verthys_chunks::save_chunk_ledger(&vpath, &ledger)
                    })
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => log::warn!(
                            "[verthys_delete_records] 块台账收敛落盘失败（删除已生效）: {}",
                            e
                        ),
                        Err(e) => log::warn!(
                            "[verthys_delete_records] 块台账收敛任务异常（删除已生效）: {}",
                            e
                        ),
                    }
                }
            }
        }
    }
    Ok(resp)
}

/// 获取当前已加载的轻量摘要记录数（用于 UI 展示）。
#[tauri::command]
pub async fn verthys_get_summary_count(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "get_summary_count") {
        return Ok(VerthysResponse::err("get_summary_count", &msg));
    }

    let req = serde_json::json!({
        "op": "get_summary_count",
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 轻量级检查是否存在指定类型的记录（只扫描摘要索引，不读数据块）。
#[tauri::command]
pub async fn verthys_has_record_by_type(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    rtype: u32,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "has_record_by_type") {
        return Ok(VerthysResponse::err("has_record_by_type", &msg));
    }

    let req = serde_json::json!({
        "op": "has_record_by_type",
        "rtype": rtype,
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

// ===== 导入导出 =====

/// 导出整个容器为加密文件（用新密码加密）。
/// 密码发送后立即擦除。
#[tauri::command]
pub async fn verthys_export(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    export_path: String,
    password: String,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, "export") {
        return Ok(VerthysResponse::err("export", &msg));
    }

    let password = Zeroizing::new(password);

    state
        .authorize_worker_path("export", "write", &export_path)
        .map_err(|e| format!("导出路径未授权: {}", e))?;

    let req_str = Zeroizing::new(
        serde_json::to_string(&PathPasswordReq {
            op: "export",
            path: &export_path,
            password: &password,
        })
        .map_err(|e| format!("serialize request: {}", e))?,
    );

    // 序列化完成即销毁口令原件，仅保留 Zeroizing 序列化副本直至发送
    drop(password);

    let resp_json = state.send(req_str.as_str())?;
    drop(req_str);
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 从加密文件导入容器（用给定密码解密）。
/// 密码发送后立即擦除。
#[tauri::command]
pub async fn verthys_import(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    import_path: String,
    password: String,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, "import") {
        return Ok(VerthysResponse::err("import", &msg));
    }

    let password = Zeroizing::new(password);

    state
        .authorize_worker_path("import", "read", &import_path)
        .map_err(|e| format!("导入路径未授权: {}", e))?;

    let req_str = Zeroizing::new(
        serde_json::to_string(&PathPasswordReq {
            op: "import",
            path: &import_path,
            password: &password,
        })
        .map_err(|e| format!("serialize request: {}", e))?,
    );

    // 序列化完成即销毁口令原件，仅保留 Zeroizing 序列化副本直至发送
    drop(password);

    let resp_json = state.send(req_str.as_str())?;
    drop(req_str);
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

// ===== 动态防护状态查询 =====

/// 查询动态防护实时状态。
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
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/* ------------------------------------------------------------------ *
 * 数据域容器会话闸门测试                                             *
 *                                                                    *
 * AppHandle 依赖 tauri::test 运行时，仅测试纯会话判定策略：           *
 * 无会话拒绝，会话存在放行——闸门代码事实为「判定不通过即写审计并      *
 * 返回 KeyStateMismatch」，会话判定是该判定的唯一变量。               *
 * ------------------------------------------------------------------ */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_access_gate_follows_container_session() {
        let state = AppState::new();
        // 无容器会话（未解锁）：拒绝
        assert!(!state_allows_data_access(&state));

        // 建立容器会话：放行（生命周期保持 NoKey —— 数据域仅依赖
        // 容器解锁，不依赖全局密钥验证状态）
        let path = temp_container_path("gate_session");
        make_container_fixture(&path).unwrap();
        let guard = VerthysSessionGuard::new(path.to_str().unwrap(), "gate-session-test")
            .expect("会话守卫创建失败");
        *state.lock_verthys_session() = Some(guard);
        assert!(state_allows_data_access(&state));

        // 会话销毁（锁定）：拒绝
        *state.lock_verthys_session() = None;
        assert!(!state_allows_data_access(&state));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn data_access_gate_message_is_key_state_mismatch() {
        // 闸门错误文案使用 KeyStateMismatch 的默认消息（文案稳定契约）
        let msg = ErrorCode::KeyStateMismatch.default_message();
        assert_eq!(msg, "密钥状态不匹配");
    }

    #[test]
    fn orphan_lock_cleanup_releases_session_guard_and_file_lock() {
        let state = AppState::new();
        let path = temp_container_path("orphan_lock_cleanup");
        make_container_fixture(&path).unwrap();
        let guard = VerthysSessionGuard::new(path.to_str().unwrap(), "orphan-lock-test")
            .expect("会话守卫创建失败");
        *state.lock_verthys_session() = Some(guard);
        let file_lock = VerthysFileLock::lock_shared(path.to_str().unwrap())
            .expect("文件锁创建失败");
        *state.lock_verthys_file() = Some(file_lock);

        release_orphan_lock_resources(&state);

        assert!(
            state.lock_verthys_session().is_none(),
            "代际冲突且无会话时必须释放哨兵锁"
        );
        assert!(
            state.lock_verthys_file().is_none(),
            "代际冲突且无会话时必须释放旧文件锁"
        );
        let _ = std::fs::remove_file(&path);
    }

    /* ------------------------------------------------------------------ *
     * 容器会话闸门测试辅助                                                *
     *                                                                    *
     * 测试只依赖文件锁与路径，不解析容器内容，因此构造空文件即可。         *
     * ------------------------------------------------------------------ */

    /// 构造空容器文件（供文件锁/会话守卫使用）。
    fn make_container_fixture(path: &std::path::Path) -> std::io::Result<()> {
        std::fs::File::create(path).map(|_| ())
    }

    /// 临时文件路径（进程 id + 用例名隔离，避免并行测试冲突）
    fn temp_container_path(case: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "verthys_vdp_{}_{}_{}.verthys",
            std::process::id(),
            case,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ))
    }

    fn temp_keyfile_case_dir(case: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "verthys_kf_{}_{}_{}",
            std::process::id(),
            case,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("创建临时目录失败");
        dir
    }

    #[test]
    fn keyfile_target_validation_rejects_existing_file() {
        let dir = temp_keyfile_case_dir("exists");
        let vault = dir.join("v.verthys");
        let kf = dir.join("existing.vkf");
        std::fs::write(&kf, b"sentinel-content").expect("写 sentinel 失败");

        let err = validate_keyfile_create_target(
            vault.to_str().unwrap(),
            kf.to_str().unwrap(),
        )
        .expect_err("已存在目标必须被拒绝");
        assert!(err.contains("已存在"), "错误文案应说明目标已存在: {err}");
        assert_eq!(
            std::fs::read(&kf).expect("sentinel 必须仍可读"),
            b"sentinel-content",
            "校验失败不得修改目标文件"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keyfile_target_validation_rejects_wrong_extension() {
        let dir = temp_keyfile_case_dir("ext");
        let vault = dir.join("v.verthys");
        let kf = dir.join("not-a-keyfile.txt");

        let err = validate_keyfile_create_target(
            vault.to_str().unwrap(),
            kf.to_str().unwrap(),
        )
        .expect_err("错误扩展名必须被拒绝");
        assert!(err.contains(".vkf"), "错误文案应说明扩展名: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keyfile_target_validation_rejects_relative_path() {
        let dir = temp_keyfile_case_dir("rel");
        let vault = dir.join("v.verthys");
        let err = validate_keyfile_create_target(vault.to_str().unwrap(), "keys/a.vkf")
            .expect_err("相对路径必须被拒绝");
        assert!(err.contains("绝对路径"), "错误文案应说明绝对路径: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keyfile_target_validation_accepts_absent_vkf() {
        let dir = temp_keyfile_case_dir("absent");
        let vault = dir.join("v.verthys");
        let kf = dir.join("new.vkf");
        validate_keyfile_create_target(vault.to_str().unwrap(), kf.to_str().unwrap())
            .expect("不存在的 .vkf 目标应通过校验");
        assert!(!kf.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keyfile_target_validation_rejects_same_path_as_container() {
        let dir = temp_keyfile_case_dir("same");
        let vault = dir.join("same.vkf");
        let err = validate_keyfile_create_target(
            vault.to_str().unwrap(),
            vault.to_str().unwrap(),
        )
        .expect_err("keyfile 与容器同路径必须被拒绝");
        assert!(err.contains("不能与容器路径相同"), "错误文案不符: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rollback_deletes_keyfile_only_when_created() {
        let dir = temp_keyfile_case_dir("rollback");
        let kf = dir.join("created.vkf");
        std::fs::write(&kf, b"not-created-by-this-flow").expect("写 sentinel 失败");

        cleanup_created_keyfile(Some(kf.to_str().unwrap()), false)
            .expect("未创建时必须为空操作");
        assert_eq!(
            std::fs::read(&kf).expect("文件必须仍在"),
            b"not-created-by-this-flow",
            "keyfile_created=false 时不得删除目标"
        );
        assert!(kf.exists());

        cleanup_created_keyfile(Some(kf.to_str().unwrap()), true)
            .expect("本次创建的文件必须可删除");
        assert!(!kf.exists(), "keyfile_created=true 时应删除本次产物");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /* ===== 机器密钥材料目录策略 ===== */

    fn unique_key_material_dir(tag: &str) -> std::path::PathBuf {
        let mut buf = [0u8; 8];
        let _ = getrandom::getrandom(&mut buf);
        let suffix: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
        std::env::temp_dir().join(format!("verthys_keymat_{}_{}", tag, suffix))
    }

    #[test]
    fn container_password_existing_only_returns_none_without_generating() {
        let root = unique_key_material_dir("existing_none");
        let primary = root.join("primary");
        let legacy = root.join("legacy");

        let result = load_container_password_from_dirs(&primary, Some(&legacy), false)
            .expect("缺失应返回 None 而非错误");
        assert!(result.is_none());
        assert!(
            !crate::util::container_secret::exists(&primary),
            "只读策略不得生成新密钥材料"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn container_password_create_generates_at_primary() {
        let root = unique_key_material_dir("create");
        let primary = root.join("primary");

        let created = load_container_password_from_dirs(&primary, None, true)
            .expect("创建策略应成功")
            .expect("创建策略应生成密钥材料");
        assert!(crate::util::container_secret::exists(&primary));
        let loaded = crate::util::container_secret::load_existing(&primary)
            .expect("读取应成功")
            .expect("主位置应有值");
        assert_eq!(loaded.as_str(), created.as_str());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn container_password_migrates_legacy_and_keeps_source() {
        let root = unique_key_material_dir("migrate");
        let primary = root.join("primary");
        let legacy = root.join("legacy");
        let original = crate::util::container_secret::load_or_create(&legacy)
            .expect("旧位置生成应成功");

        let migrated = load_container_password_from_dirs(&primary, Some(&legacy), false)
            .expect("迁移应成功")
            .expect("迁移后应返回值");
        assert_eq!(migrated.as_str(), original.as_str());
        assert!(crate::util::container_secret::exists(&primary));
        assert!(
            crate::util::container_secret::exists(&legacy),
            "迁移不得删除旧位置副本"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn container_password_restores_corrupt_primary_from_legacy() {
        let root = unique_key_material_dir("restore");
        let primary = root.join("primary");
        let legacy = root.join("legacy");
        let original = crate::util::container_secret::load_or_create(&legacy)
            .expect("旧位置生成应成功");
        std::fs::create_dir_all(&primary).expect("主位置目录应可创建");
        std::fs::write(primary.join("container.secret"), b"corrupted")
            .expect("写入损坏副本应成功");

        let restored = load_container_password_from_dirs(&primary, Some(&legacy), false)
            .expect("主位置损坏时应由旧位置恢复")
            .expect("恢复后应返回值");
        assert_eq!(restored.as_str(), original.as_str());
        let after = crate::util::container_secret::load_existing(&primary)
            .expect("读取应成功")
            .expect("主位置应有值");
        assert_eq!(after.as_str(), original.as_str());
        let _ = std::fs::remove_dir_all(&root);
    }
}
