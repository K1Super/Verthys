/*
 * 新库创建
 *
 * 职责边界：create → lock（落盘并释放 worker 容器句柄）→ 主进程哨兵锁 →
 * unlock 自检的完整编排。任何步骤失败都回滚本次产物；keyfile 仅在确认由
 * 本次流程创建时才删除。锁序红线：哨兵锁必须在 worker 释放句柄之后获取。
 */

use super::*;
use crate::controller::types::VerthysResponse;
use crate::infrastructure::file_lock::VerthysFileLock;
use crate::repository::container_layout;
use crate::repository::verthys_state::{delete_state_file, write_state_file_atomic, VerthysState};
use crate::state::verthys_session::VerthysSessionGuard;
use crate::state::AppState;
use crate::util::audit_log::{keyfile_path_tag, AuditEventType, AuditResult};
use crate::util::path::sanitize_path;
use tauri::State;
use zeroize::Zeroizing;
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
    /* 容器文件同样只在 v4_create 明确成功后视为本次产物：预检通过到
     * v4_create 之间同路径可能被其它进程创建，失败回滚不得删除它。 */
    let mut container_created = false;

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
        container_created = true;
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
        if container_created {
            let _ = std::fs::remove_file(&path_for_rollback);
        }
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
    // 否则 verthys_derive_and_store_global_key（要求 NoKey）会因状态不匹配而失败。
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
                    "[verthys_create] VerthysSessionGuard 创建失败: {}",
                    e
                );
                write_verthys_audit(
                    &app,
                    AuditEventType::VerthysUnlock,
                    &path_for_rollback,
                    AuditResult::Failure,
                    Some(format!("VerthysSessionGuard 创建失败: {}", e)),
                );
                state.set_session(None);
                return Ok(VerthysResponse::err(
                    "create",
                    "创建成功但会话建立失败，请重新打开该库",
                ));
            }
        }
    }

    create_result
}
