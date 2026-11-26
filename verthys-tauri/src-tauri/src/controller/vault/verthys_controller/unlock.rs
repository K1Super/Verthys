/*
 * 口令 / keyfile 解锁
 *
 * 职责边界：解锁的完整编排——熔断闸门、文件存在性、本机口令材料、读锁、
 * 受信档位与介质绑定守卫、路径授权、worker 解锁、会话守卫与状态文件维护。
 * 恢复码通道复用命令入口，转交 recovery 子模块。
 */

use super::*;
use crate::controller::types::VerthysResponse;
use crate::infrastructure::file_lock::VerthysFileLock;
use crate::repository::verthys_state::{read_state_file, write_state_file_atomic, VerthysState};
use crate::state::verthys_session::VerthysSessionGuard;
use crate::state::AppState;
use crate::util::audit_log::{keyfile_path_tag, AuditEventType, AuditResult};
use crate::util::path::{normalize_path, sanitize_path};
use tauri::State;
use zeroize::Zeroizing;
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
                /* 会话守卫是数据域可用的唯一凭据：创建失败必须 fail-closed，
                 * 销毁 worker 并返回错误，禁止把“worker 已解锁但主进程无会话”
                 * 的半完成状态伪装成解锁成功。 */
                state.set_session(None);
                return Ok(VerthysResponse::err(
                    "unlock",
                    "解锁会话建立失败，请重试",
                ));
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
