/*
 * 恢复码解锁与恢复码轮换
 *
 * 职责边界：恢复码是一次性高熵凭证；恢复解锁不读取本机口令、不计入口令
 * 熔断，但文件锁、路径授权、会话守卫与状态文件维护必须与口令解锁一致，
 * 防止恢复路径成为绕过单写者约束的后门。
 */

use super::*;
use crate::controller::types::VerthysResponse;
use crate::infrastructure::file_lock::VerthysFileLock;
use crate::repository::verthys_state::{read_state_file, write_state_file_atomic, VerthysState};
use crate::state::verthys_session::VerthysSessionGuard;
use crate::state::AppState;
use crate::util::audit_log::{AuditEventType, AuditResult};
use crate::util::path::{normalize_path, sanitize_path};
use tauri::State;
use zeroize::Zeroizing;
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

    /* 恢复通道与口令通道共用同一安全档位应用：档位失败必须 fail-closed，
     * 否则恢复解锁会在无运行时防护档的情况下打开容器。 */
    crate::service::preset_source::apply_persisted_preset_before_unlock(&app, &verthys_path)?;

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
    let mut resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("恢复解锁失败（响应解析失败）: {}", e))?;
    resp.adopt_worker_error_code();

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

    /* 与口令解锁一致：产品层 global-key 记录决定
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
            state.set_session(None);
            return Ok(VerthysResponse::err(
                "v4_unlock_recovery",
                "恢复会话建立失败，请重试",
            ));
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
