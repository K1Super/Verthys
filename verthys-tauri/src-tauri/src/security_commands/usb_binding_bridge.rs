/*
 * security_commands/usb_binding_bridge.rs — 可移动介质绑定的解锁期接入实现
 *
 * 职责：
 *   为解锁流程提供介质绑定守卫（解锁前判定 + 解锁后登记/重绑定）：
 *     - 解锁前：解析容器所在卷；仅可移动介质（盘符挂载点 + 非空卷标）参与
 *       绑定判定；读加盐序列号哈希与注册表既有记录比对，按服务层契约判定
 *       动作；克隆嫌疑且未确认重绑定时返回 Err（fail-closed，中止解锁）。
 *     - 解锁后：按动作登记（首次使用）或改写绑定记录（重绑定），
 *       DPAPI 持久化 + 审计；失败只审计，不影响已完成的解锁。
 *
 * 档位门控：由应用侧门控位的 USB_CLONE_DETECT 位控制；关闭档位
 * （性能档 / 自定义关闭）或门控不可用时该硬化层不启用。
 *
 * 失败可见：判定输入不可得、登记失败、克隆嫌疑均写审计；克隆嫌疑同时
 * 以明确错误码返回给前端（E_USB_CLONE_SUSPECTED）。
 *
 * 依赖反转落地：service 层只声明契约，本模块提供实现；控制器经 service
 * 调用，杜绝 controller → security_commands 的反向依赖（分层红线）。
 */

use tauri::{AppHandle, Manager};

use crate::security::app_feature_gate::{self, FEAT_USB_CLONE_DETECT};
use crate::security::usb_guard::{read_device_serial, resolve_volume_for_path, VolumeInfo};
use crate::service::usb_binding::{self, UsbBindAction};
use crate::util::audit_log::{AuditEventType, AuditResult};

use super::audit::write_security_audit;
use super::persistence::{ensure_usb_registry_loaded, ensure_usb_salt, persist_usb_registry};
use super::responses::UsbVolumeStatus;
use super::state::{lock_usb_registry_or_recover, SecurityState};

/// 注册介质绑定实现到服务层契约（应用启动阶段调用一次）
pub(crate) fn install_usb_binding() {
    usb_binding::install(pre_unlock_guard_impl, post_unlock_commit_impl);
}

/// 审计主题：路径脱敏（避免审计日志写入完整用户路径）
fn path_subject(path: &str) -> String {
    crate::util::path::sanitize_path(path)
}

/// 解析容器所在卷的绑定输入（卷信息 + 加盐序列号哈希）。
///
/// `require_gate = true` 时先检查档位门控位（解锁期守卫路径）；
/// 显式注册/重绑定命令传 false（用户显式动作不受档位限制）。
/// 返回 Ok(None) 表示不适用：门控关闭 / 判定不可得 / 固定盘 / 空卷标。
pub(crate) fn resolve_volume_hash(
    app: &AppHandle,
    verthys_path: &str,
    require_gate: bool,
) -> Result<Option<(VolumeInfo, String)>, String> {
    if require_gate && !app_feature_gate::enabled(FEAT_USB_CLONE_DETECT) {
        return Ok(None);
    }
    let info = match resolve_volume_for_path(verthys_path)? {
        Some(i) => i,
        None => return Ok(None),
    };
    // 固定盘与空卷标不参与绑定判定（绑定键为卷标，空键无法形成稳定绑定）
    if !info.removable || info.volume_label.is_empty() {
        return Ok(None);
    }
    let state = app.state::<SecurityState>();
    let salt = ensure_usb_salt(app, &state)?;
    let hash = read_device_serial(info.drive_letter, &salt)?;
    Ok(Some((info, hash)))
}

/// 检测介质绑定状态（检测命令支撑；含审计）。
///
/// 永不阻断：仅报告结论。克隆嫌疑与首次使用分别写审计留痕。
pub(crate) fn inspect_binding(app: &AppHandle, verthys_path: &str) -> UsbVolumeStatus {
    let state = app.state::<SecurityState>();
    let enabled = app_feature_gate::enabled(FEAT_USB_CLONE_DETECT);

    let resolved = resolve_volume_hash(app, verthys_path, false);
    let (info, hash) = match resolved {
        Ok(Some(v)) => v,
        Ok(None) => {
            return UsbVolumeStatus {
                applicable: false,
                drive_letter: String::new(),
                volume_label: String::new(),
                registered: false,
                verdict: if enabled { "not_applicable" } else { "disabled_by_preset" }.into(),
                enabled_by_preset: enabled,
            };
        }
        Err(e) => {
            write_security_audit(
                app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Failure,
                Some(path_subject(verthys_path).as_str()),
                Some(format!("介质绑定检测输入不可得: {}", e)),
            );
            return UsbVolumeStatus {
                applicable: false,
                drive_letter: String::new(),
                volume_label: String::new(),
                registered: false,
                verdict: "undetermined".into(),
                enabled_by_preset: enabled,
            };
        }
    };

    ensure_usb_registry_loaded(app, &state);
    let registered_hash = lock_usb_registry_or_recover(&state)
        .ok()
        .and_then(|guard| guard.known_hash(&info.volume_label));

    let registered = registered_hash.is_some();
    let verdict = match registered_hash.as_deref() {
        None => "first_use",
        Some(known) => {
            if crate::util::crypto::ct_eq(known.as_bytes(), hash.as_bytes()) {
                "trusted"
            } else {
                "clone_suspected"
            }
        }
    };

    let (result, detail) = match verdict {
        "trusted" => (AuditResult::Success, "介质绑定检测通过（卷标 + 序列号哈希匹配）"),
        "clone_suspected" => (AuditResult::Denied, "介质绑定检测：克隆嫌疑（序列号哈希不匹配）"),
        _ => (AuditResult::Success, "介质绑定检测：首次使用（尚未登记）"),
    };
    write_security_audit(
        app,
        &state,
        AuditEventType::DeviceBind,
        result,
        Some(&info.volume_label),
        Some(detail.into()),
    );

    UsbVolumeStatus {
        applicable: true,
        drive_letter: info.drive_letter.to_string(),
        volume_label: info.volume_label,
        registered,
        verdict: verdict.into(),
        enabled_by_preset: enabled,
    }
}

/// 解锁前介质绑定守卫实现（服务层契约实现）。
fn pre_unlock_guard_impl(
    app: &AppHandle,
    verthys_path: &str,
    allow_rebind: bool,
) -> Result<UsbBindAction, String> {
    let state = app.state::<SecurityState>();

    let (info, hash) = match resolve_volume_hash(app, verthys_path, true) {
        Ok(Some(v)) => v,
        // 不适用（关闭档位 / 固定盘 / 判定不可得）：放行，不制造数据不可达
        Ok(None) => return Ok(UsbBindAction::None),
        Err(e) => {
            log::warn!("[usb_binding] 介质判定输入不可得，本次未启用绑定校验: {}", e);
            write_security_audit(
                app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Failure,
                Some(path_subject(verthys_path).as_str()),
                Some(format!("介质判定输入不可得，本次未启用绑定校验: {}", e)),
            );
            return Ok(UsbBindAction::None);
        }
    };

    ensure_usb_registry_loaded(app, &state);
    let registered_hash = lock_usb_registry_or_recover(&state)?.known_hash(&info.volume_label);

    let action = usb_binding::decide_bind_action(registered_hash.as_deref(), &hash, allow_rebind);

    match &action {
        Ok(UsbBindAction::None) => {
            write_security_audit(
                app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Success,
                Some(&info.volume_label),
                Some("介质绑定校验通过（卷标 + 序列号哈希匹配）".into()),
            );
        }
        Ok(UsbBindAction::Register) => {
            write_security_audit(
                app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Success,
                Some(&info.volume_label),
                Some("介质首次使用：待解锁成功后登记绑定".into()),
            );
        }
        Ok(UsbBindAction::Rebind) => {
            write_security_audit(
                app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Failure,
                Some(&info.volume_label),
                Some("介质标识变化且用户已确认重绑定：待凭据验证通过后改写登记".into()),
            );
        }
        Err(e) => {
            log::warn!(
                "[usb_binding] 克隆嫌疑，阻止解锁: label={}",
                info.volume_label
            );
            write_security_audit(
                app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Denied,
                Some(&info.volume_label),
                Some(format!("克隆嫌疑阻止解锁: {}", e)),
            );
        }
    }

    action
}

/// 解锁成功后落实绑定动作（服务层契约实现）。失败只审计，不阻断已完成的解锁。
fn post_unlock_commit_impl(app: &AppHandle, verthys_path: &str, action: UsbBindAction) {
    if action == UsbBindAction::None {
        return;
    }
    let state = app.state::<SecurityState>();

    let (info, hash) = match resolve_volume_hash(app, verthys_path, false) {
        Ok(Some(v)) => v,
        Ok(None) => {
            write_security_audit(
                app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Failure,
                Some(path_subject(verthys_path).as_str()),
                Some("介质绑定登记未落实：判定输入不适用".into()),
            );
            return;
        }
        Err(e) => {
            write_security_audit(
                app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Failure,
                Some(path_subject(verthys_path).as_str()),
                Some(format!("介质绑定登记未落实：{}", e)),
            );
            return;
        }
    };

    ensure_usb_registry_loaded(app, &state);
    {
        let mut guard = match lock_usb_registry_or_recover(&state) {
            Ok(g) => g,
            Err(e) => {
                write_security_audit(
                    app,
                    &state,
                    AuditEventType::DeviceBind,
                    AuditResult::Failure,
                    Some(&info.volume_label),
                    Some(format!("介质绑定登记未落实（注册表不可用）: {}", e)),
                );
                return;
            }
        };
        if let Err(e) = guard.register_device(&info.volume_label, &hash) {
            write_security_audit(
                app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Failure,
                Some(&info.volume_label),
                Some(format!("介质绑定登记未落实（注册表容量限制）: {}", e)),
            );
            return;
        }
        persist_usb_registry(app, &guard);
    }

    let detail = match action {
        UsbBindAction::Register => "介质首次登记完成（凭据验证通过后）",
        UsbBindAction::Rebind => "介质绑定已改写（标识变化经凭据验证确认）",
        UsbBindAction::None => return,
    };
    write_security_audit(
        app,
        &state,
        AuditEventType::DeviceBind,
        AuditResult::Success,
        Some(&info.volume_label),
        Some(detail.into()),
    );
    log::info!(
        "[usb_binding] 绑定动作已落实: {:?} label={}",
        action,
        info.volume_label
    );
}