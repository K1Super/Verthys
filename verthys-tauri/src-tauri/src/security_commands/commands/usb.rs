/*
 * commands/usb.rs — USB 安全命令
 *
 *
 * 职责：
 *   USB 安全 Tauri 命令实现：
 *     - security_usb_read_serial：读取 USB 设备序列号（加盐 HMAC-SHA256）
 *     - security_usb_register_device：注册已知 USB 设备（需已解锁会话 + 容量限制）
 *     - security_usb_check_clone：检测克隆外设
 *     - security_usb_volume_status：检测容器所在介质的绑定状态
 *     - security_usb_register_current：登记当前容器所在的可移动介质（需已解锁会话）
 *     - security_usb_rebind_device：重新绑定介质（需已解锁会话）
 *     - security_usb_shadow_sleep：进入影子休眠（加密索引驻留内存）
 *     - security_usb_try_recover：尝试从影子休眠恢复加密索引
 *     - security_usb_purge：清除影子休眠中的加密索引
 *     - security_usb_shadow_status：查询影子休眠状态（返回真实 txid）
 */

use base64::{engine::general_purpose::STANDARD, Engine as _};
use tauri::State;

use crate::security::usb_guard::{read_device_serial, CloneCheckResult};
use crate::util::audit_log::{AuditEventType, AuditResult};

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::auth::require_session_authorized;
use crate::security_commands::persistence::{
    ensure_usb_registry_loaded, ensure_usb_salt, persist_usb_registry,
};
use crate::security_commands::responses::{SecurityResult, ShadowSleepStatus, UsbVolumeStatus};
use crate::security_commands::state::{
    lock_shadow_sleep_or_recover, lock_usb_registry_or_recover, SecurityState,
};

/* ====================================================================== *
 *  6. USB 安全命令                      *
 * ====================================================================== */

/// 读取 USB 设备序列号（通过 IOCTL_STORAGE_QUERY_PROPERTY）
/// drive_letter: 盘符（如 'E'）
///
/// 使用加盐 HMAC-SHA256 哈希序列号
/// 盐值由 DPAPI 加密存储于应用配置目录，安装时随机生成
#[tauri::command]
pub fn security_usb_read_serial(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    drive_letter: String,
) -> Result<String, String> {
    let ch = drive_letter.chars().next().ok_or("盘符为空")?;

    // 获取 USB 盐值（首次访问时从持久化加载或生成）
    let salt = ensure_usb_salt(&app, &state).map_err(|e| {
        log::error!("[security_usb_read_serial] 获取 USB 盐值失败: {}", e);
        e
    })?;

    let serial = read_device_serial(ch, &salt).map_err(|e| {
        log::error!("[security_usb_read_serial] 读取失败: {}", e);
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Failure,
            Some(&drive_letter),
            Some(format!("USB 序列号读取失败: {}", e)),
        );
        e
    })?;

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        Some(&drive_letter),
        Some("USB 序列号已读取（加盐 HMAC-SHA256）".into()),
    );

    Ok(serial)
}

/// 注册已知 USB 设备（卷标 + 序列号哈希）
///
/// 授权：需已解锁的会话（密钥生命周期为 Locked 或 Unlocked）。
/// 注册表容量限制（100 条），超限拒绝；注册后自动 DPAPI 加密
/// 持久化，形成不可篡改的安全基线。
#[tauri::command]
pub fn security_usb_register_device(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    app_state: State<'_, crate::state::AppState>,
    volume_label: String,
    serial_hash: String,
) -> Result<SecurityResult, String> {
    // 授权检查：注册设备需已解锁的会话
    if let Err(msg) = require_session_authorized(&app_state) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::DeviceBind,
            AuditResult::Denied,
            Some(&volume_label),
            Some(format!("PERMISSION_DENIED: register_device {}", msg)),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "注册 USB 设备需要已解锁的会话",
        ));
    }

    // 确保注册表已从持久化加载
    ensure_usb_registry_loaded(&app, &state);

    {
        let mut guard = lock_usb_registry_or_recover(&state)?;
        match guard.register_device(&volume_label, &serial_hash) {
            Ok(()) => {
                // 注册后 DPAPI 加密持久化
                persist_usb_registry(&app, &guard);
            }
            Err(e) => {
                // 容量限制
                write_security_audit(
                    &app,
                    &state,
                    AuditEventType::DeviceBind,
                    AuditResult::Failure,
                    Some(&volume_label),
                    Some(format!("USB 注册表已达上限: {}", e)),
                );
                return Ok(SecurityResult::error("CAPACITY_LIMIT", e));
            }
        }
    }

    write_security_audit(
        &app,
        &state,
        AuditEventType::DeviceBind,
        AuditResult::Success,
        Some(&volume_label),
        Some("USB 设备已注册（管理员授权 + DPAPI 持久化）".into()),
    );

    log::info!(
        "[security_usb_register_device] 设备已注册: label={}",
        volume_label
    );
    Ok(SecurityResult::success("USB 设备已注册并持久化"))
}

/// 检测克隆外设
///
/// 废除"首次自动注册"逻辑
///   - Trusted：卷标已知且序列号哈希匹配 → 合法设备
///   - Clone：卷标已知但序列号哈希不匹配 → 克隆外设
///   - Unknown：卷标未知 → 未注册设备，拒绝访问并触发审计事件
#[tauri::command]
pub fn security_usb_check_clone(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    volume_label: String,
    serial_hash: String,
) -> Result<CloneCheckResult, String> {
    // 确保注册表已从持久化加载
    ensure_usb_registry_loaded(&app, &state);

    let result = {
        let guard = lock_usb_registry_or_recover(&state)?;
        guard.check_clone(&volume_label, &serial_hash)
    };

    match result {
        CloneCheckResult::Trusted => {
            write_security_audit(
                &app,
                &state,
                AuditEventType::SecurityCommand,
                AuditResult::Success,
                Some(&volume_label),
                Some("USB 设备验证通过".into()),
            );
        }
        CloneCheckResult::Clone => {
            log::warn!(
                "[security_usb_check_clone] 检测到克隆外设: label={}",
                volume_label
            );
            write_security_audit(
                &app,
                &state,
                AuditEventType::SecurityCommand,
                AuditResult::Failure,
                Some(&volume_label),
                Some("检测到克隆外设（序列号不匹配）".into()),
            );
        }
        CloneCheckResult::Unknown => {
            // 未注册设备一律拒绝并触发审计事件
            log::warn!(
                "[security_usb_check_clone] 未注册设备被拒绝: label={}",
                volume_label
            );
            write_security_audit(
                &app,
                &state,
                AuditEventType::SecurityCommand,
                AuditResult::Denied,
                Some(&volume_label),
                Some("未注册的 USB 设备被拒绝访问".into()),
            );
        }
    }

    Ok(result)
}

/// 检测容器所在介质的绑定状态（检测命令）
///
/// 永不阻断：仅报告结论并写审计留痕（克隆嫌疑 → Denied 审计）。
/// verdict 取值：trusted / clone_suspected / first_use / not_applicable /
/// disabled_by_preset / undetermined
#[tauri::command]
pub fn security_usb_volume_status(
    app: tauri::AppHandle,
    verthys_path: String,
) -> Result<UsbVolumeStatus, String> {
    Ok(crate::security_commands::usb_binding_bridge::inspect_binding(
        &app,
        &verthys_path,
    ))
}

/// 登记当前容器所在的可移动介质（登记命令；需已解锁会话）
///
/// 解析容器路径 → 卷信息 → 加盐序列号哈希 → 登记并 DPAPI 持久化。
/// 固定盘 / 非盘符挂载点 / 空卷标 → NOT_APPLICABLE（无需登记）。
#[tauri::command]
pub fn security_usb_register_current(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    app_state: State<'_, crate::state::AppState>,
    verthys_path: String,
) -> Result<SecurityResult, String> {
    if let Err(msg) = require_session_authorized(&app_state) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::DeviceBind,
            AuditResult::Denied,
            Some(&verthys_path),
            Some(format!("PERMISSION_DENIED: register_current {}", msg)),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "登记介质需要已解锁的会话",
        ));
    }

    let resolved =
        crate::security_commands::usb_binding_bridge::resolve_volume_hash(&app, &verthys_path, false)?;
    let (info, hash) = match resolved {
        Some(v) => v,
        None => {
            write_security_audit(
                &app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Denied,
                Some(&verthys_path),
                Some("登记被拒绝：容器不在可移动介质（盘符挂载点）上".into()),
            );
            return Ok(SecurityResult::error(
                "NOT_APPLICABLE",
                "当前容器不在可移动介质（盘符挂载点）上，无需登记",
            ));
        }
    };

    ensure_usb_registry_loaded(&app, &state);
    {
        let mut guard = lock_usb_registry_or_recover(&state)?;
        if let Err(e) = guard.register_device(&info.volume_label, &hash) {
            write_security_audit(
                &app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Failure,
                Some(&info.volume_label),
                Some(format!("介质登记失败（注册表容量限制）: {}", e)),
            );
            return Ok(SecurityResult::error("CAPACITY_LIMIT", e));
        }
        persist_usb_registry(&app, &guard);
    }

    write_security_audit(
        &app,
        &state,
        AuditEventType::DeviceBind,
        AuditResult::Success,
        Some(&info.volume_label),
        Some("介质已登记（卷标 + 加盐序列号哈希，DPAPI 持久化）".into()),
    );
    log::info!(
        "[security_usb_register_current] 介质已登记: label={} drive={}",
        info.volume_label,
        info.drive_letter
    );
    Ok(SecurityResult::success("介质已登记并持久化"))
}

/// 重新绑定介质（重绑定命令；需已解锁会话）
///
/// 语义：改写既有登记记录（卷标已登记为前提），用于介质标识变化后的
/// 维护性替换。解锁期的重绑定由解锁命令的确认参数自动完成（凭据验证
/// 通过后落实），不依赖本命令。
#[tauri::command]
pub fn security_usb_rebind_device(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    app_state: State<'_, crate::state::AppState>,
    volume_label: String,
    serial_hash: String,
) -> Result<SecurityResult, String> {
    if let Err(msg) = require_session_authorized(&app_state) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::DeviceBind,
            AuditResult::Denied,
            Some(&volume_label),
            Some(format!("PERMISSION_DENIED: rebind_device {}", msg)),
        );
        return Ok(SecurityResult::error(
            "PERMISSION_DENIED",
            "重新绑定介质需要已解锁的会话",
        ));
    }
    if volume_label.trim().is_empty() || serial_hash.trim().is_empty() {
        write_security_audit(
            &app,
            &state,
            AuditEventType::DeviceBind,
            AuditResult::Denied,
            Some(&volume_label),
            Some("重绑定被拒绝：卷标或序列号哈希为空".into()),
        );
        return Ok(SecurityResult::error(
            "INVALID_INPUT",
            "卷标与序列号哈希不得为空",
        ));
    }

    ensure_usb_registry_loaded(&app, &state);
    {
        let mut guard = lock_usb_registry_or_recover(&state)?;
        if !guard.is_registered(&volume_label) {
            write_security_audit(
                &app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Denied,
                Some(&volume_label),
                Some("重绑定被拒绝：该卷标尚未登记".into()),
            );
            return Ok(SecurityResult::error(
                "NOT_REGISTERED",
                "该卷标尚未登记，无法重绑定（请先登记该介质）",
            ));
        }
        if let Err(e) = guard.register_device(&volume_label, &serial_hash) {
            write_security_audit(
                &app,
                &state,
                AuditEventType::DeviceBind,
                AuditResult::Failure,
                Some(&volume_label),
                Some(format!("重绑定失败: {}", e)),
            );
            return Ok(SecurityResult::error("CAPACITY_LIMIT", e));
        }
        persist_usb_registry(&app, &guard);
    }

    write_security_audit(
        &app,
        &state,
        AuditEventType::DeviceBind,
        AuditResult::Success,
        Some(&volume_label),
        Some("介质绑定已改写（重绑定）".into()),
    );
    log::info!(
        "[security_usb_rebind_device] 介质绑定已改写: label={}",
        volume_label
    );
    Ok(SecurityResult::success("介质绑定已改写"))
}

/// 进入影子休眠（外设拔出后加密索引驻留内存）
///
/// encrypted_index_b64: 加密的内存索引快照（base64）
/// txid: 事务 ID（恢复时需匹配）
/// timeout_min: 休眠超时（分钟），超时自动 purge
///
/// 加密索引使用 SecuredBuffer（Zeroizing）封装
/// 内部自动定时器到期自动 purge
/// 使用 base64 crate 替换自编 base64_decode
/// txid 由后端生成真实值（非硬编码 0）
#[tauri::command]
pub fn security_usb_shadow_sleep(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    encrypted_index_b64: String,
    txid: u64,
    timeout_min: u64,
) -> Result<(), String> {
    // 使用 base64 crate 解码
    // 解码后的数据由 ShadowSleep 内部 SecuredBuffer 保护
    let index_bytes = STANDARD
        .decode(&encrypted_index_b64)
        .map_err(|e| format!("Base64 解码失败: {}", e))?;

    {
        let mut guard = lock_shadow_sleep_or_recover(&state)?;
        // enter_shadow_sleep 内部将 index_bytes 封装到 SecuredBuffer 中
        guard.enter_shadow_sleep(index_bytes, txid, timeout_min);
    }

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        None,
        Some(format!(
            "已进入影子休眠: txid={}, timeout={}min（SecuredBuffer + 自动定时器）",
            txid, timeout_min
        )),
    );

    log::info!(
        "[security_usb_shadow_sleep] 已进入影子休眠: txid={}, timeout={}min",
        txid,
        timeout_min
    );
    Ok(())
}

/// 尝试从影子休眠恢复加密索引
///
/// 返回 base64 编码的加密索引，若恢复失败返回 null
///
/// 恢复的数据使用 Zeroizing 包装，编码后自动擦除
/// 使用 base64 crate 替换自编 base64_encode
#[tauri::command]
pub fn security_usb_try_recover(
    app: tauri::AppHandle,
    state: State<SecurityState>,
    txid: u64,
) -> Result<Option<String>, String> {
    let result = {
        let mut guard = lock_shadow_sleep_or_recover(&state)?;
        guard.try_recover(txid)
    };

    if let Some(index) = result {
        // 使用 Zeroizing 包装恢复的数据，编码后自动擦除
        let secured_index = zeroize::Zeroizing::new(index);
        // 使用 base64 crate 编码
        let encoded = STANDARD.encode(secured_index.as_slice());

        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Success,
            None,
            Some(format!("影子休眠恢复成功: txid={}", txid)),
        );

        log::info!("[security_usb_try_recover] 恢复成功: txid={}", txid);
        Ok(Some(encoded))
    } else {
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Failure,
            None,
            Some(format!("影子休眠恢复失败: txid={}", txid)),
        );

        log::warn!("[security_usb_try_recover] 恢复失败: txid={}", txid);
        Ok(None)
    }
}

/// 清除影子休眠中的加密索引
///
/// 使用 SecuredBuffer（Zeroizing），Drop 时自动 zeroize
/// 移除手动 volatile 覆写循环，消除 take() 与覆写之间的窗口期
#[tauri::command]
pub fn security_usb_purge(
    app: tauri::AppHandle,
    state: State<SecurityState>,
) -> Result<(), String> {
    {
        let mut guard = lock_shadow_sleep_or_recover(&state)?;
        guard.purge();
    }

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        None,
        Some("影子休眠索引已清除".into()),
    );

    log::info!("[security_usb_purge] 影子休眠索引已清除");
    Ok(())
}

/// 查询影子休眠状态
///
/// 修复：返回真实 txid（原硬编码为 0）
#[tauri::command]
pub fn security_usb_shadow_status(
    state: State<SecurityState>,
) -> Result<ShadowSleepStatus, String> {
    let guard = lock_shadow_sleep_or_recover(&state)?;
    Ok(ShadowSleepStatus {
        in_shadow_sleep: guard.is_in_shadow_sleep(),
        // 返回真实 txid（修复原硬编码 0）
        txid: guard.current_txid(),
    })
}
