/*
 * @file controller/device_controller.rs
 * @brief 设备机器码绑定与校验控制器
 *
 * 本模块提供设备指纹采集、设备绑定及校验功能，用于将软件实例与特定硬件设备绑定，
 * 防止未授权迁移。绑定数据经 DPAPI 加密存储于状态文件，实现离机失效。
 *
 * =============================================================================
 * 核心能力
 * =============================================================================
 * - 设备指纹采集：通过 Win32 API 获取 CPU、主板、磁盘标识，组合生成 SHA-256 指纹。
 * - 设备绑定：将设备组件序列化后经 DPAPI 加密，存储于状态文件，支持首次绑定和重新绑定。
 * - 设备校验：解密存储的组件，与当前设备进行权重匹配（CPU 25%、主板 35%、磁盘 40%），
 *   匹配度 ≥80% 视为部分匹配，允许有限恢复；低于阈值视为不匹配。
 * - 状态管理：状态文件缺失时返回未绑定状态；支持从旧版明文指纹向后兼容。
 * - 异步超时与熔断：指纹采集使用 spawn_blocking + 2 秒超时，避免阻塞主线程。
 * - 审计日志：绑定、重新绑定、校验失败等事件记录于防篡改审计日志。
 *
 * =============================================================================
 * 安全约束
 * =============================================================================
 * - DPAPI 加密确保绑定数据仅能在本机解密，状态文件复制到其他机器即失效。
 * - 权重匹配策略容忍部分硬件变更（如更换硬盘），阈值 80% 防止过度敏感。
 * - 重新绑定需记录审计事件，便于追溯。
 * - 错误信息脱敏，不泄露硬件具体标识。
 *
 * =============================================================================
 * 依赖方向
 * =============================================================================
 * controller → infrastructure::device_fingerprint / repository::verthys_state /
 *             util::crypto / util::audit_log / controller::types / controller::api_error
 */

use crate::controller::api_error::ErrorCode;
use crate::controller::types::{DeviceBindingResult, DeviceBindingStatus};
use crate::infrastructure::device_fingerprint::{
    calculate_match_score, get_device_components, DeviceComponents,
    MATCH_THRESHOLD_PERCENT,
};
use crate::repository::verthys_state::{
    read_state_file, write_state_file_atomic, VerthysState,
};
use crate::util::audit_log::{append_audit, AuditEvent, AuditEventType, AuditResult};
use crate::util::base64::{base64_decode, base64_encode};
use crate::util::crypto::dpapi_protect;
use std::time::Duration;
use tauri::State;

/// 设备指纹采集超时（2 秒），防止硬件 API 挂起。
const FINGERPRINT_TIMEOUT: Duration = Duration::from_secs(2);

// ===== 审计日志辅助 =====

/// 获取审计日志文件路径。
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

/// 从设备指纹派生审计 HMAC 密钥，用于审计日志防篡改。
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

/// 写入设备绑定相关审计事件。
fn write_device_audit(
    app: &tauri::AppHandle,
    event_type: AuditEventType,
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
    let mut event = AuditEvent::new(event_type, &session_id, "user", result);

    if let Some(d) = detail {
        event = event.with_detail(d);
    }

    if let Err(e) = append_audit(&log_path, &hmac_key, event) {
        log::warn!("[audit] 写入设备审计事件失败（不阻塞业务）: {}", e);
    }
}

// ===== DPAPI 密封/解密封 =====

/// 将设备组件序列化后经 DPAPI 加密，返回 Base64 编码字符串。
fn seal_device_components(components: &DeviceComponents) -> Result<String, String> {
    let plain_bytes = components.to_bytes();
    let encrypted = dpapi_protect(&plain_bytes, Some("verthys_device_binding"))?;
    Ok(base64_encode(&encrypted))
}

/// 从 Base64 字符串中解密封设备组件，若解密失败（跨机器）则返回 None。
fn unseal_device_components(blob_b64: &str) -> Option<DeviceComponents> {
    use crate::util::crypto::dpapi_unprotect;

    let encrypted = base64_decode(blob_b64).ok()?;
    let plain = dpapi_unprotect(&encrypted).ok()?;
    DeviceComponents::from_bytes(&plain)
}

// ===== 命令：获取设备指纹 =====

/// 获取当前设备机器码（SHA-256 十六进制字符串）。
///
/// 异步执行，超时 2 秒，防止硬件查询阻塞主线程。
#[tauri::command]
pub async fn get_device_fingerprint(
    _state: State<'_, crate::state::AppState>,
) -> Result<String, String> {
    let result = tokio::time::timeout(
        FINGERPRINT_TIMEOUT,
        tokio::task::spawn_blocking(|| {
            crate::infrastructure::device_fingerprint::get_device_fingerprint()
        }),
    )
    .await;

    match result {
        Ok(spawn_result) => match spawn_result {
            Ok(fp) => fp,
            Err(join_err) => {
                log::error!("[device] 指纹采集任务异常: {}", join_err);
                Err(ErrorCode::TemporaryFailure.default_message().to_string())
            }
        },
        Err(_) => {
            log::warn!(
                "[device] 指纹采集超时（{}s）",
                FINGERPRINT_TIMEOUT.as_secs()
            );
            Err(format!(
                "设备指纹采集超时（{}s）",
                FINGERPRINT_TIMEOUT.as_secs()
            ))
        }
    }
}

// ===== 命令：设备绑定 =====

/// 绑定当前设备，将 DPAPI 加密的设备组件存储到状态文件。
///
/// 首次绑定自动执行；若已有绑定则视为重新绑定，记录审计事件。
/// 状态文件不存在时自动创建。
#[tauri::command]
pub async fn set_device_binding(
    app: tauri::AppHandle,
    _state: State<'_, crate::state::AppState>,
) -> Result<(), String> {
    // 采集当前设备组件（异步 + 超时）
    let components = {
        let result = tokio::time::timeout(
            FINGERPRINT_TIMEOUT,
            tokio::task::spawn_blocking(get_device_components),
        )
        .await;

        match result {
            Ok(Ok(Ok(comps))) => comps,
            Ok(Ok(Err(e))) => {
                write_device_audit(
                    &app,
                    AuditEventType::DeviceBind,
                    AuditResult::Failure,
                    Some(e.clone()),
                );
                return Err(e);
            }
            Ok(Err(join_err)) => {
                return Err(format!("设备组件采集任务异常: {}", join_err));
            }
            Err(_) => {
                let msg = format!(
                    "设备指纹采集超时（{}s）",
                    FINGERPRINT_TIMEOUT.as_secs()
                );
                write_device_audit(
                    &app,
                    AuditEventType::DeviceBind,
                    AuditResult::Failure,
                    Some(msg.clone()),
                );
                return Err(msg);
            }
        }
    };

    // DPAPI 加密
    let binding_blob = seal_device_components(&components).map_err(|e| {
        write_device_audit(
            &app,
            AuditEventType::DeviceBind,
            AuditResult::Failure,
            Some(format!("DPAPI 加密失败: {}", e)),
        );
        format!("设备绑定加密失败: {}", e)
    })?;

    // 读取或创建状态文件
    let mut verthys_state = match read_state_file(&app) {
        Ok(Some(s)) => {
            if !s.device_binding_blob.is_empty() || !s.device_fingerprint.is_empty() {
                log::info!("[device] 检测到已有绑定，执行重新绑定");
                write_device_audit(
                    &app,
                    AuditEventType::DeviceRebind,
                    AuditResult::Success,
                    Some("设备重新绑定".into()),
                );
            } else {
                log::info!("[device] 首次设备绑定");
                write_device_audit(
                    &app,
                    AuditEventType::DeviceBind,
                    AuditResult::Success,
                    Some("首次设备绑定".into()),
                );
            }
            s
        }
        Ok(None) => {
            log::info!("[device] 状态文件不存在，自动创建并绑定");
            let verthys_path = crate::repository::verthys_state::read_last_verthys_path(&app)
                .unwrap_or(None
                )
                .unwrap_or_default();
            if verthys_path.is_empty() {
                return Err("无法确定 verthys 路径，请先初始化加密库".into());
            }
            VerthysState::new(&verthys_path)
        }
        Err(e) => {
            return Err(format!("读取状态文件失败: {}", e));
        }
    };

    // 存储绑定数据
    verthys_state.device_binding_blob = binding_blob;
    verthys_state.device_fingerprint = components.combined_hash.clone();

    write_state_file_atomic(&app, &verthys_state).map_err(|e| {
        write_device_audit(
            &app,
            AuditEventType::DeviceBind,
            AuditResult::Failure,
            Some(format!("状态文件写入失败: {}", e)),
        );
        format!("状态文件写入失败: {}", e)
    })?;

    log::info!("[device] 设备绑定完成（DPAPI 密封 + 权重匹配就绪）");
    Ok(())
}

// ===== 命令：设备校验 =====

/// 校验当前设备与存储的绑定是否匹配。
///
/// 返回结构化结果，包含状态（Match/PartialMatch/Mismatch/Unbound/Error）、
/// 匹配分数及错误码。部分匹配指匹配度 ≥80%，允许有限恢复但需提示。
#[tauri::command]
pub async fn check_device_binding(
    app: tauri::AppHandle,
    _state: State<'_, crate::state::AppState>,
) -> Result<DeviceBindingResult, String> {
    // 读取状态文件
    let verthys_state = read_state_file(&app)?;

    let stored_state = match verthys_state {
        Some(s) => s,
        None => {
            log::info!("[device] 状态文件不存在，返回 Unbound（首次运行）");
            return Ok(DeviceBindingResult {
                status: DeviceBindingStatus::Unbound,
                detail: "设备未绑定（首次运行）".into(),
                error_code: None,
                match_score: None,
            });
        }
    };

    let has_binding_blob = !stored_state.device_binding_blob.is_empty();
    let has_legacy_fingerprint = !stored_state.device_fingerprint.is_empty();

    if !has_binding_blob && !has_legacy_fingerprint {
        return Ok(DeviceBindingResult {
            status: DeviceBindingStatus::Unbound,
            detail: "设备未绑定".into(),
            error_code: None,
            match_score: None,
        });
    }

    // 采集当前设备组件（异步 + 超时）
    let current_components = {
        let result = tokio::time::timeout(
            FINGERPRINT_TIMEOUT,
            tokio::task::spawn_blocking(get_device_components),
        )
        .await;

        match result {
            Ok(Ok(Ok(comps))) => comps,
            Ok(Ok(Err(_e))) => {
                return Ok(DeviceBindingResult {
                    status: DeviceBindingStatus::Error,
                    detail: ErrorCode::TemporaryFailure.default_message().to_string(),
                    error_code: Some(ErrorCode::TemporaryFailure.as_str().to_string()),
                    match_score: None,
                });
            }
            Ok(Err(_)) => {
                return Ok(DeviceBindingResult {
                    status: DeviceBindingStatus::Error,
                    detail: "设备组件采集任务异常".into(),
                    error_code: Some(ErrorCode::Internal.as_str().to_string()),
                    match_score: None,
                });
            }
            Err(_) => {
                return Ok(DeviceBindingResult {
                    status: DeviceBindingStatus::Error,
                    detail: format!(
                        "设备指纹采集超时（{}s）",
                        FINGERPRINT_TIMEOUT.as_secs()
                    ),
                    error_code: Some(ErrorCode::TemporaryFailure.as_str().to_string()),
                    match_score: None,
                });
            }
        }
    };

    // 优先使用 DPAPI 绑定数据
    if has_binding_blob {
        match unseal_device_components(&stored_state.device_binding_blob) {
            Some(stored_components) => {
                let (score, match_info) =
                    calculate_match_score(&stored_components, &current_components);

                log::info!(
                    "[device] 权重匹配 score={}%, cpu={}, mb={}, disk={}",
                    score,
                    match_info.cpu_match,
                    match_info.motherboard_match,
                    match_info.disk_match
                );

                if score == 100 {
                    Ok(DeviceBindingResult {
                        status: DeviceBindingStatus::Match,
                        detail: "设备匹配".into(),
                        error_code: None,
                        match_score: Some(100),
                    })
                } else if score >= MATCH_THRESHOLD_PERCENT {
                    log::warn!(
                        "[device] 部分匹配 {}%（超阈值 {}%），允许有限恢复",
                        score,
                        MATCH_THRESHOLD_PERCENT
                    );
                    Ok(DeviceBindingResult {
                        status: DeviceBindingStatus::PartialMatch,
                        detail: format!(
                            "设备部分匹配（{}%），可能硬件已变更，建议重新绑定",
                            score
                        ),
                        error_code: None,
                        match_score: Some(score),
                    })
                } else {
                    Ok(DeviceBindingResult {
                        status: DeviceBindingStatus::Mismatch,
                        detail: format!(
                            "设备不匹配（匹配度 {}%，低于阈值 {}%）",
                            score, MATCH_THRESHOLD_PERCENT
                        ),
                        error_code: Some(ErrorCode::DeviceMismatch.as_str().to_string()),
                        match_score: Some(score),
                    })
                }
            }
            None => {
                log::warn!(
                    "[device] DPAPI 解密失败，状态文件可能来自其他机器"
                );
                Ok(DeviceBindingResult {
                    status: DeviceBindingStatus::Mismatch,
                    detail: "设备绑定数据无法解密（可能来自其他机器）".into(),
                    error_code: Some(ErrorCode::DeviceMismatch.as_str().to_string()),
                    match_score: None,
                })
            }
        }
    } else {
        // 向后兼容：旧版明文指纹比较
        log::info!("[device] 使用旧版明文指纹比较（向后兼容）");
        let current_hash = current_components.combined_hash;
        if current_hash == stored_state.device_fingerprint {
            Ok(DeviceBindingResult {
                status: DeviceBindingStatus::Match,
                detail: "设备匹配（旧版绑定）".into(),
                error_code: None,
                match_score: Some(100),
            })
        } else {
            Ok(DeviceBindingResult {
                status: DeviceBindingStatus::Mismatch,
                detail: "设备不匹配（旧版绑定）".into(),
                error_code: Some(ErrorCode::DeviceMismatch.as_str().to_string()),
                match_score: None,
            })
        }
    }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal_roundtrip() {
        let components = DeviceComponents::from_raw_ids("cpu-test", "mb-test", "disk-test");
        let sealed = seal_device_components(&components);
        if let Ok(blob) = sealed {
            let unsealed = unseal_device_components(&blob);
            assert!(unsealed.is_some());
            let restored = unsealed.unwrap();
            assert_eq!(restored.cpu_hash, components.cpu_hash);
            assert_eq!(restored.motherboard_hash, components.motherboard_hash);
            assert_eq!(restored.disk_hash, components.disk_hash);
            assert_eq!(restored.combined_hash, components.combined_hash);
        }
    }

    #[test]
    fn test_unseal_invalid_blob_returns_none() {
        let result = unseal_device_components("invalid_base64_data!!!");
        assert!(result.is_none());
    }

    #[test]
    fn test_unseal_empty_blob_returns_none() {
        let result = unseal_device_components("");
        assert!(result.is_none());
    }

    #[test]
    fn test_device_binding_result_match() {
        let result = DeviceBindingResult {
            status: DeviceBindingStatus::Match,
            detail: "设备匹配".into(),
            error_code: None,
            match_score: Some(100),
        };
        assert_eq!(result.status, DeviceBindingStatus::Match);
        assert_eq!(result.match_score, Some(100));
    }

    #[test]
    fn test_device_binding_result_partial_match() {
        let result = DeviceBindingResult {
            status: DeviceBindingStatus::PartialMatch,
            detail: "部分匹配".into(),
            error_code: None,
            match_score: Some(85),
        };
        assert_eq!(result.status, DeviceBindingStatus::PartialMatch);
        assert_eq!(result.match_score, Some(85));
    }

    #[test]
    fn test_device_binding_result_unbound() {
        let result = DeviceBindingResult {
            status: DeviceBindingStatus::Unbound,
            detail: "首次运行".into(),
            error_code: None,
            match_score: None,
        };
        assert_eq!(result.status, DeviceBindingStatus::Unbound);
    }

    #[test]
    fn test_device_binding_result_error() {
        let result = DeviceBindingResult {
            status: DeviceBindingStatus::Error,
            detail: "超时".into(),
            error_code: Some("TEMPORARY_FAILURE".into()),
            match_score: None,
        };
        assert_eq!(result.status, DeviceBindingStatus::Error);
        assert_eq!(result.error_code.as_deref(), Some("TEMPORARY_FAILURE"));
    }

    #[test]
    fn test_fingerprint_timeout_constant() {
        assert_eq!(FINGERPRINT_TIMEOUT, Duration::from_secs(2));
    }

    #[test]
    fn test_match_threshold() {
        assert_eq!(MATCH_THRESHOLD_PERCENT, 80);
    }
}