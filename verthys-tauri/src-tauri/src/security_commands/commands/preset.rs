/*
 * commands/preset.rs — 三档预设命令
 *
 *
 *
 * 职责：
 *   预设 Tauri 命令实现：
 *     - security_get_preset_config：获取三档安全预设的配置详情
 *     - security_apply_preset：运行时切换预设并落盘受信配置
 *       （会话授权 → 原子落盘 → worker switch_preset op → C 层
 *       双缓冲原子切档 → 返回新档真实配置；失败补偿回滚落盘）
 *     - security_load_preset_state：读取受信持久化的预设状态
 *       （启动恢复链的权威来源；无值返回 None，由前端走迁移）
 */

use std::time::Duration;

use tauri::State;

use crate::security_commands::audit::write_security_audit;
use crate::security_commands::auth::require_session_authorized;
use crate::security_commands::preset_persistence::{
    delete_preset_persist, read_preset_persist, write_preset_persist, PresetPersist,
};
use crate::security_commands::responses::{PresetConfig, PresetFeatures};
use crate::security_commands::state::SecurityState;
use crate::state::AppState;
use crate::util::audit_log::{AuditEventType, AuditResult};

/// 切档 worker 通信超时（C 层切换为进程内内存原子操作，5s 覆盖通信往返）
const APPLY_PRESET_TIMEOUT: Duration = Duration::from_secs(5);

/// worker 响应最小解析结构（仅读取 ok / error 两字段做裁决）
#[derive(serde::Deserialize)]
struct WorkerAck {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

/* ====================================================================== *
 *  7. 三档预设命令                                        *
 * ====================================================================== */

/// 三档标准预设的静态配置表（后端权威副本，前端查询与切档返回值共用）
fn preset_config_static(preset: u32) -> Result<PresetConfig, String> {
    let (name, code, features) = match preset {
        0 => (
            "BALANCED",
            0,
            PresetFeatures {
                anti_debug: true,
                anti_inject: true,
                integrity_check: true,
                memory_guard: true,
                key_separation: true,
                emergency_response: true,
                session_lock_on_idle: true,
                shadow_sleep: true,
                module_patrol: true,
                clip_clear_on_lock: true,
                usb_clone_detect: true,
                trace_cleanup: true,
            },
        ),
        1 => (
            "SECURE",
            1,
            PresetFeatures {
                anti_debug: true,
                anti_inject: true,
                integrity_check: true,
                memory_guard: true,
                key_separation: true,
                emergency_response: true,
                session_lock_on_idle: true,
                // SECURE 模式禁用影子休眠：锁定即内存绝对清零
                shadow_sleep: false,
                module_patrol: true,
                clip_clear_on_lock: true,
                usb_clone_detect: true,
                trace_cleanup: true,
            },
        ),
        2 => (
            "PERFORMANCE",
            2,
            PresetFeatures {
                // PERFORMANCE 模式：仅保留核心防护，禁用高开销特性
                // anti_debug 与 C 层性能档一致（关闭反调试，保留注入加固）
                anti_debug: false,
                anti_inject: true,
                integrity_check: false,
                memory_guard: false,
                // 密钥三分离为架构层固定能力，不随档位关闭
                key_separation: true,
                emergency_response: true,
                session_lock_on_idle: true,
                shadow_sleep: true,
                module_patrol: false,
                clip_clear_on_lock: true,
                usb_clone_detect: false,
                trace_cleanup: false,
            },
        ),
        _ => {
            return Err(format!(
                "未知预设代号: {}（有效值: 0=BALANCED, 1=SECURE, 2=PERFORMANCE）",
                preset
            ));
        }
    };
    Ok(PresetConfig { name, code, features })
}

/// 获取三档安全预设的配置详情
/// preset: 0=BALANCED, 1=SECURE, 2=PERFORMANCE
/// 返回该预设下各安全特性的开关状态
#[tauri::command]
pub fn security_get_preset_config(preset: u32) -> Result<PresetConfig, String> {
    preset_config_static(preset)
}

/// 读取受信持久化的预设状态（启动恢复链权威来源）
///
/// 纯读命令，无会话授权：前端在解锁前即可读取恢复；
/// 文件内不含敏感材料（仅预设代号 + 特性开关布尔集）。
#[tauri::command]
pub fn security_load_preset_state(app: tauri::AppHandle) -> Result<Option<PresetPersist>, String> {
    read_preset_persist(&app)
}

/// 运行时切换安全预设并落盘受信配置
///
/// 链路：会话授权检查 → code 合法域校验 → 原子落盘（受信文件，
/// 失败即中止）→ 0/1/2 档经 worker switch_preset op → C 层双缓冲
/// 原子切档（失败补偿回滚落盘至旧档）→ 返回新档真实配置。
/// CUSTOM(3) 无 C 层档位定义，仅落盘自定义特性并返回其配置。
/// 幂等：切到当前档返回成功。错误码：PERMISSION_DENIED /
/// E_INVALID_PRESET / E_PERSIST / E_WORKER_COMM / E_WORKER_ERROR。
#[tauri::command]
pub async fn security_apply_preset(
    app: tauri::AppHandle,
    state: State<'_, SecurityState>,
    app_state: State<'_, AppState>,
    code: u32,
    features: Option<PresetFeatures>,
) -> Result<PresetConfig, String> {
    // 授权检查：变更运行时防护配置需已解锁的会话
    if let Err(msg) = require_session_authorized(&app_state) {
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Denied,
            None,
            Some(format!("PERMISSION_DENIED: apply_preset {}", msg)),
        );
        return Err("PERMISSION_DENIED: 切换安全预设需要已解锁的会话".to_string());
    }

    // code 合法域：0..=3；CUSTOM 必须携带自定义特性
    let custom_features = if code == 3 {
        match features {
            Some(f) => Some(f),
            None => {
                return Err("E_INVALID_PRESET: CUSTOM 预设必须携带自定义特性".to_string());
            }
        }
    } else if code > 2 {
        return Err(format!(
            "E_INVALID_PRESET: 无效预设代号 {}（有效值: 0=BALANCED, 1=SECURE, 2=PERFORMANCE, 3=CUSTOM）",
            code
        ));
    } else {
        None
    };

    // 旧档（审计 + 失败补偿回滚目标）；旧受信文件副本用于回滚原样恢复
    let prev = match state.last_applied_preset.lock() {
        Ok(g) => *g,
        Err(poisoned) => *poisoned.into_inner(),
    };
    let prev_persist = read_preset_persist(&app).ok().flatten();

    // 先原子落盘：写失败即中止，运行时配置不变（磁盘与运行时恒收敛）
    let persist = PresetPersist {
        code,
        custom_features: custom_features.clone(),
    };
    if let Err(e) = write_preset_persist(&app, &persist) {
        let detail = format!("E_PERSIST: 预设配置落盘失败: {}", e);
        write_security_audit(
            &app,
            &state,
            AuditEventType::SecurityCommand,
            AuditResult::Failure,
            None,
            Some(detail.clone()),
        );
        return Err(detail);
    }

    // 0/1/2 档：worker 切档 → C 层双缓冲原子发布；失败补偿回滚落盘
    if code != 3 {
        let req = serde_json::json!({
            "op": "switch_preset",
            "preset": code,
        });
        let resp_json = app_state
            .send_with_timeout(&req.to_string(), APPLY_PRESET_TIMEOUT)
            .map_err(|e| {
                let detail = format!("E_WORKER_COMM: 切档请求发送失败: {}", e);
                write_security_audit(
                    &app,
                    &state,
                    AuditEventType::SecurityCommand,
                    AuditResult::Failure,
                    None,
                    Some(detail.clone()),
                );
                detail
            });
        let resp_json = match resp_json {
            Ok(r) => r,
            Err(detail) => {
                rollback_preset_persist(&app, &state, prev_persist.clone());
                return Err(detail);
            }
        };

        let ack: WorkerAck = match serde_json::from_str(&resp_json) {
            Ok(a) => a,
            Err(e) => {
                let detail = format!("E_WORKER_COMM: 切档响应解析失败: {}", e);
                write_security_audit(
                    &app,
                    &state,
                    AuditEventType::SecurityCommand,
                    AuditResult::Failure,
                    None,
                    Some(detail.clone()),
                );
                rollback_preset_persist(&app, &state, prev_persist.clone());
                return Err(detail);
            }
        };

        if !ack.ok {
            let detail = format!("E_WORKER_ERROR: C 层切档失败: {:?}", ack.error);
            write_security_audit(
                &app,
                &state,
                AuditEventType::SecurityCommand,
                AuditResult::Failure,
                None,
                Some(detail.clone()),
            );
            rollback_preset_persist(&app, &state, prev_persist.clone());
            return Err(detail);
        }
    }

    // 更新后端权威档位（锁中毒自愈：取出旧值后重建）
    match state.last_applied_preset.lock() {
        Ok(mut g) => *g = Some(code),
        Err(poisoned) => {
            let mut g = poisoned.into_inner();
            *g = Some(code);
        }
    }

    write_security_audit(
        &app,
        &state,
        AuditEventType::SecurityCommand,
        AuditResult::Success,
        None,
        Some(format!(
            "安全预设已切换并落盘: {} → {}",
            prev.map_or("UNKNOWN".into(), |p| p.to_string()),
            code
        )),
    );

    log::info!("[security_apply_preset] 切档并落盘成功: {:?} → {}", prev, code);

    // 返回新档真实配置（后端权威副本）
    match code {
        3 => {
            let features = custom_features
                .ok_or("E_INVALID_PRESET: CUSTOM 缺少自定义特性".to_string())?;
            Ok(PresetConfig {
                name: "CUSTOM",
                code: 3,
                features,
            })
        }
        _ => preset_config_static(code),
    }
}

/// 切档失败补偿：受信文件回滚为旧内容（best-effort，失败审计告警）
///
/// 旧文件存在则原样恢复；旧文件不存在（本次为首次落盘）则删除新文件，
/// 使磁盘回到"无配置"状态——与运行时配置均保持旧值，下次恢复链重新对齐。
fn rollback_preset_persist(
    app: &tauri::AppHandle,
    state: &SecurityState,
    prev_persist: Option<PresetPersist>,
) {
    let result = match prev_persist {
        Some(prev) => write_preset_persist(app, &prev),
        None => {
            delete_preset_persist(app);
            Ok(())
        }
    };
    if let Err(e) = result {
        write_security_audit(
            app,
            state,
            AuditEventType::SecurityCommand,
            AuditResult::Failure,
            None,
            Some(format!("落盘回滚失败: {}", e)),
        );
    }
}