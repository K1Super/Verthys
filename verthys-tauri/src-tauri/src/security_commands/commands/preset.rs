/*
 * commands/preset.rs — 三档预设命令
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

/// 查询 worker 通信超时（C 层快照读取为进程内只读操作，1s 覆盖通信往返）
const PRESET_QUERY_TIMEOUT: Duration = Duration::from_secs(1);

/// worker 响应最小解析结构（读取 ok / error / data 三字段做裁决）
#[derive(serde::Deserialize)]
struct WorkerAck {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    data: Option<String>,
}

/* ====================================================================== *
 *  预设矩阵：权威源在 C 运行时策略层（特性位投影）
 *                                                                    *
 *  位序为跨层契约，与 C 侧 SEC_FEAT_* 逐位对齐，禁止重排；宿主不再维护  *
 *  本地矩阵副本——展示与执行统一以 C 投影回读结果为准。                 *
 * ====================================================================== */

use crate::security::app_feature_gate::{
    FEAT_ANTI_DEBUG, FEAT_ANTI_INJECT, FEAT_CLIPBOARD_GUARD, FEAT_EMERGENCY_RESPONSE,
    FEAT_INTEGRITY_CHECK, FEAT_KEY_SEPARATION, FEAT_MEMORY_GUARD, FEAT_MODULE_PATROL,
    FEAT_SESSION_LOCK_IDLE, FEAT_TRACE_CLEANUP, FEAT_USB_CLONE_DETECT,
};

/// 特性位 → 特性开关集（未知位忽略）
fn features_from_bits(bits: u32) -> PresetFeatures {
    PresetFeatures {
        anti_debug: bits & FEAT_ANTI_DEBUG != 0,
        anti_inject: bits & FEAT_ANTI_INJECT != 0,
        integrity_check: bits & FEAT_INTEGRITY_CHECK != 0,
        memory_guard: bits & FEAT_MEMORY_GUARD != 0,
        key_separation: bits & FEAT_KEY_SEPARATION != 0,
        emergency_response: bits & FEAT_EMERGENCY_RESPONSE != 0,
        session_lock_on_idle: bits & FEAT_SESSION_LOCK_IDLE != 0,
        module_patrol: bits & FEAT_MODULE_PATROL != 0,
        clip_clear_on_lock: bits & FEAT_CLIPBOARD_GUARD != 0,
        usb_clone_detect: bits & FEAT_USB_CLONE_DETECT != 0,
        trace_cleanup: bits & FEAT_TRACE_CLEANUP != 0,
    }
}

/// 平衡档核心位基线（自定义档的 C 层基线投影；密钥分立/应急熔断为红线常量）
const CORE_BITS_BALANCED_BASELINE: u32 = FEAT_ANTI_DEBUG
    | FEAT_ANTI_INJECT
    | FEAT_MEMORY_GUARD
    | FEAT_KEY_SEPARATION
    | FEAT_EMERGENCY_RESPONSE;

/// 应用侧策略位（自定义模板逐项开关的投影；核心位恒取平衡档基线）
fn features_to_app_bits(f: &PresetFeatures) -> u32 {
    let mut bits = 0u32;
    if f.integrity_check {
        bits |= FEAT_INTEGRITY_CHECK;
    }
    if f.session_lock_on_idle {
        bits |= FEAT_SESSION_LOCK_IDLE;
    }
    if f.module_patrol {
        bits |= FEAT_MODULE_PATROL;
    }
    if f.clip_clear_on_lock {
        bits |= FEAT_CLIPBOARD_GUARD;
    }
    if f.usb_clone_detect {
        bits |= FEAT_USB_CLONE_DETECT;
    }
    if f.trace_cleanup {
        bits |= FEAT_TRACE_CLEANUP;
    }
    bits
}

/// 档位代号 → 名称（非法代号返回 Err，不静默回退）
fn preset_name(preset: u32) -> Result<&'static str, String> {
    match preset {
        0 => Ok("BALANCED"),
        1 => Ok("SECURE"),
        2 => Ok("PERFORMANCE"),
        _ => Err(format!(
            "未知预设代号: {}（有效值: 0=BALANCED, 1=SECURE, 2=PERFORMANCE）",
            preset
        )),
    }
}

/// 发送 worker 查询请求并解析 ack（失败返回带错误码前缀的 Err）
fn worker_query(app_state: &AppState, req: &serde_json::Value) -> Result<String, String> {
    let resp_json = app_state
        .send_with_timeout(&req.to_string(), PRESET_QUERY_TIMEOUT)
        .map_err(|e| format!("E_WORKER_COMM: 预设查询发送失败: {}", e))?;
    let ack: WorkerAck = serde_json::from_str(&resp_json)
        .map_err(|e| format!("E_WORKER_COMM: 预设查询响应解析失败: {}", e))?;
    if !ack.ok {
        return Err(format!("E_WORKER_ERROR: 预设查询失败: {:?}", ack.error));
    }
    ack.data
        .ok_or_else(|| "E_WORKER_COMM: 预设查询响应缺少数据".to_string())
}

/// 查询活跃档位（worker → C 快照读取；供切档回读校验）
fn query_active_preset(app_state: &AppState) -> Result<u32, String> {
    let data = worker_query(app_state, &serde_json::json!({ "op": "get_active_preset" }))?;
    data.trim()
        .parse::<u32>()
        .map_err(|e| format!("E_WORKER_COMM: 活跃档位解析失败: {}", e))
}

/// 查询指定档位的特性位投影（worker → C 唯一权威输出）
fn query_preset_feature_bits(app_state: &AppState, code: u32) -> Result<u32, String> {
    let data = worker_query(
        app_state,
        &serde_json::json!({ "op": "get_preset_features", "preset": code }),
    )?;
    data.trim()
        .parse::<u32>()
        .map_err(|e| format!("E_WORKER_COMM: 特性位解析失败: {}", e))
}

/* ====================================================================== *
 *  解锁前受信档位应用（服务层契约实现）
 * ====================================================================== */

/// 注册解锁前预设应用实现到服务层契约（应用启动阶段调用一次）。
///
/// 依赖反转落地：service 层只声明契约，本模块提供实现；控制器经 service
/// 调用，杜绝 controller → security_commands 的反向依赖（分层红线）。
pub(crate) fn install_preset_source() {
    crate::service::preset_source::install(apply_persisted_preset_impl);
}

/// 解锁前应用受信档位到 C 运行时策略层（服务层契约实现）。
///
/// 档位来源：容器路径对应的受信预设文件（非容器头基线——容器头仅记录
/// 创建基线，且可能滞后于用户运行期切换）。
///   - 标准档（0/1/2）：直接应用；
///   - 自定义档（3）：应用平衡档基线（应用侧开关在解锁后由宿主组合）；
///   - 无配置文件（全新容器）：应用平衡档基线。
///
/// 失败语义：读取失败或切档失败（重试一次仍失败）均返回 Err，
/// 由调用方中止解锁（fail-closed）——禁止以未知/更低档位静默继续。
fn apply_persisted_preset_impl(app: &tauri::AppHandle, verthys_path: &str) -> Result<(), String> {
    use crate::security_commands::preset_persistence::read_preset_persist_for_path;
    use tauri::Manager;

    let app_state = app.state::<AppState>();
    let security_state = app.state::<SecurityState>();

    let preset_code: u32 = match read_preset_persist_for_path(verthys_path) {
        Ok(Some(persist)) if persist.code <= 2 => persist.code,
        Ok(Some(_)) | Ok(None) => 0,
        Err(e) => {
            log::error!("[preset_source] 受信档位读取失败: {}", e);
            write_security_audit(
                app,
                &security_state,
                AuditEventType::SecurityCommand,
                AuditResult::Denied,
                None,
                Some(format!("E_PRESET_APPLY_FAILED: 受信档位读取失败，中止解锁: {}", e)),
            );
            return Err("安全预设配置不可用，已中止解锁（请检查磁盘状态）".to_string());
        }
    };

    let req = serde_json::json!({ "op": "switch_preset", "preset": preset_code });
    let mut last_err = String::new();
    for attempt in 0..2 {
        match app_state.send_with_timeout(&req.to_string(), APPLY_PRESET_TIMEOUT) {
            Ok(resp) => match serde_json::from_str::<serde_json::Value>(&resp) {
                Ok(ack) if ack.get("ok").and_then(|v| v.as_bool()) == Some(true) => {
                    log::info!(
                        "[preset_source] 解锁前已应用受信档位: preset={} attempt={}",
                        preset_code,
                        attempt + 1
                    );
                    // 门控镜像取保守值（全能力开启）：精确值由解锁后的
                    // 预设回读路径覆盖——未知窗口一律朝防护更严方向失败
                    crate::security::app_feature_gate::store(
                        crate::security::app_feature_gate::FEAT_CONSERVATIVE,
                    );
                    return Ok(());
                }
                Ok(ack) => {
                    last_err = format!("C 层拒绝切档: {:?}", ack.get("error"));
                }
                Err(e) => {
                    last_err = format!("切档响应解析失败: {}", e);
                }
            },
            Err(e) => {
                last_err = format!("切档请求失败: {}", e);
            }
        }
        if attempt == 0 {
            log::warn!("[preset_source] 切档失败，重试一次: {}", last_err);
        }
    }

    write_security_audit(
        app,
        &security_state,
        AuditEventType::SecurityCommand,
        AuditResult::Denied,
        None,
        Some(format!(
            "E_PRESET_APPLY_FAILED: 解锁前预设应用失败，已中止解锁: {}",
            last_err
        )),
    );
    Err("安全策略应用失败，已中止解锁（请重启应用后重试）".to_string())
}

/// 获取三档安全预设的配置详情
/// preset: 0=BALANCED, 1=SECURE, 2=PERFORMANCE
/// 特性位取自 C 运行时策略层投影（唯一权威输出），宿主不维护本地矩阵副本
#[tauri::command]
pub async fn security_get_preset_config(
    state: State<'_, AppState>,
    preset: u32,
) -> Result<PresetConfig, String> {
    let name = preset_name(preset)?;
    let bits = query_preset_feature_bits(&state, preset)?;
    Ok(PresetConfig {
        name,
        code: preset,
        features: features_from_bits(bits),
    })
}

/* ====================================================================== *
 *  7. 三档预设命令                                        *
 * ====================================================================== */

/// 预设持久化读取响应（受信状态 + 不一致标记）
#[derive(serde::Serialize)]
pub struct PresetLoadStateResponse {
    /// 受信持久化的预设状态；无配置（全新用户/未落盘）为 None
    pub state: Option<PresetPersist>,
    /// 持久化可能不一致标记：回滚落盘失败后为 true，
    /// 表示受信文件内容可能与运行时档位不一致（需向用户可见报告）
    pub persist_dirty: bool,
}

/// 读取受信持久化的预设状态（启动恢复链权威来源）
///
/// 纯读命令，无会话授权：前端在解锁前即可读取恢复；
/// 文件内不含敏感材料（仅预设代号 + 特性开关布尔集）。
/// 响应携带持久化不一致标记：回滚失败后该标记为真，前端据此提示。
#[tauri::command]
pub fn security_load_preset_state(
    app: tauri::AppHandle,
    state: State<'_, SecurityState>,
) -> Result<PresetLoadStateResponse, String> {
    let persisted = read_preset_persist(&app)?;
    let persist_dirty = state
        .preset_persist_dirty
        .load(std::sync::atomic::Ordering::SeqCst);
    Ok(PresetLoadStateResponse {
        state: persisted,
        persist_dirty,
    })
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
    // 落盘成功即收敛点：清除持久化不一致标记
    state
        .preset_persist_dirty
        .store(false, std::sync::atomic::Ordering::SeqCst);

    // worker 切档 → C 层双缓冲原子发布；失败补偿回滚落盘。
    // 自定义档应用平衡档基线（禁止沿用上一个标准档的残留策略），
    // 其余档位应用目标档；两者都必须回读校验真实生效。
    let expected_active: u32 = if code == 3 { 0 } else { code };
    {
        let req = serde_json::json!({
            "op": "switch_preset",
            "preset": expected_active,
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

        // 回读校验：从 C 运行时快照读回活跃档位。与目标不一致即判定
        // 切换未真实生效（发布异常/策略未落地），回滚落盘并显式报错。
        match query_active_preset(&app_state) {
            Ok(active) if active == expected_active => { /* 回读一致：继续 */ }
            Ok(active) => {
                let detail = format!(
                    "E_PRESET_VERIFY: 活跃档位回读不一致: {} != {}",
                    active, expected_active
                );
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
            Err(e) => {
                let detail = format!("E_PRESET_VERIFY: 活跃档位回读失败: {}", e);
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

    log::info!(
        "[security_apply_preset] 切档并落盘成功: {:?} → {}",
        prev,
        code
    );

    // 返回新档配置：标准档特性位取自 C 投影（唯一权威输出），
    // 自定义档返回落盘的模板特性。
    // 特性位回读失败时补偿回退运行时档位与落盘，保持三方一致。
    match code {
        3 => {
            let features =
                custom_features.ok_or("E_INVALID_PRESET: CUSTOM 缺少自定义特性".to_string())?;
            // 门控镜像：自定义档按模板逐项开关投影（核心位取平衡档基线）
            crate::security::app_feature_gate::store(
                CORE_BITS_BALANCED_BASELINE | features_to_app_bits(&features),
            );
            Ok(PresetConfig {
                name: "CUSTOM",
                code: 3,
                features,
            })
        }
        _ => {
            let name = preset_name(code)?;
            match query_preset_feature_bits(&app_state, code) {
                Ok(bits) => {
                    // 门控镜像与权威投影同步（应用侧能力执行方据此读取）
                    crate::security::app_feature_gate::store(bits);
                    Ok(PresetConfig {
                        name,
                        code,
                        features: features_from_bits(bits),
                    })
                }
                Err(e) => {
                    // 补偿回退：运行时切回旧档（首次切档回退到平衡基线）
                    let revert_code = prev.unwrap_or(0);
                    let revert = serde_json::json!({
                        "op": "switch_preset",
                        "preset": revert_code,
                    });
                    let _ = app_state
                        .send_with_timeout(&revert.to_string(), APPLY_PRESET_TIMEOUT);
                    rollback_preset_persist(&app, &state, prev_persist.clone());
                    let detail =
                        format!("E_PRESET_VERIFY: 特性位回读失败，已回退运行时档位: {}", e);
                    write_security_audit(
                        &app,
                        &state,
                        AuditEventType::SecurityCommand,
                        AuditResult::Failure,
                        None,
                        Some(detail.clone()),
                    );
                    Err(detail)
                }
            }
        }
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
        // 回滚失败：磁盘与运行时存在分歧窗口，置标记供上层可见报告
        state
            .preset_persist_dirty
            .store(true, std::sync::atomic::Ordering::SeqCst);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 三档特性位期望值（与 C 侧投影逐位对齐；位序为跨层契约）
    const BITS_BALANCED: u32 = 0x6FF;
    const BITS_SECURE: u32 = 0x7FF;
    const BITS_PERFORMANCE: u32 = 0x073;

    #[test]
    fn test_features_from_bits_matches_matrix() {
        let bal = features_from_bits(BITS_BALANCED);
        assert!(bal.anti_debug && bal.anti_inject && bal.integrity_check && bal.memory_guard);
        assert!(bal.key_separation && bal.emergency_response && bal.session_lock_on_idle);
        assert!(bal.module_patrol && bal.usb_clone_detect && bal.trace_cleanup);
        assert!(!bal.clip_clear_on_lock, "平衡档不启用剪贴板监听");

        let sec = features_from_bits(BITS_SECURE);
        assert!(sec.clip_clear_on_lock, "高安全档启用剪贴板监听");
        assert!(sec.anti_debug && sec.memory_guard && sec.integrity_check);

        let perf = features_from_bits(BITS_PERFORMANCE);
        assert!(perf.anti_debug && perf.anti_inject, "性能档保留调试检测与注入拦截");
        assert!(!perf.memory_guard && !perf.integrity_check);
        assert!(!perf.module_patrol && !perf.usb_clone_detect && !perf.trace_cleanup);
        assert!(perf.session_lock_on_idle && !perf.clip_clear_on_lock);
    }

    #[test]
    fn test_features_to_app_bits_projection() {
        let mut f = features_from_bits(BITS_BALANCED);
        f.module_patrol = false;
        f.trace_cleanup = false;
        let bits = CORE_BITS_BALANCED_BASELINE | features_to_app_bits(&f);
        assert_eq!(bits & FEAT_MODULE_PATROL, 0, "巡检关闭必须如实投影");
        assert_eq!(bits & FEAT_TRACE_CLEANUP, 0, "痕迹清理关闭必须如实投影");
        assert_ne!(bits & FEAT_INTEGRITY_CHECK, 0);
        assert_ne!(bits & FEAT_KEY_SEPARATION, 0, "密钥分立为红线常量");
        assert_ne!(bits & FEAT_ANTI_DEBUG, 0, "调试检测为红线常量");
    }

    #[test]
    fn test_features_from_bits_unknown_bits_ignored() {
        let f = features_from_bits(0xFFFF_FFFF);
        assert!(f.anti_debug && f.trace_cleanup);
    }

    #[test]
    fn test_preset_name_domain() {
        assert_eq!(preset_name(0).unwrap(), "BALANCED");
        assert_eq!(preset_name(1).unwrap(), "SECURE");
        assert_eq!(preset_name(2).unwrap(), "PERFORMANCE");
        assert!(preset_name(3).is_err());
        assert!(preset_name(9).is_err());
    }
}
