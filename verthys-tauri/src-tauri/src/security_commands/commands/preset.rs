/*
 * commands/preset.rs — 三档预设查询命令
 *
 *    "优化.md" 第十三章 — 三档安全预设
 *
 * 职责：
 *   预设查询 Tauri 命令实现：
 *     - security_get_preset_config：获取三档安全预设的配置详情
 *       preset: 0=BALANCED, 1=SECURE, 2=PERFORMANCE
 */

use crate::security_commands::responses::{PresetConfig, PresetFeatures};

/* ====================================================================== *
 *  7. 三档预设查询命令                                                    *
 * ====================================================================== */

/// 获取三档安全预设的配置详情
/// preset: 0=BALANCED, 1=SECURE, 2=PERFORMANCE
/// 返回该预设下各安全特性的开关状态
#[tauri::command]
pub fn security_get_preset_config(preset: u32) -> Result<PresetConfig, String> {
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
                anti_debug: true,
                anti_inject: true,
                integrity_check: false,
                memory_guard: false,
                key_separation: false,
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
