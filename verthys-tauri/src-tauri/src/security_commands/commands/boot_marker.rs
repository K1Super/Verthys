/*
 * commands/boot_marker.rs — 系统启动时刻标记命令
 *
 * 职责：
 *   为启动展示判定提供“本次开机”的唯一标识：系统启动时刻（Unix 毫秒）
 *   与系统运行时长（毫秒）。前端据此判断本次进程启动是否为开机后的
 *   首次，决定播放完整首映还是直接进入主界面。
 *
 * 约束：
 *   - 纯读取命令，无会话授权要求（不接触密钥与业务数据）；
 *   - Windows 专用：本应用仅在此平台部署；其他平台返回错误，由前端
 *     回退首映；
 *   - 启动时刻 = 当前墙钟 − 系统运行时长：无需额外持久化即可跨进程
 *     比较。快速启动恢复内核会话时运行时长可能不重置，属于平台行为；
 *     完整重启必然重置，前端按容差判定，不会把普通重启误判为同一次开机。
 */

use std::time::{SystemTime, UNIX_EPOCH};

/// 启动时刻快照
#[derive(serde::Serialize)]
pub struct BootEpoch {
    /// 系统启动时刻（Unix 毫秒；用于跨进程比较是否为同一次开机）
    pub boot_epoch_ms: i64,
    /// 系统已运行时长（毫秒；诊断用）
    pub uptime_ms: u64,
}

/// 由当前墙钟与运行时长推导启动时刻。
/// 墙钟早于运行时长属时钟异常：返回 0（前端按无效值回退首映）。
fn boot_epoch_from(now_ms: i64, uptime_ms: u64) -> i64 {
    let uptime = i64::try_from(uptime_ms).unwrap_or(i64::MAX);
    now_ms.saturating_sub(uptime).max(0)
}

/// 查询系统启动时刻（同一次开机内跨进程稳定）
#[tauri::command]
pub fn verthys_boot_epoch() -> Result<BootEpoch, String> {
    #[cfg(not(windows))]
    {
        Err("系统启动时刻仅支持 Windows 平台".to_string())
    }
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::GetTickCount64;

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("系统时间读取失败: {}", e))?
            .as_millis();
        let now_ms = i64::try_from(now_ms).map_err(|_| "系统时间超出可表示范围".to_string())?;
        // SAFETY: GetTickCount64 无参数、无前置条件，返回系统启动以来的毫秒数。
        let uptime_ms = unsafe { GetTickCount64() };
        Ok(BootEpoch {
            boot_epoch_ms: boot_epoch_from(now_ms, uptime_ms),
            uptime_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_epoch_subtracts_uptime() {
        assert_eq!(
            boot_epoch_from(1_700_000_000_000, 86_400_000),
            1_699_913_600_000
        );
    }

    #[test]
    fn boot_epoch_saturates_when_uptime_exceeds_wall_clock() {
        assert_eq!(boot_epoch_from(1_000, 2_000), 0);
    }
}
