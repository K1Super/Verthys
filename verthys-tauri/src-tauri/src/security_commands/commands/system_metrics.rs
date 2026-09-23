/*
 * commands/system_metrics.rs — 系统运行指标采样命令
 *
 * 职责：
 *   安全防护面板「CPU / IO 开销」指标的真实数据源：经 GetSystemTimes
 *   双采样差分计算系统 CPU 占用率。采样基线经进程内静态状态跨调用
 *   保留，每次调用返回与上一次调用之间的时间窗占用率，前端轮询
 *   周期即差分窗口，无需命令内人为等待。
 *
 * 约束：
 *   - 首次调用无基线返回 cpu_usage=None（前端占位处理，不伪造初值）；
 *   - 非 Windows 平台恒返回 None（本应用仅在 Windows 部署）；
 *   - 纯读取命令，无会话授权要求（系统指标与密钥会话无关）。
 */

use std::sync::Mutex;

/// 一次采样三元组（idle / kernel / user，单位 100ns 滴答）
#[derive(Clone, Copy)]
struct CpuTimes(u64, u64, u64);

/// 进程内采样基线（仅 windows 平台写入）
static PREV_CPU_TIMES: Mutex<Option<CpuTimes>> = Mutex::new(None);

/// 系统指标快照（前端展示模型）
#[derive(serde::Serialize)]
pub struct SystemSnapshot {
    /// 系统 CPU 占用率（0~100）；None = 首次采样无基线 / 平台不支持
    pub cpu_usage: Option<f64>,
}

#[cfg(windows)]
fn ft_u64(ft: windows::Win32::Foundation::FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

#[cfg(windows)]
fn sample_cpu_times() -> Option<CpuTimes> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetSystemTimes;
    let mut idle = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let ok = unsafe {
        GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user))
    };
    if ok.is_err() {
        return None;
    }
    Some(CpuTimes(ft_u64(idle), ft_u64(kernel), ft_u64(user)))
}

/// 差分计算占用率：busy = (kernel + user − idle)，total = kernel + user。
/// total 为 0 表示时间窗内无滴答增长，返回 0.0（无占用变化可判）。
fn cpu_busy_pct(prev: CpuTimes, cur: CpuTimes) -> f64 {
    let idle = cur.0.saturating_sub(prev.0);
    let kernel = cur.1.saturating_sub(prev.1);
    let user = cur.2.saturating_sub(prev.2);
    let total = kernel.saturating_add(user);
    if total == 0 {
        return 0.0;
    }
    let busy = total.saturating_sub(idle);
    busy as f64 / total as f64 * 100.0
}

/// 查询系统运行指标（安全防护面板真实数据源）
#[tauri::command]
pub fn verthys_system_snapshot() -> Result<SystemSnapshot, String> {
    #[cfg(not(windows))]
    {
        return Ok(SystemSnapshot { cpu_usage: None });
    }
    #[cfg(windows)]
    {
        let cur = match sample_cpu_times() {
            Some(t) => t,
            None => return Ok(SystemSnapshot { cpu_usage: None }),
        };
        let mut guard = PREV_CPU_TIMES
            .lock()
            .map_err(|e| format!("指标采样锁污染: {}", e))?;
        let prev = *guard;
        *guard = Some(cur);
        Ok(SystemSnapshot {
            cpu_usage: prev.map(|p| cpu_busy_pct(p, cur)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_ratio_windows_ticks() {
        // 占用 40%：idle 增 60 万滴答，kernel + user 共增 100 万滴答
        let prev = CpuTimes(0, 0, 0);
        let cur = CpuTimes(600_000, 400_000, 600_000);
        assert!((cpu_busy_pct(prev, cur) - 40.0).abs() < 1e-9);
    }

    #[test]
    fn zero_window_returns_zero() {
        let t = CpuTimes(10, 20, 30);
        assert_eq!(cpu_busy_pct(t, t), 0.0);
    }

    #[test]
    fn full_busy_is_100() {
        let prev = CpuTimes(0, 0, 0);
        // idle 零增长、kernel + user 同步增长 → 全忙碌
        let cur = CpuTimes(0, 500_000, 500_000);
        assert!((cpu_busy_pct(prev, cur) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn counter_wrap_saturates_to_zero() {
        // 计数器回卷（cur < prev）按无增长处理，不得产生负值
        let prev = CpuTimes(50, 40, 30);
        let cur = CpuTimes(10, 8, 7);
        assert_eq!(cpu_busy_pct(prev, cur), 0.0);
    }
}