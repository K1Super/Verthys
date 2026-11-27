/*
 * commands/system_metrics.rs — 系统运行指标采样命令
 *
 * 职责：
 *   安全防护面板「CPU 占用」指标的真实数据源。后台采样任务按固定节拍经
 *   GetSystemTimes 采样，以约 2 秒跨度差分计算全机 CPU 时间占用率并发布
 *   到进程内缓存；命令只读取最新发布值。
 *
 * 约束：
 *   - 采样窗口由采样节拍决定，与命令调用间隔及面板生命周期无关，避免
 *     长时间未调用后把整段间隔当作窗口；
 *   - 发布值超过新鲜度上限即返回 None，显示层以「无样本」呈现，不以旧值
 *     或 0 冒充实时读数；
 *   - 相邻采样墙钟间隔超限（系统休眠、进程挂起）时丢弃窗口并重建基线；
 *   - 窗口内无滴答增长时返回 None（无法判定），不伪造 0%；
 *   - 非 Windows 平台恒返回 None（本应用仅在 Windows 部署）；
 *   - 纯读取命令，无会话授权要求（系统指标与密钥会话无关）。
 */

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 采样节拍：同时决定发布频率
#[cfg(windows)]
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// 差分窗口下限：两拍间隔的抖动容差
#[cfg(any(windows, test))]
const SAMPLE_WINDOW_MIN: Duration = Duration::from_millis(1500);
/// 差分窗口上限：超过说明采样节拍丢失，跳过本次发布
#[cfg(any(windows, test))]
const SAMPLE_WINDOW_MAX: Duration = Duration::from_secs(3);
/// 相邻采样墙钟间隔上限：超过说明进程或系统未运行，窗口不可信
#[cfg(any(windows, test))]
const MAX_SAMPLE_GAP: Duration = Duration::from_secs(5);
/// 发布值最大可接受年龄：超过即视为无样本
const STALE_AFTER: Duration = Duration::from_secs(5);

/// 一次采样三元组（idle / kernel / user，单位 100ns 滴答）
#[derive(Clone, Copy)]
struct CpuTimes(u64, u64, u64);

/// 系统指标快照（前端展示模型）
#[derive(serde::Serialize)]
pub struct SystemSnapshot {
    /// 全机 CPU 时间占用率（0~100）；None = 暂无新鲜样本
    pub cpu_usage: Option<f64>,
}

/// 已发布样本（占用率 + 发布时间）
#[derive(Clone, Copy)]
struct PublishedSample {
    pct: f64,
    at: Instant,
}

/// 系统指标采样状态（托管于 Tauri；命令只读）
#[derive(Clone, Default)]
pub struct SystemMetricsState {
    published: Arc<Mutex<Option<PublishedSample>>>,
}

impl SystemMetricsState {
    /// 读取最新发布值：超过新鲜度上限返回 None
    pub fn latest(&self) -> Option<f64> {
        self.latest_at(Instant::now())
    }

    fn latest_at(&self, now: Instant) -> Option<f64> {
        let guard = self.published.lock().ok()?;
        let sample = (*guard)?;
        if now.saturating_duration_since(sample.at) <= STALE_AFTER {
            Some(sample.pct)
        } else {
            None
        }
    }

    fn publish(&self, pct: Option<f64>) {
        self.publish_at(pct, Instant::now());
    }

    fn publish_at(&self, pct: Option<f64>, at: Instant) {
        let next = pct.map(|p| PublishedSample { pct: p, at });
        if let Ok(mut guard) = self.published.lock() {
            *guard = next;
        }
    }

    /// 启动后台采样任务（非 Windows 平台为空操作）
    pub fn spawn_sampler(&self) {
        #[cfg(windows)]
        {
            let state = self.clone();
            tauri::async_runtime::spawn(async move {
                let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut window = WindowCore::new();
                let mut failing = false;
                loop {
                    ticker.tick().await;
                    match sample_cpu_times() {
                        Some(times) => {
                            if failing {
                                log::info!("[system_metrics] GetSystemTimes 采样恢复");
                                failing = false;
                            }
                            let pct = window.push(SamplePoint {
                                at: Instant::now(),
                                times,
                            });
                            state.publish(pct);
                        }
                        None => {
                            if !failing {
                                log::warn!(
                                    "[system_metrics] GetSystemTimes 采样失败，暂停发布"
                                );
                                failing = true;
                            }
                            state.publish(None);
                        }
                    }
                }
            });
        }
        #[cfg(not(windows))]
        {
            let _ = self;
        }
    }
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
    let ok = unsafe { GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)) };
    if ok.is_err() {
        return None;
    }
    Some(CpuTimes(ft_u64(idle), ft_u64(kernel), ft_u64(user)))
}

/// 差分计算占用率：kernel 时间已含 idle，故 busy = kernel + user − idle，
/// total = kernel + user。total 为 0（含计数器回卷）表示窗口内无滴答增长，
/// 返回 None 而非伪造 0%。
fn cpu_busy_pct(prev: CpuTimes, cur: CpuTimes) -> Option<f64> {
    let idle = cur.0.saturating_sub(prev.0);
    let kernel = cur.1.saturating_sub(prev.1);
    let user = cur.2.saturating_sub(prev.2);
    let total = kernel.saturating_add(user);
    if total == 0 {
        return None;
    }
    let busy = total.saturating_sub(idle);
    Some(busy as f64 / total as f64 * 100.0)
}

/// 单次采样点
#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
struct SamplePoint {
    at: Instant,
    times: CpuTimes,
}

/// 差分窗口核心（纯逻辑，可单测）
#[cfg(any(windows, test))]
struct WindowCore {
    /// 最近三个采样点（三拍 ≈ 两秒窗口）
    points: std::collections::VecDeque<SamplePoint>,
}

#[cfg(any(windows, test))]
impl WindowCore {
    fn new() -> Self {
        Self {
            points: std::collections::VecDeque::with_capacity(3),
        }
    }

    /// 推入采样点；满足窗口跨度时返回占用率，否则返回 None
    fn push(&mut self, point: SamplePoint) -> Option<f64> {
        if let Some(last) = self.points.back() {
            if point.at.saturating_duration_since(last.at) > MAX_SAMPLE_GAP {
                self.points.clear();
            }
        }
        self.points.push_back(point);
        while self.points.len() > 3 {
            self.points.pop_front();
        }
        let start = self.points.front()?;
        let span = point.at.saturating_duration_since(start.at);
        if span < SAMPLE_WINDOW_MIN || span > SAMPLE_WINDOW_MAX {
            return None;
        }
        cpu_busy_pct(start.times, point.times)
    }
}

/// 查询系统运行指标（安全防护面板真实数据源）
#[tauri::command]
pub fn verthys_system_snapshot(state: tauri::State<'_, SystemMetricsState>) -> SystemSnapshot {
    SystemSnapshot {
        cpu_usage: state.latest(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(idle: u64, kernel: u64, user: u64) -> CpuTimes {
        CpuTimes(idle, kernel, user)
    }

    #[test]
    fn busy_ratio_windows_ticks() {
        // 占用 40%：idle 增 60 万滴答，kernel + user 共增 100 万滴答
        let prev = cpu(0, 0, 0);
        let cur = cpu(600_000, 400_000, 600_000);
        assert!((cpu_busy_pct(prev, cur).unwrap() - 40.0).abs() < 1e-9);
    }

    #[test]
    fn zero_window_is_unknown() {
        let t = cpu(10, 20, 30);
        assert_eq!(cpu_busy_pct(t, t), None);
    }

    #[test]
    fn full_busy_is_100() {
        let prev = cpu(0, 0, 0);
        // idle 零增长、kernel + user 同步增长 → 全忙碌
        let cur = cpu(0, 500_000, 500_000);
        assert!((cpu_busy_pct(prev, cur).unwrap() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn counter_wrap_is_unknown() {
        // 计数器回卷（cur < prev）按无增长处理，不得产生负值或 0% 读数
        let prev = cpu(50, 40, 30);
        let cur = cpu(10, 8, 7);
        assert_eq!(cpu_busy_pct(prev, cur), None);
    }

    fn point(base: Instant, secs: u64, times: CpuTimes) -> SamplePoint {
        SamplePoint {
            at: base + Duration::from_secs(secs),
            times,
        }
    }

    #[test]
    fn window_publishes_after_two_intervals() {
        let base = Instant::now();
        let mut core = WindowCore::new();
        assert_eq!(core.push(point(base, 0, cpu(0, 0, 0))), None);
        assert_eq!(core.push(point(base, 1, cpu(300, 200, 300))), None);
        let pct = core.push(point(base, 2, cpu(600, 400, 600)));
        assert!((pct.unwrap() - 40.0).abs() < 1e-9);
    }

    #[test]
    fn window_resets_after_long_gap() {
        let base = Instant::now();
        let mut core = WindowCore::new();
        assert_eq!(core.push(point(base, 0, cpu(0, 0, 0))), None);
        assert_eq!(core.push(point(base, 1, cpu(300, 200, 300))), None);
        // 间隔 10 秒（休眠/挂起）：窗口作废，重新积累
        assert_eq!(core.push(point(base, 11, cpu(900, 800, 900))), None);
        assert_eq!(core.push(point(base, 12, cpu(1200, 1000, 1200))), None);
        let pct = core.push(point(base, 13, cpu(1500, 1200, 1500)));
        assert!((pct.unwrap() - 40.0).abs() < 1e-9);
    }

    #[test]
    fn window_without_tick_growth_is_unknown() {
        let base = Instant::now();
        let mut core = WindowCore::new();
        let frozen = cpu(10, 20, 30);
        assert_eq!(core.push(point(base, 0, frozen)), None);
        assert_eq!(core.push(point(base, 1, frozen)), None);
        assert_eq!(core.push(point(base, 2, frozen)), None);
    }

    #[test]
    fn published_value_expires_after_stale_window() {
        let state = SystemMetricsState::default();
        let t0 = Instant::now();
        state.publish_at(Some(42.0), t0);
        assert_eq!(state.latest_at(t0), Some(42.0));
        assert_eq!(state.latest_at(t0 + Duration::from_secs(4)), Some(42.0));
        assert_eq!(state.latest_at(t0 + Duration::from_secs(6)), None);
    }

    #[test]
    fn latest_without_sample_is_none() {
        let state = SystemMetricsState::default();
        assert_eq!(state.latest(), None);
    }
}
