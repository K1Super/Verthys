/**
 * useSystemMetrics.ts — 系统运行指标轮询 Composable
 *
 * 职责：
 *   1. 周期调用后端真实采样命令 verthys_system_snapshot（GetSystemTimes
 *      差分占用率），作为安全防护面板「CPU / IO 开销」的单一数据源；
 *   2. 轮询周期即采样差分窗口（2s），数值天然平滑无需前端滤波；
 *   3. cpuUsage = -1 表示尚未取得基线（显示层占位处理），采样失败
 *      保留上次值（指标为可观测出口，不打扰用户）。
 *
 * 生命周期：挂载即首采 + 定期间隔，卸载停表并丢弃在途结果。
 */

import { ref, onBeforeUnmount } from "vue";
import { verthysGetSystemSnapshot } from "../../lib/verthys";

/** 轮询间隔（毫秒）：采样差分窗口，兼顾时效与 IPC 频率 */
export const SYSTEM_METRICS_POLL_MS = 2000;

export function useSystemMetrics() {
  /** 系统 CPU 占用率（0~100；-1 = 尚无基线） */
  const cpuUsage = ref(-1);
  let timer: ReturnType<typeof setInterval> | null = null;
  let disposed = false;

  const poll = async () => {
    try {
      const snap = await verthysGetSystemSnapshot();
      if (disposed) return;
      if (snap.cpu_usage !== null && Number.isFinite(snap.cpu_usage)) {
        cpuUsage.value = Math.max(0, Math.min(100, Math.round(snap.cpu_usage)));
      }
    } catch (e) {
      console.warn("[useSystemMetrics] 指标采样失败（保留上次值）", e);
    }
  };

  void poll();
  timer = setInterval(() => void poll(), SYSTEM_METRICS_POLL_MS);

  onBeforeUnmount(() => {
    disposed = true;
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  });

  return { cpuUsage };
}