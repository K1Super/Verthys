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
 * 生命周期：由注入的启用开关驱动（解锁就绪期才轮询，避免解锁视图
 * 期间的无效 IPC）；卸载停表并丢弃在途结果。
 */

import { ref, watch, onBeforeUnmount, type Ref } from "vue";
import { verthysGetSystemSnapshot } from "../../lib/verthys";

/** 轮询间隔（毫秒）：采样差分窗口，兼顾时效与 IPC 频率 */
export const SYSTEM_METRICS_POLL_MS = 2000;

/**
 * @param enabled 轮询启用开关（false 时停表；切换为 true 立即首采）
 */
export function useSystemMetrics(enabled: Ref<boolean>) {
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

  /** 启动轮询（幂等：立即首采 + 定期间隔） */
  const startPolling = () => {
    if (timer !== null || disposed) return;
    void poll();
    timer = setInterval(() => void poll(), SYSTEM_METRICS_POLL_MS);
  };

  /** 停止轮询（保留最后值，避免指标闪跳） */
  const stopPolling = () => {
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  };

  watch(
    enabled,
    (on) => {
      if (on) startPolling();
      else stopPolling();
    },
    { immediate: true },
  );

  onBeforeUnmount(() => {
    disposed = true;
    stopPolling();
  });

  return { cpuUsage };
}