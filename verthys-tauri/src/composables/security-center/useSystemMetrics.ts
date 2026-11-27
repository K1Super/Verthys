/**
 * useSystemMetrics.ts — 系统运行指标轮询 Composable
 *
 * 职责：
 *   1. 周期调用后端只读命令 verthys_system_snapshot，读取后端固定节拍
 *      采样发布的全机 CPU 时间占用率；
 *   2. cpuUsage = null 表示当前无有效样本，显示层以「—」呈现，不得以 0 代替；
 *   3. 采样失败保留上次值，但超过陈旧上限即清为 null，避免过期读数被
 *      当作实时值长期展示；
 *   4. 轮询仅在解锁就绪期运行；卸载停表并丢弃在途结果。
 */

import { ref, watch, onBeforeUnmount, type Ref } from "vue";
import { verthysGetSystemSnapshot } from "../../lib/verthys";

/** 轮询间隔（毫秒）：后端每 1s 发布一次，前端同频读取 */
const SYSTEM_METRICS_POLL_MS = 1000;
/** 无成功样本超过该时长即视为陈旧，清为 null（覆盖 IPC 挂起场景） */
const SYSTEM_METRICS_STALE_MS = 6000;

/**
 * @param enabled 轮询启用开关（false 时停表；切换为 true 立即首采）
 */
export function useSystemMetrics(enabled: Ref<boolean>) {
  /** 全机 CPU 时间占用率（0~100；null = 无有效样本） */
  const cpuUsage = ref<number | null>(null);
  let timer: ReturnType<typeof setInterval> | null = null;
  let disposed = false;
  let inFlight = false;
  /** 最近一次成功采样的时间戳（0 = 尚无成功样本） */
  let lastSuccessAt = 0;
  /** 当前故障期是否已告警（避免每秒刷屏） */
  let failureLogged = false;

  /** 陈旧检查独立于请求状态：在途请求挂起时也要按时清为 null */
  const markStaleIfNeeded = () => {
    if (
      lastSuccessAt !== 0 &&
      Date.now() - lastSuccessAt > SYSTEM_METRICS_STALE_MS
    ) {
      cpuUsage.value = null;
      lastSuccessAt = 0;
    }
  };

  const poll = async () => {
    markStaleIfNeeded();
    if (inFlight || disposed) return;
    inFlight = true;
    try {
      const snap = await verthysGetSystemSnapshot();
      if (disposed) return;
      if (snap.cpu_usage !== null && Number.isFinite(snap.cpu_usage)) {
        cpuUsage.value = Math.max(0, Math.min(100, Math.round(snap.cpu_usage)));
        lastSuccessAt = Date.now();
        failureLogged = false;
      } else {
        cpuUsage.value = null;
        lastSuccessAt = 0;
      }
    } catch (e) {
      if (disposed) return;
      if (!failureLogged) {
        console.warn("[useSystemMetrics] 指标采样失败（保留上次值至陈旧上限）", e);
        failureLogged = true;
      }
      markStaleIfNeeded();
    } finally {
      inFlight = false;
    }
  };

  /** 启动轮询（幂等：立即首采 + 定期间隔） */
  const startPolling = () => {
    if (timer !== null || disposed) return;
    void poll();
    timer = setInterval(() => void poll(), SYSTEM_METRICS_POLL_MS);
  };

  /** 停止轮询（保留最后值；解锁期由启用开关重新驱动） */
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
