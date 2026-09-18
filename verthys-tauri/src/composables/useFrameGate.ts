/**
 * useFrameGate — 统一帧门控（所有渲染引擎共用）
 *
 * =============================================================================
 * 【方案定位】第二轮空闲 CPU 治理：帧率调度的唯一执行层
 *
 * 由 useGlobalIdleScheduler 的空闲档位驱动 rAF 帧率：
 *   active    → 60fps（每帧）
 *   settling  → 30fps（33.3ms）
 *   idle      → 5fps（200ms）
 *   deep-idle → 1fps（1000ms）
 *
 * 关键设计：
 *   1. dt 连续性：跳过的帧不推进 lastRun → 下一处理帧获得真实累积 dt
 *      （物理时间连续，弹簧/漂移积分按累积 dt 求解，无状态跳变）；
 *      dt 上限 0.5s 防异常长帧（挂起恢复/断点）物理爆炸。
 *   2. 档位切换无尖峰：watch(level) 时重置 lastRun，避免降档瞬间
 *      一次性注入大 dt。
 *   3. 回调异常熔断：单次回调抛错 → 记录并停止本门控（防错误帧循环
 *      刷屏拖垮全局），其余引擎不受影响。
 *   4. rAF 天然暂停：页面隐藏时浏览器停发 rAF → 深空闲自动完全停帧，
 *      无需额外 visibilitychange 处理（状态机已同步 deep-idle）。
 *
 * 引擎接入范式（替代各引擎私有降频逻辑）：
 *   const { level, resetIdle } = useGlobalIdleScheduler();
 *   const { start, stop } = useFrameGate(level, (dt) => { ...更新+渲染 });
 *   onMounted(start); onBeforeUnmount(stop);
 * =============================================================================
 */

import { watch, onScopeDispose, type Ref } from "vue";
import type { IdleLevel } from "./useGlobalIdleScheduler";

type FrameCallback = (dt: number) => void;

/** 各空闲档位的目标帧间隔（毫秒）；active=0 表示每帧执行 */
const FRAME_INTERVAL_MS: Record<IdleLevel, number> = {
  active: 0,
  settling: 1000 / 30,
  idle: 1000 / 5,
  "deep-idle": 1000 / 1,
};

/** dt 上限（秒）：防挂起恢复后一次性注入超长物理步长 */
const DT_MAX = 0.5;

export interface FrameGate {
  start: () => void;
  stop: () => void;
}

/**
 * 创建统一帧门控驱动的渲染回调。
 *
 * @param level 全局空闲档位（useGlobalIdleScheduler().level）
 * @param callback 每个许可帧调用，入参为真实累积 dt（秒，≤0.5）
 */
export function useFrameGate(
  level: Readonly<Ref<IdleLevel>>,
  callback: FrameCallback,
): FrameGate {
  let rafId = 0;
  let running = false;
  let lastRun = performance.now();

  function loop(now: number): void {
    if (!running) return;
    rafId = requestAnimationFrame(loop);

    const interval = FRAME_INTERVAL_MS[level.value];
    if (now - lastRun < interval) return; // 跳帧：不推进 lastRun → dt 自然累积

    const dt = Math.min((now - lastRun) / 1000, DT_MAX);
    lastRun = now;
    try {
      callback(dt);
    } catch (error) {
      console.error("[FrameGate] Render callback error:", error);
      stop();
    }
  }

  function start(): void {
    if (running) return;
    running = true;
    lastRun = performance.now();
    rafId = requestAnimationFrame(loop);
  }

  function stop(): void {
    running = false;
    if (rafId) cancelAnimationFrame(rafId);
    rafId = 0;
  }

  // 档位切换：重置基准时间，避免降/升档瞬间注入尖峰 dt
  watch(level, () => {
    lastRun = performance.now();
  });

  onScopeDispose(stop);

  return { start, stop };
}
