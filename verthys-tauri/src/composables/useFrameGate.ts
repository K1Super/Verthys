/**
 * useFrameGate — 帧门控注册层（全应用渲染引擎共用的主循环接入接口）
 *
 * =============================================================================
 * 【设计定位】统一帧门控：帧率调度的唯一执行层已收归主渲染循环
 *
 * 本模块是引擎接入主渲染循环的声明式封装：
 *   - 不自开 rAF —— start/stop 即向 master-frame-loop 注册 / 注销一个
 *     throttled 任务（跟随全局空闲档位 60 / 30 / 5 / 1 fps 节流）；
 *   - 回调签名升级为双时间参数（引擎按需取用，可忽略其一）：
 *       frameStep —— 距上一许可帧的累积时长（钳制上限 50ms），物理积分专用；
 *       wallClock —— 真实经过时间（秒，不钳制），进度计算专用；
 *   - 级联清理：作用域销毁自动注销（onScopeDispose），组件无需手动 stop。
 *
 * 帧步进语义由主循环保证：跳过的帧不推进基准时刻 → 下一许可帧获得
 * 真实累积 frameStep；钳制上限防挂起恢复后一次性注入超长物理步长。
 *
 * 引擎接入范式（替代各引擎私有 rAF 循环）：
 *   const { level } = useGlobalIdleScheduler();
 *   const { start, stop } = useFrameGate(level, (frameStep, wallClock) => {
 *     ...物理积分用 frameStep；进度/采样统计用 wallClock...
 *   });
 *   onMounted(start); onBeforeUnmount(stop);
 * =============================================================================
 */

import { onScopeDispose, type Ref } from "vue";
import type { IdleLevel } from "./useGlobalIdleScheduler";
import { masterFrameLoop } from "../core/master-frame-loop";

/** 帧门控回调：双时间参数（帧步进 / 墙钟），单位均为秒 */
export type FrameGateCallback = (frameStep: number, wallClock: number) => void;

export interface FrameGate {
  start: () => void;
  stop: () => void;
}

/**
 * 创建帧门控驱动的渲染回调（主渲染循环 throttled 任务注册层）。
 *
 * @param level 全局空闲档位（useGlobalIdleScheduler().level）——
 *   节流档位由主循环统一裁决，此处保留引用仅为 API 兼容与语义清晰
 * @param callback 每个许可帧调用；frameStep 为钳制累积时长（秒），
 *   wallClock 为真实时间（秒）
 */
export function useFrameGate(
  _level: Readonly<Ref<IdleLevel>>,
  callback: FrameGateCallback,
): FrameGate {
  let unregister: (() => void) | null = null;

  function start(): void {
    if (unregister) return;
    unregister = masterFrameLoop.register(
      (ctx) => callback(ctx.frameStep, ctx.wallClock),
      { type: "throttled" },
    );
  }

  function stop(): void {
    if (unregister) {
      unregister();
      unregister = null;
    }
  }

  onScopeDispose(stop);

  return { start, stop };
}