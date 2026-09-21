/*
 * frame-gate.ts — 帧门控全局配置（单一权威源）
 *
 * 四档帧率间隔 / 档位 DPR / 粒子密度 / 残影层可见性 / 帧步进钳制上限 /
 * 豁免时长上限 / DPR 切换防抖全部集中于此。
 * 运行时模块（主循环 / 帧门控注册层 / 粒子背景）按需导入，
 * 禁止在组件内散落硬编码档位参数。
 */

import type { IdleLevel } from "../composables/useGlobalIdleScheduler";

/** 四档目标帧间隔（ms）；active = 0 表示每帧执行 */
export const FRAME_INTERVAL_MS: Record<IdleLevel, number> = {
  active: 0,
  settling: 1000 / 30,
  idle: 1000 / 5,
  "deep-idle": 1000 / 1,
};

/**
 * 四档 DPR（渲染分辨率倍率）。
 * active 为 null = 跟随设备上限 min(devicePixelRatio, 2) 满配；
 * 其余档位为固定降分辨率值（GPU 填充率按面积平方下降）。
 */
export const DPR_BY_LEVEL: Record<IdleLevel, number | null> = {
  active: null,
  settling: 1.5,
  idle: 1.0,
  "deep-idle": 1.0,
};

/** 设备 DPR 上限（active 档满配时的钳制值） */
export const MAX_DEVICE_DPR = 2;

/** 四档粒子密度（空闲档降载通道；与帧预算降级密度取更小值生效） */
export const DENSITY_BY_IDLE: Record<IdleLevel, number> = {
  active: 1,
  settling: 1,
  idle: 0.8,
  "deep-idle": 0.8,
};

/** 帧步进钳制上限（ms）——物理积分单步上限，长帧不过冲 */
export const MAX_FRAME_STEP_MS = 50;

/** 豁免时长上限（ms）——超时强制释放，防御性兜底（正常路径主动释放） */
export const MAX_EXEMPT_DURATION_MS = 1500;

/** DPR 档位切换防抖（ms）——档位变化后延迟应用，避免频繁重设帧缓冲 */
export const DPR_SWITCH_DEBOUNCE_MS = 200;

/** 残影层档位可见性：active / settling 开，idle / deep-idle 隐藏（静止态降 draw call） */
export const TRAIL_VISIBLE_BY_LEVEL: Record<IdleLevel, boolean> = {
  active: true,
  settling: true,
  idle: false,
  "deep-idle": false,
};

/** 渡越激活阈值：warpEnv 跨越此值视为渡越开始 / 结束（残影可见性与豁免联动锚点） */
export const TRANSITION_ACTIVE_THRESHOLD = 0.01;

/** 豁免降级档（degraded 状态下的目标帧间隔 ms —— 低于 active 一档） */
export const EXEMPT_DEGRADED_INTERVAL_MS = 1000 / 30;