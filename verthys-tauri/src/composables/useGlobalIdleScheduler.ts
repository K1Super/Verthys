/**
 * useGlobalIdleScheduler — 全局空闲状态机（唯一权威源）
 *
 * =============================================================================
 * 【设计定位】空闲 CPU 治理核心基础设施
 *
 * 四档空闲状态（由无交互时长驱动，默认值可由显示设置调整）：
 *   active    <3s      → 交互态上限（默认 120fps）
 *   settling  3~10s    → 30fps，氛围动画 30fps
 *   idle      10~60s   → 5fps，氛围/状态动画暂停
 *   deep-idle >60s     → 1fps，全部暂停，背景低帧率维持
 *
 * 设置变更：等待阈值或帧率变化时，以最近一次交互时刻为基准重算当前档位
 * 并重排剩余跃迁 —— 不是从当前时刻重排，否则缩短阈值不会立即生效。
 *
 * 状态切换信号：
 *   - 指针/触碰类事件（pointermove/pointerdown/wheel/touchstart）→
 *     两段唤醒：先落 settling（30fps、DPR 1.5），持续活动满 400ms 后升 active
 *   - 键盘事件（keydown）→ 立即 active（可达性语义要求即时满响应）
 *   - 页面隐藏（visibilitychange → hidden）→ 直接 deep-idle（rAF 天然停帧）
 *   - 窗口失焦（blur）→ deep-idle；重新聚焦（focus）→ active
 *     （blur 暂停行为收归唯一权威源统一管理）
 *   - prefers-reduced-motion: reduce → 永久 idle（无障碍偏好，动画静止）
 *
 * 消费方：
 *   - useFrameGate：统一帧门控（所有渲染引擎的 rAF 帧率由本状态驱动）
 *   - App.vue 根节点：挂载 idle-{level} / glass-calm / reduce-motion class
 *     → idle-governance.css 据此暂停 CSS 动画 / 降载毛玻璃
 *   - useSessionTimer：idle 时暂停 1s UI 轮询
 *
 * 单例语义：模块级共享状态，install 幂等；任意组件首次调用时装配监听。
 * =============================================================================
 */

import { ref, readonly, watch, type Ref } from "vue";
import {
  displaySettings,
  idleThresholdsMs,
  resolveIdleLevel,
  type IdleLevel,
  type IdleTier,
} from "../settings/display-settings";

/** 指针/触碰类活动事件（passive，零阻断）— 两段唤醒路径：先 settling 再升温 */
const POINTER_ACTIVITY_EVENTS: (keyof WindowEventMap)[] = [
  "pointermove",
  "pointerdown",
  "wheel",
  "touchstart",
];

/** 键盘活动事件（passive，零阻断）— 即时 active 路径 */
const KEY_ACTIVITY_EVENTS: (keyof WindowEventMap)[] = ["keydown"];

/* ---------- 单例状态 ---------- */
const level = ref<IdleLevel>("active");
const lastActivityTime = ref(0);
let timers: number[] = [];
let installed = false;
let reducedMotionQuery: MediaQueryList | null = null;
/** 窗口失焦标记：设置变更重算时不得把失焦窗口拉回 active */
let windowBlurred = false;
/** 减少动态偏好：档位固定 idle，设置变更不参与重算 */
let reducedMotionActive = false;
/** 设置订阅句柄（install 装配 / dispose 注销） */
let stopSettingsWatch: (() => void) | null = null;

function clearTimers(): void {
  timers.forEach((t) => window.clearTimeout(t));
  timers = [];
}

/**
 * 按「上次交互时刻」重排三档跃迁（幂等：先清后排）。
 * 剩余延迟以已过时长为基准，缩短阈值时到期的档位立即触发；
 * 全部阈值均已越过时三个定时器按 0ms 依次执行，最终落最深档位。
 */
function scheduleTransitions(): void {
  clearTimers();
  const thresholds = idleThresholdsMs();
  const elapsed = Math.max(0, performance.now() - lastActivityTime.value);
  const remaining: Array<[IdleTier, number]> = [
    ["settling", thresholds.settling - elapsed],
    ["idle", thresholds.idle - elapsed],
    ["deep-idle", thresholds["deep-idle"] - elapsed],
  ];
  for (const [tier, delay] of remaining) {
    /* 已越过的档位由 resolveIdleLevel 直接落定，不再排 0ms 定时器：
       避免同一 tick 内连续改写档位造成无意义的重复通知 */
    if (delay <= 0) continue;
    timers.push(
      window.setTimeout(() => {
        level.value = tier;
      }, delay),
    );
  }
}

/**
 * 设置变更后的档位重算：
 *   - 窗口失焦 / 页面隐藏 / 减少动态偏好下不改变当前档位
 *   - 唤醒升温窗口内保持两段唤醒语义，只重排后续跃迁
 *   - 其余情况按经过时长解析应处档位，再重排剩余跃迁
 */
function resyncFromSettings(): void {
  if (!installed || reducedMotionActive || windowBlurred || document.hidden) return;
  if (wakeRampTimer !== null) {
    scheduleTransitions();
    return;
  }
  const elapsed = Math.max(0, performance.now() - lastActivityTime.value);
  level.value = resolveIdleLevel(elapsed);
  scheduleTransitions();
}

/** 活动节流窗口（毫秒）：active 态下高频事件（pointermove 为主）仅每
 *  500ms 处理一次 — 档位阈值最小 1s，窗口内的活动偏差无语义影响；
 *  非 active 态不节流（唤醒路径即时落档）。 */
const ACTIVITY_THROTTLE_MS = 500;
let lastHandledActivity = 0;

/** 指针类唤醒升温时长（毫秒）：settling 持续活动满此时长后升 active */
const WAKE_RAMP_MS = 400;
/** 升温一次性定时器（每次唤醒流程只排一次，句柄供取消） */
let wakeRampTimer: number | null = null;

/** 取消未决的升温定时器（页面隐藏/窗口失焦/卸载时随迁跃定时器一并清理） */
function cancelWakeRamp(): void {
  if (wakeRampTimer !== null) {
    window.clearTimeout(wakeRampTimer);
    wakeRampTimer = null;
  }
}

/** 键盘类交互 / 聚焦恢复 / 可见性恢复 → 立即 active 并重排跃迁 */
function onUserActivity(): void {
  /* 减少动态偏好 / 失焦 / 页面隐藏下不唤醒：降档语义优先 */
  if (reducedMotionActive || windowBlurred || document.hidden) return;
  const now = performance.now();
  if (level.value === "active" && now - lastHandledActivity < ACTIVITY_THROTTLE_MS) {
    return; // 已 active 且刚处理过 → 跳过（定时器仍按上次活动时刻排布）
  }
  lastHandledActivity = now;
  lastActivityTime.value = now;
  if (level.value !== "active") {
    level.value = "active";
  }
  scheduleTransitions();
}

/** 指针/触碰类交互 → 两段唤醒：先落 settling，再经一次性定时器于
 *  WAKE_RAMP_MS 后升 active。交互首毫秒不再直冲满帧，避免唤醒满配与
 *  用户操作同帧叠加 GPU 尖峰。节流语义与 onUserActivity 共享：
 *  active 态高频事件每 500ms 处理一次；非 active 态不节流。 */
function onPointerActivity(): void {
  /* 减少动态偏好 / 失焦 / 页面隐藏下不参与两段唤醒（与 onUserActivity 同一门控） */
  if (reducedMotionActive || windowBlurred || document.hidden) return;
  const now = performance.now();
  if (level.value === "active") {
    if (now - lastHandledActivity < ACTIVITY_THROTTLE_MS) return;
  }
  lastHandledActivity = now;
  lastActivityTime.value = now;
  if (level.value !== "active" && level.value !== "settling") {
    level.value = "settling";
  }
  scheduleTransitions();
  if (level.value !== "active" && wakeRampTimer === null) {
    wakeRampTimer = window.setTimeout(() => {
      wakeRampTimer = null;
      if (level.value !== "active") {
        level.value = "active";
      }
    }, WAKE_RAMP_MS);
  }
}

/** 强制重置为 active（引擎转场/穿梭等需要立即满帧的场景 — 绕过节流） */
/** 强制重置为 active（引擎转场/穿梭等需要立即满帧的场景 — 绕过节流）
 *  失焦 / 页面隐藏 / 减少动态偏好下拒绝唤醒：这三种状态的降档语义优先 */
function forceResetIdle(): void {
  if (reducedMotionActive || windowBlurred || document.hidden) return;
  lastHandledActivity = performance.now();
  lastActivityTime.value = performance.now();
  if (level.value !== "active") {
    level.value = "active";
  }
  scheduleTransitions();
}

/** 页面隐藏 → 直接 deep-idle；恢复可见 → 立即 active（减少动态偏好回落 idle） */
function handleVisibilityChange(): void {
  if (document.hidden) {
    clearTimers();
    cancelWakeRamp();
    level.value = "deep-idle";
  } else if (reducedMotionActive) {
    level.value = "idle";
  } else {
    onUserActivity();
  }
}

/** 窗口失焦 → deep-idle（失焦暂停行为统一由此处管理）；聚焦 → active */
function handleWindowBlur(): void {
  windowBlurred = true;
  clearTimers();
  cancelWakeRamp();
  level.value = "deep-idle";
}

function handleWindowFocus(): void {
  windowBlurred = false;
  /* 减少动态偏好下失焦已落 deep-idle，聚焦必须回到 idle 基线，
     不能让界面停在 1fps（键盘与可访问性交互仍需可用） */
  if (reducedMotionActive) {
    level.value = "idle";
    return;
  }
  onUserActivity();
}

/** prefers-reduced-motion 变更：reduce → 永久 idle；恢复 → active */
function handleReducedMotionChange(e: MediaQueryListEvent | MediaQueryList): void {
  reducedMotionActive = e.matches;
  if (e.matches) {
    clearTimers();
    /* 未决升温定时器必须一并取消，否则 400ms 后仍会把档位拉回 active */
    cancelWakeRamp();
    level.value = "idle";
  } else {
    onUserActivity();
  }
}

/** 装配全局监听（幂等，单例生命周期） */
function install(): void {
  if (typeof window === "undefined" || installed) return;
  installed = true;

  POINTER_ACTIVITY_EVENTS.forEach((e) =>
    window.addEventListener(e, onPointerActivity, { passive: true }),
  );
  KEY_ACTIVITY_EVENTS.forEach((e) =>
    window.addEventListener(e, onUserActivity, { passive: true }),
  );

  document.addEventListener("visibilitychange", handleVisibilityChange);
  window.addEventListener("blur", handleWindowBlur);
  window.addEventListener("focus", handleWindowFocus);

  reducedMotionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  handleReducedMotionChange(reducedMotionQuery);
  reducedMotionQuery.addEventListener("change", handleReducedMotionChange);

  // 装配即视为一次交互：应用启动后从 active 开始完整走完四档
  onUserActivity();

  /* 设置变更实时重排：同步 flush，阈值缩短在同一交互帧内立即生效 */
  stopSettingsWatch = watch(displaySettings, resyncFromSettings, { flush: "sync" });
}

export interface GlobalIdleScheduler {
  /** 当前空闲档位（只读响应式） */
  level: Readonly<Ref<IdleLevel>>;
  /** 强制重置为 active（引擎转场/穿梭等需要立即满帧的场景调用） */
  resetIdle: () => void;
  /** 最近一次交互时间戳（performance.now 基准，只读响应式） */
  lastActivityTime: Readonly<Ref<number>>;
}

/** 获取全局空闲状态机（单例；首次调用装配监听） */
export function useGlobalIdleScheduler(): GlobalIdleScheduler {
  install();
  return {
    level: readonly(level),
    resetIdle: forceResetIdle,
    lastActivityTime: readonly(lastActivityTime),
  };
}

/** 卸载全局监听（测试 / 应用 teardown 场景） */
export function disposeGlobalIdleScheduler(): void {
  if (!installed) return;
  clearTimers();
  cancelWakeRamp();
  POINTER_ACTIVITY_EVENTS.forEach((e) => window.removeEventListener(e, onPointerActivity));
  KEY_ACTIVITY_EVENTS.forEach((e) => window.removeEventListener(e, onUserActivity));
  document.removeEventListener("visibilitychange", handleVisibilityChange);
  window.removeEventListener("blur", handleWindowBlur);
  window.removeEventListener("focus", handleWindowFocus);
  reducedMotionQuery?.removeEventListener("change", handleReducedMotionChange);
  reducedMotionQuery = null;
  stopSettingsWatch?.();
  stopSettingsWatch = null;
  windowBlurred = false;
  reducedMotionActive = false;
  installed = false;
}
