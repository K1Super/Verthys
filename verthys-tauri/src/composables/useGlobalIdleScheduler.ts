/**
 * useGlobalIdleScheduler — 全局空闲状态机（唯一权威源）
 *
 * =============================================================================
 * 【设计定位】第二轮空闲 CPU 治理核心基础设施
 *
 * 四档空闲状态（由无交互时长驱动）：
 *   active    <3s      → 60fps，全部动画正常
 *   settling  3~10s    → 30fps，氛围动画 30fps
 *   idle      10~60s   → 5fps，氛围/状态动画暂停
 *   deep-idle >60s     → 1fps，全部暂停，背景低帧率维持
 *
 * 状态切换信号：
 *   - 交互事件（pointermove/pointerdown/keydown/wheel/touchstart）→ 立即 active
 *   - 页面隐藏（visibilitychange → hidden）→ 直接 deep-idle（rAF 天然停帧）
 *   - 窗口失焦（blur）→ deep-idle；重新聚焦（focus）→ active
 *     （保留原各引擎的 blur 暂停行为，收归唯一权威源统一管理）
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

import { ref, readonly, type Ref } from "vue";

export type IdleLevel = "active" | "settling" | "idle" | "deep-idle";

/** 状态跃迁阈值（自最近一次交互起算，毫秒） */
const THRESHOLDS = {
  settling: 3_000,
  idle: 10_000,
  "deep-idle": 60_000,
} as const;

/** 触发 active 的交互事件集（passive，零阻断） */
const ACTIVITY_EVENTS: (keyof WindowEventMap)[] = [
  "pointermove",
  "pointerdown",
  "keydown",
  "wheel",
  "touchstart",
];

/* ---------- 单例状态 ---------- */
const level = ref<IdleLevel>("active");
const lastActivityTime = ref(0);
let timers: number[] = [];
let installed = false;
let reducedMotionQuery: MediaQueryList | null = null;

function clearTimers(): void {
  timers.forEach((t) => window.clearTimeout(t));
  timers = [];
}

/** 自当前时刻重排三档跃迁定时器（幂等：先清后排） */
function scheduleTransitions(): void {
  clearTimers();
  timers.push(
    window.setTimeout(() => {
      level.value = "settling";
    }, THRESHOLDS.settling),
    window.setTimeout(() => {
      level.value = "idle";
    }, THRESHOLDS.idle),
    window.setTimeout(() => {
      level.value = "deep-idle";
    }, THRESHOLDS["deep-idle"]),
  );
}

/** 任意用户交互 → 立即 active 并重排跃迁（对外亦作 resetIdle 暴露）
 *  ★ 性能根治：pointermove 每秒可触发数百次 — 若每次都写响应式时间戳
 *  并 clear+set 三个跃迁定时器，高频鼠标移动即定时器 churn 卡顿源。
 *  节流 500ms：档位阈值最小 3s，500ms 内的活动偏差无语义影响；
 *  非 active 状态（失焦恢复/降档唤醒）不节流，保证立即满帧。 */
const ACTIVITY_THROTTLE_MS = 500;
let lastHandledActivity = 0;

function onUserActivity(): void {
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

/** 强制重置为 active（引擎转场/穿梭等需要立即满帧的场景 — 绕过节流） */
function forceResetIdle(): void {
  lastHandledActivity = performance.now();
  lastActivityTime.value = performance.now();
  if (level.value !== "active") {
    level.value = "active";
  }
  scheduleTransitions();
}

/** 页面隐藏 → 直接 deep-idle；恢复可见 → 立即 active */
function handleVisibilityChange(): void {
  if (document.hidden) {
    clearTimers();
    level.value = "deep-idle";
  } else {
    onUserActivity();
  }
}

/** 窗口失焦 → deep-idle（原各引擎 blur 暂停行为收归此处）；聚焦 → active */
function handleWindowBlur(): void {
  clearTimers();
  level.value = "deep-idle";
}

function handleWindowFocus(): void {
  onUserActivity();
}

/** prefers-reduced-motion 变更：reduce → 永久 idle；恢复 → active */
function handleReducedMotionChange(e: MediaQueryListEvent | MediaQueryList): void {
  if (e.matches) {
    clearTimers();
    level.value = "idle";
  } else {
    onUserActivity();
  }
}

/** 装配全局监听（幂等，单例生命周期） */
function install(): void {
  if (typeof window === "undefined" || installed) return;
  installed = true;

  ACTIVITY_EVENTS.forEach((e) =>
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
  ACTIVITY_EVENTS.forEach((e) => window.removeEventListener(e, onUserActivity));
  document.removeEventListener("visibilitychange", handleVisibilityChange);
  window.removeEventListener("blur", handleWindowBlur);
  window.removeEventListener("focus", handleWindowFocus);
  reducedMotionQuery?.removeEventListener("change", handleReducedMotionChange);
  reducedMotionQuery = null;
  installed = false;
}
