/*
 * devtools/useOrbDrag.ts — 悬浮球指针拖拽与边缘吸附
 *
 * 分工：本模块只处理指针状态机与松手收敛；视口钳制、吸附目标与持久化
 * 解析由 orb_geometry 提供，避免把可单测的几何逻辑埋进事件回调。
 *
 * 性能约束：仅在拖拽或松手吸附期间启动 rAF；静止后不保留动画帧。
 */
import { onBeforeUnmount, ref, type Ref } from "vue";
import { isSettled, stepSpring } from "../composables/key-tools/floating_physics";
import {
  clampOrbPosition,
  nearestEdgeX,
  type OrbPosition,
  type OrbViewport,
} from "./orb_geometry";

export interface OrbDragOptions {
  /** 球体左上角视口坐标 */
  position: Ref<OrbPosition>;
  /** 当前视口尺寸 */
  viewport: Ref<OrbViewport>;
  /** 系统减弱动效偏好：为真时直接落位，不做弹簧 */
  reducedMotion: Ref<boolean>;
  /** 位移小于阈值时视为点击 */
  onTap: () => void;
  /** 吸附结束后的最终位置，供调用方持久化 */
  onSettled: (position: OrbPosition) => void;
}

/** 点击与拖拽的分界位移（px） */
const TAP_THRESHOLD_PX = 6;

/** 临界阻尼附近的弹簧参数；只服务视觉跟随，不追求物理精确 */
const SPRING_TUNING = { stiffness: 170, damping: 20 };

export function useOrbDrag(options: OrbDragOptions) {
  const dragging = ref(false);

  let pointerId: number | null = null;
  let startX = 0;
  let startY = 0;
  let originX = 0;
  let originY = 0;
  let moved = false;
  /** 拖拽结束后的原生 click 需要被吞掉，避免松手又切换面板 */
  let suppressClick = false;
  let rafId: number | null = null;

  const stopSpring = (): void => {
    if (rafId !== null) {
      cancelAnimationFrame(rafId);
      rafId = null;
    }
  };

  const snapToEdge = (): void => {
    const target = clampOrbPosition(
      {
        x: nearestEdgeX(options.position.value, options.viewport.value),
        y: options.position.value.y,
      },
      options.viewport.value,
    );

    if (options.reducedMotion.value) {
      options.position.value = target;
      options.onSettled(target);
      return;
    }

    let current = { ...options.position.value };
    let velocity = { x: 0, y: 0 };
    let last = performance.now();

    const tick = (now: number): void => {
      const dt = (now - last) / 1000;
      last = now;
      const next = stepSpring(current, velocity, target, SPRING_TUNING, dt);
      current = next.position;
      velocity = next.velocity;
      options.position.value = current;

      if (isSettled(current, velocity, target)) {
        options.position.value = target;
        options.onSettled(target);
        rafId = null;
        return;
      }
      rafId = requestAnimationFrame(tick);
    };

    rafId = requestAnimationFrame(tick);
  };

  const endPointer = (event: PointerEvent, shouldSnap: boolean): void => {
    if (pointerId !== event.pointerId) return;
    const wasMoved = moved;
    pointerId = null;
    dragging.value = false;

    if (!wasMoved) return;

    suppressClick = true;
    /* 原生 click 在 pointerup 之后同步派发；用宏任务复位，避免吞掉下一次真实点击 */
    window.setTimeout(() => {
      suppressClick = false;
    }, 0);

    if (shouldSnap) snapToEdge();
  };

  const onPointerDown = (event: PointerEvent): void => {
    if (event.pointerType === "mouse" && event.button !== 0) return;

    stopSpring();
    pointerId = event.pointerId;
    startX = event.clientX;
    startY = event.clientY;
    originX = options.position.value.x;
    originY = options.position.value.y;
    moved = false;
    dragging.value = true;

    try {
      (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
    } catch {
      /* 指针捕获失败时仍可由元素自身接收事件，不阻断拖拽 */
    }
  };

  const onPointerMove = (event: PointerEvent): void => {
    if (pointerId !== event.pointerId) return;

    const dx = event.clientX - startX;
    const dy = event.clientY - startY;
    if (!moved && Math.hypot(dx, dy) > TAP_THRESHOLD_PX) moved = true;
    if (!moved) return;

    options.position.value = clampOrbPosition(
      { x: originX + dx, y: originY + dy },
      options.viewport.value,
    );
  };

  const onPointerUp = (event: PointerEvent): void => {
    endPointer(event, true);
  };

  const onPointerCancel = (event: PointerEvent): void => {
    if (pointerId !== event.pointerId) return;
    moved = true;
    endPointer(event, true);
  };

  const onClick = (): void => {
    if (suppressClick) {
      suppressClick = false;
      return;
    }
    options.onTap();
  };

  onBeforeUnmount(stopSpring);

  return {
    dragging,
    onPointerDown,
    onPointerMove,
    onPointerUp,
    onPointerCancel,
    onClick,
    stopSpring,
  };
}
