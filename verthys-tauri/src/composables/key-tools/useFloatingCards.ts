/**
 * key-tools/useFloatingCards.ts — 漂浮卡片控制器
 *
 * 职责：把三张卡片注册到同一舞台，负责拖拽、惯性收敛、越界钳制、邻近推挤、
 * 层序提升与复位；位置只在 rAF 中写入 transform，不进入 Vue 响应式。
 *
 * 关键约束：
 * - 拖拽面覆盖整张卡片的非交互区域（留白、标题、标签、刻度条）：按钮、输入框、
 *   滑杆、复选框标签与 role=button 的显示区保留原生语义，控制器不抢事件。
 * - 卡片只做整设备像素的纯 2D 平移：卡片子树内不得出现缩放、旋转、透视或纵深。
 *   这些变换会让合成器对文字栅格做双线性重采样，静止态就会发虚，拖拽时更明显。
 * - 只写 transform 与 zIndex；不写 filter/box-shadow，避免每帧重栅格化。
 * - 合成层按需提升：仅在拖拽 / 惯性 / 推挤期间临时写 will-change: transform，
 *   静止即撤销，常态保留桌面端完整文字抗锯齿（次像素渲染）。
 * - 静止后立即停机（rAF 不再重排）；卡片不再做常驻 transform 漂移。
 * - 位置不持久化：组件卸载后不保留任何布局状态。
 * - 舞台宽度低于移动断点时完全让位给 CSS 单列布局，不再写 transform。
 */

import { onMounted, onScopeDispose, ref, type Ref } from "vue";
import {
  clampToBounds,
  clampVelocity,
  isSettled,
  stepSpring,
  type Vec2,
} from "./floating_physics";

/** 卡片在舞台中的静止参数（以舞台中心为基准的像素偏移，保证任意尺寸下层叠关系不变） */
export interface FloatingCardSpec {
  /** 稳定标识（与模板注册名一致） */
  key: string;
  /** 相对舞台中心线的水平偏移（px，负值偏左） */
  xOffset: number;
  /** 相对舞台中心线的垂直偏移（px，负值偏上） */
  yOffset: number;
  /** 静止层序 */
  zIndex: number;
}

/** 控制器对外接口 */
export interface FloatingCardsApi {
  /** 舞台元素引用（模板 ref） */
  stageRef: Ref<HTMLElement | null>;
  /** 卡片注册函数（模板 ref 回调） */
  registerCard: (key: string, el: HTMLElement | null) => void;
}

/** 舞台内边距：卡片任何时刻不得贴边或越界 */
const STAGE_INSET = 8;
/** 弹簧：刚度 180 / 阻尼 26，阻尼比约 0.97，收敛快且无持续振荡 */
const SPRING = { stiffness: 180, damping: 26 };
/** 释放惯性滑行系数：目标点 = 落点 + 释放速度 × 该系数 */
const COAST_FACTOR = 0.16;
/** 释放速度上限（px/s） */
const MAX_RELEASE_SPEED = 1200;
/** 邻近推挤的感知半径（px） */
const PUSH_RADIUS = 420;
/** 邻近推挤比例 */
const PUSH_FACTOR = 0.12;
/** 推挤位移衰减速率（1/s） */
const PUSH_DECAY = 6;
/** 舞台低于任一断点时让位给 CSS 文档流布局（与样式层同一媒体条件） */
const FLOW_QUERY = "(max-width: 680px), (max-height: 700px)";
/** 这些命中的区域保有原生交互语义（点击、输入、勾选、滑杆），不得被拖拽抢占 */
const INTERACTIVE_SELECTOR =
  "button, a, input, select, textarea, label, [role='button'], [role='slider'], [contenteditable='true']";

const ZERO: Vec2 = { x: 0, y: 0 };

/** 一张卡片的事件句柄（同一引用用于挂载与卸载，避免匿名闭包导致监听泄漏） */
interface CardHandlers {
  down: (event: PointerEvent) => void;
  move: (event: PointerEvent) => void;
  up: (event: PointerEvent) => void;
  key: (event: KeyboardEvent) => void;
}

interface CardState {
  spec: FloatingCardSpec;
  el: HTMLElement | null;
  /** 键盘入口（头部）：指针监听挂在整卡上，它只负责方向键与焦点 */
  handle: HTMLElement | null;
  handlers: CardHandlers | null;
  home: Vec2;
  pos: Vec2;
  vel: Vec2;
  target: Vec2;
  push: Vec2;
  dragging: boolean;
  settling: boolean;
  pointerId: number | null;
  grabPointer: Vec2;
  grabBase: Vec2;
  lastMoveMs: number;
  initialized: boolean;
  /** 当前是否以 transform 合成层定位（移动期）；静止时改为 left/top 落位 */
  composited: boolean;
}

/**
 * 创建漂浮卡片控制器。
 *
 * @param specs 三张卡片的静止参数（顺序仅决定注册表顺序）
 * @returns 舞台引用与注册函数；组件卸载时自动清理监听与 rAF
 */
export function useFloatingCards(specs: readonly FloatingCardSpec[]): FloatingCardsApi {
  const stageRef = ref<HTMLElement | null>(null);
  const cards: CardState[] = specs.map((spec) => ({
    spec,
    el: null,
    handle: null,
    handlers: null,
    home: { ...ZERO },
    pos: { ...ZERO },
    vel: { ...ZERO },
    target: { ...ZERO },
    push: { ...ZERO },
    dragging: false,
    settling: false,
    pointerId: null,
    grabPointer: { ...ZERO },
    grabBase: { ...ZERO },
    lastMoveMs: 0,
    initialized: false,
    composited: false,
  }));

  let rafId = 0;
  let lastFrameMs = 0;
  let reduced = false;
  let resizeObserver: ResizeObserver | null = null;
  const motionQuery = typeof window !== "undefined"
    ? window.matchMedia("(prefers-reduced-motion: reduce)")
    : null;
  const flowQuery = typeof window !== "undefined" ? window.matchMedia(FLOW_QUERY) : null;

  /** 是否处于文档流兜底布局：此状态下不写 transform、不接受拖拽 */
  const inFlow = (): boolean => flowQuery?.matches ?? false;

  const syncReduced = (): void => {
    reduced = motionQuery?.matches ?? false;
  };

  const stageSize = (): { w: number; h: number } => ({
    w: stageRef.value?.clientWidth ?? 0,
    h: stageRef.value?.clientHeight ?? 0,
  });

  /** 卡片视觉盒与布局盒一致（无缩放/旋转/透视），边界只按偏移尺寸与舞台内边距计算 */
  const boundsFor = (card: CardState) => {
    const { w, h } = stageSize();
    const cardW = card.el?.offsetWidth ?? 0;
    const cardH = card.el?.offsetHeight ?? 0;
    return {
      minX: STAGE_INSET,
      minY: STAGE_INSET,
      maxX: Math.max(STAGE_INSET, w - cardW - STAGE_INSET),
      maxY: Math.max(STAGE_INSET, h - cardH - STAGE_INSET),
    };
  };

  /**
   * 位移吸附到设备像素栅格后再写入 transform。
   * 合成器对非整数位移按双线性重采样，卡片里的文字会整体发虚并随移动闪烁；
   * 吸附到 devicePixelRatio 栅格（如 125% 缩放下为 1/1.25px）可让每帧都落在
   * 真实物理像素上。卡片本身不做任何缩放 / 旋转 / 纵深，栅格恒定 1:1。
   */
  const snap = (value: number): string => {
    const dpr = typeof window === "undefined" ? 1 : window.devicePixelRatio || 1;
    return `${(Math.round(value * dpr) / dpr).toFixed(3)}px`;
  };

  /**
   * 合成层按需提升：移动期间临时 will-change，静止立即撤销。
   * 常驻合成层会让文字走灰度抗锯齿（桌面端失去 ClearType 次像素渲染），
   * 静止态观感就是"发虚"；移动期间则必须提升，保证整像素平移走 GPU 合成。
   */
  const setAnimating = (card: CardState, on: boolean): void => {
    const el = card.el;
    if (!el) return;
    const next = on ? "transform" : "";
    if (el.style.willChange !== next) el.style.willChange = next;
  };

  /**
   * 写入位置：静止态用 left/top 直接落位，移动态才切到 transform。
   * 只要卡片带 transform（哪怕是整数平移），浏览器就会把它提升为合成层，
   * 文字随之改用灰度抗锯齿——桌面端静止观感即"发虚"。
   * 故静止时清空 transform、以整设备像素的 left/top 定位，保留完整字形渲染；
   * 拖拽 / 惯性 / 推挤期间改走 transform（GPU 合成、整像素吸附、不重采样），
   * 停下后立刻落回 left/top。两种写法在同一帧内切换，位置完全一致，不产生跳动。
   */
  const render = (card: CardState): void => {
    const el = card.el;
    if (!el) return;
    if (inFlow()) {
      el.style.transform = "";
      el.style.left = "0px";
      el.style.top = "0px";
      card.composited = false;
      return;
    }
    const x = snap(card.pos.x + card.push.x);
    const y = snap(card.pos.y + card.push.y);
    const moving = card.dragging || card.settling
      || card.push.x !== 0 || card.push.y !== 0;
    if (moving) {
      el.style.transform = `translate(${x}, ${y})`;
      if (!card.composited || el.style.left !== "0px") {
        el.style.left = "0px";
        el.style.top = "0px";
      }
      card.composited = true;
      return;
    }
    if (card.composited) {
      el.style.transform = "";
      card.composited = false;
    }
    el.style.left = x;
    el.style.top = y;
  };

  /** 依据舞台尺寸重算静止位；已初始化卡片保留当前落点并钳制回可放置区域 */
  const layout = (): void => {
    const { w, h } = stageSize();
    if (!w || !h) return;
    for (const card of cards) {
      const el = card.el;
      if (!el) continue;
      const cardW = el.offsetWidth;
      const cardH = el.offsetHeight;
      // 以舞台中心为基准的像素偏移：任意视口下三卡的层叠量与重叠带保持不变，
      // 只整体居中浮动，不会因窗口变高而散开成规则的三行网格。
      const x = w / 2 + card.spec.xOffset - cardW / 2;
      const y = h / 2 + card.spec.yOffset - cardH / 2;
      card.home = clampToBounds({ x, y }, boundsFor(card));
      if (!card.initialized) {
        card.pos = { ...card.home };
        card.initialized = true;
      } else {
        card.pos = clampToBounds(card.pos, boundsFor(card));
      }
      card.target = { ...card.pos };
      render(card);
    }
  };

  const startLoop = (): void => {
    if (rafId !== 0) return;
    lastFrameMs = 0;
    rafId = requestAnimationFrame(frame);
  };

  const stopLoop = (): void => {
    if (rafId === 0) return;
    cancelAnimationFrame(rafId);
    rafId = 0;
    lastFrameMs = 0;
  };

  /** 单卡推进一帧；返回是否仍需下一帧 */
  const stepCard = (card: CardState, dt: number): boolean => {
    let active = false;

    // 邻近推挤只做衰减，不做持续扰动
    const decay = Math.exp(-dt * PUSH_DECAY);
    card.push.x *= decay;
    card.push.y *= decay;
    if (Math.abs(card.push.x) > 0.2 || Math.abs(card.push.y) > 0.2) active = true;
    else card.push = { ...ZERO };

    if (!card.dragging && card.settling) {
      const next = stepSpring(card.pos, card.vel, card.target, SPRING, dt);
      card.pos = clampToBounds(next.position, boundsFor(card));
      card.vel = next.velocity;
      if (isSettled(card.pos, card.vel, card.target)) {
        card.pos = { ...card.target };
        card.vel = { ...ZERO };
        card.settling = false;
      } else {
        active = true;
      }
    }

    render(card);
    // 移动期间提升为合成层；停止（含推挤衰减结束）即撤销，恢复静止态文字渲染
    setAnimating(card, card.dragging || active);
    return active;
  };

  const frame = (now: number): void => {
    rafId = 0;
    const dt = lastFrameMs ? Math.min((now - lastFrameMs) / 1000, 1 / 30) : 1 / 60;
    lastFrameMs = now;
    let active = false;
    for (const card of cards) {
      if (!card.el) continue;
      active = stepCard(card, dt) || active;
    }
    if (active) {
      rafId = requestAnimationFrame(frame);
    } else {
      lastFrameMs = 0;
    }
  };

  /** 拖拽就像在推移水面：邻近卡片获得一份随距离衰减的同向位移 */
  const pushNeighbours = (source: CardState, dx: number, dy: number): void => {
    const sourceEl = source.el;
    if (!sourceEl) return;
    const sx = source.pos.x + sourceEl.offsetWidth / 2;
    const sy = source.pos.y + sourceEl.offsetHeight / 2;
    for (const other of cards) {
      if (other === source || !other.el) continue;
      const ox = other.pos.x + other.el.offsetWidth / 2;
      const oy = other.pos.y + other.el.offsetHeight / 2;
      const distance = Math.hypot(sx - ox, sy - oy);
      const falloff = Math.max(0, 1 - distance / PUSH_RADIUS) * PUSH_FACTOR;
      if (falloff <= 0) continue;
      other.push.x += dx * falloff;
      other.push.y += dy * falloff;
    }
  };

  const onPointerDown = (card: CardState) => (event: PointerEvent): void => {
    if (event.button !== 0 || inFlow() || card.dragging) return;
    const target = event.target;
    if (!(target instanceof Element) || target.closest(INTERACTIVE_SELECTOR)) return;
    card.dragging = true;
    card.settling = false;
    card.vel = { ...ZERO };
    card.pointerId = event.pointerId;
    card.grabPointer = { x: event.clientX, y: event.clientY };
    card.grabBase = { ...card.pos };
    card.lastMoveMs = performance.now();
    card.el?.classList.add("is-grabbed");
    if (card.el) {
      card.el.style.zIndex = "40";
      setAnimating(card, true);
    }
    card.el?.setPointerCapture(event.pointerId);
  };

  const onPointerMove = (card: CardState) => (event: PointerEvent): void => {
    if (!card.dragging || event.pointerId !== card.pointerId) return;
    const bounds = boundsFor(card);
    const next = clampToBounds({
      x: card.grabBase.x + (event.clientX - card.grabPointer.x),
      y: card.grabBase.y + (event.clientY - card.grabPointer.y),
    }, bounds);
    const dx = next.x - card.pos.x;
    const dy = next.y - card.pos.y;
    if (dx !== 0 || dy !== 0) pushNeighbours(card, dx, dy);
    card.pos = next;

    // 速度仍按时间归一并做指数平滑：释放瞬间的惯性由它决定，但不再驱动逐帧倾角
    const now = performance.now();
    const elapsed = Math.max(1, now - card.lastMoveMs) / 1000;
    card.vel.x = card.vel.x * 0.65 + (dx / elapsed) * 0.35;
    card.vel.y = card.vel.y * 0.65 + (dy / elapsed) * 0.35;
    card.lastMoveMs = now;
    startLoop();
  };

  const onPointerUp = (card: CardState) => (event: PointerEvent): void => {
    if (!card.dragging || event.pointerId !== card.pointerId) return;
    card.dragging = false;
    card.pointerId = null;
    card.el?.classList.remove("is-grabbed");
    if (card.el) card.el.style.zIndex = String(card.spec.zIndex);

    const coast = clampVelocity(card.vel, MAX_RELEASE_SPEED);
    card.target = clampToBounds({
      x: card.pos.x + coast.x * COAST_FACTOR,
      y: card.pos.y + coast.y * COAST_FACTOR,
    }, boundsFor(card));

    if (reduced) {
      card.pos = { ...card.target };
      card.vel = { ...ZERO };
      card.settling = false;
      render(card);
      setAnimating(card, false);
    } else {
      card.vel = coast;
      card.settling = true;
      startLoop();
    }
    if (card.el?.hasPointerCapture?.(event.pointerId)) {
      card.el.releasePointerCapture(event.pointerId);
    }
  };

  /** 键盘等价操作：方向键微调（Shift 加速），Escape 复位该卡 */
  const onKeyDown = (card: CardState) => (event: KeyboardEvent): void => {
    if (inFlow()) return;
    if (event.key === "Escape") {
      event.preventDefault();
      cardsReset([card]);
      return;
    }
    const step = event.shiftKey ? 48 : 12;
    const dx = event.key === "ArrowLeft" ? -step : event.key === "ArrowRight" ? step : 0;
    const dy = event.key === "ArrowUp" ? -step : event.key === "ArrowDown" ? step : 0;
    if (dx === 0 && dy === 0) return;
    event.preventDefault();
    const bounds = boundsFor(card);
    card.pos = clampToBounds({ x: card.pos.x + dx, y: card.pos.y + dy }, bounds);
    card.target = { ...card.pos };
    card.vel = { ...ZERO };
    card.settling = false;
    render(card);
  };

  const attach = (card: CardState): void => {
    const el = card.el;
    if (!el) return;
    // 指针监听挂在整卡：留白、标题、标签、刻度条都能起拖；交互控件由命中选择器排除
    const handlers: CardHandlers = {
      down: onPointerDown(card),
      move: onPointerMove(card),
      up: onPointerUp(card),
      key: onKeyDown(card),
    };
    card.handlers = handlers;
    el.style.zIndex = String(card.spec.zIndex);
    el.style.willChange = "";
    el.addEventListener("pointerdown", handlers.down);
    el.addEventListener("pointermove", handlers.move);
    el.addEventListener("pointerup", handlers.up);
    el.addEventListener("pointercancel", handlers.up);
    card.handle = el.querySelector<HTMLElement>("[data-drag-handle]");
    card.handle?.addEventListener("keydown", handlers.key);
  };

  const detach = (card: CardState): void => {
    const el = card.el;
    const handlers = card.handlers;
    if (el && handlers) {
      el.removeEventListener("pointerdown", handlers.down);
      el.removeEventListener("pointermove", handlers.move);
      el.removeEventListener("pointerup", handlers.up);
      el.removeEventListener("pointercancel", handlers.up);
      card.handle?.removeEventListener("keydown", handlers.key);
    }
    card.handle = null;
    card.handlers = null;
  };

  const cardsReset = (targets: readonly CardState[]): void => {
    for (const card of targets) {
      card.dragging = false;
      card.pointerId = null;
      card.vel = { ...ZERO };
      card.push = { ...ZERO };
      card.el?.classList.remove("is-grabbed");
      if (card.el) card.el.style.zIndex = String(card.spec.zIndex);
      if (reduced) {
        card.pos = { ...card.home };
        card.target = { ...card.home };
        card.settling = false;
        render(card);
        setAnimating(card, false);
      } else {
        card.target = { ...card.home };
        card.settling = true;
      }
    }
    if (!reduced) startLoop();
  };

  const registerCard = (key: string, el: HTMLElement | null): void => {
    const card = cards.find((item) => item.spec.key === key);
    if (!card) return;
    if (card.el !== el) {
      detach(card);
      card.el = el;
      card.initialized = false;
      if (el) attach(card);
    }
    if (!el) detach(card);
  };

  onMounted(() => {
    syncReduced();
    motionQuery?.addEventListener("change", syncReduced);
    if (stageRef.value) {
      resizeObserver = new ResizeObserver(() => layout());
      resizeObserver.observe(stageRef.value);
    }
    layout();
    for (const card of cards) card.el?.classList.add("is-ready");
  });

  onScopeDispose(() => {
    stopLoop();
    resizeObserver?.disconnect();
    resizeObserver = null;
    motionQuery?.removeEventListener("change", syncReduced);
    for (const card of cards) detach(card);
  });

  return { stageRef, registerCard };
}
