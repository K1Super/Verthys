/**
 * useCosmicBackground — 宇宙交响曲氛围背景数据与视差逻辑
 *
 * 职责：
 *   1. 鼠标视差追踪（三层深度：远 5px / 中 15px / 近 30px，主循环
 *      逐帧排程缓动 — once 泵循环，收敛自停）
 *   2. 三层星场数据（远 38 颗 / 中 22 颗 / 近 14 颗）
 *   3. 宇宙尘埃微粒（50 颗缓慢漂移）
 *   4. 星座连线（9 颗主星 + 10 条连线）
 *
 * 从 MainView.vue 抽离，功能 100% 保留。
 *
 * 性能优化（CosmicBackground 统一帧驱动）：
 *   星点/尘埃不再携带 CSS animationDelay / animationDuration，
 *   改为输出数值相位（phase ∈ [0,1) 归一化相位偏移）与周期（dur，秒），
 *   由 CosmicBackground.vue 内的统一帧驱动引擎读取 data-phase / data-dur 驱动，
 *   消除 174 个独立 CSS 动画的逐元素动画调度开销。
 */

import { ref, onBeforeUnmount } from "vue";
import { masterFrameLoop } from "../core/master-frame-loop";

/** 星点条目：style 仅承载几何/颜色；phase/dur 由统一帧驱动引擎消费 */
export interface CosmicStar {
  id: string;
  style: Record<string, string>;
  /** 归一化相位偏移 ∈ [0,1)，等效原 animationDelay */
  phase: number;
  /** 闪烁周期（秒），等效原 animationDuration */
  dur: number;
}

/** 尘埃微粒条目：同 CosmicStar 语义 + 逐粒独立漂移向量（拒绝同向同步） */
export interface CosmicDust {
  id: number;
  style: Record<string, string>;
  phase: number;
  dur: number;
  /** 漂移向量 x（px/周期 — 逐粒差化方向与速率） */
  vx: number;
  /** 漂移向量 y（px/周期 — 上扬分量） */
  vy: number;
  /** X 向侧摆幅度（CSS 合成器动画用） */
  swx: number;
}

export function useCosmicBackground() {
  /* ===== 鼠标视差追踪：三层深度（远 5px / 中 15px / 近 30px），主循环排程缓动 ===== */
  const parallaxFar = ref<Record<string, string>>({});
  const parallaxMid = ref<Record<string, string>>({});
  const parallaxNear = ref<Record<string, string>>({});
  /* 泵循环激活标志（once 排程无句柄 — 靠标志自停 / 卸载断泵） */
  let parallaxActive = false;
  let parallaxTargetX = 0;
  let parallaxTargetY = 0;
  let parallaxCurrentX = 0;
  let parallaxCurrentY = 0;

  /* 性能根治：main-view 铺满视口 → 用缓存的视口尺寸归一化，
   * 去掉每次 mousemove 的 getBoundingClientRect 强制布局读取
   * （布局读取会打断渲染流水线，高频移动 = 每帧强制 reflow） */
  let vw = window.innerWidth;
  let vh = window.innerHeight;
  const onViewportResize = () => {
    vw = window.innerWidth;
    vh = window.innerHeight;
  };
  window.addEventListener("resize", onViewportResize);

  const onParallax = (e: MouseEvent) => {
    // 归一化到 -1..1（视口坐标系 — main-view 100%×100% 铺满窗口）
    parallaxTargetX = (e.clientX / vw - 0.5) * 2;
    parallaxTargetY = (e.clientY / vh - 0.5) * 2;
    if (!parallaxActive) {
      parallaxActive = true;
      masterFrameLoop.once(tickParallax);
    }
  };

  const tickParallax = () => {
    if (!parallaxActive) return;
    // 缓动追踪目标值（弹性平滑）
    parallaxCurrentX += (parallaxTargetX - parallaxCurrentX) * 0.08;
    parallaxCurrentY += (parallaxTargetY - parallaxCurrentY) * 0.08;
    const fx = (-parallaxCurrentX * 5).toFixed(2);
    const fy = (-parallaxCurrentY * 5).toFixed(2);
    const mx = (-parallaxCurrentX * 15).toFixed(2);
    const my = (-parallaxCurrentY * 15).toFixed(2);
    const nx = (-parallaxCurrentX * 30).toFixed(2);
    const ny = (-parallaxCurrentY * 30).toFixed(2);
    parallaxFar.value = { transform: `translate3d(${fx}px, ${fy}px, 0)` };
    parallaxMid.value = { transform: `translate3d(${mx}px, ${my}px, 0)` };
    parallaxNear.value = { transform: `translate3d(${nx}px, ${ny}px, 0)` };
    if (Math.abs(parallaxTargetX - parallaxCurrentX) > 0.001 ||
        Math.abs(parallaxTargetY - parallaxCurrentY) > 0.001) {
      masterFrameLoop.once(tickParallax);
    } else {
      parallaxActive = false;
    }
  };

  onBeforeUnmount(() => {
    /* 断泵：已排程的下一帧回调经 parallaxActive 守卫直接返回 */
    parallaxActive = false;
    window.removeEventListener("resize", onViewportResize);
  });

  /* ===== 三层星场：远（小而暗）/ 中（中等）/ 近（大而亮，带十字光芒） ===== */
  const starColors = ["#ffffff", "#aaccff", "#ffccdd", "#ddccff", "#ffeebb"];

  const starsFar: CosmicStar[] = Array.from({ length: 38 }, (_, i) => {
    const c = starColors[i % starColors.length];
    return {
      id: `f${i}`,
      style: {
        left: `${Math.random() * 100}%`,
        top: `${Math.random() * 80}%`,
        width: "1px",
        height: "1px",
        background: c,
        color: c,
      },
      phase: Math.random(),
      dur: 4 + Math.random() * 4,
    };
  });

  const starsMid: CosmicStar[] = Array.from({ length: 22 }, (_, i) => {
    const c = starColors[i % starColors.length];
    return {
      id: `m${i}`,
      style: {
        left: `${Math.random() * 100}%`,
        top: `${Math.random() * 80}%`,
        width: `${1.5 + Math.random() * 0.5}px`,
        height: `${1.5 + Math.random() * 0.5}px`,
        background: c,
        color: c,
      },
      phase: Math.random(),
      dur: 3 + Math.random() * 3,
    };
  });

  const starsNear: CosmicStar[] = Array.from({ length: 14 }, (_, i) => {
    const c = starColors[i % starColors.length];
    return {
      id: `n${i}`,
      style: {
        left: `${Math.random() * 100}%`,
        top: `${Math.random() * 80}%`,
        width: `${2 + Math.random() * 1.5}px`,
        height: `${2 + Math.random() * 1.5}px`,
        background: c,
        color: c,
      },
      phase: Math.random(),
      dur: 2.5 + Math.random() * 2.5,
    };
  });

  /* ===== 宇宙尘埃微粒（缓慢漂移，营造空间感） =====
   * 逐粒独立漂移向量：速率 28-70px/周期 + 仰角 18-70° + 左右随机方向 —
   * 拒绝全组同向同步漂移（反大众化：运动方向场差异化） */
  const cosmicDust: CosmicDust[] = Array.from({ length: 50 }, (_, i) => {
    const speed = 28 + Math.random() * 42;
    const dir = Math.random() < 0.5 ? 1 : -1;
    const elev = (Math.PI / 180) * (18 + Math.random() * 52);
    return {
      id: i,
      style: {
        left: `${Math.random() * 100}%`,
        top: `${Math.random() * 100}%`,
      },
      phase: Math.random(),
      dur: 20 + Math.random() * 30,
      vx: +(dir * speed * Math.cos(elev)).toFixed(1),
      vy: +(-speed * Math.sin(elev)).toFixed(1),
      /* 侧摆幅度（0.12×|vx|，CSS dust-anim 的 X 向摆动项） */
      swx: +(Math.abs(dir * speed * Math.cos(elev)) * 0.12).toFixed(2),
    };
  });

  /* ===== 星座连线：9 颗主星 + 10 条连线，组成抽象星座 ===== */
  const constellationStars = [
    { x: 12, y: 18 }, { x: 28, y: 10 }, { x: 42, y: 26 },
    { x: 55, y: 16 }, { x: 68, y: 30 }, { x: 80, y: 20 },
    { x: 35, y: 46 }, { x: 58, y: 52 }, { x: 75, y: 46 },
  ];
  const constellationLines = [
    { x1: 12, y1: 18, x2: 28, y2: 10 },
    { x1: 28, y1: 10, x2: 42, y2: 26 },
    { x1: 42, y1: 26, x2: 55, y2: 16 },
    { x1: 55, y1: 16, x2: 68, y2: 30 },
    { x1: 68, y1: 30, x2: 80, y2: 20 },
    { x1: 42, y1: 26, x2: 35, y2: 46 },
    { x1: 35, y1: 46, x2: 58, y2: 52 },
    { x1: 58, y1: 52, x2: 75, y2: 46 },
    { x1: 68, y1: 30, x2: 75, y2: 46 },
    { x1: 55, y1: 16, x2: 58, y2: 52 },
  ];

  return {
    /* 视差 */
    parallaxFar,
    parallaxMid,
    parallaxNear,
    onParallax,
    /* 星场 */
    starsFar,
    starsMid,
    starsNear,
    /* 尘埃 */
    cosmicDust,
    /* 星座 */
    constellationStars,
    constellationLines,
  };
}
