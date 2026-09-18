/**
 * useQuantumField.ts — 量子态势面板 Canvas 物理场引擎
 *
 * ★ 全新引擎：替代原 CSS 动画 + 简单 lerp 视差方案
 *
 * =============================================================================
 * 设计规范对照（交互逻辑 / 动态运动 / 渲染性能 / 反AI大众化）
 * =============================================================================
 *
 * 【交互逻辑】
 *   1. 实时响应：pointermove 直接更新目标值，rAF 单帧内消费（≤16.7ms）
 *   2. 物理阻尼与惯性：所有状态过渡由弹簧-阻尼二阶系统驱动（半隐式欧拉，
 *      帧率无关），无 CSS transition 突变、无瞬时复位、无生硬回弹
 *   3. 交互优先级：节点/核心 hover（P1）> 面板视差（P2）——hover 期间视差
 *      目标衰减 50%，状态切换全程弹簧连续过渡，无断层无冲突
 *   4. 自然衰减梯度：鼠标力场对粒子/连线的影响采用高斯核 exp(-d²/2σ²)
 *      平滑衰减，无硬边界
 *
 * 【动态运动】
 *   1. 分层运行：far（尘埃，系数 0.35）/ mid（连线+碎片，1.0）/ near（吸积盘，1.7）
 *      各层独立速度、衰减系数、影响权重；每元素叠加独立相位的多频噪声漂移
 *   2. 边界约束：尘埃轨道内旋至事件视界即被吸收并按能量守恒衰减重生外圈
 *      （统一消散规则，无穿模无溢出）
 *   3. 连续噪声扰动：多频正弦复合（非单频），拒绝整齐划一的机械同步
 *
 * 【渲染性能】
 *   1. DPR 缩放抗锯齿；粒子预渲染径向渐变贴图 drawImage（禁用 shadowBlur）；
 *      发光元素 lighter 混合、alpha 克制（≤0.85，拒绝辉光泛滥）
 *   2. ResizeObserver 自适应容器，轨道基于比例单位，视觉中心不变形
 *   3. dt 驱动物理（帧率无关）+ EMA 帧时间评估 → 粒子密度动态增减，
 *      长时间运行无衰减无泄漏（粒子池预分配，零 GC 压力）
 *   4. 统一帧门控（useFrameGate）：全局空闲四档 60/30/5/1fps，
 *      失焦/隐藏由全局调度器置 deep-idle（rAF 天然停帧）
 *
 * 【反AI大众化】
 *   1. 无标准螺旋/对称放射/刻波纹圆环：轨道为椭圆（独立偏心率+倾角），
 *      吸积盘为不等长弧段组合（90°~200° 各异），节点布局非对称偏移
 *   2. 元素分布非均匀：相位/尺寸/速度/亮度由种子化伪随机分配，可控不规则
 *   3. 运动曲线为二阶弹簧 + 多频复合噪声（非标准 ease 预设）
 *   4. 特效克制：无大范围 blur/色散/辉光堆叠，层次靠运动深度与亮度梯度
 *   5. 力场为高斯衰减的切向漩涡 + 微径向分量（差异化处理，非现成 demo 逻辑）
 */

import { onBeforeUnmount, watch, type Ref } from 'vue';
import { useGlobalIdleScheduler } from '../useGlobalIdleScheduler';
import { useFrameGate } from '../useFrameGate';

/* ============================================================
 * 常量与调参（集中管理，全部为手工设计的非模板化参数）
 * ============================================================ */

/** 尘埃粒子池上限 / 下限（帧率自适应区间） */
const DUST_MAX = 110;
const DUST_MIN = 42;
/** 数据碎片上限 / 下限 */
const SHARD_MAX = 26;
const SHARD_MIN = 10;
/** 事件视界半径（相对 min(w,h) 的比例） */
const HORIZON_R = 0.055;
/** 尘埃重生外圈半径（比例） */
const DUST_OUTER_R = 0.46;
/** 鼠标力场高斯 σ（px） */
const FIELD_SIGMA = 132;
/** 帧时间 EMA 平滑系数 */
const FRAME_EMA = 0.92;
/** dt 钳制上限（秒），掉帧时物理不爆炸 */
const DT_CLAMP = 0.05;
/** 帧率评估周期（帧） */
const ADAPT_INTERVAL = 90;
/** 有效尺寸阈值（px）：低于此值容器处于过渡/未布局状态，跳过渲染 */
const SIZE_VALID_MIN = 10;

/* ---------- 入场编排（intro choreography） ----------
 * 面板挂载/尺寸就绪瞬间从 0 开始，各层错峰苏醒，杜绝"全量元素瞬间定格出现"。
 * 曲线为 smoothstep 与 smootherstep 的加权复合（非单一标准缓动预设） */

/** 钳制 0..1 */
export function clamp01(v: number): number {
  return v < 0 ? 0 : v > 1 ? 1 : v;
}

/** 复合入场曲线：smoothstep(35%) + smootherstep(65%) 加权混合 */
export function introEase(t: number): number {
  const c1 = t * t * (3 - 2 * t);
  const c2 = t * t * t * (t * (t * 6 - 15) + 10);
  return c1 * 0.35 + c2 * 0.65;
}

/** 错峰相位窗：delay 起始 / dur 时长 → 复合曲线进度 */
export function phase(t: number, delay: number, dur: number): number {
  return introEase(clamp01((t - delay) / dur));
}

/** 弹簧-阻尼二阶系统（帧率无关，半隐式欧拉积分） */
export interface Spring {
  v: number;
  vel: number;
  target: number;
  k: number;
  c: number;
}

/** 创建弹簧（dampingRatio < 1 为欠阻尼带微惯性问题，> 1 过阻尼无过冲） */
export function makeSpring(k: number, dampingRatio = 1.0, init = 0): Spring {
  return { v: init, vel: 0, target: init, k, c: 2 * Math.sqrt(k) * dampingRatio };
}

/** 弹簧积分（半隐式欧拉：先更新速度再更新位置，能量稳定） */
export function springStep(s: Spring, dt: number): void {
  const force = (s.target - s.v) * s.k - s.vel * s.c;
  s.vel += force * dt;
  s.v += s.vel * dt;
}

/** 种子化伪随机（mulberry32 — 可复现的"可控不规则"） */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** 多频正弦复合噪声生成器（连续、非重复、拒绝整齐划一） */
export function makeDrift(seed: number): (t: number) => number {
  const r = mulberry32(seed);
  const f1 = 0.09 + r() * 0.06;
  const f2 = 0.21 + r() * 0.1;
  const f3 = 0.43 + r() * 0.17;
  const p1 = r() * Math.PI * 2;
  const p2 = r() * Math.PI * 2;
  const p3 = r() * Math.PI * 2;
  return (t: number) =>
    Math.sin(t * f1 + p1) * 0.56 +
    Math.sin(t * f2 + p2) * 0.31 +
    Math.sin(t * f3 + p3) * 0.13;
}

/* ============================================================
 * 场元素数据结构（全部池化预分配，零运行时 GC）
 * ============================================================ */

/** 引力尘埃粒子（椭圆轨道 + 内旋吸收 + 噪声扰动） */
interface Dust {
  r: number;
  theta: number;
  omega: number;
  rVel: number;
  ecc: number;
  tilt: number;
  size: number;
  alpha: number;
  sprite: number;
  seed: number;
  fade: number;
}

/** 数据碎片（切向细线段，数据流残影） */
interface Shard {
  r: number;
  theta: number;
  omega: number;
  len: number;
  alpha: number;
  seed: number;
  fade: number;
}

/** 连线数据包（沿贝塞尔流动的能量量子） */
interface Packet {
  t: number;
  speed: number;
  size: number;
  sprite: number;
}

/** 能量连线（中心 → 模块节点，二次贝塞尔） */
interface Link {
  to: { x: number; y: number };
  bow: number;
  drift: (t: number) => number;
  packets: Packet[];
  glow: number;
}

/** 吸积弧段（不等长 + 钟形端点渐隐） */
interface Arc {
  radius: number;
  span: number;
  theta: number;
  omega: number;
  alpha: number;
  color: string;
  width: number;
}

/* ============================================================
 * 引擎主体
 * ============================================================ */

/** useQuantumField 依赖注入（全部为 DOM ref + 布局常量，纯引擎无 Vue 响应式开销） */
export interface QuantumFieldOptions {
  /** 面板根元素（事件绑定 + ResizeObserver 目标） */
  panel: Ref<HTMLElement | null>;
  /** 画布元素（动态层渲染） */
  canvas: Ref<HTMLCanvasElement | null>;
  /** 视差中层 DOM（模块节点容器） */
  midLayer: Ref<HTMLElement | null>;
  /** 视差近层 DOM（中心核心容器） */
  nearLayer: Ref<HTMLElement | null>;
  /** 中心核心可交互簇（hover 弹簧驱动 scale） */
  coreCluster: Ref<HTMLElement | null>;
  /** 模块节点 DOM 列表（hover 弹簧驱动 scale） */
  nodes: Ref<HTMLElement[]>;
  /** 模块节点布局（百分比，与 DOM 定位严格一致） */
  nodePositions: Array<{ x: number; y: number }>;
  /** 中心核心就绪状态（吸积盘能量与色相应答） */
  coreReady: Ref<boolean>;
}

/**
 * 量子态势面板物理场引擎
 *
 * @param options DOM refs + 布局注入
 * @returns destroy（组件卸载时释放全部资源）
 */
export function useQuantumField(options: QuantumFieldOptions) {
  /* ---------- DOM 引用快照 ---------- */
  let panelEl: HTMLElement | null = null;
  let canvasEl: HTMLCanvasElement | null = null;
  let ctx: CanvasRenderingContext2D | null = null;
  let midEl: HTMLElement | null = null;
  let nearEl: HTMLElement | null = null;
  let coreEl: HTMLElement | null = null;
  let nodeEls: HTMLElement[] = [];

  /* ---------- 画布尺寸 ---------- */
  let width = 0;
  let height = 0;
  let dpr = 1;
  let minDim = 1;

  /* ---------- 时间 ---------- */
  let elapsed = 0;
  let frameCount = 0;
  let avgFrameMs = 16.7;

  /* ---------- ★ G-7 统一帧门控（useFrameGate） ----------
   * 帧率档位由全局空闲状态机唯一决定（active 60 / settling 30 /
   * idle 5 / deep-idle 1 fps）；dt 由门控按累积时间供给（跳帧不推进
   * 基准 → 物理时间连续），本引擎不再维护私有空闲判定与全局交互监听。 */
  const { level: idleLevel } = useGlobalIdleScheduler();

  /* ---------- ★ P2-5 监听器统一 AbortController 管理 ----------
   * init() 时创建，全部 addEventListener（面板级 + 全局交互 + 子元素 hover）
   * 经 signal 注册；destroy() 一次 abort() 移除全部，无逐项 removeEventListener
   * 的遗漏风险，子元素监听器不再依赖 GC 回收。 */
  let listenerAbort: AbortController | null = null;

  /* ---------- 入场编排状态 ----------
   * introTime = -1：等待首个有效尺寸（容器过渡中/未布局，不渲染不推进）
   * introTime ≥ 0：编排进行中/已完成，各层按错峰窗口苏醒 */
  let introTime = -1;
  let sizeValid = false;

  /* ---------- 指针状态（力场 + 视差源） ---------- */
  let pointerX = 0; // 面板内像素坐标
  let pointerY = 0;
  let pointerInside = false;

  /* ---------- 物理弹簧组 ---------- */
  // 视差（欠阻尼 0.82：带微惯性的跟手，非机械 lerp）
  const parallaxX = makeSpring(34, 0.82);
  const parallaxY = makeSpring(34, 0.82);
  // 力场强度（进入 1 / 离开 0，过阻尼无过冲）
  const fieldPower = makeSpring(24, 1.15);
  // ★ hover 让位仲裁弹簧：P1（节点/核心 hover）期间视差幅度衰减至 50% —
  // 原实现对视差输出乘 0.5/1.0 硬步进，pointerenter 瞬间近层位移
  // 一次跳变最多 11px（"内容突然跳位放大"突兀感主因）→ 弹簧连续过渡
  const hoverSuppress = makeSpring(26, 1.1, 1);
  // 中心核心 hover（★ 轻过阻尼缓胀：原 k=60 快弹在 ~140ms 内完成
  // 4.5% 缩放，读感为"突然放大"；降刚度后 ~0.4s 平滑膨胀应答）
  const coreHover = makeSpring(24, 1.1);
  // 核心就绪度（色相/能量过渡）
  const coreReadySpring = makeSpring(10, 1.2);
  // hover 仲裁：任一节点/核心 hover 时抑制视差（交互优先级 P1 > P2）
  const hoverCount = { n: 0 };

  /* ---------- 噪声通道（各层独立漂移相位） ---------- */
  const driftFar = makeDrift(0x5f3a);
  const driftMid = makeDrift(0x2c81);
  const driftNear = makeDrift(0x91d4);
  const driftGlobal = makeDrift(0x7e2b);

  /* ---------- 粒子池 ---------- */
  let activeDust = 84;
  let activeShards = 18;
  const dustPool: Dust[] = [];
  const shardPool: Shard[] = [];

  /* ---------- 连线与吸积盘 ---------- */
  const links: Link[] = [];
  const arcs: Arc[] = [];

  /* ---------- 节点 hover 弹簧池 ---------- */
  const nodeSprings: Spring[] = [];

  /* ---------- 节点像素坐标缓冲（每帧原地写入，零 GC） ---------- */
  const nodePx: Array<{ x: number; y: number }> = [];

  /* ---------- 预渲染发光贴图（径向渐变，禁 shadowBlur） ---------- */
  const sprites: HTMLCanvasElement[] = [];
  const SPRITE_COLORS = [
    'rgba(0,212,255,1)',   // 青
    'rgba(139,92,246,1)',   // 紫
    'rgba(255,110,180,1)',  // 粉
    'rgba(0,255,190,1)',    // 青绿
  ];

  /** 离屏预渲染单枚发光贴图（32px 径向渐变，边缘平滑无锯齿毛刺） */
  function makeSprite(color: string): HTMLCanvasElement {
    const size = 32;
    const c = document.createElement('canvas');
    c.width = size;
    c.height = size;
    const g = c.getContext('2d')!;
    const grad = g.createRadialGradient(16, 16, 0, 16, 16, 16);
    grad.addColorStop(0, color);
    grad.addColorStop(0.28, color.replace(',1)', ',0.55)'));
    grad.addColorStop(0.62, color.replace(',1)', ',0.12)'));
    grad.addColorStop(1, 'rgba(0,0,0,0)');
    g.fillStyle = grad;
    g.beginPath();
    g.arc(16, 16, 16, 0, Math.PI * 2);
    g.fill();
    return c;
  }

  /* ============================================================
   * 初始化与池构建
   * ============================================================ */

  /** 重生一枚尘埃（外圈随机注入，能量守恒式衰减） */
  function respawnDust(d: Dust, r?: () => number): void {
    const rand = r ?? Math.random;
    d.r = DUST_OUTER_R * (0.82 + rand() * 0.18);
    d.theta = rand() * Math.PI * 2;
    // 开普勒式：内圈角速度更快（ω ∝ r^-1.5），形成自然速度梯度
    d.omega = (0.05 + rand() * 0.1) / Math.pow(d.r / 0.2, 1.5);
    if (rand() < 0.5) d.omega = -d.omega;
    // 缓慢内旋（引力吸入）
    d.rVel = -(0.004 + rand() * 0.012);
    d.ecc = 0.72 + rand() * 0.5;
    d.tilt = rand() * Math.PI * 2;
    d.size = 1.4 + rand() * 2.6;
    d.alpha = 0.16 + rand() * 0.5;
    d.sprite = Math.floor(rand() * SPRITE_COLORS.length);
    d.seed = rand() * 1000;
    d.fade = 0;
  }

  /** 重生一枚数据碎片 */
  function respawnShard(s: Shard): void {
    const rand = Math.random;
    s.r = 0.14 + rand() * 0.3;
    s.theta = rand() * Math.PI * 2;
    s.omega = (0.12 + rand() * 0.2) / Math.pow(s.r / 0.2, 1.5);
    if (rand() < 0.5) s.omega = -s.omega;
    s.len = 5 + rand() * 8;
    s.alpha = 0.1 + rand() * 0.3;
    s.seed = rand() * 1000;
    s.fade = 0;
  }

  /** 构建全部池（种子化随机，可控不规则分布） */
  function buildPools(): void {
    const rand = mulberry32(0xa17c);
    for (let i = 0; i < DUST_MAX; i++) {
      const d: Dust = {
        r: 0, theta: 0, omega: 0, rVel: 0, ecc: 1, tilt: 0,
        size: 2, alpha: 0.3, sprite: 0, seed: 0, fade: 0,
      };
      respawnDust(d, rand);
      // 初始散布于全轨道域（非同圈起跑，拒绝均匀分布）
      d.r = HORIZON_R + rand() * (DUST_OUTER_R - HORIZON_R);
      d.fade = 1;
      dustPool.push(d);
    }
    for (let i = 0; i < SHARD_MAX; i++) {
      const s: Shard = {
        r: 0, theta: 0, omega: 0, len: 6, alpha: 0.2, seed: 0, fade: 1,
      };
      respawnShard(s);
      s.fade = 1;
      shardPool.push(s);
    }
    // 连线：每条独立弓曲方向 + 相位差异数据包
    options.nodePositions.forEach((pos, i) => {
      const linkRand = mulberry32(0x33d1 + i * 7919);
      const packets: Packet[] = [];
      const packetCount = 2 + Math.floor(linkRand() * 2);
      for (let p = 0; p < packetCount; p++) {
        packets.push({
          t: linkRand(),
          speed: 0.1 + linkRand() * 0.16,
          size: 2 + linkRand() * 2.4,
          sprite: i % SPRITE_COLORS.length,
        });
      }
      links.push({
        to: { ...pos },
        bow: (linkRand() < 0.5 ? -1 : 1) * (4 + linkRand() * 9),
        drift: makeDrift(0x11f + i * 613),
        packets,
        glow: 0,
      });
    });
    // 吸积弧段：不等长（90°~200°）+ 不等速 + 相异色（非对称组合）
    const arcRand = mulberry32(0x7c5e);
    const arcColors = [
      'rgba(0,212,255,', 'rgba(139,92,246,', 'rgba(255,110,180,', 'rgba(0,255,190,',
    ];
    const arcCount = 4;
    for (let i = 0; i < arcCount; i++) {
      arcs.push({
        radius: 0.085 + arcRand() * 0.075,
        span: (Math.PI / 180) * (92 + arcRand() * 108),
        theta: arcRand() * Math.PI * 2,
        omega: (0.12 + arcRand() * 0.3) * (arcRand() < 0.5 ? -1 : 1),
        alpha: 0.14 + arcRand() * 0.2,
        color: arcColors[i % arcColors.length],
        width: 1 + arcRand() * 1.6,
      });
    }
    // 节点 hover 弹簧（与节点等量；★ 降刚度缓胀 — 原 k=70 快弹
    // 120ms 内完成 10% 缩放，与核心同款"突然放大"突兀感）
    options.nodePositions.forEach(() => {
      nodeSprings.push(makeSpring(30, 1.05));
      nodePx.push({ x: 0, y: 0 });
    });
    // 发光贴图
    SPRITE_COLORS.forEach((c) => sprites.push(makeSprite(c)));
  }

  /* ============================================================
   * 尺寸自适应（ResizeObserver + DPR）
   * ============================================================ */

  let resizeObserver: ResizeObserver | null = null;

  /* ★ 性能根治：缓存面板 rect（applySize/ResizeObserver 时刷新）—
   * onPointerMove 高频触发，每次 getBoundingClientRect 强制布局读取
   * 会打断渲染流水线（量子面板鼠标卡顿源之一） */
  let panelRect = { left: 0, top: 0, width: 1, height: 1 };

  function applySize(): void {
    if (!panelEl || !canvasEl) return;
    const rect = panelEl.getBoundingClientRect();
    panelRect = { left: rect.left, top: rect.top, width: Math.max(rect.width, 1), height: Math.max(rect.height, 1) };
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = rect.width;
    height = rect.height;
    minDim = Math.min(width, height) || 1;
    canvasEl.width = Math.round(width * dpr);
    canvasEl.height = Math.round(height * dpr);
    canvasEl.style.width = `${width}px`;
    canvasEl.style.height = `${height}px`;
    // setTransform 重置再缩放：物理坐标系 = CSS 像素（DPR 抗锯齿）
    ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    // 尺寸守卫：无效（容器过渡/未布局）→ 冻结编排；无效→有效的跃迁瞬间启动编排
    const valid = width >= SIZE_VALID_MIN && height >= SIZE_VALID_MIN;
    if (valid && !sizeValid) {
      sizeValid = true;
      introTime = 0;
    } else if (!valid) {
      sizeValid = false;
      introTime = -1;
    }
  }

  /* ============================================================
   * 指针交互（力场源 + 视差源 + hover 仲裁）
   * ============================================================ */

  function onPointerMove(e: PointerEvent): void {
    if (!panelEl) return;
    /* ★ 用 applySize 缓存的 rect（ResizeObserver 时刷新）— 去高频强制布局读取 */
    pointerX = e.clientX - panelRect.left;
    pointerY = e.clientY - panelRect.top;
    pointerInside = true;
    // 视差目标：归一化 -1..1（单帧内被 rAF 消费，延迟 ≤1 帧）
    parallaxX.target = (pointerX / panelRect.width - 0.5) * 2;
    parallaxY.target = (pointerY / panelRect.height - 0.5) * 2;
    fieldPower.target = 1;
  }

  function onPointerLeave(): void {
    pointerInside = false;
    fieldPower.target = 0;
    parallaxX.target = 0;
    parallaxY.target = 0;
  }

  /** 绑定节点 hover（P1 优先级：抑制视差 + 弹簧缩放 + 连线增益）
   * ★ P2-5：经 AbortController signal 注册，destroy 时统一移除 */
  function bindNodeHover(el: HTMLElement, idx: number): void {
    const signal = listenerAbort?.signal;
    el.addEventListener('pointerenter', () => {
      hoverCount.n++;
      nodeSprings[idx].target = 1;
    }, { signal });
    el.addEventListener('pointerleave', () => {
      hoverCount.n = Math.max(0, hoverCount.n - 1);
      nodeSprings[idx].target = 0;
    }, { signal });
  }

  function bindCoreHover(): void {
    if (!coreEl) return;
    const signal = listenerAbort?.signal;
    coreEl.addEventListener('pointerenter', () => {
      hoverCount.n++;
      coreHover.target = 1;
    }, { signal });
    coreEl.addEventListener('pointerleave', () => {
      hoverCount.n = Math.max(0, hoverCount.n - 1);
      coreHover.target = 0;
    }, { signal });
  }

  /* ============================================================
   * 渲染辅助
   * ============================================================ */

  /** 高斯力场衰减（自然梯度，无硬边界） */
  function fieldInfluence(x: number, y: number): number {
    if (!pointerInside || fieldPower.v < 0.01) return 0;
    const dx = x - pointerX;
    const dy = y - pointerY;
    const d2 = dx * dx + dy * dy;
    const sigma2 = 2 * FIELD_SIGMA * FIELD_SIGMA;
    return Math.exp(-d2 / sigma2) * fieldPower.v;
  }

  /** 二次贝塞尔求值 */
  function bezier(
    x0: number, y0: number, cx: number, cy: number,
    x1: number, y1: number, t: number,
  ): { x: number; y: number } {
    const u = 1 - t;
    return {
      x: u * u * x0 + 2 * u * t * cx + t * t * x1,
      y: u * u * y0 + 2 * u * t * cy + t * t * y1,
    };
  }

  /* ============================================================
   * 主循环（物理积分 → DOM 层写入 → Canvas 绘制）
   * ============================================================ */

  function frame(gateDt: number): void {
    if (!ctx) return;
    // 尺寸守卫：容器处于过渡/未布局（尺寸无效）时不渲染不推进，续命等待 ResizeObserver
    if (!sizeValid) return;
    // dt 驱动（帧率无关），门控累积 dt 钳制防长帧物理爆炸
    const dt = Math.min(gateDt, DT_CLAMP);
    elapsed += dt;
    introTime += dt;
    frameCount++;

    // 帧时间 EMA（性能自适应依据）
    const frameMs = dt * 1000;
    avgFrameMs = avgFrameMs * FRAME_EMA + frameMs * (1 - FRAME_EMA);

    /* ---- 弹簧积分（全部二阶系统，先积分后消费） ---- */
    springStep(parallaxX, dt);
    springStep(parallaxY, dt);
    springStep(fieldPower, dt);
    springStep(hoverSuppress, dt);
    springStep(coreHover, dt);
    springStep(coreReadySpring, dt);
    nodeSprings.forEach((s) => springStep(s, dt));

    /* ---- 入场编排主时钟：introTime 由 applySize 的尺寸有效跃迁归零 ---- */
    const it = introTime;
    // 编排总时长（最后窗口 0.45+3*0.12+0.7 ≈ 2.2s），结束后各系数恒 1（免重复求值）
    const introRunning = it < 2.4;

    /* ---- 交互优先级仲裁：hover（P1）期间视差幅度衰减至 50%（P2 让位） ----
       ★ 让位系数由 hoverSuppress 弹簧连续过渡 — 原对输出乘 0.5/1.0
       硬步进，pointerenter 瞬间产生最多 ~11px 的层位移跳变（突兀主因）；
       入场期间视差幅度随 introPar 渐起（挂载瞬间无大幅位移跳变） */
    hoverSuppress.target = hoverCount.n > 0 ? 0.5 : 1;
    const introPar = introRunning ? phase(it, 0.2, 1.2) : 1;
    const px = parallaxX.v * hoverSuppress.v * introPar;
    const py = parallaxY.v * hoverSuppress.v * introPar;

    /* ---- 三层视差偏移（独立系数 + 独立噪声漂移） ---- */
    const farOx = -px * 5 + driftFar(elapsed) * 1.1;
    const farOy = -py * 5 + driftFar(elapsed + 37) * 1.1;
    const midOx = -px * 13 + driftMid(elapsed) * 1.9;
    const midOy = -py * 13 + driftMid(elapsed + 53) * 1.9;
    const nearOx = -px * 22 + driftNear(elapsed) * 2.8;
    const nearOy = -py * 22 + driftNear(elapsed + 71) * 2.8;

    /* ---- DOM 层写入（绕过 Vue 响应式，直接 transform，GPU 合成） ---- */
    if (midEl) midEl.style.transform = `translate3d(${midOx.toFixed(2)}px,${midOy.toFixed(2)}px,0)`;
    if (nearEl) nearEl.style.transform = `translate3d(${nearOx.toFixed(2)}px,${nearOy.toFixed(2)}px,0)`;
    // 节点错峰浮现：按索引 0.45 + i*0.12 依次苏醒（scale 0.55→1 + opacity 0→1）
    nodeEls.forEach((el, i) => {
      const s = nodeSprings[i];
      const p = introRunning ? phase(it, 0.45 + i * 0.12, 0.7) : 1;
      const scale = (0.55 + 0.45 * p) * (1 + s.v * 0.1);
      el.style.transform = `translate(-50%,-50%) scale(${scale.toFixed(4)})`;
      el.style.opacity = p.toFixed(3);
    });
    if (coreEl) {
      // 核心文字簇最先浮现（0.1s 起，先于全部节点与连线）
      const p = introRunning ? phase(it, 0.1, 0.8) : 1;
      const scale = (0.6 + 0.4 * p) * (1 + coreHover.v * 0.045);
      coreEl.style.transform = `translate(-50%,-50%) scale(${scale.toFixed(4)})`;
      coreEl.style.opacity = p.toFixed(3);
    }

    /* ---- Canvas 绘制 ---- */
    ctx.clearRect(0, 0, width, height);
    const cx = width / 2;
    const cy = height / 2;
    const readyT = coreReadySpring.v;

    // ---- far 层：引力尘埃（椭圆轨道 + 内旋吸收 + 力场漩涡偏移） ----
    ctx.globalCompositeOperation = 'lighter';
    for (let i = 0; i < activeDust; i++) {
      const d = dustPool[i];
      // 轨道积分
      d.theta += d.omega * dt;
      d.r += d.rVel * dt;
      d.fade = Math.min(1, d.fade + dt * 1.6);
      // 视界吸收 → 外圈重生（统一边界消散规则）
      if (d.r < HORIZON_R) {
        respawnDust(d);
        continue;
      }
      // 噪声扰动轨道半径（连续非重复）
      const rJit = 1 + Math.sin(elapsed * 0.7 + d.seed) * 0.02;
      // 入场：逐粒错峰淡入（seed/1000 ∈ 0..1 离散相位）+ 半径从外圈 1.18 倍收敛（引力场苏醒、尘埃被吸入）
      const ip = introRunning ? phase(it, 0.15 + (d.seed / 1000) * 0.35, 1.0) : 1;
      const rr = d.r * minDim * rJit * (1.18 - 0.18 * ip);
      // 椭圆坐标变换 + 倾角旋转
      const ex = Math.cos(d.theta) * rr;
      const ey = Math.sin(d.theta) * rr * d.ecc;
      const ct = Math.cos(d.tilt);
      const st = Math.sin(d.tilt);
      let x = cx + ex * ct - ey * st + farOx;
      let y = cy + ex * st + ey * ct + farOy;
      // 高斯力场：切向漩涡 + 微径向斥离（差异化力场响应）
      const inf = fieldInfluence(x, y);
      if (inf > 0.004) {
        const dx = x - pointerX;
        const dy = y - pointerY;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const swirl = inf * 15;
        x += (-dy / dist) * swirl + (dx / dist) * inf * 5;
        y += (dx / dist) * swirl + (dy / dist) * inf * 5;
      }
      // 视界附近亮度自然衰减（吸入变暗，无突变）
      const horizonFade = Math.min(1, (d.r - HORIZON_R) / 0.05);
      const alpha = d.alpha * d.fade * horizonFade * ip;
      if (alpha < 0.02) continue;
      const half = d.size / 2;
      ctx.globalAlpha = alpha;
      ctx.drawImage(sprites[d.sprite], x - half, y - half, d.size, d.size);
    }

    // ---- mid 层：能量连线 + 数据包 + 数据碎片 ----
    // 节点像素坐标（原地写入预分配缓冲，含 mid 视差，与 DOM 节点层严格一致）
    for (let i = 0; i < nodePx.length; i++) {
      const p = options.nodePositions[i];
      nodePx[i].x = (p.x / 100) * width + midOx;
      nodePx[i].y = (p.y / 100) * height + midOy;
    }

    // 连线（贝塞尔 + 弓曲噪声微动 + 鼠标高斯增益；入场 0.5s 起"绷紧"点亮，最晚苏醒）
    const linkIntro = introRunning ? phase(it, 0.5, 0.8) : 1;
    for (let i = 0; i < links.length; i++) {
      const link = links[i];
      const nx = nodePx[i].x;
      const ny = nodePx[i].y;
      // 连线起点：核心侧（mid 系数 0.4 的深度剪切，介于核心近层与节点中层之间）
      const sx = cx + midOx * 0.4;
      const sy = cy + midOy * 0.4;
      // 控制点：中点 + 法向弓曲 + 漂移
      const mx = (cx + nx) / 2;
      const my = (cy + ny) / 2;
      const nxv = -(ny - cy);
      const nyv = nx - cx;
      const nl = Math.sqrt(nxv * nxv + nyv * nyv) || 1;
      const bow = (link.bow + link.drift(elapsed) * 3) * (minDim / 540) * (1.6 - 0.6 * linkIntro);
      const cpx = mx + (nxv / nl) * bow;
      const cpy = my + (nyv / nl) * bow;

      // 鼠标增益：中点距离高斯衰减（自然梯度）
      const mdx = mx - pointerX;
      const mdy = my - pointerY;
      const boost = Math.exp(
        -(mdx * mdx + mdy * mdy) / (2 * FIELD_SIGMA * FIELD_SIGMA * 2.2),
      ) * fieldPower.v;
      link.glow += (boost - link.glow) * Math.min(1, dt * 8);
      // 节点 hover 时对应连线能量增益（交互联动）
      const nodeHoverGain = nodeSprings[i]?.v ?? 0;

      // 绘制连线（三层明暗：基础 + 增益段；弓曲随入场从 1.6 倍绷紧收敛）
      ctx.globalAlpha = (0.16 + link.glow * 0.3 + nodeHoverGain * 0.2) * linkIntro;
      ctx.strokeStyle = 'rgba(0,212,255,0.5)';
      ctx.lineWidth = 1 + link.glow * 0.8 + nodeHoverGain * 0.6;
      ctx.beginPath();
      ctx.moveTo(sx, sy);
      ctx.quadraticCurveTo(cpx, cpy, nx, ny);
      ctx.stroke();

      // 数据包流动（速度各异，拒绝同步；路径与连线曲线严格一致）
      for (const p of link.packets) {
        p.t += p.speed * dt * (1 + link.glow * 1.6 + nodeHoverGain * 0.8);
        if (p.t > 1) p.t -= 1;
        const pos = bezier(sx, sy, cpx, cpy, nx, ny, p.t);
        const pxA = (0.5 + link.glow * 0.5 + nodeHoverGain * 0.3) * linkIntro;
        ctx.globalAlpha = pxA * Math.sin(p.t * Math.PI) ** 0.5;
        const psz = p.size + link.glow * 1.5;
        ctx.drawImage(sprites[p.sprite], pos.x - psz / 2, pos.y - psz / 2, psz, psz);
      }
    }

    // 数据碎片（切向线段，数据流残影；入场 0.35s 起淡入，晚于尘埃）
    const shardIntro = introRunning ? phase(it, 0.35, 1.0) : 1;
    for (let i = 0; i < activeShards; i++) {
      const s = shardPool[i];
      s.theta += s.omega * dt;
      s.fade = Math.min(1, s.fade + dt * 1.4);
      const rr = s.r * minDim;
      let x = cx + Math.cos(s.theta) * rr + midOx * 0.8;
      let y = cy + Math.sin(s.theta) * rr * 0.92 + midOy * 0.8;
      const inf = fieldInfluence(x, y);
      if (inf > 0.004) {
        const dx = x - pointerX;
        const dy = y - pointerY;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        x += (-dy / dist) * inf * 12;
        y += (dx / dist) * inf * 12;
      }
      // 切向方向（垂直半径）
      const tx = -Math.sin(s.theta);
      const ty = Math.cos(s.theta) * 0.92;
      const len = s.len * (minDim / 540);
      ctx.globalAlpha = s.alpha * s.fade * (0.7 + inf * 1.2) * shardIntro;
      ctx.strokeStyle = 'rgba(0,220,255,0.6)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(x - tx * len / 2, y - ty * len / 2);
      ctx.lineTo(x + tx * len / 2, y + ty * len / 2);
      ctx.stroke();
    }

    // ---- near 层：中心吸积盘（非对称弧段组合 + 钟形端点渐隐） ----
    // 入场最先苏醒（0s 起）：暗核渐显 + 弧段半径自 0.6 展开至 1（黑洞成形感）
    const arcIntro = introRunning ? phase(it, 0, 0.9) : 1;
    const coreR = minDim * 0.24;
    // 事件视界暗核（径向渐变深黑，未就绪→就绪能量增强）
    ctx.globalCompositeOperation = 'source-over';
    const coreGrad = ctx.createRadialGradient(cx + nearOx, cy + nearOy, 0, cx + nearOx, cy + nearOy, coreR * 0.5);
    coreGrad.addColorStop(0, `rgba(4,6,12,${(0.85 + readyT * 0.1) * arcIntro})`);
    coreGrad.addColorStop(0.7, `rgba(6,9,18,${0.55 * arcIntro})`);
    coreGrad.addColorStop(1, 'rgba(6,9,18,0)');
    ctx.fillStyle = coreGrad;
    ctx.beginPath();
    ctx.arc(cx + nearOx, cy + nearOy, coreR * 0.5, 0, Math.PI * 2);
    ctx.fill();

    // 吸积弧段（不等长/不等速/相异色 + hover/ready 能量应答）
    ctx.globalCompositeOperation = 'lighter';
    const energy = 1 + coreHover.v * 0.6 + readyT * 0.35;
    for (const arc of arcs) {
      arc.theta += arc.omega * dt * (1 + coreHover.v * 0.5);
      const rr = arc.radius * minDim * (1 + coreHover.v * 0.06) * (0.6 + 0.4 * arcIntro);
      const segs = 14;
      // 弧段拆分：alpha 沿弧钟形分布（端点渐隐，无硬边）
      for (let s = 0; s < segs; s++) {
        const t0 = s / segs;
        const t1 = (s + 1) / segs;
        const a0 = arc.theta + arc.span * (t0 - 0.5);
        const a1 = arc.theta + arc.span * (t1 - 0.5);
        const bell = Math.sin(t0 * Math.PI) ** 0.8;
        ctx.globalAlpha = arc.alpha * bell * energy * arcIntro;
        ctx.strokeStyle = `${arc.color}1)`;
        ctx.lineWidth = arc.width * (0.8 + bell * 0.4);
        ctx.beginPath();
        ctx.arc(cx + nearOx, cy + nearOy, rr, a0, a1);
        ctx.stroke();
      }
    }

    // 核心辉点（吸积盘内缘能量斑，亮但克制；入场随暗核同步点亮）
    const corePulse = 0.5 + Math.sin(elapsed * 1.3) * 0.14 + coreHover.v * 0.25 + readyT * 0.15;
    ctx.globalAlpha = Math.min(0.85, corePulse) * arcIntro;
    const coreSize = 10 + coreHover.v * 5 + readyT * 3;
    ctx.drawImage(
      sprites[readyT > 0.5 ? 3 : 0],
      cx + nearOx - coreSize / 2,
      cy + nearOy - coreSize / 2,
      coreSize, coreSize,
    );

    ctx.globalAlpha = 1;
    ctx.globalCompositeOperation = 'source-over';

    /* ---- 帧率自适应（EMA 评估 → 粒子密度增减，优先保证交互流畅） ----
       仅 active 档评估：低档位下 dt 为调度间隔（200ms/1000ms），
       不反映真实渲染成本，据此降密度会在恢复交互后无谓回爬。 */
    if (idleLevel.value === 'active' && frameCount % ADAPT_INTERVAL === 0) {
      if (avgFrameMs > 21 && activeDust > DUST_MIN) {
        activeDust = Math.max(DUST_MIN, activeDust - 10);
        activeShards = Math.max(SHARD_MIN, activeShards - 3);
      } else if (avgFrameMs < 14.5 && activeDust < DUST_MAX) {
        activeDust = Math.min(DUST_MAX, activeDust + 6);
        activeShards = Math.min(SHARD_MAX, activeShards + 2);
      }
    }
  }

  /* ============================================================
   * 生命周期（启动/暂停/销毁，资源全释放无泄漏）
   * ============================================================ */

  /* ★ G-7：rAF 调度/空闲门控/失焦暂停全部由 useFrameGate 承担，
     start/stop 仅为门控代理（档位与恢复时机全局一致）。 */
  const { start: startGate, stop: stopGate } = useFrameGate(idleLevel, frame);

  function start(): void {
    startGate();
  }

  function stop(): void {
    stopGate();
  }

  function destroy(): void {
    stop();
    resizeObserver?.disconnect();
    resizeObserver = null;
    /* ★ P2-5：一次 abort 移除全部监听器（面板级 + 全局交互 + 子元素 hover），
       替代逐项 removeEventListener，子元素监听器不再依赖 GC 回收 */
    listenerAbort?.abort();
    listenerAbort = null;
    ctx = null;
    canvasEl = null;
    panelEl = null;
    midEl = null;
    nearEl = null;
    coreEl = null;
    nodeEls = [];
  }

  /* ---------- 挂载（onMounted 时机由调用方触发 init） ---------- */

  /**
   * 初始化引擎（绑定 DOM + 构建池 + 启动循环）
   * @param nodeElsReady 模板 ref 数组已就绪的节点元素
   */
  function init(nodeElsReady?: HTMLElement[]): void {
    panelEl = options.panel.value;
    canvasEl = options.canvas.value;
    midEl = options.midLayer.value;
    nearEl = options.nearLayer.value;
    coreEl = options.coreCluster.value;
    nodeEls = nodeElsReady ?? options.nodes.value;
    if (!panelEl || !canvasEl) return;
    ctx = canvasEl.getContext('2d');
    if (!ctx) return;

    buildPools();
    applySize();

    /* ★ P2-5：本生命周期全部监听器经 AbortController signal 注册，
       destroy() 一次 abort() 统一移除（重复 init 时重建 controller） */
    listenerAbort?.abort();
    listenerAbort = new AbortController();
    const sig = listenerAbort.signal;

    // 事件绑定（passive 提升滚动/指针性能）
    // ★ G-7：visibilitychange 暂停与全局交互恢复满帧已由全局空闲调度器
    //    （useGlobalIdleScheduler）统一处理，此处仅保留面板级指针事件。
    panelEl.addEventListener('pointermove', onPointerMove, { passive: true, signal: sig });
    panelEl.addEventListener('pointerleave', onPointerLeave, { passive: true, signal: sig });

    // 节点/核心 hover 绑定（P1 交互优先级）
    nodeEls.forEach((el, i) => bindNodeHover(el, i));
    bindCoreHover();

    // 尺寸自适应（容器变化 → 画布同步，布局坐标系更新）
    resizeObserver = new ResizeObserver(applySize);
    resizeObserver.observe(panelEl);

    // 就绪状态弹簧同步
    coreReadySpring.target = options.coreReady.value ? 1 : 0;

    /* ★ P1-1：入场编排按满帧渲染 — 面板挂载即交互（resetIdle），
       确保错峰入场编排全程 60fps 不降档。 */
    const { resetIdle } = useGlobalIdleScheduler();
    resetIdle();

    start();
  }

  // watch coreReady：吸积盘能量应答（弹簧过渡，无突变）
  const stopWatchReady = watch(options.coreReady, (v) => {
    coreReadySpring.target = v ? 1 : 0;
  });

  // 组件卸载兜底（Vue 生命周期内自动清理）
  onBeforeUnmount(() => {
    stopWatchReady();
    destroy();
  });

  return { init, destroy };
}

/** useQuantumField 返回值类型 */
export type UseQuantumFieldReturn = ReturnType<typeof useQuantumField>;
