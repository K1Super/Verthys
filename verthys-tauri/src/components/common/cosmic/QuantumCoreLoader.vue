<!--
  QuantumCoreLoader.vue — 脉冲星磁层辐射加载动画（v3 全新体系）
  ★ 与被否决的轨道旋转族（v1 同心环七层 / v2 倾斜椭圆 dash 差速流）
    完全不同的构造机制 — 零轨道、零圆环、零 dash 巡行、零旋转 transform：

    构造：脉冲双星系统（lighthouse 灯塔效应）
      1. 磁轴偶极（斜置 24° 双极线 — 脉冲星磁轴几何，静态骨架）
      2. 辐射束对（南北两束锥形射流，束轴垂直于磁轴 — 真实脉冲星
         物理几何；rAF 逐帧重算束路径端点，束随自转相位扫掠）
      3. 脉冲核（中心致密核 — 双周期复合脉冲：自转快脉冲 +
         慢谐波长周期，亮度包络非对称）
      4. 磁层驻波（磁轴两侧 4 道等相位驻波弧 — 束扫掠掠过时
         相位同步弹性舒张，光尘物理感）
      5. 掠射微尘（8 粒沿磁层边界的布朗光尘 — 亮尘在束掠过方位
         角附近时被短暂点亮，束离开后衰减熄灭）

    物理感核心（拒绝匀速旋转）：
      - 自转相位 = t·ω + 非对称谐波修正（速度周期性加减速 —
        cubic 组合曲线而非匀速）
      - 束扫掠周期 2.6s / 驻波相位差化 / 微尘独立布朗漂移
      - 全部亮度经复合包络（基波+2/3 次谐波加权 — 周期边界恒连续）

    性能：rAF 驱动（页面隐藏自动停帧）；仅写 opacity / SVG 属性；
      requestAnimationFrame 帧率自适应（无固定帧率假设）
  纯展示组件；固定尺寸槽位（96×96px），loading 切换零抖动。
  Props: loading — 是否显示
-->
<template>
  <div v-if="loading" class="quantum-core-loader">
    <div class="ql-loader">
      <svg ref="svgEl" class="ql-svg" viewBox="0 0 96 96" fill="none" aria-hidden="true">
        <!-- 磁层驻波（4 道弧 — 束掠过时弹性舒张） -->
        <path class="ql-standing ql-standing-1" d="" />
        <path class="ql-standing ql-standing-2" d="" />
        <path class="ql-standing ql-standing-3" d="" />
        <path class="ql-standing ql-standing-4" d="" />

        <!-- 辐射束对（南北锥形射流 — 端点逐帧重算） -->
        <path class="ql-beam ql-beam-n" d="" />
        <path class="ql-beam ql-beam-s" d="" />

        <!-- 磁轴偶极（斜置双极线 — 静态骨架） -->
        <line class="ql-dipole" x1="30.36" y1="23.64" x2="65.64" y2="58.92" />
        <circle class="ql-pole ql-pole-n" cx="30.36" cy="23.64" r="1.6" />
        <circle class="ql-pole ql-pole-s" cx="65.64" cy="58.92" r="1.6" />

        <!-- 脉冲核 -->
        <circle class="ql-pulsar-core" cx="48" cy="48" r="5.5" />
        <circle class="ql-pulsar-shell" cx="48" cy="48" r="8.5" />

        <!-- 掠射微尘（8 粒 — 束掠过时点亮） -->
        <circle v-for="d in motes" :key="d.id" class="ql-mote" :cx="d.cx" :cy="d.cy" r="0.9" />
      </svg>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from "vue";

/**
 * QuantumCoreLoader — 脉冲星磁层辐射加载动画（v3 全新体系）
 *
 * v1（同心环七层）与 v2（倾斜椭圆 dash 差速流）均被否决 — 本版
 * 彻底更换构造机制：脉冲星灯塔效应，rAF 逐帧驱动 SVG 几何实时重算。
 *
 * 几何模型（viewBox 96×96，中心 48,48）：
 *   - 磁轴：斜置 24° 过中心的直线（两极点 ±23 单位距离）
 *   - 束轴：垂直于磁轴的旋转方向（相位 φ 扫掠）
 *   - 束锥：自核缘（r=10）至束端（r=42），锥宽 ±7 单位张角
 *   - 驻波：磁轴两侧 4 道同心弧（r=18/24/30/36）— 束方位角掠过时
 *     该弧被点亮并轻微舒张（半径相位调制）
 */

interface Props {
  /** 是否显示加载动画 */
  loading: boolean;
}

const props = defineProps<Props>();

/* ===== 确定性参数（构建期一次求值 — 逐元素差化拒绝模板化） ===== */
const hash = (seed: number): number => {
  const x = Math.sin(seed * 127.1 + 311.7) * 43758.5453;
  return x - Math.floor(x);
};

/** 磁层微尘 ×8：方位角/半径/布朗相位/漂移周期全差化 */
const MOTE_N = 8;
const motes = Array.from({ length: MOTE_N }, (_, i) => ({
  id: i,
  cx: 0,
  cy: 0,
  /** 磁层边界半径（18-38 — 驻波弧带内外） */
  r: 18 + hash(i * 3 + 1) * 20,
  /** 初始方位角 */
  a0: hash(i * 3 + 2) * Math.PI * 2,
  /** 布朗漂移相位 */
  p: hash(i * 3 + 3) * Math.PI * 2,
  /** 漂移周期（s）— 5.2-11.4 差化 */
  w: 5.2 + hash(i * 3 + 4) * 6.2,
  /** 点亮峰值强度 */
  peak: 0.35 + hash(i * 3 + 5) * 0.55,
  el: null as SVGCircleElement | null,
}));

/* ===== 动画元素引用（svgEl 模板 ref — 多实例精确隔离） ===== */
const svgEl = ref<SVGSVGElement | null>(null);
let beamNEl: SVGPathElement | null = null;
let beamSEl: SVGPathElement | null = null;
let coreEl: SVGCircleElement | null = null;
let shellEl: SVGCircleElement | null = null;
let standingEls: SVGPathElement[] = [];
let rafId = 0;
let t0 = 0;
let running = false;

/* ===== 几何常量 ===== */
const CX = 48;
const CY = 48;
/** 磁轴倾角（rad） */
const MAG_TILT = (24 * Math.PI) / 180;
/** 束锥参数：核缘半径 / 束端半径 / 锥半张角 */
const R0 = 10;
const R1 = 42;
const CONE = 7 * (Math.PI / 180);
/** 自转角速度（rad/s）→ 扫掠周期 2.6s */
const OMEGA = (Math.PI * 2) / 2.6;
/** 驻波弧半径（4 道） */
const STANDING_R = [18, 24, 30, 36];

/** 谐波波（0→1→0 平滑 — 周期边界恒连续） */
const wave = (x: number): number => (1 - Math.cos(x * Math.PI * 2)) / 2;

/** 束锥路径：束轴方位角 a（垂直于磁轴方向），核缘 → 束端锥形 */
function beamPath(axisA: number): string {
  const widen = (r: number): number => CONE * (r / R1);
  const a0r = R0;
  const w0 = widen(R0);
  const w1 = widen(R1);
  /* 锥两侧母线：束轴 ± 张角（随半径线性张开） */
  const p1x = CX + Math.cos(axisA - w0) * a0r;
  const p1y = CY + Math.sin(axisA - w0) * a0r;
  const p2x = CX + Math.cos(axisA + w1) * R1;
  const p2y = CY + Math.sin(axisA + w1) * R1;
  const p3x = CX + Math.cos(axisA - w1) * R1;
  const p3y = CY + Math.sin(axisA - w1) * R1;
  const p4x = CX + Math.cos(axisA + w0) * a0r;
  const p4y = CY + Math.sin(axisA + w0) * a0r;
  return `M${p1x.toFixed(2)} ${p1y.toFixed(2)} L${p2x.toFixed(2)} ${p2y.toFixed(2)} Q${(CX + Math.cos(axisA) * (R1 + 4)).toFixed(2)} ${(CY + Math.sin(axisA) * (R1 + 4)).toFixed(2)} ${p3x.toFixed(2)} ${p3y.toFixed(2)} L${p4x.toFixed(2)} ${p4y.toFixed(2)} Q${(CX + Math.cos(axisA) * (R0 - 3)).toFixed(2)} ${(CY + Math.sin(axisA) * (R0 - 3)).toFixed(2)} ${p1x.toFixed(2)} ${p1y.toFixed(2)} Z`;
}

/** 驻波弧路径：中心角 θ、半径 r（弧 ±30° — 轻弧非整圆） */
function standingArc(theta: number, r: number): string {
  const HALF = (30 * Math.PI) / 180;
  const x1 = CX + Math.cos(theta - HALF) * r;
  const y1 = CY + Math.sin(theta - HALF) * r;
  const x2 = CX + Math.cos(theta + HALF) * r;
  const y2 = CY + Math.sin(theta + HALF) * r;
  return `M${x1.toFixed(2)} ${y1.toFixed(2)} A${r.toFixed(2)} ${r.toFixed(2)} 0 0 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

/** 方位角差归一化（-π..π） */
const angDiff = (a: number, b: number): number => {
  let d = a - b;
  while (d > Math.PI) d -= Math.PI * 2;
  while (d < -Math.PI) d += Math.PI * 2;
  return d;
};

/* ===== 主循环（rAF — 页面隐藏自动停帧） ===== */
function tick(now: number): void {
  if (!running) return;
  rafId = requestAnimationFrame(tick);
  const t = (now - t0) / 1000;

  /* 自转相位：匀速 + 非对称谐波修正（速度周期性加减速 — 拒绝匀速旋转） */
  const phase =
    OMEGA * t + 0.55 * Math.sin(t * 0.9) + 0.3 * Math.sin(t * 2.3 + 1.7);

  /* 束方位角：垂直于磁轴的两方向（南北束对） */
  const axisN = phase % (Math.PI * 2);
  const axisS = axisN + Math.PI;

  /* 北束亮度包络：谐波复合（周期边界恒连续） */
  const envN = 0.5 + 0.5 * wave((phase / (Math.PI * 2) * 3) % 1);

  /* 辐射束：路径 + 亮度（南北双束包络差化 — 永不同步） */
  if (beamNEl) {
    beamNEl.setAttribute("d", beamPath(axisN));
    beamNEl.style.opacity = (0.16 + 0.2 * envN).toFixed(3);
  }
  if (beamSEl) {
    beamSEl.setAttribute("d", beamPath(axisS));
    beamSEl.style.opacity = (0.13 + 0.16 * env2(t)).toFixed(3);
  }

  /* 脉冲核：双周期复合脉冲（快脉冲 0.9s + 慢谐波 4.1s — 非对称包络） */
  if (coreEl) {
    const fast = wave((t / 0.9) % 1);
    const slow = 0.62 + 0.38 * wave((t / 4.1) % 1);
    coreEl.style.opacity = (0.35 + 0.65 * fast * slow).toFixed(3);
  }
  if (shellEl) {
    shellEl.style.opacity = (0.18 + 0.22 * wave((t / 3.2) % 1)).toFixed(3);
  }

  /* 磁层驻波：4 道弧相位差化（束掠过时弹性舒张 + 点亮） */
  for (let i = 0; i < standingEls.length; i++) {
    const el = standingEls[i];
    if (!el) continue;
    /* 弧中心角：磁轴两侧 ±(90°) 起步，各弧相位差化 */
    const baseTheta = MAG_TILT + Math.PI / 2 + (i % 2 === 0 ? 0 : Math.PI);
    const sway = 0.12 * Math.sin(t * (0.7 + i * 0.23) + i * 1.9);
    const theta = baseTheta + sway;
    /* 半径调制：束方位角接近弧中心时轻微外扩（弹性舒张） */
    const near = Math.exp(-Math.pow(angDiff(axisN, theta) / 0.9, 2));
    const r = STANDING_R[i] + near * 2.4;
    el.setAttribute("d", standingArc(theta, r));
    /* 亮度：掠射点亮（束扫过 → 激发 → 衰减） */
    const excite = near * (0.6 + 0.4 * wave((t / (1.3 + i * 0.31)) % 1));
    el.style.opacity = (0.08 + 0.5 * excite).toFixed(3);
  }

  /* 掠射微尘：布朗漂移 + 束掠过点亮 */
  for (const d of motes) {
    if (!d.el) continue;
    const a = d.a0 + 0.9 * Math.sin(t / d.w * Math.PI * 2 + d.p) + 0.3 * Math.sin(t * 0.8 + d.p * 2);
    const x = CX + Math.cos(a) * d.r;
    const y = CY + Math.sin(a) * d.r;
    d.el.setAttribute("cx", x.toFixed(2));
    d.el.setAttribute("cy", y.toFixed(2));
    /* 束方位角邻近点亮（高斯衰减 — 交互影响范围自然衰减梯度） */
    const near = Math.exp(-Math.pow(angDiff(a, axisN) / 0.5, 2));
    d.el.style.opacity = (0.06 + d.peak * near).toFixed(3);
  }
}

/** 南束亮度包络（与北束差化 — 双束永不同步） */
function env2(t: number): number {
  return 0.5 + 0.5 * wave(((t / 1.7) + 0.33) % 1);
}

onMounted(() => {
  if (!props.loading) return;
  /* 元素引用提取（svgEl 模板 ref — 组件实例精确隔离，不误抓全局） */
  const svg = svgEl.value;
  if (!svg) return;
  beamNEl = svg.querySelector(".ql-beam-n");
  beamSEl = svg.querySelector(".ql-beam-s");
  coreEl = svg.querySelector(".ql-pulsar-core");
  shellEl = svg.querySelector(".ql-pulsar-shell");
  standingEls = Array.from(svg.querySelectorAll(".ql-standing"));
  motes.forEach((d, i) => {
    d.el = svg.querySelectorAll(".ql-mote")[i] as SVGCircleElement | null;
  });

  t0 = performance.now();
  running = true;
  rafId = requestAnimationFrame(tick);
});

onBeforeUnmount(() => {
  running = false;
  if (rafId) cancelAnimationFrame(rafId);
  motes.forEach((d) => (d.el = null));
});
</script>

<style scoped>
/* ============================================================
   QuantumCoreLoader.vue 样式引用（ql-loader.css v3 — 脉冲星磁层辐射）
   ============================================================ */
@import '../../../styles/security/ql-loader.css';

/* 容器布局 — 居中对齐，固定尺寸消除跳变 */
.quantum-core-loader {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  width: 100%;
}
</style>
