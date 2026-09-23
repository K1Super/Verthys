<!--
  HomeAtlas.vue — 引力星图（主界面默认视图核心视觉）
  偏轴轨道系统：三条非同心倾斜椭圆轨道（呼应银河盘斜视姿态与
    UnlockView 轨道丝线 — 全应用统一轨道运动语言），中心偏移各不相同
    （轨道摄动感，拒绝同心圆环模板）。
  奇点：暗食盘（黑洞事件视界 — 中心极暗 + 边缘微光 lifted）+ 双 rim
    弧反向差速旋转（内快外慢 — 开普勒差速，非辉光泛滥）。
  数据碎片刻痕：沿轨道切向的短刻线（确定性 hash 不规则分布 —
    "粒子数据碎片"主题语汇，非仪器刻度）。
  差速航点：rAF 驱动，角速度 ω ∝ r^-1.5（开普勒差速 — 与星系差速
    流转同物理规则），叠加低强度连续噪声扰动（杜绝机械同步），
    亮度复合谐波脉动。统一帧门控（useFrameGate 四档降频，失焦停帧）。
  入场：轨道 dash 生长揭示（错峰）+ 奇点缩放成型 + 碎片刻痕渐显 —
        与主界面进入转场衔接，一次性 backwards 填充零跳变。
-->
<template>
  <div class="atlas-wrap">
    <svg
      ref="svgRef"
      class="atlas"
      viewBox="0 0 920 620"
      fill="none"
      aria-hidden="true"
    >
      <defs>
        <!-- 奇点食盘：中心近纯黑 → 边缘微光（引力透镜边缘提升） -->
        <radialGradient id="ha-core" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="#010308" />
          <stop offset="74%" stop-color="#02040a" />
          <stop offset="94%" stop-color="#0a1726" />
          <stop offset="100%" stop-color="#0e1e31" />
        </radialGradient>
        <!-- 航点软边填充（抗锯齿光点 — 渐变边缘替代 blur） -->
        <radialGradient id="ha-wp-cyan">
          <stop offset="0%" stop-color="#e2f8ff" />
          <stop offset="55%" stop-color="#7fd8e8" />
          <stop offset="100%" stop-color="rgba(127, 216, 232, 0)" />
        </radialGradient>
        <radialGradient id="ha-wp-silver">
          <stop offset="0%" stop-color="#f2f8ff" />
          <stop offset="55%" stop-color="#cfe2f2" />
          <stop offset="100%" stop-color="rgba(207, 226, 242, 0)" />
        </radialGradient>
        <radialGradient id="ha-wp-violet">
          <stop offset="0%" stop-color="#efe9ff" />
          <stop offset="55%" stop-color="#b9a8e8" />
          <stop offset="100%" stop-color="rgba(185, 168, 232, 0)" />
        </radialGradient>
        <radialGradient id="ha-wp-warm">
          <stop offset="0%" stop-color="#fdf4e3" />
          <stop offset="55%" stop-color="#e8d0a4" />
          <stop offset="100%" stop-color="rgba(232, 208, 164, 0)" />
        </radialGradient>
      </defs>

      <!-- 轨道（非同心：中心逐条偏移；CSS transform 旋转 — 与脚本
           point() 同源参数，几何单一权威源） -->
      <g class="orbits">
        <ellipse
          v-for="(o, i) in orbits"
          :key="`o${i}`"
          :class="'orbit orbit-' + i"
          pathLength="1"
          :cx="o.cx"
          :cy="o.cy"
          :rx="o.rx"
          :ry="o.ry"
        />
      </g>

      <!-- 数据碎片刻痕（沿轨道切向 — 确定性 hash 不规则分布） -->
      <g class="fragments">
        <line
          v-for="f in fragments"
          :key="f.id"
          class="frag"
          :x1="f.x1"
          :y1="f.y1"
          :x2="f.x2"
          :y2="f.y2"
          :style="{ '--fd': f.delay + 'ms' }"
        />
      </g>

      <!-- 奇点：暗食盘 + 双 rim 弧反向差速 -->
      <g class="singularity">
        <circle class="event-horizon" :cx="SG.x" :cy="SG.y" r="24" fill="url(#ha-core)" />
        <circle class="rim rim-a" pathLength="1" :cx="SG.x" :cy="SG.y" r="30" />
        <circle class="rim rim-b" pathLength="1" :cx="SG.x" :cy="SG.y" r="36" />
      </g>

      <!-- 差速航点（rAF 写 SVG transform — 用户坐标系随 viewBox 缩放，
           自适应容器尺寸；初始位置由 setup 求值绑定） -->
      <g class="waypoints" ref="wpGroupRef">
        <circle
          v-for="w in waypoints"
          :key="`w${w.id}`"
          class="waypoint"
          :r="w.r"
          :fill="w.fill"
          :transform="`translate(${w.x0} ${w.y0})`"
        />
      </g>
    </svg>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from "vue";
import { useGlobalIdleScheduler } from "../../composables/useGlobalIdleScheduler";
import { useFrameGate } from "../../composables/useFrameGate";

/* ============================================================================
 * 轨道系统参数（几何单一权威源 — 模板 ellipse 与脚本 point() 同源）：
 * 三条非同心倾斜椭圆：中心逐条偏移（摄动）+ 倾角差化（-17°/-8°/+6°）
 * + 半径递减 — 呼应银河盘斜视姿态，拒绝同心圆环。
 * ========================================================================== */
interface OrbitDef {
  cx: number;
  cy: number;
  rx: number;
  ry: number;
  /** 倾角（deg，CSS transform 旋转 — fill-box 中心） */
  rot: number;
}
const ORBITS: OrbitDef[] = [
  { cx: 450, cy: 312, rx: 382, ry: 128, rot: -17 },
  { cx: 466, cy: 300, rx: 298, ry: 97, rot: -8 },
  { cx: 436, cy: 326, rx: 212, ry: 66, rot: 6 },
];
const orbits = ORBITS;

/** 奇点位置（视觉近似三轨交汇重心 — 非精确几何中心） */
const SG = { x: 452, y: 312 };

/* ---------- 椭圆参数几何（旋转坐标系求值） ---------- */
const RAD = Math.PI / 180;
/** 轨道参数角 E 处的点坐标（含倾角旋转） */
function orbitPoint(o: OrbitDef, E: number): { x: number; y: number } {
  const px = o.rx * Math.cos(E);
  const py = o.ry * Math.sin(E);
  const c = Math.cos(o.rot * RAD);
  const s = Math.sin(o.rot * RAD);
  return { x: o.cx + px * c - py * s, y: o.cy + px * s + py * c };
}
/** 轨道参数角 E 处的切向单位向量（含倾角旋转） */
function orbitTangent(o: OrbitDef, E: number): { x: number; y: number } {
  const tx = -o.rx * Math.sin(E);
  const ty = o.ry * Math.cos(E);
  const c = Math.cos(o.rot * RAD);
  const s = Math.sin(o.rot * RAD);
  const rx = tx * c - ty * s;
  const ry = tx * s + ty * c;
  const len = Math.hypot(rx, ry) || 1;
  return { x: rx / len, y: ry / len };
}

/* ---------- 数据碎片刻痕（确定性 hash — 不规则切向短刻线） ---------- */
const hash = (seed: number, salt: number): number => {
  const x = Math.sin(seed * 127.1 + salt * 311.7) * 43758.5453;
  return x - Math.floor(x);
};
const fragments = ORBITS.flatMap((o, oi) => {
  const n = 5 + Math.floor(hash(oi + 60, 1) * 3); // 每轨 5-7 根
  return Array.from({ length: n }, (_, k) => {
    const E = hash(oi + 60, k * 3 + 2) * Math.PI * 2;
    const p = orbitPoint(o, E);
    const t = orbitTangent(o, E);
    const half = (2.5 + hash(oi + 60, k * 3 + 3) * 4) / 2; // 全长 2.5-6.5px
    return {
      id: `f${oi}-${k}`,
      x1: +(p.x - t.x * half).toFixed(2),
      y1: +(p.y - t.y * half).toFixed(2),
      x2: +(p.x + t.x * half).toFixed(2),
      y2: +(p.y + t.y * half).toFixed(2),
      delay: Math.round(700 + hash(oi + 60, k * 3 + 4) * 900), // 入场错峰
    };
  });
});

/* ============================================================================
 * 差速航点（开普勒差速 — 与星系差速流转同物理规则）：
 * ω = K · rx^-1.5：外轨周期 ~90s / 中轨 ~62s / 内轨 ~37s（内快外慢）；
 * 叠加低强度连续噪声扰动（0.035·sin，逐航点独立相位 — 杜绝同步机械运动）；
 * 亮度复合谐波脉动（基波 + 2 次谐波 — 非单一正弦）。
 * ========================================================================== */
const OMEGA_K = 521; // ω = OMEGA_K / rx^1.5（rad/s）
const TAU = Math.PI * 2;
const wave = (x: number): number => 0.5 - 0.5 * Math.cos(TAU * x);

interface WaypointDef {
  id: number;
  orbit: number;
  E0: number;
  r: number;
  fill: string;
  /** 噪声/脉动独立相位种子 */
  seed: number;
  /** 脉动周期（s） */
  period: number;
  /** 初始位置（首帧前模板绑定 — 杜绝 (0,0) 闪现） */
  x0: number;
  y0: number;
}
const RAW_WAYPOINTS = [
  { orbit: 0, E0: 0.8, r: 3.2, fill: "url(#ha-wp-cyan)", seed: 1.7, period: 8.2 },
  { orbit: 1, E0: 2.3, r: 2.3, fill: "url(#ha-wp-silver)", seed: 4.1, period: 6.4 },
  { orbit: 1, E0: 5.0, r: 1.9, fill: "url(#ha-wp-violet)", seed: 7.3, period: 7.1 },
  { orbit: 2, E0: 5.7, r: 2.7, fill: "url(#ha-wp-warm)", seed: 9.9, period: 5.6 },
];
const waypoints: WaypointDef[] = RAW_WAYPOINTS.map((w, i) => {
  const p = orbitPoint(ORBITS[w.orbit], w.E0);
  return { id: i, ...w, x0: +p.x.toFixed(2), y0: +p.y.toFixed(2) };
});

/* ---------- 逐帧差速驱动（统一帧门控：四档降频 / 失焦停帧 / 异常熔断） ---------- */
const svgRef = ref<SVGSVGElement | null>(null);
const wpGroupRef = ref<SVGGElement | null>(null);
let wpEls: SVGCircleElement[] = [];
/* 进度墙钟基准：首个许可帧的 wallClock（档位降频时差速进度不减速） */
let startWall = -1;

const renderFrame = (_frameStep: number, wallClock: number) => {
  if (startWall < 0) startWall = wallClock;
  const t = wallClock - startWall;
  for (let i = 0; i < wpEls.length; i++) {
    const w = waypoints[i];
    const o = ORBITS[w.orbit];
    /* 开普勒差速：内轨快外轨慢（与星系差速流转同规则） */
    const omega = OMEGA_K / Math.pow(o.rx, 1.5);
    /* 低强度连续噪声扰动（独立相位 — 轨道相位微摄动，秩序不乱） */
    const noise = 0.035 * Math.sin(t * 0.31 + w.seed);
    const p = orbitPoint(o, w.E0 + omega * t + noise);
    wpEls[i].setAttribute("transform", `translate(${p.x.toFixed(2)} ${p.y.toFixed(2)})`);
    /* 复合谐波脉动（基波 + 2 次谐波 — 周期边界连续零跳变） */
    const frac = ((t / w.period + w.seed) % 1 + 1) % 1;
    const pulse = 0.74 + 0.26 * (0.64 * wave(frac) + 0.36 * wave(2 * frac));
    wpEls[i].style.opacity = pulse.toFixed(3);
  }
};

const { level: idleLevel } = useGlobalIdleScheduler();
const { start: startGate, stop: stopGate } = useFrameGate(idleLevel, renderFrame);

onMounted(() => {
  wpEls = wpGroupRef.value
    ? Array.from(wpGroupRef.value.querySelectorAll<SVGCircleElement>(".waypoint"))
    : [];
  startGate();
});
onBeforeUnmount(stopGate);
</script>

<style scoped>
.atlas-wrap {
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
}
.atlas {
  width: 100%;
  height: auto;
  overflow: visible;
}

/* ===== 轨道（非同心倾斜椭圆 — dash 差速巡行 + 生长揭示） =====
 * 倾角根治：静态 rotate 写入基线规则（入场 reveal 结束后永久保留 —
 *   旧版倾角仅存在于 keyframes，backwards 填充在动画结束瞬间失效，
 *   transform 回落无旋转基线 → 轨道"突然变平整"的根因）；
 *   keyframes to 帧与基线逐值一致 → 动画结束零跳变。 */
.orbit {
  transform-box: fill-box;
  transform-origin: center;
  stroke-width: 1;
  vector-effect: non-scaling-stroke;
  fill: none;
}
.orbit-0 {
  stroke: rgba(0, 212, 255, 0.14);
  stroke-dasharray: 0.44 0.07 0.3 0.19;
  transform: rotate(-17deg);
  animation:
    flow-fwd 64s linear infinite,
    reveal-o0 1.5s var(--ease) 0.15s backwards;
}
.orbit-1 {
  stroke: rgba(139, 92, 246, 0.12);
  stroke-dasharray: 0.16 0.12 0.5 0.22;
  transform: rotate(-8deg);
  animation:
    flow-rev 47s linear infinite,
    reveal-o1 1.5s var(--ease) 0.34s backwards;
}
.orbit-2 {
  stroke: rgba(205, 224, 244, 0.13);
  stroke-dasharray: 0.3 0.1 0.38 0.22;
  transform: rotate(6deg);
  animation:
    flow-fwd 36s linear infinite,
    reveal-o2 1.5s var(--ease) 0.52s backwards;
}
/* dash 巡行（pathLength=1 归一化 — 模式总长 1.0 → 整圈无缝循环） */
@keyframes flow-fwd {
  to { stroke-dashoffset: -1; }
}
@keyframes flow-rev {
  to { stroke-dashoffset: 1; }
}
/* 生长揭示：dash 自零生长 + 微缩放渐显（backwards 填充覆盖延迟期，
 * to 帧 = 基线逐值一致 — 揭示结束零跳变；巡行动画同名保留相位连续） */
@keyframes reveal-o0 {
  from {
    opacity: 0;
    transform: rotate(-17deg) scale(0.955);
    stroke-dasharray: 0 0.5 0 0.5;
  }
  to {
    opacity: 1;
    transform: rotate(-17deg) scale(1);
    stroke-dasharray: 0.44 0.07 0.3 0.19;
  }
}
@keyframes reveal-o1 {
  from {
    opacity: 0;
    transform: rotate(-8deg) scale(0.955);
    stroke-dasharray: 0 0.5 0 0.5;
  }
  to {
    opacity: 1;
    transform: rotate(-8deg) scale(1);
    stroke-dasharray: 0.16 0.12 0.5 0.22;
  }
}
@keyframes reveal-o2 {
  from {
    opacity: 0;
    transform: rotate(6deg) scale(0.955);
    stroke-dasharray: 0 0.5 0 0.5;
  }
  to {
    opacity: 1;
    transform: rotate(6deg) scale(1);
    stroke-dasharray: 0.3 0.1 0.38 0.22;
  }
}

/* ===== 数据碎片刻痕（切向短刻线 — 静态驻留，错峰渐显） ===== */
.frag {
  stroke: rgba(159, 181, 201, 0.22);
  stroke-width: 1;
  vector-effect: non-scaling-stroke;
  opacity: 0;
  animation: frag-in 0.7s var(--ease) var(--fd, 700ms) forwards;
}
@keyframes frag-in {
  to { opacity: 1; }
}

/* ===== 奇点（暗食盘 + 双 rim 弧反向差速） ===== */
.singularity {
  transform-box: fill-box;
  transform-origin: center;
  animation: sg-in 1.2s cubic-bezier(0.22, 1, 0.36, 1) 0.5s backwards;
}
.event-horizon {
  /* 事件视界边缘细描（引力透镜边缘光 — 极克制） */
  stroke: rgba(140, 190, 230, 0.16);
  stroke-width: 1;
}
.rim {
  fill: none;
  stroke-width: 1.2;
  stroke-linecap: round;
  vector-effect: non-scaling-stroke;
}
.rim-a {
  stroke: rgba(0, 212, 255, 0.5);
  stroke-dasharray: 0.26 0.74;
  animation: rim-fwd 18s linear infinite;
}
.rim-b {
  stroke: rgba(139, 92, 246, 0.3);
  stroke-dasharray: 0.15 0.85;
  animation: rim-rev 29s linear infinite;
}
@keyframes rim-fwd {
  to { stroke-dashoffset: -1; }
}
@keyframes rim-rev {
  to { stroke-dashoffset: 1; }
}
@keyframes sg-in {
  from {
    opacity: 0;
    transform: scale(0.55);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}

/* ===== 差速航点（rAF 驱动位置/亮度 — 组层入场淡入，与逐元素
        rAF opacity 写入零冲突：动画只作用于父组） ===== */
.waypoints {
  animation: wp-group-in 1s var(--ease) 1.1s backwards;
}
@keyframes wp-group-in {
  from { opacity: 0; }
  to { opacity: 1; }
}
</style>
