<!--
  ManagementHub.vue — 管理界面前置引导组件（纯视觉 · 零文字 · 吸积流光）

  布局（规整排放）：
    三个引导单元等尺寸、等间距、同一基线水平一行，居中于容器。
    --u-size / --row-delta 由引擎按容器尺寸计算写入（自适应，无变形）。

  视觉体系（每个单元 = 吸积流光结构，与量子面板同源，非仪表表盘）：
    F1 非对称开放弧流 ×2（不同半径/跨度/转速/转向，渐变描边圆头 —
       吸积盘流光，非闭合圆环）
    F2 碎屑带（mulberry32 生成的非均匀碎片矩形，慢速漂移 — 引力碎屑）
    F3 单元语义核心（全局密钥形态+设备系链 / 模块星群 / 盾形层叠）

  悬浮反馈（无大块阴影/辉光 — 三重物理驱动，引擎逐帧写入变量）：
    1. 语义核心磁悬浮升腾（--lift：boost 弹簧 px 量，上浮 + 微放大，
       惯性回落无突变）
    2. 碎屑引力收缩（独立 scale 属性叠加旋转动画 — 吸积场增强碎屑内聚）
    3. 弧流能量增稠（stroke-width / 亮度随 boost 复合增密）

  共享能量基底（Canvas，全单元间的场）：
    - 尘埃场：稀疏多频漂移微粒，光标高斯引力微扰
    - 能量丝链：三单元间的悬链曲线（下垂数值化 + 噪声微动），
      光标临近时丝线向光标弯曲（磁力线弯折，差异化传播逻辑）
    - 隧穿光包：稀有光包沿丝链隧穿传播；点击单元 → 光包向其余
      两单元定向爆发传播（能量扩散仪式）后进入管理界面

  交互引擎（与 useQuantumField 同规范）：
    单帧响应 / 弹簧阻尼（先积分后消费）/ 优先级仲裁（hover P1 抑制视差）/
    高斯衰减梯度（σ 随容器缩放）/ 错峰入场编排（复合曲线）/
    尺寸自适应（ResizeObserver + 布局变量重算）/ 零 GC 池化 /
    帧率自适应（EMA 帧时间 → 尘埃密度动态增减）/ 页面隐藏暂停

  Props: globalKeyReady / deviceCheckResult / moduleIds / moduleStateClass
  Emits: enter(section) / back（back 由点击面板空白处触发）
-->
<template>
  <div ref="panelRef" class="mh-hub" @pointermove="onPointerMove" @pointerleave="onPointerLeave" @click="onHubClick">
    <!-- 共享能量基底画布（尘埃 + 丝链 + 光包） -->
    <canvas ref="canvasRef" class="mh-field"></canvas>

    <!-- 点击空白处返回量子面板（无返回图标，引导单元点击不触发） -->

    <!-- ===== 引导单元 1：全局密钥（就绪状态 + 设备绑定） ===== -->
    <button
      ref="u1Ref"
      class="mh-unit mh-u1"
      :class="{ ready: globalKeyReady, ['mh-bind-' + bindVisual]: true }"
      @pointerenter="onEnter(0)" @pointerleave="onLeave(0)"
      @pointerdown="onDown(0)" @pointerup="onUp(0)"
      @click="activate(0)"
    >
      <svg viewBox="0 0 200 200" class="mh-svg">
        <defs>
          <linearGradient id="mh-g1" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#00ffaa"/><stop offset="1" stop-color="#00d4ff"/>
          </linearGradient>
        </defs>
        <!-- F1 非对称开放弧流（差速反向） -->
        <g class="mh-swA"><path class="mh-fa" d="M171 59 A82 82 0 0 1 114 181"/></g>
        <g class="mh-swB"><path class="mh-fb" d="M39.4 135 A70 70 0 0 1 55 46.4"/></g>
        <!-- F2 碎屑带（非均匀碎片，慢速漂移） -->
        <g class="mh-debris">
          <rect v-for="(s, i) in SHARDS[0]" :key="i" class="mh-shard"
                :x="s.x" :y="s.y" :width="s.w" :height="s.h" :opacity="s.op"
                :transform="`rotate(${s.rot} ${s.x} ${s.y})`"/>
        </g>
        <!-- F3 语义：密钥形态 + 设备系链（悬浮升腾组 --lift） -->
        <g class="mh-sema">
          <g class="mh-key" transform="rotate(-22 100 100)">
            <circle class="mh-keyBow" cx="86" cy="100" r="13"/>
            <path class="mh-keyStem" d="M99 100 H138"/>
            <path class="mh-keyTeeth" d="M127 100 V113 M137 100 V117"/>
          </g>
          <path class="mh-tether" d="M78 90 C 66 80, 60 72, 54 60"/>
          <circle class="mh-bindNode" cx="52" cy="57" r="3.4"/>
        </g>
      </svg>
    </button>

    <!-- ===== 引导单元 2：模块独立密钥 ===== -->
    <button
      ref="u2Ref"
      class="mh-unit mh-u2"
      @pointerenter="onEnter(1)" @pointerleave="onLeave(1)"
      @pointerdown="onDown(1)" @pointerup="onUp(1)"
      @click="activate(1)"
    >
      <svg viewBox="0 0 200 200" class="mh-svg">
        <defs>
          <linearGradient id="mh-g2" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#00d4ff"/><stop offset="1" stop-color="#8b5cf6"/>
          </linearGradient>
        </defs>
        <!-- F1 非对称开放弧流（大跨度主弧 + 短副弧） -->
        <g class="mh-swA"><path class="mh-fa" d="M180.8 114.2 A82 82 0 0 1 23 128"/></g>
        <g class="mh-swB"><path class="mh-fb" d="M36.1 76.7 A68 68 0 0 1 88.2 33"/></g>
        <!-- F2 碎屑带 -->
        <g class="mh-debris">
          <rect v-for="(s, i) in SHARDS[1]" :key="i" class="mh-shard"
                :x="s.x" :y="s.y" :width="s.w" :height="s.h" :opacity="s.op"
                :transform="`rotate(${s.rot} ${s.x} ${s.y})`"/>
        </g>
        <!-- F3 语义：核心辉光 + 四卫星星群 + 曲线链路（悬浮升腾组 --lift） -->
        <g class="mh-sema">
          <g v-for="(s, i) in SATS" :key="i">
            <path class="mh-satLink" :d="`M100 100 Q ${s.ctrl} ${s.x} ${s.y}`"/>
            <circle class="mh-satGlow" :class="modNodeClass(moduleIds[i])" :cx="s.x" :cy="s.y" r="7"/>
            <circle class="mh-satDot" :class="modNodeClass(moduleIds[i])" :cx="s.x" :cy="s.y" r="3"/>
          </g>
          <circle class="mh-coreHalo" cx="100" cy="100" r="15"/>
          <circle class="mh-coreDot" cx="100" cy="100" r="3.2"/>
        </g>
      </svg>
    </button>

    <!-- ===== 引导单元 3：安全防护 ===== -->
    <button
      ref="u3Ref"
      class="mh-unit mh-u3"
      @pointerenter="onEnter(2)" @pointerleave="onLeave(2)"
      @pointerdown="onDown(2)" @pointerup="onUp(2)"
      @click="activate(2)"
    >
      <svg viewBox="0 0 200 200" class="mh-svg">
        <defs>
          <linearGradient id="mh-g3" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#8b5cf6"/><stop offset="1" stop-color="#00ffaa"/>
          </linearGradient>
        </defs>
        <!-- F1 非对称开放弧流（特长主弧 + 中副弧） -->
        <g class="mh-swA"><path class="mh-fa" d="M114.2 19.2 A82 82 0 1 1 59 171"/></g>
        <g class="mh-swB"><path class="mh-fb" d="M157.2 133 A66 66 0 0 1 62.1 154"/></g>
        <!-- F2 碎屑带 -->
        <g class="mh-debris">
          <rect v-for="(s, i) in SHARDS[2]" :key="i" class="mh-shard"
                :x="s.x" :y="s.y" :width="s.w" :height="s.h" :opacity="s.op"
                :transform="`rotate(${s.rot} ${s.x} ${s.y})`"/>
        </g>
        <!-- F3 语义：盾形层叠轮廓 + 内部扫掠弧 + 核心（悬浮升腾组 --lift） -->
        <g class="mh-sema">
          <path class="mh-shieldOuter" d="M100 36 L148 55 V98 C148 127 129 149 100 164 C71 149 52 127 52 98 V55 Z"/>
          <path class="mh-shieldInner" d="M100 50 L136 65 V98 C136 119 121 136 100 148 C79 136 64 119 64 98 V65 Z"/>
          <g class="mh-so1"><path d="M76 96 A26 26 0 0 1 100 72"/></g>
          <g class="mh-so2"><path d="M122 88 A24 24 0 0 1 112 118"/></g>
          <circle class="mh-shieldCore" cx="100" cy="101" r="4"/>
        </g>
      </svg>
    </button>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import type { ModuleId } from '../../lib/keyManager';
import type { DeviceCheckResult } from '../../composables/security-center/useViewMode';
import {
  makeSpring,
  springStep,
  phase,
  makeDrift,
  mulberry32,
  type Spring,
} from '../../composables/security-center/useQuantumField';
import { useGlobalIdleScheduler } from '../../composables/useGlobalIdleScheduler';
import { useFrameGate } from '../../composables/useFrameGate';
import { createPacketRitual, type PacketRitual } from '../../composables/management/packetRitual';

/**
 * ManagementHub Props
 */
const props = defineProps<{
  /** 全局密钥就绪状态（弧色 / 密钥能量色） */
  globalKeyReady: boolean;
  /** 设备绑定校验结果（链路环形态） */
  deviceCheckResult: DeviceCheckResult;
  /** 模块 ID 列表（单元 2 卫星节点） */
  moduleIds: ModuleId[];
  /** 模块状态指示类（函数 → 卫星色） */
  moduleStateClass: (mid: ModuleId) => string;
}>();

/**
 * ManagementHub Emits
 */
const emit = defineEmits<{
  (e: 'enter', section: 'globalKey' | 'moduleKeys' | 'security'): void;
  (e: 'back'): void;
}>();

/* ===== 常量 ===== */
const SECTIONS = ['globalKey', 'moduleKeys', 'security'] as const;
const N_UNITS = 3;
/** 丝链：[单元A, 单元B, 下垂数值(负=上拱), 采样段数] — 邻接双下垛 + 跨接上拱 */
const FILAMENTS: Array<[number, number, number, number]> = [
  [0, 1, 22, 26],
  [1, 2, 22, 26],
  [0, 2, -52, 34],
];

/* ===== 传播仪式节奏配置（单一数据源） =====
 * 传播 + 落定 = 720ms 总仪式时长；视图切换由传播完成事件驱动，
 * 引擎内禁止任何固定延时等待动画。 */
const RITUAL_DURATION = {
  /** 光包传播时长（秒） */
  propagation: 0.62,
  /** 落定时长（秒，光晕扩散 + 终点锚闪光渐熄） */
  landing: 0.1,
  /** 帧步进钳制上限（秒）：仅用于弹簧/衰减等物理积分，绝不参与进度计算 */
  maxPhysicsStep: 0.05,
} as const;

/** 无障碍降级：reduced-motion 下跳过传播与落定，直接进入视图切换 */
const reducedMotion =
  typeof window !== 'undefined' &&
  typeof window.matchMedia === 'function' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/** 传播仪式状态机（纯时间逻辑，见 packetRitual） */
const ritual: PacketRitual = createPacketRitual({
  propagationDuration: RITUAL_DURATION.propagation,
  landingDuration: RITUAL_DURATION.landing,
  reducedMotion,
});
/** 落定逻辑完成帧标志：下一帧领取完成事件并驱动视图切换（双帧约定） */
let completePending = false;
/** 爆发传播的终点单元（落定光晕与锚闪光的落点） */
const burstTargets: number[] = [];
/** 爆发传播的起点单元（完成事件携带的目标分区） */
let burstFrom = 0;

/* ===== 碎屑带生成（mulberry32：非均匀半径/角度/尺寸/透明度 — 引力碎屑，拒绝刻度环） ===== */
interface Shard { x: number; y: number; rot: number; w: number; h: number; op: number; }
function genShards(seed: number, count: number): Shard[] {
  const r = mulberry32(seed);
  const out: Shard[] = [];
  for (let i = 0; i < count; i++) {
    const a = r() * Math.PI * 2;
    const rad = 60 + r() * 28;
    const x = +(100 + Math.cos(a) * rad).toFixed(1);
    const y = +(100 + Math.sin(a) * rad).toFixed(1);
    const rot = Math.round((a * 180) / Math.PI + 90 + (r() * 40 - 20));
    out.push({ x, y, rot, w: +(1 + r() * 1.2).toFixed(2), h: +(3 + r() * 5.5).toFixed(1), op: +(0.22 + r() * 0.42).toFixed(2) });
  }
  return out;
}
const SHARDS = [genShards(1013, 8), genShards(2027, 8), genShards(3041, 8)];

/* ===== 单元 2 卫星（非对称相位）与链路控制点 ===== */
const SATS = [
  { x: 68, y: 54, ctrl: '84 62' },
  { x: 136, y: 68, ctrl: '120 76' },
  { x: 60, y: 140, ctrl: '78 126' },
  { x: 130, y: 148, ctrl: '118 134' },
];

/* ===== 绑定视觉形态 ===== */
const bindVisual = computed(() => {
  switch (props.deviceCheckResult) {
    case 'match': return 'on';
    case 'mismatch':
    case 'error': return 'warn';
    case 'checking': return 'scan';
    default: return 'off';
  }
});

/* ===== 卫星状态色类 ===== */
function modNodeClass(mid: ModuleId): string {
  const s = props.moduleStateClass(mid);
  if (s.includes('active')) return 'mh-n-active';
  if (s.includes('set')) return 'mh-n-set';
  if (s.includes('empty')) return 'mh-n-empty';
  return 'mh-n-off';
}

/* ===== 点击空白处返回量子面板 =====
 * 引导单元（.mh-unit）点击由单元自身 activate 处理，冒泡到此直接忽略；
 * 其余点击（面板空白 / 能量基底画布区域 — canvas pointer-events:none，
 * target 为 .mh-hub 自身）触发 back */
function onHubClick(e: MouseEvent): void {
  const t = e.target as HTMLElement;
  if (t.closest('.mh-unit')) return;
  emit('back');
}

/* ===== DOM refs ===== */
const panelRef = ref<HTMLElement | null>(null);
const canvasRef = ref<HTMLCanvasElement | null>(null);
const u1Ref = ref<HTMLElement | null>(null);
const u2Ref = ref<HTMLElement | null>(null);
const u3Ref = ref<HTMLElement | null>(null);

/* ===== 引擎状态（全部预分配，零 GC） ===== */
// 单元弹簧：缩放（hover 1.05 / 按下 0.93）/ 磁倾角 / 能量增益
const scaleSprings: Spring[] = [makeSpring(90, 0.9, 1), makeSpring(90, 0.9, 1), makeSpring(90, 0.9, 1)];
const tiltSprings: Spring[] = [makeSpring(26, 1.05, 0), makeSpring(26, 1.05, 0), makeSpring(26, 1.05, 0)];
const boostSprings: Spring[] = [makeSpring(55, 1.1, 0), makeSpring(55, 1.1, 0), makeSpring(55, 1.1, 0)];
// 背景视差（弱）
const parallaxX = makeSpring(26, 0.9, 0);
const parallaxY = makeSpring(26, 0.9, 0);

let ctx: CanvasRenderingContext2D | null = null;
/** 引擎墙钟：未钳制门控 dt 累积（秒），供相位与进度计算，时间流速恒为 1× */
let clockSec = 0;
let introTime = 0;
let frameCount = 0;
let avgFrameMs = 16.7;
/** 上一许可帧墙钟（首帧守卫 — 首帧增量为 0） */
let lastWallClock = -1;

/* G-8 统一帧门控（useFrameGate → 主渲染循环注册层）：帧率档位由
   全局空闲状态机唯一决定（active 60 / settling 30 / idle 5 /
   deep-idle 1 fps），帧步进由主循环供给（钳制 50ms），墙钟增量
   供相位与进度；本引擎不再维护私有空闲判定、visibilitychange
   与全局交互监听。 */
const { level: idleLevel, resetIdle } = useGlobalIdleScheduler();
let hoverN = 0;
let width = 0;
let height = 0;
let minDim = 1;
let dpr = 1;
let sizeOk = false;
let unitSize = 190;
let rowDelta = 300;
/** 单元中心（面板坐标，layout() 重算） */
const centers = [new Float64Array(2), new Float64Array(2), new Float64Array(2)];
/** 光标（面板坐标；离开时置远） */
let cursorX = -1e5;
let cursorY = -1e5;
let cursorOn = false;
/** 点击传播闪光（每单元，指数衰减） */
const flash = new Float64Array(N_UNITS);
/** 布局变量写入标记 */
let styleVarsDirty = true;

/* ===== 池化场元素 ===== */
interface Mote { x01: number; y01: number; size: number; alpha: number; depth: number; dxi: number; dyi: number; }
const MOTE_MAX = 44;
const motes: Mote[] = [];
const moteDrifts: Array<(t: number) => number> = [];
{
  const r = mulberry32(20260823);
  for (let i = 0; i < MOTE_MAX; i++) {
    motes.push({
      x01: r(), y01: r(),
      size: 0.7 + r() * 1.5,
      alpha: 0.16 + r() * 0.3,
      depth: 0.4 + r() * 0.6,
      dxi: i * 2, dyi: i * 2 + 1,
    });
    moteDrifts.push(makeDrift(7000 + i * 131), makeDrift(9000 + i * 197));
  }
}
let moteActive = MOTE_MAX;

/** 丝链噪声（每链独立） */
const filDrifts = FILAMENTS.map((_, k) => makeDrift(3100 + k * 401));

/** 光包池（隧穿传播） */
interface Packet {
  active: boolean;
  t: number;
  dur: number;
  fil: number;
  rev: boolean;
  strength: number;
  /** 爆发包（点击传播仪式，进度由仪式节奏驱动）；false 为自发隧穿包 */
  burst: boolean;
}
const PACKETS: Packet[] = Array.from({ length: 14 }, () => ({
  active: false, t: 0, dur: 0.9, fil: 0, rev: false, strength: 0.5, burst: false,
}));
let nextPacketAt = 1.8;

/** 光点贴图（预渲染径向渐变，一次分配） */
let sprite: HTMLCanvasElement | null = null;

/* ===== 指针交互（单帧响应：直写目标，rAF 帧内积分消费）
 * 面板左缘/顶缘在 layout() 里一次性缓存：pointermove 事件路径零布局读取，
 * 避免与 frame() 逐帧 CSS 变量写入叠加触发同步样式重算（WebView2 卡死源）。 */
let panelLeft = 0;
let panelTop = 0;
function onPointerMove(e: PointerEvent): void {
  cursorX = e.clientX - panelLeft;
  cursorY = e.clientY - panelTop;
  cursorOn = true;
  parallaxX.target = ((cursorX / Math.max(width, 1)) - 0.5) * 2;
  parallaxY.target = ((cursorY / Math.max(height, 1)) - 0.5) * 2;
}

function onPointerLeave(): void {
  cursorOn = false;
  cursorX = -1e5;
  cursorY = -1e5;
  parallaxX.target = 0;
  parallaxY.target = 0;
}

function onEnter(i: number): void {
  hoverN++;
  scaleSprings[i].target = 1.05;
  boostSprings[i].target = 1;
}

function onLeave(i: number): void {
  hoverN = Math.max(0, hoverN - 1);
  scaleSprings[i].target = 1;
  boostSprings[i].target = 0;
}

function onDown(i: number): void {
  scaleSprings[i].target = 0.93;
}

function onUp(i: number): void {
  scaleSprings[i].target = hoverN > 0 ? 1.05 : 1;
}

/* ===== 点击：能量爆发传播 → 进入管理界面 =====
 * 视图切换由传播完成事件驱动（传播 620ms + 落定 100ms 完整呈现后，
 * 双帧约定在落定渲染帧的下一帧 emit enter）；无固定延时。
 * 传播期间重复点击其他引导单元被仪式状态机幂等拒绝。 */
function activate(i: number): void {
  if (ritual.phase !== 'idle' || completePending) return;
  // 关键动画恢复满帧：传播仪式全程 60fps（交互已触发 active，此处兜底）
  resetIdle();

  burstFrom = i;
  flash[i] = 1;
  burstTargets.length = 0;
  // 光包定向爆发：i → 其余两单元（走对应丝链）
  for (let k = 0; k < FILAMENTS.length; k++) {
    const [a, b] = FILAMENTS[k];
    if (a !== i && b !== i) continue;
    const p = PACKETS.find((q) => !q.active);
    if (!p) continue;
    p.active = true;
    p.t = 0;
    p.dur = RITUAL_DURATION.propagation;
    p.fil = k;
    p.rev = b === i; // 从 i 端出发
    p.strength = 1;
    p.burst = true;
    burstTargets.push(b === i ? a : b);
  }
  ritual.begin();
}

/* ===== 布局（规整排放：等尺寸 / 等间距 / 同基线，自适应容器） ===== */
function layout(): void {
  const panel = panelRef.value;
  const canvas = canvasRef.value;
  if (!panel || !canvas) return;
  const rect = panel.getBoundingClientRect();
  width = rect.width;
  height = rect.height;
  minDim = Math.min(width, height) || 1;
  dpr = Math.min(window.devicePixelRatio || 1, 2);
  sizeOk = width >= 10 && height >= 10;
  panelLeft = rect.left;
  panelTop = rect.top;

  /* 单元占局缩小（~75%）：尺寸上限 196→148、下限 148→112、宽度占比
   * 0.24→0.18 —— 单元更精巧，单元间/四周留白增大，空白点击返回
   * 量子面板的命中区域同步扩大；间距公式基于 unitSize 自适应不变 */
  unitSize = Math.max(112, Math.min(width * 0.18, 148));
  rowDelta = Math.min(width * 0.31, (width - unitSize * 1.12) / 2);
  rowDelta = Math.max(rowDelta, unitSize * 0.62);

  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  ctx?.setTransform(dpr, 0, 0, dpr, 0, 0);

  const cx = width / 2;
  const cy = height / 2;
  centers[0][0] = cx - rowDelta; centers[0][1] = cy;
  centers[1][0] = cx;            centers[1][1] = cy;
  centers[2][0] = cx + rowDelta; centers[2][1] = cy;
  styleVarsDirty = true;
}

/** 丝链采样点（悬链 + 噪声 + 光标磁弯） */
function filPoint(k: number, t: number, out: Float64Array): void {
  const [a, b, sag, ] = FILAMENTS[k];
  const ax = centers[a][0]; const ay = centers[a][1];
  const bx = centers[b][0]; const by = centers[b][1];
  let x = ax + (bx - ax) * t;
  let y = ay + (by - ay) * t + sag * Math.sin(Math.PI * t) * (minDim / 560);
  y += filDrifts[k](clockSec + t * 4) * 2.4;
  // 光标磁弯：高斯权重，丝线向光标轻微弯折（差异化力场传播）
  if (cursorOn) {
    const dx = cursorX - x;
    const dy = cursorY - y;
    const s2 = 2 * (0.3 * minDim) * (0.3 * minDim);
    const g = Math.exp(-(dx * dx + dy * dy) / s2);
    x += dx * 0.16 * g;
    y += dy * 0.16 * g;
  }
  out[0] = x;
  out[1] = y;
}

/* ===== 主循环（先积分后消费 → DOM/Canvas 写入） ===== */
const unitEls: Array<HTMLElement | null> = [];
const pt = new Float64Array(2);

/* SVG 丝线元素缓存（dashoffset rAF 驱动；onMounted 收集一次） */
let tetherEl: SVGPathElement | null = null;
const satLinkEls: SVGPathElement[] = [];

function frame(frameStep: number, wallClock: number): void {
  if (!ctx || !sizeOk) return;

  /* ---- 完成事件帧（双帧约定）：领取一次性完成事件 → 停止 Canvas
     （保留最后一帧作为静态视觉参与 CSS 离场）→ 驱动视图切换 ---- */
  if (completePending) {
    completePending = false;
    ritual.consumeComplete();
    stopGate();
    emit('enter', SECTIONS[burstFrom]);
    return;
  }

  /* ---- 时间分离：相位与进度用未钳制墙钟增量（时间流速恒 1×，
     帧门控只决定采样频率）；钳制后的帧步进仅用于物理积分 ---- */
  const wStep = lastWallClock < 0 ? 0 : Math.max(wallClock - lastWallClock, 0);
  lastWallClock = wallClock;
  clockSec += wStep;
  const dt = Math.min(frameStep, RITUAL_DURATION.maxPhysicsStep);
  introTime += wStep;
  frameCount++;
  // 传播仪式推进（墙钟驱动，帧率无关；到达终点帧 = 落定首帧）
  const r = ritual.advance(clockSec);

  /* ---- 帧率自适应（EMA → 尘埃密度，滞后调节） ----
     仅 active 档评估：低档位下调度间隔不反映真实渲染成本，
     据此降密度会在恢复交互后无谓回爬。 */
  if (idleLevel.value === 'active') {
    avgFrameMs += (wStep * 1000 - avgFrameMs) * 0.04;
    if (frameCount % 90 === 0) {
      if (avgFrameMs > 21 && moteActive > 24) moteActive -= 4;
      else if (avgFrameMs < 15 && moteActive < MOTE_MAX) moteActive += 4;
    }
  }

  /* ---- 弹簧积分（先积分） ---- */
  springStep(parallaxX, dt);
  springStep(parallaxY, dt);

  /* ---- 布局变量写入（仅脏时） ---- */
  const panel = panelRef.value;
  if (panel && styleVarsDirty) {
    styleVarsDirty = false;
    panel.style.setProperty('--u-size', `${unitSize.toFixed(1)}px`);
    panel.style.setProperty('--row-delta', `${rowDelta.toFixed(1)}px`);
  }

  /* ---- 视差仲裁（hover P1 → 背景视差衰减 50%） ---- */
  const suppress = hoverN > 0 ? 0.5 : 1;
  const introPar = introTime < 1.6 ? phase(introTime, 0.15, 1.0) : 1;
  const px = parallaxX.v * suppress * introPar;
  const py = parallaxY.v * suppress * introPar;

  /* ---- 单元消费：磁倾 + 缩放 + 能量 + 入场 ---- */
  const sigma = 0.3 * minDim;
  const s2 = 2 * sigma * sigma;
  for (let i = 0; i < N_UNITS; i++) {
    const el = unitEls[i];
    if (!el) continue;
    // 光标高斯邻近（自然衰减梯度，无硬边界）
    const dx = cursorX - centers[i][0];
    const dy = cursorY - centers[i][1];
    const prox = cursorOn ? Math.exp(-(dx * dx + dy * dy) / s2) : 0;
    // 磁倾目标：朝向光标的微倾（角度 °，prox 加权）
    const lean = cursorOn ? Math.max(-1, Math.min(1, dx / (unitSize * 1.4))) : 0;
    tiltSprings[i].target = lean * 3.2 * prox;
    springStep(scaleSprings[i], dt);
    springStep(tiltSprings[i], dt);
    springStep(boostSprings[i], dt);
    flash[i] *= Math.exp(-dt * 3.2);

    const ip = introTime < 1.6 ? phase(introTime, 0.08 + i * 0.13, 0.78) : 1;
    const scale = (0.62 + 0.38 * ip) * scaleSprings[i].v;
    const tx = px * (5 + i * 1.6) + (cursorOn ? dx * 0.035 * prox : 0);
    const ty = py * (5 + i * 1.6) + (cursorOn ? dy * 0.035 * prox : 0);
    el.style.transform =
      `translate(-50%,-50%) translate3d(${tx.toFixed(2)}px,${ty.toFixed(2)}px,0)` +
      ` rotate(${tiltSprings[i].v.toFixed(3)}deg) scale(${scale.toFixed(4)})`;
    el.style.opacity = ip.toFixed(3);
    el.style.setProperty('--boost', Math.min(1.6, boostSprings[i].v + flash[i] * 0.7).toFixed(3));
    el.style.setProperty('--prox', prox.toFixed(3));
    // 语义核心升腾量（boost 弹簧驱动，带惯性回落 — 磁悬浮感）
    el.style.setProperty('--lift', (boostSprings[i].v * 4.5 + flash[i] * 2).toFixed(3));
  }

  /* ---- Canvas 渲染 ---- */
  ctx.clearRect(0, 0, width, height);
  ctx.globalCompositeOperation = 'lighter';

  // 尘埃场（多频漂移 + 光标视差 + 呼吸明暗）
  const dustIntro = introTime < 1.6 ? phase(introTime, 0.1, 1.1) : 1;
  for (let i = 0; i < moteActive; i++) {
    const m = motes[i];
    const mx = m.x01 * width + moteDrifts[m.dxi](clockSec) * 16 + px * 6 * m.depth;
    const my = m.y01 * height + moteDrifts[m.dyi](clockSec) * 12 + py * 6 * m.depth;
    const breath = 0.72 + 0.28 * Math.sin(clockSec * 0.6 + i * 1.7);
    const a = m.alpha * breath * dustIntro;
    if (a <= 0.01) continue;
    ctx.globalAlpha = a;
    const s = m.size * 3.2;
    ctx.drawImage(sprite!, mx - s / 2, my - s / 2, s, s);
  }

  // 能量丝链（中部向两端的绘制进度 + 闪光增强）
  for (let k = 0; k < FILAMENTS.length; k++) {
    const [, , , segs] = FILAMENTS[k];
    const drawP = introTime < 1.6 ? phase(introTime, 0.32 + k * 0.1, 0.62) : 1;
    if (drawP <= 0.02) continue;
    const half = Math.floor((segs * drawP) / 2);
    const fl = (flash[FILAMENTS[k][0]] + flash[FILAMENTS[k][1]]) * 0.5;
    // 采样两段（从两端向中间生长）
    ctx.strokeStyle = 'rgba(0,255,190,1)';
    ctx.lineWidth = 1;
    ctx.globalAlpha = 0.1 + fl * 0.3;
    for (const [from, count] of [[0, half], [segs - half, half]] as const) {
      if (count <= 0) continue;
      ctx.beginPath();
      for (let s = 0; s <= count; s++) {
        filPoint(k, (from + s) / segs, pt);
        if (s === 0) ctx.moveTo(pt[0], pt[1]);
        else ctx.lineTo(pt[0], pt[1]);
      }
      ctx.stroke();
    }
    // 端点锚（单元侧微光）
    filPoint(k, 0, pt);
    ctx.globalAlpha = (0.18 + fl * 0.5) * drawP;
    ctx.drawImage(sprite!, pt[0] - 4, pt[1] - 4, 8, 8);
    filPoint(k, 1, pt);
    ctx.drawImage(sprite!, pt[0] - 4, pt[1] - 4, 8, 8);
  }

  // 隧穿光包（稀有自发 + 点击爆发）
  if (ritual.phase === 'idle' && clockSec >= nextPacketAt) {
    nextPacketAt = clockSec + 1.7 + Math.random() * 2.6;
    const p = PACKETS.find((q) => !q.active);
    if (p) {
      p.active = true;
      p.t = 0;
      p.dur = 1.3 + Math.random() * 0.6;
      p.fil = Math.floor(Math.random() * FILAMENTS.length);
      p.rev = Math.random() > 0.5;
      p.strength = 0.4;
      p.burst = false;
    }
  }
  for (const p of PACKETS) {
    if (!p.active) continue;
    if (p.burst) {
      // 爆发包：进度由仪式墙钟直接驱动，任何 dt 钳制都不参与
      p.t = r.propagation;
      if (p.t >= 1) continue; // 已到达终点：视觉由落定光晕接管
    } else {
      // 自发包：帧步进用未钳制墙钟增量（低档位下时间流速不变）
      p.t += wStep / p.dur;
      if (p.t >= 1) { p.active = false; continue; }
    }
    const tt = p.rev ? 1 - p.t : p.t;
    filPoint(p.fil, tt, pt);
    // 头部光点 + 短尾迹
    const sz = (7 + 9 * p.strength) * Math.sin(Math.PI * Math.min(p.t * 1.15, 1));
    ctx.globalAlpha = 0.75 * p.strength + 0.2;
    ctx.drawImage(sprite!, pt[0] - sz / 2, pt[1] - sz / 2, sz, sz);
    for (let w = 1; w <= 3; w++) {
      filPoint(p.fil, Math.max(0, Math.min(1, tt - w * 0.022 * (p.rev ? -1 : 1))), pt);
      const ts = sz * (1 - w * 0.24);
      ctx.globalAlpha = (0.5 - w * 0.13) * p.strength;
      ctx.drawImage(sprite!, pt[0] - ts / 2, pt[1] - ts / 2, ts, ts);
    }
  }

  // 落定呈现：终点光晕缓出扩散（与传播到达同帧起势，落定完整播完）
  if (r.landing > 0) {
    const eased = 1 - Math.pow(1 - r.landing, 3);
    const rad = 16 + eased * 26;
    ctx.globalAlpha = 0.5 * (1 - eased);
    for (let j = 0; j < burstTargets.length; j++) {
      const cx = centers[burstTargets[j]][0];
      const cy = centers[burstTargets[j]][1];
      ctx.drawImage(sprite!, cx - rad, cy - rad, rad * 2, rad * 2);
    }
  }

  ctx.globalAlpha = 1;
  ctx.globalCompositeOperation = 'source-over';

  /* ---- 到达终点帧：终点单元锚闪光起势（衰减渐熄构成落定收束） ---- */
  if (ritual.phase === 'landing' && r.landing === 0) {
    for (let j = 0; j < burstTargets.length; j++) {
      flash[burstTargets[j]] = 1;
    }
  }

  /* ---- 落定逻辑完成帧：本帧已渲染完整落定，下一帧领取完成事件 ---- */
  if (r.complete) {
    completePending = true;
  }

  /* ---- SVG 丝线 dashoffset rAF 驱动（原 CSS infinite 动画迁移） ----
     状态语义流动随全局空闲档位自动降频；
     相位由墙钟累积时间计算，跳帧不产生相位跳变。 */
  const tetherOwner = unitEls[0];
  if (tetherEl && tetherOwner) {
    let off = 0;
    if (tetherOwner.classList.contains('mh-bind-on')) {
      off = -14 * ((clockSec / 2.6) % 1);
    } else if (tetherOwner.classList.contains('mh-bind-scan')) {
      off = -14 * ((clockSec / 1.1) % 1);
    }
    tetherEl.style.strokeDashoffset = off.toFixed(2);
  }
  if (satLinkEls.length) {
    const satOff = -32 * ((clockSec / 5.5) % 1);
    for (let i = 0; i < satLinkEls.length; i++) {
      satLinkEls[i].style.strokeDashoffset = satOff.toFixed(2);
    }
  }
}

/* G-8：rAF 调度/空闲门控/失焦暂停全部由 useFrameGate 承担，
   档位与恢复时机与全局各引擎一致。 */
const { start: startGate, stop: stopGate } = useFrameGate(idleLevel, frame);

/* ===== 生命周期 ===== */
let resizeObserver: ResizeObserver | null = null;

onMounted(() => {
  const canvas = canvasRef.value;
  if (!canvas) return;
  ctx = canvas.getContext('2d', { alpha: true });
  if (!ctx) return;
  // 光点贴图（径向渐变，一次分配）
  sprite = document.createElement('canvas');
  sprite.width = 32;
  sprite.height = 32;
  const sctx = sprite.getContext('2d')!;
  const grad = sctx.createRadialGradient(16, 16, 0, 16, 16, 16);
  grad.addColorStop(0, 'rgba(210,255,244,1)');
  grad.addColorStop(0.35, 'rgba(0,255,190,0.55)');
  grad.addColorStop(1, 'rgba(0,255,190,0)');
  sctx.fillStyle = grad;
  sctx.fillRect(0, 0, 32, 32);

  unitEls.length = 0;
  unitEls.push(u1Ref.value, u2Ref.value, u3Ref.value);

  /* SVG 丝线缓存（dashoffset rAF 驱动元素，一次收集） */
  tetherEl = u1Ref.value?.querySelector('.mh-tether') ?? null;
  satLinkEls.length = 0;
  u2Ref.value?.querySelectorAll('.mh-satLink').forEach((el) => {
    satLinkEls.push(el as SVGPathElement);
  });

  layout();
  resizeObserver = new ResizeObserver(layout);
  resizeObserver.observe(panelRef.value!);
  /* 入场编排按满帧渲染：挂载即交互（resetIdle），
     错峰入场全程 60fps 不降档 */
  resetIdle();
  startGate();
});

onBeforeUnmount(() => {
  stopGate();
  // 中断清理：传播仪式复位（点击空白返回 / 卸载路径均走此处）
  ritual.reset();
  completePending = false;
  resizeObserver?.disconnect();
  resizeObserver = null;
  unitEls.length = 0;
  tetherEl = null;
  satLinkEls.length = 0;
  ctx = null;
  sprite = null;
});
</script>
