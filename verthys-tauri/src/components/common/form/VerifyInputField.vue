<!--
  VerifyInputField.vue — 验证类密钥输入场

  职责：
    1. 输入框 + 显隐端子 + 禁用态应答；
    2. 验证进行中沿输入框周缘连续巡行的星流光轨（每圈 1.4s）；
    3. 验证失败的底缘红线与字段容器抖动。

  星轨由统一帧门控调度，不使用独立 rAF；关键验证动画申请帧率豁免，
  结束、失败或卸载立即注销；系统减少动态或帧预算降级时只绘制静态一帧。
  输入框使用 kv-input 全局单源；字段容器只补显隐端子内距与周缘画布层。

  Props:
    - modelValue  输入值（v-model）
    - verifying   验证进行中：锁定输入并启动星轨
    - error       验证失败：底缘红线 + 抖动，星轨停止
    - disabled    外部禁用（与 verifying 取或）
    - placeholder 占位文本
    - label       无障碍名称，同时作为显隐端子的语义名词
    - active      宿主弹窗可见；关闭时收回明文显示
  Emits:
    - update:modelValue / submit
-->
<template>
  <div class="vif-field" :class="{ 'vif-field--error': error }">
    <input
      class="kv-input vif-input"
      :class="{ 'vif-input--error': error }"
      :value="modelValue"
      :type="visible ? 'text' : 'password'"
      :placeholder="placeholder"
      :aria-label="label"
      :disabled="disabled || verifying"
      autocomplete="off"
      spellcheck="false"
      @input="onInput"
      @keydown.enter="emit('submit')"
    />
    <!-- 验证中：一道星流光沿输入框周缘连续巡行（Canvas 每圈 1.4s，无进度条、无遮罩层） -->
    <canvas
      v-if="verifying && !error"
      ref="orbitCanvas"
      class="vif-orbit-canvas"
      aria-hidden="true"
    ></canvas>
    <button
      type="button"
      class="vif-eye"
      :disabled="disabled || verifying"
      :aria-label="visible ? `隐藏${label}` : `显示${label}`"
      :aria-pressed="visible"
      @click="visible = !visible"
    >
      <svg v-if="!visible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
      <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
    </button>
  </div>
</template>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, watch } from "vue";
import { masterFrameLoop, type ExemptionToken } from "../../../core/master-frame-loop";
import { useFrameGate } from "../../../composables/useFrameGate";
import { useGlobalIdleScheduler } from "../../../composables/useGlobalIdleScheduler";

const props = withDefaults(
  defineProps<{
    /** 输入值（v-model） */
    modelValue: string;
    /** 验证进行中：锁定输入并启动周缘星轨 */
    verifying?: boolean;
    /** 验证失败：底缘红线 + 字段容器抖动，星轨停止 */
    error?: boolean;
    /** 外部禁用（与 verifying 取或） */
    disabled?: boolean;
    /** 占位文本 */
    placeholder?: string;
    /** 无障碍名称，同时作为显隐端子的语义名词 */
    label: string;
    /** 宿主弹窗可见；关闭时收回明文显示 */
    active?: boolean;
  }>(),
  {
    verifying: false,
    error: false,
    disabled: false,
    placeholder: "",
    active: true,
  },
);

const emit = defineEmits<{
  (e: "update:modelValue", value: string): void;
  (e: "submit"): void;
}>();

const onInput = (event: Event): void => {
  emit("update:modelValue", (event.target as HTMLInputElement).value);
};

/** 默认密文显示；开始验证或宿主关闭即收回明文 */
const visible = ref(false);
watch(
  () => props.verifying,
  (verifying) => {
    if (verifying) visible.value = false;
  },
);
watch(
  () => props.active,
  (active) => {
    if (!active) visible.value = false;
  },
);

/* ===== 星轨 Canvas =====
 * 用 2D Canvas 逐帧绘制一圈彗星轨迹：小面积位图直接落笔，
 * 不依赖遮罩合成、锥形渐变旋转或合成层重采样，避免闪烁与掉帧。
 * 治理：每圈 1.4s；验证未结束时无缝续圈（单次动画停在半途会让弹窗
 *       读作卡死）；像素比封顶 2；尾迹点/颜色/透明度预分配，逐帧除
 *       星头渐变外零对象分配；由统一帧门控调度，不使用独立 rAF；
 *       每圈续期帧率豁免（单次豁免有 1.5s 上限），结束、失败或卸载
 *       立即注销并释放。
 */
const ORBIT_DURATION_MS = 1400;
const ORBIT_DURATION_SECONDS = ORBIT_DURATION_MS / 1000;
const ORBIT_FADE_RATIO = 0.13;
const ORBIT_MARGIN = 4;
const ORBIT_TAIL_PX = 100;
const ORBIT_TAIL_STEPS = 52;

interface OrbitPoint {
  x: number;
  y: number;
}
interface OrbitGeometry {
  x: number;
  y: number;
  w: number;
  h: number;
  r: number;
  perim: number;
  phase: number;
}

const orbitCanvas = ref<HTMLCanvasElement | null>(null);
let orbitCtx: CanvasRenderingContext2D | null = null;
let orbitW = 0;
let orbitH = 0;
let orbitGeom: OrbitGeometry | null = null;
let orbitStartClock: number | null = null;
let orbitComplete = false;
/** 首圈淡入完成后置位：续圈直接以满不透明度绘制，避免每圈重新淡入闪烁 */
let orbitFadedIn = false;
let orbitExemption: ExemptionToken | null = null;
const { level } = useGlobalIdleScheduler();
const reducedMotionQuery =
  typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia("(prefers-reduced-motion: reduce)")
    : null;

/* 尾迹点、颜色与基础透明度只在构建期求值一次，逐帧复用 */
const orbitTailPoints: OrbitPoint[] = Array.from(
  { length: ORBIT_TAIL_STEPS + 1 },
  () => ({ x: 0, y: 0 }),
);
const orbitHeadPoint: OrbitPoint = { x: 0, y: 0 };
const orbitTailColors: string[] = [];
const orbitTailAlpha: number[] = [];
for (let i = 0; i < ORBIT_TAIL_STEPS; i += 1) {
  const k = i / ORBIT_TAIL_STEPS;
  let cr: number;
  let cg: number;
  let cb: number;
  if (k < 0.55) {
    const u = k / 0.55;
    cr = 255 + (150 - 255) * u;
    cg = 246 + (225 - 246) * u;
    cb = 224 + (255 - 224) * u;
  } else {
    const u = (k - 0.55) / 0.45;
    cr = 150 + (168 - 150) * u;
    cg = 225 + (150 - 225) * u;
    cb = 255;
  }
  orbitTailColors.push(`rgb(${Math.round(cr)},${Math.round(cg)},${Math.round(cb)})`);
  orbitTailAlpha.push(Math.pow(1 - k, 1.9) * 0.62);
}

const buildGeometry = (canvasW: number, canvasH: number): OrbitGeometry => {
  const x = ORBIT_MARGIN;
  const y = ORBIT_MARGIN;
  const w = Math.max(canvasW - ORBIT_MARGIN * 2, 1);
  const h = Math.max(canvasH - ORBIT_MARGIN * 2, 1);
  const r = Math.min(8, w / 2, h / 2);
  const perim = 2 * (w - 2 * r) + 2 * (h - 2 * r) + 2 * Math.PI * r;
  return { x, y, w, h, r, perim, phase: (w - 2 * r) / 2 };
};

/** 圆角矩形周缘上按弧长取点（写入预分配点，逐帧零对象分配） */
const writePoint = (g: OrbitGeometry, dist: number, target: OrbitPoint) => {
  const topLen = g.w - 2 * g.r;
  const sideLen = g.h - 2 * g.r;
  const arcLen = (Math.PI * g.r) / 2;
  let d = ((dist % g.perim) + g.perim) % g.perim;

  if (d <= topLen) {
    target.x = g.x + g.r + d;
    target.y = g.y;
    return;
  }
  d -= topLen;
  if (d <= arcLen) {
    const a = -Math.PI / 2 + d / g.r;
    target.x = g.x + g.w - g.r + Math.cos(a) * g.r;
    target.y = g.y + g.r + Math.sin(a) * g.r;
    return;
  }
  d -= arcLen;
  if (d <= sideLen) {
    target.x = g.x + g.w;
    target.y = g.y + g.r + d;
    return;
  }
  d -= sideLen;
  if (d <= arcLen) {
    const a = d / g.r;
    target.x = g.x + g.w - g.r + Math.cos(a) * g.r;
    target.y = g.y + g.h - g.r + Math.sin(a) * g.r;
    return;
  }
  d -= arcLen;
  if (d <= topLen) {
    target.x = g.x + g.w - g.r - d;
    target.y = g.y + g.h;
    return;
  }
  d -= topLen;
  if (d <= arcLen) {
    const a = Math.PI / 2 + d / g.r;
    target.x = g.x + g.r + Math.cos(a) * g.r;
    target.y = g.y + g.h - g.r + Math.sin(a) * g.r;
    return;
  }
  d -= arcLen;
  if (d <= sideLen) {
    target.x = g.x;
    target.y = g.y + g.h - g.r - d;
    return;
  }
  d -= sideLen;
  const a = Math.PI + d / g.r;
  target.x = g.x + g.r + Math.cos(a) * g.r;
  target.y = g.y + g.r + Math.sin(a) * g.r;
};

const drawGuide = (ctx: CanvasRenderingContext2D, g: OrbitGeometry) => {
  ctx.beginPath();
  ctx.moveTo(g.x + g.r, g.y);
  ctx.lineTo(g.x + g.w - g.r, g.y);
  ctx.arcTo(g.x + g.w, g.y, g.x + g.w, g.y + g.r, g.r);
  ctx.lineTo(g.x + g.w, g.y + g.h - g.r);
  ctx.arcTo(g.x + g.w, g.y + g.h, g.x + g.w - g.r, g.y + g.h, g.r);
  ctx.lineTo(g.x + g.r, g.y + g.h);
  ctx.arcTo(g.x, g.y + g.h, g.x, g.y + g.h - g.r, g.r);
  ctx.lineTo(g.x, g.y + g.r);
  ctx.arcTo(g.x, g.y, g.x + g.r, g.y, g.r);
  ctx.closePath();
  ctx.strokeStyle = "#cde0f4";
  ctx.lineWidth = 1;
  ctx.stroke();
};

const drawOrbitFrame = (progress: number, forcedFade?: number) => {
  const ctx = orbitCtx;
  const g = orbitGeom;
  if (!ctx || !g) return;

  ctx.clearRect(0, 0, orbitW, orbitH);
  const fade = forcedFade ?? Math.min(progress / ORBIT_FADE_RATIO, 1);
  ctx.globalAlpha = 0.055 * fade;
  drawGuide(ctx, g);
  if (fade <= 0) {
    ctx.globalAlpha = 1;
    return;
  }

  const headDist = g.phase + progress * g.perim;
  const tailLen = Math.min(ORBIT_TAIL_PX, g.perim * 0.16);
  for (let i = 0; i <= ORBIT_TAIL_STEPS; i += 1) {
    writePoint(g, headDist - (i / ORBIT_TAIL_STEPS) * tailLen, orbitTailPoints[i]);
  }

  /* 尾迹由后向前逐段收细：颜色与基础透明度预计算，逐帧只写 globalAlpha。 */
  ctx.lineCap = "butt";
  for (let i = ORBIT_TAIL_STEPS - 1; i >= 0; i -= 1) {
    const from = orbitTailPoints[i + 1];
    const to = orbitTailPoints[i];
    ctx.beginPath();
    ctx.moveTo(from.x, from.y);
    ctx.lineTo(to.x, to.y);
    ctx.strokeStyle = orbitTailColors[i];
    ctx.globalAlpha = orbitTailAlpha[i] * fade;
    ctx.lineWidth = 1.05 - 0.42 * (i / ORBIT_TAIL_STEPS);
    ctx.stroke();
  }

  writePoint(g, headDist, orbitHeadPoint);
  ctx.globalAlpha = fade;
  const bloom = ctx.createRadialGradient(
    orbitHeadPoint.x,
    orbitHeadPoint.y,
    0,
    orbitHeadPoint.x,
    orbitHeadPoint.y,
    3.6,
  );
  bloom.addColorStop(0, "rgba(255,248,230,0.9)");
  bloom.addColorStop(0.45, "rgba(220,242,255,0.32)");
  bloom.addColorStop(1, "rgba(160,220,255,0)");
  ctx.fillStyle = bloom;
  ctx.beginPath();
  ctx.arc(orbitHeadPoint.x, orbitHeadPoint.y, 3.6, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = "rgba(255,252,245,0.95)";
  ctx.beginPath();
  ctx.arc(orbitHeadPoint.x, orbitHeadPoint.y, 0.9, 0, Math.PI * 2);
  ctx.fill();
  ctx.globalAlpha = 1;
};

const releaseOrbitExemption = () => {
  if (orbitExemption) {
    masterFrameLoop.releaseExemption(orbitExemption);
    orbitExemption = null;
  }
};

/** 系统减少动态或帧预算降级（≥中度）时，星轨只保留静态一帧 */
const reducedMotionActive = (): boolean =>
  reducedMotionQuery?.matches === true ||
  (typeof document !== "undefined" && document.body.classList.contains("reduced-motion"));

/* 星轨由统一帧门控调度：不自开 rAF，注册为 throttled 任务，
 * 进度使用主循环墙钟（秒），结束、失败或卸载时注销。 */
const { start: startGate, stop: stopGate } = useFrameGate(level, (_frameStep, wallClock) => {
  if (reducedMotionActive()) {
    if (!orbitComplete) {
      drawOrbitFrame(0.55);
      orbitComplete = true;
    }
    releaseOrbitExemption();
    return;
  }

  if (orbitStartClock === null) orbitStartClock = wallClock;
  let elapsed = wallClock - orbitStartClock;
  if (elapsed >= ORBIT_DURATION_SECONDS) {
    /* 验证未结束时无缝续圈：动画停在半途会让弹窗读作卡死。
     * 单次豁免有 1.5s 上限，每圈续期一次，长验证仍保持满帧巡行。 */
    orbitStartClock = wallClock;
    elapsed = 0;
    orbitFadedIn = true;
    releaseOrbitExemption();
    const renewed = masterFrameLoop.requestExemption("verify-input-orbit");
    orbitExemption = renewed.token;
  }
  /* 续圈以满不透明度绘制：progress 0 与上一圈终点同点，视觉上无缝衔接 */
  drawOrbitFrame(elapsed / ORBIT_DURATION_SECONDS, orbitFadedIn ? 1 : undefined);
});

const stopOrbit = () => {
  stopGate();
  releaseOrbitExemption();
  orbitStartClock = null;
  orbitComplete = false;
  orbitFadedIn = false;
};

const startOrbit = async () => {
  stopOrbit();
  await nextTick();
  if (!props.verifying || props.error) return;

  const canvas = orbitCanvas.value;
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  if (rect.width < ORBIT_MARGIN * 2 + 4 || rect.height < ORBIT_MARGIN * 2 + 4) return;

  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.round(rect.width * dpr);
  canvas.height = Math.round(rect.height * dpr);
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  orbitCtx = ctx;
  orbitW = rect.width;
  orbitH = rect.height;
  orbitGeom = buildGeometry(rect.width, rect.height);

  if (reducedMotionActive()) {
    drawOrbitFrame(0.55);
    return;
  }

  /* 关键验证动画申请官方帧率豁免：点击后 settling 档位不会让星轨忽快忽慢 */
  const exemption = masterFrameLoop.requestExemption("verify-input-orbit");
  orbitExemption = exemption.token;
  if (exemption.status === "rejected") {
    drawOrbitFrame(0.55);
    return;
  }

  orbitStartClock = null;
  orbitComplete = false;
  orbitFadedIn = false;
  startGate();
};

watch(
  () => [props.verifying, props.error] as const,
  ([verifying, error]) => {
    stopOrbit();
    if (verifying && !error) void startOrbit();
  },
  { immediate: true },
);

onBeforeUnmount(stopOrbit);
</script>

<style scoped>
/* 验证中锁定输入：只以降透明与禁止光标应答，不叠加额外加载形态 */
.vif-input:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

/* ===== 字段容器与星轨 =====
 * 一道极细的彗星弧沿输入框周缘巡行：暖白星头 + 冷青尾迹。
 * 由 Canvas 逐帧绘制，不做遮罩合成与锥形渐变旋转。 */
.vif-field {
  position: relative;
  border-radius: 8px;
  --kv-input-pad-right: 38px;
}
.vif-orbit-canvas {
  position: absolute;
  left: -4px;
  top: -4px;
  width: calc(100% + 8px);
  height: calc(100% + 8px);
  display: block;
  pointer-events: none;
}
/* 显隐端子内嵌：图标即控件，零底板、零阴影，仅以色彩应答 */
.vif-eye {
  position: absolute;
  top: 50%;
  right: 6px;
  transform: translateY(-50%);
  z-index: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease);
}
.vif-eye:not(:disabled):hover {
  color: var(--accent);
}
.vif-eye:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: 1px;
}
.vif-eye:disabled {
  cursor: not-allowed;
  opacity: 0.4;
}
.vif-eye svg {
  width: 14px;
  height: 14px;
}

/* 错误感知：密码框底缘红线；抖动移到字段容器，星轨随框体一同反馈。
 * 错误密码绝不放行，必须给用户明确的视觉反馈；
 * 底板已去除包围描边，错误语义由底缘红线与瞬时抖动承担，不堆叠辉光。 */
.vif-input--error {
  box-shadow:
    inset 0 1px 0 rgba(0, 0, 0, 0.45),
    inset 0 -1px 0 rgba(255, 80, 100, 0.90) !important;
}
.vif-field--error {
  animation: vif-error-shake 0.4s var(--ease);
}
@keyframes vif-error-shake {
  0%, 100% { transform: translateX(0); }
  20% { transform: translateX(-6px); }
  40% { transform: translateX(6px); }
  60% { transform: translateX(-4px); }
  80% { transform: translateX(4px); }
}
</style>
