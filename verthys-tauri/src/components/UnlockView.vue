<!--
  UnlockView.vue — 动态引导页（星系协同版 v3）
  ★ 与偏轴旋涡星系逆渡（INTRO_T=3s）同步编排：
    0-3s    星系倒卷成型（全屏逆渡）‖ VERTHYS 不规则字号雕刻排印
            逐字轨道入射 + 谱线组逐线充能
    3s+     静旋驻留 ‖ 谱线呼吸 ‖ 进入提示浮现（线体极简 · 无呼吸静态）
    点击    逐字引力弹射（外缘先走）+ 谱线组塌缩（外缘先收）
            + 丝线 dash 收回 → 星系正渡（warping）
  排印设计（v3 — 顶级排印美学，零渐变）：
    不规则字号（56-108px hash 差化）/ baseline 非均匀基线错落 /
    实色·镂空描边·accent 锚点三态混合（瑞士排印空心字手法）/
    双层雕刻（暗色克隆偏移 — 深度感，非阴影辉光）
  反大众化约束：无同心圆环 / 无渐变 / 无等距逐字浮现 / 无规整加载条；
  入射、弹射、字号、基线、三态、时序全部逐元素差异化（确定性 hash）
-->
<template>
  <div
    class="intro-view"
    @click="onEnter"
    @mousemove="onMouseMove"
  >
    <!-- 鼠标跟随光晕（低强度，交互反馈）
         ★ 性能根治：transform 直写 + rAF 阻尼跟随（合成器层，
         零布局/零重绘；渐变自带柔边，去实时 blur 滤镜） -->
    <div ref="auraEl" class="cursor-aura" aria-hidden="true"></div>

    <!-- 轨道丝线（倾斜椭圆 — 呼应银河盘 41° 斜视姿态，非同心圆环；
         dash 沿椭圆持续巡行 = 轨道碎屑流，揭示/收回均经 dash 生长塌缩） -->
    <svg
      class="orbit-filaments"
      :class="{ leaving: leaving }"
      viewBox="0 0 1200 720"
      fill="none"
      aria-hidden="true"
    >
      <ellipse class="fil fil-a" pathLength="1" cx="596" cy="352" rx="436" ry="112" />
      <ellipse class="fil fil-b" pathLength="1" cx="642" cy="326" rx="540" ry="158" />
      <ellipse class="fil fil-c" pathLength="1" cx="576" cy="374" rx="318" ry="82" />
    </svg>

    <!-- 品牌核心视觉 -->
    <div class="brand-core" :class="{ leaving: leaving }">
      <!-- 主标题：VERTHYS 不规则字号雕刻排印
           （实色 / 镂空 / accent 三态 · 非均匀基线 · 双层雕刻深度 —
             全局共享样式体系 animations.css .brand-title/.brand-char） -->
      <h1 class="brand-title">
        <span
          v-for="(cv, i) in charVariants"
          :key="i"
          class="brand-char"
          :class="cv.mode"
          :data-char="cv.ch"
          :style="{
            '--fs': cv.fs + 'px',
            '--dx': cv.dx + 'px',
            '--dy': cv.dy + 'px',
            '--by': cv.by + 'px',
            '--tr': cv.tr + 'deg',
            '--rot': cv.rot + 'deg',
            '--delay': cv.delay + 'ms',
            '--dur': cv.dur + 's',
            '--ed': cv.ed + 'ms',
          }"
        >{{ cv.ch }}</span>
      </h1>

      <!-- 谱线组（光谱发射线隐喻 — 逐线差化充能 → 呼吸 + 微跳驻留 → 外缘先收塌缩） -->
      <div class="spectra" :class="{ charged: charged }">
        <i
          v-for="(tk, i) in spectraTicks"
          :key="i"
          class="spectra-tick"
          :style="{
            '--th': tk.h + 'px',
            '--gap': tk.gap + 'px',
            '--tc': tk.tc,
            '--op': tk.op,
            '--cd': tk.td + 'ms',
            '--sd': tk.sd + 's',
            '--sm': tk.sm + 'ms',
            '--jd': tk.jd + 's',
            '--jp': tk.jp + 'ms',
            '--cl': tk.cl + 'ms',
          }"
        ></i>
      </div>

      <!-- 副标题 -->
      <p class="brand-sub" :class="{ shown: subShown }">
        <span class="sub-dot"></span>
        SECURE · VERTHYS · CORE
        <span class="sub-dot"></span>
      </p>
    </div>

    <!-- 底部进入提示（线体极简 — 非对称发丝线 + 端点竖标；无呼吸，静态高级） -->
    <transition name="hint-fade">
      <div v-if="hintVisible" class="enter-hint" :class="{ leaving: leaving }">
        <span class="hint-line hint-line-l"><i class="hint-cap"></i></span>
        <span class="hint-text">点击进入</span>
        <span class="hint-line hint-line-r"><i class="hint-cap"></i></span>
      </div>
    </transition>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from "vue";
import { useBrandTitle } from "../composables/useBrandTitle";
import { useSpectraTicks } from "../composables/useSpectraTicks";

const emit = defineEmits<{ (e: "enter"): void }>();

const subShown = ref(false);
const hintVisible = ref(false);
const charged = ref(false);
const leaving = ref(false);

/* ============================================================================
 * ★ 鼠标跟随光晕 — 性能根治版：
 *   1. 去响应式：不再经 Vue computed 每帧 patch style（省一轮调度）
 *   2. transform 直写：translate3d 合成器层移动，零 layout/零 paint
 *   3. rAF 阻尼跟随：指数趋近平滑（物理阻尼感），事件仅记录目标值
 *   4. 去实时 blur：径向渐变多段柔边等效 28px 模糊（省每帧 GPU 重采样）
 *   5. 整数像素量化：消除亚像素抖动
 * ========================================================================== */
const auraEl = ref<HTMLElement | null>(null);
let auraTx = 0;   // 当前位置（阻尼插值中）
let auraTy = 0;
let auraGx = 0;   // 目标位置（指针最近事件）
let auraGy = 0;
let auraRaf = 0;

const auraFrame = () => {
  /* 指数阻尼趋近（≈160ms 收敛）— 平滑跟随，静止时自动停帧 */
  auraTx += (auraGx - auraTx) * 0.12;
  auraTy += (auraGy - auraTy) * 0.12;
  const dx = auraGx - auraTx;
  const dy = auraGy - auraTy;
  const el = auraEl.value;
  if (el) {
    /* 整数量化 + translate3d（GPU 合成，与 -50% 居中合并） */
    el.style.transform =
      `translate3d(${Math.round(auraTx)}px, ${Math.round(auraTy)}px, 0) translate(-50%, -50%)`;
  }
  /* 已收敛且指针静止 → 停帧（零空转开销） */
  if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5) {
    auraTx = auraGx;
    auraTy = auraGy;
    auraRaf = 0;
    return;
  }
  auraRaf = requestAnimationFrame(auraFrame);
};

const kickAura = () => {
  if (!auraRaf) auraRaf = requestAnimationFrame(auraFrame);
};

/* ============================================================================
 * ★ 不规则字号雕刻排印 — 参数由 useBrandTitle 全局唯一权威源生成
 *   （与主界面 HomeView 共享同一确定性 hash 场，品牌排印跨场景同源）：
 *   字号 56-108px 逐字差化 / 基线 ±13px 非均匀错落 / 微倾 ±2° /
 *   实色·镂空·accent 三态（accent 唯一 = 'C'）/ 双层雕刻暗色克隆 /
 *   轨道入射 + 外缘先走引力弹射
 * ========================================================================== */
const charVariants = useBrandTitle();

/* ★ 谱线组（光谱发射线隐喻，拒绝规整加载条）— 参数由 useSpectraTicks
 * 唯一权威源生成（与主界面 HomeView 谱线回声共享：光谱色/时序/呼吸/
 * 微跳逐线差化 — intro 变体含充能 cd/塌缩 cl 时序编排）。
 * ★ 呼吸/微跳无缝衔接（充能→驻留跳变根治）：呼吸动画 0% 帧 = 充能
 * 100% 帧（scaleY(1)/opacity=op 逐值一致），且每线呼吸延迟 sm 精确对齐
 * 自身充能结束时刻 — 起始帧 = 当前帧零跳变 */
const spectraTicks = useSpectraTicks("intro");

/* 指针事件仅记录目标（中心系坐标），写入与插值全部由 rAF 承担 */
const onMouseMove = (e: MouseEvent) => {
  auraGx = e.clientX - window.innerWidth / 2;
  auraGy = e.clientY - window.innerHeight / 2;
  kickAura();
};

const onEnter = () => {
  if (leaving.value) return;
  leaving.value = true;
  /* 逐字弹射起飞后交接星系正渡（0.32s ≈ 弹射前段，衔接无空窗） */
  setTimeout(() => {
    emit("enter");
  }, 320);
};

let timers: number[] = [];
const pushTimer = (fn: () => void, delay: number) => {
  const id = window.setTimeout(fn, delay);
  timers.push(id);
};

onMounted(() => {
  /* 谱线组充能完毕 → 呼吸驻留（3.05s — 与逆渡 INTRO_T=3s 收束同步） */
  pushTimer(() => { charged.value = true; }, 3050);

  /* 副标题入场（逆渡消散段，星系已倒卷成型） */
  pushTimer(() => { subShown.value = true; }, 2450);

  /* 底部进入舱（逆渡完成后浮现） */
  pushTimer(() => { hintVisible.value = true; }, 3250);
});

onBeforeUnmount(() => {
  timers.forEach(t => clearTimeout(t));
  timers = [];
  if (auraRaf) {
    cancelAnimationFrame(auraRaf);
    auraRaf = 0;
  }
});
</script>

<style scoped>
.intro-view {
  position: relative;
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  overflow: hidden;
}

/* ===== 鼠标跟随光晕（低强度反馈，rAF 阻尼跟随 + transform 直写） ===== */
.cursor-aura {
  /* 锚定视口中心，位移全部由 JS translate3d 直写（合成器层零重绘） */
  position: absolute;
  left: 50%;
  top: 50%;
  width: 460px;
  height: 460px;
  border-radius: 50%;
  /* ★ 去实时 blur：多段柔边径向渐变等效 28px 模糊（静态纹理，
   * GPU 一次光栅化永久复用，移动零重采样） */
  background: radial-gradient(
    circle,
    rgba(0, 212, 255, 0.05) 0%,
    rgba(0, 212, 255, 0.038) 16%,
    rgba(0, 212, 255, 0.024) 30%,
    rgba(139, 92, 246, 0.02) 44%,
    rgba(139, 92, 246, 0.01) 56%,
    rgba(139, 92, 246, 0.004) 66%,
    transparent 76%
  );
  transform: translate3d(0, 0, 0) translate(-50%, -50%);
  pointer-events: none;
  z-index: 1;
  will-change: transform;
}

/* ============================================================================
 * ★ 轨道丝线（动态揭示/收回 + dash 巡行）
 * pathLength="1" 归一化：dasharray 分数化（各模式总长恒为 1.0），
 * fil-orbit 以 dashoffset −1（整圈）线性巡行 — 闭合路径上模式周期
 * 整除路径长 → 无缝循环，dash 沿椭圆持续流动（轨道碎屑感）。
 * 揭示：dash 自零生长 + 微缩放渐显；收回：反向塌缩回隐藏模式
 * + 向外舒展释放 — 非单纯淡入淡出。
 * 离场保留 fil-orbit（同名动画不重启 → dash 巡行零跳变）。
 * ========================================================================== */
.orbit-filaments {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 0;
}
.fil {
  transform-box: fill-box;
  transform-origin: center;
  stroke-width: 1;
  vector-effect: non-scaling-stroke;
}
/* 基线 = 揭示完成态（reveal 以 backwards 填充覆盖延迟期，
 * 结束后落回基线 — 与 to 帧逐值一致，零跳变） */
.fil-a {
  stroke: rgba(0, 212, 255, 0.11);
  stroke-dasharray: 0.46 0.06 0.3 0.18;
  opacity: 0.9;
  transform: rotate(-13deg);
  animation:
    fil-orbit 46s linear infinite,
    fil-reveal-a 1.9s var(--ease) 0.35s backwards;
}
.fil-b {
  stroke: rgba(139, 92, 246, 0.08);
  stroke-dasharray: 0.12 0.1 0.52 0.26;
  opacity: 0.75;
  transform: rotate(21deg);
  animation:
    fil-orbit 58s linear infinite,
    fil-reveal-b 1.9s var(--ease) 0.95s backwards;
}
.fil-c {
  stroke: rgba(255, 217, 160, 0.06);
  stroke-dasharray: 0.3 0.08 0.38 0.24;
  opacity: 0.7;
  transform: rotate(-6deg);
  animation:
    fil-orbit 38s linear infinite,
    fil-reveal-c 1.9s var(--ease) 1.5s backwards;
}
/* dash 巡行：闭合路径整圈偏移（模式总长=1 → 无缝循环） */
@keyframes fil-orbit {
  to { stroke-dashoffset: -1; }
}
/* 揭示：dash 自零生长 + 微缩放渐显（与星系逆渡成型同步，逐线错峰） */
@keyframes fil-reveal-a {
  from { opacity: 0; transform: rotate(-13deg) scale(0.965); stroke-dasharray: 0 0.5 0 0.5; }
  to { opacity: 0.9; transform: rotate(-13deg) scale(1); stroke-dasharray: 0.46 0.06 0.3 0.18; }
}
@keyframes fil-reveal-b {
  from { opacity: 0; transform: rotate(21deg) scale(0.965); stroke-dasharray: 0 0.5 0 0.5; }
  to { opacity: 0.75; transform: rotate(21deg) scale(1); stroke-dasharray: 0.12 0.1 0.52 0.26; }
}
@keyframes fil-reveal-c {
  from { opacity: 0; transform: rotate(-6deg) scale(0.965); stroke-dasharray: 0 0.5 0 0.5; }
  to { opacity: 0.7; transform: rotate(-6deg) scale(1); stroke-dasharray: 0.3 0.08 0.38 0.24; }
}
/* 收回：dash 塌缩回隐藏模式 + 向外舒展释放（引力松开 — 非瞬时消失）；
 * fil-orbit 同名保留 → 巡行相位连续，仅揭示层被替换 */
.orbit-filaments.leaving .fil-a {
  animation:
    fil-orbit 46s linear infinite,
    fil-retract-a 0.75s var(--ease) forwards;
}
.orbit-filaments.leaving .fil-b {
  animation:
    fil-orbit 58s linear infinite,
    fil-retract-b 0.8s var(--ease) 0.07s forwards;
}
.orbit-filaments.leaving .fil-c {
  animation:
    fil-orbit 38s linear infinite,
    fil-retract-c 0.85s var(--ease) 0.14s forwards;
}
@keyframes fil-retract-a {
  from { opacity: 0.9; transform: rotate(-13deg) scale(1); stroke-dasharray: 0.46 0.06 0.3 0.18; }
  to { opacity: 0; transform: rotate(-10deg) scale(1.05); stroke-dasharray: 0 0.5 0 0.5; }
}
@keyframes fil-retract-b {
  from { opacity: 0.75; transform: rotate(21deg) scale(1); stroke-dasharray: 0.12 0.1 0.52 0.26; }
  to { opacity: 0; transform: rotate(18deg) scale(1.06); stroke-dasharray: 0 0.5 0 0.5; }
}
@keyframes fil-retract-c {
  from { opacity: 0.7; transform: rotate(-6deg) scale(1); stroke-dasharray: 0.3 0.08 0.38 0.24; }
  to { opacity: 0; transform: rotate(-4deg) scale(1.07); stroke-dasharray: 0 0.5 0 0.5; }
}

/* ===== 品牌核心 ===== */
.brand-core {
  position: relative;
  text-align: center;
  z-index: 2;
}

/* ============================================================================
 * ★ 主标题：几何/三态着色/双层雕刻/组装曲线全部复用全局共享体系
 * （animations.css .brand-title + .brand-char + brand-assemble —
 * 与主界面 HomeView compact 级同源，引导级幅度即共享默认值）；
 * 此处仅保留本组件专属的引力弹射离场编排。
 * ========================================================================== */

/* ★ 引力弹射离场：自浮动基线沿入射向量反向弹射（外缘字先走），
 * 加速离场曲线（引力弹弓），与星系正渡衔接 */
.brand-core.leaving .brand-char {
  animation: char-eject 0.62s cubic-bezier(0.5, 0, 0.9, 0.4) var(--ed, 0ms) both;
}
@keyframes char-eject {
  0% {
    opacity: 1;
    transform: translateY(var(--by, 0px)) rotate(var(--tr, 0deg)) scale(1);
    filter: blur(0) brightness(1);
  }
  100% {
    opacity: 0;
    transform: translate(calc(var(--dx, 60px) * 1.7), calc(var(--dy, -40px) * 1.7))
      rotate(calc(var(--rot, 8deg) * -2)) scale(0.5);
    filter: blur(14px) brightness(1.5);
  }
}

/* ============================================================================
 * ★ 谱线组（光谱发射线 — 替代单线充能条）：
 * 充能：逐线自基线生长（时序差化 0.36-2.1s 覆盖逆渡包络）；
 * 驻留：逐线独立呼吸（周期/相位差化 — 活态，非静止死线）；
 * 塌缩：外缘先收（cl 时序 — 与逐字弹射外缘先走同构），
 *       scaleY→0 回落基线，与品牌动画回收节奏一致零残留。
 * ========================================================================== */
.spectra {
  display: flex;
  align-items: flex-end;
  justify-content: center;
  height: 24px;
  margin-top: 30px;
}
.spectra-tick {
  /* 基础形态（几何/光谱色/transform 基线/will-change 合成层锁定）与
   * 驻留动效（spectra-breathe 呼吸 / spectra-jitter 微跳）见全局
   * animations.css 共享体系；此处仅声明充能入场（时序编排为本组件专属） */
  animation: tick-charge 0.9s cubic-bezier(0.22, 1, 0.36, 1) var(--cd, 0ms) backwards;
}
@keyframes tick-charge {
  0% {
    transform: scaleY(0);
    opacity: 0;
  }
  70% {
    opacity: calc(var(--op, 0.7) * 1.6);
  }
  100% {
    transform: scaleY(1);
    opacity: var(--op, 0.7);
  }
}
/* 充能完毕 → 独立呼吸 + 微跳驻留（周期差化 — 光谱微脉动 + 偶发轻跳）。
 * ★ 无缝衔接核心：呼吸 0%/100% 帧 = charge 100% 帧（scaleY(1) +
 * opacity=op）逐值一致，且每线延迟 --sm 精确对齐自身充能结束时刻 —
 * 呼吸起始帧 = 元素当前帧，零跳变零重刷 */
.spectra.charged .spectra-tick {
  animation:
    tick-charge 0.9s cubic-bezier(0.22, 1, 0.36, 1) var(--cd, 0ms) backwards,
    spectra-breathe var(--sd, 3.5s) ease-in-out var(--sm, 0ms) infinite,
    spectra-jitter var(--jd, 6s) linear var(--jp, 0ms) infinite;
}
/* 塌缩：外缘先收（引力回收集波 — 与逐字弹射同步编排） */
.brand-core.leaving .spectra-tick {
  animation: tick-collapse 0.55s cubic-bezier(0.55, 0, 0.82, 0.5) var(--cl, 0ms) both;
}
@keyframes tick-collapse {
  0% {
    transform: scaleY(1);
    opacity: var(--op, 0.7);
  }
  100% {
    transform: scaleY(0);
    opacity: 0;
  }
}

/* ===== 副标题 ===== */
.brand-sub {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 14px;
  font-size: 11px;
  color: var(--text-muted);
  letter-spacing: 8px;
  font-weight: 400;
  font-family: var(--font);
  margin-top: 20px;
  opacity: 0;
  transform: translateY(8px);
  transition: opacity 1s var(--ease), transform 1s var(--ease);
}
.brand-sub.shown {
  opacity: 1;
  transform: translateY(0);
}
.brand-core.leaving .brand-sub {
  opacity: 0;
  transform: translateY(6px);
  transition: opacity 0.45s var(--ease), transform 0.45s var(--ease);
}
.sub-dot {
  width: 3px;
  height: 3px;
  border-radius: 50%;
  background: var(--accent);
  opacity: 0.6;
  box-shadow: 0 0 6px rgba(0, 212, 255, 0.5);
  animation: sub-dot-pulse 2.5s ease-in-out infinite;
}
@keyframes sub-dot-pulse {
  0%, 100% { opacity: 0.3; transform: scale(0.8); }
  50% { opacity: 0.9; transform: scale(1.2); }
}

/* ============================================================================
 * ★ 底部进入提示（v5 — 线体极简，极致美学，无呼吸静态）：
 * v5 等长校正：左右能量轨统一由 --hint-line-w 唯一权威源驱动
 *   （46px × 2 — 取 v4 非对称 54/38 的均值，轨组总宽 92px 不变、
 *   整体居中质量零漂移，仅消除左右不等长的视觉缺陷）；时序差化
 *   保留（右线晚生 0.12s — 几何等长但入场时序非机械同步）
 * v4 体系（保留）：端点竖标（1×5px 微刻度 — 仪器级收笔，非装饰堆砌）；
 *   文字静态定Opacity（无任何循环动画 — 安静的高级感）；
 *   入场：双线自文字侧向外生长（一次性）+ 文字淡入；
 *   离场：双线向文字侧收回 + 端点渐隐 + 文字字距扩散消解。
 * ========================================================================== */
.enter-hint {
  position: absolute;
  bottom: 70px;
  left: 50%;
  transform: translateX(-50%);
  display: flex;
  align-items: center;
  gap: 18px;
  z-index: 3;
  /* 左右能量轨等长唯一权威源（46px × 2 = v4 轨组总宽 54+38） */
  --hint-line-w: 46px;
}
.hint-line {
  position: relative;
  height: 1px;
  width: var(--hint-line-w);
  /* 一次性生长入场（自文字侧向外 — transform-origin 定侧） */
  animation: hint-grow 0.9s var(--ease) backwards;
}
.hint-line-l {
  background: linear-gradient(90deg, rgba(159, 181, 201, 0.42), rgba(159, 181, 201, 0.02));
  transform-origin: right center;
}
.hint-line-r {
  background: linear-gradient(270deg, rgba(159, 181, 201, 0.42), rgba(159, 181, 201, 0.02));
  transform-origin: left center;
  animation-delay: 0.12s; /* 右线晚生 — 入场层次（时序差化，几何等长） */
}
@keyframes hint-grow {
  from { transform: scaleX(0); }
  to { transform: scaleX(1); }
}
/* 端点竖标：外端 1×5px 微刻度（渐隐收笔 — 非圆点非方块） */
.hint-cap {
  position: absolute;
  top: -2.5px;
  width: 1px;
  height: 5px;
  background: rgba(159, 181, 201, 0.5);
  opacity: 0;
  animation: hint-cap-in 0.5s var(--ease) 0.7s forwards;
}
.hint-line-l .hint-cap { right: -1px; }
.hint-line-r .hint-cap { left: -1px; animation-delay: 0.82s; }
@keyframes hint-cap-in {
  to { opacity: 1; }
}
/* 文字：静态定透明度（无呼吸 — 安静驻留） */
.hint-text {
  font-size: 11px;
  color: var(--text-secondary);
  letter-spacing: 6px;
  text-indent: 6px;
  font-family: var(--font);
  opacity: 0.72;
  transition: opacity 0.55s var(--ease), letter-spacing 0.55s var(--ease);
}
/* 离场：双线向文字侧收回 + 端点渐隐 + 文字字距扩散消解 */
.enter-hint.leaving .hint-line {
  animation: hint-retract 0.55s var(--ease) forwards;
}
@keyframes hint-retract {
  to { transform: scaleX(0); }
}
.enter-hint.leaving .hint-cap {
  animation: hint-cap-out 0.4s var(--ease) forwards;
}
@keyframes hint-cap-out {
  to { opacity: 0; }
}
.enter-hint.leaving .hint-text {
  opacity: 0;
  letter-spacing: 10px;
}

/* 提示入场动画 */
.hint-fade-enter-active {
  transition: all 0.8s var(--ease);
}
.hint-fade-enter-from {
  opacity: 0;
  transform: translateX(-50%) translateY(10px);
}
</style>
