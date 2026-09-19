<!--
  CosmicBackground.vue — 深空巡天场 · 主界面氛围背景层（全面重构版）
  ★ 设计语言：真实深空摄影美学（巡天视场）— 与偏轴旋涡星系（全局
    ParticleBackground）、HomeAtlas 引力星图同属一套轨道/引力视觉体系。
  ★ 反大众化根除清单（对应旧版套路元素）：
    ✗ 脉冲星灯塔（旋转光束 + 三层辉光）      → ✓ 深空背景星系微斑（真实
      巡天视场语汇 — 6 个拉长暗淡星系像，全应用无第二处同款）
    ✗ 对称角落辉光（对角双色脉动）           → ✓ 尘带遮挡（暗色剪影层 —
      恒星间尘埃遮光，深空摄影的高对比来源）
    ✗ 行星系统（4 环 + 3 虚线轨道卫星）      → ✓ 刻痕已归 HomeAtlas 星图；
      背景层回归纯氛围（前景焦点让位默认视图主视觉）
    ✗ 左上小行星 + 卫星                      → ✓ 同上移除
    ✗ 5 颗同角度流星                         → ✓ 3 颗差化轨迹（角度/长度/
      周期/落点全差化 — 稀有即珍贵）
  ★ 运动规则升级（统一数学/物理）：
    - 星点闪烁：复合谐波（基波 + 2/3 次谐波加权 — 真实大气闪烁频谱结构，
      整数倍频保证周期边界连续，逐星相位差化拒绝同步机械波）
    - 尘埃漂移：逐粒独立向量（方向场差化）+ 侧向摆动（2 次谐波）
    - 星云/星系微斑/尘带：复合曲线呼吸/漂移（非单一正弦）
  ★ 架构保留：统一 rAF 引擎（useFrameGate 四档降频）/ 失焦 deep-idle /
    滤镜贴图烘焙 / content-visibility 视口外跳渲染。
  ★ 入场错峰：氛围引擎延迟至星系正渡包络归零后再启动（TRANSITION.
    MAINVIEW_AMBIENT_WAIT — 自预挂载起算，含提前量补偿，苏醒锚点
    仍精确对齐渡越归零）— 挂载即暖机写基线，延迟期静态驻留零跳变；
    163 元素样式写入与流星起飞不再挤占主界面入场窗口。
-->
<template>
  <div ref="rootRef" class="ambient-bg" :style="texVars">
    <!-- 深空底层：多径向叠加营造立体深度 -->
    <div class="deep-space"></div>

    <!-- 视差层 1：远（星云团 + 银河带 + 背景星系微斑，移动幅度最小） -->
    <div class="parallax-layer p-far" :style="parallaxFar">
      <div class="nebula nebula-1"></div>
      <div class="nebula nebula-2"></div>
      <div class="nebula nebula-3"></div>
      <div class="nebula nebula-4"></div>
      <div class="nebula nebula-5"></div>
      <div class="nebula nebula-6"></div>
      <div class="galaxy-band"></div>
      <div class="galaxy-band galaxy-band-2"></div>
      <!-- 深空背景星系（6 个拉长暗淡星系像 — 巡天视场纵深） -->
      <div class="bg-galaxy bg-galaxy-1"></div>
      <div class="bg-galaxy bg-galaxy-2"></div>
      <div class="bg-galaxy bg-galaxy-3"></div>
      <div class="bg-galaxy bg-galaxy-4"></div>
      <div class="bg-galaxy bg-galaxy-5"></div>
      <div class="bg-galaxy bg-galaxy-6"></div>
    </div>

    <!-- 视差层 2：中（尘带遮挡 + 星座连线，移动幅度中等） -->
    <div class="parallax-layer p-mid" :style="parallaxMid">
      <!-- 尘带（暗色剪影 — 遮挡远层发光，深空摄影高对比来源） -->
      <div class="dust-lane lane-a"></div>
      <div class="dust-lane lane-b"></div>
      <!-- 星座连线（SVG 抽象星座） -->
      <svg class="constellation" viewBox="0 0 100 80" preserveAspectRatio="none">
        <line
          v-for="(line, i) in constellationLines"
          :key="`l${i}`"
          :x1="line.x1" :y1="line.y1"
          :x2="line.x2" :y2="line.y2"
          class="const-line"
          :style="{ '--ap': (i * 0.4) / 6 }"
        />
        <circle
          v-for="(s, i) in constellationStars"
          :key="`c${i}`"
          :cx="s.x" :cy="s.y" r="0.35"
          class="const-node"
          :style="{ '--ap': (i * 0.3) / 3.5 }"
        />
      </svg>
    </div>

    <!-- 视差层 3：近（三层星场 + 宇宙尘埃，移动幅度最大） -->
    <div class="parallax-layer p-near" :style="parallaxNear">
      <!-- 远层星点（小而暗，慢闪） -->
      <div class="star-field stars-far">
        <span
          v-for="s in starsFar" :key="s.id" class="star-dot"
          :style="{ ...s.style, '--ad': s.dur + 's', '--ap': s.phase }"
        ></span>
      </div>
      <!-- 中层星点（中等亮度） -->
      <div class="star-field stars-mid">
        <span
          v-for="s in starsMid" :key="s.id" class="star-dot"
          :style="{ ...s.style, '--ad': s.dur + 's', '--ap': s.phase }"
        ></span>
      </div>
      <!-- 近层星点（大而亮，带十字光芒） -->
      <div class="star-field stars-near">
        <span
          v-for="s in starsNear" :key="s.id" class="star-dot star-bright"
          :style="{ ...s.style, '--ad': s.dur + 's', '--ap': s.phase }"
        ></span>
      </div>

      <!-- 宇宙尘埃微粒（逐粒独立向量漂移 + 侧摆） -->
      <div class="cosmic-dust">
        <span
          v-for="d in cosmicDust" :key="d.id" class="dust-particle"
          :style="{ ...d.style, '--ad': d.dur + 's', '--ap': d.phase, '--vx': d.vx, '--vy': d.vy, '--swx': d.swx }"
        ></span>
      </div>
    </div>

    <!-- 流星群（3 颗 — 角度/长度/周期/落点全差化，稀有即珍贵） -->
    <div class="meteor m1"></div>
    <div class="meteor m2"></div>
    <div class="meteor m3"></div>

    <!-- 暗角呼吸层 -->
    <div class="vignette"></div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from "vue";
import type { CosmicStar, CosmicDust } from "../../composables/useCosmicBackground";

defineProps<{
  parallaxFar: Record<string, string>;
  parallaxMid: Record<string, string>;
  parallaxNear: Record<string, string>;
  starsFar: CosmicStar[];
  starsMid: CosmicStar[];
  starsNear: CosmicStar[];
  cosmicDust: CosmicDust[];
  constellationStars: { x: number; y: number }[];
  constellationLines: { x1: number; y1: number; x2: number; y2: number }[];
}>();

/* ============================================================================
 * ★ 预渲染贴图：SVG 位图（渐变 + feGaussianBlur 烘焙）
 * ============================================================================
 * 浏览器将 data-URI SVG 背景图栅格化一次并缓存为纹理，运行时不再执行
 * filter: blur 实时重栅格化（星云 / 银河带 / 背景星系 / 尘带全部贴图化）。
 * 椭圆贴图（rx≠ry）：背景星系像的拉长形态与尘带的带状形态直接烘焙进
 * 纹理 — 元素层零 scale 变形，旋转静态化于 CSS。
 */
const svgUrl = (svg: string): string =>
  `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;

const svgStop = (offset: number, color: string): string =>
  `<stop offset="${offset}" stop-color="${color}"/>`;

/** 径向/椭圆渐变 + 高斯模糊贴图（星云 / 背景星系 / 尘带共用） */
function radialBlurTexture(
  stops: string,
  cssBlurPx: number,
  cssElSize: number,
  cx = 160,
  cy = 160,
  r = 120,
  rx = r,
  ry = r,
): string {
  const S = 320;
  const sigma = ((cssBlurPx * S) / cssElSize).toFixed(2);
  return svgUrl(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${S}" height="${S}">` +
      `<defs>` +
      `<radialGradient id="g">${stops}</radialGradient>` +
      `<filter id="f" x="-40%" y="-40%" width="180%" height="180%">` +
      `<feGaussianBlur stdDeviation="${sigma}"/></filter>` +
      `</defs>` +
      `<ellipse cx="${cx}" cy="${cy}" rx="${rx}" ry="${ry}" fill="url(#g)" filter="url(#f)"/></svg>`,
  );
}

/** 斜向线性渐变带 + 高斯模糊贴图（用于 2 银河带） */
function bandTexture(stops: string, cssAngleDeg: number, cssBlurPx: number): string {
  const W = 512;
  const H = 341;
  const rad = (cssAngleDeg * Math.PI) / 180;
  const dx = Math.sin(rad).toFixed(4);
  const dy = (-Math.cos(rad)).toFixed(4);
  const sigma = ((cssBlurPx * W) / 1280).toFixed(2); // 参考逻辑宽 1280px
  return svgUrl(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}">` +
      `<defs>` +
      `<linearGradient id="g" x1="0" y1="0" x2="${dx}" y2="${dy}">${stops}</linearGradient>` +
      `<filter id="f" x="-20%" y="-20%" width="140%" height="140%">` +
      `<feGaussianBlur stdDeviation="${sigma}"/></filter>` +
      `</defs>` +
      `<rect width="${W}" height="${H}" fill="url(#g)" filter="url(#f)"/></svg>`,
  );
}

/** 线性渐变矩形 + 微高斯模糊贴图（用于流星） */
function linearBlurTexture(
  stops: string,
  w: number,
  h: number,
  cssBlurPx: number,
  vertical: boolean,
): string {
  const sigma = cssBlurPx.toFixed(2);
  const axis = vertical ? `x1="0" y1="0" x2="0" y2="1"` : `x1="0" y1="0" x2="1" y2="0"`;
  return svgUrl(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}">` +
      `<defs>` +
      `<linearGradient id="g" ${axis}>${stops}</linearGradient>` +
      `<filter id="f" x="-40%" y="-40%" width="180%" height="180%">` +
      `<feGaussianBlur stdDeviation="${sigma}"/></filter>` +
      `</defs>` +
      `<rect width="${w}" height="${h}" fill="url(#g)" filter="url(#f)"/></svg>`,
  );
}

const texVars = computed<Record<string, string>>(() => ({
  /* 6 星云（青/紫主导 + 暖色点缀 — 不对称散布，透明度整体收敛让位前景） */
  "--tex-nebula-1": radialBlurTexture(
    svgStop(0, "rgba(139,92,246,0.24)") + svgStop(0.5, "rgba(139,92,246,0.05)") + svgStop(0.72, "rgba(139,92,246,0)"),
    70, 560,
  ),
  "--tex-nebula-2": radialBlurTexture(
    svgStop(0, "rgba(0,212,255,0.19)") + svgStop(0.55, "rgba(0,212,255,0.035)") + svgStop(0.75, "rgba(0,212,255,0)"),
    70, 480,
  ),
  "--tex-nebula-3": radialBlurTexture(
    svgStop(0, "rgba(255,110,180,0.13)") + svgStop(0.55, "rgba(180,100,255,0.04)") + svgStop(0.75, "rgba(180,100,255,0)"),
    70, 380,
  ),
  "--tex-nebula-4": radialBlurTexture(
    svgStop(0, "rgba(120,180,255,0.12)") + svgStop(0.7, "rgba(120,180,255,0)"),
    70, 320,
  ),
  "--tex-nebula-5": radialBlurTexture(
    svgStop(0, "rgba(0,255,200,0.10)") + svgStop(0.5, "rgba(0,180,200,0.03)") + svgStop(0.75, "rgba(0,180,200,0)"),
    70, 420,
  ),
  "--tex-nebula-6": radialBlurTexture(
    svgStop(0, "rgba(255,160,90,0.09)") + svgStop(0.7, "rgba(255,160,90,0)"),
    70, 300,
  ),
  /* 2 银河带（斜向辉光 — 倾角呼应银河盘斜视姿态） */
  "--tex-band-1": bandTexture(
    svgStop(0.3, "rgba(139,92,246,0)") + svgStop(0.42, "rgba(139,92,246,0.05)") +
      svgStop(0.5, "rgba(0,212,255,0.07)") + svgStop(0.58, "rgba(255,180,220,0.04)") +
      svgStop(0.7, "rgba(255,180,220,0)"),
    115, 24,
  ),
  "--tex-band-2": bandTexture(
    svgStop(0.35, "rgba(0,255,200,0)") + svgStop(0.48, "rgba(0,255,200,0.04)") +
      svgStop(0.52, "rgba(180,130,255,0.05)") + svgStop(0.65, "rgba(180,130,255,0)"),
    75, 24,
  ),
  /* ★ 深空背景星系 ×6（拉长椭圆像 — 巡天视场纵深；色温差化：
     冷白 / 淡蓝 / 暖白 / 淡紫 / 银白 / 青绿 — 真实星系形态多样性） */
  "--tex-bg-g1": radialBlurTexture(
    svgStop(0, "rgba(210,228,248,0.30)") + svgStop(0.55, "rgba(210,228,248,0.10)") + svgStop(1, "rgba(210,228,248,0)"),
    8, 52, 160, 160, 150, 148, 54,
  ),
  "--tex-bg-g2": radialBlurTexture(
    svgStop(0, "rgba(150,190,255,0.24)") + svgStop(0.6, "rgba(150,190,255,0.07)") + svgStop(1, "rgba(150,190,255,0)"),
    7, 44, 160, 160, 150, 146, 52,
  ),
  "--tex-bg-g3": radialBlurTexture(
    svgStop(0, "rgba(255,230,200,0.22)") + svgStop(0.6, "rgba(255,230,200,0.06)") + svgStop(1, "rgba(255,230,200,0)"),
    7, 36, 160, 160, 150, 144, 50,
  ),
  "--tex-bg-g4": radialBlurTexture(
    svgStop(0, "rgba(190,170,255,0.20)") + svgStop(0.6, "rgba(190,170,255,0.06)") + svgStop(1, "rgba(190,170,255,0)"),
    6, 40, 160, 160, 150, 146, 48,
  ),
  "--tex-bg-g5": radialBlurTexture(
    svgStop(0, "rgba(220,235,250,0.18)") + svgStop(0.6, "rgba(220,235,250,0.05)") + svgStop(1, "rgba(220,235,250,0)"),
    6, 32, 160, 160, 150, 142, 46,
  ),
  "--tex-bg-g6": radialBlurTexture(
    svgStop(0, "rgba(160,240,230,0.16)") + svgStop(0.6, "rgba(160,240,230,0.05)") + svgStop(1, "rgba(160,240,230,0)"),
    6, 34, 160, 160, 150, 142, 46,
  ),
  /* ★ 尘带 ×2（暗色剪影 — 恒星间尘埃遮光，遮挡远层发光成像） */
  "--tex-lane-a": radialBlurTexture(
    svgStop(0, "rgba(2,4,9,0.52)") + svgStop(0.6, "rgba(2,4,9,0.28)") + svgStop(1, "rgba(2,4,9,0)"),
    60, 900, 160, 160, 150, 148, 30,
  ),
  "--tex-lane-b": radialBlurTexture(
    svgStop(0, "rgba(2,4,9,0.44)") + svgStop(0.6, "rgba(2,4,9,0.22)") + svgStop(1, "rgba(2,4,9,0)"),
    50, 640, 160, 160, 150, 146, 26,
  ),
  /* 流星（微模糊竖向渐变 → 贴图） */
  "--tex-meteor": linearBlurTexture(
    svgStop(0, "rgba(255,255,255,0)") + svgStop(0.8, "rgba(255,255,255,0.95)") + svgStop(1, "rgba(0,212,255,0.6)"),
    16, 128, 0.5, true,
  ),
}));

</script>

<style scoped>
/* ===== 深空巡天场背景层 ===== */
.ambient-bg {
  position: absolute;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  overflow: hidden;
}

/* 深空底层：多径向叠加营造立体深度（压暗收敛 — 让位前景星图主体） */
.deep-space {
  position: absolute;
  inset: 0;
  background:
    radial-gradient(ellipse at 22% 28%, rgba(16, 10, 42, 0.40) 0%, transparent 50%),
    radial-gradient(ellipse at 78% 68%, rgba(6, 26, 44, 0.48) 0%, transparent 55%),
    radial-gradient(ellipse at 50% 46%, rgba(12, 8, 30, 0.28) 0%, transparent 70%),
    linear-gradient(180deg, #03050b 0%, #05070f 50%, #020409 100%);
}

/* 视差层：鼠标驱动深度位移 */
.parallax-layer {
  position: absolute;
  inset: 0;
  will-change: transform;
}

/* 深空星云团（贴图烘焙 — 运行时零滤镜；不对称散布） */
.nebula {
  position: absolute;
  border-radius: 50%;
  mix-blend-mode: screen;
  background: center / 100% 100% no-repeat;
  will-change: transform, opacity;
}
.nebula-1 {
  width: 560px;
  height: 560px;
  top: -120px;
  left: -100px;
  background-image: var(--tex-nebula-1);
}
.nebula-2 {
  width: 480px;
  height: 480px;
  bottom: -80px;
  right: -60px;
  background-image: var(--tex-nebula-2);
}
.nebula-3 {
  width: 380px;
  height: 380px;
  top: 22%;
  left: 32%;
  background-image: var(--tex-nebula-3);
}
.nebula-4 {
  width: 320px;
  height: 320px;
  top: 48%;
  right: 26%;
  background-image: var(--tex-nebula-4);
}
.nebula-5 {
  width: 420px;
  height: 420px;
  top: 60%;
  left: 8%;
  background-image: var(--tex-nebula-5);
}
.nebula-6 {
  width: 300px;
  height: 300px;
  top: 8%;
  right: 12%;
  background-image: var(--tex-nebula-6);
}

/* 银河带斜向辉光（双层交叉 — 倾角呼应银河盘斜视姿态） */
.galaxy-band {
  position: absolute;
  top: -20%;
  left: -10%;
  width: 120%;
  height: 80%;
  background: var(--tex-band-1) center / 100% 100% no-repeat;
  transform: rotate(-18deg);
  will-change: opacity;
}
.galaxy-band-2 {
  top: 10%;
  left: -20%;
  width: 140%;
  height: 60%;
  background: var(--tex-band-2) center / 100% 100% no-repeat;
  transform: rotate(7deg);
}

/* ============================================================================
 * ★ 深空背景星系（巡天视场纵深 — 6 个拉长暗淡星系像）：
 * 椭圆形态烘焙进贴图，元素层仅静态旋转 + 呼吸 opacity（rAF 驱动）—
 * 真实深空摄影语汇：遥远星系是视场中最暗弱、最静止的纵深锚点。
 * ========================================================================== */
.bg-galaxy {
  position: absolute;
  mix-blend-mode: screen;
  background: center / 100% 100% no-repeat;
  will-change: opacity;
}
.bg-galaxy-1 {
  width: 52px;
  height: 52px;
  top: 14%;
  left: 24%;
  transform: rotate(-32deg);
  background-image: var(--tex-bg-g1);
}
.bg-galaxy-2 {
  width: 44px;
  height: 44px;
  top: 8%;
  left: 64%;
  transform: rotate(14deg);
  background-image: var(--tex-bg-g2);
}
.bg-galaxy-3 {
  width: 36px;
  height: 36px;
  top: 30%;
  right: 8%;
  transform: rotate(-8deg);
  background-image: var(--tex-bg-g3);
}
.bg-galaxy-4 {
  width: 40px;
  height: 40px;
  top: 52%;
  left: 6%;
  transform: rotate(48deg);
  background-image: var(--tex-bg-g4);
}
.bg-galaxy-5 {
  width: 32px;
  height: 32px;
  top: 66%;
  right: 30%;
  transform: rotate(-20deg);
  background-image: var(--tex-bg-g5);
}
.bg-galaxy-6 {
  width: 34px;
  height: 34px;
  top: 40%;
  left: 46%;
  transform: rotate(62deg);
  background-image: var(--tex-bg-g6);
}

/* ============================================================================
 * ★ 尘带（暗色剪影层 — 恒星间尘埃遮光）：
 * 遮挡远层星云/银河带成像 → 深空摄影的高对比结构；漂移经 CSS 变量
 * --lx/--ly 注入（静态旋转不受 rAF 干扰）；正常混合模式压暗下方发光。
 * ========================================================================== */
.dust-lane {
  position: absolute;
  background: center / 100% 100% no-repeat;
  will-change: transform;
}
.lane-a {
  width: 86vmin;
  height: 17vmin;
  top: 5%;
  left: 28%;
  transform: rotate(-26deg) translate3d(var(--lx, 0px), var(--ly, 0px), 0);
  background-image: var(--tex-lane-a);
}
.lane-b {
  width: 64vmin;
  height: 12vmin;
  top: 57%;
  left: -7%;
  transform: rotate(9deg) translate3d(var(--lx, 0px), var(--ly, 0px), 0);
  background-image: var(--tex-lane-b);
}

/* ===== 星座连线（SVG 抽象星座 — 中景深度） ===== */
.constellation {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  opacity: 0.4;
}
.const-line {
  stroke: rgba(0, 212, 255, 0.28);
  stroke-width: 0.08;
  stroke-dasharray: 1.5 1.5;
}
.const-node {
  fill: #ffffff;
  filter: drop-shadow(0 0 1px rgba(0, 212, 255, 0.9));
}

/* ===== 三层星场（远/中/近，深度递进 — 复合谐波闪烁） ===== */
.star-field {
  position: absolute;
  inset: 0;
}
.star-dot {
  position: absolute;
  border-radius: 50%;
  box-shadow: 0 0 4px currentColor;
  opacity: calc(0.2 + 0.8 * var(--tw, 0.5));
  transform: scale(calc(0.8 + 0.6 * var(--tw, 0.5)));
  will-change: opacity, transform;
  /* 视口外星点跳过渲染 */
  content-visibility: auto;
  contain-intrinsic-size: 1px 1px;
}
.star-bright {
  box-shadow:
    0 0 6px currentColor,
    0 0 12px rgba(0, 212, 255, 0.4);
}
/* 近层亮星十字光芒（跟随父星 --tw 复合波动） */
.star-bright::before,
.star-bright::after {
  content: "";
  position: absolute;
  top: 50%;
  left: 50%;
  background: linear-gradient(90deg, transparent, currentColor, transparent);
  transform: translate(-50%, -50%) scale(calc(0.6 + 0.4 * var(--tw, 0.5)));
  opacity: calc(0.2 + 0.6 * var(--tw, 0.5));
}
.star-bright::before {
  width: 12px;
  height: 0.5px;
}
.star-bright::after {
  width: 0.5px;
  height: 12px;
}

/* ===== 宇宙尘埃微粒（逐粒独立向量漂移 + 侧摆） ===== */
.cosmic-dust {
  position: absolute;
  inset: 0;
}
.dust-particle {
  position: absolute;
  width: 1px;
  height: 1px;
  background: rgba(255, 255, 255, 0.45);
  border-radius: 50%;
  opacity: 0;
  /* GPU 合成层提升 — 数百个尘埃微粒避免软件渲染 */
  will-change: transform, opacity;
  transform: translateZ(0);
  /* 视口外尘埃跳过渲染 */
  content-visibility: auto;
  contain-intrinsic-size: 1px 1px;
}

/* ===== 流星（3 颗差化轨迹 — 贴图烘焙零滤镜） ===== */
.meteor {
  position: absolute;
  width: 2px;
  height: 130px;
  background: var(--tex-meteor) center / 100% 100% no-repeat;
  border-radius: 50%;
  opacity: 0;
  will-change: transform, opacity;
  transform: translateZ(0);
}
.m1 { top: 6%; left: 18%; }
.m2 { top: 2%; left: 62%; }
.m3 { top: 24%; left: 76%; }

/* ===== 暗角呼吸层（聚焦中心） ===== */
.vignette {
  position: absolute;
  inset: 0;
  background: radial-gradient(ellipse at center, transparent 45%, rgba(0, 0, 0, 0.55) 100%);
  pointer-events: none;
  will-change: opacity;
  transform: translateZ(0);
}

/* ==========================================================================
 * ★ 合成器驱动动画
 * 原统一 rAF 引擎（163 元素逐帧内联样式写，2-5ms/帧主线程开销）整体删除，
 * 改为 CSS keyframes（合成器线程执行，零主线程开销）：
 *   - 复合谐波曲线以 13 停站采样嵌入 keyframes（线性插值误差 <0.5% 幅度，
 *     不可感知）；逐元素相位/周期经 CSS 变量 --ap/--ad 注入（负延迟编码）
 *   - 逐元素差化参数（尘埃向量/星云漂移/星系呼吸域）经 CSS 变量注入，
 *     calc() 在 keyframes 内解析
 *   - idle-governance.css 的 .idle-idle * 暂停规则继续生效（CSS 动画）
 *   - 入场错峰语义更新：合成器动画不占用主线程，自挂载即可运行（原
 *     MAINVIEW_AMBIENT_WAIT 的主线程争抢前提消失）
 * ========================================================================== */

@keyframes star-anim {
  0% { opacity: calc(var(--so0) + var(--so1) * 0.0000); transform: scale(calc(var(--ss0) + var(--ss1) * 0.0000)); },
  7.69% { opacity: calc(var(--so0) + var(--so1) * 0.1508); transform: scale(calc(var(--ss0) + var(--ss1) * 0.1508)); },
  15.38% { opacity: calc(var(--so0) + var(--so1) * 0.4467); transform: scale(calc(var(--ss0) + var(--ss1) * 0.4467)); },
  23.08% { opacity: calc(var(--so0) + var(--so1) * 0.6320); transform: scale(calc(var(--ss0) + var(--ss1) * 0.6320)); },
  30.77% { opacity: calc(var(--so0) + var(--so1) * 0.6620); transform: scale(calc(var(--ss0) + var(--ss1) * 0.6620)); },
  38.46% { opacity: calc(var(--so0) + var(--so1) * 0.6649); transform: scale(calc(var(--ss0) + var(--ss1) * 0.6649)); },
  46.15% { opacity: calc(var(--so0) + var(--so1) * 0.6937); transform: scale(calc(var(--ss0) + var(--ss1) * 0.6937)); },
  53.85% { opacity: calc(var(--so0) + var(--so1) * 0.6937); transform: scale(calc(var(--ss0) + var(--ss1) * 0.6937)); },
  61.54% { opacity: calc(var(--so0) + var(--so1) * 0.6649); transform: scale(calc(var(--ss0) + var(--ss1) * 0.6649)); },
  69.23% { opacity: calc(var(--so0) + var(--so1) * 0.6620); transform: scale(calc(var(--ss0) + var(--ss1) * 0.6620)); },
  76.92% { opacity: calc(var(--so0) + var(--so1) * 0.6320); transform: scale(calc(var(--ss0) + var(--ss1) * 0.6320)); },
  84.62% { opacity: calc(var(--so0) + var(--so1) * 0.4467); transform: scale(calc(var(--ss0) + var(--ss1) * 0.4467)); },
  92.31% { opacity: calc(var(--so0) + var(--so1) * 0.1508); transform: scale(calc(var(--ss0) + var(--ss1) * 0.1508)); }
}

@keyframes cross-anim {
  0% { opacity: calc(var(--co0) + var(--co1) * 0.0000); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.0000)); },
  7.69% { opacity: calc(var(--co0) + var(--co1) * 0.1508); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.1508)); },
  15.38% { opacity: calc(var(--co0) + var(--co1) * 0.4467); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.4467)); },
  23.08% { opacity: calc(var(--co0) + var(--co1) * 0.6320); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.6320)); },
  30.77% { opacity: calc(var(--co0) + var(--co1) * 0.6620); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.6620)); },
  38.46% { opacity: calc(var(--co0) + var(--co1) * 0.6649); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.6649)); },
  46.15% { opacity: calc(var(--co0) + var(--co1) * 0.6937); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.6937)); },
  53.85% { opacity: calc(var(--co0) + var(--co1) * 0.6937); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.6937)); },
  61.54% { opacity: calc(var(--co0) + var(--co1) * 0.6649); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.6649)); },
  69.23% { opacity: calc(var(--co0) + var(--co1) * 0.6620); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.6620)); },
  76.92% { opacity: calc(var(--co0) + var(--co1) * 0.6320); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.6320)); },
  84.62% { opacity: calc(var(--co0) + var(--co1) * 0.4467); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.4467)); },
  92.31% { opacity: calc(var(--co0) + var(--co1) * 0.1508); transform: translate(-50%, -50%) scale(calc(var(--cs0) + var(--cs1) * 0.1508)); }
}

@keyframes h2-opacity {
  0% { opacity: calc(var(--oa) + var(--ob) * 0.0000); },
  7.69% { opacity: calc(var(--oa) + var(--ob) * 0.0954); },
  15.38% { opacity: calc(var(--oa) + var(--ob) * 0.3267); },
  23.08% { opacity: calc(var(--oa) + var(--ob) * 0.5707); },
  30.77% { opacity: calc(var(--oa) + var(--ob) * 0.7246); },
  38.46% { opacity: calc(var(--oa) + var(--ob) * 0.7700); },
  46.15% { opacity: calc(var(--oa) + var(--ob) * 0.7627); },
  53.85% { opacity: calc(var(--oa) + var(--ob) * 0.7627); },
  61.54% { opacity: calc(var(--oa) + var(--ob) * 0.7700); },
  69.23% { opacity: calc(var(--oa) + var(--ob) * 0.7246); },
  76.92% { opacity: calc(var(--oa) + var(--ob) * 0.5707); },
  84.62% { opacity: calc(var(--oa) + var(--ob) * 0.3267); },
  92.31% { opacity: calc(var(--oa) + var(--ob) * 0.0954); }
}

@keyframes nebula-anim {
  0% { opacity: calc(var(--no0) + var(--no1) * 0.0000); transform: translate(calc(var(--nx) * 1px * 0.0000), calc(var(--ny) * 1px * 0.0000)) scale(calc(1 + var(--ns) * 0.0000)); },
  7.69% { opacity: calc(var(--no0) + var(--no1) * 0.0954); transform: translate(calc(var(--nx) * 1px * 0.0954), calc(var(--ny) * 1px * 0.0954)) scale(calc(1 + var(--ns) * 0.0954)); },
  15.38% { opacity: calc(var(--no0) + var(--no1) * 0.3267); transform: translate(calc(var(--nx) * 1px * 0.3267), calc(var(--ny) * 1px * 0.3267)) scale(calc(1 + var(--ns) * 0.3267)); },
  23.08% { opacity: calc(var(--no0) + var(--no1) * 0.5707); transform: translate(calc(var(--nx) * 1px * 0.5707), calc(var(--ny) * 1px * 0.5707)) scale(calc(1 + var(--ns) * 0.5707)); },
  30.77% { opacity: calc(var(--no0) + var(--no1) * 0.7246); transform: translate(calc(var(--nx) * 1px * 0.7246), calc(var(--ny) * 1px * 0.7246)) scale(calc(1 + var(--ns) * 0.7246)); },
  38.46% { opacity: calc(var(--no0) + var(--no1) * 0.7700); transform: translate(calc(var(--nx) * 1px * 0.7700), calc(var(--ny) * 1px * 0.7700)) scale(calc(1 + var(--ns) * 0.7700)); },
  46.15% { opacity: calc(var(--no0) + var(--no1) * 0.7627); transform: translate(calc(var(--nx) * 1px * 0.7627), calc(var(--ny) * 1px * 0.7627)) scale(calc(1 + var(--ns) * 0.7627)); },
  53.85% { opacity: calc(var(--no0) + var(--no1) * 0.7627); transform: translate(calc(var(--nx) * 1px * 0.7627), calc(var(--ny) * 1px * 0.7627)) scale(calc(1 + var(--ns) * 0.7627)); },
  61.54% { opacity: calc(var(--no0) + var(--no1) * 0.7700); transform: translate(calc(var(--nx) * 1px * 0.7700), calc(var(--ny) * 1px * 0.7700)) scale(calc(1 + var(--ns) * 0.7700)); },
  69.23% { opacity: calc(var(--no0) + var(--no1) * 0.7246); transform: translate(calc(var(--nx) * 1px * 0.7246), calc(var(--ny) * 1px * 0.7246)) scale(calc(1 + var(--ns) * 0.7246)); },
  76.92% { opacity: calc(var(--no0) + var(--no1) * 0.5707); transform: translate(calc(var(--nx) * 1px * 0.5707), calc(var(--ny) * 1px * 0.5707)) scale(calc(1 + var(--ns) * 0.5707)); },
  84.62% { opacity: calc(var(--no0) + var(--no1) * 0.3267); transform: translate(calc(var(--nx) * 1px * 0.3267), calc(var(--ny) * 1px * 0.3267)) scale(calc(1 + var(--ns) * 0.3267)); },
  92.31% { opacity: calc(var(--no0) + var(--no1) * 0.0954); transform: translate(calc(var(--nx) * 1px * 0.0954), calc(var(--ny) * 1px * 0.0954)) scale(calc(1 + var(--ns) * 0.0954)); }
}

@keyframes const-line-anim {
  0% { opacity: calc(var(--oa) + var(--ob) * 0.0000); stroke-dashoffset: calc(var(--dm) * 0.0000); },
  7.69% { opacity: calc(var(--oa) + var(--ob) * 0.0954); stroke-dashoffset: calc(var(--dm) * 0.0954); },
  15.38% { opacity: calc(var(--oa) + var(--ob) * 0.3267); stroke-dashoffset: calc(var(--dm) * 0.3267); },
  23.08% { opacity: calc(var(--oa) + var(--ob) * 0.5707); stroke-dashoffset: calc(var(--dm) * 0.5707); },
  30.77% { opacity: calc(var(--oa) + var(--ob) * 0.7246); stroke-dashoffset: calc(var(--dm) * 0.7246); },
  38.46% { opacity: calc(var(--oa) + var(--ob) * 0.7700); stroke-dashoffset: calc(var(--dm) * 0.7700); },
  46.15% { opacity: calc(var(--oa) + var(--ob) * 0.7627); stroke-dashoffset: calc(var(--dm) * 0.7627); },
  53.85% { opacity: calc(var(--oa) + var(--ob) * 0.7627); stroke-dashoffset: calc(var(--dm) * 0.7627); },
  61.54% { opacity: calc(var(--oa) + var(--ob) * 0.7700); stroke-dashoffset: calc(var(--dm) * 0.7700); },
  69.23% { opacity: calc(var(--oa) + var(--ob) * 0.7246); stroke-dashoffset: calc(var(--dm) * 0.7246); },
  76.92% { opacity: calc(var(--oa) + var(--ob) * 0.5707); stroke-dashoffset: calc(var(--dm) * 0.5707); },
  84.62% { opacity: calc(var(--oa) + var(--ob) * 0.3267); stroke-dashoffset: calc(var(--dm) * 0.3267); },
  92.31% { opacity: calc(var(--oa) + var(--ob) * 0.0954); stroke-dashoffset: calc(var(--dm) * 0.0954); }
}

@keyframes dust-anim {
  0% { opacity: 0.000; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.0000), calc(var(--vy) * 1px * 0.9231), 0); },
  7.69% { opacity: 0.231; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.2158), calc(var(--vy) * 1px * 0.9231), 0); },
  15.38% { opacity: 0.461; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.6770), calc(var(--vy) * 1px * 0.9231), 0); },
  23.08% { opacity: 0.587; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.9855), calc(var(--vy) * 1px * 0.9231), 0); },
  30.77% { opacity: 0.555; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.8742), calc(var(--vy) * 1px * 0.9231), 0); },
  38.46% { opacity: 0.523; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.4398), calc(var(--vy) * 1px * 0.9231), 0); },
  46.15% { opacity: 0.491; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.0574), calc(var(--vy) * 1px * 0.9231), 0); },
  53.85% { opacity: 0.459; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.0574), calc(var(--vy) * 1px * 0.9231), 0); },
  61.54% { opacity: 0.427; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.4398), calc(var(--vy) * 1px * 0.9231), 0); },
  69.23% { opacity: 0.395; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.8742), calc(var(--vy) * 1px * 0.9231), 0); },
  76.92% { opacity: 0.363; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.9855), calc(var(--vy) * 1px * 0.9231), 0); },
  84.62% { opacity: 0.269; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.6770), calc(var(--vy) * 1px * 0.9231), 0); },
  92.31% { opacity: 0.135; transform: translate3d(calc(var(--vx) * 1px * 0.9231 + var(--swx) * 1px * 0.2158), calc(var(--vy) * 1px * 0.9231), 0); }
}

@keyframes meteor-m1 {
  0% { opacity: 0.000; transform: rotate(32deg) translate(0.0px, 0.0px); },
  3% { opacity: 0.850; transform: rotate(32deg) translate(75.0px, 75.0px); },
  12% { opacity: 0.680; transform: rotate(32deg) translate(300.0px, 300.0px); },
  18% { opacity: 0.000; transform: rotate(32deg) translate(380.0px, 380.0px); },
  100% { opacity: 0.000; transform: rotate(32deg) translate(380.0px, 380.0px); }
}

@keyframes meteor-m2 {
  0% { opacity: 0.000; transform: rotate(48deg) translate(0.0px, 0.0px); },
  3% { opacity: 0.850; transform: rotate(48deg) translate(78.0px, 78.0px); },
  10% { opacity: 0.680; transform: rotate(48deg) translate(260.0px, 260.0px); },
  16% { opacity: 0.000; transform: rotate(48deg) translate(330.0px, 330.0px); },
  100% { opacity: 0.000; transform: rotate(48deg) translate(330.0px, 330.0px); }
}

@keyframes meteor-m3 {
  0% { opacity: 0.000; transform: rotate(22deg) translate(0.0px, 0.0px); },
  3% { opacity: 0.850; transform: rotate(22deg) translate(55.4px, 55.4px); },
  13% { opacity: 0.680; transform: rotate(22deg) translate(240.0px, 240.0px); },
  20% { opacity: 0.000; transform: rotate(22deg) translate(300.0px, 300.0px); },
  100% { opacity: 0.000; transform: rotate(22deg) translate(300.0px, 300.0px); }
}

@keyframes lane-a-anim {
  0% { transform: translate3d(calc(-12px * 0.0000), calc(5px * 0.0000), 0); },
  7.69% { transform: translate3d(calc(-12px * 0.0954), calc(5px * 0.0954), 0); },
  15.38% { transform: translate3d(calc(-12px * 0.3267), calc(5px * 0.3267), 0); },
  23.08% { transform: translate3d(calc(-12px * 0.5707), calc(5px * 0.5707), 0); },
  30.77% { transform: translate3d(calc(-12px * 0.7246), calc(5px * 0.7246), 0); },
  38.46% { transform: translate3d(calc(-12px * 0.7700), calc(5px * 0.7700), 0); },
  46.15% { transform: translate3d(calc(-12px * 0.7627), calc(5px * 0.7627), 0); },
  53.85% { transform: translate3d(calc(-12px * 0.7627), calc(5px * 0.7627), 0); },
  61.54% { transform: translate3d(calc(-12px * 0.7700), calc(5px * 0.7700), 0); },
  69.23% { transform: translate3d(calc(-12px * 0.7246), calc(5px * 0.7246), 0); },
  76.92% { transform: translate3d(calc(-12px * 0.5707), calc(5px * 0.5707), 0); },
  84.62% { transform: translate3d(calc(-12px * 0.3267), calc(5px * 0.3267), 0); },
  92.31% { transform: translate3d(calc(-12px * 0.0954), calc(5px * 0.0954), 0); }
}

@keyframes lane-b-anim {
  0% { transform: translate3d(calc(9px * 0.0000), calc(-6px * 0.0000), 0); },
  7.69% { transform: translate3d(calc(9px * 0.0954), calc(-6px * 0.0954), 0); },
  15.38% { transform: translate3d(calc(9px * 0.3267), calc(-6px * 0.3267), 0); },
  23.08% { transform: translate3d(calc(9px * 0.5707), calc(-6px * 0.5707), 0); },
  30.77% { transform: translate3d(calc(9px * 0.7246), calc(-6px * 0.7246), 0); },
  38.46% { transform: translate3d(calc(9px * 0.7700), calc(-6px * 0.7700), 0); },
  46.15% { transform: translate3d(calc(9px * 0.7627), calc(-6px * 0.7627), 0); },
  53.85% { transform: translate3d(calc(9px * 0.7627), calc(-6px * 0.7627), 0); },
  61.54% { transform: translate3d(calc(9px * 0.7700), calc(-6px * 0.7700), 0); },
  69.23% { transform: translate3d(calc(9px * 0.7246), calc(-6px * 0.7246), 0); },
  76.92% { transform: translate3d(calc(9px * 0.5707), calc(-6px * 0.5707), 0); },
  84.62% { transform: translate3d(calc(9px * 0.3267), calc(-6px * 0.3267), 0); },
  92.31% { transform: translate3d(calc(9px * 0.0954), calc(-6px * 0.0954), 0); }
}

/* ---------- 合成器动画绑定 ---------- */

/* 星点：复合谐波闪烁（13 停站采样） */
.star-dot {
  --so0: 0.2; --so1: 0.8;   /* opacity 域 */
  --ss0: 0.8; --ss1: 0.6;   /* scale 域 */
  animation: star-anim var(--ad, 4s) linear calc(var(--ap, 0) * var(--ad, 4s) * -1) infinite;
}
/* 近层亮星十字光苒（独立变量域 — 交叉淡入淡出同步闪烁） */
.star-bright {
  --co0: 0.2; --co1: 0.6;
  --cs0: 0.6; --cs1: 0.4;
}
.star-bright::before,
.star-bright::after {
  animation: cross-anim var(--ad, 4s) linear calc(var(--ap, 0) * var(--ad, 4s) * -1) infinite;
}

/* 宇宙尘埃：逐粒独立向量漂移 + 侧摆 */
.dust-particle {
  animation: dust-anim var(--ad, 30s) linear calc(var(--ap, 0) * var(--ad, 30s) * -1) infinite;
}

/* 星座连线 / 节点 */
.const-line {
  --oa: 0.35; --ob: 0.5; --dm: 3;
  animation: const-line-anim 6s linear calc(var(--ap, 0) * 6s * -1) infinite;
}
.const-node {
  --oa: 0.55; --ob: 0.45;
  animation: h2-opacity 3.5s linear calc(var(--ap, 0) * 3.5s * -1) infinite;
}

/* 星云 ×6（漂移向量/缩放/呼吸域差化；相位经负延迟编码） */
.nebula-1 { --nx: 40; --ny: 30; --ns: 0.12; --no0: 0.6; --no1: 0.3; animation: nebula-anim 38s linear infinite; }
.nebula-2 { --nx: -50; --ny: -30; --ns: 0.1; --no0: 0.5; --no1: 0.35; animation: nebula-anim 44s linear infinite; }
.nebula-3 { --nx: 30; --ny: -40; --ns: 0.15; --no0: 0.4; --no1: 0.35; animation: nebula-anim 52s linear infinite; }
.nebula-4 { --nx: 40; --ny: 30; --ns: 0.12; --no0: 0.6; --no1: 0.3; animation: nebula-anim 60s linear -30s infinite; }
.nebula-5 { --nx: -50; --ny: -30; --ns: 0.1; --no0: 0.5; --no1: 0.35; animation: nebula-anim 56s linear -28s infinite; }
.nebula-6 { --nx: 30; --ny: -40; --ns: 0.15; --no0: 0.4; --no1: 0.35; animation: nebula-anim 48s linear -24s infinite; }

/* 银河带 ×2 */
.galaxy-band { --oa: 0.55; --ob: 0.45; animation: h2-opacity 18s linear infinite; }
.galaxy-band-2 { animation-delay: -12s; }

/* 背景星系 ×6（超慢呼吸，相位负延迟） */
.bg-galaxy-1 { --oa: 0.42; --ob: 0.36; animation: h2-opacity 34s linear -3.4s infinite; }
.bg-galaxy-2 { --oa: 0.38; --ob: 0.34; animation: h2-opacity 41s linear -22.55s infinite; }
.bg-galaxy-3 { --oa: 0.4; --ob: 0.34; animation: h2-opacity 29s linear -8.7s infinite; }
.bg-galaxy-4 { --oa: 0.36; --ob: 0.32; animation: h2-opacity 46s linear -34.5s infinite; }
.bg-galaxy-5 { --oa: 0.34; --ob: 0.32; animation: h2-opacity 37s linear -7.4s infinite; }
.bg-galaxy-6 { --oa: 0.32; --ob: 0.32; animation: h2-opacity 26s linear -16.12s infinite; }

/* 尘带 ×2（rotate 独立属性 + translate3d 动画 — 合成序与原 rotate→translate 一致） */
.lane-a { rotate: -26deg; animation: lane-a-anim 130s linear infinite; }
.lane-b { rotate: 9deg; animation: lane-b-anim 110s linear -55s infinite; }

/* 流星 ×3 */
.m1 { animation: meteor-m1 14s linear infinite; }
.m2 { animation: meteor-m2 19s linear -6s infinite; }
.m3 { animation: meteor-m3 24s linear -11s infinite; }

/* 暗角呼吸 */
.vignette { --oa: 0.55; --ob: 0.25; animation: h2-opacity 12s linear infinite; }

</style>
