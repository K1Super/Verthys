<!--
  CosmicBackdrop.vue — 通用宇宙主题背景层（深空巡天场）
  反大众化重构（与 CosmicBackground/HomeAtlas 同源引力视觉语法）：
    - 根除：正中心 conic 光晕环（刻板圆环+辉光泛滥）、对称闪烁星点、
      同轨迹模板流星
    - 星云：预烘焙贴图 × 4，色板收敛深空冷调（青/紫/银/金），
      非对称多相位漂移（周期边界恒连续）
    - 星点：复合谐波闪烁（多相位非等距关键帧 — 拒绝 0/50/100 对称模板），
      无辉光 shadow（纯暗点）
    - 流星：双流星全参数差化（角度/轨迹矢量/周期/相位/长度各异 —
      非等比轨迹，非同步往复）
  用法：
    <CosmicBackdrop>...</CosmicBackdrop>          ← position: absolute（模块内视图）
    <CosmicBackdrop fixed>...</CosmicBackdrop>    ← position: fixed（全屏遮罩）
    <CosmicBackdrop fixed veil="lucent">...</CosmicBackdrop>  ← 弹窗遮罩（留出可折射的衬底结构）
    <CosmicBackdrop @backdrop="onClose">...</CosmicBackdrop>  ← 点击背景触发
-->
<template>
  <div
    class="cosmic-backdrop"
    :class="{ fixed, 'view-layer': layer === 'view', 'veil-lucent': veil === 'lucent' }"
    :style="backdropStyle"
    @click.self="onBackdropClick"
  >
    <!-- 幕层：遮罩底色与氛围装饰的唯一载体，且恒为底板的兄弟节点而非祖先 ——
         入场透明度必须落在本层：元素一旦 opacity 小于 1 就成为背衬折射的
         根边界，折射只能采样边界之内的画面，底板会在整段淡入期内失去
         页面衬底、结束帧才一次性接上 -->
    <div class="cb-veil" aria-hidden="true">
      <!-- 动态星云背景层（blur 烘焙进贴图，运行时零实时滤镜） -->
      <div class="cosmic-bg">
        <div class="cb-nebula cb-nebula-1"></div>
        <div class="cb-nebula cb-nebula-2"></div>
        <div class="cb-nebula cb-nebula-3"></div>
        <div class="cb-nebula cb-nebula-4"></div>
        <div class="cb-stars">
          <span
            v-for="s in stars"
            :key="s.id"
            class="cb-star"
            :style="s.style"
          ></span>
        </div>
        <!-- 流星划过（差化轨迹 — 两颗角度/矢量/周期/相位全异） -->
        <div class="cb-meteor cb-meteor-1"></div>
        <div class="cb-meteor cb-meteor-2"></div>
      </div>
    </div>
    <slot />
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";

interface Props {
  /** 是否使用 position: fixed（全屏遮罩模式） */
  fixed?: boolean;
  /** 层级角色：view = 全屏业务视图（Unlock/Init/Verify，低于模块弹窗）；
   *  modal = 弹窗遮罩（默认，高于视图、低于窗控条） */
  layer?: "view" | "modal";
  /** 遮罩密度：deep = 深场（视图默认）；lucent = 留出衬底结构，
   *  供弹窗底板的折射有内容可折射 */
  veil?: "deep" | "lucent";
  /** 显式遮罩层级：仅高优先弹窗传入；不传时沿用样式表中的层级 */
  zIndex?: number;
}

const props = withDefaults(defineProps<Props>(), {
  fixed: false,
  layer: "modal",
  veil: "deep",
});

const emit = defineEmits<{ (e: "backdrop"): void }>();

const onBackdropClick = () => emit("backdrop");

/* ============================================================================
 * 预渲染贴图：SVG 位图（渐变 + feGaussianBlur 烘焙）
 * ============================================================================
 * 与 CosmicBackground 同手法：浏览器将 data-URI SVG 背景图栅格化一次并缓存
 * 为纹理，运行时不再执行实时重栅格化（星云 drift 动画只驱动
 * transform/opacity，纯合成）。
 * 色板收敛：粉 (255,110,180) → 金 (255,217,160)、薄荷 (0,255,200) →
 *   银 (205,224,244) — 与品牌谱线/引力星图同源深空冷调四色体系。
 */
const svgUrl = (svg: string): string =>
  `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;

const svgStop = (offset: number, color: string): string =>
  `<stop offset="${offset}" stop-color="${color}"/>`;

function radialBlurTexture(stops: string, cssBlurPx: number, cssElSize: number): string {
  const S = 320;
  const sigma = ((cssBlurPx * S) / cssElSize).toFixed(2);
  return svgUrl(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${S}" height="${S}">` +
      `<defs>` +
      `<radialGradient id="g">${stops}</radialGradient>` +
      `<filter id="f" x="-40%" y="-40%" width="180%" height="180%">` +
      `<feGaussianBlur stdDeviation="${sigma}"/></filter>` +
      `</defs>` +
      `<circle cx="160" cy="160" r="120" fill="url(#g)" filter="url(#f)"/></svg>`,
  );
}

const nebulaTexVars = computed<Record<string, string>>(() => ({
  "--tex-cb-1": radialBlurTexture(
    svgStop(0, "rgba(139,92,246,0.20)") + svgStop(0.65, "rgba(139,92,246,0)"),
    70, 460,
  ),
  "--tex-cb-2": radialBlurTexture(
    svgStop(0, "rgba(0,212,255,0.16)") + svgStop(0.65, "rgba(0,212,255,0)"),
    70, 400,
  ),
  "--tex-cb-3": radialBlurTexture(
    svgStop(0, "rgba(255,217,160,0.10)") + svgStop(0.65, "rgba(255,217,160,0)"),
    70, 320,
  ),
  "--tex-cb-4": radialBlurTexture(
    svgStop(0, "rgba(205,224,244,0.09)") + svgStop(0.65, "rgba(205,224,244,0)"),
    70, 260,
  ),
}));

/* 层级只有高优先弹窗显式传入：视图遮罩仍由样式表的 view-layer 层级接管 */
const backdropStyle = computed<Record<string, string>>(() => ({
  ...nebulaTexVars.value,
  ...(props.zIndex !== undefined ? { zIndex: String(props.zIndex) } : {}),
}));

/* ============================================================================
 * 预生成闪烁星点（构建期一次求值 — 避免每帧随机）。
 * 色板：白 / 银青 / 淡紫 / 暖金（深空巡天场四色 — 与主界面 CosmicBackground
 * 同源）；周期 2.8-7s 差化 + 相位散布，驱动非对称谐波闪烁关键帧。
 */
const starColors = ["#ffffff", "#c8e6f5", "#c9bdf2", "#f2ddad"];
const stars = Array.from({ length: 26 }, (_, i) => ({
  id: i,
  style: {
    left: `${(i * 37.7 + (i * i * 13.3) % 91) % 100}%`, // 确定性散布（去均匀网格感）
    top: `${(i * 53.1 + (i * i * 29.7) % 83) % 100}%`,
    width: `${(1 + ((i * 17) % 10) / 5.5).toFixed(2)}px`,
    height: `${(1 + ((i * 17) % 10) / 5.5).toFixed(2)}px`,
    background: starColors[i % starColors.length],
    animationDelay: `${((i * 1.37) % 6).toFixed(2)}s`,
    animationDuration: `${(2.8 + ((i * 23) % 42) / 10).toFixed(2)}s`,
  } as Record<string, string>,
}));
</script>

<style scoped>
/* ===== 背景层（默认 absolute，可切换为 fixed） =====
 * 根节点只负责定位与居中：底色与装饰全部归幕层 —— 根节点不得承载
 * 不透明度或滤镜，否则会成为底板的背衬折射边界，把页面衬底挡在边界之外 */
.cosmic-backdrop {
  position: absolute;
  inset: 0;
  z-index: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
}
/* 幕层：遮罩底色与星野装饰的唯一载体
 * 性能根治：全屏 backdrop-filter 叠在 60fps WebGL 粒子画布上 =
 * 合成器每帧对整个视口做 14px 模糊重采样（GPU 击穿主因）。
 * 去实时毛玻璃 → 遮罩底色加深补偿（背后本就是弥散星空，
 * 0.86 暗化层的视觉等效模糊后的景深压暗）；遮罩自身的
 * 星云/星点/流星装饰层（纯合成器 transform/opacity）不受影响 */
.cb-veil {
  position: absolute;
  inset: 0;
  z-index: 0;
  /* 点击穿透：遮罩的点击语义归根节点（@click.self） */
  pointer-events: none;
  background: rgba(2, 4, 10, 0.86);
}
.cosmic-backdrop.fixed {
  position: fixed;
  /* 弹窗遮罩：高于全屏视图，低于窗控条（--z-chrome = 10050） */
  z-index: 9999;
}
/* 全屏业务视图没有 overlay 的过渡通道，由幕层自身承担一次性淡入；
 * 弹窗路径的淡入归 CosmicOverlay 的过渡，两者不叠加同一属性 */
.cosmic-backdrop.fixed.view-layer .cb-veil {
  animation: cb-fade-in 0.3s var(--ease);
}
/* 弹窗遮罩的浅色变体：遮罩仍承担聚焦，但不把衬底压成死黑 ——
 * 底板是折射体，背后必须留有可被折射的星野结构，
 * 透过去的星点与色相正是「半透明」可被看见的证据 */
.cosmic-backdrop.fixed.veil-lucent .cb-veil {
  background: radial-gradient(
    120% 100% at 50% 34%,
    rgba(3, 5, 11, 0.56),
    rgba(1, 3, 8, 0.76) 78%
  );
}
.cosmic-backdrop.fixed.veil-lucent .cosmic-bg {
  opacity: 0.72;
}
/* 全屏业务视图（Unlock / Init / Verify）：低于模块弹窗（1000），
 * 使视图之上仍可正常显示对话框；窗控条（10050）恒在其上。 */
.cosmic-backdrop.fixed.view-layer {
  z-index: var(--z-view-overlay, 900);
}
@keyframes cb-fade-in {
  from { opacity: 0; }
  to { opacity: 1; }
}

/* ===== 动态星云背景层 ===== */
.cosmic-bg {
  position: absolute;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
}
.cb-nebula {
  position: absolute;
  border-radius: 50%;
  background: center / 100% 100% no-repeat;
  mix-blend-mode: screen;
  will-change: transform, opacity;
}
.cb-nebula-1 {
  width: 460px; height: 460px;
  top: -100px; left: -80px;
  background-image: var(--tex-cb-1);
  animation: cb-drift-1 34s ease-in-out infinite;
}
.cb-nebula-2 {
  width: 400px; height: 400px;
  bottom: -80px; right: -60px;
  background-image: var(--tex-cb-2);
  animation: cb-drift-2 41s ease-in-out infinite;
}
.cb-nebula-3 {
  width: 320px; height: 320px;
  top: 38%; left: 42%;
  background-image: var(--tex-cb-3);
  animation: cb-drift-3 49s ease-in-out infinite;
}
.cb-nebula-4 {
  width: 260px; height: 260px;
  top: 10%; right: 12%;
  background-image: var(--tex-cb-4);
  animation: cb-drift-4 57s ease-in-out infinite;
}
/* 非对称多相位漂移（0%=100% 周期边界连续；峰值错位 38%/64% 等 —
 * 拒绝 0/50/100 对称模板；四块相位结构各异 → 全场永无同步呼吸） */
@keyframes cb-drift-1 {
  0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.5; }
  38% { transform: translate(26px, 14px) scale(1.09); opacity: 0.82; }
  64% { transform: translate(40px, 25px) scale(1.12); opacity: 0.66; }
}
@keyframes cb-drift-2 {
  0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.42; }
  29% { transform: translate(-32px, -18px) scale(1.13); opacity: 0.72; }
  71% { transform: translate(-50px, -25px) scale(1.15); opacity: 0.58; }
}
@keyframes cb-drift-3 {
  0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.3; }
  44% { transform: translate(18px, -28px) scale(1.16); opacity: 0.55; }
  78% { transform: translate(25px, -35px) scale(1.18); opacity: 0.44; }
}
@keyframes cb-drift-4 {
  0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.24; }
  33% { transform: translate(-22px, 30px) scale(1.17); opacity: 0.48; }
  69% { transform: translate(-30px, 40px) scale(1.2); opacity: 0.38; }
}

/* 闪烁星点 — 复合谐波闪烁（多相位非等距：主峰+次峰+回摆，
 * 拒绝 0/50/100 对称缩放模板）；纯暗点无辉光 shadow */
.cb-stars { position: absolute; inset: 0; }
.cb-star {
  position: absolute;
  border-radius: 50%;
  animation: cb-twinkle 4s ease-in-out infinite;
}
@keyframes cb-twinkle {
  0%, 100% { opacity: 0.14; transform: scale(0.86); }
  18% { opacity: 0.52; }
  42% { opacity: 0.92; transform: scale(1.16); }
  61% { opacity: 0.5; transform: scale(1.0); }
  83% { opacity: 0.74; transform: scale(1.1); }
}

/* 流星划过 — 双流星全参数差化：
 * ① -31° 陡降长弧（水平 112vw / 垂直 47vh）② -16° 缓降扁弧（水平 108vw
 * / 垂直 18vh）；轨迹矢量非等比 → 弧度感各异；周期/延迟/长度全异。
 * 飞行采用非对称关键帧（加速段 0-12% 短、巡航 12-46%、尾段消隐）—
 * 拒绝匀速 ease-in 模板 */
.cb-meteor {
  position: absolute;
  height: 1px;
  opacity: 0;
  will-change: transform, opacity;
  /* 头亮尾隐（左尾右头 — 向右飞行） */
  background: linear-gradient(90deg, transparent, rgba(205, 224, 244, 0.85));
}
.cb-meteor-1 {
  top: 12%; left: -12%;
  width: 92px;
  animation: cb-meteor-fly-1 9.5s cubic-bezier(0.32, 0.09, 0.68, 0.16) 2.6s infinite;
}
.cb-meteor-2 {
  top: 63%; left: -8%;
  width: 64px;
  animation: cb-meteor-fly-2 13s cubic-bezier(0.4, 0.06, 0.62, 0.2) 7.2s infinite;
}
@keyframes cb-meteor-fly-1 {
  0% { transform: translate(0, 0) rotate(-31deg); opacity: 0; }
  5% { opacity: 0.9; }
  12% { transform: translate(13vw, 5.4vw) rotate(-31deg); opacity: 1; }
  46% { opacity: 0.85; }
  74%, 100% { transform: translate(112vw, 47vh) rotate(-31deg); opacity: 0; }
}
@keyframes cb-meteor-fly-2 {
  0% { transform: translate(0, 0) rotate(-16deg); opacity: 0; }
  4% { opacity: 0.75; }
  15% { transform: translate(16vw, 4vw) rotate(-16deg); opacity: 0.85; }
  52% { opacity: 0.6; }
  80%, 100% { transform: translate(108vw, 18vh) rotate(-16deg); opacity: 0; }
}
</style>
