<!--
  CosmicRingLoader.vue — 统一加载环（全应用唯一加载视觉）

  构造：conic 扫掠外环（拖尾彗尾光，环形掩膜成细环）+ 反向差速细内环 + 脉冲辉光核。
  全部动画仅 transform / opacity（GPU 合成），无滤镜、无布局抖动、无逐帧脚本。

  Props:
    show    — 是否显示（默认 true）
    text    — 文案（可选；不传则只渲染环）
    size    — 轨道直径（px，默认 64）。size ≤ 20 进入「迷你档」：
              仅渲染扫掠外环（内环/核心在极小尺寸下不可辨），色彩取 currentColor
    overlay — 是否以「容器级非阻塞覆盖层」呈现（默认 false）：
              true  = absolute inset:0 覆盖父容器，轨道绝对居中、文字在轨道下方
                      （与 CosmicEmpty 同一轨道定位契约，加载↔空态切换零偏移）
              false = 普通流内联居中列（加载环 + 文案）

  定位契约：overlay 模式下轨道中心恒为父容器 50%/50%，文字上沿为
    50% + size/2 + 14px —— 与 CosmicEmpty 的空态环完全同位，避免切换跳动。
-->
<template>
  <transition name="crl-fade">
    <div
      v-if="show"
      :class="overlay ? 'crl-overlay' : 'crl-inline'"
      :style="{ '--crl-size': size + 'px' }"
    >
      <span class="crl-orbit" :class="{ 'crl-orbit--mini': size <= 20 }" aria-hidden="true">
        <span class="crl-ring crl-ring--outer"></span>
        <span v-if="size > 20" class="crl-ring crl-ring--inner"></span>
        <span v-if="size > 20" class="crl-core"></span>
      </span>
      <span v-if="text" class="crl-text">{{ text }}</span>
    </div>
  </transition>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    /** 是否显示 */
    show?: boolean;
    /** 文案（可选） */
    text?: string;
    /** 轨道直径（px） */
    size?: number;
    /** 是否以容器级非阻塞覆盖层呈现 */
    overlay?: boolean;
  }>(),
  { show: true, text: "", size: 64, overlay: false },
);
</script>

<style scoped>
/* ===== 容器形态 ===== */
/* 内联：普通流居中列（加载环 + 可选文案） */
.crl-inline {
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  gap: 16px;
}
/* 覆盖层：容器级、非阻塞（pointer-events:none），不拦截任何交互 */
.crl-overlay {
  position: absolute;
  inset: 0;
  z-index: 9999;
  pointer-events: none;
}

/* ===== 轨道槽位（尺寸由 --crl-size 决定） ===== */
.crl-orbit {
  --crl-stroke: 2px;
  position: relative;
  display: block;
  width: var(--crl-size, 64px);
  height: var(--crl-size, 64px);
}
/* overlay 模式：绝对居中（与 CosmicEmpty 同位契约） */
.crl-overlay .crl-orbit {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}
/* 迷你档：细一档的环宽 */
.crl-orbit--mini {
  --crl-stroke: 1.5px;
}

.crl-ring {
  position: absolute;
  border-radius: 50%;
}

/* 外环：conic 扫掠 + 环形掩膜 → 拖尾彗尾光弧；缓入缓出旋转（非匀速机械感） */
.crl-ring--outer {
  inset: 0;
  /* 兼容回退（不支持 color-mix 时保留此声明）：纯 currentColor 硬边扫掠 */
  background: conic-gradient(from 0turn, transparent 0turn, currentColor 0.9turn, transparent 1turn);
  background: conic-gradient(
    from 0turn,
    rgba(0, 212, 255, 0) 0turn,
    rgba(0, 212, 255, 0.12) 0.34turn,
    rgba(0, 212, 255, 0.92) 0.9turn,
    rgba(0, 212, 255, 0) 1turn
  );
  -webkit-mask: radial-gradient(
    farthest-side,
    transparent calc(100% - var(--crl-stroke)),
    #000 calc(100% - var(--crl-stroke) * 0.75)
  );
  mask: radial-gradient(
    farthest-side,
    transparent calc(100% - var(--crl-stroke)),
    #000 calc(100% - var(--crl-stroke) * 0.75)
  );
  animation: crl-spin 1.05s cubic-bezier(0.62, 0.05, 0.36, 0.99) infinite;
}
/* 迷你档：色彩跟随 currentColor（按钮内指示器需随变体/危险色自适应） */
.crl-orbit--mini .crl-ring--outer {
  background: conic-gradient(from 0turn, transparent 0turn, currentColor 0.9turn, transparent 1turn);
  background: conic-gradient(
    from 0turn,
    color-mix(in srgb, currentColor 0%, transparent) 0turn,
    color-mix(in srgb, currentColor 18%, transparent) 0.34turn,
    color-mix(in srgb, currentColor 92%, transparent) 0.9turn,
    color-mix(in srgb, currentColor 0%, transparent) 1turn
  );
  animation-duration: 0.7s;
  animation-timing-function: linear;
}

/* 内环：反向细弧（紫调点缀），更慢 —— 与外环形成差速层次 */
.crl-ring--inner {
  inset: calc(var(--crl-size, 64px) * 0.094);
  border: 1.5px solid transparent;
  border-top-color: rgba(139, 92, 246, 0.7);
  border-left-color: rgba(139, 92, 246, 0.16);
  animation: crl-spin-rev 1.7s linear infinite;
}

/* 核心：径向渐变 + 柔和辉光 + 脉冲呼吸 */
.crl-core {
  position: absolute;
  inset: calc(var(--crl-size, 64px) * 0.25);
  border-radius: 50%;
  background: radial-gradient(circle, rgba(0, 212, 255, 0.95) 0%, rgba(0, 212, 255, 0.12) 72%, transparent 100%);
  box-shadow: 0 0 14px rgba(0, 212, 255, 0.42);
  animation: crl-pulse 1.7s ease-in-out infinite;
}

/* ===== 文案 ===== */
.crl-text {
  font-size: 12px;
  color: var(--text-muted);
  font-family: var(--font);
  letter-spacing: 1.5px;
  white-space: nowrap;
}
/* overlay 模式：文字在轨道下方独立定位（不参与轨道居中，与 CosmicEmpty 同位契约一致） */
.crl-overlay .crl-text {
  position: absolute;
  top: calc(50% + (var(--crl-size, 64px) / 2) + 14px);
  left: 50%;
  transform: translateX(-50%);
  animation: crl-text-blink 2s ease-in-out infinite;
}

/* ===== 动画 ===== */
@keyframes crl-spin {
  to { transform: rotate(1turn); }
}
@keyframes crl-spin-rev {
  to { transform: rotate(-1turn); }
}
@keyframes crl-pulse {
  0%, 100% { transform: scale(0.78); opacity: 0.62; }
  50% { transform: scale(1.08); opacity: 1; }
}
@keyframes crl-text-blink {
  0%, 100% { opacity: 0.55; }
  50% { opacity: 1; }
}

/* 淡入淡出（与旧加载层同款手感） */
.crl-fade-enter-active,
.crl-fade-leave-active {
  transition: opacity 0.4s var(--ease, ease), transform 0.4s var(--ease, ease);
}
.crl-fade-enter-from,
.crl-fade-leave-to {
  opacity: 0;
  transform: scale(0.92);
}

/* 尊重减弱动效偏好：停自转/脉冲/闪烁，保留静态环与核（仍可辨识加载态） */
@media (prefers-reduced-motion: reduce) {
  .crl-ring--outer,
  .crl-ring--inner,
  .crl-core,
  .crl-text {
    animation: none;
  }
  .crl-core {
    opacity: 0.85;
  }
}
</style>
