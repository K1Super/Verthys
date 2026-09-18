<!--
  CosmicLoading.vue — 通用非阻塞加载组件
  无底板、整体页面居中展示的旋转加载环 + 加载提示文字
  非阻塞（pointer-events: none），加载完成后自动消失
-->
<template>
  <transition name="cosmic-loading-fade">
    <div v-if="show" class="cosmic-loading">
      <div class="cl-orbit">
        <div class="cl-core"></div>
        <div class="cl-satellite"></div>
        <div class="cl-satellite cl-satellite-2"></div>
      </div>
      <div v-if="text" class="cl-text">{{ text }}</div>
    </div>
  </transition>
</template>

<script setup lang="ts">
/**
 * Props:
 *   show — 是否显示
 *   text — 加载提示文字（可选，不传则只显示动画）
 */
defineProps<{
  show: boolean;
  text?: string;
}>();
</script>

<style scoped>
/* ===== 无底板、居中展示的非阻塞加载层（相对于模块容器定位） =====
 * 轨道绝对居中（top: 50%），文字在轨道下方独立定位
 * 确保轨道位置与 CosmicEmpty 完全一致，消除加载→空态切换时的位置偏移
 */
.cosmic-loading {
  position: absolute;
  inset: 0;
  z-index: 9999;
  pointer-events: none;
}

/* 旋转轨道容器：绝对居中，位置固定不受文字高度影响 */
.cl-orbit {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 64px;
  height: 64px;
}

/* 中心脉冲球体（径向渐变 + 呼吸动画） */
.cl-core {
  position: absolute;
  inset: 16px;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(0, 212, 255, 0.95) 0%, rgba(139, 92, 246, 0.65) 100%);
  box-shadow:
    0 0 24px rgba(0, 212, 255, 0.5),
    0 0 48px rgba(139, 92, 246, 0.25);
  animation: cl-pulse 1.8s ease-in-out infinite;
}

/* 外层旋转环（主） */
.cl-satellite {
  position: absolute;
  inset: 0;
  border-radius: 50%;
  border: 2px solid transparent;
  border-top-color: rgba(0, 212, 255, 0.95);
  border-right-color: rgba(139, 92, 246, 0.45);
  animation: cl-spin 1.1s linear infinite;
}

/* 内层旋转环（副，反向，紫色点缀）——在主环内部，不向外溢出 */
.cl-satellite-2 {
  inset: 6px;
  border: 1px solid transparent;
  border-bottom-color: rgba(139, 92, 246, 0.5);
  border-left-color: rgba(0, 212, 255, 0.25);
  animation: cl-spin-reverse 1.6s linear infinite;
}

/* 加载提示文字：定位在轨道下方，不参与轨道定位 */
.cl-text {
  position: absolute;
  top: calc(50% + 32px + 14px);
  left: 50%;
  transform: translateX(-50%);
  font-size: 12px;
  color: var(--text-muted);
  letter-spacing: 1.5px;
  white-space: nowrap;
  font-family: var(--font);
  text-transform: uppercase;
  animation: cl-text-blink 2s ease-in-out infinite;
}

/* 动画定义 */
@keyframes cl-pulse {
  0%, 100% { transform: scale(0.82); opacity: 0.7; }
  50% { transform: scale(1.12); opacity: 1; }
}
@keyframes cl-spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
@keyframes cl-spin-reverse {
  from { transform: rotate(360deg); }
  to { transform: rotate(0deg); }
}
@keyframes cl-text-blink {
  0%, 100% { opacity: 0.55; }
  50% { opacity: 1; }
}

/* 淡入淡出过渡 */
.cosmic-loading-fade-enter-active,
.cosmic-loading-fade-leave-active {
  transition: opacity 0.4s var(--ease, ease), transform 0.4s var(--ease, ease);
}
.cosmic-loading-fade-enter-from,
.cosmic-loading-fade-leave-to {
  opacity: 0;
  transform: scale(0.92);
}
</style>
