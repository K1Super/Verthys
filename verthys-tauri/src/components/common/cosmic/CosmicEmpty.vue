<!--
  CosmicEmpty.vue — 通用空态组件
  与 CosmicLoading 视觉同源：静止的圆环 + 暗淡中心球体
  加载→旋转（CosmicLoading），空态→静止（CosmicEmpty），形成视觉呼应
  无底板、无灰色背景框，居中展示
-->
<template>
  <div class="cosmic-empty">
    <div class="ce-orbit">
      <div class="ce-core"></div>
      <div class="ce-ring"></div>
      <div class="ce-ring ce-ring-2"></div>
    </div>
    <div v-if="text" class="ce-text">{{ text }}</div>
    <div v-if="hint" class="ce-hint">{{ hint }}</div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  text?: string;
  hint?: string;
}>();
</script>

<style scoped>
/* ===== 无底板、居中展示的空态层（与 CosmicLoading 视觉同源） =====
 * 轨道绝对居中（top: 50%），文字/hint 在轨道下方独立定位
 * 确保轨道位置与 CosmicLoading 完全一致，消除加载→空态切换时的位置偏移
 */
.cosmic-empty {
  position: absolute;
  inset: 0;
  z-index: 1;
  pointer-events: none;
}

/* 静止圆环容器：绝对居中，位置固定不受文字/hint高度影响 */
.ce-orbit {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 64px;
  height: 64px;
}

/* 中心暗淡球体（不脉冲，表示无数据静止态） */
.ce-core {
  position: absolute;
  inset: 16px;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(0, 212, 255, 0.12) 0%, transparent 70%);
  opacity: 0.5;
}

/* 外圈静止环（不旋转，与加载动画的旋转环形成对比） */
.ce-ring {
  position: absolute;
  inset: 0;
  border: 1.5px solid rgba(0, 212, 255, 0.12);
  border-radius: 50%;
}

/* 内圈静止环（紫色点缀，与加载动画副环呼应） */
.ce-ring-2 {
  inset: 6px;
  border-color: rgba(139, 92, 246, 0.08);
}

/* 空态主文字：定位在轨道下方，不参与轨道定位 */
.ce-text {
  position: absolute;
  top: calc(50% + 32px + 12px);
  left: 50%;
  transform: translateX(-50%);
  font-size: 12px;
  color: var(--text-muted, #3d4452);
  letter-spacing: 2px;
  font-family: var(--font);
  white-space: nowrap;
}

/* 空态提示文字：定位在主文字下方 */
.ce-hint {
  position: absolute;
  top: calc(50% + 32px + 12px + 16px + 4px);
  left: 50%;
  transform: translateX(-50%);
  font-size: 11px;
  color: var(--text-muted, #3d4452);
  opacity: 0.5;
  letter-spacing: 1px;
  white-space: nowrap;
}
</style>
