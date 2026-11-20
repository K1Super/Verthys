<!--
  ProgressStatusLine.vue — 导入/导出进度状态行（全局复用）

  职责：统一呈现“阶段标签 · 四边形环 · 当前/总数”。
  约束：只做展示；阶段语义与计数由调用方状态提供。
        无总数时只显示标签，不渲染四边形环与计数。
-->
<template>
  <span class="psl">
    <span class="psl-label" :class="{ 'psl-label--counted': showCount }">{{ label }}</span>
    <template v-if="showCount">
      <span class="psl-separator" aria-hidden="true"></span>
      <span class="psl-count">
        <span class="psl-current">{{ safeCurrent }}</span>
        <span class="psl-slash">/</span>
        <span class="psl-total">{{ total }}</span>
      </span>
    </template>
  </span>
</template>

<script setup lang="ts">
import { computed } from "vue";

interface Props {
  /** 阶段语义（如“正在导入”“正在导出”） */
  label: string;
  /** 当前序号；仅在 total > 0 时展示 */
  current?: number;
  /** 总数；为 0 时隐藏计数区 */
  total?: number;
}

const props = withDefaults(defineProps<Props>(), {
  current: 0,
  total: 0,
});

const showCount = computed(() => props.total > 0);
/** 上限收敛：进度回调可能短暂越过总数，展示层不得出现 101/100 */
const safeCurrent = computed(() =>
  Math.min(Math.max(props.current, 0), props.total),
);
</script>

<style scoped>
/* 行内排版：标签与计数共享文字基线；四边形按光学中心单独校正 */
.psl {
  display: inline-block;
  line-height: 1;
  white-space: nowrap;
  text-shadow: none;
}
.psl-label {
  font-family: var(--font);
  font-size: 10px;
  letter-spacing: 0.22em;
  color: rgba(200, 226, 244, 0.52);
}
.psl-label--counted {
  margin-right: -0.22em; /* 抵消末字字距，使四边形两侧留白一致 */
}
.psl-separator {
  display: inline-grid;
  place-items: center;
  vertical-align: middle;
  width: 9px;
  height: 9px;
  margin: 0 10px;
  transform: translateY(-1px); /* 字面中心低于文字光学中心 */
}
.psl-separator::before {
  content: "";
  grid-area: 1 / 1;
  width: 9px;
  height: 9px;
  border: 1px solid rgba(0, 212, 255, 0.2);
  border-top-color: rgba(150, 238, 255, 0.55);
  transform: rotate(45deg);
  animation: psl-orbit 14s linear infinite;
}
.psl-count {
  display: inline-flex;
  align-items: baseline;
  gap: 4px;
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  line-height: 1;
}
.psl-current {
  font-size: 10px;
  color: rgba(238, 248, 255, 0.94);
}
.psl-slash {
  font-size: 10px;
  color: rgba(150, 180, 210, 0.3);
}
.psl-total {
  font-size: 10px;
  letter-spacing: 0.06em;
  color: rgba(190, 214, 234, 0.48);
}
@keyframes psl-orbit {
  from { transform: rotate(45deg); }
  to { transform: rotate(405deg); }
}
@media (prefers-reduced-motion: reduce) {
  .psl-separator::before { animation: none; }
}
</style>
