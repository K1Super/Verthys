<!--
  ActionButton.vue — 通用可复用按钮组件
  复用全局 .btn 基础样式（与相册导出按钮一致），简洁不带渐变
  变体：default（默认）/ danger（红色）
  尺寸：紧凑形态，几何由全局 .btn-icon 单源提供（正方形 32×32 + 图标口径）
  图标：默认加号；#icon 插槽可替换为其它图标（仍走同一套盒模型，
        与默认形态等高等宽口径一致，避免同一行按钮尺寸不齐）
-->
<template>
  <button
    type="button"
    class="btn action-btn"
    :class="[primary ? 'btn-primary' : `action-${variant}`, { 'is-loading': loading, 'btn-icon': iconOnly, 'action-labeled': !iconOnly }]"
    :disabled="disabled || loading"
    @click="$emit('click', $event)"
  >
    <CosmicRingLoader v-if="loading" :size="12" />
    <slot v-else-if="$slots.icon" name="icon" />
    <svg v-else-if="showPlus" class="action-plus" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
      <line x1="12" y1="5" x2="12" y2="19" />
      <line x1="5" y1="12" x2="19" y2="12" />
    </svg>
    <span v-if="label || $slots.default" class="action-label">
      <slot>{{ label }}</slot>
    </span>
  </button>
</template>

<script setup lang="ts">
import { computed, useSlots } from "vue";
import CosmicRingLoader from "../cosmic/CosmicRingLoader.vue";

interface Props {
  label?: string;
  variant?: "default" | "danger";
  /**
   * 采用主按钮皮肤：直接复用全局 .btn-primary（与各窗口「确认」按钮
   * 完全同一套样式：渐变面 + 势隙线三态呼吸，无白色幕布）。
   */
  primary?: boolean;
  disabled?: boolean;
  loading?: boolean;
  showPlus?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  label: "",
  variant: "default",
  primary: false,
  disabled: false,
  loading: false,
  showPlus: true,
});

defineEmits<{ (e: "click", ev: MouseEvent): void }>();

/** 纯图标形态：无文案且无默认插槽内容（方形键由全局 .btn-icon 定几何） */
const slots = useSlots();
const iconOnly = computed(() => !props.label && !slots.default);
</script>

<style scoped>
/* 布局：紧凑尺寸；盒模型内边距按形态分流 ——
   方形（纯图标）形态由全局 .btn-icon 提供几何，此处不得再声明，
   带文案形态（.action-labeled）才自带内边距与字号 */
.action-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
  user-select: none;
}
.action-labeled {
  padding: 6px 12px;
  font-size: 11px;
}

/* 变体：danger（红色，用于删除等危险操作） */
.action-danger {
  border-color: rgba(255, 46, 99, 0.15);
  color: var(--accent-red);
}
.action-danger:hover:not(:disabled) {
  background: rgba(255, 46, 99, 0.08);
  border-color: var(--accent-red);
}

/* 加号图标：SVG 描边十字 —— 几何精确、粗细可控，与全应用图标语言一致
   （替代此前的文本「+」，避免字体基线与字重差异导致的对不齐） */
.action-plus {
  width: 13px;
  height: 13px;
  flex-shrink: 0;
  display: block;
}
/* 纯图标按钮（无文案）：几何（正方形 + 图标口径）复用全局 .btn-icon，
   本组件不再自带尺寸声明，避免与其它复用方出现两处来源 */

/* 加载状态时隐藏加号 */
.is-loading .action-plus {
  display: none;
}
</style>
