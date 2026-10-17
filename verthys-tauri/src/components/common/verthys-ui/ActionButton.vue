<!--
  ActionButton.vue — 通用可复用按钮组件
  复用全局 .btn 基础样式（与相册导出按钮一致），简洁不带渐变
  变体：default（默认）/ danger（红色）
  尺寸：sm（紧凑，与相册顶部图标按钮同高 32px）
-->
<template>
  <button
    class="btn action-btn"
    :class="[primary ? 'btn-primary' : `action-${variant}`, { 'is-loading': loading, 'action-icon-only': !label && !$slots.default }]"
    :disabled="disabled || loading"
    @click="$emit('click', $event)"
  >
    <CosmicRingLoader v-if="loading" :size="12" />
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

withDefaults(defineProps<Props>(), {
  label: "",
  variant: "default",
  primary: false,
  disabled: false,
  loading: false,
  showPlus: true,
});

defineEmits<{ (e: "click", ev: MouseEvent): void }>();
</script>

<style scoped>
/* 布局：紧凑尺寸，与相册顶部图标按钮同高 32px */
.action-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 6px 12px;
  font-size: 11px;
  white-space: nowrap;
  user-select: none;
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
/* 纯图标按钮（无文案）：收紧横向内边距，使近方形、加号居中 */
.action-icon-only {
  padding: 6px 8px;
}

/* 加载状态时隐藏加号 */
.is-loading .action-plus {
  display: none;
}
</style>
