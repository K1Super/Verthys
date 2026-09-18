<!--
  ActionButton.vue — 通用可复用按钮组件
  复用全局 .btn 基础样式（与相册导出按钮一致），简洁不带渐变
  变体：default（默认）/ danger（红色）
  尺寸：sm（紧凑，复用 .import-btn 的 padding/font-size）
-->
<template>
  <button
    class="btn action-btn"
    :class="[`action-${variant}`, { 'is-loading': loading }]"
    :disabled="disabled || loading"
    @click="$emit('click', $event)"
  >
    <span v-if="loading" class="action-spinner"></span>
    <span v-else-if="showPlus" class="action-plus">+</span>
    <span class="action-label">
      <slot>{{ label }}</slot>
    </span>
  </button>
</template>

<script setup lang="ts">
interface Props {
  label?: string;
  variant?: "default" | "danger";
  disabled?: boolean;
  loading?: boolean;
  showPlus?: boolean;
}

withDefaults(defineProps<Props>(), {
  label: "",
  variant: "default",
  disabled: false,
  loading: false,
  showPlus: true,
});

defineEmits<{ (e: "click", ev: MouseEvent): void }>();
</script>

<style scoped>
/* 布局：与相册 .import-btn / .export-top-btn 一致 */
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
  box-shadow: 0 0 12px rgba(255, 46, 99, 0.1);
}

/* 加号图标 */
.action-plus {
  font-weight: 300;
  font-size: 14px;
  line-height: 1;
}

/* 加载指示器 */
.action-spinner {
  display: inline-block;
  width: 12px;
  height: 12px;
  border: 1.5px solid currentColor;
  border-top-color: transparent;
  border-radius: 50%;
  animation: action-spin 0.6s linear infinite;
}
@keyframes action-spin {
  to {
    transform: rotate(360deg);
  }
}

/* 加载状态时隐藏加号 */
.is-loading .action-plus {
  display: none;
}
</style>
