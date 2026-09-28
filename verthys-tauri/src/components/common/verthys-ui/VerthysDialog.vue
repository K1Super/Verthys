<!--
  VerthysDialog.vue — 模块对话框外壳（各模块共享）
  用法:
    <VerthysDialog v-model="showDialog" :title="editing ? '编辑' : '新增'" @save="onSave">
      <template #default>…表单字段…</template>
      <template #error>…</template>
    </VerthysDialog>

  可编排能力（不启用时保持上述默认形态）：
    - #header 插槽：以模块自定义头部替换默认标题行
    - layout="plain"：内容不再套用双列网格，由调用方自行组织排版
    - class/style 等 attrs 透传至面板（.dialog），供模块定制皮肤
-->
<template>
  <div v-if="modelValue" class="dialog-overlay" @click.self="$emit('update:modelValue', false)">
    <div
      v-bind="$attrs"
      class="dialog glass"
      role="dialog"
      aria-modal="true"
      :aria-label="title || undefined"
      :style="width ? { minWidth: width, maxWidth: width } : undefined"
    >
      <slot name="header">
        <div class="dialog-title">{{ title }}</div>
      </slot>
      <div v-if="layout === 'grid'" class="form-grid">
        <slot />
      </div>
      <slot v-else />
      <slot name="error" />
      <div class="dialog-actions">
        <button class="btn kv-cancel" @click="$emit('update:modelValue', false)" :disabled="saving">取消</button>
        <button class="btn btn-primary kv-confirm" @click="$emit('save')" :disabled="saveDisabled || saving">
          {{ saving ? savingLabel : (saveLabel || '保存') }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
/* attrs 透传交由模板内 v-bind 控制：class/style 等落到面板而非遮罩层，
 * 使模块皮肤定制与遮罩行为解耦 */
defineOptions({ inheritAttrs: false });

withDefaults(defineProps<{
  modelValue: boolean;
  /** 默认标题行文案；提供 #header 插槽时由插槽内容取代 */
  title?: string;
  saveDisabled?: boolean;
  saving?: boolean;
  saveLabel?: string;
  /** 对话框宽度（如 "420px"），不传则使用默认 min-width: 460px */
  width?: string;
  /** 内容容器布局：grid = 双列网格（默认）；plain = 不套用容器，调用方自组排版 */
  layout?: "grid" | "plain";
  /** 处理中确认按钮文案（默认「保存中…」；语义窗口可覆写，如「修改中…」「验证中…」） */
  savingLabel?: string;
}>(), {
  layout: "grid",
  savingLabel: "保存中…",
});

defineEmits<{
  (e: "update:modelValue", val: boolean): void;
  (e: "save"): void;
}>();
</script>

<style scoped>
.dialog-overlay {
  position: fixed; inset: 0;
  background: rgba(0, 0, 0, 0.74);
  display: flex; align-items: center; justify-content: center;
  z-index: 1000;
}
.dialog {
  padding: 28px; min-width: 460px; max-width: 90vw; max-height: 85vh; overflow-y: auto;
  animation: dialog-in 0.4s var(--ease);
}
.dialog-title {
  font-size: 14px; margin-bottom: 20px;
  color: var(--accent); letter-spacing: 2px; font-family: var(--font);
}
.form-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 12px;
}
.dialog-actions {
  display: flex; justify-content: flex-end; gap: 10px;
  margin-top: 20px; padding-top: 14px; border-top: 1px solid var(--border-glass);
}

@keyframes dialog-in {
  from { opacity: 0; transform: scale(0.95); }
  to { opacity: 1; transform: scale(1); }
}
</style>