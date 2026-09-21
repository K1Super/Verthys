<!--
  VerthysDialog.vue — 模块对话框外壳（复用组件）
  提取自 AccountVerthys / CertManager 的共享对话框结构
  用法:
    <VerthysDialog v-model="showDialog" :title="editing ? '编辑' : '新增'" @save="onSave">
      <template #default>…表单字段…</template>
      <template #error>…</template>
    </VerthysDialog>
-->
<template>
  <div v-if="modelValue" class="dialog-overlay" @click.self="$emit('update:modelValue', false)">
    <div class="dialog glass" :style="width ? { minWidth: width, maxWidth: width } : undefined">
      <div class="dialog-title">{{ title }}</div>
      <div class="form-grid">
        <slot />
      </div>
      <slot name="error" />
      <div class="dialog-actions">
        <button class="btn" @click="$emit('update:modelValue', false)" :disabled="saving">取消</button>
        <button class="btn btn-primary" @click="$emit('save')" :disabled="saveDisabled || saving">
          {{ saving ? '保存中…' : (saveLabel || '保存') }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  modelValue: boolean;
  title: string;
  saveDisabled?: boolean;
  saving?: boolean;
  saveLabel?: string;
  /** 对话框宽度（如 "420px"），不传则使用默认 min-width: 460px */
  width?: string;
}>();

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
