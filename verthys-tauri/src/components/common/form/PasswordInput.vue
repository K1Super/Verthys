<!--
  PasswordInput.vue — 密码输入框（含显隐切换）
  来源：SecurityCenter.vue 原 template 中所有 pw-row 密码输入实例
  用途：初始化/验证视图的密码输入（访问密钥 / 密钥口令）
  显隐切换：纯图标（无文字），符合用户偏好
-->
<template>
  <div class="form-row">
    <label v-if="label" class="form-label">{{ label }}</label>
    <div class="pw-row">
      <input
        class="sc-input"
        :type="visible ? 'text' : 'password'"
        :value="modelValue"
        :placeholder="placeholder"
        :disabled="disabled"
        @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
        @keydown.enter="$emit('submit')"
      />
      <button
        class="pw-toggle"
        type="button"
        tabindex="-1"
        :disabled="disabled"
        @click="visible = !visible"
      >
        <svg v-if="!visible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
/**
 * 密码输入框
 * - v-model 双向绑定
 * - 显隐切换：纯图标（睁开/闭合眼睛），无文字
 * - Enter 键触发 submit 事件（父组件可选监听）
 * - label 缺省时不渲染 form-label（适配无标签场景）
 */
interface Props {
  modelValue: string;
  label?: string;
  placeholder?: string;
  disabled?: boolean;
}
withDefaults(defineProps<Props>(), {
  label: '',
  placeholder: '',
  disabled: false,
});
defineEmits<{
  'update:modelValue': [value: string];
  submit: [];
}>();
const visible = ref(false);
</script>

<style scoped>
@import '../../../styles/security/form-inputs.css';
</style>
