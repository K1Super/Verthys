<!--
  ClipToast.vue — 安全复制倒计时提示（复用组件）
  配合 useClipToast composable 使用
  用法: <ClipToast :countdown="clipCountdown" text="已复制" />
-->
<template>
  <transition name="toast">
    <div v-if="countdown > 0" class="clip-toast glass">
      <span class="toast-dot"></span>
      {{ text }} · {{ countdown }}s 后自动清空
    </div>
  </transition>
</template>

<script setup lang="ts">
defineProps<{
  countdown: number;
  text?: string;
}>();
</script>

<style scoped>
.toast-enter-active, .toast-leave-active { transition: opacity 0.3s, transform 0.3s; }
.toast-enter-from, .toast-leave-to { opacity: 0; transform: translateX(-50%) translateY(10px); }
</style>
