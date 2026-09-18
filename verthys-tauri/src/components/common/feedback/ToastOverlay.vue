<!--
  ToastOverlay.vue — 顶部错误提示弹窗
  通用组件：可复用于任意视图的"顶部红色错误提示"
  来源：SecurityCenter.vue L13-L18（零行为变更提取）
  样式：使用全局 .error-toast / .toast-dot / .err-toast-* （定义于 styles/components.css）
  实现：
    1. <Teleport to="body"> 直接附加到 body，避免受父容器样式影响
    2. transition name="err-toast" 入场/出场过渡（位移 + 透明度）
    3. z-index: 100000 避免被其他元素遮挡
    4. transform: translate(-50%, 0) 统一过渡函数类型
    5. 2.5 秒自动消失由父组件控制（保持 showError 行为不变）
  Props:
    - message: string          错误信息（为空时不显示）
  Emits: 无
  用法：<ToastOverlay :message="errorMsg" />
-->
<template>
  <Teleport to="body">
    <transition name="err-toast">
      <div v-if="message" class="error-toast glass">
        <span class="toast-dot"></span>
        {{ message }}
      </div>
    </transition>
  </Teleport>
</template>

<script setup lang="ts">
/**
 * ToastOverlay — 顶部错误提示弹窗通用组件
 * 职责：仅渲染错误弹窗 DOM 与过渡动画
 * 设计：纯展示组件，单向数据流；自动消失逻辑由父组件维护（保持原 showError 行为）
 * 约束：
 *   - 不输出错误的具体信息（优化初始化对话框错误提示）
 *   - 错误提示弹窗必须通过 <Teleport to="body"> 附加到 body
 *   - 错误提示弹窗 z-index 设置为 100000
 *   - transform 函数类型统一（translate(-50%, 0)），过渡动画加 !important 确保生效
 */
interface Props {
  /** 错误信息（为空时不显示弹窗） */
  message: string;
}

defineProps<Props>();
</script>

<style scoped>
/* ToastOverlay.vue 无需局部样式：
   .error-toast / .toast-dot / .err-toast-* 过渡动画均定义于全局 styles/components.css，
   通过 :global 引用以避免 scoped 隔离破坏全局样式匹配。 */
</style>
