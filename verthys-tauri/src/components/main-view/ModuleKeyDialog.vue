<!--
  ModuleKeyDialog.vue — 模块密钥登录对话框
  从 MainView.vue 抽离，功能 100% 保留
-->
<template>
  <CosmicOverlay :show="show" width="380px" @close="$emit('close')">
    <div class="kv-title">模块密钥登录</div>
    <div class="kv-desc">
      {{ pendingModuleLabel }} · 请输入该模块的独立密钥以继续
    </div>
    <div v-if="!hasModuleKeyRecord" class="kv-warn">
      该模块尚未设置独立密钥，请先初始化
    </div>
    <!-- 验证态：密码框区域替换为进度条通道（非量子动画），原窗口内原位显示 -->
    <QuantumProgressFlow
      v-if="moduleKeyVerifying"
      :loading="moduleKeyVerifying"
      :percent="moduleKeyVerifyPercent"
      :message="moduleKeyVerifyMsg"
      :show-loader="false"
    />
    <!-- 非验证态：密码输入框 -->
    <input
      v-else
      class="kv-input"
      :class="{ 'kv-input-error': moduleKeyVerifyError }"
      :value="moduleKeyInput"
      @input="$emit('update:moduleKeyInput', ($event.target as HTMLInputElement).value)"
      type="password"
      placeholder="模块独立密钥"
      @keydown.enter="$emit('confirm')"
    />
    <div v-if="!moduleKeyVerifying" class="kv-actions">
      <button class="btn kv-cancel" @click="$emit('close')">取消</button>
      <button class="btn btn-primary kv-confirm" @click="$emit('confirm')" :disabled="!moduleKeyInput || moduleKeyVerifying">
        验证
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { defineAsyncComponent } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";

const QuantumProgressFlow = defineAsyncComponent(() => import("../common/cosmic/QuantumProgressFlow.vue"));

defineProps<{
  show: boolean;
  pendingModuleLabel: string;
  hasModuleKeyRecord: boolean;
  moduleKeyInput: string;
  moduleKeyVerifying: boolean;
  moduleKeyVerifyPercent: number;
  moduleKeyVerifyMsg: string;
  /** 感知：验证错误状态（触发密码框抖动 + 红色边框） */
  moduleKeyVerifyError: boolean;
}>();

defineEmits<{
  (e: "close"): void;
  (e: "confirm"): void;
  (e: "update:moduleKeyInput", value: string): void;
}>();
</script>

<style scoped>
/* 感知：密码框错误状态（红色边框 + 抖动动画）
 * 错误密码绝不放行，必须给用户明确的视觉反馈 */
.kv-input-error {
  border-color: rgba(255, 80, 100, 0.85) !important;
  box-shadow: 0 0 0 1px rgba(255, 80, 100, 0.45),
              0 0 12px rgba(255, 80, 100, 0.35) !important;
  animation: kv-error-shake 0.4s var(--ease);
}

@keyframes kv-error-shake {
  0%, 100% { transform: translateX(0); }
  20% { transform: translateX(-6px); }
  40% { transform: translateX(6px); }
  60% { transform: translateX(-4px); }
  80% { transform: translateX(4px); }
}
</style>
