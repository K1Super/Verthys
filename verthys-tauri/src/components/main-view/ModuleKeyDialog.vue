<!--
  ModuleKeyDialog.vue — 模块密钥登录对话框

  验证态由 VerifyInputField 单源承载：输入框周缘星流光轨 + 禁用态应答 +
  失败底缘红线与抖动；本组件只负责模块语境的外壳、说明与动作。
-->
<template>
  <CosmicOverlay
    :show="show"
    :width="VERIFY_DIALOG_WIDTH"
    aria-label="模块密钥登录"
    @close="$emit('close')"
  >
    <div class="kv-title">模块密钥登录</div>
    <div class="kv-desc">
      {{ pendingModuleLabel }} · 请输入该模块的独立密钥以继续
    </div>
    <div v-if="!hasModuleKeyRecord" class="kv-warn">
      该模块尚未设置独立密钥，请先初始化
    </div>
    <VerifyInputField
      :model-value="moduleKeyInput"
      :verifying="moduleKeyVerifying"
      :error="moduleKeyVerifyError"
      :active="show"
      label="模块独立密钥"
      placeholder="模块独立密钥"
      @update:model-value="$emit('update:moduleKeyInput', $event)"
      @submit="$emit('confirm')"
    />
    <div class="kv-actions">
      <button class="btn kv-cancel" :disabled="moduleKeyVerifying" @click="$emit('close')">
        取消
      </button>
      <button
        class="btn btn-primary kv-confirm"
        @click="$emit('confirm')"
        :disabled="!moduleKeyInput || moduleKeyVerifying"
      >
        验证
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";
import VerifyInputField from "../common/form/VerifyInputField.vue";
import { VERIFY_DIALOG_WIDTH } from "../common/form/verify-dialog";

defineProps<{
  show: boolean;
  pendingModuleLabel: string;
  hasModuleKeyRecord: boolean;
  moduleKeyInput: string;
  moduleKeyVerifying: boolean;
  /** 感知：验证错误状态（触发密码框抖动 + 红色边框） */
  moduleKeyVerifyError: boolean;
}>();

defineEmits<{
  (e: "close"): void;
  (e: "confirm"): void;
  (e: "update:moduleKeyInput", value: string): void;
}>();
</script>
