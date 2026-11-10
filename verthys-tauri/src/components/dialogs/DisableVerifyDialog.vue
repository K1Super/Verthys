<!--
  DisableVerifyDialog.vue — 关闭密钥保护验证弹窗

  职责：
    1. 弹窗标题含模块名拼接（关闭「xxx」密钥保护）
    2. 提示文案（关闭后模块解除密钥访问限制，操作需核验独立密钥）
    3. 模块独立密钥输入框（disableVerifyKey，v-model 双向绑定）
    4. 确认关闭按钮（禁用条件：disableVerifyKey 为空 / 处理中）
-->
<template>
  <CosmicOverlay :show="show" width="440px" :backdrop-close="!disableVerifyProcessing" @close="$emit('close')">
    <div class="kv-title">关闭「{{ moduleLabel }}」密钥保护</div>
    <div class="kv-desc">关闭后模块解除密钥访问限制，操作需核验模块独立密钥</div>
    <div class="kd-old-key-row">
      <div class="kd-old-key-label">模块独立密钥</div>
      <input
        class="kv-input"
        v-model="disableVerifyKey"
        type="password"
        placeholder="请输入模块独立密钥以确认关闭"
        @keydown.enter="$emit('confirm')"
      />
    </div>
    <div class="kv-actions">
      <button class="btn kv-cancel" @click="$emit('close')" :disabled="disableVerifyProcessing">取消</button>
      <button class="btn btn-primary kv-confirm" @click="$emit('confirm')" :disabled="!disableVerifyKey || disableVerifyProcessing">
        {{ disableVerifyProcessing ? '验证中…' : '确认关闭' }}
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";

/**
 * DisableVerifyDialog Props
 */
defineProps<{
  /** 弹窗显示状态 */
  show: boolean;
  /** 当前操作的模块显示名称（moduleLabels[disableVerifyModuleId]） */
  moduleLabel: string;
  /** 关闭验证处理中状态 */
  disableVerifyProcessing: boolean;
}>();

/**
 * DisableVerifyDialog Model（模块独立密钥双向绑定）
 */
const disableVerifyKey = defineModel<string>("disableVerifyKey", { default: "" });

/**
 * DisableVerifyDialog Emits
 */
defineEmits<{
  /** 关闭弹窗（取消或点击遮罩） */
  (e: "close"): void;
  /** 确认关闭（验证模块独立密钥） */
  (e: "confirm"): void;
}>();
</script>
