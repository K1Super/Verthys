<!--
  RecoveryUnlockDialog.vue — 使用一次性恢复码解锁

  恢复码只在本次提交中传递，关闭/提交后由组件清零；不写本地存储。
  输入场与模块密钥登录共用 VerifyInputField：验证态周缘星流光轨、
  禁用态应答、失败底缘红线与抖动均为同源实现；弹窗宽度同源。
-->
<template>
  <CosmicOverlay
    :show="show"
    :width="VERIFY_DIALOG_WIDTH"
    aria-label="使用恢复码解锁"
    teleport
    :overlay-z="10000"
    @close="requestClose"
  >
    <div class="kv-title">使用恢复码解锁</div>
    <div class="kv-desc">
      灾难恢复 · 请输入一次性恢复码以重新建立本机会话
    </div>

    <VerifyInputField
      v-model="code"
      :verifying="submitting"
      :error="!!error"
      :active="show"
      label="恢复码"
      placeholder="恢复码"
      @submit="submit"
    />

    <p v-if="error" class="ru-error">{{ error }}</p>

    <div class="kv-actions">
      <button class="btn kv-cancel" type="button" :disabled="submitting" @click="requestClose">
        取消
      </button>
      <button
        class="btn btn-primary kv-confirm"
        type="button"
        :disabled="submitting || code.trim().length < 16"
        @click="submit"
      >
        解锁
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";
import VerifyInputField from "../common/form/VerifyInputField.vue";
import { VERIFY_DIALOG_WIDTH } from "../common/form/verify-dialog";

const props = defineProps<{
  show: boolean;
  submitting: boolean;
  error?: string;
}>();

const emit = defineEmits<{
  (e: "submit", code: string): void;
  (e: "close"): void;
}>();

const code = ref("");

/* 开发夹具填充：只在弹窗打开时写入，不提交；发布构建整段剔除。 */
if (import.meta.env.DEV) {
  const fixtureFillHandler = (event: Event) => {
    const detail = (event as CustomEvent<{
      target?: string;
      recoveryCode?: string;
    }>).detail;
    if (!detail || detail.target !== "recovery" || !props.show) return;
    if (detail.recoveryCode) code.value = detail.recoveryCode;
  };
  window.addEventListener("verthys:devfixture-fill", fixtureFillHandler);
  onBeforeUnmount(() => {
    window.removeEventListener("verthys:devfixture-fill", fixtureFillHandler);
  });
}

/* 打开与关闭都清空：关闭后恢复码不驻留组件状态，重新打开不残留上次输入。
 * 父组件在提交成功后置 show=false，该 watch 即触发清零。 */
watch(
  () => props.show,
  () => {
    code.value = "";
  },
);

const close = () => {
  code.value = "";
  emit("close");
};

const requestClose = () => {
  if (props.submitting) return;
  close();
};

const submit = () => {
  const value = code.value.trim();
  if (value.length < 16) return;
  emit("submit", value);
};
</script>

<style scoped>
.ru-error {
  margin: 10px 0 0;
  font-size: 11px;
  line-height: 1.5;
  color: var(--danger);
}
</style>
