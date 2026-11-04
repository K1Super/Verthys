<!--
  RecoveryUnlockDialog.vue — 使用一次性恢复码解锁

  恢复码只在本次提交中传递，关闭/提交后由组件清零；不写本地存储。
  外壳复用 CosmicOverlay 统一光学底板；内容为灾难恢复的单据式录入。
-->
<template>
  <CosmicOverlay
    :show="show"
    width="520px"
    aria-label="使用恢复码解锁"
    teleport
    :overlay-z="10000"
    @close="requestClose"
  >
    <div class="ru-head">
      <div class="kv-title">使用恢复码解锁</div>
      <div class="ru-coord">
        <span class="ru-mark" aria-hidden="true"></span>
        灾难恢复 · 一次性凭证
      </div>
    </div>

    <label class="ru-label" for="ru-code">恢复码</label>
    <div class="ru-field">
      <input
        id="ru-code"
        v-model="code"
        class="kv-input ru-input"
        :type="visible ? 'text' : 'password'"
        autocomplete="off"
        spellcheck="false"
        aria-label="恢复码"
        :disabled="submitting"
        @keydown.enter="submit"
      />
      <button
        type="button"
        class="ru-eye"
        :disabled="submitting"
        :aria-label="visible ? '隐藏恢复码' : '显示恢复码'"
        :aria-pressed="visible"
        @click="visible = !visible"
      >
        <svg v-if="!visible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
      </button>
    </div>

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
        {{ submitting ? "解锁中…" : "解锁" }}
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";

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
/** 恢复码默认密文显示；关闭或提交即收回明文 */
const visible = ref(false);

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
    visible.value = false;
  },
);

/* 提交在途即收回明文：密文显示不随提交按钮状态停留 */
watch(
  () => props.submitting,
  (submitting) => {
    if (submitting) visible.value = false;
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
.ru-head {
  margin-bottom: 18px;
}
.ru-head .kv-title {
  margin-bottom: 6px;
}
.ru-coord {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 10px;
  letter-spacing: 0.2em;
  color: var(--text-muted);
}
.ru-mark {
  width: 5px;
  height: 5px;
  transform: rotate(45deg);
  background: rgba(0, 212, 255, 0.5);
}
.ru-label {
  display: block;
  margin-bottom: 8px;
  font-size: 10px;
  letter-spacing: 0.22em;
  color: var(--text-muted);
}
/* 密码框：无框凹槽，显隐端子内嵌于右内距，不挤占输入文本 */
.ru-field {
  position: relative;
  border-radius: 8px;
  --kv-input-pad-right: 38px;
}
.ru-input {
  width: 100%;
  letter-spacing: 0.08em;
  font-size: 13px;
}
.ru-input:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
/* 显隐端子：图标即控件，零底板、零阴影，仅以色彩应答 */
.ru-eye {
  position: absolute;
  top: 50%;
  right: 6px;
  transform: translateY(-50%);
  z-index: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease);
}
.ru-eye:not(:disabled):hover {
  color: var(--accent);
}
.ru-eye:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: 1px;
}
.ru-eye:disabled {
  cursor: not-allowed;
  opacity: 0.4;
}
.ru-eye svg {
  width: 14px;
  height: 14px;
}
.ru-error {
  margin: 10px 0 0;
  font-size: 11px;
  line-height: 1.5;
  color: var(--danger);
}
</style>
