<!--
  RecoveryCodeDialog.vue — 一次性恢复码展示与确认

  形态：复用 CosmicOverlay 光学切片底板，内容分三段 ——
        状态读数 / 恢复码读数 / 确认与动作。
  职责：展示新建或轮换产生的一次性恢复码，要求用户确认已存入离线介质。

  安全约束：
    1. 恢复码只在内存中展示，不写入 localStorage、日志或状态文件；
    2. 未勾选确认不得完成；未确认关闭需二次警告；
    3. 确认或关闭后由父组件清零。
-->
<template>
  <CosmicOverlay
    :show="show"
    width="560px"
    :backdrop-close="false"
    teleport
    :overlay-z="10000"
    aria-label="保存一次性恢复码"
    @close="onDialogToggle(false)"
  >
    <div class="kv-title">保存一次性恢复码</div>

    <!-- 状态读数：一次性凭据的唯一性以暖色读数直陈 -->
    <div class="rc-readout">
      <span class="rc-readout-mark" aria-hidden="true"></span>
      <span class="rc-readout-text">仅展示一次</span>
      <span class="rc-readout-rule" aria-hidden="true"></span>
    </div>

    <div class="kv-desc">
      恢复密钥是设备迁移与灾备恢复的唯一凭据，丢失不可恢复
    </div>

    <!-- 恢复码读数：单行文本框承载完整连续码，点击即复制 -->
    <div class="rc-code-label">Recovery Code · 恢复码</div>
    <div class="rc-code-field">
      <input
        class="kv-input rc-code-input"
        readonly
        :value="plainCode"
        aria-label="一次性恢复码，点击复制"
        @click="copyCode"
      />
      <button
        type="button"
        class="rc-copy-inline"
        aria-label="复制一次性恢复码"
        @click="copyCode"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      </button>
    </div>

    <label class="kf-toggle rc-check" :class="{ 'kf-toggle--on': acknowledged }">
      <input type="checkbox" v-model="acknowledged" />
      <span class="kf-box" aria-hidden="true"></span>
      <span class="kf-text">已将恢复密钥存储至离线介质，确认密钥丢失后不可恢复</span>
    </label>

    <p v-if="closeWarning" class="rc-feedback" role="alert">
      未勾选确认就关闭会永久丢失恢复码。再次点击「放弃并关闭」确认放弃。
    </p>

    <div class="kv-actions">
      <button class="btn kv-cancel" type="button" @click="onDialogToggle(false)">
        {{ closeWarning ? "放弃并关闭" : "取消" }}
      </button>
      <button
        class="btn btn-primary kv-confirm"
        type="button"
        :disabled="!acknowledged"
        @click="onConfirm"
      >
        完成
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";
import { useClipToast } from "../../composables/useClipToast";
import { useToastCenter } from "../../composables/useToastCenter";

const props = defineProps<{
  show: boolean;
  code: string;
}>();

const emit = defineEmits<{
  (e: "confirmed"): void;
  (e: "close"): void;
}>();

/** 展示与复制统一使用连续码：分组分隔符只服务输入校验，不进入读数 */
const plainCode = computed(() => props.code.replace(/[\s-]/g, "").toUpperCase());
const { copyWithTimeout } = useClipToast("恢复码已复制");
const { showError } = useToastCenter();

const copyCode = async () => {
  const written = await copyWithTimeout(plainCode.value);
  if (!written) showError("复制失败：剪贴板不可用");
};

const acknowledged = ref(false);
const closeWarning = ref(false);

const resetState = () => {
  acknowledged.value = false;
  closeWarning.value = false;
};

watch(
  () => [props.show, props.code] as const,
  ([visible]) => {
    if (visible) resetState();
  },
);

const onConfirm = () => {
  if (!acknowledged.value) return;
  emit("confirmed");
};

const onDialogToggle = (value: boolean) => {
  if (value) return;
  /* 取消按钮不承担确认语义：即使已勾选确认项，取消也必须走二次放弃，
   * 否则用户点取消会被静默当作已确认，与按钮文案冲突。 */
  if (!closeWarning.value) {
    closeWarning.value = true;
    return;
  }
  emit("close");
};
</script>

<style scoped>
/* ===== 状态读数 =====
 * 一次性语义只以暖色读数与细线收束，不另设警示盒。 */
.rc-readout {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}
.rc-readout-mark {
  flex: none;
  width: 5px;
  height: 5px;
  background: rgba(255, 184, 108, 0.88);
  transform: rotate(45deg);
}
.rc-readout-text {
  font-size: 11px;
  letter-spacing: 0.08em;
  color: rgba(255, 184, 108, 0.88);
  white-space: nowrap;
}
.rc-readout-rule {
  flex: 1;
  height: 1px;
  background: linear-gradient(
    90deg,
    rgba(205, 224, 244, 0.14),
    transparent 82%
  );
}

/* ===== 恢复码读数 =====
 * 单行文本框承载完整连续码：不换行，超宽时文本框内部横向滚动；
 * 读数、复制入口与整框点击都指向同一份连续码。 */
.rc-code-label {
  margin-bottom: 8px;
  font-size: 10px;
  letter-spacing: 0.3em;
  text-transform: uppercase;
  color: var(--text-muted);
}
.rc-code-field {
  position: relative;
  --kv-input-pad-right: 40px;
}
.rc-code-input {
  width: 100%;
  font-family: var(--font);
  font-size: 12px;
  letter-spacing: 0.02em;
  color: rgba(210, 236, 255, 0.95);
  white-space: nowrap;
  cursor: pointer;
}
.rc-copy-inline {
  position: absolute;
  right: 5px;
  top: 50%;
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
  transform: translateY(-50%);
  transition: color var(--dur-fast) var(--ease);
}
.rc-copy-inline:hover {
  color: var(--accent);
}
.rc-copy-inline:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: 1px;
}
.rc-copy-inline svg {
  width: 14px;
  height: 14px;
}

/* 确认项沿用全局 kf-toggle 指示格，仅修正为表单左对齐 */
.kf-toggle.rc-check {
  justify-content: flex-start;
  margin-top: 16px;
}

/* 关闭警示只以红字直陈，不加底色方框与图标 */
.rc-feedback {
  margin: 14px 0 0;
  font-size: 11.5px;
  line-height: 1.65;
  color: #ff9c9c;
}
</style>
