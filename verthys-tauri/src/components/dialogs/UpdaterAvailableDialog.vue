<!--
  UpdaterAvailableDialog — 更新说明与强制更新入口

  非强制更新可稍后处理；强制更新窗口不可用 Esc / 遮罩关闭，只能安装或在失败后
  重试。说明正文保持纯文本与原始换行，不在界面渲染任何富文本或外部链接。
-->
<template>
  <CosmicOverlay
    :show="open"
    width="520px"
    :persistent="forceUpdate"
    aria-labelledby="upd-title"
    @close="open = false"
  >
    <div class="kv-title" id="upd-title">发现新版本</div>

    <div class="kv-row update-version-row">
      <span class="kv-row-label">版本</span>
      <span class="kv-row-value">{{ currentVersion }} → {{ version }}</span>
      <span v-if="forceUpdate" class="kv-error update-required">必须安装</span>
    </div>

    <div class="update-notes">
      <p v-if="notes.trim()">{{ notes }}</p>
      <p v-else class="kv-note">本次更新未提供说明</p>
    </div>

    <p v-if="installing" class="kv-note update-state">
      {{ percent > 0 ? `正在下载并校验，${percent}%` : "正在准备更新…" }}
    </p>
    <p v-if="errorMessage" class="kv-error">{{ errorMessage }}</p>

    <div class="kv-actions">
      <button v-if="!forceUpdate" class="btn kv-cancel" type="button" @click="open = false">
        稍后
      </button>
      <button v-if="cancellable" class="btn" type="button" @click="$emit('cancel')">
        取消更新
      </button>
      <button
        v-else
        class="btn btn-primary kv-confirm"
        type="button"
        :disabled="installing"
        @click="$emit('install')"
      >
        {{ installing ? "正在更新…" : "安装更新" }}
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { computed } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";

const props = defineProps<{
  modelValue: boolean;
  /** 当前运行版本 */
  currentVersion: string;
  /** 可用目标版本 */
  version: string;
  /** 发布说明纯文本 */
  notes: string;
  /** 清单声明必须安装 */
  forceUpdate: boolean;
  /** 下载或安装进行中 */
  installing: boolean;
  /** 下载进度百分比 */
  percent: number;
  /** 当前阶段允许取消 */
  cancellable: boolean;
  /** 已映射的用户文案；空串表示无错误 */
  errorMessage: string;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", value: boolean): void;
  (e: "install"): void;
  (e: "cancel"): void;
}>();

const open = computed({
  get: () => props.modelValue,
  set: (value: boolean) => {
    // 强制更新窗口不接受外部关闭信号，避免业务层误置 false 绕过约束。
    if (!value && props.forceUpdate) return;
    emit("update:modelValue", value);
  },
});
</script>

<style scoped>
.update-version-row {
  margin-bottom: 14px;
}

.update-required {
  margin: 0;
  letter-spacing: 0.08em;
}

/* 发布说明：保留原始换行；滚动收敛在说明区，不挤压动作区 */
.update-notes {
  max-height: 220px;
  overflow-y: auto;
  padding-right: 6px;
}

.update-notes p {
  margin: 0;
  color: var(--text-primary);
  font-size: 13px;
  line-height: 1.8;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.update-state {
  margin-top: 12px;
  font-variant-numeric: tabular-nums;
}

.update-state + .kv-error {
  margin-top: 8px;
}

.update-notes + .update-state {
  margin-top: 12px;
}
</style>
