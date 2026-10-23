<!--
  UpdaterAvailableDialog — 更新说明与强制更新入口

  非强制更新可稍后处理；强制更新窗口不可用 Esc / 遮罩关闭，只能安装或在失败后
  重试。说明正文保持纯文本与原始换行，不在界面渲染任何富文本或外部链接。
-->
<template>
  <VerthysDialog
    v-model="open"
    title="发现新版本"
    layout="plain"
    hide-actions
    :persistent="forceUpdate"
    width="520px"
  >
    <div class="update-body">
      <div class="update-line">
        <span class="update-caption">版本</span>
        <span class="update-version">{{ currentVersion }} → {{ version }}</span>
        <span v-if="forceUpdate" class="update-required">必须安装</span>
      </div>

      <div class="update-notes">
        <p v-if="notes.trim()">{{ notes }}</p>
        <p v-else class="update-empty">本次更新未提供说明。</p>
      </div>

      <p v-if="installing" class="update-state">
        {{ percent > 0 ? `正在下载并校验，${percent}%` : "正在准备更新…" }}
      </p>
      <p v-if="errorMessage" class="update-error">{{ errorMessage }}</p>

      <div class="update-actions">
        <button v-if="!forceUpdate" class="btn kv-cancel" type="button" @click="open = false">
          稍后
        </button>
        <button class="btn" type="button" @click="$emit('export')">导出日志</button>
        <button v-if="cancellable" class="btn" type="button" @click="$emit('cancel')">
          取消更新
        </button>
        <button
          v-else
          class="btn btn-primary"
          type="button"
          :disabled="installing"
          @click="$emit('install')"
        >
          {{ installing ? "正在更新…" : "安装更新" }}
        </button>
      </div>
    </div>
  </VerthysDialog>
</template>

<script setup lang="ts">
import { computed } from "vue";
import VerthysDialog from "../common/verthys-ui/VerthysDialog.vue";

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
  (e: "export"): void;
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
.update-body {
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-width: 440px;
}

.update-line {
  display: flex;
  align-items: baseline;
  gap: 10px;
  border-bottom: 1px solid var(--border);
  padding-bottom: 10px;
}

.update-caption {
  color: var(--text-secondary);
  font-size: 12px;
}

.update-version {
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: 14px;
  letter-spacing: 0.02em;
}

.update-required {
  color: var(--danger);
  font-size: 12px;
  letter-spacing: 0.08em;
}

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

.update-notes .update-empty {
  color: var(--text-secondary);
}

.update-state {
  margin: 0;
  color: var(--text-secondary);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}

.update-error {
  margin: 0;
  color: var(--danger);
  font-size: 12px;
  line-height: 1.7;
}

.update-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

.update-actions .btn {
  box-shadow: none;
}
</style>
