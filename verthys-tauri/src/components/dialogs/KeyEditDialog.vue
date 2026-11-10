<!--
  KeyEditDialog.vue — 密钥编辑弹窗（生成/修改模块独立密钥）

  职责：
    1. 弹窗标题动态切换（修改/生成）+ 模块名拼接
    2. 修改模式：验证原独立密钥（editingOldKeyValue，v-model 双向绑定）
    3. 新密钥输入框（内嵌显隐与随机生成端子，editingKeyValue，v-model 双向绑定）
    4. 确认保存按钮（禁用条件：editingKeyValue 为空 / 处理中 / 修改模式下原密钥为空）
-->
<template>
  <CosmicOverlay :show="show" width="460px" @close="$emit('close')">
    <div class="kv-title">{{ hasRecord ? '修改' : '生成' }}{{ moduleLabel }}独立密钥</div>
    <div class="kv-desc">
      {{ hasRecord
        ? '修改后旧密钥将立即失效，使用旧密钥加密的数据将无法解密'
        : '请输入自定义密钥' }}
    </div>
    <!-- 首次启用：默认绑定恢复槽，换机时可用恢复码 + 模块口令恢复该模块 -->
    <div v-if="!hasRecord" class="kd-recovery-row">
      <div class="kd-old-key-label">模块恢复码</div>
      <input
        class="kv-input"
        v-model="editingRecoveryCode"
        type="password"
        autocomplete="off"
        spellcheck="false"
        :disabled="skipRecoveryBinding"
        placeholder="粘贴当前容器的恢复码，换机时用于恢复本模块"
        aria-label="模块恢复码（当前容器的恢复码，用于绑定模块恢复槽）"
      />
      <label class="kf-toggle kd-skip" :class="{ 'kf-toggle--on': skipRecoveryBinding }">
        <input type="checkbox" v-model="skipRecoveryBinding" />
        <span class="kf-box" aria-hidden="true"></span>
        <span class="kf-text">暂不绑定恢复槽（换机后该模块无法恢复）</span>
      </label>
    </div>
    <p v-if="keyDialogProcessing" class="kd-elapsed" role="status">
      正在写入，已耗时 {{ elapsedSeconds }} 秒…
    </p>
    <!-- 修改模式：验证原独立密钥 -->
    <div v-if="hasRecord" class="kd-old-key-row">
      <div class="kd-old-key-label">原独立密钥</div>
      <input
        class="kv-input"
        v-model="editingOldKeyValue"
        type="password"
        autocomplete="current-password"
        spellcheck="false"
        placeholder="请输入原独立密钥以验证身份"
        @keydown.enter="$emit('confirm')"
      />
    </div>
    <div class="kd-key-field">
      <input
        class="kv-input"
        v-model="editingKeyValue"
        :type="keyVisible ? 'text' : 'password'"
        autocomplete="new-password"
        spellcheck="false"
        aria-label="模块独立密钥（默认密文显示）"
        placeholder="输入自定义密钥"
        @keydown.enter="$emit('confirm')"
      />
      <div class="kd-key-tools">
        <button
          type="button"
          class="kd-key-icon"
          aria-label="随机生成 32 字节密钥"
          v-tip="'随机生成 32 字节密钥'"
          @click="$emit('randomKey')"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>
        </button>
        <button
          type="button"
          class="kd-key-icon"
          :aria-label="keyVisible ? '隐藏密钥' : '显示密钥'"
          :aria-pressed="keyVisible"
          v-tip="keyVisible ? '隐藏' : '显示'"
          @click="keyVisible = !keyVisible"
        >
          <svg v-if="!keyVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
        </button>
      </div>
    </div>
    <div class="kv-actions">
      <button class="btn kv-cancel" type="button" @click="$emit('close')">取消</button>
      <button
        class="btn btn-primary kv-confirm"
        type="button"
        @click="$emit('confirm')"
        :disabled="!editingKeyValue || keyDialogProcessing || (hasRecord && !editingOldKeyValue) || (!hasRecord && !skipRecoveryBinding && !editingRecoveryCode)"
      >
        {{ keyDialogProcessing ? '保存中…' : '确认保存' }}
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";

/** 新密钥默认密文显示（明文仅经显式切换短暂可见） */
const keyVisible = ref(false);

/** 长事务已耗时（秒）：写盘在途时按秒递增，让用户确认进程仍在推进 */
const elapsedSeconds = ref(0);
let elapsedTimer: ReturnType<typeof setInterval> | null = null;

function stopElapsed(): void {
  if (elapsedTimer) {
    clearInterval(elapsedTimer);
    elapsedTimer = null;
  }
}

/**
 * KeyEditDialog Props
 */
const props = defineProps<{
  /** 弹窗显示状态 */
  show: boolean;
  /** 当前编辑模块的显示名称（moduleLabels[editingModuleId]） */
  moduleLabel: string;
  /** 当前模块是否存在密钥记录（决定标题为「修改」/「生成」+ 是否显示原密钥验证区） */
  hasRecord: boolean;
  /** 密钥保存处理中状态 */
  keyDialogProcessing: boolean;
}>();

/**
 * KeyEditDialog Models（密钥字段双向绑定）
 */
const editingKeyValue = defineModel<string>("editingKeyValue", { default: "" });
const editingOldKeyValue = defineModel<string>("editingOldKeyValue", { default: "" });
const editingRecoveryCode = defineModel<string>("editingRecoveryCode", { default: "" });
const skipRecoveryBinding = defineModel<boolean>("skipRecoveryBinding", { default: false });

watch(
  () => props.keyDialogProcessing,
  (busy) => {
    stopElapsed();
    if (!busy) {
      elapsedSeconds.value = 0;
      return;
    }
    const startedAt = Date.now();
    elapsedSeconds.value = 0;
    elapsedTimer = setInterval(() => {
      elapsedSeconds.value = Math.floor((Date.now() - startedAt) / 1000);
    }, 1000);
  },
);
onBeforeUnmount(stopElapsed);

/**
 * KeyEditDialog Emits
 */
defineEmits<{
  /** 关闭弹窗（取消或点击遮罩） */
  (e: "close"): void;
  /** 随机生成 32 字节密钥 */
  (e: "randomKey"): void;
  /** 确认保存（生成/修改密钥） */
  (e: "confirm"): void;
}>();
</script>

<style scoped>
/* 密钥端子内嵌：显隐与随机生成都收进输入框右侧，图标即控件；
 * 右内距由底板内容体系的变量预留，端子不占输入框外的水平槽位 */
.kd-key-field {
  --kv-input-pad-right: 68px;
  position: relative;
}
.kd-key-tools {
  position: absolute;
  top: 50%;
  right: 6px;
  transform: translateY(-50%);
  display: flex;
  align-items: center;
  gap: 2px;
}
/* 无框图标端子：零底板、零阴影，仅以色彩应答悬浮与焦点 */
.kd-key-icon {
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
.kd-key-icon:hover {
  color: var(--accent);
}
.kd-key-icon:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: 1px;
}
.kd-key-icon svg {
  width: 14px;
  height: 14px;
}
</style>
