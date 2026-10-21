<!--
  KeyEditDialog.vue — 密钥编辑弹窗（生成/修改模块独立密钥）
  来源：SecurityCenter.vue 原 L122-L164（零行为变更提取）

  职责：
    1. 弹窗标题动态切换（修改/生成）+ 模块名拼接
    2. 修改模式警告（kv-warn：旧密钥加密数据将无法解密）
    3. 修改模式：验证原独立密钥（editingOldKeyValue，v-model 双向绑定）
    4. 新密钥输入框 + 随机生成按钮（editingKeyValue，v-model 双向绑定）
    5. 确认保存按钮（禁用条件：editingKeyValue 为空 / 处理中 / 修改模式下原密钥为空）

  Props: show / moduleLabel / hasRecord / keyDialogProcessing
  Models: editingKeyValue / editingOldKeyValue
  Emits: close / randomKey / confirm
-->
<template>
  <CosmicOverlay :show="show" width="460px" @close="$emit('close')">
    <div class="kv-title">{{ hasRecord ? '修改' : '生成' }}{{ moduleLabel }}独立密钥</div>
    <div class="kv-desc">
      {{ hasRecord
        ? '修改后旧密钥将立即失效，使用旧密钥加密的数据将无法解密'
        : '请输入自定义密钥' }}
    </div>
    <div v-if="hasRecord" class="kv-warn">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      <span>修改密钥会导致旧密钥加密的数据无法解密，请谨慎操作</span>
    </div>
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
    <div class="kd-input-row">
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
      <button
        type="button"
        class="kd-eye"
        :aria-label="keyVisible ? '隐藏密钥' : '显示密钥'"
        :aria-pressed="keyVisible"
        @click="keyVisible = !keyVisible"
      >
        <svg v-if="!keyVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
      </button>
      <button class="btn btn-sm kd-random" type="button" @click="$emit('randomKey')" v-tip="'随机生成 32 字节密钥'">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>
        随机
      </button>
    </div>
    <div class="kv-actions">
      <button class="btn kv-cancel" type="button" @click="$emit('close')">取消</button>
      <button class="btn btn-primary kv-confirm" type="button" @click="$emit('confirm')" :disabled="!editingKeyValue || keyDialogProcessing || (hasRecord && !editingOldKeyValue)">
        {{ keyDialogProcessing ? '保存中…' : '确认保存' }}
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { ref } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";

/** 新密钥默认密文显示（明文仅经显式切换短暂可见） */
const keyVisible = ref(false);

/**
 * KeyEditDialog Props
 */
defineProps<{
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
