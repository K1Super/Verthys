<!--
  ExportVerifyDialog.vue — 导出密钥文件验证弹窗（复用全局密钥窗口样式 · 紧凑版）

  职责：
    1. 导出密钥文件前的强制全局密钥验证门禁（双要素凭据输入：
       全局访问密钥 + 密钥口令 — 密钥文件在确认后的导出流程中选择，
       与验证合一，免除弹窗内单独选文件）
    2. 表单样式与 ChangeKeyDialog（修改全局密钥弹窗）同源：
       ck-section 分组 + ck-field 字段 + kv-input 输入框 + kv-actions 操作区
    3. 紧凑规格：400px 窄幅 + 收敛内距（导出为低频敏感操作，小窗聚焦凭据）
    4. 确认按钮（禁用条件：processing 或任一字段为空）

  Props: show / processing
  Models: password / binPassword
  Emits: close / confirm
-->
<template>
  <CosmicOverlay :show="show" width="400px" @close="$emit('close')">
    <div class="kv-title">验证全局密钥</div>
    <div class="kv-desc">
      导出密钥文件属高敏感操作，需先验证全局密钥，<br/>
    </div>
    <div class="ck-section">
      <div class="ck-section-title">验证当前密钥</div>
      <div class="ck-field">
        <label>全局访问密钥</label>
        <input class="kv-input" v-model="password" type="password" placeholder="输入全局访问密钥" />
      </div>
      <div class="ck-field">
        <label>密钥口令</label>
        <input class="kv-input" v-model="binPassword" type="password" placeholder="输入密钥口令" />
      </div>
    </div>
    <div class="kv-actions">
      <button class="btn kv-cancel" @click="$emit('close')" :disabled="processing">取消</button>
      <button class="btn btn-primary kv-confirm" @click="$emit('confirm')" :disabled="processing || !password || !binPassword">
        {{ processing ? '验证中…' : '验证并导出' }}
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";

/**
 * ExportVerifyDialog Props
 */
defineProps<{
  /** 弹窗显示状态 */
  show: boolean;
  /** 验证处理中状态（禁用表单 + 按钮） */
  processing: boolean;
}>();

/**
 * ExportVerifyDialog Models（凭据字段双向绑定）
 */
const password = defineModel<string>("password", { default: "" });
const binPassword = defineModel<string>("binPassword", { default: "" });

/**
 * ExportVerifyDialog Emits
 */
defineEmits<{
  /** 关闭弹窗（取消或点击遮罩） */
  (e: "close"): void;
  /** 确认验证（验证通过后选择密钥文件并执行导出） */
  (e: "confirm"): void;
}>();
</script>

<style scoped>
/* ===== 紧凑规格覆写（全局 kv 与 ck 系列基础上的导出弹窗专属收敛） ===== */
.kv-title {
  font-size: 16px;
  margin-bottom: 6px;
}
.kv-desc {
  font-size: 11.5px;
  line-height: 1.6;
  margin-bottom: 14px;
}
.ck-section {
  padding: 12px 14px;
  margin-bottom: 12px;
}
.ck-section-title {
  margin-bottom: 10px;
}
.kv-actions {
  margin-top: 0;
}
</style>
