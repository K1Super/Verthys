<!--
  ExportVerifyDialog.vue — 验证全局密钥（导出核验台 · 双闸放行）

  形态：复用全局弹窗外壳 CosmicOverlay 与 kv-* 内容词汇。
  构图：双闸凭据（访问密钥 / 密钥口令）经闸缝并置为一条准入管线，
        下方放行读数说明「凭据核验 → 选择 .bin 密钥文件 → 导出本地备份」。

  职责：
    1. 导出密钥文件前的强制全局密钥验证门禁（双要素凭据；
       密钥文件在确认后的导出流程中选择，验证与导出合一）
    2. 确认按钮（禁用条件：处理中或任一字段为空）

  Props: show / processing
  Models: password / binPassword
  Emits: close / confirm
-->
<template>
  <CosmicOverlay
    :show="show"
    width="560px"
    :persistent="processing"
    aria-labelledby="ev-title"
    @close="$emit('close')"
  >
    <div class="kv-title" id="ev-title">验证全局密钥</div>

    <!-- 双闸凭据：并置为一条准入管线，闸缝标注放行方向 -->
    <div class="ev-gates">
      <div class="kv-field ev-gate">
        <label class="kv-label" for="ev-pwd">访问密钥</label>
        <input id="ev-pwd" class="kv-input" v-model="password" type="password" autocomplete="current-password" spellcheck="false" />
      </div>
      <span class="ev-gate-seam" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><polyline points="9 6 15 12 9 18"/></svg>
      </span>
      <div class="kv-field ev-gate">
        <label class="kv-label" for="ev-binpwd">密钥口令</label>
        <input id="ev-binpwd" class="kv-input" v-model="binPassword" type="password" autocomplete="current-password" spellcheck="false" />
      </div>
    </div>

    <p class="kv-note ev-release">凭据核验 → 选择 .bin 密钥文件 → 导出本地备份</p>

    <div class="kv-actions">
      <button class="btn kv-cancel" type="button" :disabled="processing" @click="$emit('close')">取消</button>
      <button
        class="btn btn-primary kv-confirm"
        type="button"
        :disabled="processing || !password || !binPassword"
        @click="$emit('confirm')"
      >{{ processing ? "验证中…" : "验证并导出" }}</button>
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
  /** 关闭弹窗（取消或点击遮罩；处理中由 persistent 拦截） */
  (e: "close"): void;
  /** 确认验证（验证通过后选择密钥文件并执行导出） */
  (e: "confirm"): void;
}>();
</script>

<style scoped>
/* ===== 导出核验台：双闸放行 =====
   本文件只负责双闸并置与闸缝这一业务构图；字段、输入与动作区由 kv-* 承担 */

.ev-gates {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 34px minmax(0, 1fr);
  align-items: end;
}

/* 闸缝：管线方向标注 */
.ev-gate-seam {
  display: flex;
  align-items: center;
  justify-content: center;
  padding-bottom: 12px;
  color: rgba(var(--accent-rgb), 0.45);
}
.ev-gate-seam svg { width: 13px; height: 13px; }

/* 放行读数：流程说明还原为一条管线文字，不加外框 */
.ev-release {
  margin-top: 16px;
  font-family: var(--font-mono);
  font-size: 10.5px;
  letter-spacing: 0.6px;
}
</style>
