<!--
  ExportVerifyDialog.vue — 验证全局密钥（导出核验台 · 双闸放行）
  背景皮肤：直接复用「凭证登记台」共享层 ——
    VerthysDialog（layout="plain" + class="reg-panel"），
    与 存签 / 枢钥 登记窗口同一来源（styles/reg-desk.css），不自定义窗口底板。

  构图（打破纵向表单惯例）：
    双闸凭据舱（01 访问密钥 / 02 密钥口令）经闸缝并置为一条准入管线；
    下方「放行带」三格读数（凭据核验 → 选择 .bin 密钥文件 → 导出本地备份）
    即流程说明 — 说明不是段落，是管线读数。

  职责（零行为变更）：
    1. 导出密钥文件前的强制全局密钥验证门禁（双要素凭据；
       密钥文件在确认后的导出流程中选择，验证与导出合一）
    2. 确认按钮（禁用条件：处理中或任一字段为空）

  Props: show / processing
  Models: password / binPassword
  Emits: close / confirm
-->
<template>
  <VerthysDialog
    :model-value="show"
    layout="plain"
    class="reg-panel"
    title="验证全局密钥"
    save-label="验证并导出"
    saving-label="验证中…"
    :save-disabled="processing || !password || !binPassword"
    :saving="processing"
    @update:model-value="onShellToggle"
    @save="$emit('confirm')"
  >
    <template #header>
      <header class="reg-head">
        <span class="reg-mark" aria-hidden="true">
          <!-- 核验徽记：双闸柱夹持中枢轴（准入意象） -->
          <svg viewBox="0 0 24 24" fill="none">
            <path d="M7 3.8 V 20.2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" opacity="0.5" />
            <path d="M17 3.8 V 20.2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" opacity="0.5" />
            <path d="M12 4.6 V 8.6 M12 15.4 V 19.4" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" opacity="0.8" />
            <circle cx="12" cy="12" r="2.1" fill="currentColor" stroke="none" />
          </svg>
        </span>
        <span class="reg-heading">
          <span class="reg-kicker">中枢 · 导出核验</span>
          <span class="reg-title">验证全局密钥</span>
        </span>
        <button class="reg-close" type="button" @click="$emit('close')" aria-label="关闭窗口" v-tip="'关闭'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </header>
    </template>

    <div class="reg-body">
      <div class="reg-sec-head">
        <span class="reg-sec-no">GATE</span>
        <span class="reg-sec-name">双要素核验</span>
        <span class="reg-rule"></span>
      </div>

      <!-- 双闸凭据舱：并置为一条准入管线，闸缝标注放行方向 -->
      <div class="ev-gates">
        <div class="ev-gate">
          <span class="ev-gate-no">01</span>
          <label class="ev-gate-key" for="ev-pwd">访问密钥</label>
          <input id="ev-pwd" class="reg-input" v-model="password" type="password" placeholder="输入全局访问密钥" />
        </div>
        <span class="ev-gate-seam" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><polyline points="9 6 15 12 9 18"/></svg>
        </span>
        <div class="ev-gate">
          <span class="ev-gate-no">02</span>
          <label class="ev-gate-key" for="ev-binpwd">密钥口令</label>
          <input id="ev-binpwd" class="reg-input" v-model="binPassword" type="password" placeholder="输入密钥口令" />
        </div>
      </div>

      <!-- 放行带：三格管线读数（核验通过后选择密钥文件并导出） -->
      <div class="ev-release">
        <span class="ev-release-step is-lead">凭据核验</span>
        <svg class="ev-release-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><polyline points="9 6 15 12 9 18"/></svg>
        <span class="ev-release-step">选择 .bin 密钥文件</span>
        <svg class="ev-release-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><polyline points="9 6 15 12 9 18"/></svg>
        <span class="ev-release-step">导出本地备份</span>
      </div>
    </div>
  </VerthysDialog>
</template>

<script setup lang="ts">
import VerthysDialog from "../common/verthys-ui/VerthysDialog.vue";

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
const emit = defineEmits<{
  /** 关闭弹窗（取消或点击遮罩；处理中由父级守卫拦截） */
  (e: "close"): void;
  /** 确认验证（验证通过后选择密钥文件并执行导出） */
  (e: "confirm"): void;
}>();

/** 外壳关闭请求（取消 / 遮罩）：转交父级守卫（处理中拦截） */
const onShellToggle = (val: boolean): void => {
  if (!val) emit("close");
};
</script>

<style scoped>
/* ===== 导出核验台：双闸放行（皮肤承载：全局 reg-* 登记台词汇）=====
   本文件只负责构图差异：双闸凭据舱 + 闸缝 + 放行读数带；
   承登记台纪律：全部动效为一次性入场，无循环装饰 */

/* 双闸：准入管线（两舱 + 闸缝） */
.ev-gates {
  position: relative;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 34px minmax(0, 1fr);
  align-items: stretch;
}

/* 闸位刻度：与全局左缘轴对齐（-19px = 登记区缩进 42px − 轴位 23px） */
.ev-gates::before,
.ev-release::before {
  content: ""; position: absolute; left: -19px; width: 7px; height: 1px;
  background: var(--border-glass);
  transition: background-color var(--dur-fast) var(--ease);
}
.ev-gates::before { top: 26px; }
.ev-release::before { top: 50%; }
/* 核验聚焦时闸位刻度注能（与 reg-row / reg-vault 同语义） */
.ev-gates:focus-within::before { background: var(--accent); }

/* 闸舱：凹槽形凭据位（与 reg-input / reg-vault 同族） */
.ev-gate {
  display: flex; flex-direction: column; gap: 7px;
  padding: 12px 13px 13px;
  border: 1px solid rgba(var(--white-rgb), 0.07);
  border-radius: 8px;
  background-color: rgba(var(--black-rgb), 0.22);
  transition:
    border-color var(--dur-fast) var(--ease),
    background-color var(--dur-fast) var(--ease);
  animation: reg-sec-in 0.5s var(--ease) both;
}
.ev-gate:nth-child(1) { animation-delay: 0.12s; }
.ev-gate:nth-child(3) { animation-delay: 0.19s; }
.ev-gate:hover { border-color: rgba(var(--white-rgb), 0.12); }
.ev-gate:focus-within { border-color: rgba(var(--accent-rgb), 0.5); }
.ev-gate-no {
  font-family: var(--font-mono); font-size: 10px; letter-spacing: 2px;
  color: rgba(var(--accent-rgb), 0.7);
}
.ev-gate-key {
  font-size: 11px; letter-spacing: 1px; color: var(--text-muted);
  transition: color var(--dur-fast) var(--ease);
}
.ev-gate:focus-within .ev-gate-key { color: var(--accent); }

/* 闸缝：管线方向标注 */
.ev-gate-seam {
  display: flex; align-items: center; justify-content: center;
  color: rgba(var(--accent-rgb), 0.45);
  animation: reg-sec-in 0.5s var(--ease) both;
  animation-delay: 0.16s;
}
.ev-gate-seam svg { width: 13px; height: 13px; }

/* 放行带：三格管线读数（虚线 = 待放行） */
.ev-release {
  position: relative;
  display: flex; align-items: center; gap: 9px; flex-wrap: wrap;
  margin-top: 16px;
  padding: 10px 12px;
  border: 1px dashed rgba(var(--white-rgb), 0.1);
  border-radius: 6px;
  animation: reg-sec-in 0.5s var(--ease) both;
  animation-delay: 0.24s;
}
.ev-release-step {
  font-family: var(--font-mono); font-size: 10px; letter-spacing: 1px;
  color: var(--text-muted); white-space: nowrap;
}
.ev-release-step.is-lead { color: var(--text-secondary); }
.ev-release-arrow {
  width: 12px; height: 12px; flex-shrink: 0;
  color: rgba(var(--accent-rgb), 0.4);
}

/* 无障碍：偏好减少动态时，一次性入场直接落到终态 */
@media (prefers-reduced-motion: reduce) {
  .ev-gate,
  .ev-gate-seam,
  .ev-release { animation: none; }
}
</style>