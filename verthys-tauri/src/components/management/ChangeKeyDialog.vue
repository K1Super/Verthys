<!--
  ChangeKeyDialog.vue — 修改全局密钥弹窗（密钥轮换台 · 双舱交接）

  形态：复用全局弹窗外壳 CosmicOverlay 与 kv-* 内容词汇。
  构图：01 现行密钥舱（核验交出） ⇄ 中轴轮换 ⇄ 02 继任密钥舱（设定承入）；
        密钥文件以只读凭据槽呈现，不使用输入框。

  职责：
    1. 双舱三凭据采集：现行（访问密钥 / 密钥文件 / 密钥口令）与继任（同三项）
    2. 确认修改（禁用条件：处理中或任一凭据缺失）；处理中禁止关闭

  Props: show / changeKeyProcessing / oldBinFileName / newBinFileName
  Models: oldPassword / oldBinPassword / newPassword / newBinPassword
  Emits: close / browseOldBin / browseNewBin / confirm
-->
<template>
  <CosmicOverlay
    :show="show"
    width="min(780px, 94vw)"
    :persistent="changeKeyProcessing"
    aria-labelledby="ck-title"
    @close="$emit('close')"
  >
    <div class="kv-title" id="ck-title">修改全局密钥</div>

    <div class="ck-transit">
      <!-- 舱 01：现行密钥 · 核验交出 -->
      <section class="kv-section ck-bay">
        <div class="kv-section-label">01 现行密钥 · 核验</div>
        <div class="kv-field">
          <label class="kv-label" for="ck-old-pwd">访问密钥</label>
          <input id="ck-old-pwd" class="kv-input" v-model="oldPassword" type="password" autocomplete="current-password" spellcheck="false" />
        </div>
        <div class="kv-field">
          <span class="kv-label">密钥文件</span>
          <div class="ck-slot" :class="{ 'is-empty': !oldBinFileName }">
            <span class="ck-slot-token">{{ oldBinFileName || '待选择当前密钥文件' }}</span>
            <button class="ck-slot-pick" type="button" aria-label="选择现行密钥文件" @click="$emit('browseOldBin')" :disabled="changeKeyProcessing">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-6l-2-2H5a2 2 0 0 0-2 2z"/></svg>
              <span>选择</span>
            </button>
          </div>
        </div>
        <div class="kv-field">
          <label class="kv-label" for="ck-old-binpwd">密钥口令</label>
          <input id="ck-old-binpwd" class="kv-input" v-model="oldBinPassword" type="password" autocomplete="current-password" spellcheck="false" />
        </div>
      </section>

      <!-- 中轴：轮换节点（对向双弧，静态）+ 轴向铭文 -->
      <div class="ck-axis" aria-hidden="true">
        <span class="ck-axis-rail"></span>
        <span class="ck-axis-node">
          <svg viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="1.7" fill="currentColor" stroke="none" />
            <path d="M4.8 12 A7.2 7.2 0 0 1 19.2 12" stroke="currentColor" stroke-width="1" stroke-linecap="round" opacity="0.85" />
            <path d="M19.2 12 A7.2 7.2 0 0 1 4.8 12" stroke="currentColor" stroke-width="1" stroke-linecap="round" opacity="0.4" />
            <path d="M17.9 10.8 L19.2 12.1 L20.5 10.8" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" />
            <path d="M6.1 13.2 L4.8 11.9 L3.5 13.2" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>
        <span class="ck-axis-word">轮换</span>
        <span class="ck-axis-rail"></span>
      </div>

      <!-- 舱 02：继任密钥 · 设定承入 -->
      <section class="kv-section ck-bay">
        <div class="kv-section-label">02 继任密钥 · 设定</div>
        <div class="kv-field">
          <label class="kv-label" for="ck-new-pwd">访问密钥</label>
          <input id="ck-new-pwd" class="kv-input" v-model="newPassword" type="password" autocomplete="new-password" spellcheck="false" />
        </div>
        <div class="kv-field">
          <span class="kv-label">密钥文件</span>
          <div class="ck-slot" :class="{ 'is-empty': !newBinFileName }">
            <span class="ck-slot-token">{{ newBinFileName || '待选择新密钥文件' }}</span>
            <button class="ck-slot-pick" type="button" aria-label="选择继任密钥文件" @click="$emit('browseNewBin')" :disabled="changeKeyProcessing">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-6l-2-2H5a2 2 0 0 0-2 2z"/></svg>
              <span>选择</span>
            </button>
          </div>
        </div>
        <div class="kv-field">
          <label class="kv-label" for="ck-new-binpwd">密钥口令</label>
          <input id="ck-new-binpwd" class="kv-input" v-model="newBinPassword" type="password" autocomplete="new-password" spellcheck="false" />
        </div>
      </section>
    </div>

    <p class="kv-warn ck-void">修改完成后，当前密钥与密钥文件将失效</p>

    <div class="kv-actions">
      <button class="btn kv-cancel" type="button" :disabled="changeKeyProcessing" @click="$emit('close')">取消</button>
      <button
        class="btn btn-primary kv-confirm"
        type="button"
        :disabled="confirmBlocked"
        @click="$emit('confirm')"
      >{{ changeKeyProcessing ? "修改中…" : "确认修改" }}</button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { computed } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";

/**
 * ChangeKeyDialog Props
 */
const props = defineProps<{
  /** 弹窗显示状态 */
  show: boolean;
  /** 修改处理中状态（禁用表单 + 按钮） */
  changeKeyProcessing: boolean;
  /** 当前密钥文件名（只读凭据槽显示） */
  oldBinFileName: string;
  /** 新密钥文件名（只读凭据槽显示） */
  newBinFileName: string;
}>();

/**
 * ChangeKeyDialog Models（密码字段双向绑定）
 */
const oldPassword = defineModel<string>("oldPassword", { default: "" });
const oldBinPassword = defineModel<string>("oldBinPassword", { default: "" });
const newPassword = defineModel<string>("newPassword", { default: "" });
const newBinPassword = defineModel<string>("newBinPassword", { default: "" });

/**
 * ChangeKeyDialog Emits
 */
defineEmits<{
  /** 关闭弹窗（取消或点击遮罩；处理中由 persistent 拦截） */
  (e: "close"): void;
  /** 选择当前密钥文件 */
  (e: "browseOldBin"): void;
  /** 选择新密钥文件 */
  (e: "browseNewBin"): void;
  /** 确认修改全局密钥 */
  (e: "confirm"): void;
}>();

/** 确认禁用条件：处理中或任一凭据缺失 */
const confirmBlocked = computed(() =>
  props.changeKeyProcessing
  || !oldPassword.value || !props.oldBinFileName || !oldBinPassword.value
  || !newPassword.value || !props.newBinFileName || !newBinPassword.value,
);
</script>

<style scoped>
/* ===== 密钥轮换台：双舱交接 =====
   本文件只负责双舱并置与凭据槽这一业务构图；标题、字段、输入与动作区
   全部由 kv-* 承担，不得声明第二套弹窗皮肤 */

/* 双舱 + 中轴：01 现行 ─ 轮换 ─ 02 继任 */
.ck-transit {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 56px minmax(0, 1fr);
  align-items: stretch;
}

/* 舱体在网格内不使用分区顶线：左右并置时顶线会被中轴切断 */
.ck-bay {
  padding-top: 0;
  margin-top: 0;
  border-top: 0;
}

/* 中轴：两段刻度线夹持轮换节点与轴向铭文（一次性淡入） */
.ck-axis {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  padding: 6px 0;
  animation: ck-axis-in 0.5s var(--ease) both;
  animation-delay: 0.12s;
}
@keyframes ck-axis-in {
  from { opacity: 0; }
  to { opacity: 1; }
}
.ck-axis-rail {
  width: 1px;
  flex: 1;
  background: linear-gradient(180deg, transparent, rgba(205, 224, 244, 0.14) 30%, rgba(205, 224, 244, 0.14) 70%, transparent);
}
.ck-axis-node {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  flex-shrink: 0;
  color: rgba(var(--accent-rgb), 0.85);
}
.ck-axis-node svg { width: 100%; height: 100%; }
.ck-axis-word {
  flex-shrink: 0;
  writing-mode: vertical-rl;
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 4px;
  color: var(--text-muted);
}

/* 凭据槽：密钥文件只读位（令牌 + 选择端子，与 kv-input 同一凹槽材质） */
.ck-slot {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  padding: 3px 4px 3px 13px;
  background: linear-gradient(180deg, rgba(2, 5, 10, 0.38), rgba(2, 5, 10, 0.20));
  border-radius: 8px;
  box-shadow:
    inset 0 1px 0 rgba(var(--black-rgb), 0.50),
    inset 0 -1px 0 rgba(205, 224, 244, 0.055);
  transition: box-shadow 0.25s var(--ease);
}
.ck-slot:focus-within {
  box-shadow:
    inset 0 1px 0 rgba(var(--black-rgb), 0.45),
    inset 0 -1px 0 rgba(var(--accent-rgb), 0.60);
}
.ck-slot-token {
  flex: 1;
  min-width: 0;
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.4px;
  color: var(--accent);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.ck-slot.is-empty .ck-slot-token {
  color: var(--text-muted);
  font-family: var(--font);
  font-size: 12px;
  letter-spacing: 0.5px;
}
.ck-slot-pick {
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 6px 9px;
  background: none;
  border: 1px solid transparent;
  border-radius: 6px;
  color: var(--text-secondary);
  font-size: 11px;
  font-family: var(--font);
  letter-spacing: 0.5px;
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease), background-color var(--dur-fast) var(--ease);
}
.ck-slot-pick svg { width: 12px; height: 12px; opacity: 0.85; }
.ck-slot-pick:hover:not(:disabled) {
  color: var(--accent);
  border-color: rgba(var(--accent-rgb), 0.24);
  background-color: rgba(var(--accent-rgb), 0.06);
}
.ck-slot-pick:focus-visible { outline: 1px solid var(--border-hover); outline-offset: 1px; }
.ck-slot-pick:disabled { cursor: not-allowed; opacity: 0.55; }

/* 失效提示：文字直陈，只与动作区保持间距 */
.ck-void {
  margin-top: 16px;
  margin-bottom: 0;
}

/* 窄窗口降级：双舱改单列，中轴横置为舱间分界 */
@media (max-width: 760px) {
  .ck-transit { grid-template-columns: minmax(0, 1fr); }
  .ck-axis { flex-direction: row; padding: 2px 4px; }
  .ck-axis-rail {
    width: auto;
    height: 1px;
    flex: 1;
    background: linear-gradient(90deg, transparent, rgba(205, 224, 244, 0.14) 30%, rgba(205, 224, 244, 0.14) 70%, transparent);
  }
  .ck-axis-word { writing-mode: horizontal-tb; letter-spacing: 2px; }
}

/* 无障碍：偏好减少动态时，一次性入场直接落到终态 */
@media (prefers-reduced-motion: reduce) {
  .ck-axis { animation: none; }
}
</style>
