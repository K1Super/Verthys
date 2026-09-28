<!--
  ChangeKeyDialog.vue — 修改全局密钥弹窗（密钥轮换台 · 双舱交接）
  背景皮肤：直接复用「凭证登记台」共享层 ——
    VerthysDialog（layout="plain" + class="reg-panel reg-wide"），
    与 存签 / 枢钥 登记窗口同一来源（styles/reg-desk.css），不自定义窗口底板。

  构图（打破纵向表单惯例）：
    01 现行密钥舱（核验交出） ⇄ 中轴轮换 ⇄ 02 继任密钥舱（设定承入）；
    每舱携带局部刻度轴（全局左缘轴让位于中轴），密钥文件以「凭据槽」
    令牌呈现（非输入框）；底部「失效读数带」把警示语从段落还原为仪表读数。

  职责（零行为变更）：
    1. 双舱三凭据采集：① 现行（访问密钥 / 密钥文件 / 密钥口令）② 继任（同三项）
    2. 密钥文件为只读凭据槽 + 选择端子（emit browseOldBin / browseNewBin）
    3. 确认修改（禁用条件：处理中或任一凭据缺失）；取消（处理中由父级守卫拦截）

  Props: show / changeKeyProcessing / oldBinFileName / newBinFileName
  Models: oldPassword / oldBinPassword / newPassword / newBinPassword
  Emits: close / browseOldBin / browseNewBin / confirm
-->
<template>
  <VerthysDialog
    :model-value="show"
    layout="plain"
    class="reg-panel reg-wide"
    title="修改全局密钥"
    save-label="确认修改"
    saving-label="修改中…"
    :save-disabled="confirmBlocked"
    :saving="changeKeyProcessing"
    @update:model-value="onShellToggle"
    @save="$emit('confirm')"
  >
    <template #header>
      <header class="reg-head">
        <span class="reg-mark" aria-hidden="true">
          <!-- 轮换徽记：枢核 + 两道对向半环（顺时针 / 逆时针各一，换任意象） -->
          <svg viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="1.9" fill="currentColor" stroke="none" />
            <path d="M4.4 12 A7.6 7.6 0 0 1 19.6 12" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" opacity="0.85" />
            <path d="M19.6 12 A7.6 7.6 0 0 1 4.4 12" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" opacity="0.42" />
            <path d="M18.1 10.7 L19.6 12.2 L21.1 10.7" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round" />
            <path d="M5.9 13.3 L4.4 11.8 L2.9 13.3" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>
        <span class="reg-heading">
          <span class="reg-kicker">中枢 · 密钥轮换</span>
          <span class="reg-title">修改全局密钥</span>
        </span>
        <button class="reg-close" type="button" @click="$emit('close')" aria-label="关闭窗口" v-tip="'关闭'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </header>
    </template>

    <div class="reg-body ck-body">
      <div class="ck-transit">
        <!-- 舱 01：现行密钥 · 核验交出 -->
        <section class="reg-section ck-bay" :style="{ '--rs': '0' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">01</span>
            <span class="reg-sec-name">现行密钥 · 核验</span>
            <span class="reg-rule"></span>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="ck-old-pwd">访问密钥</label>
            <input id="ck-old-pwd" class="reg-input" v-model="oldPassword" type="password" placeholder="输入当前全局访问密钥" />
          </div>
          <div class="reg-row">
            <span class="reg-key">密钥文件</span>
            <div class="ck-slot" :class="{ 'is-empty': !oldBinFileName }">
              <span class="ck-slot-token">{{ oldBinFileName || '待选择当前密钥文件' }}</span>
              <button class="ck-slot-pick" type="button" @click="$emit('browseOldBin')" :disabled="changeKeyProcessing">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-6l-2-2H5a2 2 0 0 0-2 2z"/></svg>
                <span>选择</span>
              </button>
            </div>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="ck-old-binpwd">密钥口令</label>
            <input id="ck-old-binpwd" class="reg-input" v-model="oldBinPassword" type="password" placeholder="输入当前密钥口令" />
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
        <section class="reg-section ck-bay" :style="{ '--rs': '1' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">02</span>
            <span class="reg-sec-name">继任密钥 · 设定</span>
            <span class="reg-rule"></span>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="ck-new-pwd">访问密钥</label>
            <input id="ck-new-pwd" class="reg-input" v-model="newPassword" type="password" placeholder="输入新的全局访问密钥" />
          </div>
          <div class="reg-row">
            <span class="reg-key">密钥文件</span>
            <div class="ck-slot" :class="{ 'is-empty': !newBinFileName }">
              <span class="ck-slot-token">{{ newBinFileName || '待选择新密钥文件' }}</span>
              <button class="ck-slot-pick" type="button" @click="$emit('browseNewBin')" :disabled="changeKeyProcessing">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-6l-2-2H5a2 2 0 0 0-2 2z"/></svg>
                <span>选择</span>
              </button>
            </div>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="ck-new-binpwd">密钥口令</label>
            <input id="ck-new-binpwd" class="reg-input" v-model="newBinPassword" type="password" placeholder="输入新密钥口令" />
          </div>
        </section>
      </div>

      <!-- 失效读数带（静态裁定：警语即读数，非段落） -->
      <div class="ck-void">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M12 3 2.5 20h19L12 3z"/><line x1="12" y1="9.5" x2="12" y2="14"/><line x1="12" y1="16.5" x2="12.01" y2="16.5"/></svg>
        <span>交接完成后，现行密钥与现行密钥文件即告失效</span>
      </div>
    </div>
  </VerthysDialog>
</template>

<script setup lang="ts">
import { computed } from "vue";
import VerthysDialog from "../common/verthys-ui/VerthysDialog.vue";

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
const emit = defineEmits<{
  /** 关闭弹窗（取消或点击遮罩；处理中由父级守卫拦截） */
  (e: "close"): void;
  /** 选择当前密钥文件 */
  (e: "browseOldBin"): void;
  /** 选择新密钥文件 */
  (e: "browseNewBin"): void;
  /** 确认修改全局密钥 */
  (e: "confirm"): void;
}>();

/** 确认禁用条件：处理中或任一凭据缺失（与原实现逐项一致） */
const confirmBlocked = computed(() =>
  props.changeKeyProcessing
  || !oldPassword.value || !props.oldBinFileName || !oldBinPassword.value
  || !newPassword.value || !props.newBinFileName || !newBinPassword.value,
);

/** 外壳关闭请求（取消 / 遮罩）：转交父级守卫（处理中拦截） */
const onShellToggle = (val: boolean): void => {
  if (!val) emit("close");
};
</script>

<style scoped>
/* ===== 密钥轮换台：双舱交接（皮肤承载：全局 reg-* 登记台词汇）=====
   本文件只负责构图差异：双舱并置 + 中轴轮换 + 凭据槽 + 失效读数带；
   承登记台纪律：全部动效为一次性入场，无循环装饰 */

/* 登记区改用舱内局部刻度轴：全局左缘轴在双舱构图下让位于中轴 */
.ck-body { padding: 18px 24px 12px; }
.ck-body::before { display: none; }

/* 双舱 + 中轴：01 现行 ─ 轮换 ─ 02 继任 */
.ck-transit {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 56px minmax(0, 1fr);
  align-items: stretch;
}

/* 舱体：局部刻度轴（轴位 8px = 舱缩进 27px − 刻度偏移 19px，
   与 reg-sec-head / reg-row 的刻度同列，聚焦注能语义随皮肤沿用） */
.ck-bay { position: relative; padding-left: 27px; }
.ck-bay::before {
  content: ""; position: absolute; left: 8px; top: 10px; bottom: 10px; width: 1px;
  background: linear-gradient(180deg, transparent, var(--border-glass) 12%, var(--border-glass) 88%, transparent);
  pointer-events: none;
}

/* 中轴：两段刻度线夹持轮换节点与轴向铭文（入场一次性） */
.ck-axis {
  display: flex; flex-direction: column; align-items: center; gap: 10px;
  padding: 6px 0;
  animation: reg-sec-in 0.5s var(--ease) both;
  animation-delay: 0.12s;
}
.ck-axis-rail {
  width: 1px; flex: 1;
  background: linear-gradient(180deg, transparent, var(--border-glass) 30%, var(--border-glass) 70%, transparent);
}
.ck-axis-node {
  display: flex; align-items: center; justify-content: center;
  width: 26px; height: 26px; flex-shrink: 0;
  color: rgba(var(--accent-rgb), 0.85);
}
.ck-axis-node svg { width: 100%; height: 100%; }
.ck-axis-word {
  flex-shrink: 0;
  writing-mode: vertical-rl;
  font-family: var(--font-mono); font-size: 10px; letter-spacing: 4px;
  color: var(--text-muted);
}

/* 凭据槽：密钥文件只读凭据位（令牌 + 选择端子，凹槽形与 reg-input 同族） */
.ck-slot {
  display: flex; align-items: center; gap: 8px; min-width: 0;
  padding: 3px 4px 3px 11px;
  background-color: rgba(var(--black-rgb), 0.34);
  border: 1px solid rgba(var(--white-rgb), 0.07);
  border-radius: 6px;
  box-shadow: inset 0 1px 2px rgba(var(--black-rgb), 0.3);
  transition:
    border-color var(--dur-fast) var(--ease),
    background-color var(--dur-fast) var(--ease);
}
.ck-slot:hover { border-color: rgba(var(--white-rgb), 0.12); }
.ck-slot:focus-within {
  border-color: rgba(var(--accent-rgb), 0.5);
  background-color: rgba(var(--black-rgb), 0.44);
}
.ck-slot-token {
  flex: 1; min-width: 0;
  font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.4px;
  color: var(--accent);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ck-slot.is-empty .ck-slot-token {
  color: var(--text-muted);
  font-family: var(--font); font-size: 12px; letter-spacing: 0.5px;
}
.ck-slot-pick {
  flex-shrink: 0; display: inline-flex; align-items: center; gap: 5px;
  padding: 4px 9px;
  background: none; border: 1px solid transparent; border-radius: 5px;
  color: var(--text-secondary); font-size: 11px; font-family: var(--font); letter-spacing: 0.5px;
  cursor: pointer;
  transition:
    color var(--dur-fast) var(--ease),
    border-color var(--dur-fast) var(--ease),
    background-color var(--dur-fast) var(--ease);
}
.ck-slot-pick svg { width: 12px; height: 12px; opacity: 0.85; }
.ck-slot-pick:hover:not(:disabled) {
  color: var(--accent);
  border-color: rgba(var(--accent-rgb), 0.24);
  background-color: rgba(var(--accent-rgb), 0.06);
}
.ck-slot-pick:focus-visible { outline: 1px solid var(--border-hover); outline-offset: 1px; }
.ck-slot-pick:disabled { cursor: not-allowed; opacity: 0.55; }

/* 失效读数带：危险语义走左缘竖标（静态裁定，无错误抖动） */
.ck-void {
  position: relative;
  display: flex; align-items: center; gap: 8px;
  margin-top: 18px;
  padding: 9px 12px 9px 14px;
  border: 1px solid rgba(var(--danger-rgb), 0.2);
  border-radius: 6px;
  background-color: rgba(var(--danger-rgb), 0.04);
  color: rgba(var(--danger-rgb), 0.85);
  font-size: 11px; letter-spacing: 0.4px;
  animation: reg-row-in 0.3s var(--ease) both;
}
.ck-void::before {
  content: ""; flex-shrink: 0; align-self: stretch;
  width: 2px; border-radius: 1px;
  background: var(--danger); opacity: 0.7;
}
.ck-void svg { width: 13px; height: 13px; flex-shrink: 0; opacity: 0.9; }

/* 窄窗口降级：双舱改单列，中轴横置为舱间分界 */
@media (max-width: 760px) {
  .ck-transit { grid-template-columns: minmax(0, 1fr); }
  .ck-axis { flex-direction: row; padding: 2px 4px; }
  .ck-axis-rail {
    width: auto; height: 1px; flex: 1;
    background: linear-gradient(90deg, transparent, var(--border-glass) 30%, var(--border-glass) 70%, transparent);
  }
  .ck-axis-word { writing-mode: horizontal-tb; letter-spacing: 2px; }
}

/* 无障碍：偏好减少动态时，一次性入场直接落到终态 */
@media (prefers-reduced-motion: reduce) {
  .ck-axis,
  .ck-void { animation: none; }
}
</style>