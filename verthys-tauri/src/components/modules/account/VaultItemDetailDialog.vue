<!--
  VaultItemDetailDialog.vue — 条目详情（只读全字段视图）

  形态：复用 VerthysDialog + 「凭证登记台」皮肤。头部显示类型与条目标题，
        正文按字段分区逐行展示；敏感字段提供显隐与复制。

  为什么独立成窗口而不是继续扩展卡片：卡片固定为原始高度，只承载少数
  摘要字段；完整字段、长文本与全部敏感字段在详情窗口呈现。两者的投影分别由
  lib/vault_item_card 与 lib/vault_item_detail 承担，互不共用截断规则。

  关闭语义：复用 VerthysDialog 的既有能力 —— 点击遮罩空白处、Esc、头部关闭键
  均可关闭；hide-actions 表示本窗口只读、没有保存语义。

  用法:
    <VaultItemDetailDialog
      v-model="showDetail" :type-def="detailDef" :entry="detailEntry"
      @toggle="onDetailToggle" @copy="onDetailCopy"
    />
-->
<template>
  <VerthysDialog
    v-model="open"
    :title="panelTitle"
    layout="plain"
    hide-actions
    class="reg-panel"
  >
    <template #header>
      <header class="reg-head">
        <span class="reg-mark detail-mark" :style="markStyle" aria-hidden="true">
          <SafeSvgIcon v-if="def" class="detail-mark-icon" :source="resolveVaultIcon(def.icon)" />
        </span>
        <span class="reg-heading">
          <span class="reg-kicker">{{ def ? def.label : "存签" }}</span>
          <span class="reg-title">{{ panelTitle }}</span>
        </span>
        <button class="reg-close" type="button" @click="open = false" aria-label="关闭窗口" v-tip="'关闭'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </header>
    </template>

    <div class="reg-body detail-body">
      <section
        v-for="(section, sectionIndex) in sections"
        :key="`${sectionIndex}-${section.name}`"
        class="reg-section"
        :style="{ '--rs': String(sectionIndex) }"
      >
        <div class="reg-sec-head">
          <span class="reg-sec-no">{{ sectionNo(sectionIndex) }}</span>
          <span class="reg-sec-name">{{ section.name }}</span>
          <span class="reg-rule"></span>
        </div>
        <div class="detail-rows">
          <div
            v-for="field in section.fields"
            :key="field.fieldId"
            class="reg-row detail-row"
          >
            <span class="reg-key">{{ field.label }}</span>
            <div class="detail-value-wrap">
              <template v-if="field.sensitive">
                <span class="detail-secret">{{ secretText(field) }}</span>
                <div class="detail-actions">
                  <button
                    class="icon-btn"
                    type="button"
                    @click="$emit('toggle', field.fieldId)"
                    :aria-label="entry?.secretVisible ? `隐藏${field.label}` : `显示${field.label}`"
                    v-tip="entry?.secretVisible ? '隐藏' : '显示'"
                  >
                    <svg v-if="!entry?.secretVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                  </button>
                  <button
                    class="icon-btn"
                    type="button"
                    @click="$emit('copy', field.fieldId)"
                    :aria-label="`复制${field.label}`"
                    v-tip="'复制'"
                  >
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  </button>
                </div>
              </template>
              <span v-else class="detail-value" :class="{ 'is-multiline': field.multiline }">{{ field.value }}</span>
              <span v-if="field.readout" class="reg-readout" :class="`is-${field.readout.tone}`">
                <i class="reg-readout-dot"></i>{{ field.readout.text }}
              </span>
            </div>
          </div>
        </div>
      </section>

      <p v-if="sections.length === 0" class="detail-empty">暂无更多信息</p>
    </div>
  </VerthysDialog>
</template>

<script setup lang="ts">
import { computed } from "vue";
import type { VaultEntry } from "../../../types/verthys";
import type { VaultTypeDef } from "../../../constants/vault_item_types";
import { resolveVaultIcon } from "../../../constants/vault_item_types";
import type { VaultDetailField } from "../../../lib/vault_item_detail";
import { buildVaultDetailSections } from "../../../lib/vault_item_detail";
import {
  VAULT_TONE_RGB_VARS,
  vaultItemTitle,
  vaultSecretText,
} from "../../../lib/vault_item_card";
import VerthysDialog from "../../common/verthys-ui/VerthysDialog.vue";
import SafeSvgIcon from "../../common/SafeSvgIcon.vue";

const props = defineProps<{
  modelValue: boolean;
  /** 目标类型定义；缺失时不渲染字段（调用方不得对未知类型打开详情） */
  typeDef: VaultTypeDef | null;
  /** 目标条目；关闭过程中可能短暂为空 */
  entry: VaultEntry | null;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", val: boolean): void;
  (e: "toggle", fieldId: string): void;
  (e: "copy", fieldId: string): void;
}>();

const open = computed({
  get: () => props.modelValue,
  set: (val: boolean) => emit("update:modelValue", val),
});

const def = computed(() => props.typeDef);

/** 头部标题：条目主标题优先，缺失时回落到类型名 */
const panelTitle = computed(() => {
  if (!def.value) return "";
  const title = props.entry ? vaultItemTitle(props.entry.data, def.value) : "";
  return title || def.value.label;
});

/** 类型色调变量（头部徽记着色） */
const markStyle = computed<Record<string, string>>(() => {
  const style: Record<string, string> = {};
  if (def.value) style["--tone-rgb"] = `var(${VAULT_TONE_RGB_VARS[def.value.tone]})`;
  return style;
});

/** 详情分区投影：全部字段（不限 cardFields），空值与 transient 字段不占行 */
const sections = computed(() =>
  props.entry ? buildVaultDetailSections(props.entry.data, def.value ?? undefined) : [],
);

const sectionNo = (index: number): string => String(index + 1).padStart(2, "0");

/** 敏感字段展示文本：与卡片共用同一掩码/明文口径 */
const secretText = (field: VaultDetailField): string =>
  props.entry
    ? vaultSecretText({
        visible: props.entry.secretVisible,
        plain: props.entry.plainSecrets?.[field.fieldId],
        encrypted: field.encrypted,
        raw: field.value,
      })
    : "";
</script>

<style scoped>
/* 登记区自行留出下缘安全距离（只读窗口无动作区） */
.detail-body { padding-bottom: 18px; }

/* 头部徽记取类型色调（与卡片右上角类型标识同一色源） */
.detail-mark { color: rgb(var(--tone-rgb, var(--accent-rgb))); }
.detail-mark-icon { display: block; width: 100%; height: 100%; }
.detail-mark-icon :deep(svg) { display: block; width: 100%; height: 100%; }

/* 详情行：标签右对齐 + 值左伸；标签只作说明，不承接点击 */
.detail-row { align-items: start; }
.detail-row .reg-key { padding-top: 2px; cursor: default; }
.detail-value-wrap {
  display: flex; align-items: flex-start; gap: 10px;
  min-width: 0;
}
.detail-value {
  flex: 1; min-width: 0;
  font-size: 13px; line-height: 1.6;
  color: var(--text-primary); font-family: var(--font);
  overflow-wrap: anywhere;
}
.detail-value.is-multiline { white-space: pre-wrap; }
.detail-secret {
  flex: 1; min-width: 0;
  font-family: var(--font-mono); font-size: 12.5px; letter-spacing: 1px;
  color: var(--text-secondary);
  overflow-wrap: anywhere;
}
.detail-actions { display: flex; gap: 2px; flex-shrink: 0; }
.detail-actions .icon-btn { width: 24px; height: 24px; }
.detail-actions .icon-btn svg { width: 12px; height: 12px; }
.detail-value-wrap .reg-readout { flex-shrink: 0; padding-top: 2px; }

.detail-empty {
  font-size: 12px; color: var(--text-muted); font-family: var(--font);
  padding: 4px 0 2px;
}
</style>
