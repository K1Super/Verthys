<!--
  VaultItemDetailDialog.vue — 条目详情（只读全字段视图）

  形态：复用全局弹窗外壳 CosmicOverlay 与 kv-* 内容词汇。
        正文按字段分区逐行展示；敏感字段提供显隐与复制。

  为什么独立成窗口而不是继续扩展卡片：卡片固定为原始高度，只承载少数
  摘要字段；完整字段、长文本与全部敏感字段在详情窗口呈现。两者的投影分别由
  lib/vault_item_card 与 lib/vault_item_detail 承担，互不共用截断规则。

  关闭语义：遮罩空白、Esc 与动作区「关闭」均可关闭；本窗口只读、没有保存语义。

  用法:
    <VaultItemDetailDialog
      v-model="showDetail" :type-def="detailDef" :entry="detailEntry"
      @toggle="onDetailToggle" @copy="onDetailCopy"
    />
-->
<template>
  <CosmicOverlay
    :show="open"
    width="520px"
    aria-labelledby="vault-detail-title"
    @close="open = false"
  >
    <header class="detail-head">
      <span class="detail-mark" :style="markStyle" aria-hidden="true">
        <SafeSvgIcon v-if="def" class="detail-mark-icon" :source="resolveVaultIcon(def.icon)" />
      </span>
      <div class="detail-ident">
        <div class="kv-title" id="vault-detail-title">{{ panelTitle }}</div>
        <div class="detail-type">{{ def ? def.label : "存签" }}</div>
      </div>
    </header>

    <div class="kv-form detail-sheet">
      <section
        v-for="(section, sectionIndex) in sections"
        :key="`${sectionIndex}-${section.name}`"
        class="kv-section"
      >
        <div class="kv-section-label">
          <span class="detail-sec-no">{{ sectionNo(sectionIndex) }}</span>
          <span class="detail-sec-name">{{ section.name }}</span>
        </div>
        <div
          v-for="field in section.fields"
          :key="field.fieldId"
          class="detail-row"
          :class="{ 'is-block': field.multiline }"
        >
          <span class="kv-label detail-key">{{ field.label }}</span>
          <div class="detail-val">
            <template v-if="field.sensitive">
              <div class="detail-secret">
                <span class="kv-secret">{{ secretText(field) }}</span>
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
              </div>
            </template>
            <span v-else class="kv-value" :class="{ 'is-multiline': field.multiline }">{{ field.value }}</span>
            <span v-if="field.readout" class="kv-readout" :class="`is-${field.readout.tone}`">
              <i class="kv-readout-dot"></i>{{ field.readout.text }}
            </span>
          </div>
        </div>
      </section>

      <p v-if="sections.length === 0" class="kv-note detail-empty">暂无更多信息</p>
    </div>

    <div class="kv-actions detail-footer">
      <button class="btn btn-neutral btn-compact" type="button" @click="open = false">关闭</button>
    </div>
  </CosmicOverlay>
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
import CosmicOverlay from "../../common/cosmic/CosmicOverlay.vue";
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

/** 类型色调变量（头部标识着色） */
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
/* 头部：标识 / 标题 / 类型名构成身份读数；下缘以右向渐隐细线收束，
   标题区与字段区因此有明确分界，而不是标题直接压进第一分区 */
.detail-head {
  position: relative;
  display: flex;
  align-items: center;
  gap: 11px;
  padding-bottom: 15px;
}
.detail-head::after {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  bottom: 0;
  height: 1px;
  background: linear-gradient(
    90deg,
    rgba(205, 224, 244, 0.16),
    rgba(205, 224, 244, 0.04) 64%,
    transparent
  );
}
.detail-ident { min-width: 0; }
.detail-head .kv-title {
  margin-bottom: 0;
  line-height: 1.3;
  overflow-wrap: anywhere;
}
.detail-mark {
  flex-shrink: 0;
  width: 24px;
  height: 24px;
  color: rgb(var(--tone-rgb, var(--accent-rgb)));
}
.detail-mark-icon { display: block; width: 100%; height: 100%; }
.detail-mark-icon :deep(svg) { display: block; width: 100%; height: 100%; }
.detail-type {
  margin-top: 3px;
  font-size: 10px;
  line-height: 1.4;
  letter-spacing: 2px;
  color: rgba(132, 148, 168, 0.9);
}

/* 字段区：紧接头部细线开始；分区间距由 kv-section 的上边界承担 */
.detail-sheet { margin-top: 14px; }
/* 分区序号：与分区名同一主字体、同一字号，仅以等宽数字保持序号对齐 */
.detail-sec-no {
  font-size: 10px;
  font-variant-numeric: tabular-nums;
  letter-spacing: 1px;
  color: rgba(132, 148, 168, 0.55);
}

/* 字段行：标签列定宽、取值列随内容伸缩；行间细线是读数表的行隔，
   标签与取值不再上下堆成段落 */
.detail-row {
  display: grid;
  grid-template-columns: 88px minmax(0, 1fr);
  column-gap: 14px;
  align-items: baseline;
  padding: 9px 0;
}
.detail-row + .detail-row {
  border-top: 1px solid rgba(205, 224, 244, 0.055);
}
/* 多行文本：标签对齐首行，不随文本块垂直居中 */
.detail-row.is-block { align-items: start; }
/* 标签与取值同字号：主次由颜色与字距区分，不再用大小差制造层级 */
.detail-key {
  font-size: 12px;
  line-height: 1.6;
  overflow-wrap: anywhere;
}
.detail-val {
  display: flex;
  align-items: baseline;
  gap: 10px;
  min-width: 0;
}
/* 取值沿用同一字号；长值与多行文本仍按列宽断行 */
.detail-val .kv-value { font-size: 12px; }
/* 读数保持仪表语气：数字走等宽，中文回落项目主字体 ——
   等宽栈缺少 CJK 字形，整段交给它会让「永久有效」等状态词换成另一套汉字设计 */
.detail-val .kv-readout {
  flex-shrink: 0;
  font-family: "Cascadia Code", "Consolas", var(--font);
}

/* 敏感取值：与输入框同材质的凹槽通道，掩码/明文与显隐、复制同处一容器；
   通道已是一道边界，两个端子因此只留图标、不再各自画框 */
.detail-secret {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 1;
  min-width: 0;
  padding: 4px 4px 4px 11px;
  border-radius: 7px;
  background: linear-gradient(180deg, rgba(2, 5, 10, 0.38), rgba(2, 5, 10, 0.20));
  box-shadow:
    inset 0 1px 0 rgba(var(--black-rgb), 0.45),
    inset 0 -1px 0 rgba(205, 224, 244, 0.055);
}
/* 凭据值是专有等宽显示，字号与其它字段取值一致；中文同样回落主字体，
   避免「已加密」被等宽栈渲染成另一套汉字字形 */
.detail-secret .kv-secret {
  font-family: "Cascadia Code", "Consolas", var(--font);
  font-size: 12px;
  letter-spacing: 0.8px;
}
.detail-actions { display: flex; flex-shrink: 0; }
.detail-actions .icon-btn {
  width: 24px;
  height: 24px;
  border: 0;
  border-radius: 0;
  background: transparent;
}
.detail-actions .icon-btn:hover {
  border-color: transparent;
  background: transparent;
  color: var(--accent);
}
.detail-actions .icon-btn:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: -2px;
}
.detail-actions .icon-btn svg { width: 12px; height: 12px; }

/* 空态：没有字段时也给出一块明确区域，而不是一行悬空文字 */
.detail-empty {
  padding: 16px 12px;
  text-align: center;
  border: 1px solid rgba(205, 224, 244, 0.06);
  border-radius: 8px;
}

/* 动作区：与字段区以细线断开，关闭键不读作最后一个字段行 */
.detail-footer {
  padding-top: 14px;
  border-top: 1px solid rgba(205, 224, 244, 0.07);
}
</style>
