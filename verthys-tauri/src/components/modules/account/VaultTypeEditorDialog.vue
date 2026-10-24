<!--
  VaultTypeEditorDialog.vue — 自定义条目类型管理（类型 + 字段构建器）
  形态：复用 VerthysDialog + 「凭证登记台」皮肤；顶部为自定义类型标签条（含新建），
        下方为当前类型的声明编辑区（标识 / 字段 / 展示与搜索）。
  语义：类型集合作为单条设置记录整体保存（先写新记录、再删除被替换的旧记录）；
        删除类型不删除条目——既有条目按未知类型兜底展示并可在之后重新指派类型。
  用法:
    <VaultTypeEditorDialog v-model="showEditor" :types="customTypes" :entry-count-of="countOf" @saved="reloadTypes" />
-->
<template>
  <VerthysDialog
    v-model="open"
    title="自定义类型"
    layout="plain"
    class="reg-panel type-editor"
    save-label="保存类型"
    :saving="saving"
    @save="onSave"
  >
    <template #header>
      <header class="reg-head">
        <span class="reg-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="2" fill="currentColor" stroke="none" />
            <circle cx="12" cy="12" r="5.4" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-dasharray="25.5 8.4" transform="rotate(38 12 12)" opacity="0.8" />
            <circle cx="12" cy="12" r="8.6" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-dasharray="38.6 15.4" transform="rotate(-76 12 12)" opacity="0.45" />
          </svg>
        </span>
        <span class="reg-heading">
          <span class="reg-kicker">存签</span>
          <span class="reg-title">自定义类型</span>
        </span>
        <button class="reg-close" type="button" @click="open = false" aria-label="关闭窗口" v-tip="'关闭'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </header>
    </template>

    <div class="reg-body">
      <!-- 01 类型集：切换当前编辑的类型，或新建一个类型 -->
      <section class="reg-section" :style="{ '--rs': '0' }">
        <div class="reg-sec-head">
          <span class="reg-sec-no">01</span>
          <span class="reg-sec-name">类型集</span>
          <span class="reg-rule"></span>
        </div>
        <div class="editor-tabs">
          <button
            v-for="(item, index) in draft"
            :key="item.id"
            type="button"
            class="editor-tab"
            :aria-pressed="index === activeIndex"
            :data-on="index === activeIndex ? '1' : '0'"
            @click="activeIndex = index"
          >{{ item.label || "未命名类型" }}</button>
          <button type="button" class="editor-tab editor-tab-add" @click="addType">＋ 新建类型</button>
        </div>
      </section>

      <template v-if="active">
        <!-- 02 标识：名称 / 图标 / 色调 -->
        <section class="reg-section" :style="{ '--rs': '1' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">02</span>
            <span class="reg-sec-name">标识</span>
            <span class="reg-rule"></span>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="vt-f-label">名称</label>
            <input id="vt-f-label" class="reg-input" v-model="active.label" />
          </div>
          <div class="reg-row">
            <span class="reg-key">图标</span>
            <div class="editor-chips">
              <button
                v-for="iconId in iconIds"
                :key="iconId"
                type="button"
                class="icon-chip"
                :aria-pressed="active.icon === iconId"
                :data-on="active.icon === iconId ? '1' : '0'"
                :aria-label="iconId"
                v-tip="iconId"
                @click="active.icon = iconId"
              >
                <SafeSvgIcon class="icon-chip-mark" :source="resolveVaultIcon(iconId)" />
              </button>
            </div>
          </div>
          <div class="reg-row">
            <span class="reg-key">色调</span>
            <div class="editor-chips">
              <button
                v-for="tone in toneIds"
                :key="tone"
                type="button"
                class="tone-chip"
                :aria-pressed="active.tone === tone"
                :data-on="active.tone === tone ? '1' : '0'"
                :style="{ '--tone-rgb': `var(${VAULT_TONE_RGB_VARS[tone]})` }"
                @click="active.tone = tone"
              >{{ toneLabels[tone] }}</button>
            </div>
          </div>
        </section>

        <!-- 03 字段：字段清单构建（增删、排序、控件种类与属性） -->
        <section class="reg-section" :style="{ '--rs': '2' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">03</span>
            <span class="reg-sec-name">字段</span>
            <span class="reg-rule"></span>
          </div>
          <div v-for="(field, index) in active.fields" :key="field.id" class="field-row">
            <div class="field-row-head">
              <span class="field-index">{{ index + 1 }}</span>
              <input class="reg-input field-label" v-model="field.label" aria-label="字段名" />
              <select class="reg-input reg-select field-kind" :value="field.kind" aria-label="控件种类" @change="onFieldKindChange(field, $event)">
                <option v-for="kind in fieldKinds" :key="kind.id" :value="kind.id">{{ kind.label }}</option>
              </select>
              <div class="field-tools">
                <button type="button" class="icon-btn" :disabled="index === 0" aria-label="上移" v-tip="'上移'" @click="moveField(index, -1)">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="6 15 12 9 18 15"/></svg>
                </button>
                <button type="button" class="icon-btn" :disabled="index === active.fields.length - 1" aria-label="下移" v-tip="'下移'" @click="moveField(index, 1)">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="6 9 12 15 18 9"/></svg>
                </button>
                <button type="button" class="icon-btn" aria-label="删除字段" v-tip="'删除字段'" @click="removeField(index)">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
              </div>
            </div>
            <div class="field-row-body">
              <label class="field-flag">
                <input type="checkbox" v-model="field.required" /> 必填
              </label>
              <label class="field-flag">
                <input type="checkbox" v-model="field.sensitive" /> 敏感
              </label>
              <label class="field-flag">
                <input type="checkbox" v-model="field.carrier" /> 内容舱
              </label>
              <input
                v-if="field.kind === 'select'"
                class="reg-input field-options"
                :value="(field.options ?? []).join(' | ')"
                placeholder="候选项，以 | 分隔"
                aria-label="候选项"
                @change="onOptionsChange(field, $event)"
              />
            </div>
          </div>
          <button type="button" class="editor-add" @click="addField">＋ 添加字段</button>
        </section>

        <!-- 04 展示：主标题 / 卡片次行 / 搜索字段 -->
        <section class="reg-section" :style="{ '--rs': '3' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">04</span>
            <span class="reg-sec-name">展示</span>
            <span class="reg-rule"></span>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="vt-f-title">主标题</label>
            <select id="vt-f-title" class="reg-input reg-select" v-model="active.titleField">
              <option value="">未指定</option>
              <option v-for="field in active.fields" :key="field.id" :value="field.id">{{ field.label }}</option>
            </select>
          </div>
          <div class="reg-row">
            <span class="reg-key">卡片次行</span>
            <div class="editor-chips">
              <button
                v-for="field in active.fields"
                :key="field.id"
                type="button"
                class="filter-chip"
                :aria-pressed="active.cardFields.includes(field.id)"
                :data-on="active.cardFields.includes(field.id) ? '1' : '0'"
                @click="toggleCardField(field.id)"
              >{{ field.label }}</button>
            </div>
          </div>
          <div class="reg-row">
            <span class="reg-key">搜索字段</span>
            <div class="editor-chips">
              <button
                v-for="field in active.fields"
                :key="field.id"
                type="button"
                class="filter-chip"
                :aria-pressed="active.searchFields.includes(field.id)"
                :data-on="active.searchFields.includes(field.id) ? '1' : '0'"
                @click="toggleSearchField(field.id)"
              >{{ field.label }}</button>
            </div>
          </div>
        </section>

        <div class="editor-danger">
          <button type="button" class="editor-delete" @click="askRemoveType">删除该类型</button>
          <span class="editor-hint">删除类型不会删除条目；既有条目将按未知类型展示</span>
        </div>
      </template>

      <p v-else class="editor-empty">暂无自定义类型，点击上方「新建类型」开始创建</p>
    </div>

    <template #error v-if="errorText">
      <div class="reg-error">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        {{ errorText }}
      </div>
    </template>
  </VerthysDialog>

  <!-- 删除类型二次确认：已有该类型条目时给出条目数，说明条目不会被删除 -->
  <ConfirmDelete
    :show="showRemoveConfirm"
    :item-name="removeConfirmName"
    @confirm="confirmRemoveType"
    @cancel="showRemoveConfirm = false"
  />
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type {
  VaultFieldDef,
  VaultFieldKind,
  VaultIconId,
  VaultTone,
  VaultTypeDef,
} from "../../../constants/vault_item_types";
import {
  BUILTIN_VAULT_TYPE_IDS,
  CUSTOM_VAULT_TYPE_PREFIX,
  MAX_VAULT_CARD_FIELDS,
  VAULT_FIELD_KINDS,
  VAULT_TONES,
  createCustomFieldId,
  createCustomRangeStartId,
  createCustomVaultTypeId,
  resolveVaultIcon,
} from "../../../constants/vault_item_types";
import { VAULT_ICON_LIBRARY } from "../../../constants/vault_item_types";
import { VAULT_TONE_RGB_VARS } from "../../../lib/vault_item_card";
import { saveCustomVaultTypes, validateVaultTypeDefs } from "../../../lib/vault_item_type_store";
import VerthysDialog from "../../common/verthys-ui/VerthysDialog.vue";
import ConfirmDelete from "../../common/verthys-ui/ConfirmDelete.vue";
import SafeSvgIcon from "../../common/SafeSvgIcon.vue";

/** 卡片次行字段上限（与卡片映射、存储截断同取单一权威源） */
const MAX_CARD_FIELDS = MAX_VAULT_CARD_FIELDS;

/** 字段控件种类的中文名（键集必须覆盖全部种类 — 漏项在编译期即报错） */
const fieldKindLabels: Record<VaultFieldKind, string> = {
  text: "单行文本",
  password: "密码",
  multiline: "多行文本",
  date: "日期",
  dateRange: "日期区间",
  select: "选项",
  region: "地区",
  switch: "开关",
};

/** 面板下拉项：顺序与权威源一致 */
const fieldKinds: readonly { id: VaultFieldKind; label: string }[] = VAULT_FIELD_KINDS.map(
  (id) => ({ id, label: fieldKindLabels[id] }),
);

/** 色调中文名（键集必须覆盖全部色调） */
const toneLabels: Record<VaultTone, string> = {
  accent: "青",
  purple: "紫",
  success: "绿",
  warning: "橙",
  danger: "红",
};

const toneIds = VAULT_TONES;
const iconIds = Object.keys(VAULT_ICON_LIBRARY) as VaultIconId[];

const props = defineProps<{
  modelValue: boolean;
  /** 当前容器内的自定义类型定义（打开时作为编辑初值） */
  types: readonly VaultTypeDef[];
  /** 指定类型的条目数量（删除类型时用于提示影响范围） */
  entryCountOf: (kind: string) => number;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", val: boolean): void;
  /** 类型集合已保存并落盘（调用方据此刷新类型索引） */
  (e: "saved", types: VaultTypeDef[]): void;
}>();

const open = computed({
  get: () => props.modelValue,
  set: (val: boolean) => emit("update:modelValue", val),
});

/** 编辑副本：只在保存时整体写回，中途关闭不产生副作用 */
const draft = ref<VaultTypeDef[]>([]);
const activeIndex = ref(0);
const errorText = ref("");
const saving = ref(false);
const showRemoveConfirm = ref(false);

const active = computed<VaultTypeDef | null>(() => draft.value[activeIndex.value] ?? null);

/** 打开时以当前自定义类型重建编辑副本（逐层深拷贝 — 关闭不保存即零副作用） */
watch(
  () => props.modelValue,
  (val) => {
    if (!val) return;
    draft.value = props.types.map((item) => ({
      ...item,
      // 展示字段 / 搜索字段是数组：必须复制数组本体，否则下方切换会原地改写
      // props 里的同一数组 —— 用户点「关闭」不保存，父级数据却已经被改了
      cardFields: [...item.cardFields],
      searchFields: [...item.searchFields],
      fields: item.fields.map((field) => ({
        ...field,
        ...(field.options ? { options: [...field.options] } : {}),
      })),
    }));
    activeIndex.value = 0;
    errorText.value = "";
    saving.value = false;
    showRemoveConfirm.value = false;
  },
);

/** 新建类型：以一个可用的空壳开始，字段 id 与类型 id 均按标识规则生成 */
const addType = (): void => {
  const firstField: VaultFieldDef = { id: "f_field", label: "字段", kind: "text" };
  draft.value = [
    ...draft.value,
    {
      id: createCustomVaultTypeId(),
      label: "新类型",
      icon: "generic",
      tone: "accent",
      titleField: firstField.id,
      cardFields: [],
      searchFields: [firstField.id],
      fields: [firstField],
      builtin: false,
    },
  ];
  activeIndex.value = draft.value.length - 1;
  errorText.value = "";
};

const addField = (): void => {
  const current = active.value;
  if (!current) return;
  // 区间起始键与字段 id 共用落盘表：新字段 id 必须同时避开这两类键
  const used = current.fields
    .flatMap((field) => [field.id, field.rangeStartId ?? ""])
    .filter((key) => key.length > 0);
  const field: VaultFieldDef = { id: createCustomFieldId("字段", used), label: "字段", kind: "text" };
  current.fields = [...current.fields, field];
};

/**
 * 切换字段控件种类。
 *
 * 日期区间必须成对落盘：首次切到区间时生成起始键；离开区间时移除区间专属
 * 声明，避免留下一对「有起始键却没有控件」的孤儿状态。字段 id 与起始键都
 * 只在生成时赋值，之后不随字段改名。
 */
const onFieldKindChange = (field: VaultFieldDef, event: Event): void => {
  const kind = (event.target as HTMLSelectElement).value as VaultFieldKind;
  field.kind = kind;
  if (kind === "dateRange") {
    if (!field.rangeStartId) {
      const used = (active.value?.fields ?? [])
        .flatMap((item) => [item.id, item.rangeStartId ?? ""])
        .filter((key) => key.length > 0);
      field.rangeStartId = createCustomRangeStartId(field.id, used);
    }
    return;
  }
  delete field.rangeStartId;
  delete field.rangeStartLabel;
  delete field.rangeEndLabel;
};

const removeField = (index: number): void => {
  const current = active.value;
  if (!current || current.fields.length <= 1) return;
  const removedId = current.fields[index]?.id;
  current.fields = current.fields.filter((_, i) => i !== index);
  // 被删字段不得残留在主标题、卡片次行与搜索字段中，否则卡片会取到空值
  if (removedId) {
    if (current.titleField === removedId) current.titleField = current.fields[0]?.id ?? "";
    current.cardFields = current.cardFields.filter((id) => id !== removedId);
    current.searchFields = current.searchFields.filter((id) => id !== removedId);
  }
};

const moveField = (index: number, delta: number): void => {
  const current = active.value;
  if (!current) return;
  const target = index + delta;
  if (target < 0 || target >= current.fields.length) return;
  const next = [...current.fields];
  const [item] = next.splice(index, 1);
  next.splice(target, 0, item);
  current.fields = next;
};

/** 候选项输入：以竖线分隔，空项丢弃 */
const onOptionsChange = (field: VaultFieldDef, e: Event): void => {
  const value = (e.target as HTMLInputElement).value;
  field.options = value
    .split("|")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
};

/** 多选成员切换（纯函数：返回新数组，绝不原地改写调用方数组） */
const toggledMember = (list: readonly string[], id: string, limit?: number): string[] => {
  if (list.includes(id)) return list.filter((item) => item !== id);
  if (limit !== undefined && list.length >= limit) return [...list];
  return [...list, id];
};

/** 切换卡片次行字段（上限内增删；赋值回 draft，父级 props 不受影响） */
const toggleCardField = (id: string): void => {
  const current = active.value;
  if (!current) return;
  current.cardFields = toggledMember(current.cardFields, id, MAX_CARD_FIELDS);
};

/** 切换搜索字段 */
const toggleSearchField = (id: string): void => {
  const current = active.value;
  if (!current) return;
  current.searchFields = toggledMember(current.searchFields, id);
};

const removeConfirmName = computed(() => {
  const current = active.value;
  if (!current) return "";
  const count = props.entryCountOf(current.id);
  if (count > 0) return `${current.label} · 该类型下 ${count} 条条目将保留`;
  return current.label;
});

const askRemoveType = (): void => {
  if (!active.value) return;
  showRemoveConfirm.value = true;
};

const confirmRemoveType = (): void => {
  const current = active.value;
  if (current) {
    draft.value = draft.value.filter((item) => item.id !== current.id);
    activeIndex.value = Math.min(activeIndex.value, Math.max(draft.value.length - 1, 0));
  }
  showRemoveConfirm.value = false;
};

const onSave = async (): Promise<void> => {
  const types = draft.value;
  const errors = validateVaultTypeDefs(types, BUILTIN_VAULT_TYPE_IDS);
  if (errors.length > 0) {
    errorText.value = errors[0];
    return;
  }
  // 主标题缺失属于结构问题：校验函数已覆盖，此处仅兜底阻止写入
  if (types.some((item) => !item.id.startsWith(CUSTOM_VAULT_TYPE_PREFIX))) {
    errorText.value = `类型 id 必须以 ${CUSTOM_VAULT_TYPE_PREFIX} 开头`;
    return;
  }

  errorText.value = "";
  saving.value = true;
  try {
    const result = await saveCustomVaultTypes(types);
    if (!result.ok) {
      errorText.value = "保存失败，请重试";
      saving.value = false;
      return;
    }
    emit("saved", types);
    if (result.persisted) {
      open.value = false;
    } else {
      errorText.value = "类型已写入但落盘失败，请勿关闭应用并重试保存";
    }
  } catch {
    errorText.value = "保存失败，请重试";
  } finally {
    saving.value = false;
  }
};
</script>

<style scoped>
.type-editor { min-width: 640px; }

/* 类型集标签条 */
.editor-tabs { display: flex; flex-wrap: wrap; gap: 6px; }
.editor-tab {
  padding: 4px 10px;
  background: rgba(var(--white-rgb), 0.02);
  border: 1px solid var(--border-glass); border-radius: 10px;
  color: var(--text-secondary); font-size: 11px; letter-spacing: 0.5px; font-family: var(--font);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}
.editor-tab:hover { color: var(--text-primary); border-color: var(--border-hover); }
.editor-tab[data-on="1"] { color: var(--accent); border-color: rgba(var(--accent-rgb), 0.28); background: rgba(var(--accent-rgb), 0.06); }
.editor-tab-add { color: var(--text-muted); }

/* 图标 / 色调选择条 */
.editor-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.icon-chip {
  display: flex; align-items: center; justify-content: center;
  width: 26px; height: 26px; padding: 0;
  background: rgba(var(--white-rgb), 0.02);
  border: 1px solid var(--border-glass); border-radius: var(--radius-sm);
  color: var(--text-secondary); cursor: pointer;
}
.icon-chip-mark { width: 14px; height: 14px; }
.icon-chip-mark :deep(svg) { width: 100%; height: 100%; }
.icon-chip[data-on="1"] { color: var(--accent); border-color: rgba(var(--accent-rgb), 0.28); background: rgba(var(--accent-rgb), 0.06); }
.tone-chip {
  padding: 4px 10px;
  background: rgba(var(--tone-rgb, var(--accent-rgb)), 0.04);
  border: 1px solid rgba(var(--tone-rgb, var(--accent-rgb)), 0.2); border-radius: 10px;
  color: rgb(var(--tone-rgb, var(--accent-rgb)));
  font-size: 11px; font-family: var(--font); cursor: pointer;
}
.tone-chip[data-on="1"] { border-color: rgb(var(--tone-rgb, var(--accent-rgb))); }

/* 字段构建行 */
.field-row {
  margin-top: 10px; padding: 9px 10px;
  background: rgba(var(--white-rgb), 0.015);
  border: 1px solid var(--border-glass); border-radius: var(--radius-sm);
}
.field-row-head { display: flex; align-items: center; gap: 8px; }
.field-index {
  flex-shrink: 0; width: 14px;
  font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);
}
.field-label { flex: 1; }
.field-kind { flex: 0 0 96px; }
.field-tools { display: flex; gap: 2px; flex-shrink: 0; }
.field-tools .icon-btn { width: 22px; height: 22px; }
.field-tools .icon-btn svg { width: 12px; height: 12px; }
.field-tools .icon-btn:disabled { cursor: not-allowed; opacity: 0.4; }
.field-row-body { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; margin-top: 8px; padding-left: 22px; }
.field-flag {
  display: inline-flex; align-items: center; gap: 4px;
  font-size: 11px; color: var(--text-secondary); font-family: var(--font);
  cursor: pointer;
}
.field-options { flex: 1; min-width: 160px; }

.editor-add {
  margin-top: 10px; padding: 5px 12px;
  background: none; border: 1px dashed var(--border-glass); border-radius: 6px;
  color: var(--text-secondary); font-size: 11px; font-family: var(--font);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}
.editor-add:hover { color: var(--accent); border-color: var(--border-hover); }

.editor-danger {
  display: flex; align-items: center; gap: 12px;
  margin-top: 18px; padding-top: 12px;
  border-top: 1px solid var(--border-glass);
}
.editor-delete {
  padding: 4px 12px;
  background: none; border: 1px solid rgba(var(--danger-rgb), 0.28); border-radius: 6px;
  color: var(--danger); font-size: 11px; font-family: var(--font); cursor: pointer;
}
.editor-delete:hover { border-color: var(--danger); }
.editor-hint { font-size: 10.5px; color: var(--text-muted); font-family: var(--font); }

.editor-empty { font-size: 12px; color: var(--text-muted); font-family: var(--font); }
</style>
