<!--
  VaultTypeEditorDialog.vue — 自定义条目类型工作台

  形态：左侧类型轨（切换 / 新建 / 删除）+ 右侧单类型编辑区。
    右侧固定头部（类型标识与名称）与动作区，只有字段与展示配置滚动，
    长字段清单不再把整个弹窗撑成一条长表。

  字段编辑：每行只保留「序号 / 字段名 / 控件种类 / 状态标记 / 工具」，
    必填、敏感、内容舱、分区、行数、区间标签、开关说明等属性收进
    按字段展开的配置面板；候选项用可增删的列表编辑，不再靠竖线分隔。

  数据约束（与 lib/vault_item_type_store 的清洗、校验同源）：
    - 主标题与搜索字段必须是明文可读字段；敏感字段不得充当标题或参与搜索；
    - 卡片次行排除主标题、敏感字段与到期字段；
    - 内容舱只属于多行文本；日期区间必须成对声明起始键；
    - 选项字段至少保留一个非空候选项，且候选项不得重复。

  保存语义：整批类型定义一次落盘；中途关闭不写回任何改动。
  用法:
    <VaultTypeEditorDialog v-model="showEditor" :types="customTypes" @saved="reloadTypes" />
-->
<template>
  <CosmicOverlay
    :show="open"
    width="min(900px, 94vw)"
    :persistent="saving"
    aria-labelledby="vte-title"
    @close="open = false"
  >
    <div class="kv-title" id="vte-title">自定义类型</div>

    <div class="editor-shell">
      <!-- 类型轨：切换、新建与删除都离开正文，避免与字段编辑混在一起 -->
      <aside class="type-rail">
        <div class="rail-head">
          <span>类型</span>
          <span class="rail-count">{{ String(draft.length).padStart(2, "0") }}</span>
        </div>

        <div class="rail-list">
          <button
            v-for="(item, index) in draft"
            :key="item.id"
            type="button"
            class="rail-item"
            :data-on="index === activeIndex ? '1' : '0'"
            :aria-label="isTypeDirty(item) ? `${item.label || '未命名类型'}，有未保存修改` : undefined"
            @click="selectType(index)"
          >
            <span
              class="rail-mark"
              :style="{ '--tone-rgb': `var(${VAULT_TONE_RGB_VARS[item.tone]})` }"
              aria-hidden="true"
            >
              <SafeSvgIcon :source="resolveVaultIcon(item.icon)" />
            </span>
            <span class="rail-name">{{ item.label || "未命名类型" }}</span>
            <span
              v-if="isTypeDirty(item)"
              class="rail-dirty"
              v-tip="'有未保存修改'"
              aria-hidden="true"
            ></span>
          </button>
          <button type="button" class="rail-add" @click="addType">＋ 新建类型</button>
        </div>

        <div class="rail-foot">
          <button
            type="button"
            class="btn btn-destructive btn-compact rail-remove"
            :disabled="!active"
            @click="askRemoveType"
          >删除该类型</button>
          <p class="rail-note">删除类型不会删除条目；确认后点击保存生效</p>
        </div>
      </aside>

      <!-- 当前类型：头部与动作区固定，只有正文滚动 -->
      <section class="type-main">
        <template v-if="active">
          <header class="type-head">
          <span
            class="type-mark"
            :style="{ '--tone-rgb': `var(${VAULT_TONE_RGB_VARS[active.tone]})` }"
            aria-hidden="true"
          >
            <SafeSvgIcon :source="resolveVaultIcon(active.icon)" />
          </span>
          <input
            ref="typeTitleRef"
            v-model="active.label"
            class="type-title-input"
            autocomplete="off"
            placeholder="未命名类型"
            aria-label="类型名"
          />
        </header>

        <div class="type-body">
          <!-- 01 外观：只保留图标与色调，名称由头部承担 -->
          <section class="kv-section">
            <div class="kv-section-label">01 外观</div>
            <div class="kv-field">
              <span class="kv-label">图标</span>
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
            <div class="kv-field">
              <span class="kv-label">色调</span>
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

          <!-- 02 字段：紧凑行 + 按需展开的属性面板 -->
          <section class="kv-section">
            <div class="kv-section-label">02 字段</div>

            <div class="field-table">
              <div
                v-for="(field, index) in active.fields"
                :key="field.id"
                class="field-entry"
                :class="{ 'is-open': openFieldId === field.id }"
              >
                <div class="field-line">
                  <span class="field-no">{{ String(index + 1).padStart(2, "0") }}</span>
                  <input
                    class="kv-input field-label-input"
                    v-model="field.label"
                    autocomplete="off"
                    placeholder="字段名"
                    aria-label="字段名"
                  />
                  <VaultSelect
                    class="field-kind"
                    compact
                    :model-value="field.kind"
                    :options="fieldKindOptions"
                    :allow-empty="false"
                    aria-label="控件种类"
                    @update:model-value="onFieldKindChange(field, $event)"
                  />
                  <div class="field-marks" aria-hidden="true">
                    <span v-if="field.required" class="field-mark">必填</span>
                    <span v-if="field.sensitive" class="field-mark is-sensitive">敏感</span>
                    <span v-if="field.carrier" class="field-mark">内容舱</span>
                  </div>
                  <div class="field-tools">
                    <button
                      type="button"
                      class="icon-btn field-toggle"
                      :aria-expanded="openFieldId === field.id"
                      :aria-label="openFieldId === field.id ? '收起字段设置' : '展开字段设置'"
                      v-tip="'字段设置'"
                      @click="toggleField(field.id, $event)"
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="6 9 12 15 18 9" /></svg>
                    </button>
                    <button
                      type="button"
                      class="icon-btn"
                      :disabled="index === 0"
                      aria-label="上移"
                      v-tip="'上移'"
                      @click="moveField(index, -1)"
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="6 15 12 9 18 15" /></svg>
                    </button>
                    <button
                      type="button"
                      class="icon-btn"
                      :disabled="index === active.fields.length - 1"
                      aria-label="下移"
                      v-tip="'下移'"
                      @click="moveField(index, 1)"
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="6 9 12 15 18 9" /></svg>
                    </button>
                    <button
                      type="button"
                      class="icon-btn"
                      :disabled="active.fields.length <= 1"
                      aria-label="删除字段"
                      v-tip="'删除字段'"
                      @click="removeField(index)"
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                    </button>
                  </div>
                </div>

                <div v-if="openFieldId === field.id" class="field-panel">
                  <div class="field-flags">
                    <label class="kf-toggle" :class="{ 'kf-toggle--on': field.required }">
                      <input type="checkbox" v-model="field.required" />
                      <span class="kf-box" aria-hidden="true"></span>
                      <span class="kf-text">必填</span>
                    </label>
                    <label class="kf-toggle" :class="{ 'kf-toggle--on': field.sensitive }">
                      <input
                        type="checkbox"
                        :checked="field.sensitive === true"
                        @change="onSensitiveChange(field, $event)"
                      />
                      <span class="kf-box" aria-hidden="true"></span>
                      <span class="kf-text">敏感</span>
                    </label>
                    <label
                      v-if="field.kind === 'multiline'"
                      class="kf-toggle"
                      :class="{ 'kf-toggle--on': field.carrier }"
                    >
                      <input type="checkbox" v-model="field.carrier" />
                      <span class="kf-box" aria-hidden="true"></span>
                      <span class="kf-text">内容舱</span>
                    </label>
                  </div>

                  <div class="field-props">
                    <div class="kv-field field-prop field-prop-wide">
                      <label class="kv-label">分区</label>
                      <input
                        class="kv-input"
                        v-model="field.group"
                        autocomplete="off"
                        placeholder="留空则归入类型分区"
                        aria-label="分区"
                      />
                      <p class="kv-hint">相邻同名字段会合并为一个分区</p>
                    </div>

                    <div v-if="field.kind === 'multiline'" class="kv-field field-prop">
                      <label class="kv-label">行数</label>
                      <input
                        class="kv-input"
                        type="number"
                        autocomplete="off"
                        min="1"
                        max="12"
                        :value="field.multilineRows ?? 2"
                        aria-label="行数"
                        @change="onRowsCommit(field, $event)"
                      />
                    </div>

                    <div
                      v-if="field.kind === 'switch'"
                      class="kv-field field-prop field-prop-wide"
                    >
                      <label class="kv-label">开关说明</label>
                      <input
                        class="kv-input"
                        v-model="field.hint"
                        autocomplete="off"
                        placeholder="留空不显示"
                        aria-label="开关说明"
                      />
                    </div>

                    <template v-if="field.kind === 'dateRange'">
                      <div class="kv-field field-prop">
                        <label class="kv-label">起始标签</label>
                        <input
                          class="kv-input"
                          v-model="field.rangeStartLabel"
                          autocomplete="off"
                          placeholder="自"
                          aria-label="起始标签"
                        />
                      </div>
                      <div class="kv-field field-prop">
                        <label class="kv-label">结束标签</label>
                        <input
                          class="kv-input"
                          v-model="field.rangeEndLabel"
                          autocomplete="off"
                          placeholder="至"
                          aria-label="结束标签"
                        />
                      </div>
                    </template>
                  </div>

                  <div v-if="field.kind === 'select'" class="field-options-editor">
                    <span class="kv-label">候选项</span>
                    <div class="option-list">
                      <div
                        v-for="(option, optionIndex) in field.options ?? []"
                        :key="optionIndex"
                        class="option-row"
                      >
                        <span class="option-no">{{ String(optionIndex + 1).padStart(2, "0") }}</span>
                        <input
                          class="kv-input option-input"
                          :value="option"
                          autocomplete="off"
                          aria-label="候选项"
                          @input="onOptionInput(field, optionIndex, $event)"
                        />
                        <button
                          type="button"
                          class="icon-btn option-remove"
                          aria-label="删除候选项"
                          v-tip="'删除'"
                          @click="removeOption(field, optionIndex)"
                        >
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                        </button>
                      </div>
                      <button type="button" class="option-add" @click="addOption(field)">＋ 添加候选项</button>
                    </div>
                    <p class="kv-hint">至少保留一个非空候选项，且候选项不可重复</p>
                  </div>
                </div>
              </div>
            </div>

            <button type="button" class="editor-add" @click="addField">＋ 添加字段</button>
          </section>

          <!-- 03 展示与检索：主标题 + 每字段两列开关 -->
          <section class="kv-section">
            <div class="kv-section-label">03 展示与检索</div>
            <div class="kv-field">
              <label class="kv-label" for="vt-f-title">主标题</label>
              <VaultSelect
                id="vt-f-title"
                :model-value="active.titleField"
                :options="titleFieldOptions"
                :allow-empty="false"
                placeholder="未指定"
                aria-label="主标题"
                @update:model-value="onTitleFieldChange"
              />
              <p class="kv-hint">只列出非敏感字段；标题会直接显示在卡片上</p>
            </div>

            <div class="kv-field">
              <span class="kv-label">字段行为</span>
              <div class="display-matrix">
                <div class="display-head" aria-hidden="true">
                  <span>字段</span>
                  <span>次行</span>
                  <span>搜索</span>
                </div>
                <div
                  v-for="field in active.fields"
                  :key="field.id"
                  class="display-row"
                >
                  <span class="display-name" v-tip="field.label">{{ field.label || "未命名字段" }}</span>
                  <label
                    class="kf-toggle display-cell"
                    :class="{ 'is-disabled': !canBeCardLine(field) }"
                  >
                    <input
                      type="checkbox"
                      :checked="active.cardFields.includes(field.id)"
                      :disabled="!canBeCardLine(field)"
                      :aria-label="`${field.label || '未命名字段'}：卡片次行`"
                      @change="toggleCardField(field.id)"
                    />
                    <span class="kf-box" aria-hidden="true"></span>
                  </label>
                  <label
                    class="kf-toggle display-cell"
                    :class="{ 'is-disabled': !canBeSearch(field) }"
                  >
                    <input
                      type="checkbox"
                      :checked="active.searchFields.includes(field.id)"
                      :disabled="!canBeSearch(field)"
                      :aria-label="`${field.label || '未命名字段'}：搜索`"
                      @change="toggleSearchField(field.id)"
                    />
                    <span class="kf-box" aria-hidden="true"></span>
                  </label>
                </div>
              </div>
              <p class="kv-hint">
                卡片次行最多 {{ MAX_CARD_FIELDS }} 项；主标题与敏感字段不参与次行，敏感字段不可搜索；至少保留一个搜索字段
              </p>
            </div>
          </section>
        </div>
        </template>

        <!-- 无类型：保存动作仍保留，删除最后一个类型后必须有落盘入口 -->
        <section v-else class="type-empty">
          <p class="kv-note">还没有自定义类型</p>
          <button type="button" class="btn btn-primary btn-compact" @click="addType">新建类型</button>
        </section>

        <footer class="type-actions">
          <p v-if="errorText" class="kv-error editor-error">{{ errorText }}</p>
          <div class="type-action-row">
            <span class="kv-summary">关闭不保存修改</span>
            <button
              class="btn btn-neutral btn-compact"
              type="button"
              :disabled="saving"
              @click="open = false"
            >取消</button>
            <button
              class="btn btn-primary btn-compact"
              type="button"
              :disabled="saving"
              @click="onSave"
            >{{ saving ? "保存中…" : draft.length === 0 ? "保存并关闭" : "保存类型" }}</button>
          </div>
        </footer>
      </section>
    </div>
  </CosmicOverlay>

  <!-- 删除类型二次确认：条目保留规则已在类型轨就地说明 -->
  <ConfirmDelete
    :show="showRemoveConfirm"
    title="删除自定义类型？"
    :desc="removeTypeDesc"
    @confirm="confirmRemoveType"
    @cancel="showRemoveConfirm = false"
  />
</template>

<script setup lang="ts">
import { computed, nextTick, ref, watch } from "vue";
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
  VAULT_EXPIRY_FIELD_ID,
  VAULT_FIELD_KINDS,
  VAULT_TONES,
  createCustomFieldId,
  createCustomRangeStartId,
  createCustomVaultTypeId,
  resolveVaultIcon,
} from "../../../constants/vault_item_types";
import { VAULT_ICON_LIBRARY } from "../../../constants/vault_item_types";
import { VAULT_TONE_RGB_VARS } from "../../../lib/vault/vault_item_card";
import { saveCustomVaultTypes, sanitizeVaultTypeDefs, validateVaultTypeDefs } from "../../../lib/vault/vault_item_type_store";
import CosmicOverlay from "../../common/cosmic/CosmicOverlay.vue";
import ConfirmDelete from "../../common/verthys-ui/ConfirmDelete.vue";
import VaultSelect from "../../common/verthys-ui/VaultSelect.vue";
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
/** 当前展开属性面板的字段 id（同一时间只展开一个） */
const openFieldId = ref<string | null>(null);
/** 新建类型后把焦点交给名称输入 */
const typeTitleRef = ref<HTMLInputElement | null>(null);

const active = computed<VaultTypeDef | null>(() => draft.value[activeIndex.value] ?? null);

/** 打开时的序列化快照：左轨用它标记哪些类型有未落盘改动 */
const originalById = computed(
  () => new Map(props.types.map((type) => [type.id, JSON.stringify(type)])),
);
const isTypeDirty = (type: VaultTypeDef): boolean =>
  originalById.value.get(type.id) !== JSON.stringify(type);

/** 删除确认文案：删除只在点击保存后落盘，必须让用户看到这一层语义 */
const removeTypeDesc = computed(() => {
  const label = active.value?.label.trim() || "未命名类型";
  return `类型「${label}」将从列表移除，点击保存后落盘；已有条目不会被删除，将按未知类型展示。`;
});

/** 选择器候选项：控件种类与主标题共用同一份「值 + 文案」投影 */
const fieldKindOptions = computed(() =>
  fieldKinds.map((kind) => ({ value: kind.id, label: kind.label })),
);
/** 主标题只允许明文可读字段：标题在卡面上直接明文渲染 */
const titleFieldOptions = computed(() =>
  (active.value?.fields ?? [])
    .filter((field) => field.sensitive !== true)
    .map((field) => ({ value: field.id, label: field.label })),
);

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
    openFieldId.value = null;
    errorText.value = "";
    saving.value = false;
    showRemoveConfirm.value = false;
  },
  // 组件可能以「已打开」状态挂载（测试 / 宿主预置），此时也必须初始化草稿
  { immediate: true },
);

const selectType = (index: number): void => {
  if (!draft.value[index]) return;
  activeIndex.value = index;
  openFieldId.value = null;
  errorText.value = "";
};

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
  openFieldId.value = null;
  errorText.value = "";
  void nextTick(() => {
    typeTitleRef.value?.focus();
    typeTitleRef.value?.select();
  });
};

/** 新字段的默认名：按现有字段数递增，避开已占用名称（字段名必须唯一） */
const nextFieldLabel = (current: VaultTypeDef): string => {
  const labels = new Set(current.fields.map((field) => field.label.trim()));
  let index = current.fields.length + 1;
  while (labels.has(`字段 ${index}`)) index += 1;
  return `字段 ${index}`;
};

const addField = (): void => {
  const current = active.value;
  if (!current) return;
  // 区间起始键与字段 id 共用落盘表：新字段 id 必须同时避开这两类键
  const used = current.fields
    .flatMap((field) => [field.id, field.rangeStartId ?? ""])
    .filter((key) => key.length > 0);
  const label = nextFieldLabel(current);
  const lastGroup = current.fields[current.fields.length - 1]?.group;
  const field: VaultFieldDef = {
    id: createCustomFieldId(label, used),
    label,
    kind: "text",
    ...(lastGroup ? { group: lastGroup } : {}),
  };
  current.fields = [...current.fields, field];
  openFieldId.value = field.id;
};

/** 控件种类切换：按种类补齐/清理专属声明，避免留下孤儿属性 */
const onFieldKindChange = (field: VaultFieldDef, value: string): void => {
  const kind = value as VaultFieldKind;
  if (kind === field.kind) return;
  field.kind = kind;

  if (kind === "select") {
    if (!field.options || field.options.length === 0) field.options = ["选项 1"];
  } else {
    delete field.options;
  }

  if (kind === "multiline") {
    if (!field.multilineRows) field.multilineRows = 2;
  } else {
    delete field.multilineRows;
    delete field.carrier;
  }

  if (kind !== "switch") delete field.hint;

  if (kind === "dateRange") {
    if (!field.rangeStartId) {
      const used = (active.value?.fields ?? [])
        .flatMap((item) => [item.id, item.rangeStartId ?? ""])
        .filter((key) => key.length > 0);
      field.rangeStartId = createCustomRangeStartId(field.id, used);
    }
  } else {
    delete field.rangeStartId;
    delete field.rangeStartLabel;
    delete field.rangeEndLabel;
  }

  /* 带专属属性的控件在切换后直接展开面板，省去再点一次设置 */
  if (kind === "select" || kind === "multiline" || kind === "switch" || kind === "dateRange") {
    openFieldId.value = field.id;
  }
};

const toggleField = (id: string, event: MouseEvent): void => {
  const next = openFieldId.value === id ? null : id;
  openFieldId.value = next;
  if (!next) return;
  /* 展开面板可能落在正文视口之外：把当前字段行滚到最近可见位置 */
  const entry = (event.currentTarget as HTMLElement | null)?.closest(".field-entry");
  void nextTick(() => entry?.scrollIntoView({ block: "nearest" }));
};

const removeField = (index: number): void => {
  const current = active.value;
  if (!current || current.fields.length <= 1) return;
  const removed = current.fields[index];
  if (!removed) return;
  current.fields = current.fields.filter((_, i) => i !== index);
  if (openFieldId.value === removed.id) openFieldId.value = null;

  // 被删字段不得残留在主标题、卡片次行与搜索字段中，否则卡片会取到空值
  if (current.titleField === removed.id) {
    const fallback = current.fields.find((field) => field.sensitive !== true) ?? current.fields[0];
    current.titleField = fallback?.id ?? "";
  }
  current.cardFields = current.cardFields.filter((id) => id !== removed.id);
  current.searchFields = current.searchFields.filter((id) => id !== removed.id);
  if (current.searchFields.length === 0) {
    const fallback = current.fields.find((field) => field.sensitive !== true);
    if (fallback) current.searchFields = [fallback.id];
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

/** 敏感开关：敏感字段不得同时占据标题、次行或搜索位 */
const onSensitiveChange = (field: VaultFieldDef, event: Event): void => {
  const sensitive = (event.target as HTMLInputElement).checked;
  field.sensitive = sensitive;
  if (!sensitive) return;
  const current = active.value;
  if (!current) return;
  current.cardFields = current.cardFields.filter((id) => id !== field.id);
  current.searchFields = current.searchFields.filter((id) => id !== field.id);
  if (current.titleField === field.id) {
    const fallback = current.fields.find(
      (item) => item.id !== field.id && item.sensitive !== true,
    );
    if (fallback) current.titleField = fallback.id;
  }
  if (current.searchFields.length === 0) {
    const fallback = current.fields.find((item) => item.sensitive !== true);
    if (fallback) current.searchFields = [fallback.id];
  }
};

/** 主标题切换：标题已在卡面独占一行，不能重复进入次行 */
const onTitleFieldChange = (id: string): void => {
  const current = active.value;
  if (!current) return;
  current.titleField = id;
  current.cardFields = current.cardFields.filter((fieldId) => fieldId !== id);
};

/** 卡片次行资格：主标题、敏感字段与到期字段都不进入摘要行 */
const canBeCardLine = (field: VaultFieldDef): boolean => {
  const current = active.value;
  if (!current) return false;
  if (field.id === current.titleField) return false;
  if (field.sensitive === true) return false;
  if (field.id === VAULT_EXPIRY_FIELD_ID) return false;
  return true;
};

/** 搜索资格：敏感字段不可进入检索索引（否则可用关键字试探密文内容） */
const canBeSearch = (field: VaultFieldDef): boolean => field.sensitive !== true;

/** 多选成员切换（纯函数：返回新数组，绝不原地改写调用方数组） */
const toggledMember = (list: readonly string[], id: string, limit?: number): string[] => {
  if (list.includes(id)) return list.filter((item) => item !== id);
  if (limit !== undefined && list.length >= limit) return [...list];
  return [...list, id];
};

const toggleCardField = (id: string): void => {
  const current = active.value;
  if (!current) return;
  const field = current.fields.find((item) => item.id === id);
  if (!field || !canBeCardLine(field)) return;
  current.cardFields = toggledMember(current.cardFields, id, MAX_CARD_FIELDS);
};

const toggleSearchField = (id: string): void => {
  const current = active.value;
  if (!current) return;
  const field = current.fields.find((item) => item.id === id);
  if (!field || !canBeSearch(field)) return;
  current.searchFields = toggledMember(current.searchFields, id);
};

/** 多行文本行数：提交时收敛到 1–12，输入过程不打断光标 */
const onRowsCommit = (field: VaultFieldDef, event: Event): void => {
  const raw = Number((event.target as HTMLInputElement).value);
  field.multilineRows = Number.isFinite(raw)
    ? Math.min(12, Math.max(1, Math.round(raw)))
    : 2;
};

const onOptionInput = (field: VaultFieldDef, index: number, event: Event): void => {
  if (!field.options) field.options = [];
  field.options[index] = (event.target as HTMLInputElement).value;
};

const addOption = (field: VaultFieldDef): void => {
  if (!field.options) field.options = [];
  const used = new Set(field.options.map((option) => option.trim()));
  let index = field.options.length + 1;
  while (used.has(`选项 ${index}`)) index += 1;
  field.options.push(`选项 ${index}`);
};

const removeOption = (field: VaultFieldDef, index: number): void => {
  if (!field.options) return;
  field.options.splice(index, 1);
};

/**
 * 保存前收敛草稿：去空白、清掉与控件种类不匹配的孤儿属性，并把展示/
 * 检索配置收敛到合法字段。清洗后仍不合法时交给校验函数报告。
 */
const normalizeDraft = (): void => {
  const usedTypeLabels = new Set<string>();
  for (const type of draft.value) {
    /* 类型名与字段名必须唯一：旧版编辑器允许重名，若不在保存前收敛，
       整批保存会被校验拒绝，连删除类型也会被一起卡住。 */
    let typeLabel = type.label.trim() || "未命名类型";
    if (usedTypeLabels.has(typeLabel)) {
      let suffix = 2;
      while (usedTypeLabels.has(`${typeLabel} ${suffix}`)) suffix += 1;
      typeLabel = `${typeLabel} ${suffix}`;
    }
    type.label = typeLabel;
    usedTypeLabels.add(typeLabel);

    /* 全部字段都敏感的类型没有可用主标题与搜索位，结构上无法保存。
       补一个明文名称字段（不改变任何既有敏感值），让类型恢复可编辑，
       也避免它阻塞整批保存与删除。 */
    if (!type.fields.some((field) => field.sensitive !== true)) {
      const usedKeys = type.fields
        .flatMap((field) => [field.id, field.rangeStartId ?? ""])
        .filter((key) => key.length > 0);
      const nameField: VaultFieldDef = {
        id: createCustomFieldId("名称", usedKeys),
        label: "名称",
        kind: "text",
        required: true,
      };
      type.fields = [nameField, ...type.fields];
      type.titleField = nameField.id;
      type.searchFields = [nameField.id];
    }

    const fieldById = new Map(type.fields.map((field) => [field.id, field]));
    const usedFieldLabels = new Set<string>();

    for (const field of type.fields) {
      let fieldLabel = field.label.trim() || "未命名字段";
      if (usedFieldLabels.has(fieldLabel)) {
        let suffix = 2;
        while (usedFieldLabels.has(`${fieldLabel} ${suffix}`)) suffix += 1;
        fieldLabel = `${fieldLabel} ${suffix}`;
      }
      field.label = fieldLabel;
      usedFieldLabels.add(fieldLabel);

      if (field.required !== true) delete field.required;
      if (field.sensitive !== true) delete field.sensitive;
      if (field.carrier !== true) delete field.carrier;

      if (field.kind === "select") {
        const seenOptions = new Set<string>();
        field.options = (field.options ?? [])
          .map((option) => option.trim())
          .filter((option) => {
            if (!option || seenOptions.has(option)) return false;
            seenOptions.add(option);
            return true;
          });
        if (field.options.length === 0) field.options = ["选项 1"];
      } else {
        delete field.options;
      }

      if (field.kind === "dateRange") {
        if (field.rangeStartLabel?.trim()) field.rangeStartLabel = field.rangeStartLabel.trim();
        else delete field.rangeStartLabel;
        if (field.rangeEndLabel?.trim()) field.rangeEndLabel = field.rangeEndLabel.trim();
        else delete field.rangeEndLabel;
      } else {
        delete field.rangeStartId;
        delete field.rangeStartLabel;
        delete field.rangeEndLabel;
      }

      if (field.kind !== "switch" || !field.hint?.trim()) delete field.hint;
      else field.hint = field.hint.trim();

      if (field.group?.trim()) field.group = field.group.trim();
      else delete field.group;

      if (field.kind === "multiline") {
        const rows = Number(field.multilineRows);
        field.multilineRows = Number.isFinite(rows)
          ? Math.min(12, Math.max(1, Math.round(rows)))
          : 2;
      } else {
        delete field.multilineRows;
        delete field.carrier;
      }
    }

    /* 标题与检索位收敛到合法字段：手写/历史定义可能把敏感字段放在这里 */
    const title = fieldById.get(type.titleField);
    if (!title || title.sensitive === true) {
      const fallback = type.fields.find((field) => field.sensitive !== true);
      if (fallback) type.titleField = fallback.id;
    }
    type.cardFields = [...new Set(type.cardFields.filter((id) => {
      const field = fieldById.get(id);
      return (
        field !== undefined &&
        id !== type.titleField &&
        field.sensitive !== true &&
        id !== VAULT_EXPIRY_FIELD_ID
      );
    }))].slice(0, MAX_CARD_FIELDS);
    type.searchFields = [...new Set(type.searchFields.filter((id) => {
      const field = fieldById.get(id);
      return field !== undefined && field.sensitive !== true;
    }))];
    if (type.searchFields.length === 0) {
      const fallback = type.fields.find((field) => field.sensitive !== true);
      if (fallback) type.searchFields = [fallback.id];
    }
  }
};

const askRemoveType = (): void => {
  if (!active.value) return;
  showRemoveConfirm.value = true;
};

const confirmRemoveType = (): void => {
  const current = active.value;
  if (current) {
    draft.value = draft.value.filter((item) => item.id !== current.id);
    activeIndex.value = Math.min(activeIndex.value, Math.max(draft.value.length - 1, 0));
    openFieldId.value = null;
    errorText.value = "";
  }
  showRemoveConfirm.value = false;
};

const onSave = async (): Promise<void> => {
  normalizeDraft();
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
    emit("saved", sanitizeVaultTypeDefs(types));
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
/* ===== 工作台骨架 =====
 * 左轨固定宽度承载类型切换与删除；右区头部、动作区固定，仅正文滚动。
 * 固定 shell 高度让长字段清单在正文内滚动，而不是把弹窗撑成长表单。 */
.editor-shell {
  display: grid;
  grid-template-columns: 206px minmax(0, 1fr);
  height: min(560px, 66vh);
  min-height: 380px;
  margin-top: 12px;
  border-top: 1px solid rgba(205, 224, 244, 0.07);
}

/* ===== 类型轨 ===== */
.type-rail {
  display: flex;
  flex-direction: column;
  min-height: 0;
  padding-right: 16px;
  border-right: 1px solid rgba(205, 224, 244, 0.07);
}
.rail-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  padding: 12px 0 8px;
  font-size: 10px;
  letter-spacing: 2px;
  color: rgba(132, 148, 168, 0.85);
}
.rail-count {
  font-family: var(--font-mono);
  font-size: 9.5px;
  letter-spacing: 1px;
  color: var(--text-muted);
}
.rail-list {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 2px 0 8px;
}
.rail-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 9px;
  border: 1px solid transparent;
  border-radius: 7px;
  background: transparent;
  color: var(--text-secondary);
  font-family: var(--font);
  text-align: left;
  cursor: pointer;
  transition:
    color var(--dur-fast) var(--ease),
    border-color var(--dur-fast) var(--ease),
    background-color var(--dur-fast) var(--ease);
}
.rail-item:hover {
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.03);
}
.rail-item[data-on="1"] {
  border-color: rgba(var(--accent-rgb), 0.28);
  background: rgba(var(--accent-rgb), 0.06);
  color: var(--accent);
}
.rail-mark {
  flex-shrink: 0;
  width: 16px;
  height: 16px;
  color: rgb(var(--tone-rgb, var(--accent-rgb)));
}
.rail-mark :deep(svg) { display: block; width: 100%; height: 100%; }
.rail-name {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12px;
  letter-spacing: 0.3px;
}
.rail-dirty {
  flex-shrink: 0;
  width: 4px;
  height: 4px;
  margin-left: auto;
  border-radius: 50%;
  background: var(--accent);
}
.rail-add {
  margin-top: 2px;
  padding: 7px 9px;
  border: 1px dashed rgba(205, 224, 244, 0.14);
  border-radius: 7px;
  background: none;
  color: var(--text-muted);
  font-family: var(--font);
  font-size: 11px;
  text-align: left;
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}
.rail-add:hover { color: var(--accent); border-color: var(--border-hover); }
.rail-foot {
  padding-top: 12px;
  border-top: 1px solid rgba(205, 224, 244, 0.07);
}
.rail-remove { width: 100%; }
.rail-note {
  margin: 8px 0 0;
  font-size: 10px;
  line-height: 1.6;
  color: var(--text-muted);
}

/* ===== 右区 ===== */
.type-main {
  display: flex;
  flex-direction: column;
  min-width: 0;
  min-height: 0;
  padding-left: 20px;
}
.type-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 0 14px;
  border-bottom: 1px solid rgba(205, 224, 244, 0.07);
}
.type-mark {
  flex-shrink: 0;
  width: 24px;
  height: 24px;
  color: rgb(var(--tone-rgb, var(--accent-rgb)));
}
.type-mark :deep(svg) { display: block; width: 100%; height: 100%; }
.type-title-input {
  flex: 1;
  min-width: 0;
  padding: 0 0 3px;
  border: 0;
  border-bottom: 1px solid rgba(205, 224, 244, 0.12);
  border-radius: 0;
  background: transparent;
  color: #e8f1fa;
  font-family: var(--font);
  font-size: 15px;
  font-weight: 600;
  letter-spacing: 0.4px;
  outline: none;
  transition: border-color var(--dur-fast) var(--ease);
}
.type-title-input:focus { border-bottom-color: rgba(var(--accent-rgb), 0.55); }
.type-title-input::placeholder { color: rgba(132, 148, 168, 0.6); }
.type-body {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  padding-right: 4px;
}
.type-actions {
  flex-shrink: 0;
  padding-top: 14px;
  border-top: 1px solid rgba(205, 224, 244, 0.07);
}
.type-action-row {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}
.editor-error { margin: 0 0 10px; }
.type-empty {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  align-items: center;
  justify-content: center;
  gap: 12px;
  margin-bottom: 14px;
  text-align: center;
  border: 1px solid rgba(205, 224, 244, 0.07);
  border-radius: 9px;
}

/* ===== 字段表 ===== */
.field-table {
  border-top: 1px solid rgba(205, 224, 244, 0.07);
  border-bottom: 1px solid rgba(205, 224, 244, 0.07);
}
.field-entry { padding: 6px 0; }
.field-entry + .field-entry { border-top: 1px solid rgba(205, 224, 244, 0.055); }
.field-line {
  display: flex;
  align-items: center;
  gap: 8px;
}
.field-no {
  flex-shrink: 0;
  width: 16px;
  font-family: var(--font-mono);
  font-size: 9.5px;
  color: var(--text-muted);
}
.field-label-input {
  flex: 1;
  min-width: 0;
  padding: 9px 10px;
  font-size: 12px;
}
.field-kind { flex: 0 0 112px; }
.field-marks {
  display: flex;
  gap: 5px;
  flex-shrink: 0;
  min-width: 44px;
}
.field-mark {
  font-size: 9px;
  letter-spacing: 0.6px;
  color: var(--text-muted);
  white-space: nowrap;
}
.field-mark.is-sensitive { color: rgba(var(--warning-rgb), 0.9); }
.field-tools { display: flex; gap: 2px; flex-shrink: 0; }
.field-tools .icon-btn { width: 22px; height: 22px; }
.field-tools .icon-btn svg { width: 11px; height: 11px; }
.field-tools .icon-btn:disabled { cursor: not-allowed; opacity: 0.35; }
.field-toggle svg { transition: transform var(--dur-fast) var(--ease); }
.field-entry.is-open .field-toggle svg { transform: rotate(180deg); }

/* 展开面板：同一块凹槽承载所有字段属性，不再拆成多张卡片 */
.field-panel {
  margin: 6px 0 4px 24px;
  padding: 10px 12px;
  border-top: 1px solid rgba(205, 224, 244, 0.07);
  border-radius: 0 0 7px 7px;
  background: rgba(2, 5, 10, 0.20);
}
.field-flags {
  display: flex;
  flex-wrap: wrap;
  gap: 14px;
  padding-bottom: 10px;
  border-bottom: 1px solid rgba(205, 224, 244, 0.07);
}
.field-props {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 12px;
  padding-top: 10px;
}
.field-props .kv-field { margin-top: 0; }
.field-prop-wide { grid-column: 1 / -1; }
.field-props .kv-input { padding: 8px 10px; font-size: 12px; }

/* ===== 候选项编辑 ===== */
.field-options-editor {
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px solid rgba(205, 224, 244, 0.07);
}
.option-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin-top: 6px;
}
.option-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.option-no {
  flex-shrink: 0;
  width: 16px;
  font-family: var(--font-mono);
  font-size: 9.5px;
  color: var(--text-muted);
}
.option-input {
  flex: 1;
  min-width: 0;
  padding: 7px 10px;
  font-size: 12px;
}
.option-remove { width: 22px; height: 22px; }
.option-remove svg { width: 11px; height: 11px; }
.option-add {
  align-self: flex-start;
  margin-top: 4px;
  padding: 4px 9px;
  border: 1px dashed rgba(205, 224, 244, 0.14);
  border-radius: 6px;
  background: none;
  color: var(--text-muted);
  font-family: var(--font);
  font-size: 10.5px;
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}
.option-add:hover { color: var(--accent); border-color: var(--border-hover); }

/* ===== 展示与检索矩阵 ===== */
.display-matrix { border-top: 1px solid rgba(205, 224, 244, 0.07); }
.display-head,
.display-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 56px 56px;
  align-items: center;
  gap: 8px;
}
.display-head {
  padding: 6px 0;
  border-bottom: 1px solid rgba(205, 224, 244, 0.07);
  font-size: 10px;
  letter-spacing: 1.5px;
  color: var(--text-muted);
}
.display-head span:not(:first-child) { text-align: center; }
.display-row { padding: 7px 0; }
.display-row + .display-row { border-top: 1px solid rgba(205, 224, 244, 0.055); }
.display-name {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12px;
  color: var(--text-secondary);
  font-family: var(--font);
}
.display-cell {
  justify-content: center;
  gap: 0;
  padding: 4px 0;
}
.display-cell.is-disabled {
  cursor: not-allowed;
  opacity: 0.3;
}

/* ===== 类型集标签条 ===== */
.editor-tabs { display: flex; flex-wrap: wrap; gap: 6px; }
.editor-tab {
  padding: 4px 10px;
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(205, 224, 244, 0.12);
  border-radius: 10px;
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
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(205, 224, 244, 0.12); border-radius: 6px;
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

.editor-add {
  margin-top: 10px; padding: 5px 12px;
  background: none; border: 1px dashed rgba(205, 224, 244, 0.14); border-radius: 6px;
  color: var(--text-secondary); font-size: 11px; font-family: var(--font);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}
.editor-add:hover { color: var(--accent); border-color: var(--border-hover); }
.editor-add:focus-visible { outline: 1px solid var(--border-hover); outline-offset: 1px; }

.rail-item:focus-visible,
.rail-add:focus-visible,
.option-add:focus-visible,
.field-toggle:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: 1px;
}
</style>
