<!--
  VaultItemFormDialog.vue — 类型化条目编辑窗口（schema 驱动）
  形态：复用全局弹窗外壳 CosmicOverlay + kv-* 内容词汇（分区字段 + 选项条 + 内容舱）。
  驱动：字段清单来自 VaultTypeDef.fields，六类控件按 kind 渲染，不按类型名分支。
  特化：账号类型使用固定窗口结构（标识 / 凭据 / 加密 / 附注四段 + 独立密钥行），
        独立加密的落盘判定交由 lib/vault_item_codec 的保存决策完成。
  用法:
    <VaultItemFormDialog
      v-model="showForm" :type-def="formType" :initial-data="formInitial"
      @submit="onPersist"
    />
-->
<template>
  <CosmicOverlay
    :show="open"
    width="560px"
    :persistent="saving"
    aria-labelledby="vault-form-title"
    @close="open = false"
  >
    <div class="kv-title" id="vault-form-title">{{ panelTitle }}</div>

    <div v-if="def && isAccount" class="kv-form">
      <section class="kv-section">
        <div class="kv-section-label">01 标识</div>
        <div class="kv-field">
          <label class="kv-label" for="acc-f-platform"><i class="kv-req" aria-hidden="true">*</i>平台</label>
          <input id="acc-f-platform" class="kv-input" v-model="values.platform" aria-required="true" />
        </div>
        <div class="kv-field">
          <label class="kv-label" for="acc-f-username"><i class="kv-req" aria-hidden="true">*</i>账户</label>
          <input id="acc-f-username" class="kv-input" v-model="values.username" aria-required="true" />
        </div>
      </section>

      <section class="kv-section">
        <div class="kv-section-label">02 凭据</div>
        <div class="kv-field">
          <label class="kv-label" for="acc-f-password">密码</label>
          <div class="kv-input-group">
            <input id="acc-f-password" class="kv-input" v-model="values.password" :type="pwdVisible.password ? 'text' : 'password'" aria-required="true" />
            <button
              class="icon-btn"
              type="button"
              @click="pwdVisible.password = !pwdVisible.password"
              :aria-label="pwdVisible.password ? '隐藏密码' : '显示密码'"
              v-tip="pwdVisible.password ? '隐藏' : '显示'"
            >
              <svg v-if="!pwdVisible.password" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
            </button>
          </div>
        </div>
      </section>

      <section class="kv-section">
        <div class="kv-section-label">03 加密</div>
        <label class="kv-option" :class="{ 'is-on': accountEncrypted }">
          <input type="checkbox" v-model="accountEncrypted" :disabled="initialEncrypted" />
          <span class="kv-option-check"></span>
          <span class="kv-option-text">独立加密</span>
          <span class="kv-option-hint">查看时需二次输入独立密钥</span>
        </label>
        <div v-if="accountEncrypted" class="kv-field">
          <label class="kv-label" for="acc-f-encKey">密钥</label>
          <div class="kv-input-group">
            <input
              id="acc-f-encKey"
              class="kv-input"
              v-model="accountEncKey"
              :type="encKeyVisible ? 'text' : 'password'"
              aria-required="true"
            />
            <button
              class="icon-btn"
              type="button"
              @click="encKeyVisible = !encKeyVisible"
              :aria-label="encKeyVisible ? '隐藏密钥' : '显示密钥'"
              v-tip="encKeyVisible ? '隐藏' : '显示'"
            >
              <svg v-if="!encKeyVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
            </button>
          </div>
        </div>
        <!-- 已开启独立加密却未提供密钥：窗口内联提示，替代静默放弃 -->
        <p v-if="accountEncrypted && !accountEncKey" class="kv-hint is-error">请输入独立密钥后保存</p>
      </section>

      <section class="kv-section">
        <div class="kv-section-label">04 附注</div>
        <div class="kv-field">
          <label class="kv-label" for="acc-f-note">备注</label>
          <textarea id="acc-f-note" class="kv-input kv-textarea" v-model="values.note" rows="2"></textarea>
        </div>
      </section>
    </div>

    <!-- 通用窗口：字段按 kind 渲染；相邻同组字段合为一个分区 -->
    <div v-else-if="def" class="kv-form">
      <section
        v-for="(section, sectionIndex) in formSections"
        :key="`${sectionIndex}-${section.name}`"
        class="kv-section"
      >
        <div class="kv-section-label">{{ sectionNo(sectionIndex) }} {{ section.name }}</div>
        <div class="form-fields">
          <template v-for="field in section.fields" :key="field.id">
            <!-- 选项条：整行可点的开关（用户自定义类型可能声明） -->
            <label v-if="field.kind === 'switch'" class="kv-option" :class="{ 'is-on': values[field.id] === '1' }">
              <input
                type="checkbox"
                :checked="values[field.id] === '1'"
                @change="onSwitchChange(field.id, $event)"
              />
              <span class="kv-option-check"></span>
              <span class="kv-option-text">{{ field.label }}</span>
              <span v-if="field.hint" class="kv-option-hint">{{ field.hint }}</span>
            </label>

            <!-- 内容舱：长文本凭据，支持拖拽与文件导入 -->
            <div v-else-if="field.carrier" class="kv-field">
              <label class="kv-label" :for="domId(field)"><i v-if="field.required" class="kv-req" aria-hidden="true">*</i>{{ field.label }}</label>
              <div
                class="carrier"
                :class="{ 'is-drag': dragFieldId === field.id }"
                @dragover.prevent="onDragOver(field.id)"
                @dragleave.prevent="onDragLeave($event, field.id)"
                @drop.prevent="onDrop($event, field.id)"
              >
                <textarea
                  :id="domId(field)"
                  class="kv-input kv-textarea carrier-input"
                  :rows="field.multilineRows ?? 5"
                  v-model="values[field.id]"
                ></textarea>
                <div class="carrier-bar">
                  <button class="carrier-import" type="button" @click="triggerFilePick(field.id)">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    <span>导入文件</span>
                  </button>
                  <span v-if="pickedFileName[field.id]" class="carrier-file" v-tip="pickedFileName[field.id]">{{ pickedFileName[field.id] }}</span>
                  <span class="carrier-readout">{{ dragFieldId === field.id ? '松开即导入' : charStats(field.id) }}</span>
                </div>
              </div>
            </div>

            <!-- 日期：日期控件 + 到期读数 -->
            <div v-else-if="field.kind === 'date'" class="kv-field">
              <label class="kv-label" :for="domId(field)"><i v-if="field.required" class="kv-req" aria-hidden="true">*</i>{{ field.label }}</label>
              <div class="date-line">
                <div class="date-wrap" @click="openDatePicker($event)">
                  <input :id="domId(field)" class="kv-input date-input" :class="{ 'has-value': values[field.id] }" type="date" v-model="values[field.id]" />
                  <span v-if="!values[field.id]" class="date-ph">未设置</span>
                </div>
                <!-- 到期读数只属于到期字段：出生日期等普通日期不产生「距到期」语义 -->
                <span v-if="field.id === expiryFieldId" class="kv-readout" :class="`is-${readoutFor(field.id).tone}`">
                  <i class="kv-readout-dot"></i>{{ readoutFor(field.id).text }}
                </span>
              </div>
            </div>

            <!-- 日期区间：起止成对呈现（结束日仍是字段 id，到期读数口径不变） -->
            <div v-else-if="field.kind === 'dateRange'" class="kv-field">
              <span class="kv-label"><i v-if="field.required" class="kv-req" aria-hidden="true">*</i>{{ field.label }}</span>
              <div class="range">
                <div class="range-line">
                  <span class="range-tag">{{ rangeStartLabelOf(field) }}</span>
                  <div class="date-wrap" @click="openDatePicker($event)">
                    <input
                      :id="`${domId(field)}-start`"
                      class="kv-input date-input"
                      :class="{ 'has-value': values[rangeStartIdOf(field)] }"
                      type="date"
                      v-model="values[rangeStartIdOf(field)]"
                      :max="values[field.id] || undefined"
                      :aria-label="`${field.label}${rangeStartLabelOf(field)}`"
                    />
                    <span v-if="!values[rangeStartIdOf(field)]" class="date-ph">未设置</span>
                  </div>
                  <span class="range-sep" aria-hidden="true"></span>
                  <span class="range-tag">{{ rangeEndLabelOf(field) }}</span>
                  <div class="date-wrap" @click="openDatePicker($event)">
                    <input
                      :id="domId(field)"
                      class="kv-input date-input"
                      :class="{ 'has-value': values[field.id] }"
                      type="date"
                      v-model="values[field.id]"
                      :min="values[rangeStartIdOf(field)] || undefined"
                      :aria-label="`${field.label}${rangeEndLabelOf(field)}`"
                    />
                    <span v-if="!values[field.id]" class="date-ph">未设置</span>
                  </div>
                </div>
                <span v-if="field.id === expiryFieldId" class="kv-readout" :class="`is-${readoutFor(field.id).tone}`">
                  <i class="kv-readout-dot"></i>{{ readoutFor(field.id).text }}
                </span>
              </div>
            </div>

            <!-- 选择：下拉候选项 -->
            <div v-else-if="field.kind === 'select'" class="kv-field">
              <label class="kv-label" :for="domId(field)"><i v-if="field.required" class="kv-req" aria-hidden="true">*</i>{{ field.label }}</label>
              <select :id="domId(field)" class="kv-input kv-select" v-model="values[field.id]">
                <option value="">未指定</option>
                <option v-for="opt in field.options ?? []" :key="opt" :value="opt">{{ opt }}</option>
              </select>
            </div>

            <!-- 地区：全国省 / 市 / 区三级联动 -->
            <div v-else-if="field.kind === 'region'" class="kv-field">
              <span class="kv-label"><i v-if="field.required" class="kv-req" aria-hidden="true">*</i>{{ field.label }}</span>
              <VaultRegionPicker v-model="values[field.id]" />
            </div>

            <!-- 多行文本 -->
            <div v-else-if="field.kind === 'multiline'" class="kv-field">
              <label class="kv-label" :for="domId(field)"><i v-if="field.required" class="kv-req" aria-hidden="true">*</i>{{ field.label }}</label>
              <textarea :id="domId(field)" class="kv-input kv-textarea" :rows="field.multilineRows ?? 2" v-model="values[field.id]"></textarea>
            </div>

            <!-- 文本 / 密码：密码带显隐切换 -->
            <div v-else class="kv-field">
              <label class="kv-label" :for="domId(field)"><i v-if="field.required" class="kv-req" aria-hidden="true">*</i>{{ field.label }}</label>
              <div v-if="field.kind === 'password'" class="kv-input-group">
                <input
                  :id="domId(field)"
                  class="kv-input"
                  v-model="values[field.id]"
                  :type="pwdVisible[field.id] ? 'text' : 'password'"
                />
                <button
                  class="icon-btn"
                  type="button"
                  @click="pwdVisible[field.id] = !pwdVisible[field.id]"
                  :aria-label="pwdVisible[field.id] ? '隐藏' : '显示'"
                  v-tip="pwdVisible[field.id] ? '隐藏' : '显示'"
                >
                  <svg v-if="!pwdVisible[field.id]" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                </button>
              </div>
              <input v-else :id="domId(field)" class="kv-input" v-model="values[field.id]" />
            </div>
          </template>
        </div>
      </section>
      <input ref="fileInputRef" type="file" class="carrier-file-input" :accept="CARRIER_FILE_ACCEPT" @change="onFilePicked" />
    </div>

    <p v-if="formError" class="kv-error form-error">{{ formError }}</p>

    <div class="kv-actions">
      <button class="btn kv-cancel" type="button" :disabled="saving" @click="open = false">取消</button>
      <button
        class="btn btn-primary kv-confirm"
        type="button"
        :disabled="saveDisabled || saving"
        @click="onSubmit"
      >{{ saving ? "保存中…" : isEdit ? "保存修改" : "确认" }}</button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { VaultFieldDef, VaultTypeDef, VaultItemPayload } from "../../../constants/vault_item_types";
import { ACCOUNT_VAULT_TYPE_ID, VAULT_EXPIRY_FIELD_ID, groupVaultFieldSections, vaultRangeStartFieldId } from "../../../constants/vault_item_types";
import {
  buildVaultItemData,
  resolveSecretSaveAction,
} from "../../../lib/vault_item_codec";
import { vaultExpiryReadout, vaultExpiryTimestamp } from "../../../lib/vault_item_card";
import { encryptPasswordField } from "../../../lib/verthys";
import CosmicOverlay from "../../common/cosmic/CosmicOverlay.vue";
import VaultRegionPicker from "./VaultRegionPicker.vue";

/** 内容舱可导入的文件类型（凭据与配置文本，覆盖证书、密钥与文本材料） */
const CARRIER_FILE_ACCEPT = ".pem,.crt,.cer,.der,.key,.pub,.json,.txt,.conf,.cfg,.ovpn";

const props = withDefaults(
  defineProps<{
    modelValue: boolean;
    /** 目标类型定义；为空时不渲染任何字段 */
    typeDef: VaultTypeDef | null;
    /** 编辑既有条目时的原始数据；新增时为 null */
    initialData?: Record<string, string> | null;
    /** 保存处理中（由调用方在持久化期间置位） */
    saving?: boolean;
  }>(),
  { initialData: null, saving: false },
);

const emit = defineEmits<{
  (e: "update:modelValue", val: boolean): void;
  (e: "submit", payload: VaultItemPayload): void;
}>();

const open = computed({
  get: () => props.modelValue,
  set: (val: boolean) => emit("update:modelValue", val),
});

const def = computed(() => props.typeDef);
const isAccount = computed(() => def.value?.id === ACCOUNT_VAULT_TYPE_ID);
const isEdit = computed(() => props.initialData !== null);
const initialEncrypted = computed(() => props.initialData?.encrypted === "1");

/** 字段取值字典（键为字段 id） */
const values = ref<Record<string, string>>({});
/** 密码类字段的显隐（按字段 id） */
const pwdVisible = ref<Record<string, boolean>>({});
/** 账号独立加密开关与密钥（密钥只参与当次加密，不写入条目数据） */
const accountEncrypted = ref(false);
const accountEncKey = ref("");
const encKeyVisible = ref(false);
/** 窗口内联校验提示 */
const formError = ref("");
/** 内容舱：当前拖拽目标字段、导入文件名与待导入字段 */
const dragFieldId = ref<string | null>(null);
const pickedFileName = ref<Record<string, string>>({});
const pendingCarrierField = ref<string | null>(null);
const fileInputRef = ref<HTMLInputElement | null>(null);

const panelTitle = computed(() => {
  if (!def.value) return "";
  return isEdit.value ? `编辑${def.value.label}` : def.value.label;
});

/** 分区清单：与详情窗口共用同一分组规则（constants/vault_item_types） */
const formSections = computed(() => (def.value ? groupVaultFieldSections(def.value) : []));

/** 分区编号：两位数（01、02…），与账号窗口同一登记台语法 */
const sectionNo = (index: number): string => String(index + 1).padStart(2, "0");

/** 到期字段 id：只有该字段产生到期读数（与卡片、筛选同一权威源） */
const expiryFieldId = VAULT_EXPIRY_FIELD_ID;

/** 区间起始字段 id：与落盘投影（lib/vault_item_codec）共用同一回退规则 */
const rangeStartIdOf = vaultRangeStartFieldId;
const rangeStartLabelOf = (field: VaultFieldDef): string => field.rangeStartLabel ?? "自";
const rangeEndLabelOf = (field: VaultFieldDef): string => field.rangeEndLabel ?? "至";

/** 区间起止颠倒（两端都填写且都能解析时才算）：与到期读数共用同一解析口径 */
const isRangeReversed = (field: VaultFieldDef): boolean => {
  const start = values.value[rangeStartIdOf(field)] ?? "";
  const end = values.value[field.id] ?? "";
  if (!start || !end) return false;
  const startTime = vaultExpiryTimestamp(start);
  const endTime = vaultExpiryTimestamp(end);
  return startTime !== null && endTime !== null && startTime > endTime;
};

/** 必填但未填写的字段名（保存按钮禁用条件与提交前校验共用） */
const missingRequired = computed<string[]>(() => {
  const current = def.value;
  if (!current) return [];
  const missing: string[] = [];
  for (const field of current.fields) {
    if (field.required !== true) continue;
    if (!(values.value[field.id] ?? "").trim()) {
      missing.push(field.label);
      continue;
    }
    // 必填的区间要求起止成对：只填到期日属于「有效期未完整登记」
    if (field.kind === "dateRange" && !(values.value[rangeStartIdOf(field)] ?? "").trim()) {
      missing.push(field.label);
    }
  }
  return missing;
});

/* 保存可用性必须与落盘决策同源：
 *   - 通用类型：必填项是否填满；
 *   - 账号类型：必填项 + 独立加密的保存决策（resolveSecretSaveAction）。
 * 不得以「已开启加密但未输入密钥」直接禁用保存 ——
 * 既有已加密条目由于开关被锁定、密钥框恒为空，改一个备注也会被永久禁用；
 * 而落盘决策本身支持 unchanged→reuse（无需密钥）。两套判断必然互相冲突。 */
const secretPlan = computed(() =>
  resolveSecretSaveAction({
    previousEncrypted: initialEncrypted.value,
    previousValue: props.initialData?.password ?? "",
    currentValue: values.value.password ?? "",
    enableEncryption: accountEncrypted.value,
    hasKey: accountEncKey.value.length > 0,
  }),
);

const saveDisabled = computed(() => {
  if (!def.value) return true;
  if (missingRequired.value.length > 0) return true;
  return isAccount.value && secretPlan.value.action === "needs-key";
});

/** 重置表单：以类型字段清单与既有数据初始化（新增时取字段默认值） */
const resetForm = (): void => {
  const current = def.value;
  const initial = props.initialData;
  const next: Record<string, string> = {};
  if (current) {
    for (const field of current.fields) {
      /* 默认值只服务新增：编辑既有条目（哪怕缺该键）必须保持空，否则一次
         保存就会把模板默认值写进历史记录，用户无从察觉。 */
      next[field.id] = initial ? (initial[field.id] ?? "") : (field.default ?? "");
      if (field.kind === "dateRange") {
        const startId = rangeStartIdOf(field);
        next[startId] = initial ? (initial[startId] ?? "") : "";
      }
    }
  }
  values.value = next;
  pwdVisible.value = {};
  pickedFileName.value = {};
  pendingCarrierField.value = null;
  dragFieldId.value = null;
  formError.value = "";
  accountEncKey.value = "";
  accountEncrypted.value = initialEncrypted.value;
  encKeyVisible.value = false;
};

/* 打开窗口或切换类型时重建表单，保证不残留上一次编辑的取值。
 * 默认的 pre 刷新时机在子组件渲染前执行，因此字段渲染时即已带上回填值，不会先空后满 */
watch(
  () => [props.modelValue, def.value?.id] as const,
  ([visible]) => {
    if (visible) resetForm();
  },
  { immediate: true },
);

const domId = (field: VaultFieldDef): string => `vault-f-${field.id}`;

const readoutFor = (fieldId: string) => vaultExpiryReadout(values.value[fieldId] ?? "");

const charStats = (fieldId: string): string => {
  const text = values.value[fieldId] ?? "";
  if (!text) return "0 字符 · 0 行";
  return `${text.length} 字符 · ${text.split(/\r\n|\r|\n/).length} 行`;
};

const onSwitchChange = (fieldId: string, e: Event): void => {
  const checked = (e.target as HTMLInputElement).checked;
  values.value = { ...values.value, [fieldId]: checked ? "1" : "0" };
};

/** 日期控件：点击整行即唤起系统日期选择（不支持则该输入框自行聚焦） */
const openDatePicker = (e: MouseEvent): void => {
  const wrap = e.currentTarget as HTMLElement | null;
  const input = wrap?.querySelector("input") as (HTMLInputElement & { showPicker?: () => void }) | null;
  if (!input) return;
  try {
    input.showPicker?.();
  } catch {
    input.focus();
  }
};

const triggerFilePick = (fieldId: string): void => {
  pendingCarrierField.value = fieldId;
  fileInputRef.value?.click();
};

/** 读取文件文本写入内容舱（仅取文本内容，不保留文件字节） */
const readIntoField = async (fieldId: string, file: File): Promise<void> => {
  try {
    const text = await file.text();
    values.value = { ...values.value, [fieldId]: text };
    pickedFileName.value = { ...pickedFileName.value, [fieldId]: file.name };
  } catch {
    formError.value = "文件读取失败，请重试";
  }
};

const onFilePicked = async (e: Event): Promise<void> => {
  const target = e.target as HTMLInputElement;
  const fieldId = pendingCarrierField.value;
  const file = target.files?.[0];
  // 复位选择器：同一文件再次导入时仍能触发 change
  target.value = "";
  if (!fieldId || !file) return;
  await readIntoField(fieldId, file);
};

const onDragOver = (fieldId: string): void => {
  dragFieldId.value = fieldId;
};

/** 拖拽离开判定：指针仍在舱内（子元素间移动）时保持高亮，越过边界才复位 */
const onDragLeave = (e: DragEvent, fieldId: string): void => {
  const current = e.currentTarget as HTMLElement | null;
  const related = e.relatedTarget as Node | null;
  if (current && related && current.contains(related)) return;
  if (dragFieldId.value === fieldId) dragFieldId.value = null;
};

const onDrop = async (e: DragEvent, fieldId: string): Promise<void> => {
  dragFieldId.value = null;
  const file = e.dataTransfer?.files?.[0];
  if (!file) return;
  await readIntoField(fieldId, file);
};

/** 账号类型提交：先做保存决策再落盘取值，缺密钥时以窗口内联提示中止 */
const submitAccount = async (current: VaultTypeDef): Promise<void> => {
  if (!(values.value.platform ?? "").trim()) {
    formError.value = "请填写平台名称";
    return;
  }
  if (!(values.value.username ?? "").trim()) {
    formError.value = "请填写账户";
    return;
  }

  const plan = secretPlan.value;

  if (plan.action === "needs-key") {
    formError.value = "请输入独立密钥";
    return;
  }

  let stored = plan.value;
  if (plan.action === "encrypt") {
    try {
      stored = await encryptPasswordField(plan.value, accountEncKey.value);
    } catch {
      formError.value = "加密失败，请重试";
      return;
    }
  }

  emit("submit", {
    kind: current.id,
    data: buildVaultItemData(current, {
      ...values.value,
      password: stored,
      encrypted: plan.encrypted ? "1" : "0",
    }),
  });
};

const onSubmit = async (): Promise<void> => {
  const current = def.value;
  if (!current) return;
  formError.value = "";

  if (isAccount.value) {
    await submitAccount(current);
    return;
  }

  const missing = missingRequired.value;
  if (missing.length > 0) {
    formError.value = `请填写${missing.join("、")}`;
    return;
  }

  // 起止颠倒属于输入矛盾：放行会把无法成立的有效期落盘，必须在提交前拦下
  const reversed = current.fields.find((field) => isRangeReversed(field));
  if (reversed) {
    formError.value = `「${reversed.label}」的起始日不能晚于到期日`;
    return;
  }

  emit("submit", { kind: current.id, data: buildVaultItemData(current, values.value) });
};
</script>

<style scoped>
/* ===== 业务结构 =====
   标题、分区、字段、输入、选项与动作区全部由 kv-* 承担；
   本文件只保留内容舱与日期区间这两类专属排版 */

/* 分区内字段间距：kv-field 负责相邻字段，开关与字段之间由本规则补足 */
.form-fields > * + * { margin-top: 12px; }

/* 内容舱：文本域 + 底部工具条共用一道凹槽，导入端子只在条内应答 */
.carrier {
  border-radius: 8px;
  background: linear-gradient(180deg, rgba(2, 5, 10, 0.38), rgba(2, 5, 10, 0.20));
  box-shadow:
    inset 0 1px 0 rgba(var(--black-rgb), 0.50),
    inset 0 -1px 0 rgba(205, 224, 244, 0.055);
  overflow: hidden;
  transition: box-shadow 0.25s var(--ease);
}
.carrier.is-drag {
  box-shadow:
    inset 0 1px 0 rgba(var(--black-rgb), 0.45),
    inset 0 -1px 0 rgba(var(--accent-rgb), 0.60);
}
.carrier-input {
  display: block;
  background: transparent;
  box-shadow: none;
  border-radius: 8px 8px 0 0;
  font-family: var(--font-mono);
  font-size: 11.5px;
  letter-spacing: 0.3px;
}
.carrier-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 7px 10px;
  border-top: 1px solid rgba(205, 224, 244, 0.06);
}
.carrier-import {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 9px;
  background: none;
  border: 1px solid transparent;
  border-radius: 5px;
  color: var(--text-secondary);
  font-size: 11px;
  font-family: var(--font);
  letter-spacing: 0.5px;
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease), background-color var(--dur-fast) var(--ease);
}
.carrier-import svg { width: 12px; height: 12px; opacity: 0.85; }
.carrier-import:hover {
  color: var(--accent);
  border-color: rgba(var(--accent-rgb), 0.24);
  background-color: rgba(var(--accent-rgb), 0.06);
}
.carrier-import:focus-visible { outline: 1px solid var(--border-hover); outline-offset: 1px; }
.carrier-file {
  min-width: 0;
  max-width: 200px;
  flex-shrink: 1;
  font-family: var(--font-mono);
  font-size: 10.5px;
  letter-spacing: 0.3px;
  color: var(--accent);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.carrier-readout {
  margin-left: auto;
  flex-shrink: 0;
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  white-space: nowrap;
  transition: color var(--dur-fast) var(--ease);
}
.carrier.is-drag .carrier-readout { color: var(--accent); }
.carrier-file-input { display: none; }

/* 日期：单枚日期控件 + 到期读数；日期占位由本地覆盖层承担（原生透明文字不可读） */
.date-line { display: flex; align-items: center; gap: 12px; min-width: 0; flex-wrap: wrap; }
.date-wrap {
  position: relative;
  flex: 0 0 132px;
  width: 132px;
  max-width: 132px;
  min-width: 0;
  cursor: pointer;
}
.date-input {
  color: transparent;
  padding-right: 30px;
  max-width: 100%;
  cursor: pointer;
}
.date-input.has-value { color: var(--text-primary); }
.date-input::-webkit-calendar-picker-indicator {
  position: absolute;
  right: 9px;
  top: 50%;
  transform: translateY(-50%);
  opacity: 0.55;
  filter: invert(0.75);
  cursor: pointer;
}
.date-input::-webkit-calendar-picker-indicator:hover { opacity: 0.9; }
.date-ph {
  position: absolute;
  left: 13px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 13px;
  color: var(--text-muted);
  pointer-events: none;
}

/* 日期区间：起止成对同排，到期读数另起一行 */
.range { display: flex; flex-direction: column; gap: 8px; min-width: 0; }
.range-line { display: flex; align-items: center; gap: 8px; min-width: 0; flex-wrap: wrap; }
.range-tag {
  flex-shrink: 0;
  font-size: 10px;
  letter-spacing: 1px;
  color: var(--text-muted);
  font-family: var(--font);
}
.range-sep { flex-shrink: 0; width: 10px; height: 1px; background: rgba(205, 224, 244, 0.14); }

.form-error { margin-top: 14px; }
</style>
