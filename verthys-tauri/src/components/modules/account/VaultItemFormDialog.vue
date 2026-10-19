<!--
  VaultItemFormDialog.vue — 类型化条目编辑窗口（schema 驱动）
  形态：复用 VerthysDialog + 「凭证登记台」皮肤（分区登记行 + 刻度轴 + 选项条 + 内容舱）。
  驱动：字段清单来自 VaultTypeDef.fields，六类控件按 kind 渲染，不按类型名分支。
  特化：账号类型保留既有窗口结构与行为（标识 / 凭据 / 加密 / 附注四段 + 独立密钥行），
        独立加密的落盘判定交由 lib/vault_item_codec 的保存决策完成。
  用法:
    <VaultItemFormDialog
      v-model="showForm" :type-def="formType" :initial-data="formInitial"
      @submit="onPersist"
    />
-->
<template>
  <VerthysDialog
    v-model="open"
    :title="panelTitle"
    layout="plain"
    class="reg-panel"
    :save-label="isEdit ? '保存修改' : '确认'"
    :save-disabled="saveDisabled"
    :saving="saving"
    @save="onSubmit"
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
          <span class="reg-title">{{ panelTitle }}</span>
        </span>
        <button class="reg-close" type="button" @click="open = false" aria-label="关闭窗口" v-tip="'关闭'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </header>
    </template>

    <!-- 账号窗口：与既有实现逐段一致（标识 / 凭据 / 加密 / 附注） -->
    <div v-if="def && isAccount" class="reg-body">
      <section class="reg-section" :style="{ '--rs': '0' }">
        <div class="reg-sec-head">
          <span class="reg-sec-no">01</span>
          <span class="reg-sec-name">标识</span>
          <span class="reg-rule"></span>
        </div>
        <div class="reg-row">
          <label class="reg-key" for="acc-f-platform"><i class="reg-req" aria-hidden="true">*</i>平台</label>
          <input id="acc-f-platform" class="reg-input" v-model="values.platform" aria-required="true" />
        </div>
        <div class="reg-row">
          <label class="reg-key" for="acc-f-username"><i class="reg-req" aria-hidden="true">*</i>账户</label>
          <input id="acc-f-username" class="reg-input" v-model="values.username" aria-required="true" />
        </div>
      </section>

      <section class="reg-section" :style="{ '--rs': '1' }">
        <div class="reg-sec-head">
          <span class="reg-sec-no">02</span>
          <span class="reg-sec-name">凭据<i class="reg-req" aria-hidden="true">*</i></span>
          <span class="reg-rule"></span>
        </div>
        <div class="reg-row">
          <label class="reg-key" for="acc-f-password">密码</label>
          <div class="reg-input-group">
            <input id="acc-f-password" class="reg-input" v-model="values.password" :type="pwdVisible.password ? 'text' : 'password'" aria-required="true" />
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

      <section class="reg-section" :style="{ '--rs': '2' }">
        <div class="reg-sec-head">
          <span class="reg-sec-no">03</span>
          <span class="reg-sec-name">加密</span>
          <span class="reg-rule"></span>
        </div>
        <label class="reg-option" :class="{ on: accountEncrypted }">
          <input class="reg-option-input" type="checkbox" v-model="accountEncrypted" :disabled="initialEncrypted" />
          <span class="reg-option-check"></span>
          <span class="reg-option-text">独立加密</span>
          <span class="reg-option-hint">查看时需二次输入独立密钥</span>
        </label>
        <div v-if="accountEncrypted" class="reg-row reg-option-row">
          <label class="reg-key" for="acc-f-encKey">密钥</label>
          <div class="reg-input-group">
            <input
              id="acc-f-encKey"
              class="reg-input"
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
        <p v-if="accountEncrypted && !accountEncKey" class="reg-hint-inline">请输入独立密钥后保存</p>
      </section>

      <section class="reg-section" :style="{ '--rs': '3' }">
        <div class="reg-sec-head">
          <span class="reg-sec-no">04</span>
          <span class="reg-sec-name">附注</span>
          <span class="reg-rule"></span>
        </div>
        <div class="reg-row">
          <label class="reg-key" for="acc-f-note">备注</label>
          <textarea id="acc-f-note" class="reg-input reg-textarea" v-model="values.note" rows="2"></textarea>
        </div>
      </section>
    </div>

    <!-- 通用窗口：字段按 kind 渲染，顺序即字段清单顺序 -->
    <div v-else-if="def" class="reg-body">
      <section class="reg-section" :style="{ '--rs': '0' }">
        <div class="reg-sec-head">
          <span class="reg-sec-no">01</span>
          <span class="reg-sec-name">{{ def.label }}</span>
          <span class="reg-rule"></span>
        </div>
        <div class="form-fields">
          <template v-for="field in def.fields" :key="field.id">
            <!-- 选项条：整行可点的开关（用户自定义类型可能声明） -->
            <label v-if="field.kind === 'switch'" class="reg-option" :class="{ on: values[field.id] === '1' }">
              <input
                class="reg-option-input"
                type="checkbox"
                :checked="values[field.id] === '1'"
                @change="onSwitchChange(field.id, $event)"
              />
              <span class="reg-option-check"></span>
              <span class="reg-option-text">{{ field.label }}</span>
              <span v-if="field.hint" class="reg-option-hint">{{ field.hint }}</span>
            </label>

            <!-- 内容舱：长文本凭据，支持拖拽与文件导入 -->
            <div v-else-if="field.carrier" class="reg-row reg-row-vault">
              <label class="reg-key" :for="domId(field)"><i v-if="field.required" class="reg-req" aria-hidden="true">*</i>{{ field.label }}</label>
              <div
                class="reg-vault reg-vault-inline"
                :class="{ 'is-drag': dragFieldId === field.id }"
                @dragover.prevent="onDragOver(field.id)"
                @dragleave.prevent="onDragLeave($event, field.id)"
                @drop.prevent="onDrop($event, field.id)"
              >
                <textarea
                  :id="domId(field)"
                  class="reg-vault-input"
                  :rows="field.multilineRows ?? 5"
                  v-model="values[field.id]"
                ></textarea>
                <div class="reg-vault-bar">
                  <button class="reg-vault-import" type="button" @click="triggerFilePick(field.id)">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    <span>导入文件</span>
                  </button>
                  <span v-if="pickedFileName[field.id]" class="reg-vault-file" v-tip="pickedFileName[field.id]">{{ pickedFileName[field.id] }}</span>
                  <span class="reg-vault-readout">{{ dragFieldId === field.id ? '松开即导入' : charStats(field.id) }}</span>
                </div>
              </div>
            </div>

            <!-- 日期：日期控件 + 到期读数 -->
            <div v-else-if="field.kind === 'date'" class="reg-row">
              <label class="reg-key" :for="domId(field)"><i v-if="field.required" class="reg-req" aria-hidden="true">*</i>{{ field.label }}</label>
              <div class="reg-expiry">
                <div class="reg-date-wrap" @click="openDatePicker($event)">
                  <input :id="domId(field)" class="reg-input reg-date" :class="{ 'has-value': values[field.id] }" type="date" v-model="values[field.id]" />
                  <span v-if="!values[field.id]" class="reg-date-ph">未设置</span>
                </div>
                <span class="reg-readout" :class="`is-${readoutFor(field.id).tone}`">
                  <i class="reg-readout-dot"></i>{{ readoutFor(field.id).text }}
                </span>
              </div>
            </div>

            <!-- 选择：下拉候选项 -->
            <div v-else-if="field.kind === 'select'" class="reg-row">
              <label class="reg-key" :for="domId(field)"><i v-if="field.required" class="reg-req" aria-hidden="true">*</i>{{ field.label }}</label>
              <select :id="domId(field)" class="reg-input reg-select" v-model="values[field.id]">
                <option value="">未指定</option>
                <option v-for="opt in field.options ?? []" :key="opt" :value="opt">{{ opt }}</option>
              </select>
            </div>

            <!-- 多行文本 -->
            <div v-else-if="field.kind === 'multiline'" class="reg-row">
              <label class="reg-key" :for="domId(field)"><i v-if="field.required" class="reg-req" aria-hidden="true">*</i>{{ field.label }}</label>
              <textarea :id="domId(field)" class="reg-input reg-textarea" :rows="field.multilineRows ?? 2" v-model="values[field.id]"></textarea>
            </div>

            <!-- 文本 / 密码：密码带显隐切换 -->
            <div v-else class="reg-row">
              <label class="reg-key" :for="domId(field)"><i v-if="field.required" class="reg-req" aria-hidden="true">*</i>{{ field.label }}</label>
              <div v-if="field.kind === 'password'" class="reg-input-group">
                <input
                  :id="domId(field)"
                  class="reg-input"
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
              <input v-else :id="domId(field)" class="reg-input" v-model="values[field.id]" />
            </div>
          </template>
        </div>
      </section>
      <input ref="fileInputRef" type="file" class="reg-file-input" :accept="CARRIER_FILE_ACCEPT" @change="onFilePicked" />
    </div>

    <template #error v-if="formError">
      <div class="reg-error">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        {{ formError }}
      </div>
    </template>
  </VerthysDialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { VaultFieldDef, VaultTypeDef, VaultItemPayload } from "../../../constants/vault_item_types";
import { ACCOUNT_VAULT_TYPE_ID } from "../../../constants/vault_item_types";
import {
  buildVaultItemData,
  resolveSecretSaveAction,
} from "../../../lib/vault_item_codec";
import { vaultExpiryReadout } from "../../../lib/vault_item_card";
import { encryptPasswordField } from "../../../lib/verthys";
import VerthysDialog from "../../common/verthys-ui/VerthysDialog.vue";

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

/** 必填但未填写的字段名（保存按钮禁用条件与提交前校验共用） */
const missingRequired = computed<string[]>(() => {
  const current = def.value;
  if (!current) return [];
  return current.fields
    .filter((field) => field.required === true && !(values.value[field.id] ?? "").trim())
    .map((field) => field.label);
});

/* 账号类型沿用既有保存禁用条件（开启独立加密必须提供密钥）；
 * 其余类型以必填项是否填满为条件 */
const saveDisabled = computed(() =>
  isAccount.value ? accountEncrypted.value && !accountEncKey.value : missingRequired.value.length > 0,
);

/** 重置表单：以类型字段清单与既有数据初始化（新增时全部为空） */
const resetForm = (): void => {
  const current = def.value;
  const next: Record<string, string> = {};
  if (current) {
    for (const field of current.fields) {
      next[field.id] = props.initialData?.[field.id] ?? "";
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

  const plan = resolveSecretSaveAction({
    previousEncrypted: initialEncrypted.value,
    previousValue: props.initialData?.password ?? "",
    currentValue: values.value.password ?? "",
    enableEncryption: accountEncrypted.value,
    hasKey: accountEncKey.value.length > 0,
  });

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

  emit("submit", { kind: current.id, data: buildVaultItemData(current, values.value) });
};
</script>

<style scoped>
/* 通用窗口的字段间距：所有直系字段块统一上间距 10px，首块不留空 */
.form-fields > .reg-row,
.form-fields > .reg-option { margin-top: 10px; }
.form-fields > :first-child { margin-top: 0; }

/* 内容舱所在行：标签与舱顶对齐；舱位刻度与登记行刻度重合，避免双刻度错位 */
.reg-row-vault { align-items: start; }
.reg-row-vault .reg-key { padding-top: 9px; }
.reg-vault-inline::before { content: none; }

/* 独立加密缺密钥的内联提示 */
.reg-hint-inline {
  margin-top: 8px;
  font-size: 11px; letter-spacing: 0.3px;
  color: var(--warning); font-family: var(--font);
}
</style>
