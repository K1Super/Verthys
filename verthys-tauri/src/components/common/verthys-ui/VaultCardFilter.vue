<!--
  VaultCardFilter.vue — 条目高级筛选（按钮 + 折叠面板 + 条件摘要）
  形态：搜索栏内一枚筛选按钮（图标 + 生效条件计数）；开启时按钮左侧显示紧凑摘要与一键清除。
        面板为锚定下拉（非全屏、非弹窗体系），点击外部或 Esc 关闭。
  用法:
    <VaultCardFilter v-model="filterCriteria" :types="pickTypes" :result-count="filteredCount" />
-->
<template>
  <div ref="rootRef" class="vault-filter">
    <!-- 生效条件摘要 + 一键清除（面板收起时也可见） -->
    <span v-if="summary" class="filter-summary" v-tip="summary">
      <span class="summary-text">{{ summary }}</span>
      <button class="summary-clear" type="button" aria-label="清除筛选" v-tip="'清除筛选'" @click="clear">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </span>

    <!-- 触发键：复用共享 ActionButton 及其主键皮肤（与同行「添加」键同一套样式，
         仅图标不同），使二者在盒模型与皮肤上完全一致 -->
    <span class="filter-trigger-wrap">
      <ActionButton
        primary
        :aria-expanded="open"
        aria-haspopup="true"
        :aria-label="activeCount > 0 ? `筛选（已选 ${activeCount} 项）` : '筛选'"
        v-tip="'筛选'"
        :show-plus="false"
        @click="toggle"
      >
        <template #icon>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 5h18l-7 8v6l-4 2v-8z"/></svg>
        </template>
      </ActionButton>
      <span v-if="activeCount > 0" class="filter-count">{{ activeCount }}</span>
    </span>

    <div v-if="open" class="filter-panel" role="dialog" aria-label="筛选条件">
      <section class="filter-group">
        <div class="filter-group-head">类型</div>
        <div class="filter-chips">
          <button
            v-for="def in types"
            :key="def.id"
            type="button"
            class="filter-chip"
            :aria-pressed="criteria.kinds.includes(def.id)"
            :data-on="criteria.kinds.includes(def.id) ? '1' : '0'"
            @click="toggleKind(def.id)"
          >{{ def.label }}</button>
        </div>
      </section>

      <section class="filter-group">
        <div class="filter-group-head">到期状态</div>
        <div class="filter-chips">
          <button
            v-for="option in expiryOptions"
            :key="option.id"
            type="button"
            class="filter-chip"
            :aria-pressed="criteria.expiry.includes(option.id)"
            :data-on="criteria.expiry.includes(option.id) ? '1' : '0'"
            @click="toggleExpiry(option.id)"
          >{{ option.label }}</button>
        </div>
      </section>

      <section class="filter-group">
        <div class="filter-group-head">保护状态</div>
        <div class="filter-chips">
          <button
            v-for="option in protectionOptions"
            :key="option.id"
            type="button"
            class="filter-chip"
            :aria-pressed="criteria.protection.includes(option.id)"
            :data-on="criteria.protection.includes(option.id) ? '1' : '0'"
            @click="toggleProtection(option.id)"
          >{{ option.label }}</button>
        </div>
      </section>

      <section class="filter-group">
        <div class="filter-group-head">排序</div>
        <div class="filter-chips">
          <button
            v-for="option in sortOptions"
            :key="option.id"
            type="button"
            class="filter-chip"
            :aria-pressed="criteria.sort === option.id"
            :data-on="criteria.sort === option.id ? '1' : '0'"
            @click="setSort(option.id)"
          >{{ option.label }}</button>
        </div>
      </section>

      <div class="filter-foot">
        <span class="filter-result">筛选后 {{ resultCount }} 条</span>
        <button class="filter-clear" type="button" :disabled="activeCount === 0" @click="clear">清除筛选</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import ActionButton from "./ActionButton.vue";
import type { VaultTypeDef } from "../../../constants/vault_item_types";
import {
  VAULT_EXPIRY_FILTER_OPTIONS,
  VAULT_PROTECTION_FILTER_OPTIONS,
  VAULT_SORT_OPTIONS,
  countActiveVaultFilters,
  createEmptyVaultFilter,
  describeVaultFilter,
  type VaultExpiryFilter,
  type VaultFilterCriteria,
  type VaultProtectionFilter,
  type VaultSortKey,
} from "../../../lib/vault_item_filter";

const props = defineProps<{
  modelValue: VaultFilterCriteria;
  /** 可供选择的类型（内置在前、自定义在后） */
  types: readonly VaultTypeDef[];
  /** 当前条件在已加载数据上的命中条数（由列表模块计算，面板内实时回显） */
  resultCount: number;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", criteria: VaultFilterCriteria): void;
}>();

const expiryOptions = VAULT_EXPIRY_FILTER_OPTIONS;
const protectionOptions = VAULT_PROTECTION_FILTER_OPTIONS;
const sortOptions = VAULT_SORT_OPTIONS;

const open = ref(false);
const rootRef = ref<HTMLElement | null>(null);

const criteria = computed(() => props.modelValue);
const activeCount = computed(() => countActiveVaultFilters(criteria.value));
const summary = computed(() => {
  const labelOf = (kind: string): string =>
    props.types.find((def) => def.id === kind)?.label ?? kind;
  return describeVaultFilter(criteria.value, labelOf);
});

/** 以新条件替换整体条件对象，保证父级拿到新引用以便重算列表 */
const patch = (part: Partial<VaultFilterCriteria>): void => {
  emit("update:modelValue", { ...criteria.value, ...part });
};

const toggleIn = <T,>(list: T[], value: T): T[] =>
  list.includes(value) ? list.filter((item) => item !== value) : [...list, value];

const toggleKind = (kind: string): void => patch({ kinds: toggleIn(criteria.value.kinds, kind) });
const toggleExpiry = (flag: VaultExpiryFilter): void => patch({ expiry: toggleIn(criteria.value.expiry, flag) });
const toggleProtection = (flag: VaultProtectionFilter): void =>
  patch({ protection: toggleIn(criteria.value.protection, flag) });
const setSort = (sort: VaultSortKey): void => patch({ sort });

const clear = (): void => emit("update:modelValue", createEmptyVaultFilter());

const toggle = (): void => {
  open.value = !open.value;
};

/** 关闭面板：点击面板外或按下 Esc */
const onDocumentPointerDown = (e: PointerEvent): void => {
  const root = rootRef.value;
  if (!root) return;
  const target = e.target as Node | null;
  if (target && root.contains(target)) return;
  open.value = false;
};

const onDocumentKeydown = (e: KeyboardEvent): void => {
  if (e.key === "Escape") open.value = false;
};

/* 面板开启期间才挂全局监听，收起后立即释放，避免常驻全局事件 */
watch(open, (value) => {
  if (value) {
    document.addEventListener("pointerdown", onDocumentPointerDown, true);
    document.addEventListener("keydown", onDocumentKeydown);
  } else {
    document.removeEventListener("pointerdown", onDocumentPointerDown, true);
    document.removeEventListener("keydown", onDocumentKeydown);
  }
});

onBeforeUnmount(() => {
  document.removeEventListener("pointerdown", onDocumentPointerDown, true);
  document.removeEventListener("keydown", onDocumentKeydown);
});
</script>

<style scoped>
.vault-filter { position: relative; display: flex; align-items: center; gap: 8px; flex-shrink: 0; }

/* 条件摘要：面板收起时仍可见，一行紧凑文案 + 一键清除 */
.filter-summary {
  display: inline-flex; align-items: center; gap: 2px;
  max-width: 190px; padding: 2px 2px 2px 8px;
  border: 1px solid var(--border-glass); border-radius: 10px;
  font-size: 10.5px; letter-spacing: 0.5px; font-family: var(--font);
  color: var(--accent);
}
.summary-text { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.summary-clear {
  display: flex; align-items: center; justify-content: center;
  width: 16px; height: 16px; padding: 0;
  background: none; border: none; color: inherit;
  cursor: pointer; opacity: 0.7;
}
.summary-clear svg { width: 11px; height: 11px; }
.summary-clear:hover { opacity: 1; }
.summary-clear:focus-visible { outline: 1px solid var(--border-hover); outline-offset: 1px; }

/* 筛选按钮：几何、皮肤与图标口径全部交由共享 .btn / .btn-icon 与 ActionButton 提供，
   此处只承载计数角标。
   角标取深色底：主键皮肤本身是实心亮面，角标需自带衬底才能分辨 */
.filter-trigger-wrap { position: relative; display: inline-flex; flex-shrink: 0; }
.filter-count {
  position: absolute; top: -5px; right: -5px;
  min-width: 13px; height: 13px; padding: 0 3px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 7px;
  background: rgba(var(--black-rgb), 0.8);
  color: var(--accent);
  font-size: 9px; line-height: 1; font-family: var(--font-mono);
  pointer-events: none;
}

/* 锚定面板：绝对定位下拉，不覆盖整屏、不进入弹窗体系 */
.filter-panel {
  position: absolute; top: calc(100% + 8px); right: 0; z-index: 120;
  width: 320px; max-height: 60vh; overflow-y: auto;
  padding: 14px;
  background: var(--bar-surface);
  border: 1px solid var(--border-glass); border-radius: var(--radius);
  box-shadow: 0 12px 36px rgba(var(--black-rgb), 0.5);
  animation: filter-panel-in 0.24s var(--ease);
}
@keyframes filter-panel-in {
  from { opacity: 0; }
  to { opacity: 1; }
}

.filter-group + .filter-group { margin-top: 12px; }
.filter-group-head {
  margin-bottom: 7px;
  font-size: 10.5px; letter-spacing: 2px; color: var(--text-secondary); font-family: var(--font);
}
.filter-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.filter-chip {
  padding: 4px 9px;
  background: rgba(var(--white-rgb), 0.02);
  border: 1px solid var(--border-glass); border-radius: 10px;
  color: var(--text-secondary); font-size: 11px; letter-spacing: 0.5px; font-family: var(--font);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
}
.filter-chip:hover { color: var(--text-primary); border-color: var(--border-hover); }
.filter-chip:focus-visible { outline: 1px solid var(--border-hover); outline-offset: 1px; }
.filter-chip[data-on="1"] {
  color: var(--accent);
  border-color: rgba(var(--accent-rgb), 0.28);
  background: rgba(var(--accent-rgb), 0.06);
}

.filter-foot {
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
  margin-top: 14px; padding-top: 10px;
  border-top: 1px solid var(--border-glass);
}
.filter-result { font-size: 10.5px; letter-spacing: 0.5px; color: var(--text-muted); font-family: var(--font-mono); }
.filter-clear {
  padding: 3px 9px;
  background: none; border: 1px solid var(--border-glass); border-radius: 6px;
  color: var(--text-secondary); font-size: 11px; font-family: var(--font);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}
.filter-clear:hover:not(:disabled) { color: var(--accent); border-color: var(--border-hover); }
.filter-clear:disabled { color: var(--text-muted); cursor: not-allowed; }
</style>
