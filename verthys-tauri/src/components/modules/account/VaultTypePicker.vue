<!--
  VaultTypePicker.vue — 条目类型选择台

  形态：复用全局弹窗外壳 CosmicOverlay 与 kv-* 内容词汇；
        类型以紧凑行式图块排列（图标在左、名称在右），全部图块取存签主色调。
  语义：纯选择窗口，不产出"保存"语义，动作区只有关闭。
  交互：方向键移动焦点、Enter 进入、Esc 关闭；关闭即取消，不产生任何副作用。
  用法:
    <VaultTypePicker v-model="showPicker" :types="pickTypes" @select="onPickType" />
-->
<template>
  <CosmicOverlay
    :show="open"
    width="520px"
    aria-labelledby="vtp-title"
    @close="open = false"
  >
    <div class="kv-title" id="vtp-title">{{ panelTitle }}</div>

    <div ref="gridRef" class="type-grid" role="group" aria-label="条目类型" @keydown="onKeydown">
      <button
        v-for="def in types"
        :key="def.id"
        type="button"
        class="type-cell"
        @click="choose(def.id)"
      >
        <SafeSvgIcon class="type-cell-icon" :source="resolveVaultIcon(def.icon)" />
        <span class="type-cell-label">{{ def.label }}</span>
      </button>

      <!-- 末尾入口：进入自定义类型管理（新建 / 编辑 / 删除类型） -->
      <button v-if="manageable" type="button" class="type-cell type-cell-manage" @click="manage">
        <span class="type-cell-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        </span>
        <span class="type-cell-label">自定义…</span>
      </button>
    </div>

    <div class="kv-actions">
      <button class="btn kv-cancel" type="button" @click="open = false">关闭</button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";
import type { VaultTypeDef } from "../../../constants/vault_item_types";
import { resolveVaultIcon } from "../../../constants/vault_item_types";
import CosmicOverlay from "../../common/cosmic/CosmicOverlay.vue";
import SafeSvgIcon from "../../common/SafeSvgIcon.vue";

const props = defineProps<{
  modelValue: boolean;
  /** 可选类型（内置在前、自定义在后；顺序即展示顺序） */
  types: readonly VaultTypeDef[];
  /** 面板标题（重新指派类型时由调用方覆写） */
  title?: string;
  /** 是否展示自定义类型管理入口 */
  manageable?: boolean;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", val: boolean): void;
  (e: "select", typeId: string): void;
  (e: "manage"): void;
}>();

const open = computed({
  get: () => props.modelValue,
  set: (val: boolean) => emit("update:modelValue", val),
});

const panelTitle = computed(() => props.title ?? "选择类型");

/** 网格容器引用（键盘焦点迁移按文档顺序取图块，不依赖逐项引用） */
const gridRef = ref<HTMLElement | null>(null);

/** 取网格内全部图块按钮（按文档顺序） */
const gridCells = (): HTMLButtonElement[] => {
  const root = gridRef.value;
  if (!root) return [];
  return Array.from(root.querySelectorAll<HTMLButtonElement>(".type-cell"));
};

const choose = (typeId: string): void => {
  emit("select", typeId);
  open.value = false;
};

/** 进入自定义类型管理：关闭本面板后由调用方打开类型编辑器 */
const manage = (): void => {
  emit("manage");
  open.value = false;
};

/**
 * 键盘交互：方向键在网格内循环移动焦点；Esc 与焦点陷阱由外壳承担。
 * 焦点落在图块按钮上，点击与回车由按钮自身处理，此处只做焦点迁移。
 */
const onKeydown = (e: KeyboardEvent): void => {
  const cells = gridCells();
  if (cells.length === 0) return;

  const current = cells.findIndex((cell) => cell === document.activeElement);
  let next = current;

  if (e.key === "ArrowRight" || e.key === "ArrowDown") {
    next = current < 0 ? 0 : (current + 1) % cells.length;
  } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
    next = current < 0 ? cells.length - 1 : (current - 1 + cells.length) % cells.length;
  } else {
    return;
  }

  e.preventDefault();
  cells[next].focus();
};
</script>

<style scoped>
/* 图块网格：等宽列，行高固定 —— 类型名长短不影响排列节奏 */
.type-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(74px, 1fr));
  gap: 6px;
}

/* 图块：图标在左、名称在右的窄行式；统一取存签主色调的低透度层 */
.type-cell {
  position: relative;
  display: flex;
  align-items: center;
  gap: 6px;
  height: 32px;
  padding: 0 6px;
  background: linear-gradient(
    168deg,
    rgba(var(--accent-rgb), 0.055),
    rgba(var(--accent-rgb), 0.012)
  );
  border: 1px solid rgba(var(--accent-rgb), 0.16);
  border-radius: 7px;
  color: var(--text-secondary);
  font-size: 12px;
  letter-spacing: 0.5px;
  font-family: var(--font);
  cursor: pointer;
  transition:
    color var(--dur-fast) var(--ease),
    border-color var(--dur-fast) var(--ease),
    background-color var(--dur-fast) var(--ease);
}
.type-cell:hover {
  color: var(--text-primary);
  border-color: rgba(var(--accent-rgb), 0.38);
  background-color: rgba(var(--accent-rgb), 0.07);
}
.type-cell:active {
  border-color: rgba(var(--accent-rgb), 0.52);
  background-color: rgba(var(--accent-rgb), 0.11);
}
.type-cell:focus-visible {
  outline: 1px solid rgba(var(--accent-rgb), 0.6);
  outline-offset: 2px;
}

.type-cell-icon { width: 12px; height: 12px; flex-shrink: 0; color: var(--accent); }
.type-cell-icon :deep(svg) { display: block; width: 100%; height: 100%; }

.type-cell-label {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* 管理入口：虚线描边与可选类型区分，色相回落中性并仅在交互时注能 */
.type-cell-manage {
  border-style: dashed;
  border-color: rgba(205, 224, 244, 0.14);
  color: var(--text-muted);
}
.type-cell-manage .type-cell-icon { color: var(--text-muted); }
.type-cell-manage:hover { color: var(--text-primary); border-color: var(--border-hover); }
.type-cell-manage:hover .type-cell-icon { color: var(--accent); }
</style>
