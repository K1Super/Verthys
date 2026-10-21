<!--
  VerthysDialog.vue — 模块对话框外壳（各模块共享）
  用法:
    <VerthysDialog v-model="showDialog" :title="editing ? '编辑' : '新增'" @save="onSave">
      <template #default>…表单字段…</template>
      <template #error>…</template>
    </VerthysDialog>

  可编排能力（不启用时保持上述默认形态）：
    - #header 插槽：以模块自定义头部替换默认标题行
    - layout="plain"：内容不再套用双列网格，由调用方自行组织排版
    - hide-actions：不渲染动作区（纯选择类窗口无"保存"语义，由头部关闭键承担取消）
    - class/style 等 attrs 透传至面板（.dialog），供模块定制皮肤
-->
<template>
  <div v-if="modelValue" class="dialog-overlay" @click.self="onOverlayClick">
    <div
      ref="panelRef"
      v-bind="$attrs"
      class="dialog glass"
      role="dialog"
      aria-modal="true"
      :aria-label="title || undefined"
      tabindex="-1"
      :style="width ? { minWidth: width, maxWidth: width } : undefined"
    >
      <slot name="header">
        <div class="dialog-title">{{ title }}</div>
      </slot>
      <div v-if="layout === 'grid'" class="form-grid">
        <slot />
      </div>
      <slot v-else />
      <slot name="error" />
      <div v-if="!hideActions" class="dialog-actions">
        <button class="btn kv-cancel" @click="$emit('update:modelValue', false)" :disabled="saving">取消</button>
        <button class="btn btn-primary kv-confirm" @click="$emit('save')" :disabled="saveDisabled || saving">
          {{ saving ? savingLabel : (saveLabel || '保存') }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, watch } from "vue";
/* 模态栈与滚动锁由 utils/modal_stack 统一维护：
 *   同一文档可同时存在多层对话框（编辑器内再叠确认删除），共享一份栈才能
 *   让 Esc 只由栈顶响应、滚动锁按层计数。 */
import { isTopModal as isTopModalId, popModal, pushModal } from "../../../utils/modal_stack";

/* attrs 透传交由模板内 v-bind 控制：class/style 等落到面板而非遮罩层，
 * 使模块皮肤定制与遮罩行为解耦 */
defineOptions({ inheritAttrs: false });

const props = withDefaults(defineProps<{
  modelValue: boolean;
  /** 默认标题行文案；提供 #header 插槽时由插槽内容取代 */
  title?: string;
  saveDisabled?: boolean;
  saving?: boolean;
  saveLabel?: string;
  /** 对话框宽度（如 "420px"），不传则使用默认 min-width: 460px */
  width?: string;
  /** 内容容器布局：grid = 双列网格（默认）；plain = 不套用容器，调用方自组排版 */
  layout?: "grid" | "plain";
  /** 处理中确认按钮文案（默认「保存中…」；语义窗口可覆写，如「修改中…」「验证中…」） */
  savingLabel?: string;
  /** 不渲染动作区：纯选择/只读类窗口无保存语义，取消由头部关闭键或遮罩承担 */
  hideActions?: boolean;
}>(), {
  layout: "grid",
  savingLabel: "保存中…",
});

const emit = defineEmits<{
  (e: "update:modelValue", val: boolean): void;
  (e: "save"): void;
}>();

const panelRef = ref<HTMLElement | null>(null);

/** 本实例在模态栈中的身份：Symbol 保证多实例互不相等 */
const modalId = Symbol("verthys-dialog");

/** 打开前的焦点来源，关闭后原路归还，避免键盘操作位置丢失 */
let savedFocus: HTMLElement | null = null;

/** 面板内可聚焦元素的选择器（按文档顺序取用，构成 Tab 环形路径） */
const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

/** 收集面板内实际可聚焦的元素：display:none / 未布局的控件不参与环 */
function focusableIn(panel: HTMLElement): HTMLElement[] {
  return Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    (el) => el.offsetParent !== null || el === document.activeElement,
  );
}

function isTopModal(): boolean {
  return isTopModalId(modalId);
}

function onKeydown(e: KeyboardEvent): void {
  if (!props.modelValue || !isTopModal()) return;

  if (e.key === "Escape") {
    e.preventDefault();
    // 请求在途时不得关闭：窗口消失会让已提交的写入失去落点提示
    if (props.saving) return;
    emit("update:modelValue", false);
    return;
  }

  if (e.key !== "Tab") return;
  const panel = panelRef.value;
  if (!panel) return;
  const items = focusableIn(panel);
  if (items.length === 0) {
    e.preventDefault();
    panel.focus();
    return;
  }
  const first = items[0];
  const last = items[items.length - 1];
  const active = document.activeElement as HTMLElement | null;
  const inside = active !== null && active !== panel && panel.contains(active);
  if (!e.shiftKey) {
    if (!inside || active === last) {
      e.preventDefault();
      first.focus();
    }
  } else if (!inside || active === first) {
    e.preventDefault();
    last.focus();
  }
}

/** 入场焦点：优先首个可交互控件，无控件时落到面板自身（面板可聚焦以承接 Esc/Tab） */
function focusInitial(): void {
  const panel = panelRef.value;
  if (!panel) return;
  const items = focusableIn(panel);
  (items[0] ?? panel).focus();
}

function onOverlayClick(): void {
  if (props.saving) return;
  emit("update:modelValue", false);
}

function teardown(): void {
  document.removeEventListener("keydown", onKeydown, true);
  popModal(modalId);
  const target = savedFocus;
  savedFocus = null;
  if (target && target.isConnected) target.focus();
}

watch(
  () => props.modelValue,
  async (open) => {
    if (open) {
      const active = document.activeElement;
      savedFocus = active instanceof HTMLElement ? active : null;
      pushModal(modalId);
      document.addEventListener("keydown", onKeydown, true);
      await nextTick();
      focusInitial();
    } else {
      teardown();
    }
  },
  { immediate: true },
);

onBeforeUnmount(() => {
  if (props.modelValue) teardown();
});
</script>

<style scoped>
.dialog-overlay {
  position: fixed; inset: 0;
  background: rgba(0, 0, 0, 0.74);
  display: flex; align-items: center; justify-content: center;
  z-index: 1000;
}
.dialog {
  padding: 28px; min-width: 460px; max-width: 90vw; max-height: 85vh; overflow-y: auto;
  animation: dialog-in 0.4s var(--ease);
}
/* 面板可聚焦是为了在无控件时承接键盘事件，本身不是交互目标，不显示焦点框 */
.dialog:focus,
.dialog:focus-visible { outline: none; }
.dialog-title {
  font-size: 14px; margin-bottom: 20px;
  color: var(--accent); letter-spacing: 2px; font-family: var(--font);
}
.form-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 12px;
}
.dialog-actions {
  display: flex; justify-content: flex-end; gap: 10px;
  margin-top: 20px; padding-top: 14px; border-top: 1px solid var(--border-glass);
}

/* 入场只走 2D 平移与不透明度：弹窗体含表单文字与矢量控件，
 * scale 会让内容纹理按非 1 比例缩放、结束帧再重栅格化 —
 * 出现中即"模糊 → 清晰"跳变，故不设缩放分量。 */
@keyframes dialog-in {
  from { opacity: 0; transform: translateY(12px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>