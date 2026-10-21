<!--
  CosmicOverlay.vue — 可复用宇宙主题弹窗遮罩
  v3: 背景层由通用组件 CosmicBackdrop 提供，底板由 CosmicDialog 提供
  与 SecurityCenter 等模块共享统一背景 + 底板规范
-->
<template>
  <Transition name="cosmic">
    <CosmicBackdrop v-if="show" fixed @backdrop="onBackdrop">
      <div ref="hostRef" class="cosmic-overlay-host">
        <CosmicDialog
          :width="width"
          role="dialog"
          aria-modal="true"
          :aria-label="ariaLabel"
        >
          <slot />
        </CosmicDialog>
      </div>
    </CosmicBackdrop>
  </Transition>
</template>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, watch } from "vue";
import CosmicBackdrop from "./CosmicBackdrop.vue";
import CosmicDialog from "./CosmicDialog.vue";

interface Props {
  show: boolean;
  width?: string;
  /** 点击遮罩背景是否关闭（默认 true） */
  backdropClose?: boolean;
  /** 弹窗无障碍名称（读屏播报；无可见标题关联时的兜底） */
  ariaLabel?: string;
}

const props = withDefaults(defineProps<Props>(), {
  width: "400px",
  backdropClose: true,
  ariaLabel: "对话框",
});

const emit = defineEmits<{ (e: "close"): void }>();

const onBackdrop = () => {
  if (props.backdropClose) emit("close");
};

/* ===== 模态语义：焦点陷阱 + Esc 关闭 + 焦点归还 =====
 * 旧实现仅有视觉遮罩：键盘 Tab 可穿透到背景页面，Esc 无响应，
 * 关闭后焦点丢失到 body —— 读屏与键盘用户无法完成弹窗交互闭环。 */
const hostRef = ref<HTMLElement | null>(null);
let prevFocus: HTMLElement | null = null;

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

/** 当前弹窗内可见的可聚焦元素（按 DOM 顺序） */
const collectFocusables = (): HTMLElement[] => {
  const host = hostRef.value;
  if (!host) return [];
  return Array.from(host.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR))
    .filter((el) => el.offsetParent !== null || el === document.activeElement);
};

const onKeydown = (e: KeyboardEvent) => {
  if (!props.show) return;
  if (e.key === 'Escape') {
    e.preventDefault();
    emit('close');
    return;
  }
  if (e.key !== 'Tab') return;
  const list = collectFocusables();
  const host = hostRef.value;
  if (!host) return;
  if (list.length === 0) {
    e.preventDefault();
    return;
  }
  const first = list[0];
  const last = list[list.length - 1];
  const active = document.activeElement as HTMLElement | null;
  const inside = active !== null && host.contains(active);
  if (e.shiftKey) {
    if (!inside || active === first) {
      e.preventDefault();
      last.focus();
    }
  } else if (!inside || active === last) {
    e.preventDefault();
    first.focus();
  }
};

watch(
  () => props.show,
  async (show) => {
    if (show) {
      prevFocus =
        document.activeElement instanceof HTMLElement ? document.activeElement : null;
      document.addEventListener('keydown', onKeydown, true);
      await nextTick();
      const list = collectFocusables();
      (list[0] ?? hostRef.value)?.focus?.();
    } else {
      document.removeEventListener('keydown', onKeydown, true);
      if (prevFocus && prevFocus.isConnected) prevFocus.focus();
      prevFocus = null;
    }
  },
  { immediate: true },
);

onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKeydown, true);
});
</script>

<style scoped>
/* display: contents —— 语义包装不参与布局（弹窗仍是遮罩的居中子项） */
.cosmic-overlay-host {
  display: contents;
}
</style>

<style scoped>
/* ===== 进场 / 退场动画（针对子组件根元素） ===== */
.cosmic-enter-active {
  transition: opacity 0.3s var(--ease);
}
.cosmic-enter-active :deep(.cosmic-dialog) {
  transition: opacity 0.45s var(--ease), transform 0.45s var(--ease);
}
.cosmic-leave-active {
  transition: opacity 0.2s var(--ease);
}
.cosmic-leave-active :deep(.cosmic-dialog) {
  transition: opacity 0.2s var(--ease), transform 0.2s var(--ease);
}
.cosmic-enter-from {
  opacity: 0;
}
/* 遮罩与弹窗渡越只走 2D 平移与不透明度：弹窗内含文字与矢量标识，
 * scale 会使内容纹理按非 1 比例缩放、结束帧再重栅格化，出现中即
 * "模糊 → 清晰"跳变 — 方向感由平移承担，不依赖缩放。 */
.cosmic-enter-from :deep(.cosmic-dialog) {
  opacity: 0;
  transform: translateY(20px);
}
.cosmic-leave-to {
  opacity: 0;
}
.cosmic-leave-to :deep(.cosmic-dialog) {
  opacity: 0;
  transform: translateY(8px);
}
</style>
