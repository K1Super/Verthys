<!--
  CosmicOverlay.vue — 可复用宇宙主题弹窗遮罩
  背景层由 CosmicBackdrop 提供，底板由 CosmicDialog 提供；
  遮罩底色与星野装饰收在 CosmicBackdrop 的幕层（.cb-veil）内，
  与底板并列而不在其祖先链上 —— 入场/退场的不透明度只落在幕层与底板自身，
  遮罩根节点恒为不透明，底板的背衬折射不会在淡入期被边界截断。
  高优先窗口可传 teleport + overlayZ，脱离应用堆叠上下文并提升层级。
-->
<template>
  <Teleport to="body" :disabled="!teleport">
    <Transition name="cosmic">
      <CosmicBackdrop
        v-if="show"
        fixed
        veil="lucent"
        :z-index="overlayZ"
        @backdrop="onBackdrop"
      >
        <div ref="hostRef" class="cosmic-overlay-host" tabindex="-1">
          <CosmicDialog
            :width="width"
            :role="role"
            aria-modal="true"
            :aria-label="ariaLabelledby ? undefined : ariaLabel"
            :aria-labelledby="ariaLabelledby || undefined"
          >
            <slot />
          </CosmicDialog>
        </div>
      </CosmicBackdrop>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, watch } from "vue";
import CosmicBackdrop from "./CosmicBackdrop.vue";
import CosmicDialog from "./CosmicDialog.vue";
/* 模态栈与滚动锁由 utils/modal_stack 统一维护：多层窗口并存时只有栈顶
 * 响应 Esc；滚动锁按层计数，内层关闭不会提前解锁页面 */
import { isTopModal, popModal, pushModal } from "../../../utils/modal_stack";

interface Props {
  show: boolean;
  width?: string;
  /** 面板语义：普通窗口为 dialog；不可逆确认窗为 alertdialog */
  role?: "dialog" | "alertdialog";
  /** 点击遮罩背景是否关闭（默认 true）；与 persistent 取与 */
  backdropClose?: boolean;
  /** 强制窗口：Esc 与遮罩点击均不得关闭，只能由业务动作结束 */
  persistent?: boolean;
  /** 弹窗无障碍名称（无可见标题关联时使用；ariaLabelledby 优先） */
  ariaLabel?: string;
  /** 标题元素 id：存在时以关联标题作为无障碍名称 */
  ariaLabelledby?: string;
  /** 打开时的初始焦点选择器（如 ".kv-cancel"）；缺省落到首个可聚焦元素 */
  initialFocus?: string;
  /** 是否将遮罩 teleport 到 body：保证模态始终覆盖应用堆叠上下文 */
  teleport?: boolean;
  /** 遮罩层级（默认沿用 Cosmic 弹窗层 9999；高优先窗口可提升到 10000） */
  overlayZ?: number;
}

const props = withDefaults(defineProps<Props>(), {
  width: "400px",
  role: "dialog",
  backdropClose: true,
  persistent: false,
  ariaLabel: "对话框",
  ariaLabelledby: "",
  initialFocus: "",
  teleport: true,
  overlayZ: 9999,
});

const emit = defineEmits<{ (e: "close"): void }>();

/** 本实例在模态栈中的身份：嵌套窗口只允许栈顶响应 Esc 与遮罩关闭 */
const modalId = Symbol("cosmic-overlay");

/** 关闭请求的唯一判定：强制窗口与禁用遮罩关闭时，Esc 同样不得放行 */
const canDismiss = (): boolean =>
  isTopModal(modalId) && props.backdropClose && !props.persistent;

const onBackdrop = () => {
  if (canDismiss()) emit("close");
};

/* ===== 模态语义：焦点陷阱 + Esc 关闭 + 焦点归还 =====
 * 仅视觉遮罩无法完成键盘与读屏交互闭环：Tab 会穿透到背景页面，Esc 无
 * 响应，关闭后焦点丢失到 body。 */
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
  if (!props.show || !isTopModal(modalId)) return;
  if (e.key === 'Escape') {
    e.preventDefault();
    if (canDismiss()) emit('close');
    return;
  }
  if (e.key !== 'Tab') return;
  const list = collectFocusables();
  const host = hostRef.value;
  if (!host) return;
  if (list.length === 0) {
    e.preventDefault();
    host.focus();
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

/* 初始焦点：破坏性窗口用 initialFocus 指定取消键，避免误按回车执行；
 * 其余窗口落到首个可聚焦控件，无控件时落到模态宿主承接键盘事件 */
const focusInitial = (): void => {
  const host = hostRef.value;
  if (!host) return;
  if (props.initialFocus) {
    const target = host.querySelector<HTMLElement>(props.initialFocus);
    if (target) {
      target.focus();
      return;
    }
  }
  const list = collectFocusables();
  (list[0] ?? host).focus();
};

watch(
  () => props.show,
  async (show) => {
    if (show) {
      prevFocus =
        document.activeElement instanceof HTMLElement ? document.activeElement : null;
      pushModal(modalId);
      document.addEventListener('keydown', onKeydown, true);
      await nextTick();
      focusInitial();
    } else {
      document.removeEventListener('keydown', onKeydown, true);
      popModal(modalId);
      if (prevFocus && prevFocus.isConnected) prevFocus.focus();
      prevFocus = null;
    }
  },
  { immediate: true },
);

onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKeydown, true);
  popModal(modalId);
});
</script>

<style scoped>
/* display: contents —— 语义包装不参与布局（弹窗仍是遮罩的居中子项） */
.cosmic-overlay-host {
  display: contents;
}
/* 焦点兜底落在宿主：宿主本身不是可交互目标，不绘制焦点框 */
.cosmic-overlay-host:focus,
.cosmic-overlay-host:focus-visible {
  outline: none;
}
</style>

<style scoped>
/* ===== 进场 / 退场动画 =====
 * 透明度只允许落在幕层与底板自身，且两者互不为祖先 ——
 * 底板的背衬折射因此从首帧起就与页面衬底连通。
 * 遮罩根节点只登记过渡时长（Vue 以根元素的时长决定活动类的撤除时刻），
 * 自身永不改变不透明度：根节点一旦 opacity 小于 1 就会成为折射的根边界，
 * 折射在整段淡入期内被截断、结束帧才一次性接上，观感即「扫过后突变」。
 * 承载文字的底板仍只走不透明度：位移会把字形提升为合成层，收尾回落主层时
 * 重新子像素化，观感即「忽然模糊、随即清晰」；光的运动归底板内的 1px 装饰层。 */
.cosmic-enter-active {
  transition: opacity 0.46s var(--ease);
}
.cosmic-enter-active :deep(.cb-veil) {
  transition: opacity 0.36s var(--ease);
}
.cosmic-enter-active :deep(.cosmic-dialog) {
  transition: opacity 0.46s var(--ease);
}
.cosmic-leave-active {
  transition: opacity 0.22s var(--ease);
}
.cosmic-leave-active :deep(.cb-veil) {
  transition: opacity 0.22s var(--ease);
}
.cosmic-leave-active :deep(.cosmic-dialog) {
  transition: opacity 0.18s var(--ease);
}
.cosmic-enter-from :deep(.cb-veil) {
  opacity: 0;
}
.cosmic-enter-from :deep(.cosmic-dialog) {
  opacity: 0;
}
.cosmic-leave-to :deep(.cb-veil) {
  opacity: 0;
}
.cosmic-leave-to :deep(.cosmic-dialog) {
  opacity: 0;
}
@media (prefers-reduced-motion: reduce) {
  .cosmic-enter-active,
  .cosmic-enter-active :deep(.cb-veil),
  .cosmic-enter-active :deep(.cosmic-dialog),
  .cosmic-leave-active,
  .cosmic-leave-active :deep(.cb-veil),
  .cosmic-leave-active :deep(.cosmic-dialog) {
    transition-duration: 0.01s;
  }
}
</style>
