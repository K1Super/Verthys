<!--
  VaultSelect.vue — 存签统一选择控件（自绘弹层）

  形态：触发面沿用 kv-input 凹槽通道，右侧读数箭头在展开时翻转；
        选项弹层使用深色薄雾基面、行内菱形选中标记与行距，与弹窗同一套语言。

  为什么不用原生 select：原生选项弹层由系统绘制，背景、行距、选中态与
  项目主题完全脱节（Windows/WebView2 下尤其明显），无法通过 CSS 收进
  统一设计。自绘弹层才能让下拉与弹窗、卡片读作同一套加工件语言。

  定位：弹层固定定位并挂到 body —— 表单内容区可滚动，绝对定位会被
  overflow 裁切；固定定位也不受父级 transform / 滤镜包含块影响。

  键盘：Enter / Space / ↑ / ↓ 打开，↑ / ↓ 移动，Enter / Space 选中，
  Esc 关闭，Tab 收起。焦点始终留在触发面，选项经 aria-activedescendant 播报。
  Esc 在 window 捕获阶段截断：下拉打开时只收起下拉，不关闭外层表单弹窗。

  用法:
    <VaultSelect v-model="value" :options="['甲', '乙']" placeholder="未指定" />
    <VaultSelect
      :model-value="kind" :options="kinds" aria-label="控件种类"
      @update:model-value="onKindChange"
    />
-->
<template>
  <div
    class="vault-select"
    :class="{ 'is-open': open, 'is-compact': compact }"
  >
    <button
      ref="triggerRef"
      :id="id || undefined"
      type="button"
      class="kv-input vs-trigger"
      role="combobox"
      aria-haspopup="listbox"
      :aria-expanded="open"
      :aria-controls="open ? listboxId : undefined"
      :aria-activedescendant="activeOptionId"
      :aria-label="ariaLabel || undefined"
      :aria-required="required || undefined"
      :disabled="disabled"
      @click="onTriggerClick"
      @keydown="onTriggerKeydown"
    >
      <span class="vs-value" :class="{ 'is-placeholder': isPlaceholder }">
        {{ displayLabel }}
      </span>
      <svg
        class="vs-chevron"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.8"
        aria-hidden="true"
      >
        <polyline points="6 9 12 15 18 9" />
      </svg>
    </button>

    <Teleport to="body">
      <Transition name="vs">
        <div
          v-if="open"
          ref="panelRef"
          :id="listboxId"
          class="vs-panel"
          role="listbox"
          :aria-label="ariaLabel || undefined"
          :style="panelStyle"
        >
          <div
            v-for="(option, index) in allOptions"
            :id="optionId(index)"
            :key="`${index}-${option.value}`"
            class="vs-option"
            :class="{
              'is-active': index === activeIndex,
              'is-selected': option.value === modelValue,
            }"
            role="option"
            :aria-selected="option.value === modelValue"
            @pointermove="hoverActive(index)"
            @click="choose(option)"
          >
            <span class="vs-option-label">{{ option.label }}</span>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, useId, watch } from "vue";

/** 选择项：字符串即值也是文案；需要区分值与文案时传对象 */
interface VaultSelectOption {
  value: string;
  label: string;
}

type VaultSelectOptionInput = string | VaultSelectOption;

const props = withDefaults(
  defineProps<{
    modelValue: string;
    options: readonly VaultSelectOptionInput[];
    /** 空值占位文案；空值是可选中的一项，选它即清空 */
    placeholder?: string;
    /** 是否提供空值项；必选项（如控件种类、主标题）传 false */
    allowEmpty?: boolean;
    disabled?: boolean;
    required?: boolean;
    /** 触发面 id：供外层 label 的 for 关联 */
    id?: string;
    /** 触发面与弹层的无障碍名称（外层没有可关联 label 时必填） */
    ariaLabel?: string;
    /** 紧凑规格：三列并置的窄控件使用 */
    compact?: boolean;
  }>(),
  {
    placeholder: "未指定",
    allowEmpty: true,
    disabled: false,
    required: false,
    id: "",
    ariaLabel: "",
    compact: false,
  },
);

const emit = defineEmits<{
  (e: "update:modelValue", value: string): void;
}>();

/** 实例级 id：选项 id 必须跨实例唯一，供 aria-activedescendant 指向 */
const uid = `vault-select-${useId()}`;
const listboxId = `${uid}-listbox`;
const optionId = (index: number): string => `${uid}-option-${index}`;

const triggerRef = ref<HTMLButtonElement | null>(null);
const panelRef = ref<HTMLElement | null>(null);
const open = ref(false);
const activeIndex = ref(0);
const panelStyle = ref<Record<string, string>>({});

/** 首项为空值占位：与原生下拉的空 option 同位，选中即清空 */
const normalizedOptions = computed<VaultSelectOption[]>(() =>
  props.options.map((option) =>
    typeof option === "string" ? { value: option, label: option } : option,
  ),
);
const allOptions = computed<VaultSelectOption[]>(() => [
  ...(props.allowEmpty ? [{ value: "", label: props.placeholder }] : []),
  ...normalizedOptions.value,
]);

/* 历史取值可能已不在候选项中：原值照常显示，不回退成占位或首项 ——
   否则用户会以为数据被改写。候选项里只有声明过的值可选。 */
const selectedOption = computed(() =>
  allOptions.value.find((option) => option.value === props.modelValue),
);
const displayLabel = computed(
  () => selectedOption.value?.label ?? props.modelValue,
);
const isPlaceholder = computed(() => props.modelValue === "");
const activeOptionId = computed(() =>
  open.value && activeIndex.value >= 0 ? optionId(activeIndex.value) : undefined,
);

/** 弹层几何参数：宽度在触发面与可读上限之间收敛，视线内放不下时向上翻 */
const PANEL_GAP = 6;
const PANEL_MAX_HEIGHT = 244;
const PANEL_MIN_WIDTH = 168;
const PANEL_MAX_WIDTH = 340;

const updatePosition = (): void => {
  const trigger = triggerRef.value;
  if (!trigger) return;
  const rect = trigger.getBoundingClientRect();
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;
  /* 触发面滚出视口后弹层不再有意义：跟随定位只会得到一块悬空面板 */
  if (rect.bottom < 0 || rect.top > viewportHeight) {
    closePanel();
    return;
  }
  const width = Math.min(
    Math.max(Math.round(rect.width), PANEL_MIN_WIDTH),
    PANEL_MAX_WIDTH,
  );
  const left = Math.max(
    8,
    Math.min(Math.round(rect.left), viewportWidth - width - 8),
  );
  const spaceBelow = viewportHeight - rect.bottom - PANEL_GAP - 8;
  const spaceAbove = rect.top - PANEL_GAP - 8;
  const desired = Math.min(PANEL_MAX_HEIGHT, allOptions.value.length * 34 + 12);
  const openUp = spaceBelow < desired && spaceAbove > spaceBelow;
  const maxHeight = Math.max(
    96,
    Math.min(PANEL_MAX_HEIGHT, openUp ? spaceAbove : spaceBelow),
  );
  const style: Record<string, string> = {
    left: `${left}px`,
    width: `${width}px`,
    maxHeight: `${maxHeight}px`,
    /* 选项字号跟随触发面规格：弹层被 teleport 到 body，无法继承根节点字号 */
    "--vs-option-size": props.compact ? "12px" : "13px",
    /* 入场位移方向跟随展开方向：向上翻时自下而上收拢 */
    "--vs-shift": openUp ? "3px" : "-3px",
  };
  if (openUp) style.bottom = `${Math.round(viewportHeight - rect.top + PANEL_GAP)}px`;
  else style.top = `${Math.round(rect.bottom + PANEL_GAP)}px`;
  panelStyle.value = style;
};

/** 当前活动项滚入弹层视口：只动弹层自身 scrollTop，不带动页面 */
const scrollActiveIntoView = (): void => {
  const panel = panelRef.value;
  if (!panel) return;
  const option = document.getElementById(optionId(activeIndex.value));
  if (!option) return;
  if (option.offsetTop < panel.scrollTop) {
    panel.scrollTop = Math.max(0, option.offsetTop - 6);
  } else if (
    option.offsetTop + option.offsetHeight >
    panel.scrollTop + panel.clientHeight
  ) {
    panel.scrollTop =
      option.offsetTop + option.offsetHeight - panel.clientHeight + 6;
  }
};

const setActive = (index: number): void => {
  const count = allOptions.value.length;
  if (count === 0) return;
  activeIndex.value = ((index % count) + count) % count;
  void nextTick(scrollActiveIntoView);
};

/** 指针悬停只更新活动项：选项已在视口内，不需要再滚动 */
const hoverActive = (index: number): void => {
  activeIndex.value = index;
};

const openPanel = async (): Promise<void> => {
  if (props.disabled || open.value) return;
  const selected = allOptions.value.findIndex(
    (option) => option.value === props.modelValue,
  );
  activeIndex.value = selected >= 0 ? selected : 0;
  /* 先算几何再挂载：首帧就有定位，避免弹层在 0,0 闪一帧 */
  updatePosition();
  open.value = true;
  await nextTick();
  updatePosition();
  scrollActiveIntoView();
};

const closePanel = (restoreFocus = false): void => {
  if (!open.value) return;
  open.value = false;
  if (restoreFocus) triggerRef.value?.focus();
};

const onTriggerClick = (): void => {
  if (props.disabled) return;
  if (open.value) closePanel();
  else void openPanel();
};

const choose = (option: VaultSelectOption): void => {
  emit("update:modelValue", option.value);
  closePanel(true);
};

const onTriggerKeydown = (event: KeyboardEvent): void => {
  if (props.disabled) return;
  const key = event.key;
  if (!open.value) {
    if (
      key === "Enter" ||
      key === " " ||
      key === "ArrowDown" ||
      key === "ArrowUp"
    ) {
      event.preventDefault();
      void openPanel();
    }
    return;
  }
  switch (key) {
    case "ArrowDown":
      event.preventDefault();
      setActive(activeIndex.value + 1);
      break;
    case "ArrowUp":
      event.preventDefault();
      setActive(activeIndex.value - 1);
      break;
    case "Home":
      event.preventDefault();
      setActive(0);
      break;
    case "End":
      event.preventDefault();
      setActive(allOptions.value.length - 1);
      break;
    case "Enter":
    case " ": {
      event.preventDefault();
      const option = allOptions.value[activeIndex.value];
      if (option) choose(option);
      break;
    }
    case "Tab":
      closePanel();
      break;
    default:
      break;
  }
};

/* ===== 弹层打开期间的全局监听 =====
 * 关闭即全部释放，不常驻全局事件；window 捕获阶段先于 CosmicOverlay
 * 在 document 上的 Esc 监听，stopPropagation 才能把 Esc 留在下拉内部。 */
const onWindowKeydown = (event: KeyboardEvent): void => {
  if (event.key !== "Escape" || !open.value) return;
  event.preventDefault();
  event.stopPropagation();
  closePanel(true);
};

const onDocumentPointerDown = (event: PointerEvent): void => {
  const target = event.target as Node | null;
  if (!target) return;
  if (triggerRef.value?.contains(target) || panelRef.value?.contains(target)) return;
  closePanel();
};

let scrollRaf = 0;
const onWindowScroll = (event: Event): void => {
  if (
    panelRef.value &&
    event.target instanceof Node &&
    panelRef.value.contains(event.target)
  ) {
    return;
  }
  if (scrollRaf !== 0) return;
  scrollRaf = window.requestAnimationFrame(() => {
    scrollRaf = 0;
    updatePosition();
  });
};

const detachWindowListeners = (): void => {
  window.removeEventListener("scroll", onWindowScroll, true);
  window.removeEventListener("resize", updatePosition);
  window.removeEventListener("keydown", onWindowKeydown, true);
  document.removeEventListener("pointerdown", onDocumentPointerDown, true);
  if (scrollRaf !== 0) {
    window.cancelAnimationFrame(scrollRaf);
    scrollRaf = 0;
  }
};

watch(
  open,
  (value) => {
    if (value) {
      window.addEventListener("scroll", onWindowScroll, true);
      window.addEventListener("resize", updatePosition);
      window.addEventListener("keydown", onWindowKeydown, true);
      document.addEventListener("pointerdown", onDocumentPointerDown, true);
    } else {
      detachWindowListeners();
    }
  },
  { flush: "sync" },
);

/* 父级在展开期间禁用控件（如地区数据重载）：弹层必须同步收起，
   否则会留下一个无法通过触发面关闭的浮层 */
watch(
  () => props.disabled,
  (disabled) => {
    if (disabled) closePanel();
  },
  { flush: "sync" },
);

onBeforeUnmount(() => {
  detachWindowListeners();
});
</script>

<style scoped>
.vault-select {
  position: relative;
  min-width: 0;
}

/* 触发面：沿用弹窗输入凹槽；右侧箭头是唯一与输入框不同的读数标记 */
.vs-trigger {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  width: 100%;
  min-width: 0;
  padding-right: 12px;
  text-align: left;
  cursor: pointer;
  user-select: none;
}
.vs-trigger:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}
.vs-value {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.vs-value.is-placeholder {
  color: rgba(122, 138, 160, 0.55);
}
.vs-chevron {
  flex-shrink: 0;
  width: 12px;
  height: 12px;
  color: var(--text-muted);
  transition:
    transform var(--dur-fast) var(--ease),
    color var(--dur-fast) var(--ease);
}
.vault-select.is-open .vs-chevron {
  transform: rotate(180deg);
  color: var(--accent);
}

/* 紧凑规格：地区三级联动三列并置，列宽有限，字号与内距同步收一档 */
.vault-select.is-compact .vs-trigger {
  padding: 9px;
  font-size: 12px;
}
.vault-select.is-compact .vs-chevron {
  width: 10px;
  height: 10px;
}

/* 选项弹层：深色薄雾基面 + 顶缘光缝；几何由脚本按触发面写入 */
.vs-panel {
  position: fixed;
  z-index: 10020;
  padding: 5px;
  overflow-y: auto;
  overscroll-behavior: contain;
  border: 1px solid rgba(205, 224, 244, 0.10);
  border-radius: 9px;
  background:
    linear-gradient(112deg, rgba(236, 246, 255, 0.045), transparent 42%),
    linear-gradient(168deg, rgba(17, 22, 34, 0.97), rgba(7, 10, 17, 0.98));
  box-shadow:
    0 16px 38px -14px rgba(var(--black-rgb), 0.74),
    0 2px 7px rgba(var(--black-rgb), 0.36),
    inset 0 1px 0 rgba(236, 246, 255, 0.06);
  font-family: var(--font);
}

.vs-option {
  position: relative;
  display: flex;
  align-items: center;
  /* 左内距与触发面文字对齐（弹层自身另有 5px 内距） */
  padding: 7px 10px 7px 8px;
  border-radius: 6px;
  font-size: var(--vs-option-size, 13px);
  line-height: 1.5;
  color: var(--text-secondary);
  cursor: pointer;
  user-select: none;
  transition:
    color var(--dur-fast) var(--ease),
    background-color var(--dur-fast) var(--ease);
}
.vs-option + .vs-option {
  margin-top: 2px;
}
.vs-option.is-active {
  background: rgba(205, 224, 244, 0.06);
  color: var(--text-primary);
}
/* 选中态只留色彩：强调色文字 + 极淡底色，不再出现左侧标记或括号 */
.vs-option.is-selected {
  color: var(--accent);
  background: rgba(var(--accent-rgb), 0.045);
}
.vs-option.is-selected.is-active {
  background: rgba(var(--accent-rgb), 0.08);
}

/* 出入场：自触发面方向轻推 3px，方向由脚本写入 --vs-shift */
.vs-enter-active,
.vs-leave-active {
  transition:
    opacity 0.14s var(--ease),
    transform 0.14s var(--ease);
}
.vs-enter-from,
.vs-leave-to {
  opacity: 0;
  transform: translateY(var(--vs-shift, -3px));
}
@media (prefers-reduced-motion: reduce) {
  .vs-enter-active,
  .vs-leave-active {
    transition-duration: 0.01s;
  }
  .vs-chevron {
    transition: none;
  }
}
</style>
