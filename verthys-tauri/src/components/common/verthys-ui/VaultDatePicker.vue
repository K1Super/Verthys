<!--
  VaultDatePicker.vue — 存签统一日期选择控件（自绘日历面板）

  形态：触发面沿用 kv-input 凹槽通道，右侧为日历图标；面板与下拉选择器
        共用同一套深色薄雾基面、行距与选中语法。
  为什么不用原生 date 控件：原生日历弹层由 WebView 绘制，配色、字号与行距
        脱离项目主题，且无法通过 CSS 收进统一设计；自绘面板才能让日历与
        弹窗、下拉读作同一套加工件语言。
  键盘：焦点始终留在触发面（与下拉控件同一交互模型，外层弹窗的焦点陷阱
        不会因焦点进入 Teleport 面板而失序）。方向键移动活动日，
        Home / End 到本周首末，PageUp / PageDown 换月，
        Enter / Space 选中，Esc 收起，Tab 收起并交还表单的既有顺序。
  用法:
    <VaultDatePicker v-model="birthDate" aria-label="出生日期" />
    <VaultDatePicker v-model="end" :min="start" aria-label="到期日" />
-->
<template>
  <div class="vault-date" :class="{ 'is-open': open }">
    <button
      ref="triggerRef"
      :id="id || undefined"
      type="button"
      class="kv-input vd-trigger"
      aria-haspopup="dialog"
      :aria-controls="open ? panelId : undefined"
      :aria-expanded="open"
      :aria-label="ariaLabel || undefined"
      :aria-required="required || undefined"
      @click="onTriggerClick"
      @keydown="onTriggerKeydown"
    >
      <span class="vd-value" :class="{ 'is-placeholder': !modelValue }">{{ displayText }}</span>
      <svg class="vd-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
        <rect x="3.5" y="5" width="17" height="15.5" rx="2" />
        <path d="M3.5 9.5h17" />
        <path d="M8 3.5v3" />
        <path d="M16 3.5v3" />
      </svg>
    </button>

    <!-- 活动日的读屏播报：键盘移动时同步更新，不依赖焦点离开触发面 -->
    <span class="vd-sr" aria-live="polite">{{ open ? activeLabel : "" }}</span>

    <Teleport to="body">
      <Transition name="vd">
        <div
          v-if="open"
          :id="panelId"
          ref="panelRef"
          class="vd-panel"
          :style="panelStyle"
          role="dialog"
          :aria-label="panelLabel"
          @mousedown.prevent
        >
          <div class="vd-head">
            <button class="vd-nav" type="button" tabindex="-1" aria-label="上一年" @click="shiftView(-12)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
                <path d="m11 6-6 6 6 6" />
                <path d="m18 6-6 6 6 6" />
              </svg>
            </button>
            <button class="vd-nav" type="button" tabindex="-1" aria-label="上个月" @click="shiftView(-1)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
                <polyline points="15 6 9 12 15 18" />
              </svg>
            </button>
            <span class="vd-title">{{ viewYear }} 年 {{ viewMonth }} 月</span>
            <button class="vd-nav" type="button" tabindex="-1" aria-label="下个月" @click="shiftView(1)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
                <polyline points="9 6 15 12 9 18" />
              </svg>
            </button>
            <button class="vd-nav" type="button" tabindex="-1" aria-label="下一年" @click="shiftView(12)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
                <path d="m6 6 6 6-6 6" />
                <path d="m13 6 6 6-6 6" />
              </svg>
            </button>
          </div>

          <div class="vd-week" aria-hidden="true">
            <span v-for="label in WEEK_LABELS" :key="label">{{ label }}</span>
          </div>

          <div class="vd-grid" role="group" :aria-label="`${viewYear} 年 ${viewMonth} 月`">
            <button
              v-for="cell in cells"
              :id="cellId(cell.date)"
              :key="cell.date"
              type="button"
              tabindex="-1"
              class="vd-day"
              :class="{
                'is-outside': !cell.inMonth,
                'is-selected': cell.date === modelValue,
                'is-today': cell.date === today,
                'is-active': cell.date === activeDate,
              }"
              :data-date="cell.date"
              :disabled="isDisabled(cell.date)"
              :aria-label="dayLabel(cell.date)"
              :aria-pressed="cell.date === modelValue"
              @click="choose(cell.date)"
              @pointermove="activeDate = cell.date"
            >{{ cell.day }}</button>
          </div>

          <div class="vd-foot">
            <button class="vd-action" type="button" tabindex="-1" :disabled="isDisabled(today)" @click="choose(today)">今天</button>
            <button class="vd-action" type="button" tabindex="-1" :disabled="!modelValue" @click="clear">清除</button>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, useId, watch } from "vue";
import {
  buildMonthGrid,
  daysInMonth,
  parseIsoDate,
  shiftDay,
  shiftMonth,
  todayIso,
  toIsoDate,
} from "../../../lib/util/calendar";

const props = withDefaults(
  defineProps<{
    modelValue: string;
    /** 触发面 id：供外层 label 的 for 关联 */
    id?: string;
    /** 触发面无关联 label 时必填的可访问名称 */
    ariaLabel?: string;
    required?: boolean;
    /** 可选下限（含），纯日期字符串；非法值按未设置处理 */
    min?: string;
    /** 可选上限（含），纯日期字符串；非法值按未设置处理 */
    max?: string;
    /** 空值占位文案 */
    placeholder?: string;
  }>(),
  {
    id: "",
    ariaLabel: "",
    required: false,
    min: "",
    max: "",
    placeholder: "未设置",
  },
);

const emit = defineEmits<{
  (e: "update:modelValue", value: string): void;
}>();

/** 周一起始：周末两天聚合在行尾；读屏播报复用同一组星期名 */
const WEEK_LABELS = ["一", "二", "三", "四", "五", "六", "日"] as const;

/** 实例级 id：面板与活动格需要跨实例唯一的锚点 */
const uid = `vault-date-${useId()}`;
const panelId = `${uid}-panel`;
const cellId = (date: string): string => `${uid}-d-${date}`;

const triggerRef = ref<HTMLButtonElement | null>(null);
const panelRef = ref<HTMLElement | null>(null);
const open = ref(false);
const viewYear = ref(2000);
const viewMonth = ref(1);
/** 键盘活动日（`YYYY-MM-DD`）：焦点留在触发面，活动日以高亮与播报呈现 */
const activeDate = ref("");
const panelStyle = ref<Record<string, string>>({});

/** 今日按打开时刻计算：面板存续期间的跨午夜不改变「今天」的判定基准 */
const today = todayIso();

const minIso = computed(() => (parseIsoDate(props.min) ? props.min : ""));
const maxIso = computed(() => (parseIsoDate(props.max) ? props.max : ""));

const displayText = computed(() => props.modelValue || props.placeholder);
const panelLabel = computed(() => (props.ariaLabel ? `选择${props.ariaLabel}` : "选择日期"));

const cells = computed(() => buildMonthGrid(viewYear.value, viewMonth.value));
const weekRows = computed(() => cells.value.length / 7);

/** 读屏与悬浮提示共用的日期全称 */
const dayLabel = (date: string): string => {
  const parsed = parseIsoDate(date);
  if (!parsed) return date;
  const weekday = WEEK_LABELS[(new Date(parsed.year, parsed.month - 1, parsed.day).getDay() + 6) % 7];
  return `${parsed.year} 年 ${parsed.month} 月 ${parsed.day} 日 星期${weekday}`;
};

const activeLabel = computed(() => (activeDate.value ? dayLabel(activeDate.value) : ""));

/** 超出可选范围的日期不可选（纯日期字符串可直接按字典序比较） */
const isDisabled = (date: string): boolean =>
  (minIso.value !== "" && date < minIso.value) ||
  (maxIso.value !== "" && date > maxIso.value);

/** 打开时的活动日：已有取值优先，否则取夹到可选范围内的今天 */
const fallbackDate = (): string => {
  if (minIso.value !== "" && today < minIso.value) return minIso.value;
  if (maxIso.value !== "" && today > maxIso.value) return maxIso.value;
  return today;
};

const syncViewToActive = (): void => {
  const parsed = parseIsoDate(activeDate.value);
  if (!parsed) return;
  if (parsed.year !== viewYear.value || parsed.month !== viewMonth.value) {
    viewYear.value = parsed.year;
    viewMonth.value = parsed.month;
  }
};

/* ===== 定位：固定定位并挂到 body，弹窗内容区滚动不会裁切面板 ===== */
const PANEL_WIDTH = 272;
const PANEL_GAP = 6;

const updatePosition = (): void => {
  const trigger = triggerRef.value;
  if (!trigger) return;
  const rect = trigger.getBoundingClientRect();
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;
  if (rect.bottom < 0 || rect.top > viewportHeight) {
    closePanel();
    return;
  }
  const left = Math.max(8, Math.min(Math.round(rect.left), viewportWidth - PANEL_WIDTH - 8));
  const desired = 100 + weekRows.value * 30;
  const spaceBelow = viewportHeight - rect.bottom - PANEL_GAP - 8;
  const spaceAbove = rect.top - PANEL_GAP - 8;
  const openUp = spaceBelow < desired && spaceAbove > spaceBelow;
  const available = openUp ? spaceAbove : spaceBelow;
  const style: Record<string, string> = {
    left: `${left}px`,
    width: `${PANEL_WIDTH}px`,
    maxHeight: `${Math.max(168, Math.min(desired, available))}px`,
    "--vd-shift": openUp ? "3px" : "-3px",
  };
  if (openUp) style.bottom = `${Math.round(viewportHeight - rect.top + PANEL_GAP)}px`;
  else style.top = `${Math.round(rect.bottom + PANEL_GAP)}px`;
  panelStyle.value = style;
};

const openPanel = async (): Promise<void> => {
  if (open.value) return;
  const initial = parseIsoDate(props.modelValue) ? props.modelValue : fallbackDate();
  activeDate.value = initial;
  const parsed = parseIsoDate(initial);
  if (parsed) {
    viewYear.value = parsed.year;
    viewMonth.value = parsed.month;
  }
  updatePosition();
  open.value = true;
  await nextTick();
  updatePosition();
};

const closePanel = (restoreFocus = false): void => {
  if (!open.value) return;
  open.value = false;
  if (restoreFocus) triggerRef.value?.focus();
};

/** 选中并收起：与下拉选择器一致，选完即可继续用键盘走到下一个字段 */
const choose = (date: string): void => {
  if (!date || isDisabled(date)) return;
  emit("update:modelValue", date);
  closePanel(true);
};

const clear = (): void => {
  emit("update:modelValue", "");
  closePanel(true);
};

/* ===== 键盘：活动日随方向键移动，视图跟随跨月活动日 ===== */
const moveActive = (deltaDays: number): void => {
  const next = shiftDay(activeDate.value, deltaDays);
  if (!next) return;
  activeDate.value = next;
  syncViewToActive();
};

/** Home / End：移到本周的周一或周日 */
const moveToWeekEdge = (edge: 0 | 6): void => {
  const parsed = parseIsoDate(activeDate.value);
  if (!parsed) return;
  const weekday = (new Date(parsed.year, parsed.month - 1, parsed.day).getDay() + 6) % 7;
  moveActive(edge - weekday);
};

/** PageUp / PageDown：换月并保留日号（目标月没有该日时收敛到月末） */
const shiftActiveMonth = (delta: number): void => {
  const parsed = parseIsoDate(activeDate.value);
  if (!parsed) return;
  const target = shiftMonth(parsed.year, parsed.month, delta);
  const day = Math.min(parsed.day, daysInMonth(target.year, target.month));
  activeDate.value = toIsoDate(target.year, target.month, day);
  viewYear.value = target.year;
  viewMonth.value = target.month;
};

/** 头部换月：活动日跟随到同月同日，避免高亮留在已隐藏的月份 */
const shiftView = (delta: number): void => {
  const parsed = parseIsoDate(activeDate.value);
  const currentDay = parsed?.day ?? 1;
  const target = shiftMonth(viewYear.value, viewMonth.value, delta);
  viewYear.value = target.year;
  viewMonth.value = target.month;
  activeDate.value = toIsoDate(target.year, target.month, Math.min(currentDay, daysInMonth(target.year, target.month)));
};

const onTriggerClick = (): void => {
  if (open.value) closePanel();
  else void openPanel();
};

const onTriggerKeydown = (event: KeyboardEvent): void => {
  if (!open.value) {
    if (event.key === "Enter" || event.key === " " || event.key === "ArrowDown") {
      event.preventDefault();
      void openPanel();
    }
    return;
  }

  switch (event.key) {
    case "Escape":
      event.preventDefault();
      event.stopPropagation();
      closePanel(true);
      break;
    case "Tab":
      // 焦点本就在触发面：收起后让浏览器的默认 Tab 继续走表单顺序
      closePanel();
      break;
    case "ArrowLeft":
      event.preventDefault();
      moveActive(-1);
      break;
    case "ArrowRight":
      event.preventDefault();
      moveActive(1);
      break;
    case "ArrowUp":
      event.preventDefault();
      moveActive(-7);
      break;
    case "ArrowDown":
      event.preventDefault();
      moveActive(7);
      break;
    case "Home":
      event.preventDefault();
      moveToWeekEdge(0);
      break;
    case "End":
      event.preventDefault();
      moveToWeekEdge(6);
      break;
    case "PageUp":
      event.preventDefault();
      shiftActiveMonth(-1);
      break;
    case "PageDown":
      event.preventDefault();
      shiftActiveMonth(1);
      break;
    case "Enter":
    case " ":
      event.preventDefault();
      choose(activeDate.value);
      break;
    default:
      break;
  }
};

/* ===== 打开期间的全局监听：关闭即全部释放，不常驻全局事件 ===== */
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
  if (panelRef.value && event.target instanceof Node && panelRef.value.contains(event.target)) return;
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

onBeforeUnmount(() => {
  detachWindowListeners();
});
</script>

<style scoped>
.vault-date {
  position: relative;
  min-width: 0;
  width: 100%;
}

/* 触发面：沿用弹窗输入凹槽；右侧日历图标是唯一与输入框不同的读数标记 */
.vd-trigger {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
  min-width: 0;
  padding-right: 10px;
  text-align: left;
  cursor: pointer;
  user-select: none;
}
.vd-value {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0.3px;
}
.vd-value.is-placeholder {
  color: rgba(122, 138, 160, 0.55);
  letter-spacing: normal;
}
.vd-icon {
  flex-shrink: 0;
  width: 13px;
  height: 13px;
  color: var(--text-muted);
  transition: color var(--dur-fast) var(--ease);
}
.vault-date.is-open .vd-icon {
  color: var(--accent);
}

/* 读屏播报层：不参与布局，也不出现在视觉层 */
.vd-sr {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: -1px;
  padding: 0;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
  border: 0;
}

/* 面板：与下拉选择器同一材质与边界；几何由脚本按触发面写入 */
.vd-panel {
  position: fixed;
  z-index: 10020;
  padding: 9px 10px 8px;
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

/* 头部：年 / 月读数居中，两侧各有一对「年 / 月」步进端子 */
.vd-head {
  display: flex;
  align-items: center;
  gap: 2px;
  padding: 1px 2px 8px;
}
.vd-title {
  flex: 1;
  text-align: center;
  font-size: 12px;
  letter-spacing: 0.8px;
  color: var(--text-primary);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.vd-nav {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 21px;
  height: 21px;
  padding: 0;
  border: 0;
  border-radius: 5px;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), background-color var(--dur-fast) var(--ease);
}
.vd-nav svg {
  width: 11px;
  height: 11px;
}
.vd-nav:hover {
  color: var(--accent);
  background: rgba(var(--accent-rgb), 0.06);
}
.vd-nav:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: -1px;
}

/* 星期行：与日格同列宽，读数用字距而非字重区分 */
.vd-week {
  display: grid;
  grid-template-columns: repeat(7, 1fr);
  gap: 2px;
  padding: 0 0 5px;
  border-bottom: 1px solid rgba(205, 224, 244, 0.06);
}
.vd-week span {
  text-align: center;
  font-size: 10px;
  letter-spacing: 1px;
  color: var(--text-muted);
}

.vd-grid {
  display: grid;
  grid-template-columns: repeat(7, 1fr);
  gap: 2px;
  padding-top: 6px;
}

/* 日格：选中 = 强调色文字 + 一线描边；今天 = 数字下方的定位点。
   不铺实底色、不做胶囊，保持与下拉选中态同一克制语法 */
.vd-day {
  position: relative;
  height: 28px;
  padding: 0;
  border: 1px solid transparent;
  border-radius: 6px;
  background: transparent;
  color: var(--text-secondary);
  font-size: 12px;
  font-family: var(--font);
  font-variant-numeric: tabular-nums;
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), background-color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}
.vd-day:hover:not(:disabled) {
  color: var(--text-primary);
  background: rgba(205, 224, 244, 0.06);
}
.vd-day.is-active:not(:disabled) {
  background: rgba(205, 224, 244, 0.06);
}
.vd-day.is-outside {
  color: rgba(132, 148, 168, 0.34);
}
.vd-day.is-today::after {
  content: "";
  position: absolute;
  left: 50%;
  bottom: 3px;
  width: 3px;
  height: 3px;
  border-radius: 50%;
  background: var(--accent);
  transform: translateX(-50%);
}
.vd-day.is-selected {
  color: var(--accent);
  border-color: rgba(var(--accent-rgb), 0.42);
  background: rgba(var(--accent-rgb), 0.05);
}
.vd-day:disabled {
  color: rgba(132, 148, 168, 0.2);
  background: transparent;
  cursor: not-allowed;
}
.vd-day:disabled.is-today::after {
  background: rgba(132, 148, 168, 0.24);
}
.vd-day:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: -1px;
}

/* 底部：今天与清除是仅有的两个整体动作，与日格以细线断开 */
.vd-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 6px;
  padding: 6px 2px 0;
  border-top: 1px solid rgba(205, 224, 244, 0.07);
}
.vd-action {
  padding: 2px 0;
  border: 0;
  background: none;
  color: var(--text-secondary);
  font-size: 11px;
  font-family: var(--font);
  letter-spacing: 0.5px;
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease);
}
.vd-action:hover:not(:disabled) {
  color: var(--accent);
}
.vd-action:disabled {
  color: var(--text-muted);
  cursor: not-allowed;
}
.vd-action:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: 1px;
}

/* 出入场：自触发面方向轻推 3px，方向由脚本写入 --vd-shift */
.vd-enter-active,
.vd-leave-active {
  transition: opacity 0.14s var(--ease), transform 0.14s var(--ease);
}
.vd-enter-from,
.vd-leave-to {
  opacity: 0;
  transform: translateY(var(--vd-shift, -3px));
}
@media (prefers-reduced-motion: reduce) {
  .vd-enter-active,
  .vd-leave-active {
    transition-duration: 0.01s;
  }
}
</style>
