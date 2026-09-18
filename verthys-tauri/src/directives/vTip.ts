/**
 * vTip.ts — 量子悬浮提示全局指令
 *
 * 用法：v-tip="'提示文字'" 或 v-tip="动态变量"
 * 效果：量子粒子从下方汇聚上升 → 玻璃面板浮现 → 文字从模糊渐晰
 *       非传统气泡，无尖角箭头，底部为发光能量线
 */

const TIP_ATTR = "data-cosmic-tip";
const TIP_ID = "cosmic-tip-instance";

let tipEl: HTMLDivElement | null = null;
let hideTimer: number | null = null;
let showTimer: number | null = null;

/** 创建提示 DOM */
function ensureTipEl(): HTMLDivElement {
  if (tipEl) return tipEl;
  tipEl = document.createElement("div");
  tipEl.id = TIP_ID;
  tipEl.className = "cosmic-tip";
  tipEl.setAttribute(TIP_ATTR, "");
  tipEl.innerHTML =
    '<span class="ct-glow"></span>' +
    '<span class="ct-text"></span>' +
    '<span class="ct-line"></span>';
  tipEl.style.position = "fixed";
  tipEl.style.zIndex = "100000";
  tipEl.style.pointerEvents = "none";
  tipEl.style.opacity = "0";
  document.body.appendChild(tipEl);
  return tipEl;
}

/** 定位提示元素（在目标上方居中） */
function positionTip(el: HTMLDivElement, target: HTMLElement): void {
  const rect = target.getBoundingClientRect();
  const tipRect = el.getBoundingClientRect();

  let left = rect.left + rect.width / 2 - tipRect.width / 2;
  let top = rect.top - tipRect.height - 10;

  // 边界检测
  if (left < 8) left = 8;
  if (left + tipRect.width > window.innerWidth - 8)
    left = window.innerWidth - tipRect.width - 8;
  if (top < 8) top = rect.bottom + 10; // 空间不足时显示在下方

  el.style.left = `${left}px`;
  el.style.top = `${top}px`;
}

/** 显示提示 */
function showTip(target: HTMLElement, text: string): void {
  if (!text) return;
  if (showTimer) {
    clearTimeout(showTimer);
    showTimer = null;
  }
  if (hideTimer) {
    clearTimeout(hideTimer);
    hideTimer = null;
  }

  showTimer = window.setTimeout(() => {
    const el = ensureTipEl();
    const textEl = el.querySelector(".ct-text") as HTMLElement;
    textEl.textContent = text;

    el.style.opacity = "1";
    el.classList.remove("ct-hide");
    el.classList.add("ct-show");

    // 等一帧后定位（确保宽度已计算）
    requestAnimationFrame(() => {
      positionTip(el, target);
    });
  }, 300); // 300ms 延迟，避免快速划过时频繁弹出
}

/** 隐藏提示 */
function hideTip(): void {
  if (showTimer) {
    clearTimeout(showTimer);
    showTimer = null;
  }
  if (hideTimer) return;

  hideTimer = window.setTimeout(() => {
    if (!tipEl) return;
    tipEl.classList.remove("ct-show");
    tipEl.classList.add("ct-hide");
    tipEl.style.opacity = "0";
  }, 100);
}

/** 从元素读取提示文本（优先 v-tip 值，回退到 title 属性） */
function readTipText(el: HTMLElement, bindingValue: unknown): string {
  if (typeof bindingValue === "string") return bindingValue;
  // 动态绑定值为函数时调用
  if (typeof bindingValue === "function") {
    const result = bindingValue();
    return typeof result === "string" ? result : "";
  }
  return "";
}

/** Vue 自定义指令定义 */
export const vTip = {
  mounted(el: HTMLElement & { _tipText?: string }, binding: { value: unknown }) {
    el._tipText = readTipText(el, binding.value);
    el.removeAttribute("title"); // 移除原生 title 避免双重提示

    el.addEventListener("mouseenter", () => {
      // 动态读取：如果元素有 data-tip 属性则优先使用
      const dynamicText = el.getAttribute("data-tip");
      showTip(el, dynamicText || el._tipText || "");
    });
    el.addEventListener("mouseleave", hideTip);
    el.addEventListener("mousedown", hideTip);
    el.addEventListener("click", hideTip);
  },

  updated(el: HTMLElement & { _tipText?: string }, binding: { value: unknown }) {
    el._tipText = readTipText(el, binding.value);
  },

  beforeUnmount() {
    hideTip();
  },
};
