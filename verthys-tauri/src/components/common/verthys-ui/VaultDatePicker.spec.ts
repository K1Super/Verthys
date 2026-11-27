// @vitest-environment happy-dom
/*
 * VaultDatePicker.spec.ts — 存签自绘日期控件行为契约
 *
 * 覆盖：占位/取值显示、面板按取值月份展开、点击选日上抛、
 * 键盘移动与选中、Esc 只收起面板且不冒泡、可选范围的禁用，
 * 今天与清除两个整体动作。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, ref, type App } from "vue";
import VaultDatePicker from "./VaultDatePicker.vue";
import { todayIso } from "../../../lib/util/calendar";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
  document.body.innerHTML = "";
});

function mountPicker(options: {
  modelValue?: string;
  min?: string;
  max?: string;
  ariaLabel?: string;
} = {}) {
  const model = ref(options.modelValue ?? "");
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(VaultDatePicker, {
        modelValue: model.value,
        "onUpdate:modelValue": (next: string) => {
          model.value = next;
        },
        min: options.min ?? "",
        max: options.max ?? "",
        ariaLabel: options.ariaLabel ?? "出生日期",
      }),
  });
  app.mount(container);
  mounted.push({ app, container });
  return { model };
}

const trigger = (): HTMLButtonElement => document.querySelector<HTMLButtonElement>(".vd-trigger")!;
const panel = (): HTMLElement | null => document.querySelector(".vd-panel");
const day = (date: string): HTMLButtonElement =>
  document.querySelector<HTMLButtonElement>(`.vd-day[data-date="${date}"]`)!;
const actionByText = (text: string): HTMLButtonElement =>
  Array.from(document.querySelectorAll<HTMLButtonElement>(".vd-action")).find(
    (node) => node.textContent?.trim() === text,
  )!;

const key = (k: string): void => {
  trigger().dispatchEvent(new KeyboardEvent("keydown", { key: k, bubbles: true }));
};

describe("存签自绘日期控件", () => {
  it("触发面显示占位或当前值，并声明弹层语义", () => {
    mountPicker();
    expect(trigger().textContent).toContain("未设置");
    expect(trigger().getAttribute("aria-expanded")).toBe("false");
    expect(panel()).toBeNull();
  });

  it("按当前取值月份展开，点击日格上抛并收起", async () => {
    const { model } = mountPicker({ modelValue: "2026-11-15" });
    trigger().click();
    await nextTick();

    expect(panel()).toBeTruthy();
    expect(document.querySelector(".vd-title")?.textContent).toContain("2026 年 11 月");
    expect(day("2026-11-15").classList.contains("is-selected")).toBe(true);

    day("2026-11-20").click();
    await nextTick();
    expect(model.value).toBe("2026-11-20");
    expect(trigger().getAttribute("aria-expanded")).toBe("false");
  });

  it("键盘可移动活动日并选中", async () => {
    const { model } = mountPicker({ modelValue: "2026-11-15" });
    key("Enter");
    await nextTick();
    expect(panel()).toBeTruthy();

    key("ArrowRight");
    await nextTick();
    expect(day("2026-11-16").classList.contains("is-active")).toBe(true);

    key("Enter");
    await nextTick();
    expect(model.value).toBe("2026-11-16");
    expect(trigger().getAttribute("aria-expanded")).toBe("false");
  });

  it("方向键跨月时视图跟随活动日", async () => {
    mountPicker({ modelValue: "2026-11-30" });
    trigger().click();
    await nextTick();

    key("ArrowRight");
    await nextTick();
    expect(document.querySelector(".vd-title")?.textContent).toContain("2026 年 12 月");
    expect(day("2026-12-01").classList.contains("is-active")).toBe(true);
  });

  it("Esc 只收起面板，不把事件放给外层弹窗", async () => {
    mountPicker();
    trigger().click();
    await nextTick();

    const outer = vi.fn();
    document.addEventListener("keydown", outer, true);
    key("Escape");
    await nextTick();
    document.removeEventListener("keydown", outer, true);

    expect(trigger().getAttribute("aria-expanded")).toBe("false");
    expect(outer).not.toHaveBeenCalled();
  });

  it("超出起止范围的日期禁用且不可选", async () => {
    const { model } = mountPicker({
      modelValue: "2026-11-15",
      min: "2026-11-10",
      max: "2026-11-20",
    });
    trigger().click();
    await nextTick();

    expect(day("2026-11-09").disabled).toBe(true);
    expect(day("2026-11-10").disabled).toBe(false);
    expect(day("2026-11-21").disabled).toBe(true);

    day("2026-11-09").click();
    await nextTick();
    expect(model.value).toBe("2026-11-15");
  });

  it("今天与清除两个整体动作可用", async () => {
    const { model } = mountPicker({ modelValue: "2026-11-15" });
    trigger().click();
    await nextTick();

    actionByText("今天").click();
    await nextTick();
    expect(model.value).toBe(todayIso());

    trigger().click();
    await nextTick();
    actionByText("清除").click();
    await nextTick();
    expect(model.value).toBe("");
  });
});
