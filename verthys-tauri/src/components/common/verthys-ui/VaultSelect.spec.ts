// @vitest-environment happy-dom
/*
 * VaultSelect.spec.ts — 存签自绘选择器行为契约
 *
 * 覆盖：占位与当前值显示、候选项弹层、点击选择上抛、键盘打开与选中、
 * Esc 只收起弹层且不冒泡到外层、禁用态不展开。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, ref, type App } from "vue";
import VaultSelect from "./VaultSelect.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
  document.body.innerHTML = "";
});

function mountSelect(options: {
  modelValue?: string;
  disabled?: boolean;
  placeholder?: string;
  allowEmpty?: boolean;
} = {}) {
  const model = ref(options.modelValue ?? "");
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(VaultSelect, {
        modelValue: model.value,
        "onUpdate:modelValue": (next: string) => {
          model.value = next;
        },
        options: ["普通护照", "公务护照", "外交护照"],
        disabled: options.disabled ?? false,
        placeholder: options.placeholder ?? "未指定",
        allowEmpty: options.allowEmpty ?? true,
      }),
  });
  app.mount(container);
  mounted.push({ app, container });
  return { model, container };
}

const trigger = (): HTMLButtonElement =>
  document.querySelector<HTMLButtonElement>(".vs-trigger")!;
const panel = (): HTMLElement | null => document.querySelector(".vs-panel");
const optionLabels = (): string[] =>
  Array.from(document.querySelectorAll(".vs-option-label")).map(
    (node) => node.textContent?.trim() ?? "",
  );
const optionByText = (text: string): HTMLElement | undefined =>
  Array.from(document.querySelectorAll<HTMLElement>(".vs-option")).find(
    (node) => node.textContent?.trim() === text,
  );

describe("存签自绘选择器", () => {
  it("触发面显示占位或当前值，并声明组合框语义", () => {
    mountSelect();
    expect(trigger().textContent).toContain("未指定");
    expect(trigger().getAttribute("role")).toBe("combobox");
    expect(trigger().getAttribute("aria-expanded")).toBe("false");
    expect(panel()).toBeNull();
  });

  it("点击后渲染候选项，选中项上抛并收起弹层", async () => {
    const { model } = mountSelect({ modelValue: "普通护照" });
    trigger().click();
    await nextTick();
    expect(panel()).toBeTruthy();
    expect(optionLabels()).toEqual(["未指定", "普通护照", "公务护照", "外交护照"]);

    optionByText("公务护照")?.click();
    await nextTick();
    expect(model.value).toBe("公务护照");
    /* 关闭走 Transition 退场：断言展开态已收起，而不是等动画计时结束 */
    expect(trigger().getAttribute("aria-expanded")).toBe("false");
    expect(panel()?.classList.contains("vs-leave-active")).toBe(true);
  });

  it("键盘可打开、移动并选中活动项", async () => {
    const { model } = mountSelect();
    trigger().dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }),
    );
    await nextTick();
    expect(panel()).toBeTruthy();

    trigger().dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }),
    );
    trigger().dispatchEvent(
      new KeyboardEvent("keydown", { key: "Enter", bubbles: true }),
    );
    await nextTick();
    expect(model.value).toBe("普通护照");
    expect(trigger().getAttribute("aria-expanded")).toBe("false");
  });

  it("Esc 只收起弹层，不把事件放给外层弹窗", async () => {
    mountSelect();
    trigger().click();
    await nextTick();
    expect(panel()).toBeTruthy();

    const outer = vi.fn();
    document.addEventListener("keydown", outer, true);
    trigger().dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
    );
    await nextTick();
    document.removeEventListener("keydown", outer, true);

    expect(trigger().getAttribute("aria-expanded")).toBe("false");
    expect(outer).not.toHaveBeenCalled();
  });

  it("禁用态不展开", async () => {
    mountSelect({ disabled: true });
    trigger().click();
    await nextTick();
    expect(panel()).toBeNull();
  });

  it("必选项不提供空值项，不能把值清空", async () => {
    mountSelect({ modelValue: "公务护照", allowEmpty: false });
    trigger().click();
    await nextTick();
    expect(optionLabels()).toEqual(["普通护照", "公务护照", "外交护照"]);
  });
});
