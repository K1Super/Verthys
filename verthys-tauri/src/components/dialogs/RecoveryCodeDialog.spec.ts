// @vitest-environment happy-dom
/*
 * RecoveryCodeDialog.spec.ts — 一次性恢复码展示与确认契约
 *
 * 覆盖：高优先 teleport/层级、连续恢复码展示与点击复制、确认项解锁完成、未确认关闭二次警告。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import { toastState } from "../../composables/useToastCenter";
import RecoveryCodeDialog from "./RecoveryCodeDialog.vue";

const CODE = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-IIII-JJJJ-KKKK-LLLL-MMMM-NNNN";
const PLAIN_CODE = CODE.replace(/-/g, "");

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
});

function mountDialog(handlers: Record<string, unknown> = {}) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(RecoveryCodeDialog, {
        show: true,
        code: CODE,
        ...handlers,
      }),
  });
  app.mount(container);
  mounted.push({ app, container });
  /* 高优先恢复码窗口 teleport 到 body；查询根固定为 document.body */
  return document.body;
}

function buttons(container: HTMLElement): HTMLButtonElement[] {
  return Array.from(container.querySelectorAll<HTMLButtonElement>("button"));
}

function buttonByText(container: HTMLElement, text: string): HTMLButtonElement | undefined {
  return buttons(container).find((b) => b.textContent?.trim() === text);
}

describe("一次性恢复码弹窗", () => {
  it("高优先窗口 teleport 到 body 并使用 10000 层级", () => {
    const root = mountDialog();
    const backdrop = root.querySelector<HTMLElement>(".cosmic-backdrop");
    expect(backdrop).toBeTruthy();
    expect(backdrop?.parentElement).toBe(document.body);
    expect(backdrop?.style.zIndex).toBe("10000");
  });

  it("展示统一光学弹窗与完整连续恢复码", () => {
    const root = mountDialog();
    expect(root.querySelector(".cosmic-dialog")).toBeTruthy();
    const input = root.querySelector<HTMLInputElement>(".rc-code-input");
    expect(input).toBeTruthy();
    expect(input?.value).toBe(PLAIN_CODE);
    expect(buttonByText(root, "完成")?.disabled).toBe(true);
  });

  it("点击恢复码复制连续码到剪贴板并经全局 Toast 提示", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const container = mountDialog();
    const input = container.querySelector<HTMLInputElement>(".rc-code-input");
    if (!input) throw new Error("code input missing");
    input.click();
    await Promise.resolve();
    await Promise.resolve();
    await nextTick();

    expect(writeText).toHaveBeenCalledWith(PLAIN_CODE);
    expect(toastState.status.value).toBe("恢复码已复制");
  });

  it("勾选确认项后完成按钮解锁并发出 confirmed", async () => {
    let fired = false;
    const container = mountDialog({ onConfirmed: () => (fired = true) });
    const check = container.querySelector<HTMLInputElement>(".rc-check input");
    if (!check) throw new Error("checkbox missing");
    check.checked = true;
    check.dispatchEvent(new Event("change"));
    await nextTick();

    const save = buttonByText(container, "完成");
    expect(save?.disabled).toBe(false);
    save?.click();
    await nextTick();
    expect(fired).toBe(true);
  });

  it("勾选确认后取消仍走二次放弃，不得被当作确认", async () => {
    let fired = false;
    let closed = false;
    const container = mountDialog({
      onConfirmed: () => (fired = true),
      onClose: () => (closed = true),
    });
    const check = container.querySelector<HTMLInputElement>(".rc-check input");
    if (!check) throw new Error("checkbox missing");
    check.checked = true;
    check.dispatchEvent(new Event("change"));
    await nextTick();

    buttonByText(container, "取消")?.click();
    await nextTick();
    expect(fired).toBe(false);
    expect(closed).toBe(false);
    expect(container.textContent).toContain("永久丢失恢复码");
    buttonByText(container, "放弃并关闭")?.click();
    await nextTick();
    expect(fired).toBe(false);
    expect(closed).toBe(true);
  });

  it("未确认关闭需要二次警告", async () => {
    let closed = false;
    const container = mountDialog({ onClose: () => (closed = true) });
    buttonByText(container, "取消")?.click();
    await nextTick();
    expect(closed).toBe(false);
    expect(container.textContent).toContain("永久丢失恢复码");
    buttonByText(container, "放弃并关闭")?.click();
    await nextTick();
    expect(closed).toBe(true);
  });
});
