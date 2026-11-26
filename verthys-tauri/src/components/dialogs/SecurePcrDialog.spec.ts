// @vitest-environment happy-dom
/*
 * SecurePcrDialog.spec.ts — 高安全预设 PCR 提示契约
 *
 * 覆盖：提示不收集恢复码、绑定状态独立于提示正文展示、
 *       确认关闭与「前往」分别向上抛出。
 */
import { afterEach, describe, expect, it } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import SecurePcrDialog from "./SecurePcrDialog.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
});

async function mountDialog(
  props: Record<string, unknown> = {},
  handlers: Record<string, unknown> = {},
) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(SecurePcrDialog, {
        show: true,
        pcrEnabled: false,
        ...props,
        ...handlers,
      }),
  });
  app.mount(container);
  mounted.push({ app, container });
  await nextTick();
  return document.body;
}

function buttonByText(container: HTMLElement, text: string): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
    (button) => button.textContent?.trim() === text,
  );
}

describe("高安全 PCR 提示弹窗", () => {
  it("不提供恢复码输入，绑定状态独立于提示正文", async () => {
    const container = await mountDialog();
    expect(container.querySelector("input")).toBeNull();
    expect(container.textContent).toContain(
      "固件或启动状态变更将导致解锁失效，需恢复码重密封密钥，启用前请确认恢复码已保存",
    );
    const state = container.querySelector(".pcr-state");
    expect(state?.textContent?.trim()).toBe("当前未绑定");
    expect(state?.closest(".pcr-notice")).toBeNull();
  });

  it("状态读取失败时如实显示未确认", async () => {
    const container = await mountDialog({ pcrEnabled: null });
    expect(container.textContent).toContain("当前状态未确认");
  });

  it("确认关闭发出 close", async () => {
    let closed = false;
    const container = await mountDialog({}, { onClose: () => (closed = true) });
    buttonByText(container, "确认")?.click();
    expect(closed).toBe(true);
  });

  it("前往发出 goto", async () => {
    let goto = false;
    const container = await mountDialog({}, { onGoto: () => (goto = true) });
    buttonByText(container, "前往")?.click();
    expect(goto).toBe(true);
  });
});
