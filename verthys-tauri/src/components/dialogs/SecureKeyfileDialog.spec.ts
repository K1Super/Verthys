// @vitest-environment happy-dom
/*
 * SecureKeyfileDialog.spec.ts — 高安全预设 keyfile 引导契约
 *
 * 覆盖：确认发出 confirm、稍后关闭发出 close、busy 时按钮禁用。
 */
import { afterEach, describe, expect, it } from "vitest";
import { createApp, h, type App } from "vue";
import SecureKeyfileDialog from "./SecureKeyfileDialog.vue";

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
      h(SecureKeyfileDialog, {
        show: true,
        busy: false,
        ...handlers,
      }),
  });
  app.mount(container);
  mounted.push({ app, container });
  /* VerthysDialog 默认 teleport 到 body，查询根同步为 body */
  return document.body;
}

function buttonByText(container: HTMLElement, text: string): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
    (button) => button.textContent?.trim() === text,
  );
}

describe("高安全 keyfile 引导弹窗", () => {
  it("确认后发出 confirm", () => {
    let confirmed = false;
    const container = mountDialog({ onConfirm: () => (confirmed = true) });
    buttonByText(container, "选择位置并启用")?.click();
    expect(confirmed).toBe(true);
  });

  it("稍后关闭发出 close", () => {
    let closed = false;
    const container = mountDialog({ onClose: () => (closed = true) });
    buttonByText(container, "稍后")?.click();
    expect(closed).toBe(true);
  });

  it("busy 时两个按钮都禁用", () => {
    const container = mountDialog({ busy: true });
    expect(buttonByText(container, "稍后")?.disabled).toBe(true);
    expect(buttonByText(container, "启用中…")?.disabled).toBe(true);
  });
});
