// @vitest-environment happy-dom
/*
 * ConfirmDelete.spec.ts — 通用删除确认窗行为契约
 *
 * 覆盖：统一外壳渲染、不可逆窗口语义、初始焦点落在取消键、Esc 取消、确认上抛。
 */
import { afterEach, describe, expect, it } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import ConfirmDelete from "./ConfirmDelete.vue";

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
      h(ConfirmDelete, {
        show: true,
        title: "确认删除",
        desc: "不可恢复",
        ...handlers,
      }),
  });
  app.mount(container);
  mounted.push({ app, container });
  return document.body;
}

function buttonByText(root: HTMLElement, text: string): HTMLButtonElement | undefined {
  return Array.from(root.querySelectorAll<HTMLButtonElement>("button")).find(
    (button) => button.textContent?.trim() === text,
  );
}

describe("通用删除确认窗", () => {
  it("渲染统一宇宙外壳并声明不可逆窗口语义", async () => {
    const root = mountDialog();
    await nextTick();
    expect(root.querySelector(".cosmic-dialog")).toBeTruthy();
    expect(root.querySelector('[role="alertdialog"]')).toBeTruthy();
  });

  it("初始焦点落在取消键：误按回车不得执行删除", async () => {
    const root = mountDialog();
    await nextTick();
    await nextTick();
    expect(document.activeElement).toBe(buttonByText(root, "取消"));
  });

  it("Esc 与取消键都只发出 cancel", async () => {
    const events: string[] = [];
    mountDialog({
      onCancel: () => events.push("cancel"),
      onConfirm: () => events.push("confirm"),
    });
    await nextTick();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(events).toEqual(["cancel"]);
  });

  it("确认键发出 confirm", () => {
    const events: string[] = [];
    const root = mountDialog({
      onCancel: () => events.push("cancel"),
      onConfirm: () => events.push("confirm"),
    });
    buttonByText(root, "确认删除")?.click();
    expect(events).toEqual(["confirm"]);
  });
});
