// @vitest-environment happy-dom
/*
 * UpdaterAvailableDialog.spec.ts — 更新说明与强制更新窗口契约
 *
 * 覆盖：版本与说明展示、普通更新可稍后、强制更新不可关闭、安装动作可触发。
 */
import { afterEach, describe, expect, it } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import UpdaterAvailableDialog from "./UpdaterAvailableDialog.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
});

function mountDialog(
  overrides: Record<string, unknown> = {},
  handlers: Record<string, unknown> = {},
) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const props = {
    modelValue: true,
    currentVersion: "4.1.4",
    version: "4.1.5",
    notes: "修复更新校验问题",
    forceUpdate: false,
    installing: false,
    percent: 0,
    cancellable: false,
    errorMessage: "",
    ...overrides,
    ...handlers,
  };
  const app = createApp({ render: () => h(UpdaterAvailableDialog, props) });
  app.mount(container);
  mounted.push({ app, container });
  return container;
}

function buttonByText(container: HTMLElement, text: string): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
    (button) => button.textContent?.trim() === text,
  );
}

describe("更新说明窗口", () => {
  it("展示版本跨度与发布说明", () => {
    const container = mountDialog();

    expect(container.textContent).toContain("4.1.4 → 4.1.5");
    expect(container.textContent).toContain("修复更新校验问题");
  });

  it("普通更新可以稍后处理", async () => {
    let closed = false;
    const container = mountDialog({}, {
      "onUpdate:modelValue": (value: boolean) => {
        closed = value === false;
      },
    });

    buttonByText(container, "稍后")?.click();
    await nextTick();

    expect(closed).toBe(true);
  });

  it("强制更新不提供稍后且遮罩不可关闭", async () => {
    let closed = false;
    const container = mountDialog(
      { forceUpdate: true },
      {
        "onUpdate:modelValue": (value: boolean) => {
          closed = value === false;
        },
      },
    );

    expect(buttonByText(container, "稍后")).toBeUndefined();
    container.querySelector<HTMLElement>(".dialog-overlay")?.click();
    await nextTick();

    expect(closed).toBe(false);
  });

  it("安装动作由窗口上抛", async () => {
    let installed = false;
    const container = mountDialog({}, {
      onInstall: () => {
        installed = true;
      },
    });

    buttonByText(container, "安装更新")?.click();
    await nextTick();

    expect(installed).toBe(true);
  });
});
