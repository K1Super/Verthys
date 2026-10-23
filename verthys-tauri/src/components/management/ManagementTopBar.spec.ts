// @vitest-environment happy-dom
/*
 * ManagementTopBar.spec.ts — 更新端子机械量表契约
 *
 * 覆盖：
 *   1. 非下载态不渲染量表，避免常驻刻度干扰端子基线
 *   2. 下载态固定 30 刻度、首尾端桩与每五格主刻度，点亮数量按整格推进
 *   3. 100% 补满末格
 *   4. 颜色沿全量程固定映射，首格青色、末格青绿色
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, reactive, type App } from "vue";
import ManagementTopBar from "./ManagementTopBar.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
});

function mountTopBar(updateInstalling: boolean, updatePercent: number) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const state = reactive({
    globalKeyReady: true,
    sessionRemaining: 600_000,
    idleLockEnabled: true,
    updateAvailable: true,
    updateVersion: "4.1.4",
    updateChecking: false,
    updateInstalling,
    updatePercent,
    updateCancellable: false,
    updateFailed: false,
  });
  const app = createApp({ render: () => h(ManagementTopBar, state) });
  app.directive("tip", { mounted() {} });
  app.mount(container);
  mounted.push({ app, container });
  return { container, state };
}

describe("更新端子机械量表", () => {
  it("非下载态不渲染量表", () => {
    const { container } = mountTopBar(false, 42);

    expect(container.querySelector(".sf-update-scale")).toBeNull();
  });

  it("下载态固定 30 刻度并按整格推进", async () => {
    const { container, state } = mountTopBar(true, 0);

    expect(container.querySelectorAll(".sf-update-tick").length).toBe(30);
    expect(container.querySelectorAll(".sf-update-tick.is-major").length).toBe(7);
    expect(container.querySelectorAll(".sf-update-tick.is-lit").length).toBe(0);

    state.updatePercent = 42;
    await nextTick();
    expect(container.querySelectorAll(".sf-update-tick.is-lit").length).toBe(12);

    state.updatePercent = 100;
    await nextTick();
    expect(container.querySelectorAll(".sf-update-tick.is-lit").length).toBe(30);
  });

  it("刻度颜色沿全量程固定映射", () => {
    const { container } = mountTopBar(true, 42);
    const ticks = container.querySelectorAll(".sf-update-tick");

    const first = ticks[0]?.getAttribute("style") ?? "";
    const last = ticks[29]?.getAttribute("style") ?? "";
    expect(first).toContain("--sf-tick-color");
    expect(first).toContain("rgba(0, 212, 255, 0.90)");
    expect(last).toContain("rgba(0, 255, 170, 0.90)");
  });

  it("下载阶段按钮切换为取消并触发取消事件", async () => {
    const container = document.createElement("div");
    document.body.appendChild(container);
    const cancelled = vi.fn();
    const state = reactive({
      globalKeyReady: true,
      sessionRemaining: 600_000,
      idleLockEnabled: true,
      updateAvailable: true,
      updateVersion: "4.1.4",
      updateChecking: false,
      updateInstalling: true,
      updatePercent: 42,
      updateCancellable: true,
      updateFailed: false,
      onCancelUpdate: cancelled,
    });
    const app = createApp({ render: () => h(ManagementTopBar, state) });
    app.directive("tip", { mounted() {} });
    app.mount(container);
    mounted.push({ app, container });

    const button = container.querySelector(".sf-terminal--update") as HTMLButtonElement;
    expect(button.textContent).toContain("取消更新");
    button.click();

    expect(cancelled).toHaveBeenCalledTimes(1);
  });
});
