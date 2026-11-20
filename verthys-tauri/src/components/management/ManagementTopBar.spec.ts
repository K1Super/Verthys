// @vitest-environment happy-dom
/*
 * ManagementTopBar.spec.ts — 更新节点环形机械量表与悬浮提示契约
 *
 * 覆盖：
 *   1. 非下载态不渲染量表，避免常驻刻度干扰节点基线
 *   2. 下载态固定 30 刻度、首尾端桩与每五格主刻度，点亮数量按整格推进
 *   3. 100% 补满末格
 *   4. 颜色沿全量程固定映射，首格青色、末格青绿色
 *   5. 更新节点悬浮提示只描述动作；版本取自构建注入，呈现为更新节点
 *      左侧的常驻读数（禁止组件写死版本）
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, reactive, type App } from "vue";
import ManagementTopBar from "./ManagementTopBar.vue";

/** 注入一个与真实产品版本不同的测试版本：若组件写死版本号，断言必然失败 */
const INJECTED_VERSION = "7.7.7-test";

beforeEach(() => {
  vi.stubEnv("VITE_APP_VERSION", INJECTED_VERSION);
});

afterEach(() => {
  vi.unstubAllEnvs();
});

/** v-tip 指令替身：把绑定值落到属性上，供断言读取（生产指令操作的是 body 浮层） */
const tipRecorder = {
  mounted(el: HTMLElement, binding: { value: unknown }) {
    el.setAttribute("data-tip-text", String(binding.value ?? ""));
  },
  updated(el: HTMLElement, binding: { value: unknown }) {
    el.setAttribute("data-tip-text", String(binding.value ?? ""));
  },
};

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
});

function mountTopBar(
  updateInstalling: boolean,
  updatePercent: number,
  overrides: { updateAvailable?: boolean; updateVersion?: string } = {},
) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const state = reactive({
    globalKeyReady: true,
    sessionRemaining: 600_000,
    idleLockEnabled: true,
    updateAvailable: overrides.updateAvailable ?? true,
    updateVersion: overrides.updateVersion ?? "4.1.4",
    updateChecking: false,
    updateInstalling,
    updatePercent,
    updateCancellable: false,
  });
  const app = createApp({ render: () => h(ManagementTopBar, state) });
  app.directive("tip", tipRecorder);
  app.mount(container);
  mounted.push({ app, container });
  return { container, state };
}

/** 更新节点的悬浮提示承载槽（v-tip 挂在按钮外层槽位上） */
function updateTipText(container: HTMLDivElement): string {
  return (
    container
      .querySelector(".sf-act--update")
      ?.parentElement?.getAttribute("data-tip-text") ?? ""
  );
}

describe("更新节点环形机械量表", () => {
  it("不渲染日志与诊断导出动作节点", () => {
    const { container } = mountTopBar(false, 42);

    expect(container.querySelector('button[aria-label*="导出"]')).toBeNull();
  });

  it("非下载态不渲染量表", () => {
    const { container } = mountTopBar(false, 42);

    expect(container.querySelector(".sf-update-dial")).toBeNull();
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
      onCancelUpdate: cancelled,
    });
    const app = createApp({ render: () => h(ManagementTopBar, state) });
    app.directive("tip", tipRecorder);
    app.mount(container);
    mounted.push({ app, container });

    // 纯图标契约：取消语义只经提示与无障碍名称暴露，按钮内无可见文字
    const button = container.querySelector(".sf-act--update") as HTMLButtonElement;
    expect(button.textContent?.trim()).toBe("");
    expect(button.getAttribute("aria-label")).toContain("取消下载");
    button.click();

    expect(cancelled).toHaveBeenCalledTimes(1);
  });

  it("动作区纯图标渲染，每个节点均具备无障碍名称", () => {
    const { container } = mountTopBar(false, 0);
    const buttons = Array.from(container.querySelectorAll(".sf-meridian-actions .sf-act"));

    // 无更新失败时动作区为 更新 / 锁定 两枚节点
    expect(buttons.length).toBe(2);
    for (const button of buttons) {
      expect(button.textContent?.trim()).toBe("");
      expect(button.getAttribute("aria-label")).toBeTruthy();
    }
  });
});

describe("更新节点 · 版本读数与悬浮提示", () => {
  it("无可用更新时提示与无障碍名称均为检查更新", () => {
    const { container } = mountTopBar(false, 0, { updateAvailable: false });
    const button = container.querySelector(".sf-act--update") as HTMLButtonElement;

    expect(updateTipText(container)).toBe("检查更新");
    expect(button.getAttribute("aria-label")).toBe("检查更新");
  });

  it("发现更新时以目标版本描述安装动作", () => {
    const { container } = mountTopBar(false, 0, {
      updateAvailable: true,
      updateVersion: "9.9.9",
    });

    expect(updateTipText(container)).toBe("更新到 9.9.9，安装前自动落盘并锁定");
  });

  it("下载中提示只描述进度，不改变取消语义", () => {
    const { container } = mountTopBar(true, 42, { updateAvailable: true });

    expect(updateTipText(container)).toBe("正在更新 42%");
  });

  it("当前版本常驻于更新节点左侧，不进入悬浮提示", () => {
    const { container } = mountTopBar(false, 0, { updateAvailable: false });
    const actions = container.querySelector(".sf-meridian-actions") as HTMLElement;
    const readout = actions.querySelector(".sf-version") as HTMLElement;

    expect(readout.textContent?.trim()).toBe(`V${INJECTED_VERSION}`);
    expect(readout.getAttribute("aria-label")).toBe(`当前版本 ${INJECTED_VERSION}`);
    // 读数必须排在任何动作节点之前，与更新按钮紧邻
    expect(actions.firstElementChild).toBe(readout);
    expect(updateTipText(container)).not.toContain(INJECTED_VERSION);
  });

  it("版本读数不进入更新按钮的无障碍名称", () => {
    const { container } = mountTopBar(false, 0, { updateAvailable: false });
    const button = container.querySelector(".sf-act--update") as HTMLButtonElement;

    expect(button.getAttribute("aria-label")).not.toContain(INJECTED_VERSION);
  });
});
