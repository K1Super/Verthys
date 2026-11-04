// @vitest-environment happy-dom
/*
 * DevDock.spec.ts — 开发悬浮球入口与面板契约
 *
 * 覆盖：构建标记挂载、点击展开、七项工具渲染、Esc 关闭。
 * 拖拽与吸附几何由 orb_geometry.spec 覆盖，不在 DOM 测试里模拟布局。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import DevDock from "./DevDock.vue";
import { DEVDOCK_MARKER } from "./marker";

vi.mock("./fixture/profile_client", () => ({
  getFixtureStatus: vi.fn(async () => ({
    enabled: true,
    reason: "",
    storeDir: "",
    profileExists: true,
  })),
  getFixtureProfile: vi.fn(async () => ({
    profile: {
      schemaVersion: 1,
      containerPath: "/tmp/fixture.verthys",
      containerKeyfilePath: "",
      globalPassword: "global",
      binPassword: "bin",
      binKeyfilePath: "",
      moduleKeys: {},
      recoveryCode: "",
      updatedAt: "",
    },
    fingerprints: { global: "—", bin: "—", recovery: "—", modules: {} },
  })),
  saveFixtureProfile: vi.fn(),
  clearFixtureProfile: vi.fn(),
}));

vi.mock("./fixture/fill_bus", () => ({
  DEV_FIXTURE_FILL_EVENT: "verthys:devfixture-fill",
  publishFixtureFill: vi.fn(),
}));

import { publishFixtureFill } from "./fixture/fill_bus";

let app: App | null = null;
let host: HTMLDivElement | null = null;

beforeEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });

  host = document.createElement("div");
  document.body.appendChild(host);
  app = createApp({ render: () => h(DevDock) });
  app.mount(host);
});

afterEach(() => {
  app?.unmount();
  host?.remove();
  app = null;
  host = null;
});

describe("开发悬浮球", () => {
  it("挂载构建标记与悬浮球入口", () => {
    expect(document.querySelector(`[data-verthys-devtools="${DEVDOCK_MARKER}"]`)).not.toBeNull();
    expect(document.querySelector(".devdock-orb")).not.toBeNull();
  });

  it("点击球体展开控制台且只渲染当前分区", async () => {
    (document.querySelector(".devdock-orb") as HTMLButtonElement).click();
    await nextTick();

    expect(document.querySelector("#devdock-panel")).not.toBeNull();
    expect(document.querySelectorAll("[data-devtool-group]").length).toBe(1);
    expect(document.querySelectorAll(".devdock-tool-row").length).toBe(2);
  });

  it("切换扇区导轨后可访问全部分区工具", async () => {
    (document.querySelector(".devdock-orb") as HTMLButtonElement).click();
    await nextTick();

    const tabs = Array.from(
      document.querySelectorAll<HTMLButtonElement>(".console-tab"),
    );
    let rendered = 0;
    for (const tab of tabs) {
      if (tab.dataset.tabGroup === "fixture") continue;
      tab.click();
      await nextTick();
      rendered += document.querySelectorAll(".devdock-tool-row").length;
    }

    expect(rendered).toBe(7);
  });

  it("扇区导轨支持方向键切换分区", async () => {
    (document.querySelector(".devdock-orb") as HTMLButtonElement).click();
    await nextTick();

    const firstTab = document.querySelector(
      '[data-tab-group="logs"]',
    ) as HTMLButtonElement;
    firstTab.dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }),
    );
    await nextTick();
    await nextTick();

    expect(
      document.querySelector(".console-tab.is-active")?.getAttribute("aria-label"),
    ).toBe("运行时观测");
  });

  it("悬浮球体展开四枚分组卫星", async () => {
    const orb = document.querySelector(".devdock-orb") as HTMLButtonElement;
    orb.dispatchEvent(new Event("pointerenter"));
    await nextTick();

    expect(document.querySelectorAll(".devdock-sat.is-visible").length).toBe(4);
  });

  it("关闭面板后卫星扇区保持收起，需重新进入才展开", async () => {
    const orb = document.querySelector(".devdock-orb") as HTMLButtonElement;
    orb.dispatchEvent(new Event("pointerenter"));
    await nextTick();
    expect(document.querySelectorAll(".devdock-sat.is-visible").length).toBe(4);

    orb.click();
    await nextTick();
    expect(document.querySelector("#devdock-panel")).not.toBeNull();
    expect(document.querySelectorAll(".devdock-sat.is-visible").length).toBe(0);

    orb.click();
    await nextTick();
    await nextTick();
    expect(document.querySelector("#devdock-panel")).toBeNull();
    expect(document.querySelectorAll(".devdock-sat.is-visible").length).toBe(0);

    orb.dispatchEvent(new Event("pointerenter"));
    await nextTick();
    expect(document.querySelectorAll(".devdock-sat.is-visible").length).toBe(4);
  });

  it("点击分组卫星打开对应分组并激活分组标签", async () => {
    const orb = document.querySelector(".devdock-orb") as HTMLButtonElement;
    orb.dispatchEvent(new Event("pointerenter"));
    await nextTick();

    const satellite = document.querySelector(
      ".devdock-sat.is-visible .sat-node",
    ) as HTMLButtonElement;
    satellite.click();
    await nextTick();

    expect(document.querySelector("#devdock-panel")).not.toBeNull();
    expect(
      document.querySelector(".console-tab.is-active")?.getAttribute("aria-label"),
    ).toBe("日志与诊断");
  });

  it("第四枚卫星直接执行填充且不打开面板", async () => {
    const orb = document.querySelector(".devdock-orb") as HTMLButtonElement;
    orb.dispatchEvent(new Event("pointerenter"));
    await nextTick();

    const nodes = document.querySelectorAll<HTMLButtonElement>(
      ".devdock-sat.is-visible .sat-node",
    );
    expect(nodes.length).toBe(4);
    expect(nodes[3].getAttribute("aria-label")).toBe("填充当前表单");

    nodes[3].click();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await nextTick();

    expect(document.querySelector("#devdock-panel")).toBeNull();
    expect(vi.mocked(publishFixtureFill)).toHaveBeenCalledTimes(4);
  });

  it("点击填充页签渲染填充配置面板", async () => {
    const orb = document.querySelector(".devdock-orb") as HTMLButtonElement;
    orb.click();
    await nextTick();

    const fixtureTab = document.querySelector(
      '[data-tab-group="fixture"]',
    ) as HTMLButtonElement;
    fixtureTab.click();
    await nextTick();

    expect(document.querySelector(".fixture-panel")).not.toBeNull();
  });

  it("Esc 关闭面板并把焦点还给球体", async () => {
    const orb = document.querySelector(".devdock-orb") as HTMLButtonElement;
    orb.click();
    await nextTick();
    await nextTick();

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    await nextTick();

    expect(document.querySelector("#devdock-panel")).toBeNull();
    expect(document.activeElement).toBe(orb);
  });
});
