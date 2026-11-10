// @vitest-environment happy-dom
/*
 * useModuleNavigation.spec.ts — 导航守卫与分包就绪
 *
 * 覆盖：
 *   1. 开发填充按模块弹窗分发：模块密钥在弹窗打开前缓存，打开或切换时
 *      按 pendingModuleId 填入；未派发填充事件时不写入。
 *   2. 分包就绪先于导航提交：冷包未完成前不切换；后发请求不被先发慢包覆盖。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, defineComponent, h, nextTick, type App } from "vue";

const loaderMock = vi.hoisted(() => ({
  ensureModuleLoaded: vi.fn(async (_id: string) => {}),
}));

vi.mock("../app/module-loaders", () => ({
  ensureModuleLoaded: loaderMock.ensureModuleLoaded,
  isModuleNavId: (id: string) =>
    ["accounts", "photos", "verthys", "tools", "security"].includes(id),
}));

vi.mock("../lib/keyManager", async () => {
  const { ref } = await import("vue");
  return {
    hasModuleKeyRecordRef: ref({ photo: true, accounts: true, fileverthys: true }),
    verifyModuleKey: vi.fn(async () => ({ ok: true })),
    isModuleReady: vi.fn(() => false),
    isModuleKeyEnabled: vi.fn(() => true),
    verthysReadyRef: ref(true),
    moduleKeyStatusLoadingRef: ref(false),
    moduleKeyStatusLoadedRef: ref(true),
    moduleKeyStatusFailedRef: ref(false),
    moduleKeyEnabledRef: ref({ photo: true, accounts: true, fileverthys: true }),
    MODULE_LABELS: { photo: "拾光", accounts: "存签", fileverthys: "清藏" },
    touchSession: vi.fn(),
  };
});

vi.mock("../cache/composition/verthys-cache", () => ({
  scheduleBackgroundFlush: vi.fn(),
  ensureRecordScan: vi.fn(async () => {}),
  clearModuleCache: vi.fn(),
  clearRecordScanCache: vi.fn(),
  markModuleReady: vi.fn(),
  removeModuleKey: vi.fn(),
}));

vi.mock("../session/security-session", () => ({
  touchSession: vi.fn(),
}));

vi.mock("./updater-critical", () => ({
  isUpdaterCritical: () => false,
}));

vi.mock("./useToastCenter", () => ({
  useToastCenter: () => ({ showError: vi.fn(), showStatus: vi.fn() }),
}));

vi.mock("../utils/gc", () => ({ scheduleGc: vi.fn() }));
vi.mock("../utils/promise_utils", () => ({
  withTimeout: (promise: Promise<unknown>) => promise,
}));

import { useModuleNavigation } from "./useModuleNavigation";

type NavigationApi = ReturnType<typeof useModuleNavigation>;

let app: App | null = null;
let host: HTMLDivElement | null = null;
let api: NavigationApi;

beforeEach(() => {
  loaderMock.ensureModuleLoaded.mockReset();
  loaderMock.ensureModuleLoaded.mockImplementation(async () => {});
  host = document.createElement("div");
  document.body.appendChild(host);
  const Comp = defineComponent({
    setup() {
      api = useModuleNavigation();
      return () => h("div");
    },
  });
  app = createApp(Comp);
  app.mount(host);
});

afterEach(() => {
  app?.unmount();
  host?.remove();
  app = null;
  host = null;
});

function dispatchModuleKeys(moduleKeys: Record<string, string>): void {
  window.dispatchEvent(
    new CustomEvent("verthys:devfixture-fill", {
      detail: { target: "module", moduleKeys },
    }),
  );
}

describe("useModuleNavigation 开发填充", () => {
  it("弹窗打开前缓存模块密钥，打开或切换时按模块填入", async () => {
    dispatchModuleKeys({
      photo: "PHOTO-KEY",
      accounts: "ACCOUNTS-KEY",
      fileverthys: "FILE-KEY",
    });

    await api.switchModule("accounts");
    await nextTick();
    expect(api.moduleKeyInput.value).toBe("ACCOUNTS-KEY");

    api.cancelModuleKeyVerify();
    await api.switchModule("verthys");
    await nextTick();
    expect(api.moduleKeyInput.value).toBe("FILE-KEY");
  });

  it("未派发填充事件时不写入模块密钥", async () => {
    await api.switchModule("accounts");
    await nextTick();
    expect(api.moduleKeyInput.value).toBe("");
  });
});

describe("useModuleNavigation 分包就绪", () => {
  it("分包未就绪前不提交导航，就绪后提交", async () => {
    let release!: () => void;
    loaderMock.ensureModuleLoaded.mockImplementationOnce(
      () => new Promise<void>((resolve) => { release = resolve; }),
    );

    const switching = api.switchModule("security");
    await Promise.resolve();
    expect(api.currentModule.value).toBe("");

    release();
    await switching;
    expect(api.currentModule.value).toBe("security");
  });

  it("后发切换优先，先发慢包完成后不得覆盖", async () => {
    let releaseSlow!: () => void;
    loaderMock.ensureModuleLoaded.mockImplementationOnce(
      () => new Promise<void>((resolve) => { releaseSlow = resolve; }),
    );

    const slowSwitch = api.switchModule("tools");
    await api.switchModule("security");
    expect(api.currentModule.value).toBe("security");

    releaseSlow();
    await slowSwitch;
    expect(api.currentModule.value).toBe("security");
  });
});
