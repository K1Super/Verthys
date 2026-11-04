// @vitest-environment happy-dom
/*
 * useModuleNavigation.spec.ts — 开发填充按模块弹窗分发
 *
 * 覆盖：模块密钥在弹窗打开前缓存，弹窗打开或切换时按 pendingModuleId 填入，
 * 不再出现“只填第一个模块”的行为；未派发填充事件时不写入。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, defineComponent, h, nextTick, type App } from "vue";

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
