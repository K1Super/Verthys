// @vitest-environment happy-dom
/*
 * ModuleRecoveryDialog.spec.ts — 模块恢复槽对话框契约
 *
 * 覆盖：绑定状态展示、输入门禁、绑定成功提示、重密封策略拒绝文案。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";

const bind = vi.fn();
const reseal = vi.fn();

vi.mock("../../key/module-auth", () => ({
  bindModuleRecovery: (...args: unknown[]) => bind(...args),
  resealModuleDevice: (...args: unknown[]) => reseal(...args),
}));

import ModuleRecoveryDialog from "./ModuleRecoveryDialog.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
});

function mountDialog(hasRecovery: boolean) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () => h(ModuleRecoveryDialog, {
      show: true,
      moduleLabel: "拾光",
      moduleId: "photo",
      hasRecovery,
    }),
  });
  app.mount(container);
  mounted.push({ app, container });
  /* CosmicOverlay 以 fixed 遮罩内联渲染；容器位于 body，查询根统一为 body */
  return document.body;
}

function buttonByText(container: HTMLElement, text: string): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
    (b) => b.textContent?.trim() === text,
  );
}

async function settle() {
  await Promise.resolve();
  await Promise.resolve();
  await nextTick();
}

describe("模块恢复槽对话框", () => {
  it("按 C 层状态展示已绑定/未绑定", () => {
    expect(mountDialog(true).textContent).toContain("恢复槽已绑定");
    expect(mountDialog(false).textContent).toContain("恢复槽未绑定");
  });

  it("缺少口令或恢复码时绑定按钮禁用", async () => {
    const container = mountDialog(false);
    const input = (id: string) => container.querySelector<HTMLInputElement>(`#${id}`)!;
    const bindButton = buttonByText(container, "绑定恢复槽")!;
    expect(bindButton.disabled).toBe(true);

    input("mr-password").value = "module-pass";
    input("mr-password").dispatchEvent(new Event("input"));
    await settle();
    expect(bindButton.disabled).toBe(true);

    input("mr-recovery").value = "RECOVERY-CODE";
    input("mr-recovery").dispatchEvent(new Event("input"));
    await settle();
    expect(bindButton.disabled).toBe(false);
  });

  it("绑定成功显示提示并调用后端", async () => {
    bind.mockResolvedValueOnce({ ok: true });
    const container = mountDialog(false);
    const password = container.querySelector<HTMLInputElement>("#mr-password")!;
    const recovery = container.querySelector<HTMLInputElement>("#mr-recovery")!;
    password.value = "module-pass";
    password.dispatchEvent(new Event("input"));
    recovery.value = "RECOVERY-CODE";
    recovery.dispatchEvent(new Event("input"));
    await settle();

    buttonByText(container, "绑定恢复槽")!.click();
    await settle();

    expect(bind).toHaveBeenCalledWith("photo", "module-pass", "RECOVERY-CODE");
    expect(container.textContent).toContain("恢复槽已绑定");
    expect(recovery.value).toBe("");
  });

  it("重密封被策略拒绝时展示结构化文案", async () => {
    reseal.mockResolvedValueOnce({
      ok: false,
      code: "E_MODULE_POLICY",
      message: "重密封模块设备槽失败：当前会话或模块状态不允许该操作",
    });
    const container = mountDialog(false);
    const password = container.querySelector<HTMLInputElement>("#mr-password")!;
    password.value = "module-pass";
    password.dispatchEvent(new Event("input"));
    await settle();

    buttonByText(container, "重密封设备槽")!.click();
    await settle();

    expect(reseal).toHaveBeenCalledWith("photo", "module-pass");
    expect(container.textContent).toContain("当前会话不允许该操作");
  });
});
