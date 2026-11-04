// @vitest-environment happy-dom
/*
 * DevicePcrPanel.spec.ts — 设备与 PCR 面板契约
 *
 * 覆盖：状态展示、启用参数（位图 + 恢复码）、关闭动作、缺少恢复码时阻断。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";

const pcrStatus = vi.fn();
const pcrEnable = vi.fn();
const pcrDisable = vi.fn();
const pcrReseal = vi.fn();
const recoveryRotate = vi.fn();
const keyfileStatus = vi.fn();

vi.mock("../../lib/verthys", () => ({
  verthysPcrStatus: (...args: unknown[]) => pcrStatus(...args),
  verthysPcrEnable: (...args: unknown[]) => pcrEnable(...args),
  verthysPcrDisable: (...args: unknown[]) => pcrDisable(...args),
  verthysPcrReseal: (...args: unknown[]) => pcrReseal(...args),
  verthysRecoveryRotate: (...args: unknown[]) => recoveryRotate(...args),
  verthysKeyfileStatus: (...args: unknown[]) => keyfileStatus(...args),
}));

import DevicePcrPanel from "./DevicePcrPanel.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
});

function mountPanel(handlers: Record<string, unknown> = {}) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({ render: () => h(DevicePcrPanel, handlers) });
  app.directive("tip", {});
  app.mount(container);
  mounted.push({ app, container });
  return container;
}

/**
 * 按动作文案定位按钮。
 * 端子按钮与锚点「修改全局密钥」同构：标签与描述微文同属一个按钮，
 * 故优先匹配标签文本；纯图标节点改用 aria-label 单独定位。
 */
function buttonByText(container: HTMLElement, text: string): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
    (b) =>
      b.querySelector(".sf-tb-label")?.textContent?.trim() === text ||
      b.textContent?.trim() === text,
  );
}

function setValue(input: HTMLInputElement, value: string) {
  input.value = value;
  input.dispatchEvent(new Event("input"));
}

async function settle() {
  await Promise.resolve();
  await Promise.resolve();
  await nextTick();
}

describe("设备与 PCR 面板", () => {
  beforeEach(() => {
    pcrStatus.mockReset();
    pcrEnable.mockReset();
    pcrDisable.mockReset();
    pcrReseal.mockReset();
    recoveryRotate.mockReset();
    keyfileStatus.mockReset();
    keyfileStatus.mockResolvedValue({ ok: true, op: "v4_keyfile_status", recovery_mode: false });
  });

  it("默认状态展示为未启用", async () => {
    pcrStatus.mockResolvedValue({ ok: true, op: "v4_pcr_status", pcr_enabled: false });
    const container = mountPanel();
    await settle();
    expect(container.textContent).toContain("目标 PCR");
    expect(buttonByText(container, "启用 PCR 绑定")).toBeTruthy();
  });

  it("启用时传递位图与恢复码", async () => {
    pcrStatus.mockResolvedValueOnce({ ok: true, op: "v4_pcr_status", pcr_enabled: false });
    pcrEnable.mockResolvedValue({ ok: true, op: "v4_pcr_enable" });
    pcrStatus.mockResolvedValue({ ok: true, op: "v4_pcr_status", pcr_enabled: true, pcr_select: 0x880 });
    const container = mountPanel();
    await settle();
    const codeInput = container.querySelector<HTMLInputElement>("#pcr-recovery");
    if (!codeInput) throw new Error("missing recovery input");
    setValue(codeInput, "CODE-1234");
    await nextTick();
    buttonByText(container, "启用 PCR 绑定")?.click();
    await settle();
    expect(pcrEnable).toHaveBeenCalledWith(0x880, "CODE-1234");
    expect(buttonByText(container, "关闭 PCR 绑定")).toBeTruthy();
    expect(container.textContent).toContain("已绑定 PCR");
  });

  it("缺少恢复码时不发起启用", async () => {
    pcrStatus.mockResolvedValue({ ok: true, op: "v4_pcr_status", pcr_enabled: false });
    const container = mountPanel();
    await settle();
    buttonByText(container, "启用 PCR 绑定")?.click();
    await settle();
    expect(pcrEnable).not.toHaveBeenCalled();
    expect(container.textContent).toContain("请输入当前恢复码");
  });

  it("轮换恢复码需要二次确认，并在成功后上抛新码", async () => {
    pcrStatus.mockResolvedValue({ ok: true, op: "v4_pcr_status", pcr_enabled: false });
    recoveryRotate.mockResolvedValue({
      ok: true,
      op: "v4_recovery_rotate",
      recovery_code: "NEW-CODE",
    });
    let rotated = "";
    const container = mountPanel({ onRecoveryRotated: (code: string) => (rotated = code) });
    await settle();
    const codeInput = container.querySelector<HTMLInputElement>("#pcr-recovery");
    if (!codeInput) throw new Error("missing recovery input");
    setValue(codeInput, "OLD-CODE");
    await nextTick();

    buttonByText(container, "轮换恢复码")?.click();
    await settle();
    expect(recoveryRotate).not.toHaveBeenCalled();
    expect(container.textContent).toContain("旧恢复码立即失效");

    buttonByText(container, "确认轮换（旧码立即失效）")?.click();
    await settle();
    expect(recoveryRotate).toHaveBeenCalledWith("OLD-CODE");
    expect(rotated).toBe("NEW-CODE");
    expect(container.textContent).not.toContain("NEW-CODE");
  });

  it("恢复会话：空恢复码可启用与重密封，并提示已认证", async () => {
    pcrStatus.mockResolvedValue({ ok: true, op: "v4_pcr_status", pcr_enabled: false });
    pcrEnable.mockResolvedValue({ ok: true, op: "v4_pcr_enable" });
    pcrReseal.mockResolvedValue({ ok: true, op: "v4_pcr_reseal" });
    keyfileStatus.mockResolvedValue({ ok: true, op: "v4_keyfile_status", recovery_mode: true });

    const container = mountPanel();
    await settle();
    expect(container.textContent).toContain("当前为恢复会话");

    // 空码启用：恢复会话已由恢复码认证，不要求再次输入
    buttonByText(container, "启用 PCR 绑定")?.click();
    await settle();
    expect(pcrEnable).toHaveBeenCalledWith(0x880, "");

    // 打开后再关闭需要重密封：空码同样放行
    pcrStatus.mockResolvedValue({
      ok: true,
      op: "v4_pcr_status",
      pcr_enabled: true,
      pcr_select: 0x880,
    });
    container
      .querySelector<HTMLButtonElement>('button[aria-label="刷新设备 PCR 状态"]')
      ?.click();
    await settle();
    buttonByText(container, "重密封")?.click();
    await settle();
    expect(pcrReseal).toHaveBeenCalledWith("");
  });

  it("普通会话：空恢复码不发起重密封并提示输入", async () => {
    pcrStatus.mockResolvedValue({
      ok: true,
      op: "v4_pcr_status",
      pcr_enabled: true,
      pcr_select: 0x880,
    });
    pcrReseal.mockResolvedValue({ ok: true, op: "v4_pcr_reseal" });
    const container = mountPanel();
    await settle();
    buttonByText(container, "重密封")?.click();
    await settle();
    expect(pcrReseal).not.toHaveBeenCalled();
    expect(container.textContent).toContain("请输入当前恢复码");
  });
});
