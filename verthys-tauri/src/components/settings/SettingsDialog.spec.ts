// @vitest-environment happy-dom
/*
 * SettingsDialog.spec.ts — 全局显示设置面板行为契约
 *
 * 覆盖：
 *   1. 标准下拉承载帧率；页脚右下为恢复默认与保存，无多余关闭控件
 *   2. 编辑只写入草稿，保存后才落到运行时与持久化
 *   3. 等待秒数提交、非法输入回退、恢复默认、遮罩关闭丢弃草稿
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import SettingsDialog from "./SettingsDialog.vue";
import { displaySettings, resetDisplaySettings } from "../../settings/display-settings";
import { disposeGlobalIdleScheduler } from "../../composables/app/useGlobalIdleScheduler";

let app: App | null = null;
let host: HTMLElement | null = null;
let closed = 0;

function mount(): void {
  host = document.createElement("div");
  document.body.appendChild(host);
  app = createApp({
    render: () => h(SettingsDialog, { show: true, onClose: () => (closed += 1) }),
  });
  app.mount(host);
}

function triggers(): HTMLButtonElement[] {
  return Array.from(document.querySelectorAll<HTMLButtonElement>(".vs-trigger"));
}

function footerButtons(): HTMLButtonElement[] {
  return Array.from(document.querySelectorAll<HTMLButtonElement>(".settings-actions button"));
}

function buttonByLabel(label: string): HTMLButtonElement {
  const button = Array.from(document.querySelectorAll<HTMLButtonElement>("button")).find((item) =>
    (item.textContent ?? "").trim().includes(label),
  );
  expect(button).toBeTruthy();
  return button!;
}

async function chooseFromSelect(index: number, optionLabel: string): Promise<void> {
  triggers()[index].click();
  await nextTick();
  const option = Array.from(document.querySelectorAll<HTMLElement>(".vs-option")).find(
    (item) => (item.textContent ?? "").trim() === optionLabel,
  );
  expect(option).toBeTruthy();
  option!.click();
  await nextTick();
}

function waitInput(): HTMLInputElement {
  const input = document.querySelector<HTMLInputElement>(".settings-input");
  expect(input).toBeTruthy();
  return input!;
}

beforeEach(async () => {
  closed = 0;
  resetDisplaySettings();
  window.localStorage.clear();
  mount();
  await nextTick();
});

afterEach(() => {
  app?.unmount();
  app = null;
  host?.remove();
  host = null;
  disposeGlobalIdleScheduler();
  document.body.innerHTML = "";
  resetDisplaySettings();
  window.localStorage.clear();
});

describe("SettingsDialog", () => {
  it("页脚右下为恢复默认与保存，保存按钮在未修改时禁用", () => {
    expect(triggers().length).toBe(4);
    expect(document.querySelectorAll(".settings-input").length).toBe(3);
    expect(document.querySelectorAll(".settings-unit--fps").length).toBe(4);
    expect(document.querySelector(".settings-close")).toBeNull();
    const buttons = footerButtons();
    expect(buttons.map((item) => (item.textContent ?? "").trim())).toEqual([
      "恢复默认",
      "保存",
    ]);
    expect(buttonByLabel("保存").disabled).toBe(true);
  });

  it("下拉弹层宽度固定为 76px", async () => {
    triggers()[0].click();
    await nextTick();
    const panel = document.querySelector<HTMLElement>(".vs-panel");
    expect(panel).toBeTruthy();
    expect(panel!.style.width).toBe("76px");
  });

  it("选择上限只写入草稿，保存后才落到设置", async () => {
    await chooseFromSelect(0, "30");
    expect(displaySettings.value.activeFps).toBe(120);
    expect(buttonByLabel("保存").disabled).toBe(false);

    buttonByLabel("保存").click();
    await nextTick();
    expect(displaySettings.value.activeFps).toBe(30);
    expect(closed).toBe(1);
  });

  it("选择无经保存写入", async () => {
    await chooseFromSelect(0, "无");
    buttonByLabel("保存").click();
    await nextTick();
    expect(displaySettings.value.activeFps).toBe("unlimited");
  });

  it("空闲档帧率经保存写入", async () => {
    await chooseFromSelect(1, "60");
    buttonByLabel("保存").click();
    await nextTick();
    expect(displaySettings.value.tiers.settling.fps).toBe(60);
  });

  it("等待秒数提交后保存生效", async () => {
    const input = waitInput();
    input.value = "5";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    await nextTick();
    buttonByLabel("保存").click();
    await nextTick();
    expect(displaySettings.value.tiers.settling.afterSec).toBe(5);
  });

  it("键入等待秒数无需先失焦即可保存", async () => {
    const input = waitInput();
    input.value = "7";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await nextTick();
    expect(buttonByLabel("保存").disabled).toBe(false);

    buttonByLabel("保存").click();
    await nextTick();
    expect(displaySettings.value.tiers.settling.afterSec).toBe(7);
  });

  it("非法输入回显当前草稿值且不产生可保存修改", async () => {
    const input = waitInput();
    input.value = "abc";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    await nextTick();
    expect(input.value).toBe("3");
    expect(buttonByLabel("保存").disabled).toBe(true);
  });

  it("恢复默认只重置草稿，保存后才提交", async () => {
    await chooseFromSelect(0, "30");
    buttonByLabel("保存").click();
    await nextTick();
    expect(displaySettings.value.activeFps).toBe(30);

    await chooseFromSelect(0, "60");
    buttonByLabel("恢复默认").click();
    await nextTick();
    expect(displaySettings.value.activeFps).toBe(30);
    expect(buttonByLabel("保存").disabled).toBe(false);

    buttonByLabel("保存").click();
    await nextTick();
    expect(displaySettings.value.activeFps).toBe(120);
  });

  it("点击遮罩关闭并丢弃未保存修改", async () => {
    await chooseFromSelect(0, "30");
    const backdrop = document.querySelector<HTMLElement>(".cosmic-backdrop");
    expect(backdrop).toBeTruthy();
    backdrop!.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(closed).toBe(1);
    expect(displaySettings.value.activeFps).toBe(120);
  });
});
