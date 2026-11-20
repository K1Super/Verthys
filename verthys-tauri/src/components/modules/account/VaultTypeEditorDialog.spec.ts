// @vitest-environment happy-dom
/*
 * VaultTypeEditorDialog.spec.ts — 自定义类型工作台的最小行为契约
 *
 * 覆盖：空态新建、左右工作台渲染、新字段唯一命名与属性面板展开、
 * 切换控件种类后出现对应的专属编辑器。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import type { VaultTypeDef } from "../../../constants/vault_item_types";
import { saveCustomVaultTypes } from "../../../lib/vault_item_type_store";
import VaultTypeEditorDialog from "./VaultTypeEditorDialog.vue";

/* 保存动作只验证组件交给持久化层的形态；真实落盘由 vault_item_type_store.spec 覆盖 */
vi.mock("../../../lib/vault_item_type_store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/vault_item_type_store")>();
  return {
    ...actual,
    saveCustomVaultTypes: vi.fn(async () => ({ ok: true, persisted: true })),
  };
});

const saveMock = vi.mocked(saveCustomVaultTypes);

beforeEach(() => {
  saveMock.mockClear();
});

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
  document.body.innerHTML = "";
});

function mountEditor(types: VaultTypeDef[] = []): HTMLElement {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(VaultTypeEditorDialog, {
        modelValue: true,
        types,
      }),
  });
  // 组件依赖项目全局的 v-tip 指令；测试里给一个空实现即可
  app.directive("tip", {});
  app.mount(container);
  mounted.push({ app, container });
  return document.body;
}

const buttonByText = (root: HTMLElement, text: string): HTMLButtonElement | undefined =>
  Array.from(root.querySelectorAll<HTMLButtonElement>("button")).find((button) =>
    button.textContent?.includes(text),
  );

async function openNewType(root: HTMLElement): Promise<void> {
  await nextTick();
  await nextTick();
  buttonByText(root, "新建类型")?.click();
  await nextTick();
}

describe("自定义类型工作台", () => {
  it("空态可新建类型，并渲染类型轨与字段表", async () => {
    const root = mountEditor();
    await nextTick();
    await nextTick();
    expect(root.querySelector(".type-empty")).toBeTruthy();

    await openNewType(root);
    expect(root.querySelector(".type-rail .rail-item")).toBeTruthy();
    expect(root.querySelector<HTMLInputElement>(".type-title-input")?.value).toBe("新类型");
    expect(root.querySelectorAll(".field-entry").length).toBe(1);
  });

  it("新增字段生成不重复的名称，并展开属性面板", async () => {
    const root = mountEditor();
    await openNewType(root);
    buttonByText(root, "添加字段")?.click();
    await nextTick();

    const labels = Array.from(
      root.querySelectorAll<HTMLInputElement>(".field-label-input"),
    ).map((input) => input.value);
    expect(labels).toEqual(["字段", "字段 2"]);
    expect(root.querySelector(".field-panel")).toBeTruthy();
    expect(
      root.querySelector("input[placeholder='留空则归入类型分区']"),
    ).toBeTruthy();
  });

  it("切换控件种类后出现候选项编辑区", async () => {
    const root = mountEditor();
    await openNewType(root);

    root.querySelector<HTMLButtonElement>(".field-kind .vs-trigger")?.click();
    await nextTick();
    const option = Array.from(root.querySelectorAll<HTMLElement>(".vs-option")).find(
      (node) => node.textContent?.trim() === "选项",
    );
    expect(option).toBeTruthy();
    option?.click();
    await nextTick();

    expect(root.querySelector(".field-options-editor")).toBeTruthy();
    expect(root.querySelectorAll(".option-row").length).toBe(1);
  });

  it("删除类型：确认后从类型轨移除并回到空态", async () => {
    const def: VaultTypeDef = {
      id: "custom:test",
      label: "测试类型",
      icon: "generic",
      tone: "accent",
      titleField: "f_name",
      cardFields: [],
      searchFields: ["f_name"],
      fields: [{ id: "f_name", label: "名称", kind: "text" }],
      builtin: false,
    };
    const root = mountEditor([def]);
    await nextTick();
    await nextTick();

    buttonByText(root, "删除该类型")?.click();
    await nextTick();
    await nextTick();
    expect(root.textContent).toContain("确认删除");

    buttonByText(root, "确认删除")?.click();
    await nextTick();
    await nextTick();
    expect(root.querySelector(".rail-item")).toBeFalsy();
    expect(root.querySelector(".type-empty")).toBeTruthy();

    /* 删除最后一个类型后，动作区仍必须存在；否则空集永远无法落盘 */
    expect(buttonByText(root, "保存并关闭")).toBeTruthy();
    buttonByText(root, "保存并关闭")?.click();
    await nextTick();
    await nextTick();
    await nextTick();
    expect(saveMock).toHaveBeenCalledTimes(1);
    expect(saveMock.mock.calls[0][0]).toEqual([]);
  });

  it("旧版重复字段名与候选值在保存前自动收敛，不阻断删除/保存", async () => {
    const legacy: VaultTypeDef = {
      id: "custom:legacy",
      label: "旧类型",
      icon: "generic",
      tone: "accent",
      titleField: "f_a",
      cardFields: ["f_a", "f_b"],
      searchFields: ["f_a", "f_a"],
      fields: [
        { id: "f_a", label: "字段", kind: "text", required: true },
        { id: "f_b", label: "字段", kind: "select", options: ["同", " ", "同"] },
        { id: "f_c", label: "", kind: "text" },
      ],
      builtin: false,
    };
    const root = mountEditor([legacy]);
    await nextTick();
    await nextTick();

    buttonByText(root, "保存类型")?.click();
    await nextTick();
    await nextTick();
    await nextTick();

    expect(saveMock).toHaveBeenCalledTimes(1);
    const saved = saveMock.mock.calls[0][0];
    expect(saved[0].label).toBe("旧类型");
    expect(saved[0].fields.map((field) => field.label)).toEqual([
      "字段",
      "字段 2",
      "未命名字段",
    ]);
    expect(saved[0].fields[1].options).toEqual(["同"]);
    // 主标题不再重复进入次行，搜索字段去重
    expect(saved[0].cardFields).toEqual(["f_b"]);
    expect(saved[0].searchFields).toEqual(["f_a"]);
  });

  it("全敏感类型在保存前补出明文名称字段，避免结构不可保存", async () => {
    const legacy: VaultTypeDef = {
      id: "custom:secret",
      label: "全敏感",
      icon: "generic",
      tone: "danger",
      titleField: "f_secret",
      cardFields: [],
      searchFields: [],
      fields: [{ id: "f_secret", label: "密钥", kind: "password", sensitive: true }],
      builtin: false,
    };
    const root = mountEditor([legacy]);
    await nextTick();
    await nextTick();

    buttonByText(root, "保存类型")?.click();
    await nextTick();
    await nextTick();
    await nextTick();

    expect(saveMock).toHaveBeenCalledTimes(1);
    const saved = saveMock.mock.calls[0][0][0];
    expect(saved.fields[0]).toMatchObject({
      label: "名称",
      kind: "text",
      required: true,
    });
    expect(saved.fields[0].sensitive).toBeUndefined();
    expect(saved.titleField).toBe(saved.fields[0].id);
    expect(saved.searchFields).toEqual([saved.fields[0].id]);
  });
});
