// @vitest-environment happy-dom
/*
 * ModuleDangerZone.spec.ts — 模块删除二次确认契约
 *
 * 覆盖：状态展示、已删除禁用、DELETE 字面量校验、删除成功后刷新。
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";

const status = vi.fn();
const remove = vi.fn();

/* 部分 mock：缓存域初始化会引用 lib/verthys 的其他导出，不能整体替换。 */
vi.mock("../../lib/verthys", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/verthys")>();
  return {
    ...actual,
    verthysV4ModuleStatus: (...args: unknown[]) => status(...args),
    verthysV4ModuleDelete: (...args: unknown[]) => remove(...args),
  };
});

import { initVerthysCache } from "../../cache/composition/verthys-cache";
import ModuleDangerZone from "./ModuleDangerZone.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
});

function mountPanel() {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({ render: () => h(ModuleDangerZone) });
  app.directive("tip", {});
  app.mount(container);
  mounted.push({ app, container });
  /* 删除确认弹窗由 CosmicOverlay 渲染（默认 teleport 到 body），
   * 查询根统一为 body；面板本体仍在 container 内。 */
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

describe("模块数据销毁面板", () => {
  beforeAll(() => {
    // 删除成功后的缓存失效依赖缓存域单例
    initVerthysCache();
  });

  beforeEach(() => {
    status.mockReset();
    remove.mockReset();
  });

  it("展示三模块状态，已删除模块禁用删除", async () => {
    status.mockImplementation(async (id: number) => ({
      ok: true,
      op: "v4_module_status",
      enabled: id === 0,
      deleted: id === 2,
      unlocked: false,
    }));
    const container = mountPanel();
    await settle();
    expect(container.textContent).toContain("照片");
    expect(container.textContent).toContain("已删除");
    const buttons = Array.from(
      container.querySelectorAll<HTMLButtonElement>('button[aria-label$=" · 删除模块"]'),
    );
    expect(buttons[2]?.disabled).toBe(true);
  });

  it("输入 DELETE 后才允许永久删除并刷新状态", async () => {
    status.mockResolvedValue({ ok: true, op: "v4_module_status", enabled: false });
    remove.mockResolvedValue({ ok: true, op: "v4_module_delete" });
    const container = mountPanel();
    await settle();

    container
      .querySelector<HTMLButtonElement>('button[aria-label$=" · 删除模块"]')
      ?.click();
    await nextTick();
    const input = container.querySelector<HTMLInputElement>("#mdz-confirm");
    if (!input) throw new Error("confirm input missing");
    input.value = "delete";
    input.dispatchEvent(new Event("input"));
    await nextTick();
    const save = buttonByText(container, "永久删除");
    expect(save?.disabled).toBe(true);

    input.value = "DELETE";
    input.dispatchEvent(new Event("input"));
    await nextTick();
    expect(save?.disabled).toBe(false);
    save?.click();
    await settle();
    expect(remove).toHaveBeenCalledWith(0, "DELETE");
    // 初次加载 3 + 删除后刷新面板 3 + 同步模块保护状态 3
    await vi.waitFor(() => expect(status).toHaveBeenCalledTimes(9));
  });
});
