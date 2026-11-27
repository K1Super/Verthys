// @vitest-environment happy-dom
/*
 * ModuleKeyRow.spec.ts — 模块密钥轨道条目设计契约
 *
 * 覆盖：
 *   1. 名称与状态为双行标识，状态按中点分段且不再使用竖标
 *   2. 密钥保护开关复用动作节点并把新状态回传父层
 *   3. 图标节点复用共享动作节点：恢复槽绑定态常驻青绿，关闭保护时密钥节点不渲染
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, h, type App } from "vue";
import ModuleKeyRow from "./ModuleKeyRow.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
});

function mountRow(
  overrides: Record<string, unknown> = {},
  handlers: {
    toggle?: (checked: boolean) => void;
    openKey?: () => void;
    logout?: () => void;
  } = {},
) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(ModuleKeyRow, {
        mid: "photo",
        idx: 0,
        label: "拾光",
        globalKeyReady: true,
        enabled: true,
        hasRecord: true,
        ready: false,
        hasRecovery: true,
        stateClass: "state-set",
        stateText: "已设置 · 256-bit · 恢复槽",
        onToggleEnabled: handlers.toggle ?? (() => {}),
        onOpenKeyDialog: handlers.openKey ?? (() => {}),
        onLogoutModule: handlers.logout ?? (() => {}),
        ...overrides,
      }),
  });
  app.directive("tip", {});
  app.mount(container);
  mounted.push({ app, container });
  return container;
}

describe("ModuleKeyRow 轨道设计契约", () => {
  it("状态读数分段呈现，名称与状态间无竖标", () => {
    const container = mountRow();
    const word = container.querySelector(".sf-orbit-state-word");
    const metas = Array.from(container.querySelectorAll(".sf-orbit-state-meta")).map(
      (node) => node.textContent?.trim(),
    );

    expect(container.querySelector(".sf-orbit-name")?.textContent).toBe("拾光");
    expect(word?.textContent).toBe("已设置");
    expect(metas).toEqual(["256-bit", "恢复槽"]);
    expect(container.querySelector(".sf-state-tick")).toBeNull();
    expect(container.querySelector(".sf-status-mark")).not.toBeNull();
    expect(container.querySelector(".sf-orbit-id")).not.toBeNull();

    // 普通动作节点不携带 aria-pressed，只有双态保护开关才声明按压语义
    const keyNode = container.querySelector(
      'button[aria-label="拾光 · 修改独立密钥"]',
    ) as HTMLButtonElement;
    expect(keyNode.hasAttribute("aria-pressed")).toBe(false);
  });

  it("保护开关复用动作节点并回传新状态", () => {
    const toggle = vi.fn();
    const container = mountRow({}, { toggle });
    const node = container.querySelector(
      'button[aria-label="拾光 · 模块密钥保护开关"]',
    ) as HTMLButtonElement;

    expect(node.classList.contains("sf-act")).toBe(true);
    expect(node.classList.contains("is-latched")).toBe(true);
    expect(node.getAttribute("aria-pressed")).toBe("true");
    node.click();

    expect(toggle).toHaveBeenCalledTimes(1);
    expect(toggle).toHaveBeenCalledWith(false);
  });

  it("恢复槽绑定态常驻青绿，保护关闭时相关功能节点不渲染", () => {
    const bound = mountRow();
    expect(bound.querySelector(".sf-act--success.is-latched")).not.toBeNull();
    expect(
      bound
        .querySelector('button[aria-label="拾光 · 修改独立密钥"]')
        ?.hasAttribute("disabled"),
    ).toBe(false);

    const unbound = mountRow({ hasRecovery: false });
    expect(unbound.querySelector(".sf-act--success.is-latched")).toBeNull();

    // 保护关闭：修改/生成/恢复槽/登出全部不渲染，
    // 不再出现「生成独立密钥」的误导提示，也不保留可点击的登出入口
    const off = mountRow({ enabled: false, ready: true, hasRecord: false });
    expect(off.querySelector('button[aria-label="拾光 · 修改独立密钥"]')).toBeNull();
    expect(off.querySelector('button[aria-label="拾光 · 生成独立密钥"]')).toBeNull();
    expect(off.querySelector('button[aria-label="拾光 · 恢复槽"]')).toBeNull();
    expect(off.querySelector('button[aria-label="拾光 · 登出模块"]')).toBeNull();
  });

  it("登录就绪后登出节点可触发", () => {
    const logout = vi.fn();
    const container = mountRow({ ready: true }, { logout });
    const node = container.querySelector(
      'button[aria-label="拾光 · 登出模块"]',
    ) as HTMLButtonElement;

    node.click();
    expect(logout).toHaveBeenCalledTimes(1);
  });
});
