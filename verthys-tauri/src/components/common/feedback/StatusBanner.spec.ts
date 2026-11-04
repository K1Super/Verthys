// @vitest-environment happy-dom
/*
 * StatusBanner.spec.ts — 全局常驻横幅契约
 *
 * 覆盖：
 *   1. 语义色类与 role 声明（读屏可感知状态）
 *   2. 单动作渲染 / 点击上报 / 禁用态不误触
 *   3. 无动作配置时不渲染动作区（避免空按钮占位）
 *   4. 多动作按数组顺序渲染并回传各自 key
 *   5. 关闭入口独立上报
 *   6. actions 插槽优先于内置动作
 *   7. 宿主类名透传到横幅根节点（版面约束由调用方承担）
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, h, type App, type Slot } from "vue";
import StatusBanner, { type BannerAction } from "./StatusBanner.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
  vi.clearAllMocks();
});

interface MountOptions {
  tone?: "info" | "warning" | "danger" | "success";
  actionLabel?: string;
  actionDisabled?: boolean;
  actions?: BannerAction[];
  dismissible?: boolean;
  class?: string;
  slots?: Record<string, Slot>;
  onAction?: (key: string) => void;
  onDismiss?: () => void;
}

function mount(options: MountOptions = {}) {
  const { slots, onAction, onDismiss, ...props } = options;
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(StatusBanner, { ...props, onAction, onDismiss }, slots),
  });
  app.mount(container);
  mounted.push({ app, container });
  return container;
}

describe("常驻状态横幅", () => {
  it("默认使用中性语义色并声明 status 角色", () => {
    const container = mount();
    const banner = container.querySelector(".status-banner");

    expect(banner).not.toBeNull();
    expect(banner?.classList.contains("is-info")).toBe(true);
    expect(banner?.getAttribute("role")).toBe("status");
  });

  it("按 tone 输出对应语义色类", () => {
    const container = mount({ tone: "warning" });
    const banner = container.querySelector(".status-banner");

    expect(banner?.classList.contains("is-warning")).toBe(true);
    expect(banner?.classList.contains("is-info")).toBe(false);
  });

  it("渲染动作并在点击时回传固定 key", () => {
    const onAction = vi.fn();
    const container = mount({ actionLabel: "重绑本机设备", onAction });
    const action = container.querySelector<HTMLButtonElement>(".sb-action");

    expect(action?.textContent?.trim()).toBe("重绑本机设备");
    action?.click();
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onAction).toHaveBeenCalledWith("primary");
  });

  it("禁用态不触发动作", () => {
    const onAction = vi.fn();
    const container = mount({ actionLabel: "处理中", actionDisabled: true, onAction });
    const action = container.querySelector<HTMLButtonElement>(".sb-action");

    expect(action?.disabled).toBe(true);
    action?.click();
    expect(onAction).not.toHaveBeenCalled();
  });

  it("未配置动作时不渲染动作区", () => {
    const container = mount();

    expect(container.querySelector(".sb-tail")).toBeNull();
    expect(container.querySelector(".sb-action")).toBeNull();
  });

  it("多动作按数组顺序渲染并回传各自 key", () => {
    const onAction = vi.fn();
    const container = mount({
      actions: [
        { key: "retry", label: "重试" },
        { key: "resume", label: "继续解密" },
      ],
      onAction,
    });
    const buttons = container.querySelectorAll<HTMLButtonElement>(".sb-action");

    expect(buttons.length).toBe(2);
    expect(buttons[0]?.textContent?.trim()).toBe("重试");
    expect(buttons[1]?.textContent?.trim()).toBe("继续解密");
    buttons[1]?.click();
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onAction).toHaveBeenCalledWith("resume");
  });

  it("关闭入口独立上报", () => {
    const onDismiss = vi.fn();
    const container = mount({ dismissible: true, onDismiss });
    const dismiss = container.querySelector<HTMLButtonElement>(".sb-dismiss");

    expect(dismiss?.getAttribute("aria-label")).toBe("关闭提示");
    dismiss?.click();
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("宿主类名透传到横幅根节点", () => {
    const container = mount({ class: "recovery-banner" });

    expect(container.querySelector(".status-banner.recovery-banner")).not.toBeNull();
  });

  it("actions 插槽优先于内置动作", () => {
    const onAction = vi.fn();
    const container = mount({
      actionLabel: "默认动作",
      onAction,
      slots: { actions: () => [h("button", { class: "custom-action" }, "自定义动作")] },
    });

    expect(container.querySelector(".sb-action")).toBeNull();
    expect(container.querySelector(".custom-action")?.textContent).toBe("自定义动作");
  });
});
