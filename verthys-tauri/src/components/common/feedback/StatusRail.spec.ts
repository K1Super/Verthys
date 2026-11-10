// @vitest-environment happy-dom
/*
 * StatusRail.spec.ts — 常驻状态轨契约
 *
 * 覆盖：
 *   1. 无告知时不渲染轨道（空态不占位）
 *   2. 每条告知渲染一枚刻度键，语义色与无障碍名称随条目下发
 *   3. 点击展开面板：正文、动作文案与 Toast 同源玻璃基面类名
 *   4. 动作点击先收起面板再回传对应 key
 *   5. 再次点击同一键收起、点击另一条切换
 *   6. 轨外 pointerdown 收起、轨内 pointerdown 保留
 *   7. Escape 收起面板
 *   8. 告知消除后面板自动收起（不残留上一轮展开态）
 *   9. 图标悬浮提示随条目下发，面板展开时抑制（不遮挡面板）
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, ref, type App, type Ref } from "vue";
import StatusRail, { type StatusRailNotice } from "./StatusRail.vue";

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
  notices: StatusRailNotice[] | Ref<StatusRailNotice[]>;
  onAction?: (key: string) => void;
}

/** 提示指令替身：把绑定值落到可断言属性，避免依赖全局指令注册 */
const tipStub = {
  mounted: (el: HTMLElement, binding: { value: string }) => {
    el.setAttribute("data-tip-value", binding.value ?? "");
  },
  updated: (el: HTMLElement, binding: { value: string }) => {
    el.setAttribute("data-tip-value", binding.value ?? "");
  },
};

function mount(options: MountOptions): HTMLDivElement {
  const { notices, onAction } = options;
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({
    render: () =>
      h(StatusRail, {
        notices: Array.isArray(notices) ? notices : notices.value,
        onAction,
      }),
  });
  app.directive("tip", tipStub);
  app.mount(container);
  mounted.push({ app, container });
  return container;
}

const NOTICES: StatusRailNotice[] = [
  {
    key: "reseal",
    tone: "warning",
    icon: "device",
    tip: "恢复码会话：尚未重绑本机设备槽",
    text: "当前为恢复码会话：尚未重绑本机设备槽，下次普通解锁将失败。",
    actionLabel: "重绑本机设备",
  },
  {
    key: "rotate",
    tone: "info",
    icon: "rotate",
    tip: "恢复码会话：可执行全库密钥轮换",
    text: "恢复码会话可执行全库密钥轮换：重建容器 DEK，当前恢复码继续有效。",
    actionLabel: "全库密钥轮换",
  },
];

const rail = (container: HTMLElement) => container.querySelector<HTMLElement>(".status-rail");
const triggers = (container: HTMLElement) =>
  [...container.querySelectorAll<HTMLButtonElement>(".sr-trigger")];
const panel = (container: HTMLElement) => container.querySelector<HTMLElement>(".sr-panel");

describe("常驻状态轨", () => {
  it("无告知时不渲染轨道", () => {
    const container = mount({ notices: [] });

    expect(rail(container)).toBeNull();
  });

  it("每条告知渲染一枚刻度键并下发语义色与无障碍名称", () => {
    const container = mount({ notices: NOTICES });
    const buttons = triggers(container);

    expect(rail(container)).not.toBeNull();
    expect(buttons.length).toBe(2);
    expect(buttons[0]?.classList.contains("sf-act--warn")).toBe(true);
    expect(buttons[1]?.classList.contains("sf-act--update")).toBe(true);
    expect(buttons[0]?.getAttribute("aria-label")).toBe(NOTICES[0]!.text);
    expect(buttons[0]?.getAttribute("data-tip-value")).toBe(NOTICES[0]!.tip);
    expect(buttons[0]?.getAttribute("aria-expanded")).toBe("false");
  });

  it("点击展开面板并在 Toast 同源玻璃基面上呈现正文与动作", async () => {
    const container = mount({ notices: NOTICES });

    triggers(container)[1]?.click();
    await nextTick();

    const opened = panel(container);
    expect(opened).not.toBeNull();
    expect(opened?.classList.contains("notice-card")).toBe(true);
    expect(opened?.classList.contains("is-info")).toBe(true);
    expect(opened?.textContent).toContain("全库密钥轮换");
    expect(opened?.textContent).toContain("当前恢复码继续有效");
    expect(triggers(container)[1]?.getAttribute("aria-expanded")).toBe("true");
    expect(triggers(container)[1]?.getAttribute("aria-controls")).toBe(opened?.id);
    /* 面板已展示完整正文：展开项不再弹悬浮提示，避免遮挡面板 */
    expect(triggers(container)[1]?.getAttribute("data-tip-value")).toBe("");
  });

  it("动作点击先收起面板再回传对应 key", async () => {
    const onAction = vi.fn();
    const container = mount({ notices: NOTICES, onAction });

    triggers(container)[0]?.click();
    await nextTick();
    const action = panel(container)?.querySelector<HTMLButtonElement>(".sr-action");
    expect(action?.textContent?.trim()).toBe("重绑本机设备");

    action?.click();
    await nextTick();

    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onAction).toHaveBeenCalledWith("reseal");
    /* 面板已进入离场（Transition 在测试环境不派发 transitionend，
       行为以展开状态为准）；动作本身必须先收起再回传 */
    expect(triggers(container)[0]?.getAttribute("aria-expanded")).toBe("false");
    expect(container.querySelector(".sr-panel.is-warning")).not.toBeNull();
  });

  it("再次点击同一键收起，点击另一条切换面板", async () => {
    const container = mount({ notices: NOTICES });

    triggers(container)[0]?.click();
    await nextTick();
    expect(container.querySelector(".sr-panel.is-warning")).not.toBeNull();

    triggers(container)[1]?.click();
    await nextTick();
    expect(container.querySelector(".sr-panel.is-info")).not.toBeNull();
    expect(triggers(container)[1]?.getAttribute("aria-expanded")).toBe("true");

    triggers(container)[1]?.click();
    await nextTick();
    expect(triggers(container)[1]?.getAttribute("aria-expanded")).toBe("false");
  });

  it("轨外 pointerdown 收起面板，轨内 pointerdown 保留", async () => {
    const container = mount({ notices: NOTICES });

    triggers(container)[0]?.click();
    await nextTick();
    expect(triggers(container)[0]?.getAttribute("aria-expanded")).toBe("true");

    triggers(container)[0]?.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true }));
    await nextTick();
    expect(triggers(container)[0]?.getAttribute("aria-expanded")).toBe("true");

    document.body.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true }));
    await nextTick();
    expect(triggers(container)[0]?.getAttribute("aria-expanded")).toBe("false");
  });

  it("Escape 收起面板", async () => {
    const container = mount({ notices: NOTICES });

    triggers(container)[0]?.click();
    await nextTick();
    expect(triggers(container)[0]?.getAttribute("aria-expanded")).toBe("true");

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    await nextTick();
    expect(triggers(container)[0]?.getAttribute("aria-expanded")).toBe("false");
  });

  it("告知消除后面板自动收起", async () => {
    const notices = ref<StatusRailNotice[]>([...NOTICES]);
    const container = mount({ notices });

    triggers(container)[1]?.click();
    await nextTick();
    expect(triggers(container)[1]?.getAttribute("aria-expanded")).toBe("true");

    notices.value = notices.value.filter((notice) => notice.key !== "rotate");
    await nextTick();

    expect(container.querySelector(".sr-panel")).toBeNull();
    expect(triggers(container).length).toBe(1);
  });
});
