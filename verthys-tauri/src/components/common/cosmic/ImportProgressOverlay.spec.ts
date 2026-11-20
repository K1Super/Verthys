// @vitest-environment happy-dom
/**
 * ImportProgressOverlay.spec.ts — 结构化状态插槽回归
 *
 * 覆盖：提供 message 插槽时替换默认文案；未提供时回退到 message 属性。
 * 进度条本身由 QuantumProgressFlow 既有测试与构建保障，这里只锁定文案转发。
 */
import { describe, it, expect, afterEach } from "vitest";
import { createApp, defineComponent, h, type App, type VNode } from "vue";
import ImportProgressOverlay from "./ImportProgressOverlay.vue";

let app: App | null = null;
let host: HTMLDivElement | null = null;

function mountOverlay(
  extra: Record<string, unknown> = {},
  slot?: () => VNode,
): string {
  host = document.createElement("div");
  document.body.appendChild(host);
  const Root = defineComponent({
    render() {
      return h(
        ImportProgressOverlay,
        { visible: true, percent: 42, ...extra },
        slot ? { message: slot } : undefined,
      );
    },
  });
  app = createApp(Root);
  app.mount(host);
  return host.textContent || "";
}

afterEach(() => {
  app?.unmount();
  app = null;
  host?.remove();
  host = null;
});

describe("ImportProgressOverlay — message 插槽", () => {
  it("有结构化插槽时替换默认文案", () => {
    const text = mountOverlay({ message: "默认文案" }, () =>
      h("span", { class: "custom-status" }, "正在导入 1 / 100"),
    );

    expect(text).toContain("正在导入 1 / 100");
    expect(text).not.toContain("默认文案");
  });

  it("无插槽时回退到 message 文案", () => {
    const text = mountOverlay({ message: "默认文案" });

    expect(text).toContain("默认文案");
  });

  it("结构化标签与计数渲染为统一状态行", () => {
    const text = mountOverlay({
      statusLabel: "正在导入",
      statusCurrent: 3,
      statusTotal: 100,
    });

    expect(text).toContain("正在导入");
    expect(text).toContain("3");
    expect(text).toContain("100");
  });
});
