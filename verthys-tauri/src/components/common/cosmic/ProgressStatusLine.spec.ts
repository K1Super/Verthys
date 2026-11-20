// @vitest-environment happy-dom
/**
 * ProgressStatusLine.spec.ts — 统一进度状态行
 *
 * 覆盖：无总数时只显示标签；有总数时显示四边形环与计数；当前值上限收敛。
 */
import { describe, it, expect, afterEach } from "vitest";
import { createApp, defineComponent, h, type App } from "vue";
import ProgressStatusLine from "./ProgressStatusLine.vue";

let app: App | null = null;
let host: HTMLDivElement | null = null;

function mount(props: { label: string; current?: number; total?: number }): HTMLDivElement {
  host = document.createElement("div");
  document.body.appendChild(host);
  const Root = defineComponent({
    render() {
      return h(ProgressStatusLine, props);
    },
  });
  app = createApp(Root);
  app.mount(host);
  return host;
}

afterEach(() => {
  app?.unmount();
  app = null;
  host?.remove();
  host = null;
});

describe("ProgressStatusLine", () => {
  it("无总数时只显示阶段标签", () => {
    const el = mount({ label: "正在读取文件" });

    expect(el.textContent).toContain("正在读取文件");
    expect(el.querySelector(".psl-count")).toBeNull();
    expect(el.querySelector(".psl-separator")).toBeNull();
  });

  it("有总数时显示四边形环与当前/总数", () => {
    const el = mount({ label: "正在导入", current: 3, total: 100 });

    expect(el.textContent).toContain("正在导入");
    expect(el.querySelector(".psl-separator")).not.toBeNull();
    expect(el.querySelector(".psl-current")?.textContent).toBe("3");
    expect(el.querySelector(".psl-total")?.textContent).toBe("100");
  });

  it("当前值超过总数时收敛到总数", () => {
    const el = mount({ label: "正在导出", current: 120, total: 100 });

    expect(el.querySelector(".psl-current")?.textContent).toBe("100");
  });

  it("总数为 0 时忽略当前值，不渲染计数", () => {
    const el = mount({ label: "正在打包", current: 5, total: 0 });

    expect(el.querySelector(".psl-count")).toBeNull();
    expect(el.querySelector(".psl-separator")).toBeNull();
  });
});
