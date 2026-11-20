// @vitest-environment happy-dom
/*
 * AnchorManagementPanel.spec.ts — 回退锚点刷新动作的稳定性契约
 *
 * 覆盖：刷新请求瞬间返回时，busy 窗口仍保持最短时长；刷新图标使用
 * 一次性整圈类，相邻扫描按钮的禁用态不会一闪而过。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import AnchorManagementPanel from "./AnchorManagementPanel.vue";

vi.mock("../../lib/verthys", () => ({
  verthysRollbackAnchorList: vi.fn(async () => ({ anchors: [], state: 1 })),
  verthysRollbackAnchorScan: vi.fn(),
  verthysRollbackAnchorReclaim: vi.fn(),
  verthysRollbackAnchorRelease: vi.fn(),
}));

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
  document.body.innerHTML = "";
});

function mountPanel(): void {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const app = createApp({ render: () => h(AnchorManagementPanel) });
  app.directive("tip", {});
  app.mount(container);
  mounted.push({ app, container });
}

describe("回退锚点刷新稳定性", () => {
  it("请求瞬间返回时仍保持最短 busy 窗口，扫描按钮不会被闪一下", async () => {
    mountPanel();
    await nextTick();
    await Promise.resolve();
    await nextTick();

    const refresh = document.querySelector<HTMLButtonElement>(
      'button[aria-label="刷新回退锚点"]',
    );
    const scan = document.querySelector<HTMLButtonElement>(
      'button[aria-label="扫描与释放"]',
    );
    expect(refresh).toBeTruthy();
    expect(scan).toBeTruthy();
    expect(refresh!.classList.contains("is-busy")).toBe(true);
    expect(refresh!.querySelector("svg")?.classList.contains("is-spinning-once")).toBe(true);
    expect(scan!.disabled).toBe(true);

    /* 50ms 处仍应处于 busy：请求瞬间返回也不能只闪一帧 */
    await new Promise((resolve) => setTimeout(resolve, 50));
    await nextTick();
    expect(refresh!.classList.contains("is-busy")).toBe(true);
    expect(scan!.disabled).toBe(true);

    /* 超过最短 busy 窗口后恢复 */
    await new Promise((resolve) => setTimeout(resolve, 500));
    await nextTick();
    expect(refresh!.classList.contains("is-busy")).toBe(false);
    expect(scan!.disabled).toBe(false);
  });

  it("旋转图标以自身中心为轴；长任务保留无限旋转，刷新使用一次性整圈", () => {
    const css = readFileSync(
      resolve(process.cwd(), "src/styles/security/section-field.css"),
      "utf8",
    );
    expect(css).toContain("transform-box: fill-box");
    expect(css).toContain("transform-origin: center");
    expect(css).toContain("animation: sf-act-spin 1.5s linear infinite");
    expect(css).toContain("animation: sf-act-spin 0.44s linear");
  });
});
