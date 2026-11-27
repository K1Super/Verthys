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
import { toastState } from "../../../composables/ui/useToastCenter";
import {
  verthysRollbackAnchorList,
  verthysRollbackAnchorReleaseBatch,
  verthysRollbackAnchorScan,
} from "../../../lib/verthys";

vi.mock("../../../lib/verthys", () => ({
  verthysRollbackAnchorList: vi.fn(async () => ({ anchors: [], state: 1 })),
  verthysRollbackAnchorScan: vi.fn(async () => ({
    entries: [],
    roots: [],
    files_seen: 0,
    matched_count: 0,
    truncated: false,
    partial: false,
    permission_errors: 0,
    other_errors: 0,
    scanned_at: 0,
    depth: 8,
    cached: false,
  })),
  verthysRollbackAnchorForgetRoot: vi.fn(),
  verthysRollbackAnchorScanCancel: vi.fn(),
  verthysRollbackAnchorReleaseBatch: vi.fn(async () => ({
    ok: true,
    released: 0,
    cleanupFailed: 0,
    results: [],
  })),
}));

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
  document.body.innerHTML = "";
  toastState.status.value = "";
  vi.clearAllMocks();
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
      'button[aria-label="扫描"]',
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

  it("打开回退锚点管理时只读取持久化证据，不触发扫描", async () => {
    mountPanel();
    await nextTick();
    await Promise.resolve();
    await nextTick();
    /* 初次刷新有最短 busy 窗口，等待其结束后再打开弹窗 */
    await new Promise((resolve) => setTimeout(resolve, 500));
    await nextTick();

    const entry = document.querySelector<HTMLButtonElement>(
      'button[aria-label="扫描"]',
    );
    expect(entry).toBeTruthy();
    expect(entry!.disabled).toBe(false);
    entry!.click();
    await nextTick();
    await Promise.resolve();
    await nextTick();

    const scanMock = vi.mocked(verthysRollbackAnchorScan);
    expect(scanMock).toHaveBeenCalledTimes(1);
    expect(scanMock.mock.calls[0][0]).toEqual({ peek: true });
    expect(scanMock.mock.calls[0][1]).toBeUndefined();
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

function buttonByText(text: string): HTMLButtonElement | undefined {
  return Array.from(document.querySelectorAll("button")).find(
    (button) => button.textContent?.trim() === text,
  ) as HTMLButtonElement | undefined;
}

describe("回退锚点单入口批量清理/释放", () => {
  const uuid = "22222222222222222222222222222222";

  afterEach(() => {
    vi.mocked(verthysRollbackAnchorList).mockImplementation(async () => ({
      anchors: [],
      state: 1,
    }));
    vi.mocked(verthysRollbackAnchorReleaseBatch).mockImplementation(
      async () => ({
        ok: true,
        released: 0,
        cleanupFailed: 0,
        results: [],
      }),
    );
  });

  async function openDialog(): Promise<void> {
    mountPanel();
    await nextTick();
    await new Promise((resolve) => setTimeout(resolve, 520));
    await nextTick();
    document.querySelector<HTMLButtonElement>('button[aria-label="扫描"]')!.click();
    await nextTick();
    await Promise.resolve();
    await nextTick();
  }

  it("全 DEAD 选中时只发起一次批量清理", async () => {
    vi.mocked(verthysRollbackAnchorList).mockResolvedValue({
      anchors: [{ uuid, generation: 2, witness: "dead" }],
      state: 1,
    });
    vi.mocked(verthysRollbackAnchorReleaseBatch).mockResolvedValue({
      ok: true,
      released: 1,
      cleanupFailed: 0,
      results: [{ uuid, released: true, cleanupFailed: false }],
    });

    await openDialog();
    buttonByText("清理选中")!.click();
    await nextTick();
    buttonByText("确认清理")!.click();
    await nextTick();
    await Promise.resolve();
    await nextTick();

    const batch = vi.mocked(verthysRollbackAnchorReleaseBatch);
    expect(batch).toHaveBeenCalledTimes(1);
    expect(batch).toHaveBeenCalledWith([uuid], true);
    expect(toastState.status.value).toContain("清理完成：1 条");
  });

  it("批量失败时展示可行动错误文案", async () => {
    vi.mocked(verthysRollbackAnchorList).mockResolvedValue({
      anchors: [{ uuid, generation: 2, witness: "dead" }],
      state: 1,
    });
    vi.mocked(verthysRollbackAnchorReleaseBatch).mockResolvedValue({
      ok: false,
      results: [],
      error: "ERR_00000008",
    });

    await openDialog();
    buttonByText("清理选中")!.click();
    await nextTick();
    buttonByText("确认清理")!.click();
    await nextTick();
    await new Promise((resolve) => setTimeout(resolve, 520));
    await nextTick();

    expect(vi.mocked(verthysRollbackAnchorReleaseBatch)).toHaveBeenCalledTimes(1);
    const text = document.body.textContent ?? "";
    const occurrences = text.split("回退状态文件读写失败").length - 1;
    expect(occurrences).toBe(1);
  });
});
