// @vitest-environment happy-dom
/*
 * DevLogPanel.spec.ts — 日志面板读取契约
 *
 * 覆盖：日志行渲染与等级标记、空态、读取失败直陈错误。
 * 定时刷新只由组件自身生命周期管理，测试用真实定时器并在卸载时清理。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import DevLogPanel from "./DevLogPanel.vue";

const tailMock = vi.hoisted(() => vi.fn());

vi.mock("./log_client", () => ({
  tailDevLogs: tailMock,
}));

let app: App | null = null;
let host: HTMLDivElement | null = null;

function mountPanel(): void {
  host = document.createElement("div");
  document.body.appendChild(host);
  app = createApp({ render: () => h(DevLogPanel) });
  app.mount(host);
}

async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
  await nextTick();
}

beforeEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
});

afterEach(() => {
  app?.unmount();
  host?.remove();
  app = null;
  host = null;
});

describe("实时日志面板", () => {
  it("渲染日志行并标注等级", async () => {
    tailMock.mockResolvedValue({
      logDir: "C:/logs",
      lines: [
        {
          timestamp: "2026-11-26T10:00:00Z",
          level: "INFO",
          pid: 1,
          module: "entry",
          message: "started",
          processName: "main_ui",
        },
        {
          timestamp: "2026-11-26T10:00:01Z",
          level: "WARN",
          pid: 1,
          module: "entry",
          message: "slow",
          processName: "worker",
        },
        {
          timestamp: "2026-11-26T10:00:02Z",
          level: "ERROR",
          pid: 1,
          module: "entry",
          message: "boom",
          processName: "inspector",
        },
      ],
    });

    mountPanel();
    await settle();

    expect(tailMock).toHaveBeenCalledWith("all", 200);
    expect(document.querySelectorAll(".log-row").length).toBe(3);
    expect(document.querySelector(".log-row.is-warn")).not.toBeNull();
    expect(document.querySelector(".log-row.is-error")).not.toBeNull();
    expect(document.querySelector(".log-foot")?.textContent).toContain("C:/logs");
  });

  it("无日志时显示空态", async () => {
    tailMock.mockResolvedValue({ logDir: "C:/logs", lines: [] });

    mountPanel();
    await settle();

    expect(document.querySelectorAll(".log-row").length).toBe(0);
    expect(document.querySelector(".log-empty")?.textContent).toContain("暂无日志");
  });

  it("读取失败直陈错误而不伪造日志", async () => {
    tailMock.mockRejectedValue(new Error("读取日志失败: denied"));

    mountPanel();
    await settle();

    expect(document.querySelectorAll(".log-row").length).toBe(0);
    expect(document.querySelector(".log-error")?.textContent).toContain("读取日志失败");
  });
});
