// @vitest-environment happy-dom
/*
 * launch-presentation-runtime.spec.ts — 启动展示判定运行时
 *
 * 覆盖：同一次开机直接进入、重启首映、IPC 失败/超时回退首映、
 * 响应非法回退首映、非 Tauri 环境回退首映，以及启动时刻的读写。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));

import {
  BOOT_EPOCH_TOLERANCE_MS,
  LAUNCH_BOOT_EPOCH_KEY,
} from "./launch-presentation";
import {
  BOOT_EPOCH_IPC_TIMEOUT_MS,
  resolveLaunchPresentation,
} from "./launch-presentation-runtime";

const EPOCH = 1_700_000_000_000;

/** happy-dom 窗口上的 Tauri 桥注入位（运行时只检查其存在性） */
const tauriWindow = window as unknown as { __TAURI_INTERNALS__?: unknown };

beforeEach(() => {
  invokeMock.mockReset();
  tauriWindow.__TAURI_INTERNALS__ = {};
  window.localStorage.clear();
});

afterEach(() => {
  delete tauriWindow.__TAURI_INTERNALS__;
  vi.useRealTimers();
});

describe("resolveLaunchPresentation", () => {
  it("同一次开机：直接进入并记录启动时刻", async () => {
    window.localStorage.setItem(LAUNCH_BOOT_EPOCH_KEY, String(EPOCH));
    invokeMock.mockResolvedValue({ boot_epoch_ms: EPOCH, uptime_ms: 60_000 });

    await expect(resolveLaunchPresentation()).resolves.toBe("direct");
    expect(window.localStorage.getItem(LAUNCH_BOOT_EPOCH_KEY)).toBe(String(EPOCH));
  });

  it("重启：首映并更新启动时刻", async () => {
    window.localStorage.setItem(
      LAUNCH_BOOT_EPOCH_KEY,
      String(EPOCH - BOOT_EPOCH_TOLERANCE_MS - 1),
    );
    invokeMock.mockResolvedValue({ boot_epoch_ms: EPOCH, uptime_ms: 60_000 });

    await expect(resolveLaunchPresentation()).resolves.toBe("ceremony");
    expect(window.localStorage.getItem(LAUNCH_BOOT_EPOCH_KEY)).toBe(String(EPOCH));
  });

  it("IPC 失败：首映且不篡改已有标记", async () => {
    const previous = String(EPOCH - 1);
    window.localStorage.setItem(LAUNCH_BOOT_EPOCH_KEY, previous);
    invokeMock.mockRejectedValue(new Error("ipc failed"));

    await expect(resolveLaunchPresentation()).resolves.toBe("ceremony");
    expect(window.localStorage.getItem(LAUNCH_BOOT_EPOCH_KEY)).toBe(previous);
  });

  it("响应非法：首映", async () => {
    invokeMock.mockResolvedValue({ boot_epoch_ms: 0, uptime_ms: 0 });

    await expect(resolveLaunchPresentation()).resolves.toBe("ceremony");
  });

  it("非 Tauri 环境：首映且不发起 IPC", async () => {
    delete tauriWindow.__TAURI_INTERNALS__;

    await expect(resolveLaunchPresentation()).resolves.toBe("ceremony");
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("IPC 超时：首映，不阻塞启动", async () => {
    vi.useFakeTimers();
    invokeMock.mockImplementation(() => new Promise(() => {}));

    const pending = resolveLaunchPresentation();
    await vi.advanceTimersByTimeAsync(BOOT_EPOCH_IPC_TIMEOUT_MS);
    await expect(pending).resolves.toBe("ceremony");
  });
});
