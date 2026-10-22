/**
 * useAppUpdater 单元测试。
 *
 * 覆盖检查、下载、安装三段状态机与错误路径；模块级单例在每条用例前
 * 重建，避免上一条用例的更新句柄与进度残留。
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const hoisted = vi.hoisted(() => {
  const update = {
    currentVersion: "4.1.2",
    version: "4.1.3",
    date: "2026-10-22T00:00:00Z",
    body: "修复若干问题",
    close: vi.fn<() => Promise<void>>(),
    download: vi.fn<(onEvent?: (event: unknown) => void) => Promise<void>>(),
    install: vi.fn<() => Promise<void>>(),
  };
  return {
    update,
    check: vi.fn<() => Promise<unknown>>(),
    isTauri: vi.fn<() => boolean>(),
  };
});

vi.mock("@tauri-apps/plugin-updater", () => ({ check: hoisted.check }));
vi.mock("@tauri-apps/api/core", () => ({ isTauri: hoisted.isTauri }));

async function loadUpdater() {
  vi.resetModules();
  const mod = await import("./useAppUpdater");
  return mod.useAppUpdater();
}

beforeEach(() => {
  vi.clearAllMocks();
  hoisted.isTauri.mockReturnValue(true);
  hoisted.check.mockResolvedValue(hoisted.update);
  hoisted.update.close.mockResolvedValue(undefined);
  hoisted.update.install.mockResolvedValue(undefined);
  hoisted.update.download.mockImplementation(async (onEvent) => {
    onEvent?.({ event: "Started", data: { contentLength: 100 } });
    onEvent?.({ event: "Progress", data: { chunkLength: 60 } });
    onEvent?.({ event: "Progress", data: { chunkLength: 40 } });
    onEvent?.({ event: "Finished" });
  });
});

describe("useAppUpdater", () => {
  it("浏览器环境不调用后端检查", async () => {
    hoisted.isTauri.mockReturnValue(false);
    const updater = await loadUpdater();

    await expect(updater.checkForUpdate()).resolves.toBeNull();
    expect(hoisted.check).not.toHaveBeenCalled();
  });

  it("发现更新时写入版本元数据并保留句柄", async () => {
    const updater = await loadUpdater();

    const found = await updater.checkForUpdate();

    expect(found).toMatchObject({ currentVersion: "4.1.2", version: "4.1.3" });
    expect(updater.availableUpdate.value?.version).toBe("4.1.3");
    expect(updater.checking.value).toBe(false);
  });

  it("检查失败记录错误并返回空结果", async () => {
    hoisted.check.mockRejectedValue(new Error("network down"));
    const updater = await loadUpdater();

    await expect(updater.checkForUpdate(true)).resolves.toBeNull();

    expect(updater.lastError.value).toBe("network down");
    expect(updater.availableUpdate.value).toBeNull();
    expect(updater.checking.value).toBe(false);
  });

  it("下载前调用安装不触发后端", async () => {
    const updater = await loadUpdater();
    await updater.checkForUpdate();

    await updater.installUpdate();

    expect(hoisted.update.install).not.toHaveBeenCalled();
  });

  it("下载累计进度并在完成后允许安装", async () => {
    const updater = await loadUpdater();
    await updater.checkForUpdate();

    await updater.downloadUpdate();

    expect(hoisted.update.download).toHaveBeenCalledTimes(1);
    expect(updater.totalBytes.value).toBe(100);
    expect(updater.downloadedBytes.value).toBe(100);
    expect(updater.downloaded.value).toBe(true);

    await updater.installUpdate();

    expect(hoisted.update.install).toHaveBeenCalledTimes(1);
  });

  it("下载失败重置进行中状态并抛出错误", async () => {
    hoisted.update.download.mockRejectedValue(new Error("disk full"));
    const updater = await loadUpdater();
    await updater.checkForUpdate();

    await expect(updater.downloadUpdate()).rejects.toThrow("disk full");

    expect(updater.lastError.value).toBe("disk full");
    expect(updater.installing.value).toBe(false);
    expect(updater.downloaded.value).toBe(false);
    await expect(updater.installUpdate()).resolves.toBeUndefined();
    expect(hoisted.update.install).not.toHaveBeenCalled();
  });

  it("重复检查释放旧句柄且重置下载状态", async () => {
    const updater = await loadUpdater();
    await updater.checkForUpdate();
    await updater.downloadUpdate();

    await updater.checkForUpdate();

    expect(hoisted.update.close).toHaveBeenCalledTimes(1);
    expect(updater.downloaded.value).toBe(false);
    expect(updater.downloadedBytes.value).toBe(0);
  });
});
