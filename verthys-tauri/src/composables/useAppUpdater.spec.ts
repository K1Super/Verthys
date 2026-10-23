/*
 * useAppUpdater 单元测试。
 *
 * Rust 更新服务承担安全判定，本文件验证前端状态层是否正确转发命令、
 * 聚合进度、维护准备态与错误码，并确保未准备时不会触发安装。
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const hoisted = vi.hoisted(() => {
  const invoke = vi.fn<(command: string, args?: Record<string, unknown>) => Promise<unknown>>();
  const listen = vi.fn<(event: string, handler: (event: { payload: unknown }) => void) => Promise<() => void>>();
  const isTauri = vi.fn<() => boolean>();
  return { invoke, listen, isTauri };
});

vi.mock("@tauri-apps/api/core", () => ({
  invoke: hoisted.invoke,
  isTauri: hoisted.isTauri,
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: hoisted.listen }));

interface CheckResult {
  updateId: string;
  currentVersion: string;
  version: string;
  date?: string;
  notes?: string;
  releaseId: string;
  channel: string;
  fileVersion: string;
  size: number;
  forceUpdate: boolean;
}

const checkResult: CheckResult = {
  updateId: "update-1",
  currentVersion: "4.1.2",
  version: "4.1.3",
  date: "2026-10-22T00:00:00Z",
  notes: "修复若干问题",
  releaseId: "20261022-000000-4.1.3-abcdef12",
  channel: "local",
  fileVersion: "4.1.3",
  size: 100,
  forceUpdate: false,
};

const prepared = {
  updateId: "update-1",
  version: "4.1.3",
  releaseId: checkResult.releaseId,
  sha256: "a".repeat(64),
  size: 100,
  fileVersion: "4.1.3",
};

async function loadUpdater() {
  vi.resetModules();
  const module = await import("./useAppUpdater");
  return module.useAppUpdater();
}

beforeEach(() => {
  vi.clearAllMocks();
  hoisted.isTauri.mockReturnValue(true);
  hoisted.listen.mockResolvedValue(() => {});
  hoisted.invoke.mockImplementation(async (command) => {
    if (command === "updater_check") return checkResult;
    if (command === "updater_prepare") return prepared;
    if (command === "updater_begin_lock") {
      return {
        challenge: "challenge-1",
        releaseId: checkResult.releaseId,
        sha256: prepared.sha256,
        expiresInMs: 120_000,
      };
    }
    if (command === "updater_confirm_lock") {
      return { receipt: "receipt-1", expiresInMs: 120_000 };
    }
    if (command === "updater_abort_lock") return undefined;
    if (command === "updater_set_critical") return undefined;
    if (command === "updater_install") return undefined;
    if (command === "updater_cancel") return undefined;
    throw new Error(`unexpected command: ${command}`);
  });
});

describe("useAppUpdater", () => {
  it("浏览器环境不调用后端检查", async () => {
    hoisted.isTauri.mockReturnValue(false);
    const updater = await loadUpdater();

    await expect(updater.checkForUpdate()).resolves.toBeNull();
    expect(hoisted.invoke).not.toHaveBeenCalled();
  });

  it("检查成功写入更新元数据", async () => {
    const updater = await loadUpdater();

    const found = await updater.checkForUpdate();

    expect(found).toMatchObject({ updateId: "update-1", version: "4.1.3" });
    expect(updater.availableUpdate.value?.releaseId).toBe(checkResult.releaseId);
    expect(updater.checking.value).toBe(false);
    expect(updater.state.value).toBe("Available");
  });

  it("检查失败记录错误码与文案", async () => {
    hoisted.invoke.mockRejectedValue({
      code: "E_UPDATER_NETWORK",
      message: "网络不可达",
    });
    const updater = await loadUpdater();

    await expect(updater.checkForUpdate(true)).resolves.toBeNull();

    expect(updater.lastError.value).toBe("网络不可达");
    expect(updater.lastErrorCode.value).toBe("E_UPDATER_NETWORK");
    expect(updater.availableUpdate.value).toBeNull();
    expect(updater.state.value).toBe("Failed");
  });

  it("没有可用更新时下载被拒绝", async () => {
    const updater = await loadUpdater();

    await expect(updater.downloadUpdate()).rejects.toThrow("没有可安装的更新");
    expect(hoisted.invoke).not.toHaveBeenCalledWith("updater_prepare", expect.anything());
  });

  it("准备成功累计进度并允许安装", async () => {
    const updater = await loadUpdater();
    await updater.checkForUpdate();

    hoisted.listen.mockImplementation(async (_event, handler) => {
      handler({ payload: { event: "Started", data: { contentLength: 100 } } });
      handler({ payload: { event: "Progress", data: { chunkLength: 60 } } });
      handler({ payload: { event: "Progress", data: { chunkLength: 40 } } });
      return () => {};
    });

    await updater.downloadUpdate();

    expect(hoisted.invoke).toHaveBeenCalledWith("updater_prepare", { updateId: "update-1" });
    expect(updater.totalBytes.value).toBe(100);
    expect(updater.downloadedBytes.value).toBe(100);
    expect(updater.downloaded.value).toBe(true);
    expect(updater.state.value).toBe("ReadyToInstall");

    const challenge = await updater.beginLock();
    expect(hoisted.invoke).toHaveBeenCalledWith("updater_begin_lock", {
      updateId: "update-1",
    });
    const receipt = await updater.confirmLock(
      { clean: true, flushed: true, dirty: false, errors: [], durationMs: 12 },
      challenge.challenge,
    );
    await updater.installUpdate(receipt.receipt);

    expect(hoisted.invoke).toHaveBeenCalledWith("updater_install", {
      updateId: "update-1",
      receipt: "receipt-1",
    });
  });

  it("准备失败重置进行中状态并保留错误", async () => {
    hoisted.invoke.mockImplementation(async (command) => {
      if (command === "updater_check") return checkResult;
      if (command === "updater_prepare") {
        throw { code: "E_UPDATER_HASH_MISMATCH", message: "哈希不一致" };
      }
      return undefined;
    });
    const updater = await loadUpdater();
    await updater.checkForUpdate();

    await expect(updater.downloadUpdate()).rejects.toMatchObject({ code: "E_UPDATER_HASH_MISMATCH" });

    expect(updater.lastErrorCode.value).toBe("E_UPDATER_HASH_MISMATCH");
    expect(updater.installing.value).toBe(false);
    expect(updater.downloaded.value).toBe(false);
  });

  it("未准备时安装不触发后端", async () => {
    const updater = await loadUpdater();
    await updater.checkForUpdate();

    await updater.installUpdate("");

    expect(hoisted.invoke).not.toHaveBeenCalledWith("updater_install", expect.anything());
  });

  it("锁库挑战与结果一并提交给后端复核", async () => {
    const updater = await loadUpdater();
    await updater.checkForUpdate();
    await updater.downloadUpdate();
    const outcome = {
      clean: true,
      flushed: true,
      dirty: false,
      errors: [],
      durationMs: 12,
    };

    const challenge = await updater.beginLock();
    await updater.confirmLock(outcome, challenge.challenge);

    expect(hoisted.invoke).toHaveBeenCalledWith("updater_confirm_lock", {
      challenge: "challenge-1",
      outcome,
    });
  });

  it("下载被后端取消时回到空闲态且保留取消码", async () => {
    hoisted.invoke.mockImplementation(async (command) => {
      if (command === "updater_check") return checkResult;
      if (command === "updater_prepare") {
        throw { code: "E_UPDATER_CANCELLED", message: "更新已取消" };
      }
      return undefined;
    });
    const updater = await loadUpdater();
    await updater.checkForUpdate();

    await expect(updater.downloadUpdate()).rejects.toMatchObject({
      code: "E_UPDATER_CANCELLED",
    });

    expect(updater.state.value).toBe("Idle");
    expect(updater.downloaded.value).toBe(false);
    expect(updater.lastErrorCode.value).toBeNull();
  });

  it("取消清理准备态并关闭会话", async () => {
    const updater = await loadUpdater();
    await updater.checkForUpdate();
    await updater.downloadUpdate();

    await updater.cancelUpdate();

    expect(hoisted.invoke).toHaveBeenCalledWith("updater_cancel");
    expect(updater.availableUpdate.value).toBeNull();
    expect(updater.preparedUpdate.value).toBeNull();
    expect(updater.downloaded.value).toBe(false);
    expect(updater.state.value).toBe("Idle");
  });

  it("锁库或安装阶段取消被拒绝且保留准备态", async () => {
    hoisted.invoke.mockImplementation(async (command) => {
      if (command === "updater_check") return checkResult;
      if (command === "updater_prepare") return prepared;
      if (command === "updater_cancel") {
        throw { code: "E_UPDATER_BUSY", message: "已有更新操作在进行" };
      }
      return undefined;
    });
    const updater = await loadUpdater();
    await updater.checkForUpdate();
    await updater.downloadUpdate();

    await expect(updater.cancelUpdate()).rejects.toMatchObject({
      code: "E_UPDATER_BUSY",
    });

    expect(updater.preparedUpdate.value).not.toBeNull();
    expect(updater.downloaded.value).toBe(true);
    expect(updater.state.value).toBe("ReadyToInstall");
  });
});
