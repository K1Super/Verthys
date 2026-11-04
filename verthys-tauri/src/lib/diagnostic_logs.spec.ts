/**
 * diagnostic_logs 单元测试。
 *
 * 验证导出入口只转发用户选择的绝对路径，不把日志内容或密钥带到前端；
 * 非 Tauri 环境与用户取消都返回 null。
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const hoisted = vi.hoisted(() => ({
  invoke: vi.fn<(command: string, args?: Record<string, unknown>) => Promise<unknown>>(),
  save: vi.fn<() => Promise<string | null>>(),
  isTauri: vi.fn<() => boolean>(),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: hoisted.invoke,
  isTauri: hoisted.isTauri,
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({
  save: hoisted.save,
}));

import { exportAppLogs } from "./diagnostic_logs";

describe("exportAppLogs", () => {
  beforeEach(() => {
    hoisted.invoke.mockReset();
    hoisted.save.mockReset();
    hoisted.isTauri.mockReset();
  });

  it("非 Tauri 环境直接返回 null", async () => {
    hoisted.isTauri.mockReturnValue(false);
    await expect(exportAppLogs()).resolves.toBeNull();
    expect(hoisted.save).not.toHaveBeenCalled();
  });

  it("用户取消时不调用后端", async () => {
    hoisted.isTauri.mockReturnValue(true);
    hoisted.save.mockResolvedValue(null);
    await expect(exportAppLogs()).resolves.toBeNull();
    expect(hoisted.invoke).not.toHaveBeenCalled();
  });

  it("选择路径后转发 diagnostics_export_logs 命令", async () => {
    hoisted.isTauri.mockReturnValue(true);
    hoisted.save.mockResolvedValue("C:\\Users\\alice\\verthys-diagnostics.zip");
    hoisted.invoke.mockResolvedValue("C:\\Users\\alice\\verthys-diagnostics.zip");

    await expect(exportAppLogs()).resolves.toBe(
      "C:\\Users\\alice\\verthys-diagnostics.zip",
    );
    expect(hoisted.invoke).toHaveBeenCalledWith("diagnostics_export_logs", {
      targetPath: "C:\\Users\\alice\\verthys-diagnostics.zip",
    });
  });

  it("后端失败向上抛出，由调用方提示", async () => {
    hoisted.isTauri.mockReturnValue(true);
    hoisted.save.mockResolvedValue("C:\\Users\\alice\\verthys-diagnostics.zip");
    hoisted.invoke.mockRejectedValue(new Error("export failed"));

    await expect(exportAppLogs()).rejects.toThrow("export failed");
  });
});
