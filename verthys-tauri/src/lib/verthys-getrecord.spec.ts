/**
 * verthys-getrecord.spec.ts — 单条记录读取的判别式语义测试
 *
 * 覆盖点：失败不再被折叠为空值——超出单条上限与通道异常可归类；
 * 兼容包装（原函数）行为保持不变。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../utils/invoke_wrapper", () => ({ invokeWithTimeout: vi.fn() }));
vi.mock("../core/frontend-ipc-priority", () => ({ markFrontendIpcActive: vi.fn() }));

import { invokeWithTimeout } from "../utils/invoke_wrapper";
import { verthysGetRecordDetailed, verthysGetRecord } from "./verthys";

const invokeMock = vi.mocked(invokeWithTimeout);

describe("verthysGetRecordDetailed", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("超限失败不被折叠为空值：返回判别式与归因", async () => {
    invokeMock.mockResolvedValue({
      ok: false,
      error: "record_too_large: 12582913 > 12582912",
    } as never);

    const outcome = await verthysGetRecordDetailed(7);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.code).toBe("record_too_large");
      expect(outcome.error).toContain("record_too_large");
    }
    // 兼容包装保持既有契约（失败仍为空值）
    expect(await verthysGetRecord(7)).toBeNull();
  });

  it("通道异常归类为 channel_error", async () => {
    invokeMock.mockResolvedValue({ ok: false, error: "worker ipc timeout" } as never);
    const outcome = await verthysGetRecordDetailed(8);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.code).toBe("channel_error");
    }
  });

  it("成功路径映射记录字段", async () => {
    invokeMock.mockResolvedValue({
      ok: true, rtype: 5, name: "chunk_1", data: "AAAA",
    } as never);
    const outcome = await verthysGetRecordDetailed(1);
    expect(outcome).toEqual({
      ok: true,
      record: { type: 5, name: "chunk_1", dataB64: "AAAA" },
    });
  });
});