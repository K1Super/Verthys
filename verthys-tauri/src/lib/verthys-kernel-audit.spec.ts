/**
 * verthys-kernel-audit.spec.ts — 内核降级审计去重契约
 *
 * 覆盖点：同一 (state, reason) 只写一次；状态变化重新写；显式重置后
 * 重新写；写入失败释放去重键以便下轮重试。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../utils/ipc/invoke_wrapper", () => ({ invokeWithTimeout: vi.fn() }));
vi.mock("../core/frontend-ipc-priority", () => ({ markFrontendIpcActive: vi.fn() }));

import { invokeWithTimeout } from "../utils/ipc/invoke_wrapper";
import {
  verthysAuditKernelDegraded,
  verthysResetKernelDegradedAudit,
} from "./verthys";

const invokeMock = vi.mocked(invokeWithTimeout);

describe("verthysAuditKernelDegraded", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockResolvedValue(undefined as never);
    verthysResetKernelDegradedAudit();
  });

  it("同一 (state, reason) 只写一次", async () => {
    await verthysAuditKernelDegraded(6, 1);
    await verthysAuditKernelDegraded(6, 1);

    expect(invokeMock).toHaveBeenCalledTimes(1);
    expect(invokeMock).toHaveBeenCalledWith(
      "verthys_audit_kernel_degraded",
      { kernelState: 6, kernelReason: 1 },
    );
  });

  it("状态或原因变化重新写", async () => {
    await verthysAuditKernelDegraded(6, 1);
    await verthysAuditKernelDegraded(7, 2);

    expect(invokeMock).toHaveBeenCalledTimes(2);
  });

  it("显式重置后允许再次写入", async () => {
    await verthysAuditKernelDegraded(6, 1);
    verthysResetKernelDegradedAudit();
    await verthysAuditKernelDegraded(6, 1);

    expect(invokeMock).toHaveBeenCalledTimes(2);
  });

  it("写入失败释放去重键，下轮可重试", async () => {
    invokeMock.mockRejectedValueOnce(new Error("ipc down"));

    await expect(verthysAuditKernelDegraded(6, 1)).rejects.toThrow("ipc down");
    await verthysAuditKernelDegraded(6, 1);

    expect(invokeMock).toHaveBeenCalledTimes(2);
  });
});
