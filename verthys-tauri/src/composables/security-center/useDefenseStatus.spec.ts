/**
 * useDefenseStatus.spec.ts — 动态防护态势裁决守卫
 *
 * 覆盖（防回退门）：
 * - 报告缺位 / 全部未校验 → pending
 * - 1 条阻断 + 6 条未校验 → partial
 * - 7 条阻断且关键路径全阻断 → ok
 * - 关键路径标志为假 → degraded
 * - 失败优先于降级 → breach
 * - 拉取失败保留旧报告并标记陈旧
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { nextTick } from "vue";

const mocks = vi.hoisted(() => ({
  verthysReady: null as unknown as { value: boolean },
  verthysGetSecurityStatus: vi.fn(),
}));

vi.mock("../../lib/keyManager", async () => {
  const { ref } = await import("vue");
  mocks.verthysReady = ref(true);
  return { verthysReadyRef: mocks.verthysReady };
});

vi.mock("../../lib/verthys", () => ({
  verthysGetSecurityStatus: mocks.verthysGetSecurityStatus,
}));

import { useDefenseStatus } from "./useDefenseStatus";

function report(partial: Record<string, unknown>) {
  return {
    path_state: [1, 1, 1, 1, 1, 1, 1],
    blocked_count: 7,
    degraded_count: 0,
    failed_count: 0,
    all_critical_blocked: true,
    ...partial,
  };
}

let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.clearAllMocks();
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  warnSpy.mockRestore();
});

describe("useDefenseStatus 态势裁决", () => {
  it("报告缺位 → pending（不宣称全阻断）", () => {
    mocks.verthysGetSecurityStatus.mockResolvedValue(report({}));
    mocks.verthysReady.value = false;
    const { defenseMeta } = useDefenseStatus();
    expect(defenseMeta.value.stance).toBe("pending");
  });

  it("全部未校验 → pending", async () => {
    mocks.verthysReady.value = true;
    mocks.verthysGetSecurityStatus.mockResolvedValue(
      report({ path_state: [0, 0, 0, 0, 0, 0, 0], blocked_count: 0, all_critical_blocked: false }),
    );
    const { defenseMeta } = useDefenseStatus();
    await vi.waitFor(() => expect(defenseMeta.value.unchecked).toBe(7));
    expect(defenseMeta.value.stance).toBe("pending");
  });

  it("1 条阻断 + 6 条未校验 → partial（旧实现谎报全阻断）", async () => {
    mocks.verthysReady.value = true;
    mocks.verthysGetSecurityStatus.mockResolvedValue(
      report({ blocked_count: 1, all_critical_blocked: false }),
    );
    const { defenseMeta } = useDefenseStatus();
    await vi.waitFor(() => expect(defenseMeta.value.blocked).toBe(1));
    await nextTick();
    expect(defenseMeta.value.stance).toBe("partial");
  });

  it("7 条阻断且关键路径全阻断 → ok", async () => {
    mocks.verthysReady.value = true;
    mocks.verthysGetSecurityStatus.mockResolvedValue(report({}));
    const { defenseMeta } = useDefenseStatus();
    await vi.waitFor(() => expect(defenseMeta.value.blocked).toBe(7));
    await nextTick();
    expect(defenseMeta.value.stance).toBe("ok");
  });

  it("关键路径标志为假 → degraded（不宣称全阻断）", async () => {
    mocks.verthysReady.value = true;
    mocks.verthysGetSecurityStatus.mockResolvedValue(
      report({ all_critical_blocked: false }),
    );
    const { defenseMeta } = useDefenseStatus();
    await vi.waitFor(() => expect(defenseMeta.value.blocked).toBe(7));
    await nextTick();
    expect(defenseMeta.value.stance).toBe("degraded");
  });

  it("失败优先于降级 → breach", async () => {
    mocks.verthysReady.value = true;
    mocks.verthysGetSecurityStatus.mockResolvedValue(
      report({ blocked_count: 5, degraded_count: 1, failed_count: 1 }),
    );
    const { defenseMeta } = useDefenseStatus();
    await vi.waitFor(() => expect(defenseMeta.value.failed).toBe(1));
    await nextTick();
    expect(defenseMeta.value.stance).toBe("breach");
  });

  it("拉取失败保留旧报告并标记陈旧", async () => {
    mocks.verthysReady.value = true;
    mocks.verthysGetSecurityStatus.mockResolvedValueOnce(report({}));
    const { defenseMeta, refreshDefenseStatus } = useDefenseStatus();
    await vi.waitFor(() => expect(defenseMeta.value.blocked).toBe(7));
    expect(defenseMeta.value.stale).toBe(false);

    mocks.verthysGetSecurityStatus.mockRejectedValueOnce(new Error("ipc down"));
    await refreshDefenseStatus();
    await nextTick();

    expect(defenseMeta.value.blocked).toBe(7);
    expect(defenseMeta.value.stale).toBe(true);
  });
});
