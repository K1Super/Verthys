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
  listen: vi.fn(),
  tauriEnv: vi.fn(),
}));

vi.mock("../../lib/keyManager", async () => {
  const { ref } = await import("vue");
  mocks.verthysReady = ref(true);
  return { verthysReadyRef: mocks.verthysReady };
});

vi.mock("../../lib/verthys", () => ({
  verthysGetSecurityStatus: mocks.verthysGetSecurityStatus,
}));

vi.mock("@tauri-apps/api/event", () => ({ listen: mocks.listen }));

vi.mock("../../utils/tauri_env", () => ({
  isTauriEnvironment: mocks.tauriEnv,
}));

import { useDefenseStatus } from "./useDefenseStatus";

function report(partial: Record<string, unknown>) {
  return {
    path_state: [1, 1, 1, 1, 1, 1, 1],
    blocked_count: 7,
    degraded_count: 0,
    failed_count: 0,
    all_critical_blocked: true,
    has_degraded: false,
    path_reason: [7, 13, 20, 7, 10, 13, 14],
    limited_count: 0,
    policy_flags: 0,
    checked_at_unix_ms: 1700000000000,
    ...partial,
  };
}

let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.clearAllMocks();
  mocks.tauriEnv.mockReturnValue(false);
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

  it("存在可修复降级 → degraded（不宣称全阻断）", async () => {
    mocks.verthysReady.value = true;
    mocks.verthysGetSecurityStatus.mockResolvedValue(
      report({
        blocked_count: 6,
        degraded_count: 1,
        limited_count: 0,
        path_state: [1, 2, 1, 1, 1, 1, 1],
        path_reason: [1, 6, 7, 7, 10, 13, 14],
      }),
    );
    const { defenseMeta } = useDefenseStatus();
    await vi.waitFor(() => expect(defenseMeta.value.degraded).toBe(1));
    await nextTick();
    expect(defenseMeta.value.stance).toBe("degraded");
  });

  it("仅已加固项 → limited（与可修复降级区分）", async () => {
    mocks.verthysReady.value = true;
    mocks.verthysGetSecurityStatus.mockResolvedValue(
      report({
        blocked_count: 5,
        degraded_count: 2,
        limited_count: 2,
        path_state: [1, 2, 2, 1, 1, 1, 1],
        path_reason: [1, 2, 5, 7, 10, 13, 14],
      }),
    );
    const { defenseMeta, defensePaths } = useDefenseStatus();
    await vi.waitFor(() => expect(defenseMeta.value.degraded).toBe(2));
    await nextTick();
    expect(defenseMeta.value.stance).toBe("limited");
    expect(defenseMeta.value.limited).toBe(2);
    expect(defenseMeta.value.stanceLabel).toContain("已加固");
    expect(defensePaths.value[1].stateLabel).toBe("已加固");
    expect(defensePaths.value[1].limited).toBe(true);
    expect(defensePaths.value[1].reasonLabel).toContain("密钥驻留用户态");
  });

  it("可修复降级与已加固项混合 → degraded（可修复项优先）", async () => {
    mocks.verthysReady.value = true;
    mocks.verthysGetSecurityStatus.mockResolvedValue(
      report({
        blocked_count: 4,
        degraded_count: 3,
        limited_count: 2,
        path_state: [1, 2, 2, 2, 1, 1, 1],
        path_reason: [1, 2, 5, 8, 10, 13, 14],
      }),
    );
    const { defenseMeta } = useDefenseStatus();
    await vi.waitFor(() => expect(defenseMeta.value.degraded).toBe(3));
    await nextTick();
    expect(defenseMeta.value.stance).toBe("degraded");
    expect(defenseMeta.value.stanceLabel).toContain("可修复降级");
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

  it("runtime-guards 事件触发立即重采样", async () => {
    mocks.tauriEnv.mockReturnValue(true);
    mocks.verthysReady.value = false;
    let handler: (() => void) | null = null;
    mocks.listen.mockImplementation(async (_event: string, cb: () => void) => {
      handler = cb;
      return () => {};
    });
    mocks.verthysGetSecurityStatus.mockResolvedValue(report({}));

    const { defenseMeta } = useDefenseStatus();
    await vi.waitFor(() => expect(handler).not.toBeNull());

    mocks.verthysReady.value = true;
    await vi.waitFor(() => expect(defenseMeta.value.blocked).toBe(7));
    const before = mocks.verthysGetSecurityStatus.mock.calls.length;

    handler!();
    await vi.waitFor(() =>
      expect(mocks.verthysGetSecurityStatus.mock.calls.length).toBeGreaterThan(before),
    );
  });
});
