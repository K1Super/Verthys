// @vitest-environment happy-dom
/**
 * useSessionTimer.spec.ts — 会话倒计时显示守卫
 *
 * 覆盖（单一事实源语义）：
 * - startSessionTick 幂等：重复调用不得叠加 interval
 * - 显示值恒由权威截止时间推导（无本地递减计数）
 * - 空闲锁定关闭时显示完整超时
 * - 截止时间已过的剩余为 0，不再本地循环复位
 * - 用户活动刷新截止时间 → 显示即时同步
 * - 低功耗档恢复 → 立即校正（无需暂停时长补偿）
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ref, nextTick } from "vue";
import { useSessionTimer } from "./useSessionTimer";

/** mock 工厂与用例共享的权威状态（hoisted：先于模块导入创建） */
const authority = vi.hoisted(() => ({
  timeoutMs: 60_000,
  deadline: null as unknown as { value: number },
  idleLevel: null as unknown as { value: string },
}));

vi.mock("../../lib/keyManager", async () => {
  const { ref } = await import("vue");
  const deadline = ref(0);
  authority.deadline = deadline;
  return {
    sessionIdleDeadlineRef: deadline,
    getSessionTimeout: () => authority.timeoutMs,
    getSessionRemainingMs: () =>
      deadline.value === 0
        ? authority.timeoutMs
        : Math.max(0, deadline.value - Date.now()),
  };
});

vi.mock("../useGlobalIdleScheduler", async () => {
  const { ref } = await import("vue");
  const level = ref("active");
  authority.idleLevel = level;
  return { useGlobalIdleScheduler: () => ({ level }) };
});

beforeEach(() => {
  vi.useFakeTimers();
  authority.timeoutMs = 60_000;
  authority.deadline.value = 0;
  authority.idleLevel.value = "active";
});

afterEach(() => {
  vi.useRealTimers();
});

describe("useSessionTimer 倒计时", () => {
  it("startSessionTick 幂等：重复启动只有一个计时器，按权威截止时间递减", async () => {
    const ready = ref(true);
    const lock = ref(true);
    const t = useSessionTimer({ globalKeyReady: ready, idleLockEnabled: lock });
    authority.deadline.value = Date.now() + 60_000;
    await nextTick();
    expect(t.sessionRemaining.value).toBe(60_000);

    t.startSessionTick();
    t.startSessionTick();
    t.startSessionTick();

    await vi.advanceTimersByTimeAsync(1000);
    expect(t.sessionRemaining.value).toBe(59_000);

    await vi.advanceTimersByTimeAsync(2000);
    expect(t.sessionRemaining.value).toBe(57_000);
    t.stopSessionTick();
  });

  it("空闲锁定关闭：显示保持完整超时", async () => {
    const ready = ref(true);
    const lock = ref(false);
    const t = useSessionTimer({ globalKeyReady: ready, idleLockEnabled: lock });
    authority.deadline.value = Date.now() + 10_000;
    t.startSessionTick();
    await vi.advanceTimersByTimeAsync(5000);
    expect(t.sessionRemaining.value).toBe(60_000);
    t.stopSessionTick();
  });

  it("截止时间过后显示 0，不再本地循环复位（倒计时不得造假）", async () => {
    const ready = ref(true);
    const lock = ref(true);
    const t = useSessionTimer({ globalKeyReady: ready, idleLockEnabled: lock });
    authority.deadline.value = Date.now() + 1000;
    t.startSessionTick();
    await vi.advanceTimersByTimeAsync(1000);
    expect(t.sessionRemaining.value).toBe(0);
    // 旧实现会在归零后复位为完整超时，导致显示与实际锁定完全脱节
    await vi.advanceTimersByTimeAsync(2000);
    expect(t.sessionRemaining.value).toBe(0);
    t.stopSessionTick();
  });

  it("用户活动刷新截止时间 → 显示即时同步（无需等待下一拍）", async () => {
    const ready = ref(true);
    const lock = ref(true);
    const t = useSessionTimer({ globalKeyReady: ready, idleLockEnabled: lock });
    authority.deadline.value = Date.now() + 60_000;
    await nextTick();
    expect(t.sessionRemaining.value).toBe(60_000);

    await vi.advanceTimersByTimeAsync(30_000);
    authority.deadline.value = Date.now() + 60_000;
    await nextTick();
    expect(t.sessionRemaining.value).toBe(60_000);
  });

  it("低功耗档恢复：按截止时间立即校正，显示与真实流逝一致", async () => {
    const ready = ref(true);
    const lock = ref(true);
    const t = useSessionTimer({ globalKeyReady: ready, idleLockEnabled: lock });
    authority.deadline.value = Date.now() + 60 * 60_000;
    await nextTick();

    authority.idleLevel.value = "deep-idle";
    await nextTick();
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    // 低功耗档暂停逐秒更新（显示值不变）
    expect(t.sessionRemaining.value).toBe(60 * 60_000);

    authority.idleLevel.value = "active";
    await nextTick();
    expect(t.sessionRemaining.value).toBe(50 * 60_000);
  });
});
