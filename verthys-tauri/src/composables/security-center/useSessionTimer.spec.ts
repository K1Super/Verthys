// @vitest-environment happy-dom
/**
 * useSessionTimer.spec.ts — 会话倒计时显示守卫
 *
 * 覆盖：
 * - startSessionTick 幂等：重复调用不得叠加 interval（倒计时不得成倍加速）
 * - 就绪且开启空闲锁定时倒计时推进，归零后按当前超时循环复位
 * - 空闲锁定关闭时冻结
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ref, nextTick } from "vue";
import { useSessionTimer } from "./useSessionTimer";

vi.mock("../../lib/keyManager", () => ({
  getSessionTimeout: vi.fn(() => 60_000),
}));

vi.mock("../useGlobalIdleScheduler", async () => {
  const { ref } = await import("vue");
  return { useGlobalIdleScheduler: () => ({ level: ref("active") }) };
});

let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.useFakeTimers();
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  warnSpy.mockRestore();
  vi.useRealTimers();
});

describe("useSessionTimer 倒计时", () => {
  it("startSessionTick 幂等：重复启动只有一个计时器", async () => {
    const ready = ref(true);
    const lock = ref(true);
    const t = useSessionTimer({ globalKeyReady: ready, idleLockEnabled: lock });
    t.sessionRemaining.value = 60_000;
    t.startSessionTick();
    t.startSessionTick();
    t.startSessionTick();

    await vi.advanceTimersByTimeAsync(1000);
    expect(t.sessionRemaining.value).toBe(59_000);

    await vi.advanceTimersByTimeAsync(2000);
    expect(t.sessionRemaining.value).toBe(57_000);
    t.stopSessionTick();
  });

  it("空闲锁定关闭：倒计时冻结", async () => {
    const ready = ref(true);
    const lock = ref(false);
    const t = useSessionTimer({ globalKeyReady: ready, idleLockEnabled: lock });
    t.sessionRemaining.value = 60_000;
    t.startSessionTick();
    await vi.advanceTimersByTimeAsync(5000);
    expect(t.sessionRemaining.value).toBe(60_000);
    t.stopSessionTick();
  });

  it("归零后按当前超时复位（循环显示）", async () => {
    const ready = ref(true);
    const lock = ref(true);
    const t = useSessionTimer({ globalKeyReady: ready, idleLockEnabled: lock });
    t.sessionRemaining.value = 1000;
    t.startSessionTick();
    await vi.advanceTimersByTimeAsync(1000);
    expect(t.sessionRemaining.value).toBe(0);
    // 归零后的下一拍按当前超时复位（循环显示，不长时间停留 0）
    await vi.advanceTimersByTimeAsync(1000);
    expect(t.sessionRemaining.value).toBe(60_000);
    await nextTick();
    t.stopSessionTick();
  });
});
