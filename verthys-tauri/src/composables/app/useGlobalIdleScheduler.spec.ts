// @vitest-environment happy-dom
/*
 * useGlobalIdleScheduler.spec.ts — 空闲调度器与设置联动契约
 *
 * 覆盖：
 *   1. 默认阈值按 3s / 10s / 60s 排程
 *   2. 设置变更按上次交互时刻重排，缩短阈值立即生效
 *   3. 减少动态偏好下交互不唤醒；失焦 / 聚焦语义正常
 *
 * 计时器以受控捕获替代真实等待：只验证排程延迟与回调落档，
 * 不依赖 fake timer 对 window 计时器的兼容性。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  disposeGlobalIdleScheduler,
  useGlobalIdleScheduler,
} from "./useGlobalIdleScheduler";
import { resetDisplaySettings, updateDisplaySettings } from "../../settings/display-settings";

const originalMatchMedia = window.matchMedia;

interface CapturedTimer {
  id: number;
  delay: number;
  cb: () => void;
  cleared: boolean;
}

/** 捕获调度器排程：返回可观察的定时器表与未取消项读取 */
function captureTimers(): {
  pending: () => CapturedTimer[];
} {
  const scheduled: CapturedTimer[] = [];
  let seq = 0;
  vi.spyOn(window, "setTimeout").mockImplementation(((cb: () => void, delay?: number) => {
    const id = ++seq;
    scheduled.push({ id, delay: delay ?? 0, cb, cleared: false });
    return id as unknown as number;
  }) as unknown as typeof window.setTimeout);
  vi.spyOn(window, "clearTimeout").mockImplementation(((id: number) => {
    const entry = scheduled.find((item) => item.id === id);
    if (entry) entry.cleared = true;
  }) as unknown as typeof window.clearTimeout);
  return {
    pending: () => scheduled.filter((item) => !item.cleared),
  };
}

/** 固定 media query 结果（减少动态偏好的唯一输入） */
function stubMatchMedia(matches: boolean): void {
  window.matchMedia = ((query: string) => ({
    matches,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}

beforeEach(() => {
  disposeGlobalIdleScheduler();
  resetDisplaySettings();
  /* 冻结 performance.now：剩余延迟由「阈值 − 已过时长」导出，
     真实时钟在并行负载下会漂移数百毫秒，使断言随机器负载抖动。
     基准取正值，避免安装时的活动被 500ms 节流窗口吞掉 */
  vi.spyOn(performance, "now").mockReturnValue(10_000);
});

afterEach(() => {
  disposeGlobalIdleScheduler();
  vi.restoreAllMocks();
  resetDisplaySettings();
  window.matchMedia = originalMatchMedia;
});

describe("useGlobalIdleScheduler", () => {
  it("默认阈值按 3s / 10s / 60s 排程并依次落档", () => {
    stubMatchMedia(false);
    const timers = captureTimers();
    const { level } = useGlobalIdleScheduler();
    expect(level.value).toBe("active");

    const pending = timers.pending();
    /* 剩余延迟 = 阈值 − 已过时长，允许毫秒级经过时间误差 */
    expect(pending[0].delay).toBeGreaterThan(2_900);
    expect(pending[0].delay).toBeLessThanOrEqual(3_000);
    expect(pending[1].delay).toBeGreaterThan(9_900);
    expect(pending[1].delay).toBeLessThanOrEqual(10_000);
    expect(pending[2].delay).toBeGreaterThan(59_900);
    expect(pending[2].delay).toBeLessThanOrEqual(60_000);

    pending[0].cb();
    expect(level.value).toBe("settling");
    pending[1].cb();
    expect(level.value).toBe("idle");
    pending[2].cb();
    expect(level.value).toBe("deep-idle");
  });

  it("设置变更按上次交互时刻重排，缩短阈值立即生效", () => {
    stubMatchMedia(false);
    const timers = captureTimers();
    const { level } = useGlobalIdleScheduler();

    updateDisplaySettings({ tiers: { settling: { afterSec: 1 } } });
    let pending = timers.pending();
    expect(pending[0].delay).toBeGreaterThan(900);
    expect(pending[0].delay).toBeLessThanOrEqual(1_000);

    pending[0].cb();
    expect(level.value).toBe("settling");

    /* 延长后按经过时长重算：尚未到 5s，应回到 active 并推迟落档 */
    updateDisplaySettings({ tiers: { settling: { afterSec: 5 }, idle: { afterSec: 30 } } });
    expect(level.value).toBe("active");
    pending = timers.pending();
    expect(pending[0].delay).toBeGreaterThan(4_900);
    expect(pending[0].delay).toBeLessThanOrEqual(5_000);
  });

  it("减少动态偏好下档位固定 idle，交互与强制重置都不唤醒", () => {
    stubMatchMedia(true);
    captureTimers();
    const { level, resetIdle } = useGlobalIdleScheduler();
    expect(level.value).toBe("idle");

    window.dispatchEvent(new Event("pointermove"));
    window.dispatchEvent(new Event("keydown"));
    resetIdle();
    expect(level.value).toBe("idle");
  });

  it("失焦落 deep-idle，聚焦恢复 active", () => {
    stubMatchMedia(false);
    captureTimers();
    const { level } = useGlobalIdleScheduler();

    window.dispatchEvent(new Event("blur"));
    expect(level.value).toBe("deep-idle");
    window.dispatchEvent(new Event("focus"));
    expect(level.value).toBe("active");
  });
});
