/**
 * frame-budget.spec.ts — 帧预算监控确定性单元测试
 *
 * 直接注入任务耗时样本序列（recordFrame），不依赖真实帧调度；
 * 空闲档位经模块 mock 可变 level（覆盖仅 active 采样的守卫路径）。
 * 覆盖：环形缓冲容量与尾部保留、巨帧丢弃、非 active 档不采样、
 * 每 60 帧评估一次的决策节奏、getMetrics 分位数数值、draw call 上报。
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { FrameBudgetMonitor } from "./frame-budget";

/* 可变空闲档位（模块 mock 与测试共享同一引用） */
const holst = vi.hoisted(() => ({
  idleLevel: { value: "active" as "active" | "settling" | "idle" | "deep-idle" },
}));

vi.mock("../composables/useGlobalIdleScheduler", () => ({
  useGlobalIdleScheduler: () => ({ level: holst.idleLevel }),
  disposeGlobalIdleScheduler: () => {},
}));

function makeMonitor(): FrameBudgetMonitor {
  const monitor = new FrameBudgetMonitor();
  monitor.start();
  return monitor;
}

describe("FrameBudgetMonitor", () => {
  afterEach(() => {
    holst.idleLevel.value = "active";
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  /** 档位落地会操作 document.body —— node 环境注入桩 */
  function stubDocument(): void {
    vi.stubGlobal("document", {
      body: { classList: { toggle: vi.fn() } },
    });
  }

  it("环形缓冲最多保留最近 60 个样本（覆盖写不留旧值）", () => {
    stubDocument();
    vi.spyOn(console, "info").mockImplementation(() => {});
    const m = makeMonitor();
    for (let i = 1; i <= 120; i++) m.recordFrame(i);
    const metrics = m.getMetrics();
    expect(metrics.samples).toBe(60);
    expect(metrics.jsTimeMs).toBe(120); // 最后一条为最近样本
    expect(metrics.meanMs).toBeCloseTo(90.5, 6); // 均值 = 61..120 的平均
  });

  it("巨帧丢弃：≤0 或 ≥1000ms 的样本不计入", () => {
    const m = makeMonitor();
    m.recordFrame(3);
    m.recordFrame(1000);
    m.recordFrame(0);
    m.recordFrame(-1);
    expect(m.getMetrics().samples).toBe(1);
    expect(m.getMetrics().jsTimeMs).toBe(3);
  });

  it("仅 active 档采样：非 active 期间样本被忽略", () => {
    const m = makeMonitor();
    m.recordFrame(3);
    holst.idleLevel.value = "idle";
    m.recordFrame(4);
    expect(m.getMetrics().samples).toBe(1);
    holst.idleLevel.value = "active";
    m.recordFrame(5);
    expect(m.getMetrics().samples).toBe(2);
  });

  it("每 60 帧评估一次：越预算序列在第 2 次评估才降一档", () => {
    stubDocument();
    vi.spyOn(console, "info").mockImplementation(() => {});
    const m = makeMonitor();
    for (let i = 0; i < 60; i++) m.recordFrame(100);
    expect(m.getLevel()).toBe(0); // 第 1 次评估仅累计越预算计数
    for (let i = 0; i < 60; i++) m.recordFrame(100);
    expect(m.getLevel()).toBe(1); // 连续 2 次越预算 → 降一档
  });

  it("getMetrics 分位数数值正确（均值 / P50 / P95 / P99）", () => {
    stubDocument();
    vi.spyOn(console, "info").mockImplementation(() => {});
    const m = makeMonitor();
    for (let i = 1; i <= 60; i++) m.recordFrame(i * 10); // 10..600 毫秒
    const metrics = m.getMetrics();
    expect(metrics.samples).toBe(60);
    expect(metrics.meanMs).toBeCloseTo(305, 6);
    expect(metrics.p50Ms).toBe(300);
    expect(metrics.p95Ms).toBe(570);
    expect(metrics.p99Ms).toBe(600);
    expect(metrics.level).toBe(0);
  });

  it("draw call 上报进入指标快照", () => {
    const m = makeMonitor();
    m.reportDrawCalls(7);
    expect(m.getMetrics().drawCalls).toBe(7);
  });
});