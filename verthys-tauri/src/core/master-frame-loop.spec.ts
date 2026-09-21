/**
 * master-frame-loop.spec.ts — 主渲染循环确定性单元测试
 *
 * 经注入假宿主（手动推帧调度器 + 可推进墙钟）驱动 MasterFrameLoop：
 * 不依赖真实 rAF / performance.now，帧间隔由测试显式推进。
 * 空闲档位经模块 mock 提供可变 level（覆盖节流档行为；node 环境
 * 无 window，真实调度器 install 为无操作）。
 *
 * 覆盖：注册/注销、mustRun 上限拒绝、空闲档节流间隔、整帧跳过后
 * frameStep 累积与钳制、豁免授予与释放、页面隐藏拒绝、引用计数、
 * 超时强制释放、错误熔断、once 低档位逐帧执行、任务耗时上报。
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { MasterFrameLoop, type LoopHost } from "./master-frame-loop";
import { frameBudgetMonitor } from "./frame-budget";

/* 可变空闲档位（模块 mock 与测试共享同一引用） */
const holst = vi.hoisted(() => ({
  idleLevel: { value: "active" as "active" | "settling" | "idle" | "deep-idle" },
}));

vi.mock("../composables/useGlobalIdleScheduler", () => ({
  useGlobalIdleScheduler: () => ({ level: holst.idleLevel }),
  disposeGlobalIdleScheduler: () => {},
}));

/** 假宿主：advance 推进墙钟并触发一次已排程的帧回调 */
function makeHost() {
  let pending: ((tsMs: number) => void) | null = null;
  let now = 0;
  const host: LoopHost = {
    requestFrame: (cb) => {
      pending = cb;
      return 1;
    },
    cancelFrame: () => {
      pending = null;
    },
    nowMs: () => now,
  };
  const advance = (ms: number): void => {
    now += ms;
    const cb = pending;
    pending = null;
    if (cb) cb(now);
  };
  return { host, advance };
}

describe("MasterFrameLoop", () => {
  afterEach(() => {
    holst.idleLevel.value = "active";
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("注册任务逐帧执行；注销后不再执行", () => {
    const { host, advance } = makeHost();
    const loop = new MasterFrameLoop(host);
    loop.start();
    let calls = 0;
    const unregister = loop.register(() => {
      calls++;
    });
    advance(50);
    advance(50);
    expect(calls).toBe(2);
    unregister?.();
    advance(50);
    advance(50);
    expect(calls).toBe(2);
    loop.stop();
  });

  it("mustRun 数量超上限时拒绝注册", () => {
    const { host } = makeHost();
    const loop = new MasterFrameLoop(host);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const a = loop.register(() => {}, { type: "mustRun" });
    const b = loop.register(() => {}, { type: "mustRun" });
    const c = loop.register(() => {}, { type: "mustRun" });
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(c).toBeNull();
    expect(warn).toHaveBeenCalledTimes(1);
    a?.();
    b?.();
  });

  it("空闲档节流：idle 200ms 间隔仅执行到期帧", () => {
    holst.idleLevel.value = "idle";
    const { host, advance } = makeHost();
    const loop = new MasterFrameLoop(host);
    loop.start();
    let calls = 0;
    loop.register(() => {
      calls++;
    });
    for (let i = 0; i < 8; i++) advance(50); // t = 400ms
    expect(calls).toBe(2); // 仅 t=200 / t=400 到期执行
    loop.stop();
  });

  it("整帧跳过不推进基准：到期帧 frameStep 累积含跳过时长且钳制 50ms", () => {
    holst.idleLevel.value = "idle";
    const { host, advance } = makeHost();
    const loop = new MasterFrameLoop(host);
    loop.start();
    const steps: number[] = [];
    loop.register((ctx) => steps.push(ctx.frameStep));
    for (let i = 0; i < 8; i++) advance(50); // 执行于 t=200 / t=400
    advance(700); // t=1100：距上次 700ms → 钳制 50ms
    expect(steps).toEqual([0.05, 0.05, 0.05]);
    loop.stop();
  });

  it("豁免 granted 后低档位恢复每帧执行；释放后恢复节流", () => {
    holst.idleLevel.value = "idle";
    const { host, advance } = makeHost();
    const loop = new MasterFrameLoop(host);
    loop.start();
    let calls = 0;
    loop.register(() => {
      calls++;
    });
    const res = loop.requestExemption("t");
    expect(res.status).toBe("granted");
    for (let i = 0; i < 6; i++) advance(50); // 豁免期（300ms）每帧执行
    expect(calls).toBe(6);
    loop.releaseExemption(res.token);
    const afterRelease = calls;
    for (let i = 0; i < 10; i++) advance(50); // 恢复 200ms 节流（500ms 窗口）
    expect(calls - afterRelease).toBeGreaterThanOrEqual(2);
    expect(calls - afterRelease).toBeLessThanOrEqual(3);
    loop.stop();
  });

  it("豁免引用计数：仅全部 token 释放后才恢复节流", () => {
    holst.idleLevel.value = "idle";
    const { host, advance } = makeHost();
    const loop = new MasterFrameLoop(host);
    loop.start();
    let calls = 0;
    loop.register(() => {
      calls++;
    });
    const r1 = loop.requestExemption("a");
    const r2 = loop.requestExemption("b");
    expect(r1.token).not.toBeNull();
    expect(r2.token).not.toBeNull();
    for (let i = 0; i < 5; i++) advance(50);
    expect(calls).toBe(5);
    loop.releaseExemption(r1.token);
    for (let i = 0; i < 5; i++) advance(50); // r2 仍生效 → 继续每帧
    expect(calls).toBe(10);
    loop.releaseExemption(r2.token);
    const afterAll = calls;
    for (let i = 0; i < 10; i++) advance(50); // 全部释放 → 恢复节流
    expect(calls - afterAll).toBeLessThanOrEqual(3);
    loop.stop();
  });

  it("页面隐藏时豁免申请被拒绝", () => {
    const { host } = makeHost();
    const loop = new MasterFrameLoop(host);
    vi.stubGlobal("document", { visibilityState: "hidden" });
    const info = vi.spyOn(console, "info").mockImplementation(() => {});
    const res = loop.requestExemption("t");
    expect(res.status).toBe("rejected");
    expect(res.token).toBeNull();
    expect(info).toHaveBeenCalled();
  });

  it("豁免超时强制释放：超过时长上限后恢复档位节流", () => {
    holst.idleLevel.value = "idle";
    const { host, advance } = makeHost();
    const loop = new MasterFrameLoop(host);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    loop.start();
    let calls = 0;
    loop.register(() => {
      calls++;
    });
    loop.requestExemption("t");
    for (let i = 0; i < 42; i++) advance(50); // t = 2100ms
    /* 豁免期 t=50..1550 每帧执行（31 次）；1550 帧末尾超时释放后
     * 恢复 200ms 节流 → t=1750 / t=1950 两次 */
    expect(calls).toBe(33);
    expect(warn).toHaveBeenCalled();
    loop.stop();
  });

  it("once 任务在低档位仍每帧执行（不受节流档影响）", () => {
    holst.idleLevel.value = "deep-idle";
    const { host, advance } = makeHost();
    const loop = new MasterFrameLoop(host);
    loop.start();
    let calls = 0;
    loop.once(() => {
      calls++;
    });
    advance(50);
    loop.once(() => {
      calls++;
    });
    advance(50);
    expect(calls).toBe(2);
    loop.stop();
  });

  it("任务连续抛错 10 次自动注销（错误熔断）", () => {
    const { host, advance } = makeHost();
    const loop = new MasterFrameLoop(host);
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    loop.start();
    let calls = 0;
    loop.register(() => {
      calls++;
      throw new Error("boom");
    });
    for (let i = 0; i < 15; i++) advance(50);
    expect(calls).toBe(10);
    expect(error).toHaveBeenCalledTimes(10);
    loop.stop();
  });

  it("每执行帧上报任务总耗时到帧预算监控", () => {
    const { host, advance } = makeHost();
    const spy = vi.spyOn(frameBudgetMonitor, "recordFrame");
    const loop = new MasterFrameLoop(host);
    loop.start();
    loop.register(() => {});
    advance(50);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(0); // 帧内 t0 与 nowMs 同刻
    loop.stop();
  });

  it("start/stop 幂等；stop 后不再推帧", () => {
    const { host, advance } = makeHost();
    const loop = new MasterFrameLoop(host);
    let calls = 0;
    loop.register(() => {
      calls++;
    });
    loop.start();
    loop.start();
    advance(50);
    expect(calls).toBe(1);
    loop.stop();
    loop.stop();
    advance(50);
    expect(calls).toBe(1);
    loop.start();
    advance(50);
    expect(calls).toBe(2);
    loop.stop();
  });
});