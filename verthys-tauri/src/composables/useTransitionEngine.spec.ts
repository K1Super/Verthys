/**
 * useTransitionEngine.spec.ts — 渡越序列引擎确定性单元测试
 *
 * 直接调用 update(frameStep, wallStep) 显式推帧，不依赖真实帧调度。
 * 覆盖：双时间参数语义（wallStep 推进时钟与复合序列 / frameStep 仅
 * 缩放物理积分）、打断路径不变量（值连续接续 / 方向换向有界且穿越为
 * 瞬态 / 强度单调不回退 / 交接锚点 / 消散锚点）、换向接缝动量连续、
 * 正渡幂等守卫、自然路径回归、无障碍门控，以及积分历史环形覆盖与
 * 二分插值。
 */
import { describe, it, expect } from "vitest";
import { TransitionEngine } from "./useTransitionEngine";

/** 帧步长（秒）— 60fps 基准 */
const FRAME = 1 / 60;

/** 以固定帧步进推进引擎（wallStep 与 frameStep 同值 — 等价 60fps 满帧） */
function advance(e: TransitionEngine, seconds: number): void {
  const steps = Math.round(seconds / FRAME);
  for (let i = 0; i < steps; i++) e.update(FRAME, FRAME);
}

/** 新建已触发正渡的引擎（触发时刻为 0：打断强度 e0=0，剖面与自然同形） */
function makeEntering(): TransitionEngine {
  const e = new TransitionEngine();
  e.triggerEnter();
  return e;
}

/** 帧网格推进至 ti 后触发正渡（模拟逆渡期间的点击时刻） */
function makeInterruptedAt(ti: number): TransitionEngine {
  const e = new TransitionEngine();
  advance(e, ti);
  e.triggerEnter();
  return e;
}

/** 推 n 帧并记录 (wallClock, swirl) 轨迹 */
function pushFrames(
  e: TransitionEngine,
  n: number,
  frameStep: number,
  wallStep: number,
): { t: number; v: number }[] {
  const records: { t: number; v: number }[] = [];
  for (let i = 0; i < n; i++) {
    e.update(frameStep, wallStep);
    records.push({ t: e.time, v: e.swirl });
  }
  return records;
}

/** 独立参考实现：自然正渡剖面（与引擎逐点对照 — 不共享引擎内部实现） */
const refSmootherstep = (u: number): number => u * u * u * (u * (u * 6 - 15) + 10);
const refEnvelope = (x: number): number => {
  if (x <= 0 || x >= 1) return 0;
  if (x < 0.3) return 0.42 * refSmootherstep(x / 0.3);
  if (x < 0.62) return 0.42 + 0.58 * refSmootherstep((x - 0.3) / 0.32);
  return 1 - refSmootherstep((x - 0.62) / 0.38);
};

describe("TransitionEngine", () => {
  it("双时间参数语义：wallStep 推进时钟，frameStep 只缩放物理积分", () => {
    const a = makeEntering();
    const b = makeEntering();
    advance(a, 2);
    advance(b, 2); // 推进至换向窗口之后（方向权重非零，积分可比）
    const a0 = { swirl: a.swirl, dist: a.warpDist };
    const b0 = { swirl: b.swirl, dist: b.warpDist };
    a.update(0.2, 0.5);
    b.update(0.4, 0.5);
    expect(a.time).toBeCloseTo(b.time, 12);
    expect(b.swirl - b0.swirl).toBeCloseTo((a.swirl - a0.swirl) * 2, 10);
    expect(b.warpDist - b0.dist).toBeCloseTo((a.warpDist - a0.dist) * 2, 8);
  });

  it("时钟只吃 wallStep：frameStep 不影响复合序列进度", () => {
    const a = makeEntering();
    const b = makeEntering();
    advance(a, 1);
    advance(b, 1);
    a.update(0.08, 0.25);
    b.update(0.0001, 0.25);
    expect(a.time).toBeCloseTo(b.time, 12);
    expect(a.warpEnv).toBeCloseTo(b.warpEnv, 12);
    expect(a.dirW).toBeCloseTo(b.dirW, 12);
    expect(a.swirl).not.toBeCloseTo(b.swirl, 6);
  });

  describe("打断路径不变量（逆渡期间点击）", () => {
    const INTERRUPT_TIMES = [0.3, 0.9, 1.5, 1.86, 2.5, 2.9];
    /* 换向场景（打断瞬间方向量幅度显著 — 贴零窗口断言的适用集合） */
    const REVERSAL_TIMES = [0.9, 1.5, 1.86, 2.2, 2.5];

    it("触发瞬间为值连续接续：方向取反、强度维持", () => {
      for (const ti of INTERRUPT_TIMES) {
        const e = makeInterruptedAt(ti);
        const e0 = e.warpEnv;
        expect(e0).toBeGreaterThanOrEqual(0);
        expect(e0).toBeLessThanOrEqual(1);
        expect(e.dirW).toBeCloseTo(-e0, 12);
      }
    });

    it.each(INTERRUPT_TIMES)("ti=%fs：有界换向穿越 + 强度不回退 + 交接锚点", (ti) => {
      const e = makeInterruptedAt(ti);
      const e0 = e.warpEnv;
      let minE = Infinity;
      let prevDir = e.dirW;
      let crossRate: number | null = null;
      const steps = Math.round(3.1 / FRAME);
      for (let i = 0; i < steps; i++) {
        e.update(FRAME, FRAME);
        minE = Math.min(minE, e.warpEnv);
        expect(e.warpEnv).toBeLessThanOrEqual(1 + 1e-12);
        /* 方向量全程有界（动量前探不超全速） */
        expect(Math.abs(e.dirW)).toBeLessThanOrEqual(1 + 1e-9);
        if (crossRate === null && prevDir < 0 && e.dirW >= 0) {
          crossRate = (e.dirW - prevDir) / FRAME;
        }
        prevDir = e.dirW;
      }
      /* 换向为运动穿过零点（速率下限 — 与驻停形态区分） */
      expect(crossRate).not.toBeNull();
      expect(crossRate as number).toBeGreaterThanOrEqual(0.05);
      expect(minE).toBeGreaterThanOrEqual(e0 - 1e-9);
      /* 峰驻末端：强度与方向同步抵达 1（页面交接锚点） */
      expect(e.warpEnv).toBeCloseTo(1, 4);
      expect(e.dirW).toBeCloseTo(1, 4);
      /* 消散段归零 */
      advance(e, 1.9);
      expect(Math.abs(e.warpEnv)).toBeLessThan(1e-6);
      expect(Math.abs(e.dirW)).toBeLessThan(1e-6);
    });

    it("换向穿越为瞬态：贴零窗口远短于驻停（无停顿感）", () => {
      for (const ti of REVERSAL_TIMES) {
        const e = makeInterruptedAt(ti);
        let longest = 0;
        let current = 0;
        const steps = Math.round(3.1 / FRAME);
        for (let i = 0; i < steps; i++) {
          e.update(FRAME, FRAME);
          if (Math.abs(e.dirW) <= 0.05) {
            current += FRAME;
            longest = Math.max(longest, current);
          } else {
            current = 0;
          }
        }
        expect(longest).toBeLessThanOrEqual(0.2);
      }
    });

    it("换向接缝一阶连续（动量匹配）：点击瞬间方向速率不跳变", () => {
      for (const ti of [0.9, 1.5, 2.2]) {
        const e = new TransitionEngine();
        advance(e, ti - FRAME);
        const d0 = e.dirW;
        e.update(FRAME, FRAME);
        const d1 = e.dirW;
        const inSlope = (d1 - d0) / FRAME;
        e.triggerEnter();
        e.update(FRAME, FRAME);
        const outSlope = (e.dirW - d1) / FRAME;
        expect(Math.abs(outSlope - inSlope)).toBeLessThanOrEqual(0.12);
      }
    });
  });

  it("正渡幂等：进行中重复触发不重置序列", () => {
    const e = new TransitionEngine();
    advance(e, 1);
    e.triggerEnter();
    advance(e, 2);
    const envBefore = e.warpEnv;
    e.triggerEnter(); // 重复触发 — 忽略
    e.update(FRAME, FRAME);
    expect(e.warpEnv).toBeGreaterThan(envBefore - 1e-9);
    expect(e.warpEnv).toBeGreaterThan(0.5); // 未被重置回起点
  });

  it("自然路径回归：逆渡完成后的正渡与标准剖面逐点一致", () => {
    const e = new TransitionEngine();
    advance(e, 3.2); // 逆渡自然完成（无打断）
    e.triggerEnter();
    for (let i = 0; i < 200; i++) {
      e.update(FRAME, FRAME);
      const x = ((i + 1) * FRAME) / 5;
      expect(e.warpEnv).toBeCloseTo(refEnvelope(x), 8);
      expect(e.dirW).toBeCloseTo(refEnvelope(x), 8);
    }
  });

  it("无障碍门控：减少动态偏好下逆渡跳过、正渡停用", () => {
    const e = new TransitionEngine();
    e.setReducedMotion(true);
    advance(e, 3);
    expect(e.warpEnv).toBe(0);
    expect(e.dirW).toBe(0);
    expect(e.swirl).toBe(0);
    e.triggerEnter(); // 被拒绝（无大幅运动）
    advance(e, 5);
    expect(e.warpEnv).toBe(0);
    expect(e.dirW).toBe(0);
    /* 关闭后正渡恢复自然路径（逆渡不重放） */
    e.setReducedMotion(false);
    e.triggerEnter();
    advance(e, 1);
    expect(e.warpEnv).toBeGreaterThan(0);
  });

  it("积分历史环形覆盖：早于最早保留样本 → 0", () => {
    const e = makeEntering();
    const records = pushFrames(e, 80, 0.1, 0.05);
    /* 容量 64 → 最旧保留样本为 records[16]；更早时刻查询为 0 */
    expect(e.swirlAt(records[0].t)).toBe(0);
    expect(e.swirlAt(records[15].t)).toBe(0);
    /* 边界含等号：恰为最旧样本时刻同样返回 0 */
    expect(e.swirlAt(records[16].t)).toBe(0);
  });

  it("晚于最新样本 → 最新值（历史钳到尾部）", () => {
    const e = makeEntering();
    const records = pushFrames(e, 80, 0.1, 0.05);
    const last = records[records.length - 1];
    expect(e.swirlAt(1e9)).toBeCloseTo(last.v, 5);
  });

  it("二分插值：相邻样本中点 = 线性插值", () => {
    const e = makeEntering();
    const records = pushFrames(e, 80, 0.1, 0.05);
    const i = 40; // 保留窗口内相邻样本对
    const tMid = (records[i].t + records[i + 1].t) / 2;
    const expected =
      records[i].v +
      ((records[i + 1].v - records[i].v) * (tMid - records[i].t)) /
        (records[i + 1].t - records[i].t);
    expect(e.swirlAt(tMid)).toBeCloseTo(expected, 3);
  });

  it("样本时刻精确命中：返回被命中样本自身值（插值系数 ≈ 0）", () => {
    const e = makeEntering();
    const records = pushFrames(e, 80, 0.1, 0.05);
    const i = 50; // 保留窗口中部
    expect(e.swirlAt(records[i].t)).toBeCloseTo(records[i].v, 3);
  });
});