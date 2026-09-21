/**
 * useTransitionEngine.spec.ts — 方向性渡越序列引擎确定性单元测试
 *
 * 直接调用 update(frameStep, wallStep) 显式推帧，不依赖真实帧调度。
 * 覆盖：双时间参数语义（wallStep 推进时钟与包络 / frameStep 仅推进
 * 物理积分）、积分历史环形覆盖（64 样本上限，早于最早 → 0、
 * 晚于最新 → 最新值）、二分线性插值精确性。
 */
import { describe, it, expect } from "vitest";
import { TransitionEngine } from "./useTransitionEngine";

/** 新建已点击进入的引擎（intro 于 0 时刻被打断 → 幅度恒 0，dirW = enterEnv ≥ 0） */
function makeEntering(): TransitionEngine {
  const e = new TransitionEngine();
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

describe("TransitionEngine", () => {
  it("双时间参数语义：wallStep 推进时钟，frameStep 只推进积分", () => {
    const a = makeEntering();
    const b = makeEntering();
    a.update(0.2, 0.5);
    b.update(0.4, 0.5);
    expect(a.time).toBe(0.5);
    expect(b.time).toBe(0.5);
    expect(b.swirl).toBeCloseTo(a.swirl * 2, 10);
    expect(b.warpDist).toBeCloseTo(a.warpDist * 2, 10);
  });

  it("时钟只吃 wallStep：frameStep 变化不影响包络进度", () => {
    const a = makeEntering();
    const b = makeEntering();
    a.update(1.0, 0.25);
    b.update(0.001, 0.25);
    expect(a.time).toBe(0.25);
    expect(b.time).toBe(0.25);
    expect(a.warpEnv).toBeCloseTo(b.warpEnv, 12);
    expect(a.swirl).not.toBe(b.swirl);
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