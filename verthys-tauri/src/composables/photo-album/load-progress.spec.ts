/**
 * photo-album/load-progress.spec.ts — 加载进度信号层契约测试
 *
 * 锁定三条不变式：
 *   1. 阶段百分比只取真实节点：分母不可得时停在区间起点（不伪造完成度）；
 *   2. 计数到位才推进，done≥total 才触及阶段上限；
 *   3. 单调闸门拦住回退与异常输入（NaN/负值/越界）。
 */
import { describe, it, expect } from "vitest";
import {
  stageStartPercent,
  stagePercent,
  monotonicPercent,
  STAGE_RANGES,
} from "./load-progress";

describe("stageStartPercent", () => {
  it("阶段起点取自区间定义，完成态为 100，空闲/取消为 0", () => {
    expect(stageStartPercent("index")).toBe(STAGE_RANGES.index[0]);
    expect(stageStartPercent("records")).toBe(STAGE_RANGES.records[0]);
    expect(stageStartPercent("decrypt")).toBe(STAGE_RANGES.decrypt[0]);
    expect(stageStartPercent("done")).toBe(100);
    expect(stageStartPercent("idle")).toBe(0);
    expect(stageStartPercent("cancelled")).toBe(0);
  });
});

describe("stagePercent", () => {
  it("分母不可得时停在阶段起点，不猜完成度", () => {
    expect(stagePercent("records", 120, 0)).toBe(STAGE_RANGES.records[0]);
    expect(stagePercent("records", 120, -5)).toBe(STAGE_RANGES.records[0]);
    expect(stagePercent("records", 120, Number.NaN)).toBe(STAGE_RANGES.records[0]);
  });

  it("真实计数按比例推进，且只有 done≥total 才触及上限", () => {
    const [lo, hi] = STAGE_RANGES.records;
    expect(stagePercent("records", 0, 400)).toBe(lo);
    expect(stagePercent("records", 200, 400)).toBe(Math.floor(lo + (hi - lo) * 0.5));
    expect(stagePercent("records", 399, 400)).toBeLessThan(hi);
    expect(stagePercent("records", 400, 400)).toBe(hi);
    expect(stagePercent("records", 800, 400)).toBe(hi);
  });

  it("解密阶段区间与完成态", () => {
    const [lo, hi] = STAGE_RANGES.decrypt;
    expect(stagePercent("decrypt", 3, 12)).toBe(Math.floor(lo + (hi - lo) * 0.25));
    expect(stagePercent("done", 0, 0)).toBe(100);
  });
});

describe("monotonicPercent", () => {
  it("值只前进不后退", () => {
    expect(monotonicPercent(40, 30)).toBe(40);
    expect(monotonicPercent(40, 55)).toBe(55);
  });

  it("异常输入被收束到 0..100 且不破坏既有进度", () => {
    expect(monotonicPercent(0, Number.NaN)).toBe(0);
    expect(monotonicPercent(30, Number.NaN)).toBe(30);
    expect(monotonicPercent(30, -10)).toBe(30);
    expect(monotonicPercent(30, 250)).toBe(100);
    expect(monotonicPercent(Number.NaN, 12)).toBe(12);
  });
});