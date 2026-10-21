/**
 * presetMetrics.spec.ts — 安全防护面板指标合成纯函数测试
 *
 * 覆盖：覆盖度双权重合成、防御无校验结果的特性兜底、综合评分
 * 双权重合成、CPU 无基线中性负载、0~100 钳制。
 * 口径：防御得分分母恒为全部 7 条路径（未校验计入分母），
 *       单路径权重 已阻断=1 / 降级=0.5 / 失败=0。
 */
import { describe, it, expect } from "vitest";
import {
  computeSecurityCoverage,
  computeOverallScore,
} from "./presetMetrics";

describe("computeSecurityCoverage", () => {
  it("全特性启用 + 全路径已防御 → 100", () => {
    expect(
      computeSecurityCoverage({
        enabledCount: 12,
        totalCount: 12,
        blocked: 7,
        degraded: 0,
        failed: 0,
      }),
    ).toBe(100);
  });

  it("特性占比与防御加权得分双权重合成（部分启用 + 6 阻断 1 降级）", () => {
    // featureRatio = 7/12 ≈ 0.5833
    // defenseScore = 6×1 + 1×0.5 = 6.5；/7 ≈ 0.9286（分母恒为 7）
    // (0.5833×0.55 + 0.9286×0.45)×100 ≈ 73.87 → 74
    expect(
      computeSecurityCoverage({
        enabledCount: 7,
        totalCount: 12,
        blocked: 6,
        degraded: 1,
        failed: 0,
      }),
    ).toBe(74);
  });

  it("防御路径尚无校验结果 → 仅按特性占比（不虚假压低）", () => {
    // 10/12 ≈ 0.8333 → 83
    expect(
      computeSecurityCoverage({
        enabledCount: 10,
        totalCount: 12,
        blocked: 0,
        degraded: 0,
        failed: 0,
      }),
    ).toBe(83);
  });

  it("防御存在失败路径 → 降级折算 0.5、失败计 0", () => {
    // featureRatio = 1；defenseScore = 5 + 1×0.5 = 5.5；/7 ≈ 0.7857
    // (0.55 + 0.7857×0.45)×100 ≈ 90.36 → 90
    expect(
      computeSecurityCoverage({
        enabledCount: 12,
        totalCount: 12,
        blocked: 5,
        degraded: 1,
        failed: 1,
      }),
    ).toBe(90);
  });

  it("仅校验 1 条且已阻断 → 未校验路径留在分母，不得满分", () => {
    // featureRatio = 1；defenseScore = 1；/7 ≈ 0.1429
    // (0.55 + 0.1429×0.45)×100 ≈ 61.43 → 61
    expect(
      computeSecurityCoverage({
        enabledCount: 12,
        totalCount: 12,
        blocked: 1,
        degraded: 0,
        failed: 0,
      }),
    ).toBe(61);
  });
});

describe("computeOverallScore", () => {
  it("覆盖率与负载双权重合成", () => {
    // 80×0.6 + (100−30)×0.4 = 48 + 28 = 76
    expect(computeOverallScore(80, 30)).toBe(76);
  });

  it("CPU 无基线按中性负载 50 计", () => {
    // 80×0.6 + 50×0.4 = 48 + 20 = 68
    expect(computeOverallScore(80, -1)).toBe(68);
  });

  it("极端输入钳制在 0~100", () => {
    expect(computeOverallScore(0, 100)).toBe(0);
    // 100×0.6 + 50×0.4 = 80
    expect(computeOverallScore(100, -1)).toBe(80);
  });
});