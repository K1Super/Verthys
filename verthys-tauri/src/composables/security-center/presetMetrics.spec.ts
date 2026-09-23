/**
 * presetMetrics.spec.ts — 安全防护面板指标合成纯函数测试
 *
 * 覆盖：覆盖度双权重合成、防御无校验结果的特性兜底、综合评分
 * 双权重合成、CPU 无基线中性负载、0~100 钳制。
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

  it("特性占比与防御占比双权重合成（部分启用 + 全防御）", () => {
    // featureRatio = 7/12 ≈ 0.5833；defenseRatio = 1
    // (0.5833×0.55 + 1×0.45)×100 = 77.08 → 77
    expect(
      computeSecurityCoverage({
        enabledCount: 7,
        totalCount: 12,
        blocked: 6,
        degraded: 1,
        failed: 0,
      }),
    ).toBe(77);
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

  it("防御存在失败路径 → 防御占比按已防御折算", () => {
    // featureRatio = 1；defenseRatio = (5+1)/7 ≈ 0.8571
    // (0.55 + 0.8571×0.45)×100 = 93.57 → 94
    expect(
      computeSecurityCoverage({
        enabledCount: 12,
        totalCount: 12,
        blocked: 5,
        degraded: 1,
        failed: 1,
      }),
    ).toBe(94);
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