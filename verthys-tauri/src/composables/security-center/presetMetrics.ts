/**
 * presetMetrics.ts — 安全防护面板指标合成纯函数
 *
 * 职责：
 *   面板三个百分比（CPU 开销 / 安全覆盖 / 综合评分）的真实数据合成层。
 *   输入全部来自真实来源（后端系统采样、后端权威配置快照、防御闭环
 *   运行时报告），不包含任何随滑块位置摆动的模拟公式；纯函数可单测。
 *
 * 合成口径：
 *   - 安全覆盖 = 0.55 × 已启用特性占比 + 0.45 × 防御路径加权得分
 *     · 分母恒为全部攻击路径数（7）：未校验路径不得从分母消失，
 *       否则「仅校验 1 条且已阻断」与「7 条全阻断」同得满分；
 *     · 单路径权重：已阻断 = 1、降级 = 0.5、失败/未校验 = 0；
 *     · 全部未校验时防御份额不参与合成（仅按特性占比），避免开场即 0 分；
 *   - 综合评分 = 0.6 × 覆盖率 + 0.4 × (100 − CPU 负载)，0~100 钳制。
 */

/** 覆盖度合成输入（全部为真实信号） */
export interface CoverageInputs {
  /** 当前档位已启用特性数（后端配置快照） */
  enabledCount: number;
  /** 特性全集数 */
  totalCount: number;
  /** 防御闭环：已阻断路径数 */
  blocked: number;
  /** 防御闭环：降级路径数 */
  degraded: number;
  /** 防御闭环：失败路径数 */
  failed: number;
}

/** 防御路径总数（与 useDefenseStatus 的 7 条路径定义、C 层枚举镜像） */
export const DEFENSE_PATH_TOTAL = 7;
/** 覆盖度合成权重：特性占比份额 */
export const COVERAGE_FEATURE_WEIGHT = 0.55;
/** 覆盖度合成权重：防御路径份额 */
export const COVERAGE_DEFENSE_WEIGHT = 0.45;
/** 降级路径在防御得分中的折算权重（部分防护有效） */
export const DEGRADED_PATH_WEIGHT = 0.5;
/** 综合评分权重：覆盖率份额 */
export const OVERALL_COVERAGE_WEIGHT = 0.6;
/** 综合评分权重：低负载份额 */
export const OVERALL_LOAD_WEIGHT = 0.4;

/**
 * 合成安全覆盖度百分比（0~100 整数）
 * @param inp 真实信号输入
 */
export function computeSecurityCoverage(inp: CoverageInputs): number {
  const total = Math.max(inp.totalCount, 1);
  const featureRatio = Math.max(0, Math.min(1, inp.enabledCount / total));
  const checked = inp.blocked + inp.degraded + inp.failed;
  let pct: number;
  if (checked > 0) {
    // 加权得分 / 全部路径数：未校验路径留在分母中（不得因未检测而满分）
    const defenseScore =
      inp.blocked + inp.degraded * DEGRADED_PATH_WEIGHT;
    const defenseRatio = Math.max(
      0,
      Math.min(1, defenseScore / DEFENSE_PATH_TOTAL),
    );
    pct =
      (featureRatio * COVERAGE_FEATURE_WEIGHT +
        defenseRatio * COVERAGE_DEFENSE_WEIGHT) *
      100;
  } else {
    pct = featureRatio * 100;
  }
  return Math.round(Math.max(0, Math.min(100, pct)));
}

/**
 * 合成综合评分（0~100 整数）
 * @param coverage 安全覆盖度
 * @param cpuUsage CPU 占用率（-1 = 无基线，按 50 中性负载计）
 */
export function computeOverallScore(coverage: number, cpuUsage: number): number {
  const load = cpuUsage >= 0 ? cpuUsage : 50;
  const pct =
    coverage * OVERALL_COVERAGE_WEIGHT + (100 - load) * OVERALL_LOAD_WEIGHT;
  return Math.round(Math.max(0, Math.min(100, pct)));
}