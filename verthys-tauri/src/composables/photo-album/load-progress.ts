/**
 * photo-album/load-progress.ts — 照片加载进度信号层（纯函数，可单测）
 *
 * 职责：把"阶段 + 真实计数"映射为进度百分比，并提供单调闸门。
 *
 * 设计约束（进度条规范）：
 * - 阶段百分比只在真实节点上取值：进入阶段取区间起点，计数到位才在区间内
 *   按 done/total 推进，不再猜完成度；
 * - 分母不可得（total ≤ 0 或非有限值）时停在区间起点，由文案承担"仍在推进"
 *   的反馈，禁止用估算值伪装完成度；
 * - 表现层只消费单调不减的值（回退跳变会让用户误判"重来一遍"）。
 */

/** 加载阶段：索引扫描 → 记录扫描（回退路径）→ 可视区解密 → 完成/取消 */
export type PhotoLoadStage = "idle" | "index" | "records" | "decrypt" | "done" | "cancelled";

/**
 * 各阶段百分比区间 [起点, 上限]。
 *
 * Why 留上界：阶段完成才允许进入下一区间，避免"索引刚完就 90%"造成的
 * 前快后慢观感；解密阶段覆盖多数耗时，故区间跨度最大。
 */
export const STAGE_RANGES: Readonly<Record<Exclude<PhotoLoadStage, "idle" | "done" | "cancelled">, readonly [number, number]>> = {
  index: [8, 40],
  records: [8, 40],
  decrypt: [45, 95],
};

/** 阶段起点百分比（进入阶段即显示，不伪装成 0%） */
export function stageStartPercent(stage: PhotoLoadStage): number {
  if (stage === "done") return 100;
  if (stage === "cancelled" || stage === "idle") return 0;
  return STAGE_RANGES[stage][0];
}

/**
 * 阶段内按真实完成度插值。
 *
 * @param stage 当前阶段
 * @param done 已完成计数（真实值：已装载条数 / 已解密张数）
 * @param total 阶段总量（真实值；≤0 或非有限表示分母不可得）
 * @returns 阶段区间内的百分比（取整向下，只有 done≥total 才触及上限）
 */
export function stagePercent(stage: PhotoLoadStage, done: number, total: number): number {
  if (stage === "done") return 100;
  if (stage === "cancelled" || stage === "idle") return 0;
  const [lo, hi] = STAGE_RANGES[stage];
  if (!Number.isFinite(done) || !Number.isFinite(total) || total <= 0) return lo;
  const ratio = Math.min(1, Math.max(0, done / total));
  return Math.floor(lo + (hi - lo) * ratio);
}

/** 单调闸门：值只前进不后退，并收束到 0..100（上游异常输入不造成视觉溢出） */
export function monotonicPercent(prev: number, next: number): number {
  const p = Number.isFinite(prev) ? Math.min(100, Math.max(0, prev)) : 0;
  const n = Number.isFinite(next) ? Math.min(100, Math.max(0, next)) : p;
  return Math.max(p, n);
}