/*
 * flowWater.spec.ts — 「光水」渲染契约守卫
 *
 * 覆盖三条调用方赖以成立的契约：
 *   1. 半宽几何：锥形单调（前缘满宽、尾端收窄）+ 涟漪有界 → 水带不翻边、
 *      不出现负宽；
 *   2. 淡出/未启动即零描绘：fade≤0 或 head≤0 时不得触碰上下文（视图切换前
 *      的「淡出完成」语义依赖此条，残留绘制会让离场画面留痕）；
 *   3. 描绘坐标恒为有限值，且沿程亮度由单一线性渐变连续给出（单次填充 +
 *      单次描边、停靠点 alpha 单调 —— 无分块阶梯与块间接缝；NaN 会静默
 *      吞掉整帧 Canvas 绘制）。
 *
 * 用极简 2D 上下文替身记录调用，不引入 canvas 依赖（本文件为纯几何单元）。
 */
import { describe, it, expect } from "vitest";
import { drawWaterFlow, waterHalfWidth, WATER_MAX_POINTS, type WaterStyle } from "./flowWater";

/** 基准样式：涟漪关闭（ripples = 0 → 调制恒为 1），便于单独验证锥形 */
const plain: WaterStyle = {
  edge: "rgba(0,212,255,", core: "rgba(214,255,252,",
  halfW: 6, trail: 0.34, ripples: 0, phase: 0,
};
/** 基准样式：带涟漪 */
const rippled: WaterStyle = { ...plain, ripples: 2.4, phase: 0.31 };

/** 极简 2D 上下文替身：记录调用、数值参数与渐变停靠点 */
function makeCtx() {
  const calls: { op: string; args: number[] }[] = [];
  const stops: { offset: number; color: string }[] = [];
  const rec = (op: string) => (...args: unknown[]): void => {
    calls.push({ op, args: args.filter((a): a is number => typeof a === "number") });
  };
  const gradient = {
    addColorStop: (offset: number, color: string): void => {
      stops.push({ offset, color });
    },
  };
  const raw = {
    beginPath: rec("beginPath"),
    moveTo: rec("moveTo"),
    lineTo: rec("lineTo"),
    closePath: rec("closePath"),
    fill: rec("fill"),
    stroke: rec("stroke"),
    drawImage: rec("drawImage"),
    createLinearGradient: (...args: number[]) => {
      calls.push({ op: "createLinearGradient", args });
      return gradient;
    },
    fillStyle: "",
    strokeStyle: "",
    lineWidth: 0,
    globalAlpha: 1,
  };
  return { ctx: raw as unknown as CanvasRenderingContext2D, calls, raw, stops };
}

/** 直线路径采样（等参数步长） */
function straightPath(len = WATER_MAX_POINTS) {
  const xs = new Float64Array(len);
  const ys = new Float64Array(len);
  for (let i = 0; i < len; i++) {
    xs[i] = (i / (len - 1)) * 240 + 40;
    ys[i] = 80;
  }
  return { xs, ys };
}

describe("waterHalfWidth 半宽几何", () => {
  it("锥形单调：尾端 32% 满宽 → 前缘满宽", () => {
    expect(waterHalfWidth(0, plain)).toBeCloseTo(plain.halfW * 0.32, 6);
    expect(waterHalfWidth(1, plain)).toBeCloseTo(plain.halfW, 6);
    let previous = waterHalfWidth(0, plain);
    for (const u of [0.15, 0.3, 0.5, 0.75, 1]) {
      const w = waterHalfWidth(u, plain);
      expect(w).toBeGreaterThanOrEqual(previous);
      previous = w;
    }
  });

  it("涟漪有界：恒为正且不超过 ±28% 调制", () => {
    for (let i = 0; i <= 40; i++) {
      const u = i / 40;
      const taper = 0.32 + 0.68 * Math.pow(u, 0.7);
      const w = waterHalfWidth(u, rippled);
      expect(w).toBeGreaterThan(0);
      expect(Math.abs(w / (rippled.halfW * taper) - 1)).toBeLessThanOrEqual(0.2801);
    }
  });

  it("越界 u 按端点夹紧（调用方不给非法位置留隐患）", () => {
    expect(waterHalfWidth(-2, plain)).toBe(waterHalfWidth(0, plain));
    expect(waterHalfWidth(3, plain)).toBe(waterHalfWidth(1, plain));
  });
});

describe("drawWaterFlow 描绘契约", () => {
  const { xs, ys } = straightPath();

  it("未启动（head ≤ 0）或淡出完成（fade 低于收敛阈值）时零描绘", () => {
    const a = makeCtx();
    drawWaterFlow(a.ctx, xs, ys, xs.length, 0, 1, plain, null);
    expect(a.calls).toHaveLength(0);

    const b = makeCtx();
    drawWaterFlow(b.ctx, xs, ys, xs.length, 1, 0, plain, null);
    expect(b.calls).toHaveLength(0);

    /* 收敛阈值 0.01：低于此浓度不再触碰上下文（淡出尾端的无效绘制消除） */
    const c = makeCtx();
    drawWaterFlow(c.ctx, xs, ys, xs.length, 1, 0.005, plain, null);
    expect(c.calls).toHaveLength(0);
  });

  it("连续包络：单次填充 + 单次描边，沿程亮度自尾端透明单调升至前缘最亮", () => {
    const { ctx, calls, stops } = makeCtx();
    drawWaterFlow(ctx, xs, ys, xs.length, 0.6, 1, plain, null);

    /* 单次填充 + 单次描边（沿程亮度由一条线性渐变连续给出）：分块描会多次
       切换 fillStyle / lineWidth —— 块边界读作「阶梯」与「结节」，
       尾端 30% 硬切读作「一段被截断的实体」 */
    expect(calls.filter((c) => c.op === "fill")).toHaveLength(1);
    expect(calls.filter((c) => c.op === "stroke")).toHaveLength(1);
    /* 两条渐变：外缘水带 + 内芯高亮（各自的停靠点独立成形） */
    expect(calls.filter((c) => c.op === "createLinearGradient")).toHaveLength(2);

    /* 外缘 4 停靠点 + 内芯 3 停靠点；偏移递增、alpha 单调不减、两端透明起点 */
    const alphaOf = (color: string): number =>
      Number(color.match(/,\s*([\d.]+)\)$/)?.[1] ?? Number.NaN);
    const alphas = stops.map((s) => alphaOf(s.color));
    expect(alphas.every((a) => Number.isFinite(a))).toBe(true);
    const edge = alphas.slice(0, 4);
    const core = alphas.slice(4);
    expect(stops).toHaveLength(7);
    expect(edge[0]).toBe(0);
    expect(core[0]).toBe(0);
    for (let k = 1; k < edge.length; k += 1) expect(edge[k]).toBeGreaterThan(edge[k - 1]);
    for (let k = 1; k < core.length; k += 1) expect(core[k]).toBeGreaterThan(core[k - 1]);
    /* 前缘：内芯亮于外缘（内芯为高光层） */
    expect(core[core.length - 1]).toBeGreaterThan(edge[edge.length - 1]);
    const offsets = stops.map((s) => s.offset);
    for (let k = 1; k < 4; k += 1) expect(offsets[k]).toBeGreaterThan(offsets[k - 1]);
    for (let k = 5; k < 7; k += 1) expect(offsets[k]).toBeGreaterThan(offsets[k - 1]);

    /* 坐标全为有限值（NaN 会静默吞掉整帧 Canvas 绘制） */
    for (const call of calls) {
      for (const value of call.args) expect(Number.isFinite(value)).toBe(true);
    }
  });

  it("前缘光点仅在提供贴图时描绘，且淡出期不残留", () => {
    const without = makeCtx();
    drawWaterFlow(without.ctx, xs, ys, xs.length, 0.6, 1, plain, null);
    expect(without.calls.some((c) => c.op === "drawImage")).toBe(false);

    const withSprite = makeCtx();
    const sprite = { width: 32, height: 32 } as HTMLCanvasElement;
    drawWaterFlow(withSprite.ctx, xs, ys, xs.length, 1, 1, rippled, sprite);
    expect(withSprite.calls.filter((c) => c.op === "drawImage")).toHaveLength(1);
    /* 淡出末期浓度极低时不描绘光点（避免离场画面残留亮斑） */
    const fading = makeCtx();
    drawWaterFlow(fading.ctx, xs, ys, xs.length, 1, 0.05, rippled, sprite);
    expect(fading.calls.some((c) => c.op === "drawImage")).toBe(false);
  });

  it("回归复位 globalAlpha（调用方后续绘制不被污染）", () => {
    const { ctx, raw } = makeCtx();
    const sprite = { width: 32, height: 32 } as HTMLCanvasElement;
    drawWaterFlow(ctx, xs, ys, xs.length, 1, 1, plain, sprite);
    expect(raw.globalAlpha).toBe(1);
  });
});
