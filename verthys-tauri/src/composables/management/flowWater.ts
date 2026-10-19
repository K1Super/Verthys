/**
 * flowWater.ts — 「光水」流光带渲染（单一权威）
 *
 * 用途：把既有的能量路径升级为可读的「流动」——
 *   中枢量子面板的中心→模块节点连线在进入下一界面前以水状流光自中心流向
 *   拾光/清藏/存签三节点，随后整体淡出，再由视图过渡接管。
 *
 * 职责边界：
 *   - 纯 Canvas 几何与描绘：零 Vue、零 DOM 查询、零定时器。时间与进度由
 *     调用方的仪式状态机（见 management/packetRitual）供给；
 *   - 路径由调用方按等参数步长采样后传入（xs/ys 等长缓冲），本模块不采样、
 *     不持有路径所有权；
 *   - 只描绘装饰图层，不承载任何文字（文字清晰度铁律：承载文字的层不得参与
 *     位移/缩放/滤波，见 styles/text_sharpness.spec.ts）。
 *
 * 视觉构造（三层复合，全部由相位数学产生；除前缘光点外无贴图）：
 *   1. 水带外缘：沿路径的锥形柔光带（头部宽、尾迹收窄），带宽受沿程正弦涟漪
 *      调制（逐链频率与相位互异 → 三条水带不同步，无机械感）；
 *      沿程亮度为单一线性渐变（尾端透明 → 前缘最亮）—— 无分块阶梯、无块间
 *      接缝、尾端不截断；整体浓度由调用方的 fade 经 globalAlpha 承担；
 *   2. 内芯高亮：沿同一路径的等宽细亮线，亮度取向与外缘同源；
 *   3. 前缘光点：行进头部的光斑（复用调用方预渲染的光点贴图）。
 *   水带折线按路径自身采样密度取样 → 与连线折线同阶精度，
 *   不因二次重采样在带缘引入额外角点。
 */

/** 水带样式（逐链差化的常量，由调用方预分配，本模块只读） */
export interface WaterStyle {
  /** 外缘柔光色前缀（形如 'rgba(0,212,255,'；alpha 由本模块追加） */
  readonly edge: string;
  /** 内芯高亮色前缀 */
  readonly core: string;
  /** 前缘最大半宽（px） */
  readonly halfW: number;
  /** 尾迹长度（路径比例 0..1） */
  readonly trail: number;
  /** 沿程涟漪周期数与相位（逐链互异 → 水带不同步） */
  readonly ripples: number;
  readonly phase: number;
}

/** 调用方采样缓冲容量上限（超出即按此截断） */
export const WATER_MAX_POINTS = 128;

/** 尾迹采样段上限（几何精度与绘制成本的平衡点） */
const SEG_MAX = 48;

/* ---------- 沿程亮度包络（定值 — 整体浓度由 globalAlpha 承担） ----------
 * [停靠位置, alpha]：尾端 alpha=0 使尾迹自行消散（原实现尾端 30% 硬切，
 * 读作「一段被截断的实体」）；前缘取满值，形成可读的流动方向。
 * 停靠点是沿程形状的单一权威：中庸段偏亮（保持水面体量），仅尾端消散。 */
const EDGE_RAMP: readonly (readonly [number, number])[] = [
  [0, 0], [0.22, 0.14], [0.6, 0.3], [1, 0.5],
];
const CORE_RAMP: readonly (readonly [number, number])[] = [
  [0, 0], [0.25, 0.4], [1, 0.9],
];

/* 每帧复用的几何缓冲（模块级单例：同帧内多链串行描绘，无并发） */
const bandX = new Float64Array(SEG_MAX + 1);
const bandY = new Float64Array(SEG_MAX + 1);
const nrmX = new Float64Array(SEG_MAX + 1);
const nrmY = new Float64Array(SEG_MAX + 1);
const headPt = new Float64Array(2);

/**
 * 水带半宽（几何法，可独立验证）。
 *
 * @param u 尾迹内归一化位置：0 = 尾端，1 = 前缘
 * @returns 半宽（px）＝ 前缘最大半宽 × 锥形收缩 × 涟漪调制
 */
export function waterHalfWidth(u: number, style: WaterStyle): number {
  const t = u < 0 ? 0 : u > 1 ? 1 : u;
  /* 锥形：前缘满宽、尾端收至 32%（指数 <1 → 收缩集中在尾部，主体保持饱满） */
  const taper = 0.32 + 0.68 * Math.pow(t, 0.7);
  /* 涟漪：沿程正弦调制，逐链相位/周期互异 */
  const ripple = 1 + 0.28 * Math.sin((t * style.ripples + style.phase) * Math.PI * 2);
  return style.halfW * taper * ripple;
}

/** 从采样缓冲按路径比例 s（0..1）线性取点 */
function sampleAt(
  xs: Float64Array, ys: Float64Array, len: number, s: number, out: Float64Array,
): void {
  const f = s * (len - 1);
  const i0 = f <= 0 ? 0 : Math.min(len - 2, Math.floor(f));
  const t = f - i0;
  out[0] = xs[i0] + (xs[i0 + 1] - xs[i0]) * t;
  out[1] = ys[i0] + (ys[i0 + 1] - ys[i0]) * t;
}

/**
 * 描绘行进中的水带。
 *
 * 调用方契约：
 *   - 进入前须已置 `globalCompositeOperation = 'lighter'`；
 *   - fade ≤ 0 或 head ≤ 0 时不绘制（淡出完成/未启动）；
 *   - 本函数自行管理 `globalAlpha`，返回前复位为 1。
 *
 * 单次填充 + 单次描边（不做逐块描绘）：沿程亮度由一条线性渐变连续给出 ——
 * 亮度无阶梯、块间无接缝；逐帧色串构建仅存在于本函数（≤1.02s 的仪式窗口内），
 * 且只为渐变停靠点拼定有限条字符串。
 *
 * @param xs / ys 路径采样（等参数步长，长度 ≥ 2）
 * @param len 有效采样点数
 * @param head 前缘位置（0..1 — 由调用方缓动后传入，到达环沿即 1）
 * @param fade 整体浓度（0..1 — 由调用方推进至 0 即完成淡出）
 * @param sprite 前缘光点贴图（可为 null — 则不绘前缘光点）
 */
export function drawWaterFlow(
  ctx: CanvasRenderingContext2D,
  xs: Float64Array, ys: Float64Array, len: number,
  head: number, fade: number, style: WaterStyle, sprite: HTMLCanvasElement | null,
): void {
  if (len < 2 || head <= 0 || fade <= 0.01) return;

  const h = head > 1 ? 1 : head;
  const tail = h - style.trail > 0 ? h - style.trail : 0;
  const span = h - tail;
  if (span <= 1e-4) return;

  /* ---- 尾迹采样：位置 + 单位法线（中心差分切线，端点退化处取相邻差分）。
     段数按「尾迹跨越的路径采样数」取 → 与路径折线同阶精度 ---- */
  const segs = Math.min(SEG_MAX, Math.max(3, Math.ceil(span * (len - 1)) + 2));
  for (let j = 0; j <= segs; j++) {
    sampleAt(xs, ys, len, tail + (span * j) / segs, headPt);
    bandX[j] = headPt[0];
    bandY[j] = headPt[1];
  }
  for (let j = 0; j <= segs; j++) {
    const a = j > 0 ? j - 1 : 0;
    const b = j < segs ? j + 1 : segs;
    const dx = bandX[b] - bandX[a];
    const dy = bandY[b] - bandY[a];
    const l = Math.sqrt(dx * dx + dy * dy) || 1;
    nrmX[j] = -dy / l;
    nrmY[j] = dx / l;
  }

  /* ---- 沿程亮度：单一线性渐变（尾→头）。
     路径为二次贝塞尔，尾—头弦内的曲率垂距远小于带长（同量级偏差 <4%，
     不可见），故以弦向渐变近似沿程亮度 —— 换来真正连续的包络：原分块实现
     在块边界读作「阶梯」，尾端读作「截断」。整体浓度由 globalAlpha 承担，
     故逐帧只乘一个标量，不做逐块色串拼接 ---- */
  ctx.globalAlpha = fade;
  const x0 = bandX[0];
  const y0 = bandY[0];
  const x1 = bandX[segs];
  const y1 = bandY[segs];

  const edgeGrad = ctx.createLinearGradient(x0, y0, x1, y1);
  for (let k = 0; k < EDGE_RAMP.length; k++) {
    const stop = EDGE_RAMP[k];
    edgeGrad.addColorStop(stop[0], `${style.edge}${stop[1]})`);
  }

  /* 外缘水带（闭合填充：左缘正向 + 右缘反向 —— 单次 fill，无逐段描边开销） */
  ctx.beginPath();
  for (let j = 0; j <= segs; j++) {
    const w = waterHalfWidth(j / segs, style);
    const x = bandX[j] + nrmX[j] * w;
    const y = bandY[j] + nrmY[j] * w;
    if (j === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  for (let j = segs; j >= 0; j--) {
    const w = waterHalfWidth(j / segs, style);
    ctx.lineTo(bandX[j] - nrmX[j] * w, bandY[j] - nrmY[j] * w);
  }
  ctx.closePath();
  ctx.fillStyle = edgeGrad;
  ctx.fill();

  /* 内芯高亮：沿同一中心线等宽描边（宽度不再随块跳变 —— 原逐块常量线宽
     在块边界读作「结节」），亮度取向与水带同源 */
  const coreGrad = ctx.createLinearGradient(x0, y0, x1, y1);
  for (let k = 0; k < CORE_RAMP.length; k++) {
    const stop = CORE_RAMP[k];
    coreGrad.addColorStop(stop[0], `${style.core}${stop[1]})`);
  }
  ctx.beginPath();
  for (let j = 0; j <= segs; j++) {
    if (j === 0) ctx.moveTo(bandX[j], bandY[j]);
    else ctx.lineTo(bandX[j], bandY[j]);
  }
  ctx.lineWidth = Math.max(0.9, style.halfW * 0.42);
  ctx.strokeStyle = coreGrad;
  ctx.stroke();

  /* ---- 前缘光点：行进头部。
     亮度沉降先于水带（fade ≤ 0.18 起不再描绘）—— 淡出期由「亮点先散、
     水带余韵后收」构成溶解次序，离场画面不留亮斑 ---- */
  if (sprite && fade > 0.18) {
    sampleAt(xs, ys, len, h, headPt);
    const size = style.halfW * 2.8 * (0.6 + 0.4 * fade);
    ctx.globalAlpha = Math.min(1, fade * 0.95);
    ctx.drawImage(sprite, headPt[0] - size / 2, headPt[1] - size / 2, size, size);
  }
  ctx.globalAlpha = 1;
}
