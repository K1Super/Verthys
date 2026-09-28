/**
 * useBrandTitle — VERTHYS 品牌字标系统（全局唯一权威源）
 *
 * 设计体系：星轨刻线体（Orbital Engraved Capitals）
 *   VERTHYS 字标为定制字形（非任何字库字），全部数据在此单源定义，
 *   引导页 / 主界面 / 弹窗三级共用同一形态，仅幅度与暴露项分级收敛。
 *
 *   1. 单线几何骨格 — cap = 100，baseline = 100，笔画重量逐级可调；
 *      端切面垂直于笔画（butt）、尖锋/叉口为锐角 miter — 仪器刻度式
 *      切割语言（「刻线」），拒绝圆头软切与等宽模板感。
 *   2. 光门（唯一镂空字）— V 为发丝镂空（1.8），似光绘之门；
 *      其余六字实色主力，构成「一清六实」的克重对比。
 *   3. 枢钥刻槽（keyway）— E/R/T/H/Y/S 各携一刀 21° 半深切痕
 *      （切入笔画一半深度，不切断笔画）：同刃角、异落位，
 *      呼应星盘刻度与锁芯钥匙槽 — 品牌独有形制。
 *   4. 悬锤垂针 — Y 尾针下探至 116.5（越过基线 16.5）：全字唯一
 *      垂坠，如铅锤定中，破除等底排印的板滞。
 *   5. 双层雕刻 — 暗色克隆沿光向（右下）偏移，物理凹刻深度；
 *      非阴影非辉光，零渐变。
 *   6. 单一强调 — 仅 H 取主题强调色的深度化变体（#16c8ea），
 *      其余冰银（#d9e6f2）：拒绝多点亮色泛滥。
 *
 * 反大众化约束（延续并升级旧体系）：
 *   旧体系以确定性 hash 差化「形态」（字号/基线/倾角随机错落）——
 *   形散而近于生硬。本体系改由设计决定形态（字形即定数，零随机），
 *   确定性 hash 仅差化「运动」（入射向量/时序/时长逐字独立）：
 *   设计定形，扰动生于运动 —— 形整而气活。
 *
 * 运动语言（轨道入射 → 引力弹射）：
 *   入射沿上半弧差异化角度 + 距离差化，末段轻度过冲回稳；
 *   弹射离场自外缘先走（引力弹弓语义，仅引导页使用）。
 *   intro 戏剧性 / compact 安静驻留 / mini 近静默 — 三级幅度收敛。
 */

/** 字标级别：intro（引导页）/ compact（主界面）/ mini（弹窗品牌字） */
export type BrandLevel = "intro" | "compact" | "mini";

/** 着色三态：冰银实色 / 唯一强调 / 光门镂空 */
export type BrandTone = "ice" | "accent" | "hollow";

/** 枢钥刻槽落位（字形局部坐标 — 即切痕中心） */
export interface BrandNotch {
  cx: number;
  cy: number;
}

/** 刻槽形制（刃角恒定 21° — 与轨道丝线族同角语言） */
export interface BrandNotchSpec {
  w: number;
  h: number;
  angle: number;
}

/** 单字模型（模板层据此直出 SVG） */
export interface BrandGlyph {
  /** 字键（V/E/R/T/H/Y/S — 亦作遮罩 id 后缀） */
  key: string;
  /** 笔画中心线路径（cap 0-100 坐标系） */
  d: string;
  /** 布局横向偏移（字距为设计值 — 非等距也无 hash 抖动） */
  x: number;
  tone: BrandTone;
  /** 本字刻槽落位（null = 无刻痕：V 光门独清） */
  notch: BrandNotch | null;
  /** 逐字 CSS 变量（入射 / 时序 / 弹射 — 运动差化，非形态差化） */
  style: Record<string, string>;
}

export interface BrandWordmark {
  viewBox: string;
  notch: BrandNotchSpec;
  glyphs: BrandGlyph[];
  /** 入场完成时刻（ms — 末字 delay + dur 与各字最大值）：软离场门控源 */
  doneAt: number;
}

/* ============================================================================
 * 字形库（自绘中心线 — butt 端切面，y 向下，cap 0..100，baseline 100）
 *   端切面即笔画终点（butt）；转角为 miter（V 尖锋 / Y 叉口吃满锐角）；
 *   Y 尾针越过基线至 116.5；S 为双弧 + 三次样条脊线（ogee 中脊）
 * ========================================================================== */
const GLYPHS: Array<{ key: string; d: string; x: number; tone: BrandTone; notch: BrandNotch | null }> = [
  {
    key: "V",
    /* 尖锋至 86.5 + miter 延伸 ≈ 100.6（基线对齐）— 光门镂空字 */
    d: "M4.25 1.48 L33 86.5 L61.75 1.48",
    x: 0,
    tone: "hollow",
    notch: null,
  },
  {
    key: "E",
    /* 中臂短于上下臂 8.5 — 经典克重收束 */
    d: "M63 4.5 H4.5 V95.5 H63 M4.5 50 H54.5",
    x: 86.8,
    tone: "ice",
    notch: { cx: 9, cy: 27 },
  },
  {
    key: "R",
    /* 几何圆腹（r 25.5）+ 直腿（55°）下落至基线 */
    d: "M0 4.5 H31 A25.5 25.5 0 0 1 31 55.5 H0 M4.5 0 V100 M31 55.5 L60.3 97.4",
    x: 174.8,
    tone: "ice",
    notch: { cx: 9, cy: 72 },
  },
  {
    key: "T",
    d: "M0 4.5 H55 M27.5 0 V100",
    x: 264.4,
    tone: "ice",
    notch: { cx: 23, cy: 66 },
  },
  {
    key: "H",
    /* 唯一强调字（主题强调色的深度化变体） */
    d: "M4.5 0 V100 M63.5 0 V100 M0 50 H68",
    x: 346.4,
    tone: "accent",
    notch: { cx: 9, cy: 30 },
  },
  {
    key: "Y",
    /* 锐角叉口双肩 + 尾针下探 116.5（悬锤垂针） */
    d: "M3.81 2.39 L33 50 M62.19 2.39 L33 50 M33 50 V116.5",
    x: 438.4,
    tone: "ice",
    notch: { cx: 28.5, cy: 66 },
  },
  {
    key: "S",
    /* 双弧（r 24，上下各溢出 1.5 光学补偿）+ 三次样条中脊（相切进出） */
    d: "M51.78 15 A24 24 0 1 0 16.22 45.91 C22.52 50.84 37.48 49.16 43.78 54.09 A24 24 0 1 1 8.22 85",
    x: 529.7,
    tone: "ice",
    notch: { cx: 3.6, cy: 34 },
  },
];

/** 刻槽形制：6.2 × 7.0 @ 21° — 半深切痕（约切入笔画 4.2 / 9.8，笔画不断） */
const NOTCH_SPEC: BrandNotchSpec = { w: 6.2, h: 7, angle: 21 };

/** 画布（含 Y 尾针与 S 光学溢出余量；左右留白对称） */
const VIEW_BOX = "-14 -4 618 125";

/* ============================================================================
 * 级别运动场（确定性 hash — 只差化运动，不差化形态）
 *   dist/dur 区间 · lift 入射抬升 · rot 微倾幅度 · stagger/jitter 时序
 *   expose：刻槽与镂空仅在可辨级别暴露（mini 弹窗级收敛为静默简化锁版）
 * ========================================================================== */
interface LevelSpec {
  exposeNotches: boolean;
  exposeHollow: boolean;
  dist: [number, number];
  lift: number;
  rot: number;
  stagger: number;
  jitter: number;
  dur: [number, number];
  /** 弹射幅度缩放（仅引导页实际使用） */
  ejectScale: number;
}

const LEVELS: Record<BrandLevel, LevelSpec> = {
  intro: {
    exposeNotches: true,
    exposeHollow: true,
    dist: [66, 152],
    lift: 18,
    rot: 8.5,
    stagger: 128,
    jitter: 168,
    dur: [0.95, 1.3],
    ejectScale: 1,
  },
  compact: {
    exposeNotches: true,
    exposeHollow: true,
    dist: [24, 54],
    lift: 7,
    rot: 3.6,
    stagger: 92,
    jitter: 118,
    dur: [0.72, 0.92],
    ejectScale: 0.6,
  },
  mini: {
    exposeNotches: false,
    exposeHollow: false,
    dist: [10, 22],
    lift: 4,
    rot: 2.2,
    stagger: 52,
    jitter: 78,
    dur: [0.5, 0.66],
    ejectScale: 0.4,
  },
};

/** 确定性 hash（seed×salt 双域）∈ [0,1) */
const hash = (seed: number, salt: number): number => {
  const x = Math.sin(seed * 127.1 + salt * 311.7) * 43758.5453;
  return x - Math.floor(x);
};

/**
 * 生成字标模型（字形 + 刻槽 + 逐字运动变量）。
 * 构建期一次求值恒定 — 非运行时随机抖动。
 */
export function useBrandTitle(level: BrandLevel = "intro"): BrandWordmark {
  const spec = LEVELS[level];
  let doneAt = 0;

  const glyphs: BrandGlyph[] = GLYPHS.map((g, i) => {
    const h = (n: number) => hash(i, n);

    /* 轨道入射：上半弧差异化角度 + 距离差化（级别缩放） */
    const ang = (0.22 + h(1) * 0.56) * Math.PI;
    const dist = spec.dist[0] + h(2) * (spec.dist[1] - spec.dist[0]);
    const dx = +(Math.cos(ang) * dist).toFixed(1);
    const dy = +(Math.sin(ang) * dist * 0.5 - spec.lift).toFixed(1);
    const rot = +((h(3) * 2 - 1) * spec.rot).toFixed(2);
    const delay = Math.round(spec.stagger * i + h(4) * spec.jitter);
    const dur = +(spec.dur[0] + h(5) * (spec.dur[1] - spec.dur[0])).toFixed(2);

    doneAt = Math.max(doneAt, delay + dur * 1000);

    return {
      key: g.key,
      d: g.d,
      x: g.x,
      /* 简化级别：镂空降为实色（发丝描边在小字号级低于可辨阈值） */
      tone: g.tone === "hollow" && !spec.exposeHollow ? "ice" : g.tone,
      notch: spec.exposeNotches ? g.notch : null,
      style: {
        "--dx": `${dx}px`,
        "--dy": `${dy}px`,
        "--rot": `${rot}deg`,
        "--delay": `${delay}ms`,
        "--dur": `${dur}s`,
        /* 弹射时序：外缘先走（末字最先离场 — 引力弹弓语义） */
        "--ed": `${Math.round(((GLYPHS.length - 1 - i) * 42 + 60) * spec.ejectScale)}ms`,
      },
    };
  });

  return { viewBox: VIEW_BOX, notch: NOTCH_SPEC, glyphs, doneAt };
}