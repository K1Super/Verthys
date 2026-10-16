/**
 * useBrandTitle — VERTHYS 品牌字标系统（全局唯一权威源）
 *
 * 设计体系：星弦衡列体（Stellar Chord Alignment）
 *   VERTHYS 字标为定制字形（非任何字库字），全部数据在此单源定义，
 *   引导页 / 主界面 / 弹窗三级共用同一形态，仅幅度分级收敛。
 *
 *   1. 连续光弦笔画 — 全部笔画一笔连续、零切口零断笔（butt 端面
 *      垂直于笔画、尖锋为锐角 miter）：笔画如光弦张成骨架，
 *      弦的连续性即字标的形之所在 — 全字形无一处切口。
 *   2. 光门（唯一细弦字）— V 为发丝细弦（1.8）：七字中唯一的
 *      「虚」，似一道光门；其余六字实弦主力，构成一虚六实的克重对比。
 *   3. 悬锤垂针 — Y 尾弦下探至 116.5（越过基线 16.5）：全字唯一
 *      垂坠，如铅锤定中，破除等底排印的板滞。
 *   4. 单一强调 — 仅 H 取主题强调色（#16c8ea）：七弦中的定音弦，
 *      其余冰银（#d9e6f2）— 拒绝多点亮色泛滥。
 *   5. 双层雕刻 — 暗色克隆沿光向（右下）偏移的物理凹刻深度；
 *      非阴影非辉光，零渐变零滤镜。
 *
 * 运动语言（升轨入列 → 离轨升离）：
 *   逐字沿自身轴线自下升轨，携微摆入列（摆角交替异号、两翼强而
 *   中心弱 — 阵形收拢感）；时序为左→右加速扫掠（步距递减 = 光
 *   书写加速感）。离场为入列的惯性延续：沿轴线升离、外缘先走
 *   （与轨道丝线塌缩同构）。三级幅度收敛：intro 戏剧 / compact
 *   安静 / mini 近静默。
 *   全部运动参数为设计定值（逐字设计表驱动）— 形与动皆无随机，
 *   气韵生于设计的波形，非随机扰动。
 */

/** 字标级别：intro（引导页）/ compact（主界面）/ mini（弹窗品牌字） */
export type BrandLevel = "intro" | "compact" | "mini";

/** 着色三态：冰银实弦 / 唯一强调 / 光门发丝 */
export type BrandTone = "ice" | "accent" | "hollow";

/** 单字模型（模板层据此直出 SVG） */
export interface BrandGlyph {
  /** 字键（V/E/R/T/H/Y/S） */
  key: string;
  /** 笔画中心线路径（cap 0-100 坐标系 — 一笔连续，零切口） */
  d: string;
  /** 布局横向偏移（字距为设计值） */
  x: number;
  tone: BrandTone;
  /** 逐字 CSS 变量（升幅 / 摆角 / 时序 — 设计定值，非随机） */
  style: Record<string, string>;
}

export interface BrandWordmark {
  viewBox: string;
  glyphs: BrandGlyph[];
  /** 入场完成时刻（ms — 末字 delay + dur）：软离场门控源 */
  doneAt: number;
}

/* ============================================================================
 * 字形库（自绘中心线 — butt 端切面，y 向下，cap 0..100，baseline 100）
 *   端切面即笔画终点（butt）；转角为 miter（V 尖锋 / Y 叉口吃满锐角）；
 *   Y 尾弦越过基线至 116.5；S 为双弧 + 三次样条脊线（ogee 中脊）
 * ========================================================================== */
const GLYPHS: Array<{ key: string; d: string; x: number; tone: BrandTone }> = [
  {
    key: "V",
    /* 尖锋至 86.5 + miter 延伸 ≈ 100.6（基线对齐）— 光门发丝字 */
    d: "M4.25 1.48 L33 86.5 L61.75 1.48",
    x: 0,
    tone: "hollow",
  },
  {
    key: "E",
    /* 中臂短于上下臂 8.5 — 经典克重收束 */
    d: "M63 4.5 H4.5 V95.5 H63 M4.5 50 H54.5",
    x: 86.8,
    tone: "ice",
  },
  {
    key: "R",
    /* 几何圆腹（r 25.5）+ 直腿（55°）下落至基线 */
    d: "M0 4.5 H31 A25.5 25.5 0 0 1 31 55.5 H0 M4.5 0 V100 M31 55.5 L60.3 97.4",
    x: 174.8,
    tone: "ice",
  },
  {
    key: "T",
    d: "M0 4.5 H55 M27.5 0 V100",
    x: 264.4,
    tone: "ice",
  },
  {
    key: "H",
    /* 唯一强调字（主题强调色）— 侧弦外伸的过桥横弦为形制细节 */
    d: "M4.5 0 V100 M63.5 0 V100 M0 50 H68",
    x: 346.4,
    tone: "accent",
  },
  {
    key: "Y",
    /* 锐角叉口双肩 + 尾弦下探 116.5（悬锤垂针） */
    d: "M3.81 2.39 L33 50 M62.19 2.39 L33 50 M33 50 V116.5",
    x: 438.4,
    tone: "ice",
  },
  {
    key: "S",
    /* 双弧（r 24，上下各溢出 1.5 光学补偿）+ 三次样条中脊（相切进出） */
    d: "M51.78 15 A24 24 0 1 0 16.22 45.91 C22.52 50.84 37.48 49.16 43.78 54.09 A24 24 0 1 1 8.22 85",
    x: 529.7,
    tone: "ice",
  },
];

/** 画布（含 Y 尾弦与 S 光学溢出余量；左右留白对称） */
const VIEW_BOX = "-14 -4 618 125";

/* ============================================================================
 * 级别运动场（设计定值 — 无随机）
 *   rise 入列升幅 / sway 摆幅上限 / dur 入列时长 /
 *   delays 逐字延迟（左→右步距收窄 = 加速扫掠）/
 *   exitStep·exitBase 离轨时序（外缘先走 — 中心迟、边缘即发）
 * ========================================================================== */
interface LevelSpec {
  /** V 是否保留光门发丝（mini 级 30px 高度下发丝低于可辨阈值，收敛为实弦） */
  hollow: boolean;
  rise: number;
  sway: number;
  dur: number;
  delays: number[];
  exitStep: number;
  exitBase: number;
}

const LEVELS: Record<BrandLevel, LevelSpec> = {
  intro: {
    hollow: true,
    rise: 24,
    sway: 4.2,
    dur: 1.02,
    delays: [0, 95, 180, 255, 320, 375, 420],
    exitStep: 70,
    exitBase: 60,
  },
  compact: {
    hollow: true,
    rise: 12,
    sway: 2.6,
    dur: 0.72,
    delays: [0, 66, 126, 178, 222, 258, 286],
    exitStep: 46,
    exitBase: 40,
  },
  mini: {
    hollow: false,
    rise: 7,
    sway: 1.6,
    dur: 0.5,
    delays: [0, 40, 76, 108, 136, 160, 180],
    exitStep: 30,
    exitBase: 26,
  },
};

/* 摆角符号交替（防同倾 — 阵形左右开合而非齐倾） */
const SWAY_SIGN = [-1, 1, -1, 1, -1, 1, -1];

/**
 * 生成字标模型（字形 + 逐字设计运动变量）。
 * 构建期一次求值恒定 — 非运行时随机抖动。
 * 升幅与摆角按翼位加权：两翼行距与摆幅更大、中心收敛 —
 * 自两翼向中心收拢的阵形感（非均匀机械，亦非随机离散）。
 */
export function useBrandTitle(level: BrandLevel = "intro"): BrandWordmark {
  const spec = LEVELS[level];
  let doneAt = 0;

  const glyphs: BrandGlyph[] = GLYPHS.map((g, i) => {
    /* 翼位权重：0 = 中心（T），1 = 两翼（V/S） */
    const flank = Math.abs(i - 3) / 3;
    const rise = +(spec.rise * (0.82 + 0.18 * flank)).toFixed(1);
    const rot = +(SWAY_SIGN[i] * spec.sway * (0.28 + 0.72 * flank)).toFixed(2);
    const delay = spec.delays[i];
    /* 离轨时序：翼距中心越远越先离场（外缘先走 — 与丝线塌缩同构） */
    const ed = Math.round((3 - Math.abs(i - 3)) * spec.exitStep + spec.exitBase);

    doneAt = Math.max(doneAt, delay + spec.dur * 1000);

    return {
      key: g.key,
      d: g.d,
      x: g.x,
      /* 简化级别：光门收敛为实弦（发丝描边在小字号级低于可辨阈值） */
      tone: g.tone === "hollow" && !spec.hollow ? "ice" : g.tone,
      style: {
        "--dy": `${rise}px`,
        "--rot": `${rot}deg`,
        "--delay": `${delay}ms`,
        "--dur": `${spec.dur}s`,
        "--ed": `${ed}ms`,
      },
    };
  });

  return { viewBox: VIEW_BOX, glyphs, doneAt };
}
