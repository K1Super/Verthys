/**
 * useBrandTitle — VERTHYS 品牌排印参数系统（全局唯一权威源）
 *
 * 职责：
 *   生成「不规则字号雕刻排印」的逐字参数 — 不规则字号 / 非均匀浮动基线 /
 *   逐字微倾 / 实色·镂空·accent 三态混合 / 轨道入射与弹射向量。
 *   UnlockView（引导页 84px 级）与 HomeView（主界面紧凑级）共享同一
 *   确定性参数场，保证品牌排印跨场景形态同源（同一 hash 场，仅幅度缩放）。
 *
 * 反大众化设计：
 *   - 确定性 hash（可控不规则偏差）— 拒绝等距模板与均匀排布
 *   - 所有参数逐字独立差化，构建期一次求值恒定（非运行时随机抖动）
 *   - accent 锚点唯一（index 4 = 'C'），拒绝多点亮色泛滥
 *
 * 运动语言（轨道成型 → 引力弹射）：
 *   入射向量沿上半弧差异化角度，弹射外缘先走（引力弹弓语义）；
 *   compact 模式按统一比例收敛幅度（主界面安静驻留，不复制引导页戏剧性）。
 */

/** 品牌排印字符参数（全部数值 — 模板层负责拼接单位） */
export interface BrandChar {
  ch: string;
  /** 着色三态：实色 / 镂空描边 / 唯一 accent 锚点 */
  mode: "solid" | "hollow" | "accent";
  /** 字号（px）— 不规则视觉重量分布 */
  fs: number;
  /** 浮动基线偏移（px）— 非均匀错落 */
  by: number;
  /** 逐字微倾角（deg） */
  tr: number;
  /** 入射向量 x（px）— 轨道成型入场 */
  dx: number;
  /** 入射向量 y（px） */
  dy: number;
  /** 入射旋转偏角（deg） */
  rot: number;
  /** 入场延迟（ms）— 基础交错 + hash 抖动 */
  delay: number;
  /** 入场时长（s）— 逐字差化 */
  dur: number;
  /** 弹射延迟（ms）— 外缘字先走 */
  ed: number;
}

/** 确定性 hash（seed×salt 双域）∈ [0,1) */
const hash = (seed: number, salt: number): number => {
  const x = Math.sin(seed * 127.1 + salt * 311.7) * 43758.5453;
  return x - Math.floor(x);
};

export const BRAND_TITLE = "VERTHYS";
/** accent 锚点字符索引（'C' — 单锚点，唯一强调色） */
const ACCENT_IDX = 4;

export interface BrandTitleOptions {
  /** 紧凑级（主界面）：字号 30-50px，幅度整体收敛 */
  compact?: boolean;
  /** mini 级（弹窗品牌字）：字号 24-34px（弹窗内最大文字 — 层级高于 sc-title 16px），幅度收敛 */
  mini?: boolean;
}

/** 排印级别：intro（引导页默认）/ compact（主界面）/ mini（弹窗品牌字） */
type BrandLevel = "intro" | "compact" | "mini";

export function useBrandTitle(options: BrandTitleOptions = {}): BrandChar[] {
  const level: BrandLevel = options.mini
    ? "mini"
    : options.compact
      ? "compact"
      : "intro";

  return BRAND_TITLE.split("").map((ch, i) => {
    const h = (n: number) => hash(i, n);

    /* 三态抽取：accent 唯一；其余按 hash 加权（实色主力 / 镂空次之） */
    const mr = h(11);
    const mode: BrandChar["mode"] =
      i === ACCENT_IDX ? "accent" : mr < 0.45 ? "solid" : mr < 0.85 ? "hollow" : "solid";

    /* 轨道入射向量：上半弧差异化角度 + 距离差化（级别缩放） */
    const ang = (0.22 + h(1) * 0.56) * Math.PI;
    const distBase =
      level === "mini" ? 13 + h(2) * 15 : level === "compact" ? 38 + h(2) * 46 : 92 + h(2) * 108;
    const r1 = (n: number, lo: number, hi: number) =>
      +(lo + h(n) * (hi - lo)).toFixed(1);
    const levelPick = <T,>(intro: T, compact: T, mini: T): T =>
      level === "mini" ? mini : level === "compact" ? compact : intro;

    return {
      ch,
      mode,
      fs: Math.round(levelPick(56 + h(12) * 52, 30 + h(12) * 20, 24 + h(12) * 10)),
      /* mini 级浮动基线整型化：亚像素基线 = 小字号文字持续子像素
       * 光栅化模糊（恒模糊非运动瞬态）— 必须落物理像素栅格 */
      by: levelPick(r1(13, -13, 13), r1(13, -6.5, 6.5), Math.round(-2 + h(13) * 4)),
      tr: levelPick(r1(14, -2, 2), r1(14, -1.4, 1.4), r1(14, -0.7, 0.7)),
      dx: +(Math.cos(ang) * distBase).toFixed(1),
      dy: +(Math.sin(ang) * distBase * 0.55 - (level === "mini" ? 4 : level === "compact" ? 10 : 26)).toFixed(1),
      rot: levelPick(r1(3, -23, 23), r1(3, -11.5, 11.5), r1(3, -7, 7)),
      delay: Math.round(
        (level === "mini" ? 0.5 : level === "compact" ? 0.8 : 1) * (130 * i + h(4) * 230),
      ),
      dur: +levelPick(1.05 + h(5) * 0.4, 0.82 + h(5) * 0.3, 0.6 + h(5) * 0.22).toFixed(2),
      ed: Math.round(
        (level === "mini" ? 0.4 : level === "compact" ? 0.6 : 1) * ((BRAND_TITLE.length - 1 - i) * 42 + 60),
      ),
    };
  });
}
