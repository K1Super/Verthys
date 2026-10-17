/**
 * useBrandTitle — VERTHYS 品牌字标系统（全局唯一权威源）
 *
 * 设计体系：星晶棱镜体（Stellar Prism Crystal）
 *   VERTHYS 字标为定制字形（非任何字库字），全部数据在此单源定义；
 *   引导页 / 主界面 / 弹窗三级共用同一形态，仅材质参数分级收敛。
 *
 * 材质（半透明晶棱 — 深空背景透过笔画可见）：
 *   笔画不是一个实色描边，而是四层光学叠加，由 BrandMark 按此单源
 *   直出（几何/浓度皆在此定数，模板只负责装配）：
 *     1. 折射影 refract — 右下方位移的暗像：光穿过晶体后的落点。
 *        以偏移替代表模糊 —— 零滤镜即得柔化，规避实时滤镜的逐帧
 *        重算（滤镜在动画元素上会触发每帧重新求值）。
 *     2. 玻璃体 glass — 半透明冰蓝渐变（左上受光 → 中段透深 →
 *        右端回亮）：中段透深让深空背景穿透，右端回亮即光穿出晶体。
 *     3. 远侧棱光 edge-far — 右下侧较弱的反光：透过晶体体的光打亮
 *        远壁，使截面成为玻璃棒而非单侧高光的塑料浮雕。
 *     4. 近侧棱光 edge — 左上侧最强的镜面反光（受光面），渐变内
 *        多段明暗 = 序列棱面各自受光的角度差。
 *     能量芯 core — 仅 H：强调色竖向渐变（中段最亮），透过玻璃体
 *        显出，如晶体内部的能量芯（以光楔替代独立叠层）。
 *
 *   光楔共用：玻璃体与双侧棱光取同一斜向光楔（userSpaceOnUse 全域渐变），
 *   全字受同一束光 —— 各字所处相位不同即自然异相，无需逐字造作。
 *
 * 形（柔顺曲线骨架）：
 *   竖画保持垂直（曲则失稳），横画与转角一律走曲线；端面为圆端、
 *   拐点为圆角转接 —— 全字无锐角切面（V 尖锋与 Y 叉口由圆角自然
 *   收成小半径过渡）。圆端在笔画前进方向上多出半个笔宽，故各端点
 *   按半个笔宽内收，柔化后外缘仍与原字面等高。
 *   V 为棱镜口（近乎全透的极淡轮廓 + 全亮棱边折光线，七字中唯一「虚」）；
 *   H 侧弦外伸的过桥横弦；Y 尾弦下探 116.5（悬锤垂针）。
 *
 * 动（星晶凝聚 → 折光消散）：
 *   入场自外侧与下方双向量平移入列 → 轻度越位 → 位移归零；
 *   离场沿同一轴线继续平移散离（光散去）。
 *   位移与相位为逐字设计定值（两翼权重：行距更大、中心收敛 —
 *   阵形感），非随机扰动；时序左→右步距收窄（加速扫掠）。
 *   运动只用平移与不透明度：缩放与旋转会令合成层改变光栅比例或以
 *   非轴对齐方式重采样，细亮笔画在渡越窗口内糊化、结束帧再骤然转锐 ——
 *   舍缩放与旋转，换取字标全程锐利。
 */

/** 字标级别：intro（引导页）/ compact（主界面）/ mini（弹窗品牌字） */
export type BrandLevel = "intro" | "compact" | "mini";

/** 材质三态：玻璃体（六字）/ 能量芯（H）/ 棱镜口（V） */
export type BrandTone = "glass" | "core" | "prism";

/** 单字模型（模板层据此直出 SVG） */
export interface BrandGlyph {
  /** 字键（V/E/R/T/H/Y/S） */
  key: string;
  /** 笔画中心线路径（cap 0-100 坐标系 — 一笔连续，零切口） */
  d: string;
  /** 布局横向偏移（字距为设计值） */
  x: number;
  tone: BrandTone;
  /** 玻璃体（与棱边光）所用光楔键："glass" 冰蓝 / "core" 强调色 */
  grad: "glass" | "core";
  /** 折射影是否渲染（棱镜口为纯透字 —— 无暗影，保其通透） */
  refract: boolean;
  /** 逐字 CSS 变量（凝聚向量 / 摆角 / 时序 — 设计定值，非随机） */
  style: Record<string, string>;
}

export interface BrandWordmark {
  viewBox: string;
  glyphs: BrandGlyph[];
  /** 入场完成时刻（ms — 末字 delay + dur）：软离场门控源 */
  doneAt: number;
}

/* ============================================================================
 * 字形库（自绘中心线 — 圆端面，y 向下，cap 0..100，baseline 100）
 *   柔顺语言：竖画保持垂直（曲则失稳），横画与转角一律走三次贝塞尔曲线；
 *   各自由端按半个笔宽内收（圆端沿笔画方向外扩半个笔宽，内收后外缘
 *   与原字面等高）；V 尖锋、Y 叉口、E/R/T/H 的转角皆交由圆角转接；
 *   曲线字形（R 腹 / S 脊 / Y 肩）保留约 1.4 的光学溢出。
 *   路径皆为连续一笔 —— 缺口仅可能来自遮罩裁切，故全系统不设遮罩。
 * ========================================================================== */
const GLYPHS: Array<{ key: string; d: string; x: number; tone: BrandTone }> = [
  {
    key: "V",
    /* 双斜弦各走微弧（外弓 2.2 — 去直折而生张力），尖锋落 y=95：
       圆角转接半径 5 → 尖端恰抵基线 100；顶端收至 y=4.8 使圆端触 0 */
    d: "M4.25 4.8 C11.73 35.54 21.32 65.6 33 95 C44.68 65.6 54.27 35.54 61.75 4.8",
    x: 0,
    tone: "prism",
  },
  {
    key: "E",
    /* 脊垂直；上下臂各外张微弧 1（开口柔化），中臂上弓 1 且短于上下臂；
       三臂自由端各内收 5 使外缘仍抵 63 / 54.5 */
    d: "M58 4.5 C40.17 3.17 22.32 3.17 4.5 4.5 V95.5 C22.32 96.83 40.17 96.83 58 95.5 M4.5 50 C19.5 48.67 34.5 48.67 49.5 50",
    x: 86.8,
    tone: "glass",
  },
  {
    key: "R",
    /* 满圆腹（三次贝塞尔双弓，右凸至 57）+ 与脊平接的腰 + 柔腿
       （先水平后下摆，起笔圆端没入腰线 —— 腹内不留孤岛状端头） */
    d: "M4.5 5 H30 C45.5 5 57 16.5 57 30 C57 43.5 45.5 55.5 30 55.5 H4.5 M4.5 5 V95 M30 55.5 H38.5 C45.5 69 52 83 57.5 95.5",
    x: 174.8,
    tone: "glass",
  },
  {
    key: "T",
    /* 横弦上弓 0.8（柔化直梁），两端内收 5 使外缘抵 0 / 55 */
    d: "M5 4.5 C20 3.43 35 3.43 50 4.5 M27.5 5 V95",
    x: 264.4,
    tone: "glass",
  },
  {
    key: "H",
    /* 唯一强调字 — 过桥横弦两侧外伸（形制细节），横弦端内收 5 使外缘抵 0 / 68 */
    d: "M4.5 5 V95 M63.5 5 V95 M5 50 H63",
    x: 346.4,
    tone: "core",
  },
  {
    key: "Y",
    /* 双肩走外弓 1.5 的柔曲线汇于中轴，尾弦下探至 111.5（圆端再延 5 → 116.5） */
    d: "M5 4.3 C13.05 20.31 22.39 35.56 33 50 C43.61 35.56 52.95 20.31 61 4.3 M33 50 V111.5",
    x: 438.4,
    tone: "glass",
  },
  {
    key: "S",
    /* 六段三次贝塞尔全相切（C1 连续，无一处折角）：上碗右凸 / 下碗左凸，
       中脊斜穿；上下各溢出 1.4 光学补偿 */
    d: "M50 14 C46 2 38 -1.4 30 -1.4 C20 -1.4 8.5 14 8.5 30 C8.5 38 20 45 30 50 C40 55 51.5 60 51.5 70 C51.5 88 42 101.4 30 101.4 C18 101.4 10 94 10 86",
    x: 529.7,
    tone: "glass",
  },
];

/** 画布（含 Y 尾弦与 S 光学溢出余量；左右留白对称） */
const VIEW_BOX = "-14 -4 618 125";

/* ============================================================================
 * 级别运动场（设计定值 — 无随机；仅平移与不透明度，缘起见文件头「动」）
 *   converge 横向凝聚幅度（自外侧收束，中心字为零）· rise 纵向升幅 ·
 *   dur 单字凝聚时长 · delays 逐字延迟（左→右步距收窄 = 加速扫掠）·
 *   exitStep·exitBase 消散时序（外缘先走）
 * ========================================================================== */
interface LevelSpec {
  /** V 是否保留棱镜口（30px 高度下极淡轮廓低于可辨阈值，收敛为玻璃体） */
  prism: boolean;
  converge: number;
  rise: number;
  dur: number;
  delays: number[];
  exitStep: number;
  exitBase: number;
}

const LEVELS: Record<BrandLevel, LevelSpec> = {
  intro: {
    prism: true,
    converge: 17,
    rise: 23,
    dur: 1.06,
    delays: [0, 95, 180, 255, 320, 375, 420],
    exitStep: 70,
    exitBase: 60,
  },
  compact: {
    prism: true,
    converge: 8.5,
    rise: 12,
    dur: 0.74,
    delays: [0, 66, 126, 178, 222, 258, 286],
    exitStep: 46,
    exitBase: 40,
  },
  mini: {
    prism: false,
    converge: 4,
    rise: 6.5,
    dur: 0.52,
    delays: [0, 40, 76, 108, 136, 160, 180],
    exitStep: 30,
    exitBase: 26,
  },
};

/**
 * 生成字标模型（字形 + 逐字设计运动变量）。
 * 构建期一次求值恒定 — 非运行时随机抖动。
 * 凝聚向量按翼位加权：两翼行距更大、中心收敛 —— 自两翼向
 * 中心收拢的阵形感（非均匀机械，亦非随机离散）。
 */
export function useBrandTitle(level: BrandLevel = "intro"): BrandWordmark {
  const spec = LEVELS[level];
  let doneAt = 0;

  const glyphs: BrandGlyph[] = GLYPHS.map((g, i) => {
    /* 翼位权重：0 = 中心（T），1 = 两翼（V/S） */
    const flank = Math.abs(i - 3) / 3;
    const outward = Math.sign(i - 3);
    const dx = +(outward * spec.converge * (0.3 + 0.7 * flank)).toFixed(1);
    const dy = +(spec.rise * (0.84 + 0.16 * flank)).toFixed(1);
    const delay = spec.delays[i];
    /* 消散时序：翼距中心越远越先离场（外缘先走 — 与丝线塌缩同构） */
    const ed = Math.round((3 - Math.abs(i - 3)) * spec.exitStep + spec.exitBase);

    doneAt = Math.max(doneAt, delay + spec.dur * 1000);

    const tone: BrandTone = g.tone === "prism" && !spec.prism ? "glass" : g.tone;

    return {
      key: g.key,
      d: g.d,
      x: g.x,
      tone,
      grad: tone === "core" ? "core" : "glass",
      refract: tone !== "prism",
      style: {
        "--dx": `${dx}px`,
        "--dy": `${dy}px`,
        "--delay": `${delay}ms`,
        "--dur": `${spec.dur}s`,
        "--ed": `${ed}ms`,
      },
    };
  });

  return { viewBox: VIEW_BOX, glyphs, doneAt };
}
