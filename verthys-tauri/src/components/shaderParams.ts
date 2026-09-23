/*
 * shaderParams.ts — 粒子着色器参数唯一权威源（全部具名 · 模板字符串注入）
 *
 * 职责：ParticleBackground 三层粒子（远景幕布 / 银河盘 / 近景尘埃）的
 * 全部着色器物理参数与层构建基线参数。历史实现中这些数值以魔法数字
 * 形式散落在着色器模板字符串与构建调用里 — 本模块将其全部具名化，
 * 由 particleShaders.ts 的模板字符串注入（构建期常量折叠，零运行时
 * 开销），调参只改此处一处。
 *
 * 分层结构：
 *   WARP_GLSL / ORBIT_GLSL — 着色器内部共享数学常数（hash/噪声频率/
 *     散布/衰减系数 — 两层各自独立命名空间，互不串用）
 *   CURTAIN_WARP / GALAXY_ORBIT / CLOSE_ORBIT — 分层实例参数（同一
 *     着色器模板的不同物理实例化）
 *   *_LAYER — 层构建基线（数量/尺寸/透明度基准与包络增益）
 *   TRAIL_SPECS / TRAIL_RESPONSE / CLOSE_BREATH — 残影拖尾与帧循环
 *     材质响应参数
 *   ALPHA_TEST — 片元丢弃阈值（原 PointsMaterial alphaTest 等效）
 */

/* ============================================================================
 * 着色器实例参数形状（由 particleShaders.ts 模板消费）
 * ========================================================================== */

/** 幕布层（远景星点）渡越参数 — 全屏收缩 + 差速推进样式 */
export interface CurtainShaderOpts {
  /** mod 环绕周期（必须覆盖层 z 范围） */
  span: number;
  /** mod 偏移中心（静止态 z+C ∈ [0, span) 保证位置不变） */
  center: number;
  /** 远端淡入区间（环绕重生侧） */
  fadeNear: [number, number];
  /** 近端淡出区间（穿越相机侧） */
  fadeFar: [number, number];
  /** 差速推进基速 / 逐粒子差异 */
  speedBase: number;
  speedVar: number;
  /** 螺旋卷积强度（弧度） */
  swirl: number;
  /** 向消失点收缩强度（远景专属） */
  shrink: number;
  /** 渡越横向噪声幅度 */
  noiseAmp: number;
  /** 静止态漂移幅度（低强度连续噪声） */
  idleDrift: number;
}

/** 轨道层（银河盘 / 近景尘埃）渡越参数 — 引力缠绕样式 */
export interface OrbitShaderOpts {
  /** 渡越缠绕强度（弧度/单位积分，按半径衰减施加；符号由积分方向决定） */
  swirlGain: number;
  /** 渡越半径收缩上限（0-1） */
  shrinkGain: number;
  /** 核心吞没淡出半径（0 = 无核心淡出） */
  coreFadeR: number;
  /** 渡越噪声幅度（当前轨道角驱动 → 拖尾随弧线弯曲） */
  noiseAmp: number;
  /** 静止态漂移幅度（逐粒子独立相位） */
  idleDrift: number;
}

/* ============================================================================
 * 着色器内部共享数学常数（模板注入 — 禁止在 GLSL 字符串中书写裸数字）
 * ========================================================================== */

/** 幕布层 GLSL 常数（warpHash / 双频噪声 / 散布收缩 / 静止漂移） */
export const WARP_GLSL = {
  hashMul: 127.1,
  hashScale: 43758.5453,
  /** 单周期角（逐粒子相位） */
  tau: 6.2832,
  /** 双周期角（hash 相位） */
  twoTau: 12.566,
  /** 边界消散随 uWarp 激活速率 */
  fadeRamp: 2.0,
  /** 螺旋卷积半径衰减（近轴快远轴慢 — 非均匀卷积） */
  swirlRadiusK: 0.006,
  /** 收缩逐粒子散布（下限 / 变量幅度） */
  shrinkScatterLo: 0.7,
  shrinkScatterVar: 0.6,
  /** 双频噪声混合比 */
  noiseMixA: 0.6,
  noiseMixB: 0.4,
  /** 噪声一频：Y 空间频率 / T 时间频率 */
  noiseFreq1Y: 0.013,
  noiseFreq1T: 1.9,
  /** 噪声二频 */
  noiseFreq2Y: 0.031,
  noiseFreq2T: 1.1,
  /** Y 向噪声幅度占比（X 向 1.0） */
  noiseAmp2Ratio: 0.7,
  /** 噪声三频（X 空间驱动）：频率 / 时间 / 种子相位 */
  noiseFreq3X: 0.011,
  noiseFreq3T: 1.4,
  noiseSeedPhi: 3.1,
  /** 静止漂移：X/Y 频率 / 相位基数 / Y 幅度占比 */
  idleFreqX: 0.35,
  idleFreqY: 0.28,
  idlePhaseB: 4.4,
  idleAmpRatio: 0.8,
} as const;

/** 轨道层 GLSL 常数（缠绕 / 收缩 / 噪声 / 核心吞没 / 静止漂移） */
export const ORBIT_GLSL = {
  hashMul: 127.1,
  hashScale: 43758.5453,
  tau: 6.2832,
  twoTau: 12.566,
  /** 缠绕半径衰减（内圈缠绕快外圈慢，非刚体） */
  swirlRadiusK: 0.0028,
  /** 缠绕逐粒子散布（下限 / 变量幅度） */
  swirlScatterLo: 0.8,
  swirlScatterVar: 0.4,
  /** 收缩逐粒子散布（下限 / 变量幅度） */
  shrinkScatterLo: 0.55,
  shrinkScatterVar: 0.45,
  /** 双频噪声混合比 */
  noiseMixA: 0.6,
  noiseMixB: 0.4,
  /** 噪声一频：轨道角频率 / 时间频率 */
  noiseFreq1: 2.1,
  noiseFreq1T: 1.9,
  /** 噪声二频 */
  noiseFreq2: 3.7,
  noiseFreq2T: 1.3,
  /** Y 向噪声幅度占比 */
  noiseAmp2Ratio: 0.7,
  /** 噪声三频（轨道角驱动）：频率 / 时间 / 种子相位 */
  noiseFreq3: 2.9,
  noiseFreq3T: 1.55,
  noiseSeedPhi: 3.1,
  /** 静止漂移：X/Y 频率 / 相位基数 / Y 幅度占比 */
  idleFreqX: 0.35,
  idleFreqY: 0.28,
  idlePhaseB: 4.4,
  idleAmpRatio: 0.8,
  /** Z 向噪声幅度占比（相对 noiseAmp） */
  zNoiseRatio: 0.5,
  /** 核心吞没：淡出内缘（×coreFadeR）/ 可见度下限 / 动态跨度 / 吸积补偿 */
  coreEdge: 0.3,
  coreFloor: 0.34,
  coreSpan: 0.66,
  coreBoost: 1.35,
  /** 核心吞没随 uWarp 激活速率 */
  coreRamp: 1.6,
} as const;

/* ============================================================================
 * 分层实例参数（同一模板的物理实例化）
 * ========================================================================== */

/**
 * 远景幕布（1000 颗星点，z∈[-1000,-200]）：微纵深漂移（speedBase 0.08 —
 * 深空视差感而非推进），渡越视觉主体交给银河盘轨道缠绕 + 相机掠翼弧线。
 * z 范围 + center ∈ [0, span) → 静止态 mod 恒等（位置不变）。
 */
export const CURTAIN_WARP: CurtainShaderOpts = {
  span: 2000,
  center: 1100,
  fadeNear: [-1050, -880],
  fadeFar: [680, 880],
  speedBase: 0.08,
  speedVar: 0.05,
  swirl: 0.35,
  shrink: 0.22,
  noiseAmp: 12,
  idleDrift: 0.6,
};

/**
 * 银河盘引力坠渡参数（3s 序列标定）：缠绕增益 2.4（∫env≈1.65 → 全程
 * 约 ±4 rad，内圈衰减后 ~±2.6 — 倒卷/收紧清晰可辨）/ 收缩 35% /
 * 核心吞没半径 90 / 噪声 14 / 静止漂移 1.1。
 * 增益为 3s 基准标定 — 每帧速率剖面恒定，累计角度随 ENTER_T 线性缩放
 * （5s 正渡 ≈ ±4.3 rad），缠绕手感不因时长改变。
 */
export const GALAXY_ORBIT: OrbitShaderOpts = {
  swirlGain: 2.4,
  shrinkGain: 0.35,
  coreFadeR: 90,
  noiseAmp: 14,
  idleDrift: 1.1,
};

/**
 * 近景坠渡参数（3s 序列标定）：缠绕增益 3.6（大半径衰减后仍 ~±1 大弧
 * 横扫）/ 无收缩（保持掠过半径）/ 无核心吞没 / 最强噪声 26 / 静止漂移 1.8。
 * 增益为 3s 基准标定 — 累计弧长随 ENTER_T 线性缩放（5s 正渡更长掠翼）。
 */
export const CLOSE_ORBIT: OrbitShaderOpts = {
  swirlGain: 3.6,
  shrinkGain: 0,
  coreFadeR: 0,
  noiseAmp: 26,
  idleDrift: 1.8,
};

/* ============================================================================
 * 层构建基线与帧循环材质响应
 * ========================================================================== */

/** 幕布层构建基线（count / 尺寸与透明度基准 / 渡越增幅 / 缓旋速率） */
export const CURTAIN_LAYER = {
  count: 1000,
  size: 1.8,
  opacity: 0.6,
  /** 渡越尺寸增幅（envSmooth 驱动） */
  warpSizeGain: 2.2,
  warpOpacityGain: 0.22,
  /** 静止态缓旋速率（rad/s — 深景层克制） */
  driftRate: 0.003,
} as const;

/** 银河盘层构建基线（尺寸/透明度基线 — 旧 2.2/0.7 在 880 距离下仅 ~1.25px，星系不明显根因） */
/** 银河盘层构建基线（v4 — 静息亮度二次提升，用户校正「还是太暗」）：
 * 尺寸基线 5.0 / 透明度 1.0 —— 渡越增益再等量下调（1.2 / 0），
 * 峰值（6.2 / 1.0）与 v2/v3 严格一致；静息发光能量相对 v2 基线
 * ≈ (5.0/3.4)² × (1.0/0.85) ≈ 2.5×。
 * （历史：v2 4.0/0.95 ≈ +55% 仍偏暗；旧 2.2/0.7 在 880 距离下仅 ~1.25px） */
export const GALAXY_LAYER = {
  count: 3000,
  size: 5.0,
  opacity: 1.0,
  warpSizeGain: 1.2,
  warpOpacityGain: 0,
} as const;

/** 近景尘埃层构建基线 */
export const CLOSE_LAYER = {
  count: 600,
  size: 3,
  opacity: 0.5,
  warpSizeGain: 5.5,
} as const;

/** 残影拖尾层相位滞后（秒）与透明度/尺寸缩放（共享 geometry，独立材质） */
export const TRAIL_SPECS = [
  { lag: 0.065, opacity: 0.42, sizeScale: 0.82 },
  { lag: 0.135, opacity: 0.24, sizeScale: 0.66 },
  { lag: 0.215, opacity: 0.12, sizeScale: 0.5 },
] as const;

/** 残影拖尾帧循环响应：透明度 = baseOpacity × (base + gain × envSmooth)
 * （v4 — 静息基底 0.42→0.55：暗相位/静息态残光再提升；
 * base+gain=1.0 峰值不变，渡越期观感与前版一致） */
export const TRAIL_RESPONSE = {
  base: 0.55,
  gain: 0.45,
} as const;

/** 近景尘埃呼吸（静止态活态）：opacity = base + sin(t·rate)·amp + envSmooth·warpGain */
export const CLOSE_BREATH = {
  base: 0.4,
  amp: 0.1,
  rate: 0.3,
  warpOpacityGain: 0.45,
} as const;

/** 片元丢弃阈值（原 PointsMaterial alphaTest 等效 — 完全透明 texel 剔除） */
export const ALPHA_TEST = 0.001;
