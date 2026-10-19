/**
 * useQuantumField.ts — 量子态势面板 Canvas 物理场引擎
 *
 * =============================================================================
 * 设计规范对照（交互逻辑 / 动态运动 / 渲染性能 / 反AI大众化）
 * =============================================================================
 *
 * 【交互逻辑】
 *   1. 实时响应：pointermove 直接更新目标值，rAF 单帧内消费（≤16.7ms）
 *   2. 物理阻尼与惯性：所有状态过渡由弹簧-阻尼二阶系统驱动（半隐式欧拉，
 *      帧率无关），无 CSS transition 突变、无瞬时复位、无生硬回弹
 *   3. 交互优先级：节点/核心 hover（P1）> 面板视差（P2）——hover 期间视差
 *      目标衰减 50%，状态切换全程弹簧连续过渡，无断层无冲突
 *   4. 自然衰减梯度：鼠标力场对粒子/连线的影响采用高斯核 exp(-d²/2σ²)
 *      平滑衰减，无硬边界
 *
 * 【动态运动】
 *   1. 分层运行：far（尘埃，系数 0.35）/ mid（连线+碎片，1.0）/ near（吸积盘，1.7）
 *      各层独立速度、衰减系数、影响权重；每元素叠加独立相位的多频噪声漂移
 *      （鼠标视差只作用于 Canvas 内的尘埃与数据碎片两层；DOM 层与圆环、
 *      三个模块节点、三条连线一概零视差）
 *   2. 边界约束：尘埃轨道内旋至事件视界即被吸收并按能量守恒衰减重生外圈
 *      （统一消散规则，无穿模无溢出）
 *   3. 连续噪声扰动：多频正弦复合（非单频），拒绝整齐划一的机械同步
 *   4. 核心辉点无周期调制（有意设计）：吸积盘内缘能量斑的亮度只随
 *      「悬浮 / 就绪」这类交互状态即时变化（CORE_GLOW），不含任何
 *      sin/时间项驱动的呼吸 —— 呼吸效果已整体移除，不得再引入
 *   5. 零视差组（有意设计）：圆环整组（吸积盘 / 暗核 / 核心辉点）恒绘于
 *      面板中心，核心文字近层无位移写入；三个模块节点（DOM 节点层无位移写入）
 *      与三条能量连线（起点 = 静态中心、终点 = 装饰环环沿 —— 环心沿圆环
 *      方向回缩固定半径，见 LINK_DOCK_R；含数据包与光水路径）同属该组
 *      —— 鼠标移动时整组一动不动。
 *      视差仅保留给圆环「背后」的氛围元素：Canvas 尘埃（系数 5）与
 *      数据碎片（系数 13×0.8），二者只改绘制坐标，无任何 DOM 位移
 *   6. 卫星环饰与吸积盘同一渲染语言（有意设计）：三个模块节点的装饰环不再由
 *      DOM/SVG 描边承担，而由本引擎绘制 —— 发丝刻度环（三段非均匀断裂弧 +
 *      断口刻度）+ 内外双自转能量弧（钟形端点渐隐、模块色相）+ 状态扇段
 *      （跨度弹簧 × 色相插值 × 休眠压暗）+ 捕获光晕贴图。逐节点独立种子 →
 *      刻向/相位/跨度/速度互异（拒绝整齐划一的机械同步）；运动由引擎驱动，
 *      故与核心吸积盘共享同一档位治理与自限节拍
 *
 * 【渲染性能】
 *   1. DPR 缩放抗锯齿；粒子预渲染径向渐变贴图 drawImage（禁用 shadowBlur）；
 *      发光元素 lighter 混合、alpha 克制（≤0.85，拒绝辉光泛滥）
 *   2. ResizeObserver 自适应容器，轨道基于比例单位，视觉中心不变形
 *   3. dt 驱动物理（帧率无关）+ 引擎自测耗时 EMA → 粒子密度动态增减，
 *      长时间运行无衰减无泄漏（粒子池预分配，零 GC 压力）
 *   4. 统一帧门控（useFrameGate）：全局空闲四档 60/30/5/1fps，
 *      失焦/隐藏由全局调度器置 deep-idle（rAF 天然停帧）
 *   5. 文字清晰度：承载文字的层（核心 DOM 存活期内不参与任何缩放或位移）
 *      —— 缩放归装饰环热区（其内仅矢量图标，自身为独立合成层，逐帧缩放
 *      不再使父层栅格失效）；两层 DOM 均零位移且不提升合成层 → 保持主层内
 *      栅格化，字形走亚像素抗锯齿（更清晰），且永不被重栅格化。
 *      非整数缩放与亚像素平移都会让合成层重采样，字形在悬浮/静止期发糊
 *   6. 逐帧热路径零构建开销（鼠标移动卡顿根治 — 移动即满帧，逐帧成本
 *      被放大 60~144 次/秒）：核心暗核预渲染为贴图（禁逐帧
 *      createRadialGradient）；弧段描边色与钟形权重构建期定型（禁逐帧
 *      色串拼接与 sin/pow）；数据包位置写入预分配缓冲（禁逐帧对象分配）；
 *      力场高斯分母与截断半径为模块常量（禁逐帧重算，且按截断半径前置
 *      判定免去远粒子 Math.exp）
 *   7. 引擎自限渲染节拍（RENDER_MIN_INTERVAL_S = 1/75s）：本引擎稳态可见
 *      运动均远低于 60fps 连续性判据，跟满高刷屏只让逐帧成本线性放大而不
 *      产生任何可见增益 —— 60Hz 逐帧 / 120Hz 隔帧 / 144Hz 隔两帧 / 200Hz
 *      隔三帧，物理步进改取引擎自身帧间隔（wStep）以在自限下保持速度不变。
 *      唯光水仪式豁免本节拍：前缘光点行进速度远高于稳态运动，抽帧会被读作
 *      「跳动」，故该 ≤1.02s 的一次性编排按满帧渲染（关键动画不受节流）
 *
 */

import { onBeforeUnmount, watch, type Ref } from 'vue';
import { useGlobalIdleScheduler } from '../useGlobalIdleScheduler';
import { useFrameGate } from '../useFrameGate';
import { createPacketRitual, type PacketRitual } from '../management/packetRitual';
import { drawWaterFlow, WATER_MAX_POINTS, type WaterStyle } from '../management/flowWater';

/* ============================================================
 * 常量与调参（集中管理，全部为手工设计的非模板化参数）
 * ============================================================ */

/** 尘埃粒子池上限 / 下限（帧率自适应区间） */
const DUST_MAX = 110;
const DUST_MIN = 42;
/** 数据碎片上限 / 下限 */
const SHARD_MAX = 26;
const SHARD_MIN = 10;
/** 事件视界半径（相对 min(w,h) 的比例） */
const HORIZON_R = 0.055;
/** 尘埃重生外圈半径（比例） */
const DUST_OUTER_R = 0.46;
/** 鼠标力场高斯 σ（px） */
const FIELD_SIGMA = 132;
/** 力场高斯分母 σ² 的 2 倍（逐帧复用 — 原每次求值重算 2σ²） */
const FIELD_SIGMA2 = 2 * FIELD_SIGMA * FIELD_SIGMA;
/** 力场可感阈值（影响量低于此值视作零响应） */
const FIELD_EPSILON = 0.004;
/** 力场截断距离平方：exp(-d²/σ²) 恰降至可感阈值的 d² —— 逐粒前置
 *  判定即返回零，免去绝大多数远粒子的 Math.exp 求值 */
const FIELD_CUTOFF2 = FIELD_SIGMA2 * -Math.log(FIELD_EPSILON);
/** 连线中点增益高斯分母（σ 放宽 √2.2 —— 连线尺度大于粒子） */
const LINK_SIGMA2 = FIELD_SIGMA2 * 2.2;
/** 连线终点回缩半径（px）：装饰环圆心 → 环沿。
 *  装饰环半径 21（见 qd-panel.css 的 .qd-node-reticle：viewBox 48 = 元素
 *  48 CSS px，r = 21）+ 0.5 描边外缘 + 0.5 视觉间隙。节点 DOM 锚点即环圆心
 *  （见 qd-panel.css 的 .qd-module-node），终点沿「圆环中心 → 环心」方向
 *  回缩至此半径：线尾对接在环沿，绝不进入环内空间 —— 旧实心暗底托时代
 *  终点取环心无碍（线尾落在盘内读作「接在盘上」），换成中空刻度环 +
 *  悬浮字形后则读作「线穿过图标、把节点串起来」。 */
const LINK_DOCK_R = 22;

/* ---------- 卫星环饰（模块节点的引力锚点环 — 与吸积盘同一渲染语言） ----------
 * 三个模块节点原先只有一层静态 SVG 发丝描边，而中心圆环是本引擎逐帧渲染的
 * 多层活体（等长断弧 + 暗核 + 辉点 + 尘埃场），两者媒介层级相差一档 ——
 * 「与圆环天差地别」的根因即此。故把卫星环饰一并搬入本引擎：与吸积盘共用
 * 同一套语言（钟形端点渐隐的断裂弧、预渲染贴图、additive 发光、模块色相），
 * 运动同样由本引擎驱动 —— CSS/DOM 动画在 deep-idle 不会停帧，而本引擎的
 * 自限节拍与空闲档位对该层同样生效。
 *
 * 全部为定值 px：节点尺寸由 CSS 定死 48px、回缩半径 LINK_DOCK_R 亦为定值，
 * 故卫星环饰不随面板尺度缩放（与 DOM 图标严格同径）。 */
const SAT_R_BEZEL = 20.5;
/** 自转能量弧 / 状态扇段的分段数（钟形端点渐隐 — 与吸积弧同法，尺度更小故段数更少） */
const SAT_SEGS = 6;
/** 静态刻度环的三段断裂弧与三处断口（度）——
 *  沿用既定的非均匀取值，环的身份与此前完全一致 */
const SAT_BEZEL_ARCS_DEG = [121.68, 98.64, 95.76];
const SAT_BEZEL_GAPS_DEG = [12.24, 9.36, 22.32];
/** 环内刻度长度（自环沿向内，px）与环沿线宽 */
const SAT_TICK_LEN = 2.4;
const SAT_BEZEL_WIDTH = 1;
/** 外圈自转能量弧：跨度、角速度（rad/s → 约 30~78s 一圈）与亮度区间 */
const SAT_ACCENT_SPAN = [1.15, 1.75];
const SAT_ACCENT_OMEGA = [0.08, 0.2];
/** 内圈反向自转弧（制造纵深）：半径、跨度、角速度 */
const SAT_INNER_R = 13.4;
const SAT_INNER_SPAN = [0.55, 0.95];
const SAT_INNER_OMEGA = [-0.14, -0.06];
/** 捕获光晕（additive 贴图）直径 / 环半径，与其浓度上限（克制 — 拒绝辉光泛滥） */
const SAT_HALO_SCALE = 4.6;
const SAT_HALO_ALPHA = 0.15;
/** 保护已关闭（state-off）时的整体压暗系数 */
const SAT_DORMANT_ALPHA = 0.42;
/** 悬浮时的环饰能量增益 */
const SAT_HOVER_LIFT = 0.6;

/**
 * 模块状态读数（圆周占比 + 色相）：与节点状态类的语义一一对应，
 * 与先前的 DOM 扇段编码同值（已登录 30% / 已设置 20% / 未设置 11% / 关闭 5%），
 * 故状态的可读性不因媒介迁移而改变。
 */
const SAT_STATE: Record<string, { span: number; rgb: readonly [number, number, number] }> = {
  'state-active': { span: 0.3, rgb: [0, 255, 170] },
  'state-set': { span: 0.2, rgb: [0, 212, 255] },
  'state-empty': { span: 0.11, rgb: [255, 170, 0] },
  'state-off': { span: 0.05, rgb: [150, 164, 180] },
};

/**
 * 卫星弧段钟形端点渐隐权重（构建期一次求值的 LUT，下标 = 段序号）——
 * 与吸积弧同一形态语言，逐帧仅查表、免去 Math.sin/pow 复合求值 */
const SAT_BELL = Array.from({ length: SAT_SEGS }, (_, s) =>
  Math.pow(Math.sin((s / (SAT_SEGS - 1)) * Math.PI), 0.8),
);

/** 卫星环饰的自转能量弧（逐节点相位/跨度/速度互异 — 拒绝机械同步） */
interface SatArc {
  radius: number;
  span: number;
  theta: number;
  omega: number;
  width: number;
  alpha: number;
  /** 描边色串（构建期一次拼定 — 逐帧仅写 globalAlpha） */
  stroke: string;
}

/**
 * 构建卫星静态刻度环路径（局部坐标，环心为原点）：三段非均匀断裂弧 +
 * 每处断口一枚内指刻度 —— 「刻痕即刻度」的仪表语言，拒绝「一枚完美圆环」
 * 的加载器观感（与吸积盘的分段不等长弧同族）。
 *
 * @param base 逐节点静态偏转角（rad）—— 同一几何、不同刻向，赋予三个节点
 *   各自的仪表朝向（差异来自确定性取值，非随机抖动）
 */
function makeSatBezelPath(base: number): Path2D {
  const path = new Path2D();
  const r = SAT_R_BEZEL;
  const tickIn = SAT_R_BEZEL - SAT_TICK_LEN;
  const deg = Math.PI / 180;
  let acc = 0;
  for (let i = 0; i < SAT_BEZEL_ARCS_DEG.length; i++) {
    const a0 = base + acc * deg;
    const a1 = a0 + SAT_BEZEL_ARCS_DEG[i] * deg;
    path.moveTo(Math.cos(a0) * r, Math.sin(a0) * r);
    path.arc(0, 0, r, a0, a1);
    acc += SAT_BEZEL_ARCS_DEG[i];
    const mid = base + (acc + SAT_BEZEL_GAPS_DEG[i] / 2) * deg;
    path.moveTo(Math.cos(mid) * r, Math.sin(mid) * r);
    path.lineTo(Math.cos(mid) * tickIn, Math.sin(mid) * tickIn);
    acc += SAT_BEZEL_GAPS_DEG[i];
  }
  return path;
}
/** 引擎自身耗时 EMA 平滑系数（密度自适应依据） */
const FRAME_EMA = 0.92;
/** 引擎自身单帧耗时上限 / 下限（ms）：超过上限降密度，低于下限回补。
 *  采用引擎自测耗时而非帧间隔 —— 帧间隔在 120/144Hz 屏上恒小于 14.5ms，
 *  原实现据此持续抬升密度至上限，使高刷屏上的引擎负载被无谓放大 2 倍以上。 */
const COST_HIGH_MS = 6.5;
const COST_LOW_MS = 2.5;
/** dt 钳制上限（秒），掉帧时物理不爆炸 */
const DT_CLAMP = 0.05;
/** 密度评估周期（帧） */
const ADAPT_INTERVAL = 90;

/* ---------- 引擎自限渲染节拍 ----------
 * 本引擎可见运动的最大频率：视差弹簧跟手（~0.8s 收敛）、尘埃轨道（数十秒
 * 一圈）、弧段自转（10~50s 一圈）、数据包流（~4s 一趟）、入场编排（一次性）。
 * 全部远低于 60fps 的连续性判据 —— 跟满 120/144Hz 高刷屏不产生任何可见
 * 增益，却让逐帧成本线性放大 2~2.4 倍：整层画布重绘（清屏 + 全量描绘）
 * 与两个视差承载层的整层写入，全部按刷新率重复付账。鼠标移动期间档位恒为
 * active（逐 rAF），这正是「视差特别卡顿」的直接来源。
 *
 * 取 1/75s 门限：60Hz 屏逐帧执行（60fps，与改造前完全一致）；120Hz 屏
 * 隔帧执行（60fps）；144Hz 屏隔两帧执行（72fps）—— 三档都落在等间隔
 * 节拍上（每 1/2/2 个 rAF 一次），不产生不均匀抖动。
 * 舍弃帧不推进 lastWallClock，故下一执行帧的 wStep 覆盖被跳过的全部时间：
 * 物理与进度零丢帧时间，弹簧/轨道速度不因自限而变慢。 */
const RENDER_MIN_INTERVAL_S = 1 / 75;

/** 有效尺寸阈值（px）：低于此值容器处于过渡/未布局状态，跳过渲染 */
const SIZE_VALID_MIN = 10;

/* ---------- 核心辉点亮度（静态 — 有意不含任何周期性调制） ----------
 * 设计约束：辉点亮度只随「悬浮 / 就绪」这类交互状态即时变化（状态应答），
 * 不得由任何时间项（sin/elapsed 等）驱动 —— 呼吸效果已按设计整体移除。
 * 上界 0.55 + 0.17 + 0.12 = 0.84 < 0.85，故 ceil 永不生效（仅作防御）。 */
const CORE_GLOW = {
  base: 0.55,
  hoverLift: 0.17,
  readyLift: 0.12,
  ceil: 0.85,
} as const;

/* ---------- 光水仪式（进入下一界面前的能量显影与收束） ----------
 * 与引导区同规范：进度只由墙钟累积量驱动（帧率无关，无固定延时等待），
 * 视图切换由完成事件驱动（双帧约定），reduced-motion 下直通跳过。 */
const FLOW_DURATION = {
  /** 传播时长（秒）：光水自中心流向三模块节点 */
  propagation: 0.66,
  /** 落定时长（秒）：节点光晕扩散 + 光水整体淡出至零浓度 */
  landing: 0.36,
} as const;

/** 光水配色（三条水带各取一色 + 逐链相位差化 → 不同步，非机械重复） */
const WATER_EDGE = ['rgba(0,212,255,', 'rgba(139,92,246,', 'rgba(255,110,180,'];
const WATER_CORE = ['rgba(214,255,252,', 'rgba(226,214,255,', 'rgba(255,226,240,'];

/** 光水回传的分区（与 QuantumDashboard 的 enterSection 载荷同一口径） */
export type DashboardSection = 'globalKey' | 'moduleKeys';

/* ---------- 入场编排（intro choreography） ----------
 * 面板挂载/尺寸就绪瞬间从 0 开始，各层错峰苏醒，杜绝"全量元素瞬间定格出现"。
 * 曲线为 smoothstep 与 smootherstep 的加权复合（非单一标准缓动预设） */

/** 钳制 0..1 */
export function clamp01(v: number): number {
  return v < 0 ? 0 : v > 1 ? 1 : v;
}

/** 复合入场曲线：smoothstep(35%) + smootherstep(65%) 加权混合 */
export function introEase(t: number): number {
  const c1 = t * t * (3 - 2 * t);
  const c2 = t * t * t * (t * (t * 6 - 15) + 10);
  return c1 * 0.35 + c2 * 0.65;
}

/** 错峰相位窗：delay 起始 / dur 时长 → 复合曲线进度 */
export function phase(t: number, delay: number, dur: number): number {
  return introEase(clamp01((t - delay) / dur));
}

/**
 * 光水前缘位置曲线：smoothstep（与开场编排同一族缓动语言）。
 *
 * 匀速推进会让前缘「起步即全速、到点即撞停」；smoothstep 两端速度为零，
 * 读作自中心涌出、再在环沿落定的连续流体。曲线只作用于归一化进度，
 * 故推进仍纯由墙钟累积量决定：帧率无关、总时长不变、端点不变。
 */
export function flowHeadEase(p: number): number {
  const t = clamp01(p);
  return t * t * (3 - 2 * t);
}

/** 弹簧-阻尼二阶系统（帧率无关，半隐式欧拉积分） */
export interface Spring {
  v: number;
  vel: number;
  target: number;
  k: number;
  c: number;
}

/** 创建弹簧（dampingRatio < 1 为欠阻尼带微惯性问题，> 1 过阻尼无过冲） */
export function makeSpring(k: number, dampingRatio = 1.0, init = 0): Spring {
  return { v: init, vel: 0, target: init, k, c: 2 * Math.sqrt(k) * dampingRatio };
}

/** 弹簧积分（半隐式欧拉：先更新速度再更新位置，能量稳定） */
export function springStep(s: Spring, dt: number): void {
  const force = (s.target - s.v) * s.k - s.vel * s.c;
  s.vel += force * dt;
  s.v += s.vel * dt;
}

/** 种子化伪随机（mulberry32 — 可复现的"可控不规则"） */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** 多频正弦复合噪声生成器（连续、非重复、拒绝整齐划一） */
export function makeDrift(seed: number): (t: number) => number {
  const r = mulberry32(seed);
  const f1 = 0.09 + r() * 0.06;
  const f2 = 0.21 + r() * 0.1;
  const f3 = 0.43 + r() * 0.17;
  const p1 = r() * Math.PI * 2;
  const p2 = r() * Math.PI * 2;
  const p3 = r() * Math.PI * 2;
  return (t: number) =>
    Math.sin(t * f1 + p1) * 0.56 +
    Math.sin(t * f2 + p2) * 0.31 +
    Math.sin(t * f3 + p3) * 0.13;
}

/* ============================================================
 * 场元素数据结构（全部池化预分配，零运行时 GC）
 * ============================================================ */

/** 引力尘埃粒子（椭圆轨道 + 内旋吸收 + 噪声扰动） */
interface Dust {
  r: number;
  theta: number;
  omega: number;
  rVel: number;
  ecc: number;
  tilt: number;
  size: number;
  alpha: number;
  sprite: number;
  seed: number;
  fade: number;
}

/** 数据碎片（切向细线段，数据流残影） */
interface Shard {
  r: number;
  theta: number;
  omega: number;
  len: number;
  alpha: number;
  seed: number;
  fade: number;
}

/** 连线数据包（沿贝塞尔流动的能量量子） */
interface Packet {
  t: number;
  speed: number;
  size: number;
  sprite: number;
}

/** 能量连线（中心 → 模块节点，二次贝塞尔） */
interface Link {
  to: { x: number; y: number };
  bow: number;
  drift: (t: number) => number;
  packets: Packet[];
  glow: number;
}

/** 连线当帧几何（基础连线与光水共用同一几何源 — 严禁两处各算一套） */
interface LinkGeom {
  /** 起点（核心侧） */
  sx: number;
  sy: number;
  /** 终点（节点像素坐标） */
  nx: number;
  ny: number;
  /** 控制点 */
  cpx: number;
  cpy: number;
  /** 中点（鼠标力场增益判定用） */
  mx: number;
  my: number;
}

/** 吸积弧段（不等长 + 钟形端点渐隐） */
interface Arc {
  radius: number;
  span: number;
  theta: number;
  omega: number;
  alpha: number;
  /** 描边色串（构建期一次拼定 — 逐段重拼会逐帧产生 56 次字符串分配
   *  与 CSS 颜色解析；逐帧仅写入 globalAlpha / lineWidth） */
  stroke: string;
  width: number;
}

/** 弧段钟形端点渐隐权重（构建期一次求值的 LUT，下标 = 段序号）——
 *  逐帧仅查表，免去每段 Math.sin + Math.pow 的复合求值 */
const ARC_SEGS = 14;
const ARC_BELL = Array.from({ length: ARC_SEGS }, (_, s) =>
  Math.pow(Math.sin((s / ARC_SEGS) * Math.PI), 0.8),
);

/* ============================================================
 * 引擎主体
 * ============================================================ */

/** useQuantumField 依赖注入（全部为 DOM ref + 布局常量，纯引擎无 Vue 响应式开销） */
export interface QuantumFieldOptions {
  /** 面板根元素（事件绑定 + ResizeObserver 目标） */
  panel: Ref<HTMLElement | null>;
  /** 画布元素（动态层渲染） */
  canvas: Ref<HTMLCanvasElement | null>;
  /** 中心核心可交互簇（hover 弹簧驱动 scale） */
  coreCluster: Ref<HTMLElement | null>;
  /** 模块节点 DOM 列表（hover 弹簧驱动 scale） */
  nodes: Ref<HTMLElement[]>;
  /** 模块节点布局（百分比，与 DOM 定位严格一致） */
  nodePositions: Array<{ x: number; y: number }>;
  /** 模块状态类名（与 nodePositions 同序）—— 卫星环饰的状态扇段由此读取
   *  （跨度 / 色相 / 休眠压暗）；与 DOM 的 state-* 类同源，故两者不会漂移 */
  nodeStates: { readonly value: readonly string[] };
  /** 中心核心就绪状态（吸积盘能量与色相应答） */
  coreReady: Ref<boolean>;
  /** 光水仪式完成回调（落定渲染帧的下一帧调用 — 双帧约定，
   *  与 ManagementHub 的传播完成事件同规范）；缺省则不回调 */
  onFlowComplete?: (section: DashboardSection) => void;
}

/**
 * 量子态势面板物理场引擎
 *
 * @param options DOM refs + 布局注入
 * @returns destroy（组件卸载时释放全部资源）
 */
export function useQuantumField(options: QuantumFieldOptions) {
  /* ---------- DOM 引用快照 ---------- */
  let panelEl: HTMLElement | null = null;
  let canvasEl: HTMLCanvasElement | null = null;
  let ctx: CanvasRenderingContext2D | null = null;
  let coreEl: HTMLElement | null = null;
  let nodeEls: HTMLElement[] = [];
  /** 装饰球体引用（逐帧缩放目标 — 承载文字的节点外层不得缩放） */
  let orbEls: HTMLElement[] = [];

  /* ---------- 画布尺寸 ---------- */
  let width = 0;
  let height = 0;
  let dpr = 1;
  let minDim = 1;

  /* ---------- 时间 ---------- */
  let elapsed = 0;
  let frameCount = 0;
  /** 引擎自身单帧耗时 EMA（ms）——密度自适应的唯一依据 */
  let avgEngineCostMs = 2.5;
  /** 上一帧墙钟（首帧守卫 — 首帧 wStep=0 不推进时间轴，避免跳变） */
  let lastWallClock = -1;

  /* ---------- G-7 统一帧门控（useFrameGate） ----------
   * 帧率档位由全局空闲状态机唯一决定（active 60 / settling 30 /
   * idle 5 / deep-idle 1 fps）；dt 由门控按累积时间供给（跳帧不推进
   * 基准 → 物理时间连续），本引擎不再维护私有空闲判定与全局交互监听。 */
  const { level: idleLevel, resetIdle } = useGlobalIdleScheduler();

  /* ---------- 监听器统一 AbortController 管理 ----------
   * init() 时创建，全部 addEventListener（面板级 + 全局交互 + 子元素 hover）
   * 经 signal 注册；destroy() 一次 abort() 移除全部，无逐项 removeEventListener
   * 的遗漏风险，子元素监听器不再依赖 GC 回收。 */
  let listenerAbort: AbortController | null = null;

  /* ---------- 入场编排状态 ----------
   * introTime = -1：等待首个有效尺寸（容器过渡中/未布局，不渲染不推进）
   * introTime ≥ 0：编排进行中/已完成，各层按错峰窗口苏醒 */
  let introTime = -1;
  let sizeValid = false;

  /* ---------- 指针状态（力场 + 视差源） ---------- */
  let pointerX = 0; // 面板内像素坐标
  let pointerY = 0;
  let pointerInside = false;

  /* ---------- 物理弹簧组 ---------- */
  // 视差（欠阻尼 0.82：带微惯性的跟手，非机械 lerp）
  const parallaxX = makeSpring(34, 0.82);
  const parallaxY = makeSpring(34, 0.82);
  // 力场强度（进入 1 / 离开 0，过阻尼无过冲）
  const fieldPower = makeSpring(24, 1.15);
  // hover 让位仲裁弹簧：P1（节点/核心 hover）期间视差幅度衰减至 50% —
  // 原实现对视差输出乘 0.5/1.0 硬步进，pointerenter 瞬间近层位移
  // 一次跳变最多 11px（"内容突然跳位放大"突兀感主因）→ 弹簧连续过渡
  const hoverSuppress = makeSpring(26, 1.1, 1);
  // 中心核心 hover（轻过阻尼缓胀：原 k=60 快弹在 ~140ms 内完成
  // 4.5% 缩放，读感为"突然放大"；降刚度后 ~0.4s 平滑膨胀应答）
  const coreHover = makeSpring(24, 1.1);
  // 核心就绪度（色相/能量过渡）
  const coreReadySpring = makeSpring(10, 1.2);
  // hover 仲裁：任一节点/核心 hover 时抑制视差（交互优先级 P1 > P2）
  const hoverCount = { n: 0 };

  /* ---------- 噪声通道（各视差层独立漂移相位 — 仅尘埃与碎片仍带视差） ---------- */
  const driftFar = makeDrift(0x5f3a);
  const driftDebris = makeDrift(0x2c81);

  /* ---------- 粒子池 ---------- */
  let activeDust = 84;
  let activeShards = 18;
  const dustPool: Dust[] = [];
  const shardPool: Shard[] = [];

  /* ---------- 连线与吸积盘 ---------- */
  const links: Link[] = [];
  const arcs: Arc[] = [];

  /* ---------- 光水（中心 → 模块节点：能量显影 + 离场前收束淡出） ----------
   * 采样缓冲与几何缓冲预分配（零运行时 GC）；样式随容器尺寸在 applySize
   * 内重建（水带宽度与面板尺度同源）。 */
  const geoms: LinkGeom[] = [];
  const waterStyles: WaterStyle[] = [];
  const waterXs: Float64Array[] = [];
  const waterYs: Float64Array[] = [];
  const bezOut = new Float64Array(2);
  /* 数据包位置缓冲（逐包原地复用 — 原实现每包每帧返回新对象，逐帧产生
   * 8 个短生命周期对象交由 GC） */
  const pktOut = new Float64Array(2);
  const reducedMotion =
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const flow: PacketRitual = createPacketRitual({
    propagationDuration: FLOW_DURATION.propagation,
    landingDuration: FLOW_DURATION.landing,
    reducedMotion,
  });
  /** 光水完成事件携带的分区（仪式期间不变） */
  let flowSection: DashboardSection = 'globalKey';
  /** 完成事件帧标志（双帧约定：落定渲染帧的下一帧领取完成事件） */
  let flowCompletePending = false;

  /* ---------- 节点 hover 弹簧池 ---------- */
  const nodeSprings: Spring[] = [];

  /* ---------- 卫星环饰（逐节点：静态刻度环 + 双自转弧 + 状态扇段） ---------- */
  /** 静态刻度环路径（构建期成路径 — 逐帧一次描边，零逐帧路径构建） */
  const satBezel: Path2D[] = [];
  /** 外圈自转能量弧（模块色相 — 与连线/光水同源） */
  const satAccent: SatArc[] = [];
  /** 内圈反向自转弧（纵深） */
  const satInner: SatArc[] = [];
  /** 状态扇段跨度弹簧（状态切换无硬跳） */
  const satSpanSpring: Spring[] = [];
  /** 状态扇段当前色相（逐帧向目标色相插值，帧率无关） */
  const satHue: number[][] = [];
  /** 休眠压暗系数（0 = 常态，1 = 保护已关闭；逐帧收敛，切换无硬跳） */
  const satDim: number[] = [];

  /* ---------- 节点像素坐标缓冲（每帧原地写入，零 GC） ---------- */
  const nodePx: Array<{ x: number; y: number }> = [];

  /* ---------- 预渲染发光贴图（径向渐变，禁 shadowBlur） ---------- */
  const sprites: HTMLCanvasElement[] = [];
  const SPRITE_COLORS = [
    'rgba(0,212,255,1)',   // 青
    'rgba(139,92,246,1)',   // 紫
    'rgba(255,110,180,1)',  // 粉
    'rgba(0,255,190,1)',    // 青绿
  ];

  /** 离屏预渲染单枚发光贴图（32px 径向渐变，边缘平滑无锯齿毛刺） */
  function makeSprite(color: string): HTMLCanvasElement {
    const size = 32;
    const c = document.createElement('canvas');
    c.width = size;
    c.height = size;
    const g = c.getContext('2d')!;
    const grad = g.createRadialGradient(16, 16, 0, 16, 16, 16);
    grad.addColorStop(0, color);
    grad.addColorStop(0.28, color.replace(',1)', ',0.55)'));
    grad.addColorStop(0.62, color.replace(',1)', ',0.12)'));
    grad.addColorStop(1, 'rgba(0,0,0,0)');
    g.fillStyle = grad;
    g.beginPath();
    g.arc(16, 16, 16, 0, Math.PI * 2);
    g.fill();
    return c;
  }

  /* 核心暗核贴图（离屏一次栅格化）：替代逐帧 createRadialGradient +
   * fill —— 原实现每帧新建径向渐变对象（分配 + 渐变色带求值）并填充
   * 0.24×minDim 直径的圆；改为贴图 drawImage 后，逐帧仅一次纹理绘制。
   * 贴图 alpha 斜坡按 0.85 基准归一（中心 1 → 0.647 → 0），逐帧整体
   * 浓度（含 readyT 的微调）由 globalAlpha 承担，视觉与逐帧渐变一致。 */
  let nucleusSprite: HTMLCanvasElement | null = null;

  function makeNucleusSprite(): HTMLCanvasElement {
    const size = 512;
    const c = document.createElement('canvas');
    c.width = size;
    c.height = size;
    const g = c.getContext('2d')!;
    const r = size / 2;
    const grad = g.createRadialGradient(r, r, 0, r, r, r);
    grad.addColorStop(0, 'rgba(4,6,12,1)');
    grad.addColorStop(0.7, 'rgba(6,9,18,0.647)');
    grad.addColorStop(1, 'rgba(6,9,18,0)');
    g.fillStyle = grad;
    g.fillRect(0, 0, size, size);
    return c;
  }

  /* ============================================================
   * 初始化与池构建
   * ============================================================ */

  /** 重生一枚尘埃（外圈随机注入，能量守恒式衰减） */
  function respawnDust(d: Dust, r?: () => number): void {
    const rand = r ?? Math.random;
    d.r = DUST_OUTER_R * (0.82 + rand() * 0.18);
    d.theta = rand() * Math.PI * 2;
    // 开普勒式：内圈角速度更快（ω ∝ r^-1.5），形成自然速度梯度
    d.omega = (0.05 + rand() * 0.1) / Math.pow(d.r / 0.2, 1.5);
    if (rand() < 0.5) d.omega = -d.omega;
    // 缓慢内旋（引力吸入）
    d.rVel = -(0.004 + rand() * 0.012);
    d.ecc = 0.72 + rand() * 0.5;
    d.tilt = rand() * Math.PI * 2;
    d.size = 1.4 + rand() * 2.6;
    d.alpha = 0.16 + rand() * 0.5;
    d.sprite = Math.floor(rand() * SPRITE_COLORS.length);
    d.seed = rand() * 1000;
    d.fade = 0;
  }

  /** 重生一枚数据碎片 */
  function respawnShard(s: Shard): void {
    const rand = Math.random;
    s.r = 0.14 + rand() * 0.3;
    s.theta = rand() * Math.PI * 2;
    s.omega = (0.12 + rand() * 0.2) / Math.pow(s.r / 0.2, 1.5);
    if (rand() < 0.5) s.omega = -s.omega;
    s.len = 5 + rand() * 8;
    s.alpha = 0.1 + rand() * 0.3;
    s.seed = rand() * 1000;
    s.fade = 0;
  }

  /** 构建/重建光水样式（水带宽度与面板尺度同源 — 在 applySize 内随尺寸刷新） */
  function buildWaterStyles(): void {
    waterStyles.length = 0;
    const scale = Math.max(0.7, Math.min(1.9, minDim / 540));
    for (let i = 0; i < links.length; i++) {
      waterStyles.push({
        edge: WATER_EDGE[i % WATER_EDGE.length],
        core: WATER_CORE[i % WATER_CORE.length],
        halfW: 4.8 * scale,
        trail: 0.34,
        /* 逐链涟漪周期与相位互异（2.0/2.7/3.4 周期）→ 水带波纹不同步 */
        ripples: 2 + i * 0.7,
        phase: 0.19 + i * 0.37,
      });
    }
  }

  /** 构建全部池（种子化随机，可控不规则分布） */
  function buildPools(): void {
    const rand = mulberry32(0xa17c);
    for (let i = 0; i < DUST_MAX; i++) {
      const d: Dust = {
        r: 0, theta: 0, omega: 0, rVel: 0, ecc: 1, tilt: 0,
        size: 2, alpha: 0.3, sprite: 0, seed: 0, fade: 0,
      };
      respawnDust(d, rand);
      // 初始散布于全轨道域（非同圈起跑，拒绝均匀分布）
      d.r = HORIZON_R + rand() * (DUST_OUTER_R - HORIZON_R);
      d.fade = 1;
      dustPool.push(d);
    }
    for (let i = 0; i < SHARD_MAX; i++) {
      const s: Shard = {
        r: 0, theta: 0, omega: 0, len: 6, alpha: 0.2, seed: 0, fade: 1,
      };
      respawnShard(s);
      s.fade = 1;
      shardPool.push(s);
    }
    // 连线：每条独立弓曲方向 + 相位差异数据包
    options.nodePositions.forEach((pos, i) => {
      const linkRand = mulberry32(0x33d1 + i * 7919);
      const packets: Packet[] = [];
      const packetCount = 2 + Math.floor(linkRand() * 2);
      for (let p = 0; p < packetCount; p++) {
        packets.push({
          t: linkRand(),
          speed: 0.1 + linkRand() * 0.16,
          size: 2 + linkRand() * 2.4,
          sprite: i % SPRITE_COLORS.length,
        });
      }
      links.push({
        to: { ...pos },
        bow: (linkRand() < 0.5 ? -1 : 1) * (4 + linkRand() * 9),
        drift: makeDrift(0x11f + i * 613),
        packets,
        glow: 0,
      });
      /* 光水几何缓冲 + 采样缓冲（每条连线独立；采样点数为容量上限，
         逐链相位/频率差化 → 三条水带不同步） */
      geoms.push({ sx: 0, sy: 0, nx: 0, ny: 0, cpx: 0, cpy: 0, mx: 0, my: 0 });
      waterXs.push(new Float64Array(WATER_MAX_POINTS));
      waterYs.push(new Float64Array(WATER_MAX_POINTS));
    });
    // 吸积弧段：不等长（90°~200°）+ 不等速 + 相异色（非对称组合）
    const arcRand = mulberry32(0x7c5e);
    const arcColors = [
      'rgba(0,212,255,', 'rgba(139,92,246,', 'rgba(255,110,180,', 'rgba(0,255,190,',
    ];
    const arcCount = 4;
    for (let i = 0; i < arcCount; i++) {
      arcs.push({
        radius: 0.085 + arcRand() * 0.075,
        span: (Math.PI / 180) * (92 + arcRand() * 108),
        theta: arcRand() * Math.PI * 2,
        omega: (0.12 + arcRand() * 0.3) * (arcRand() < 0.5 ? -1 : 1),
        alpha: 0.14 + arcRand() * 0.2,
        /* 描边色串一次拼定（不透明度恒为 1，逐帧明暗由 globalAlpha 承担） */
        stroke: `${arcColors[i % arcColors.length]}1)`,
        width: 1 + arcRand() * 1.6,
      });
    }
    // 节点 hover 弹簧（与节点等量；降刚度缓胀 — 原 k=70 快弹
    // 120ms 内完成 10% 缩放，与核心同款"突然放大"突兀感）
    options.nodePositions.forEach(() => {
      nodeSprings.push(makeSpring(30, 1.05));
      nodePx.push({ x: 0, y: 0 });
    });
    /* 卫星环饰：逐节点独立种子 → 刻向/相位/跨度/角速度互异（拒绝整齐划一）；
     * 半径与线宽为定值（与 DOM 环同径），仅相位/跨度/速度/色相逐节点差化 */
    const nodeStates = options.nodeStates.value;
    options.nodePositions.forEach((_, i) => {
      const satRand = mulberry32(0x6b21 + i * 8191);
      satBezel.push(makeSatBezelPath(satRand() * Math.PI * 2));
      const satStroke = `${WATER_EDGE[i % WATER_EDGE.length]}1)`;
      satAccent.push({
        radius: SAT_R_BEZEL,
        span: SAT_ACCENT_SPAN[0] + satRand() * (SAT_ACCENT_SPAN[1] - SAT_ACCENT_SPAN[0]),
        theta: satRand() * Math.PI * 2,
        omega:
          (SAT_ACCENT_OMEGA[0] + satRand() * (SAT_ACCENT_OMEGA[1] - SAT_ACCENT_OMEGA[0])) *
          (satRand() < 0.5 ? -1 : 1),
        width: 1.3 + satRand() * 0.5,
        alpha: 0.34 + satRand() * 0.14,
        stroke: satStroke,
      });
      satInner.push({
        radius: SAT_INNER_R,
        span: SAT_INNER_SPAN[0] + satRand() * (SAT_INNER_SPAN[1] - SAT_INNER_SPAN[0]),
        theta: satRand() * Math.PI * 2,
        omega: SAT_INNER_OMEGA[0] + satRand() * (SAT_INNER_OMEGA[1] - SAT_INNER_OMEGA[0]),
        width: 0.8,
        alpha: 0.2 + satRand() * 0.12,
        stroke: satStroke,
      });
      const st = SAT_STATE[nodeStates[i]] ?? SAT_STATE['state-off'];
      satSpanSpring.push(makeSpring(26, 1.0, st.span));
      satHue.push([st.rgb[0], st.rgb[1], st.rgb[2]]);
      satDim.push(nodeStates[i] === 'state-off' ? 1 : 0);
    });
    // 发光贴图 + 核心暗核贴图（离屏一次栅格化，逐帧零渐变构建）
    SPRITE_COLORS.forEach((c) => sprites.push(makeSprite(c)));
    nucleusSprite = makeNucleusSprite();
  }

  /* ============================================================
   * 尺寸自适应（ResizeObserver + DPR）
   * ============================================================ */

  let resizeObserver: ResizeObserver | null = null;

  /* 性能根治：缓存面板 rect（applySize/ResizeObserver 时刷新）—
   * onPointerMove 高频触发，每次 getBoundingClientRect 强制布局读取
   * 会打断渲染流水线（量子面板鼠标卡顿源之一） */
  let panelRect = { left: 0, top: 0, width: 1, height: 1 };

  function applySize(): void {
    if (!panelEl || !canvasEl) return;
    const rect = panelEl.getBoundingClientRect();
    panelRect = { left: rect.left, top: rect.top, width: Math.max(rect.width, 1), height: Math.max(rect.height, 1) };
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = rect.width;
    height = rect.height;
    minDim = Math.min(width, height) || 1;
    /* 光水样式随尺寸重建（须在 minDim 更新之后、且 buildPools 已建连线之后） */
    buildWaterStyles();
    canvasEl.width = Math.round(width * dpr);
    canvasEl.height = Math.round(height * dpr);
    canvasEl.style.width = `${width}px`;
    canvasEl.style.height = `${height}px`;
    // setTransform 重置再缩放：物理坐标系 = CSS 像素（DPR 抗锯齿）
    ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    // 尺寸守卫：无效（容器过渡/未布局）→ 冻结编排；无效→有效的跃迁瞬间启动编排
    const valid = width >= SIZE_VALID_MIN && height >= SIZE_VALID_MIN;
    if (valid && !sizeValid) {
      sizeValid = true;
      introTime = 0;
      /* 冻结期间 frame 早退不更新墙钟，恢复首帧同样需要守卫防跳变 */
      lastWallClock = -1;
    } else if (!valid) {
      sizeValid = false;
      introTime = -1;
    }
  }

  /* ============================================================
   * 指针交互（力场源 + 视差源 + hover 仲裁）
   * ============================================================ */

  function onPointerMove(e: PointerEvent): void {
    if (!panelEl) return;
    /* 用 applySize 缓存的 rect（ResizeObserver 时刷新）— 去高频强制布局读取 */
    pointerX = e.clientX - panelRect.left;
    pointerY = e.clientY - panelRect.top;
    pointerInside = true;
    // 视差目标：归一化 -1..1（单帧内被 rAF 消费，延迟 ≤1 帧）
    parallaxX.target = (pointerX / panelRect.width - 0.5) * 2;
    parallaxY.target = (pointerY / panelRect.height - 0.5) * 2;
    fieldPower.target = 1;
  }

  function onPointerLeave(): void {
    pointerInside = false;
    fieldPower.target = 0;
    parallaxX.target = 0;
    parallaxY.target = 0;
  }

  /** 绑定节点 hover（P1 优先级：抑制视差 + 弹簧缩放 + 连线增益）
   * 经 AbortController signal 注册，destroy 时统一移除 */
  function bindNodeHover(el: HTMLElement, idx: number): void {
    const signal = listenerAbort?.signal;
    el.addEventListener('pointerenter', () => {
      hoverCount.n++;
      nodeSprings[idx].target = 1;
    }, { signal });
    el.addEventListener('pointerleave', () => {
      hoverCount.n = Math.max(0, hoverCount.n - 1);
      nodeSprings[idx].target = 0;
    }, { signal });
  }

  function bindCoreHover(): void {
    if (!coreEl) return;
    const signal = listenerAbort?.signal;
    coreEl.addEventListener('pointerenter', () => {
      hoverCount.n++;
      coreHover.target = 1;
    }, { signal });
    coreEl.addEventListener('pointerleave', () => {
      hoverCount.n = Math.max(0, hoverCount.n - 1);
      coreHover.target = 0;
    }, { signal });
  }

  /* ============================================================
   * 渲染辅助
   * ============================================================ */

  /** 高斯力场衰减（自然梯度，无硬边界）。
   *  截断前置：超出可感半径直接返回零，逐粒免去 Math.exp 求值；
   *  分母为构建期常量（原每次调用重算 2σ²）。 */
  function fieldInfluence(x: number, y: number): number {
    if (!pointerInside || fieldPower.v < 0.01) return 0;
    const dx = x - pointerX;
    const dy = y - pointerY;
    const d2 = dx * dx + dy * dy;
    if (d2 > FIELD_CUTOFF2) return 0;
    return Math.exp(-d2 / FIELD_SIGMA2) * fieldPower.v;
  }

  /** 二次贝塞尔求值（写入预分配缓冲 — 光水采样与数据包共用，零分配） */
  function bezierInto(
    x0: number, y0: number, cx: number, cy: number,
    x1: number, y1: number, t: number, out: Float64Array,
  ): void {
    const u = 1 - t;
    out[0] = u * u * x0 + 2 * u * t * cx + t * t * x1;
    out[1] = u * u * y0 + 2 * u * t * cy + t * t * y1;
  }

  /**
   * 连线当帧几何（基础连线与光水共用同一几何源 — 严禁两处各算一套）。
   * 写入 geoms[i]（零分配），返回同一对象供本帧消费。
   * 起终点均为静态坐标：起点 = 圆环静态中心，终点 = 装饰环环沿
   * —— 三条连线与三个模块同属零视差组（见视差偏移段）。
   */
  function computeLinkGeom(
    i: number, cx: number, cy: number, linkIntro: number,
  ): LinkGeom {
    const link = links[i];
    const g = geoms[i];
    /* 终点：环心（节点 DOM 锚点 = 装饰环圆心，见 qd-panel.css 的
       .qd-module-node）沿「圆环中心 → 环心」方向回缩至环沿（LINK_DOCK_R）
       —— 线尾对接在环沿，绝不进入环内空间（终点取环心会穿过悬浮字形）。
       节点与圆环距离不足回缩量时退化为环心：节点坐标来自可编辑的
       nodePositions 入参，属输入边界。 */
    const rx = nodePx[i].x;
    const ry = nodePx[i].y;
    const dx = rx - cx;
    const dy = ry - cy;
    const dl = Math.sqrt(dx * dx + dy * dy) || 1;
    const dockR = dl > LINK_DOCK_R ? LINK_DOCK_R : dl;
    g.nx = rx - (dx / dl) * dockR;
    g.ny = ry - (dy / dl) * dockR;
    /* 起点：圆环静态中心（无深度剪切 — 圆环本身不位移） */
    g.sx = cx;
    g.sy = cy;
    /* 控制点：中点 + 法向弓曲 + 漂移（弓曲随入场从 1.6 倍绷紧收敛） */
    g.mx = (cx + g.nx) / 2;
    g.my = (cy + g.ny) / 2;
    const nxv = -(g.ny - cy);
    const nyv = g.nx - cx;
    const nl = Math.sqrt(nxv * nxv + nyv * nyv) || 1;
    const bow = (link.bow + link.drift(elapsed) * 3) * (minDim / 540) * (1.6 - 0.6 * linkIntro);
    g.cpx = g.mx + (nxv / nl) * bow;
    g.cpy = g.my + (nyv / nl) * bow;
    return g;
  }

  /** 采样连线为光水路径（等参数步长，零分配），返回有效点数 */
  function sampleLink(i: number): number {
    const g = geoms[i];
    const xs = waterXs[i];
    const ys = waterYs[i];
    const last = WATER_MAX_POINTS - 1;
    for (let k = 0; k <= last; k++) {
      bezierInto(g.sx, g.sy, g.cpx, g.cpy, g.nx, g.ny, k / last, bezOut);
      xs[k] = bezOut[0];
      ys[k] = bezOut[1];
    }
    return WATER_MAX_POINTS;
  }

  /* ============================================================
   * 节点装饰环（图标与卫星环饰共用同一曲线/系数 — 单一权威）
   * ============================================================ */

  /** 节点苏醒相位（环饰与图标同一条错峰曲线 — 严禁两处各算一套） */
  function nodeIntroPhase(running: boolean, it: number, i: number): number {
    return running ? phase(it, 0.45 + i * 0.12, 0.7) : 1;
  }

  /** 装饰环缩放系数（环饰与图标同源 — 单一权威） */
  function orbScaleOf(p: number, hover: number): number {
    return (0.72 + 0.28 * p) * (1 + hover * 0.1);
  }

  /** 钟形端点渐隐弧段（本地坐标：环心为原点，半径/角度均由调用方给定）——
   *  与吸积弧共用同一钟形形态语言，且跳过权重为 0 的首末段（免无谓描边） */
  function strokeSatArc(
    c: CanvasRenderingContext2D, radius: number, span: number, mid: number, alpha: number,
  ): void {
    for (let s = 0; s < SAT_SEGS; s++) {
      const bell = SAT_BELL[s];
      if (bell <= 0.001) continue;
      c.globalAlpha = alpha * bell;
      c.beginPath();
      c.arc(0, 0, radius, mid + span * (s / SAT_SEGS - 0.5), mid + span * ((s + 1) / SAT_SEGS - 0.5));
      c.stroke();
    }
  }

  /**
   * 描绘卫星环饰（模块节点的引力锚点环）。
   *
   * 与吸积盘完全同一套渲染语言：钟形端点渐隐的断裂弧 + 预渲染贴图 + additive
   * 发光 + 模块色相。层次（由后至前）：捕获光晕 → 静态刻度环 → 外圈自转能量弧
   * → 内圈反向自转弧 → 状态扇段。全部绘于节点像素坐标（= 装饰环心），
   * 缩放系数与节点图标同源，故环饰与图标严格同步、且不产生任何 DOM transform。
   *
   * 调用位置契约：须在节点像素坐标写入之后、能量连线之前 —— 连线终点对接在
   * 环沿（LINK_DOCK_R），环饰压在连线之下，故线尾落在环沿上、不穿过环内空间。
   */
  function drawSatellites(c: CanvasRenderingContext2D, introRunning: boolean, it: number, dt: number): void {
    const states = options.nodeStates.value;
    for (let i = 0; i < nodePx.length; i++) {
      const spring = nodeSprings[i];
      const hover = spring ? spring.v : 0;
      const p = nodeIntroPhase(introRunning, it, i);
      const k = orbScaleOf(p, hover);
      const px = nodePx[i].x;
      const py = nodePx[i].y;

      /* 状态过渡（原 DOM 版由 CSS 过渡承担，现由本引擎统一承担）：
         跨度由弹簧驱动、色相逐帧插值、休眠压暗连续收敛 —— 状态切换全程无硬跳 */
      const key = states[i];
      const st = SAT_STATE[key] ?? SAT_STATE['state-off'];
      satSpanSpring[i].target = st.span;
      satDim[i] += ((key === 'state-off' ? 1 : 0) - satDim[i]) * Math.min(1, dt * 5);
      const dim = 1 - (1 - SAT_DORMANT_ALPHA) * satDim[i];
      const hue = satHue[i];
      const hueK = Math.min(1, dt * 6);
      hue[0] += (st.rgb[0] - hue[0]) * hueK;
      hue[1] += (st.rgb[1] - hue[1]) * hueK;
      hue[2] += (st.rgb[2] - hue[2]) * hueK;
      /* 环饰能量：入场苏醒 × 悬浮应答 × 休眠压暗（三者同一乘子链） */
      const energy = p * dim * (1 + hover * SAT_HOVER_LIFT);

      /* 捕获光晕（预渲染贴图 — 与核心暗核/辉点同一素材体系；浓度 ≤0.15，克制） */
      const halo = SAT_R_BEZEL * k * SAT_HALO_SCALE;
      c.globalAlpha = SAT_HALO_ALPHA * energy;
      c.drawImage(sprites[i % sprites.length], px - halo / 2, py - halo / 2, halo, halo);

      /* 环饰本体：本地坐标（环心为原点）+ 与图标同源的缩放 */
      c.save();
      c.translate(px, py);
      c.scale(k, k);

      /* 静态刻度环（三段非均匀断裂弧 + 三处断口刻度；构建期成路径，逐帧一次描边） */
      c.globalAlpha = 0.16 * energy;
      c.lineWidth = SAT_BEZEL_WIDTH;
      c.strokeStyle = 'rgba(176,202,220,1)';
      c.stroke(satBezel[i]);

      /* 外圈自转能量弧：模块色相（与连线/光水同源），钟形端点渐隐；悬浮时增亮增粗 */
      const accent = satAccent[i];
      accent.theta += accent.omega * dt;
      c.strokeStyle = accent.stroke;
      c.lineWidth = accent.width * (1 + hover * 0.25);
      strokeSatArc(c, accent.radius, accent.span, accent.theta, accent.alpha * energy);

      /* 内圈反向自转弧：制造纵深（与吸积盘的内外圈层次同构） */
      const inner = satInner[i];
      inner.theta += inner.omega * dt;
      c.strokeStyle = inner.stroke;
      c.lineWidth = inner.width;
      strokeSatArc(c, inner.radius, inner.span, inner.theta, inner.alpha * energy);

      /* 状态扇段：恒居正上方，跨度（弹簧）× 色相（插值）双通道编码状态 */
      c.strokeStyle = `rgb(${hue[0] | 0},${hue[1] | 0},${hue[2] | 0})`;
      c.lineWidth = 1.8;
      strokeSatArc(c, SAT_R_BEZEL, satSpanSpring[i].v * Math.PI * 2, -Math.PI / 2, 0.9 * energy);

      c.restore();
    }
  }

  /* ============================================================
   * 主循环（物理积分 → DOM 层写入 → Canvas 绘制）
   * ============================================================ */

  function frame(_frameStep: number, wallClock: number): void {
    if (!ctx) return;
    // 尺寸守卫：容器处于过渡/未布局（尺寸无效）时不渲染不推进，续命等待 ResizeObserver
    if (!sizeValid) return;

    /* ---- 光水完成事件帧（双帧约定）：领取一次性完成事件 → 停帧
       （保留最后一帧作为静态视觉参与 CSS 离场）→ 驱动视图切换 ----
       本段置于自限节拍之前：完成事件不受节拍延迟。 */
    if (flowCompletePending) {
      flowCompletePending = false;
      flow.consumeComplete();
      stop();
      options.onFlowComplete?.(flowSection);
      return;
    }

    /* ---- 自限渲染节拍（见 RENDER_MIN_INTERVAL_S）：未达门限的 rAF 整帧跳过。
       跳过不推进 lastWallClock，故下一执行帧的 wStep 覆盖被跳过的全部时间。
       光水仪式豁免本门限：其为 ≤1.02s 的一次性编排，前缘光点行进速度远高于
       任何稳态运动 —— 在高刷屏（自限节拍按 1/75s 抽帧）上行进头部会被读作
       「跳动」；关键动画按满帧渲染，与 playFlow 的 resetIdle 同属既定裁定。 */
    const ritualInFlight = flow.phase === 'propagating' || flow.phase === 'landing';
    if (!ritualInFlight && lastWallClock >= 0 && wallClock - lastWallClock < RENDER_MIN_INTERVAL_S) return;

    // 时间分离：漂移/入场相位用墙钟增量（流速恒 1×）；物理积分用同一增量
    const frameStartMs = performance.now();
    const wStep = lastWallClock < 0 ? 0 : Math.max(wallClock - lastWallClock, 0);
    lastWallClock = wallClock;
    /* 物理步进取「引擎自身相邻执行帧间隔」（wStep）而非门控 frameStep：
       自限节拍下帧门控仍逐 rAF 调用本引擎，其 frameStep 只是一个 rAF 间隔，
       沿用会让弹簧/轨道在自限节拍下按倍数变慢。dt 由 wStep 自洽推导，
       帧门控的累积语义（跳帧不推进基准）在此由本引擎自行等价保证。 */
    const dt = Math.min(wStep, DT_CLAMP);
    elapsed += wStep;
    introTime += wStep;
    frameCount++;
    /* 光水仪式推进（墙钟驱动，帧率无关 — 与引导区同规范；idle 阶段返回全零） */
    const fr = flow.advance(elapsed);

    /* ---- 弹簧积分（全部二阶系统，先积分后消费） ---- */
    springStep(parallaxX, dt);
    springStep(parallaxY, dt);
    springStep(fieldPower, dt);
    springStep(hoverSuppress, dt);
    springStep(coreHover, dt);
    springStep(coreReadySpring, dt);
    nodeSprings.forEach((s) => springStep(s, dt));
    satSpanSpring.forEach((s) => springStep(s, dt));

    /* ---- 入场编排主时钟：introTime 由 applySize 的尺寸有效跃迁归零 ---- */
    const it = introTime;
    // 编排总时长（最后窗口 0.45+3*0.12+0.7 ≈ 2.2s），结束后各系数恒 1（免重复求值）
    const introRunning = it < 2.4;

    /* ---- 交互优先级仲裁：hover（P1）期间视差幅度衰减至 50%（P2 让位） ----
       让位系数由 hoverSuppress 弹簧连续过渡 — 原对输出乘 0.5/1.0
       硬步进，pointerenter 瞬间产生最多 ~11px 的层位移跳变（突兀主因）；
       入场期间视差幅度随 introPar 渐起（挂载瞬间无大幅位移跳变） */
    hoverSuppress.target = hoverCount.n > 0 ? 0.5 : 1;
    const introPar = introRunning ? phase(it, 0.2, 1.2) : 1;
    const px = parallaxX.v * hoverSuppress.v * introPar;
    const py = parallaxY.v * hoverSuppress.v * introPar;

    /* ---- 视差偏移（仅 Canvas 内部：far 尘埃 / debris 数据碎片） ----
     * 零视差（有意设计，全部恒居静态坐标）：
     *   - 圆环整组（吸积盘 / 暗核 / 核心辉点 + 核心文字近层）；
     *   - 模块节点三个（DOM 中层不再有位移写入 → 节点层静止）；
     *   - 三条能量连线及其数据包、光水路径（起点 = 圆环静态中心，
     *     终点 = 节点静态像素坐标）。
     * 仍保留视差的：尘埃（系数 5）与数据碎片（系数 13 × 0.8）——
     * 二者均为圆环「背后」的氛围元素，只作用于 Canvas 绘制坐标，
     * 不产生任何 DOM 层位移（无合成层、无重采样、无文字清晰度代价）。 */
    const farOx = -px * 5 + driftFar(elapsed) * 1.1;
    const farOy = -py * 5 + driftFar(elapsed + 37) * 1.1;
    const debrisOx = -px * 13 + driftDebris(elapsed) * 1.9;
    const debrisOy = -py * 13 + driftDebris(elapsed + 53) * 1.9;

    /* ---- DOM 层写入（绕过 Vue 响应式，直接 transform，GPU 合成） ----
     * 逐帧写入仅装饰球体一处（缩放）；节点层与核心文字层均静态。 */
    /* 节点入场：文字层只淡入（缩放归装饰球体，见下）；
       核心文字簇同样只淡入且不位移 —— 悬浮应答完全由吸积盘与核心辉点的
       能量增益承担（Canvas 侧），核心文字存活期间不参与任何位移/缩放/旋转。 */
    nodeEls.forEach((el, i) => {
      const p = nodeIntroPhase(introRunning, it, i);
      el.style.opacity = p.toFixed(3);
      const orb = orbEls[i];
      if (orb) {
        /* 装饰环（矢量图标 — 无字形栅格化）：入场涌现 + 悬浮磁吸放大；
           缩放系数与 Canvas 侧卫星环饰共用 orbScaleOf（单一权威 → 环饰与图标同步） */
        orb.style.transform = `scale(${orbScaleOf(p, nodeSprings[i].v).toFixed(4)})`;
      }
    });
    if (coreEl) {
      /* 核心文字簇最先浮现（0.1s 起，先于全部节点与连线） */
      const p = introRunning ? phase(it, 0.1, 0.8) : 1;
      coreEl.style.opacity = p.toFixed(3);
    }

    /* ---- Canvas 绘制 ---- */
    ctx.clearRect(0, 0, width, height);
    const cx = width / 2;
    const cy = height / 2;
    const readyT = coreReadySpring.v;

    // ---- far 层：引力尘埃（椭圆轨道 + 内旋吸收 + 力场漩涡偏移） ----
    ctx.globalCompositeOperation = 'lighter';
    for (let i = 0; i < activeDust; i++) {
      const d = dustPool[i];
      // 轨道积分
      d.theta += d.omega * dt;
      d.r += d.rVel * dt;
      d.fade = Math.min(1, d.fade + dt * 1.6);
      // 视界吸收 → 外圈重生（统一边界消散规则）
      if (d.r < HORIZON_R) {
        respawnDust(d);
        continue;
      }
      // 噪声扰动轨道半径（连续非重复）
      const rJit = 1 + Math.sin(elapsed * 0.7 + d.seed) * 0.02;
      // 入场：逐粒错峰淡入（seed/1000 ∈ 0..1 离散相位）+ 半径从外圈 1.18 倍收敛（引力场苏醒、尘埃被吸入）
      const ip = introRunning ? phase(it, 0.15 + (d.seed / 1000) * 0.35, 1.0) : 1;
      const rr = d.r * minDim * rJit * (1.18 - 0.18 * ip);
      // 椭圆坐标变换 + 倾角旋转
      const ex = Math.cos(d.theta) * rr;
      const ey = Math.sin(d.theta) * rr * d.ecc;
      const ct = Math.cos(d.tilt);
      const st = Math.sin(d.tilt);
      let x = cx + ex * ct - ey * st + farOx;
      let y = cy + ex * st + ey * ct + farOy;
      // 高斯力场：切向漩涡 + 微径向斥离（差异化力场响应）
      const inf = fieldInfluence(x, y);
      if (inf > FIELD_EPSILON) {
        const dx = x - pointerX;
        const dy = y - pointerY;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const swirl = inf * 15;
        x += (-dy / dist) * swirl + (dx / dist) * inf * 5;
        y += (dx / dist) * swirl + (dy / dist) * inf * 5;
      }
      // 视界附近亮度自然衰减（吸入变暗，无突变）
      const horizonFade = Math.min(1, (d.r - HORIZON_R) / 0.05);
      const alpha = d.alpha * d.fade * horizonFade * ip;
      if (alpha < 0.02) continue;
      const half = d.size / 2;
      ctx.globalAlpha = alpha;
      ctx.drawImage(sprites[d.sprite], x - half, y - half, d.size, d.size);
    }

    // ---- mid 层：卫星环饰 + 能量连线 + 数据包 + 数据碎片 ----
    // 节点像素坐标（原地写入预分配缓冲，无偏移 —— 与静态 DOM 节点层严格一致）
    for (let i = 0; i < nodePx.length; i++) {
      const p = options.nodePositions[i];
      nodePx[i].x = (p.x / 100) * width;
      nodePx[i].y = (p.y / 100) * height;
    }

    /* 卫星环饰（模块节点的引力锚点环 — 与吸积盘同一渲染语言）：须在连线之前
       描绘，线尾对接在环沿（LINK_DOCK_R）→ 环饰压在连线之下，线不穿过环内空间 */
    drawSatellites(ctx, introRunning, it, dt);

    // 连线（贝塞尔 + 弓曲噪声微动 + 鼠标高斯增益；入场 0.5s 起"绷紧"点亮，最晚苏醒）
    const linkIntro = introRunning ? phase(it, 0.5, 0.8) : 1;
    /* 连线描边色在组内恒定 — 提出循环（逐帧仅写 globalAlpha / lineWidth） */
    ctx.strokeStyle = 'rgba(0,212,255,0.5)';
    for (let i = 0; i < links.length; i++) {
      const link = links[i];
      const g = computeLinkGeom(i, cx, cy, linkIntro);

      // 鼠标增益：中点距离高斯衰减（自然梯度；分母为构建期常量）
      const mdx = g.mx - pointerX;
      const mdy = g.my - pointerY;
      const boost = Math.exp(-(mdx * mdx + mdy * mdy) / LINK_SIGMA2) * fieldPower.v;
      link.glow += (boost - link.glow) * Math.min(1, dt * 8);
      // 节点 hover 时对应连线能量增益（交互联动）
      const nodeHoverGain = nodeSprings[i]?.v ?? 0;

      // 绘制连线（三层明暗：基础 + 增益段；弓曲随入场从 1.6 倍绷紧收敛）
      ctx.globalAlpha = (0.16 + link.glow * 0.3 + nodeHoverGain * 0.2) * linkIntro;
      ctx.lineWidth = 1 + link.glow * 0.8 + nodeHoverGain * 0.6;
      ctx.beginPath();
      ctx.moveTo(g.sx, g.sy);
      ctx.quadraticCurveTo(g.cpx, g.cpy, g.nx, g.ny);
      ctx.stroke();

      // 数据包流动（速度各异，拒绝同步；路径与连线曲线严格一致）
      for (const p of link.packets) {
        p.t += p.speed * dt * (1 + link.glow * 1.6 + nodeHoverGain * 0.8);
        if (p.t > 1) p.t -= 1;
        /* 位置写入预分配缓冲（零分配）—— 原每包每帧返回新对象 */
        bezierInto(g.sx, g.sy, g.cpx, g.cpy, g.nx, g.ny, p.t, pktOut);
        const pxA = (0.5 + link.glow * 0.5 + nodeHoverGain * 0.3) * linkIntro;
        ctx.globalAlpha = pxA * Math.sqrt(Math.sin(p.t * Math.PI));
        const psz = p.size + link.glow * 1.5;
        ctx.drawImage(sprites[p.sprite], pktOut[0] - psz / 2, pktOut[1] - psz / 2, psz, psz);
      }
    }

    /* ---- 光水（中心 → 模块节点）：传播期自中心流向三节点，落定期整体淡出 ----
     * 仅仪式进行中描绘（idle/done 帧 fr 全零 → 零开销）；
     * 路径取连线几何单一源，故水带与既有能量连线严格重合（终点即环沿）；
     * 前缘位置经 flowHeadEase 缓动 —— 匀速推进读作「起步即全速、到点即撞停」。 */
    if (fr.propagation > 0) {
      const waterFade = 1 - fr.landing;
      const head = flowHeadEase(fr.propagation);
      for (let i = 0; i < links.length && i < waterStyles.length; i++) {
        const n = sampleLink(i);
        drawWaterFlow(
          ctx, waterXs[i], waterYs[i], n,
          head, waterFade, waterStyles[i], sprites[i % sprites.length],
        );
      }
      /* 落定：节点光晕扩散（与到达同帧起势，扩散同时淡出） */
      if (fr.landing > 0) {
        const eased = 1 - Math.pow(1 - fr.landing, 3);
        const bloomScale = Math.max(0.7, Math.min(1.9, minDim / 540));
        const rad = (16 + eased * 30) * bloomScale;
        ctx.globalAlpha = 0.5 * (1 - eased);
        for (let i = 0; i < nodePx.length; i++) {
          ctx.drawImage(sprites[3], nodePx[i].x - rad, nodePx[i].y - rad, rad * 2, rad * 2);
        }
        ctx.globalAlpha = 1;
      }
    }

    // 数据碎片（切向线段，数据流残影；入场 0.35s 起淡入，晚于尘埃）
    const shardIntro = introRunning ? phase(it, 0.35, 1.0) : 1;
    /* 碎片描边色线宽在组内恒定 — 提出循环：逐帧仅写入 globalAlpha，
       免去逐粒色串赋值（原 26 次/帧的颜色解析） */
    ctx.strokeStyle = 'rgba(0,220,255,0.6)';
    ctx.lineWidth = 1;
    for (let i = 0; i < activeShards; i++) {
      const s = shardPool[i];
      s.theta += s.omega * dt;
      s.fade = Math.min(1, s.fade + dt * 1.4);
      const rr = s.r * minDim;
      /* 碎片是圆环「背后」仍保留视差的氛围层（系数 13×0.8）——
         只作用于 Canvas 绘制坐标，不产生任何 DOM 位移 */
      let x = cx + Math.cos(s.theta) * rr + debrisOx * 0.8;
      let y = cy + Math.sin(s.theta) * rr * 0.92 + debrisOy * 0.8;
      const inf = fieldInfluence(x, y);
      if (inf > FIELD_EPSILON) {
        const dx = x - pointerX;
        const dy = y - pointerY;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        x += (-dy / dist) * inf * 12;
        y += (dx / dist) * inf * 12;
      }
      // 切向方向（垂直半径）
      const tx = -Math.sin(s.theta);
      const ty = Math.cos(s.theta) * 0.92;
      const len = s.len * (minDim / 540);
      ctx.globalAlpha = s.alpha * s.fade * (0.7 + inf * 1.2) * shardIntro;
      ctx.beginPath();
      ctx.moveTo(x - tx * len / 2, y - ty * len / 2);
      ctx.lineTo(x + tx * len / 2, y + ty * len / 2);
      ctx.stroke();
    }

    // ---- near 层：中心吸积盘（非对称弧段组合 + 钟形端点渐隐） ----
    // 入场最先苏醒（0s 起）：暗核渐显 + 弧段半径自 0.6 展开至 1（黑洞成形感）
    const arcIntro = introRunning ? phase(it, 0, 0.9) : 1;
    const coreR = minDim * 0.24;
    /* 圆环整组（暗核 / 吸积弧 / 核心辉点）恒绘于面板中心（cx, cy）——
       与近层 DOM（核心文字）的静态居中严格重合：整组零视差，
       鼠标移动时圆环与核心文字一动不动（圆环背后的尘埃/连线/碎片
       与模块节点视差照旧，见上方偏移段）。 */
    /* 事件视界暗核（预渲染贴图，一次 drawImage 取代逐帧 createRadialGradient
       + fill —— 渐变对象每次新建、色带每帧重求值是逐帧常态开销；
       整体浓度（含 readyT 的细微增强）统一并入 globalAlpha 出口）。 */
    ctx.globalCompositeOperation = 'source-over';
    if (nucleusSprite) {
      ctx.globalAlpha = arcIntro * (0.85 + readyT * 0.1);
      ctx.drawImage(nucleusSprite, cx - coreR * 0.5, cy - coreR * 0.5, coreR, coreR);
    }

    // 吸积弧段（不等长/不等速/相异色 + hover/ready 能量应答）
    ctx.globalCompositeOperation = 'lighter';
    const energy = 1 + coreHover.v * 0.6 + readyT * 0.35;
    for (const arc of arcs) {
      arc.theta += arc.omega * dt * (1 + coreHover.v * 0.5);
      const rr = arc.radius * minDim * (1 + coreHover.v * 0.06) * (0.6 + 0.4 * arcIntro);
      /* 描边色在弧内恒定（构建期一次拼定）—— 提出内层循环，逐帧色串由
         56 次降为 4 次，且不再逐段产生字符串分配与 CSS 颜色解析 */
      ctx.strokeStyle = arc.stroke;
      // 弧段拆分：alpha 沿弧钟形分布（端点渐隐，无硬边）；权重查 LUT
      for (let s = 0; s < ARC_SEGS; s++) {
        const t0 = s / ARC_SEGS;
        const t1 = (s + 1) / ARC_SEGS;
        const a0 = arc.theta + arc.span * (t0 - 0.5);
        const a1 = arc.theta + arc.span * (t1 - 0.5);
        const bell = ARC_BELL[s];
        ctx.globalAlpha = arc.alpha * bell * energy * arcIntro;
        ctx.lineWidth = arc.width * (0.8 + bell * 0.4);
        ctx.beginPath();
        ctx.arc(cx, cy, rr, a0, a1);
        ctx.stroke();
      }
    }

    /* 核心辉点（吸积盘内缘能量斑）—— 静态亮度：只随悬浮/就绪状态即时变化，
       不含任何周期性调制（呼吸效果按设计整体移除，勿再引入时间项）。
       就绪色（青绿）与未就绪色（青）按 readyT 连续交叉淡化 —— 原实现
       在 readyT 跨 0.5 时整枚贴图硬切换，过渡中途出现一次色彩跳变。 */
    const coreGlowLevel =
      CORE_GLOW.base + coreHover.v * CORE_GLOW.hoverLift + readyT * CORE_GLOW.readyLift;
    const coreAlpha = Math.min(CORE_GLOW.ceil, coreGlowLevel) * arcIntro;
    const coreSize = 10 + coreHover.v * 5 + readyT * 3;
    const glowX = cx - coreSize / 2;
    const glowY = cy - coreSize / 2;
    /* 两枚贴图按 readyT 加权相加（lighter 混合下强度直接叠加）——
       权重为 0 的一侧跳过绘制，稳态仍为单枚绘制 */
    if (readyT < 0.999) {
      ctx.globalAlpha = coreAlpha * (1 - readyT);
      ctx.drawImage(sprites[0], glowX, glowY, coreSize, coreSize);
    }
    if (readyT > 0.001) {
      ctx.globalAlpha = coreAlpha * readyT;
      ctx.drawImage(sprites[3], glowX, glowY, coreSize, coreSize);
    }

    ctx.globalAlpha = 1;
    ctx.globalCompositeOperation = 'source-over';

    /* ---- 光水落定逻辑完成帧：本帧已渲染完整淡出（浓度归零），下一帧
       领取一次性完成事件（双帧约定，保证淡出画面至少呈现过一帧） ---- */
    if (fr.complete) flowCompletePending = true;

    /* ---- 密度自适应（引擎自身耗时 EMA → 粒子密度增减，优先保证交互流畅） ----
       成本采样取本帧自测耗时（frame 体起止 performance.now 差），而非帧间隔：
       帧间隔只反映显示器刷新率（120/144Hz 屏恒 <14.5ms），据此评估会把
       密度持续抬到上限，使高刷屏上的引擎负载被无谓放大 2 倍以上。
       仅 active 档评估：低档位为有意降频，其单帧耗时含调度间隔，不反映
       真实渲染成本，据此降密度会在恢复交互后无谓回爬。 */
    const frameCostMs = performance.now() - frameStartMs;
    avgEngineCostMs = avgEngineCostMs * FRAME_EMA + frameCostMs * (1 - FRAME_EMA);
    if (idleLevel.value === 'active' && frameCount % ADAPT_INTERVAL === 0) {
      if (avgEngineCostMs > COST_HIGH_MS && activeDust > DUST_MIN) {
        activeDust = Math.max(DUST_MIN, activeDust - 10);
        activeShards = Math.max(SHARD_MIN, activeShards - 3);
      } else if (avgEngineCostMs < COST_LOW_MS && activeDust < DUST_MAX) {
        activeDust = Math.min(DUST_MAX, activeDust + 6);
        activeShards = Math.min(SHARD_MAX, activeShards + 2);
      }
    }
  }

  /* ============================================================
   * 生命周期（启动/暂停/销毁，资源全释放无泄漏）
   * ============================================================ */

  /* G-7：rAF 调度/空闲门控/失焦暂停全部由 useFrameGate 承担，
     start/stop 仅为门控代理（档位与恢复时机全局一致）。 */
  const { start: startGate, stop: stopGate } = useFrameGate(idleLevel, frame);

  function start(): void {
    /* 重启首帧守卫：循环停止期间墙钟持续前进，若沿用旧 lastWallClock
       会在恢复首帧产生巨大 wStep 跳变（暂停/销毁后重挂均覆盖） */
    lastWallClock = -1;
    startGate();
  }

  function stop(): void {
    stopGate();
  }

  function destroy(): void {
    stop();
    /* 光水仪式中断复位：卸载路径不得遗留完成待领取标志
       （否则重新 init 后首个推进帧会误发完成事件） */
    flow.reset();
    flowCompletePending = false;
    resizeObserver?.disconnect();
    resizeObserver = null;
    /* 一次 abort 移除全部监听器（面板级 + 全局交互 + 子元素 hover），
       替代逐项 removeEventListener，子元素监听器不再依赖 GC 回收 */
    listenerAbort?.abort();
    listenerAbort = null;
    ctx = null;
    canvasEl = null;
    panelEl = null;
    coreEl = null;
    nodeEls = [];
    orbEls = [];
  }

  /* ---------- 挂载（onMounted 时机由调用方触发 init） ---------- */

  /**
   * 初始化引擎（绑定 DOM + 构建池 + 启动循环）
   * @param nodeElsReady 模板 ref 数组已就绪的节点元素
   */
  function init(nodeElsReady?: HTMLElement[]): void {
    panelEl = options.panel.value;
    canvasEl = options.canvas.value;
    coreEl = options.coreCluster.value;
    nodeEls = nodeElsReady ?? options.nodes.value;
    /* 装饰球体引用（逐帧缩放目标）：承载文字的节点外层不参与缩放，
       故从节点子树中取装饰球体元素一次（节点结构与文字布局稳定，无需逐帧查询） */
    orbEls = nodeEls
      .map((el) => el.querySelector<HTMLElement>('.qd-node-orb'))
      .filter((el): el is HTMLElement => el !== null);
    if (!panelEl || !canvasEl) return;
    ctx = canvasEl.getContext('2d');
    if (!ctx) return;

    buildPools();
    applySize();

    /* 本生命周期全部监听器经 AbortController signal 注册，
       destroy() 一次 abort() 统一移除（重复 init 时重建 controller） */
    listenerAbort?.abort();
    listenerAbort = new AbortController();
    const sig = listenerAbort.signal;

    // 事件绑定（passive 提升滚动/指针性能）
    // G-7：visibilitychange 暂停与全局交互恢复满帧已由全局空闲调度器
    //    （useGlobalIdleScheduler）统一处理，此处仅保留面板级指针事件。
    panelEl.addEventListener('pointermove', onPointerMove, { passive: true, signal: sig });
    panelEl.addEventListener('pointerleave', onPointerLeave, { passive: true, signal: sig });

    // 节点/核心 hover 绑定（P1 交互优先级）
    nodeEls.forEach((el, i) => bindNodeHover(el, i));
    bindCoreHover();

    // 尺寸自适应（容器变化 → 画布同步，布局坐标系更新）
    resizeObserver = new ResizeObserver(applySize);
    resizeObserver.observe(panelEl);

    // 就绪状态弹簧同步
    coreReadySpring.target = options.coreReady.value ? 1 : 0;

    /* 入场编排按满帧渲染 — 面板挂载即交互（resetIdle），
       确保错峰入场编排全程 60fps 不降档。 */
    resetIdle();

    start();
  }

  // watch coreReady：吸积盘能量应答（弹簧过渡，无突变）
  const stopWatchReady = watch(options.coreReady, (v) => {
    coreReadySpring.target = v ? 1 : 0;
  });

  // 组件卸载兜底（Vue 生命周期内自动清理）
  onBeforeUnmount(() => {
    stopWatchReady();
    destroy();
  });

  /**
   * 启动光水仪式（幂等：进行中或完成待领取时拒绝本次调用）。
   *
   * 仪式语义：光水自中心沿三条连线流向模块节点（传播）→ 节点光晕扩散且
   * 光水整体淡出（落定）→ 完成事件帧领取 → 由 onFlowComplete 驱动视图切换。
   * 全程只由帧循环驱动，无固定延时等待（reduced-motion 下直通跳过）。
   *
   * @param section 完成事件回传的分区
   * @returns 是否被接受（false = 已有仪式在途，调用方应忽略本次点击）
   */
  function playFlow(section: DashboardSection): boolean {
    if (flow.phase !== 'idle' || flowCompletePending) return false;
    flowSection = section;
    /* 关键动画恢复满帧：仪式全程 60fps（交互已触发 active，此处兜底） */
    resetIdle();
    flow.begin();
    return true;
  }

  return { init, destroy, playFlow };
}

/** useQuantumField 返回值类型 */
export type UseQuantumFieldReturn = ReturnType<typeof useQuantumField>;
