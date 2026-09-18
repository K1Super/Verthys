/*
 * app/constants.ts — 全局常量定义
 *
 *   所有动画延时、超时数字提取到全局常量，消除硬编码
 */

/** 点击正渡总时长（毫秒）— 渡越序列唯一权威源：
 * 引擎（ParticleBackground ENTER_T）与全部编排节点（预挂载 / 页面交接 /
 * 星河态切换 / 页面 materialize tokens.css --dur-page-enter）均由此派生 —
 * 调整渡越总时长只改此一处，编排相对节奏（包络锚点比例）保持不变 */
export const ENTER_T_MS = 5000;

/** ★ 双缓冲预挂载点（毫秒，自渡越时钟 0 点）：
 * = 弹射交接（320ms）+ 逐字弹射动画（620ms）+ 余量（160ms）。
 * MainView 在此时刻挂载进 prewarm 冻结层（visibility:hidden +
 * 动画 paused + pointer-events:none）——组件树构建 / 首次布局 /
 * composable 初始化的全部尖峰成本在蓄能段（视觉最平缓期）消化；
 * 交接帧（PAGE_HANDOFF）只剩一次 class 切换（零挂载零布局）。
 * 挂载过早 → 冻结期 JS 定时器错序放大；过晚 → 预热情不足。 */
export const PREWARM_MOUNT = 1100;

/** 页面流转与星河阶段转场节点（毫秒）— 由 ENTER_T_MS 等比派生
 * （引擎三段 C2 包络：0-30% 蓄能 / 30-62% 峰驻加速 / 62-100% 消散） */
export const TRANSITION = {
  /** 页面交接点 — UnlockView 淡出 / MainView materialize 启动
   *  = 包络 x=0.62（峰驻末端·消散起点：星系开始「松开」，
   *  界面同步自深度虚化中成型 — 「星系松开 → 界面浮现」叙事轴） */
  PAGE_HANDOFF: Math.round(ENTER_T_MS * 0.62),
  /** 星河从渡越进入流动状态 —
   *  = 包络 x=5/6（消散尾声，星河重组落位） */
  GALAXY_PHASE: Math.round((ENTER_T_MS * 5) / 6),
  /** ★ MainView 自预挂载起 → 渡越包络归零（氛围苏醒锚点）的等待时长：
   *  氛围引擎（163 元素满帧驱动）与模块分包预热以此避让渡越尾部 +
   *  materialize 全屏过渡的满帧窗口 —「星系落定后氛围苏醒」语义
   *  精确保持（预挂载提前量已内含：ENTER_T_MS - PREWARM_MOUNT） */
  MAINVIEW_AMBIENT_WAIT: ENTER_T_MS - PREWARM_MOUNT,
} as const;
