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

/** 启动逆渡时长（毫秒）— 引擎逆渡与引导页品牌编排的统一权威源 */
export const INTRO_T_MS = 3000;

/** 引导页编排节点（毫秒，自组件挂载起算）— 与 INTRO_T_MS 同源对齐 */
export const INTRO = {
  /** 副标题入场（逆渡消散段） */
  SUB_SHOWN: 2450,
  /** 谱线充能完毕 → 呼吸驻留（逆渡收束 + 50ms 余量） */
  CHARGED: INTRO_T_MS + 50,
  /** 进入提示浮现（逆渡完成后） */
  HINT_VISIBLE: INTRO_T_MS + 250,
} as const;

/** 双缓冲预挂载点（毫秒，自点击时刻起算）：
 * = 逐字弹射最晚起始（--ed ≤ 312ms）+ 弹射时长（620ms，弹射完成
 *   ≤ 932ms）+ 余量（≥ 168ms）。
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
  /** MainView 自预挂载起 → 渡越包络归零（氛围苏醒锚点）的等待时长：
   *  氛围引擎（163 元素满帧驱动）与模块分包预热以此避让渡越尾部 +
   *  materialize 全屏过渡的满帧窗口 —「星系落定后氛围苏醒」语义
   *  精确保持（预挂载提前量已内含：ENTER_T_MS - PREWARM_MOUNT） */
  MAINVIEW_AMBIENT_WAIT: ENTER_T_MS - PREWARM_MOUNT,
} as const;

/** 无障碍编排（prefers-reduced-motion）：引擎正渡整体停用（无大幅
 *  运动），页面流转压缩为短流程；预挂载节点沿用 PREWARM_MOUNT 不变
 *  （双缓冲时序要求交接必须晚于预挂载）。 */
export const TRANSITION_REDUCED = {
  /** 页面交接点：预挂载 + 200ms 消化余量 */
  PAGE_HANDOFF: PREWARM_MOUNT + 200,
  /** 星河态切换：交接后 200ms（取景已就位 — 无运镜） */
  GALAXY_PHASE: PREWARM_MOUNT + 400,
} as const;
