/**
 * useSpectraTicks — 谱线组参数唯一权威源
 *
 * =============================================================================
 * 【方案定位】谱线（光谱发射线隐喻）跨场景共享的数据层：
 *   UnlockView（intro 变体 — 充能/驻留/塌缩三态编排）
 *   HomeView  （echo 变体  — 静默回声：入场生长 + 驻留微脉动 + 微跳）
 *
 * 两组件此前各自内联一份参数生成（hash/光谱色/时序）— 本 composable
 * 消除该重复；确定性 hash 域（salt/区间）与原实现逐值一致，视觉形态
 * 恒定（非随机漂移）。
 *
 * 样式层同步共享（styles/animations.css）：
 *   .spectra-tick 基础 + spectra-breathe（呼吸）+ spectra-jitter（微跳）
 *   — keyframes 只写 @property 注册变量（--sbr/--sjt），transform 基线
 *   组合两条独立动画通道，双动画叠加互不覆盖（合成器友好）。
 * =============================================================================
 */

/** 谱线变体：intro = 引导页充能组 / echo = 主界面静默回声 */
export type SpectraVariant = "intro" | "echo";

export interface SpectraTick {
  /** 线高（px） */
  h: number;
  /** 左间距（px，首线 0） */
  gap: number;
  /** 光谱色（青/紫/银/金加权 — rgba 串） */
  tc: string;
  /** 基线透明度 */
  op: string;
  /** 入场延迟（ms — 主界面 tick-in / 引导页 tick-charge） */
  td: number;
  /** 呼吸周期（s） */
  sd: string;
  /** 呼吸起始延迟（ms — 精确对齐自身入场结束时刻，无缝衔接零跳变） */
  sm: number;
  /** 微跳周期（s — 逐线差化散相） */
  jd: string;
  /** 微跳起始延迟（ms — 呼吸接入后再启用，自初值 0px 起步零跳变） */
  jp: number;
  /** 塌缩延迟（ms — 外缘先收，仅 intro 变体消费） */
  cl: number;
}

/** 确定性 hash（seed×salt 双域）— 逐元素独立参数，可控不规则偏差 */
const hash = (seed: number, salt: number): number => {
  const x = Math.sin(seed * 127.1 + salt * 311.7) * 43758.5453;
  return x - Math.floor(x);
};

export function useSpectraTicks(variant: SpectraVariant): SpectraTick[] {
  const intro = variant === "intro";
  const N = intro ? 9 : 6;
  /* intro：charged 类挂载时刻（与逆渡 INTRO_T 收束同步）— 呼吸延迟
   * 换算基准（充能未完的线，呼吸在其充能恰好结束后无缝接入） */
  const CHARGED_AT = 3050;
  const GROW_DUR = intro ? 900 : 700; // 入场动画时长（charge/tick-in）

  return Array.from({ length: N }, (_, i) => {
    const h = (n: number) => hash(i + (intro ? 41 : 17), n); // 变体独立 salt 域
    const cr = h(1);
    const base =
      cr < 0.4 ? "rgba(0,212,255," :
      cr < 0.68 ? "rgba(139,92,246," :
      cr < 0.88 ? "rgba(205,224,244," : "rgba(255,217,160,";
    const td = Math.round(
      intro ? 360 + i * 165 + h(6) * 140 : 520 + i * 115 + h(6) * 150,
    );
    /* 呼吸起始 = 自身入场结束时刻（intro 需再折算 charged 挂载时间差，≥0） */
    const sm = intro
      ? Math.max(0, td + GROW_DUR - CHARGED_AT)
      : td + GROW_DUR;
    return {
      h: Math.round(intro ? 8 + h(2) * 15 : 5 + h(2) * 6),
      gap: i === 0 ? 0 : Math.round(intro ? 9 + h(3) * 17 : 7 + h(3) * 8),
      tc: `${base}${((intro ? 0.5 : 0.42) + h(4) * (intro ? 0.38 : 0.3)).toFixed(2)})`,
      op: ((intro ? 0.55 : 0.45) + h(5) * (intro ? 0.35 : 0.28)).toFixed(2),
      td,
      sd: (intro ? 2.8 + h(7) * 1.7 : 4.2 + h(7) * 3.3).toFixed(2),
      sm,
      /* 微跳：周期 5.2-8.8s 逐线差化（长期散相拒绝同步机械跳）；
       * 起始 = 呼吸接入后再叠加差化延迟（首簇前关键帧自带静默段） */
      jd: (5.2 + h(9) * 3.6).toFixed(2),
      jp: Math.round(sm + h(11) * 1000),
      cl: Math.round(((N - 1) / 2 - Math.abs(i - (N - 1) / 2)) * 55),
    };
  });
}
