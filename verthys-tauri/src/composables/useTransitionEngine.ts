/*
 * useTransitionEngine.ts — 方向性渡越序列引擎（启动逆渡 / 点击正渡）
 *
 * 从 ParticleBackground.vue 抽离的纯数学状态机（零 THREE 依赖 — 可独立
 * 推演与测试）：复合强度与方向权重双通道求值、符号缠绕积分、幕布位移
 * 积分。ParticleBackground 每帧仅调用 update(dt) 并读取结果，
 * renderFrame 不持有任何序列状态。
 *
 * 打断路径设计（启动逆渡期间点击）：
 *   逆渡残余与正渡序列不做独立叠加 —— 叠加会使总强度先跌后升（失力
 *   谷值）、方向权重在短窗内穿轴反转（高速回转 + 相机过轴甩动）。
 *   改由两个结构统一承载：
 *   - 复合强度：以打断时刻的逆渡强度 e0 为起点的抬升剖面 —— 沿自然
 *     正渡剖面的同形抬升（e0 + (1-e0)·rise）单调升档至峰驻末端，其后
 *     转入消散；全程不回退，e0 趋零时退化为自然剖面（两条路径同族
 *     连续）。
 *   - 方向权重：单条换向曲线 —— 以打断瞬间的方向量与一/二阶导为起点
 *     （动量匹配，接缝无速率台阶）、以自然剖面平台点为终点（值/一阶/
 *     二阶三量匹配），窗口内一次穿越零点、无驻停段，随后并入自然
 *     剖面。
 *
 * 连续性契约：
 *   - 值连续：强度/方向在全路径零阶连续，无跳变；
 *   - 段内与段间二阶连续：包络三段、换向曲线、抬升剖面并入消散段、
 *     换向曲线并入自然剖面 —— 值/一阶/二阶全匹配；
 *   - 打断帧接续：方向通道二阶连续（值/一阶/二阶全匹配 — 动量连续
 *     换向，无接缝顿挫）；强度通道值连续，一阶为由来向斜率决定的
 *     有限台阶（上界 = 逆渡包络最大斜率）—— 强度受「值域受限 +
 *     不回退」约束，精确斜率匹配会迫使曲线过冲，此处以有限台阶换取
 *     值域与不回退严格成立。
 *
 * 时钟纪律：所有时钟无条件单调推进，绝不冻结；效果生效与否由完成
 * 标志独立守卫 —— 时钟停滞导致效果残留的问题从结构上排除。
 * 无障碍：prefers-reduced-motion 下跳过启动逆渡并停用正渡（无大幅
 * 运动），由 setReducedMotion 控制。
 */

import { ENTER_T_MS, INTRO_T_MS } from "../app/constants";

/** 启动逆渡时长（秒）：唯一权威源 = app/constants INTRO_T_MS */
export const INTRO_T = INTRO_T_MS / 1000;
/** 点击正渡时长（秒）：唯一权威源 = app/constants ENTER_T_MS */
export const ENTER_T = ENTER_T_MS / 1000;

/* ===== 换向窗口（秒）：单条二阶连续换向曲线（动量匹配，无驻停段） ===== */
const REVERSAL_T = 1.5;

/** 渡越峰值速度（units/s，远景幕布位移积分系数） */
const WARP_SPEED = 1200;

/* ===== 包络形状常数（归一化 x∈[0,1] — 三段 smootherstep，全程二阶连续） ===== */
const ENV_CHARGE_END = 0.3;
const ENV_PEAK_END = 0.62;
const ENV_CHARGE_LEVEL = 0.42;

/** smootherstep（五次多项式）及一/二阶导：两端 0/1 阶导全零 — 段间二阶匹配 */
const smootherstep = (u: number): number => u * u * u * (u * (u * 6 - 15) + 10);
const smootherstepD1 = (u: number): number => 30 * u * u * (1 - u) * (1 - u);
const smootherstepD2 = (u: number): number => 60 * u * (1 - u) * (1 - 2 * u);

/**
 * 复合渡越包络（归一化 x∈[0,1]，三段 smootherstep — 全程二阶连续）：
 *   蓄能段 x<0.30：0 → 0.42 ／ 峰驻段 0.30≤x<0.62：0.42 → 1.0 ／
 *   消散段 x≥0.62：1.0 → 0（引力井松开 — 平滑释放）。
 */
const warpEnvelope = (x: number): number => {
  if (x <= 0 || x >= 1) return 0;
  if (x < ENV_CHARGE_END) return ENV_CHARGE_LEVEL * smootherstep(x / ENV_CHARGE_END);
  if (x < ENV_PEAK_END)
    return (
      ENV_CHARGE_LEVEL +
      (1 - ENV_CHARGE_LEVEL) * smootherstep((x - ENV_CHARGE_END) / (ENV_PEAK_END - ENV_CHARGE_END))
    );
  return 1 - smootherstep((x - ENV_PEAK_END) / (1 - ENV_PEAK_END));
};

/** 包络一阶/二阶导（对 x）—— 换向并入点的切线条件 */
const warpEnvelopeD = (x: number): [number, number] => {
  if (x <= 0 || x >= 1) return [0, 0];
  if (x < ENV_CHARGE_END) {
    const u = x / ENV_CHARGE_END;
    return [
      (ENV_CHARGE_LEVEL * smootherstepD1(u)) / ENV_CHARGE_END,
      (ENV_CHARGE_LEVEL * smootherstepD2(u)) / (ENV_CHARGE_END * ENV_CHARGE_END),
    ];
  }
  if (x < ENV_PEAK_END) {
    const w = ENV_PEAK_END - ENV_CHARGE_END;
    const u = (x - ENV_CHARGE_END) / w;
    return [
      ((1 - ENV_CHARGE_LEVEL) * smootherstepD1(u)) / w,
      ((1 - ENV_CHARGE_LEVEL) * smootherstepD2(u)) / (w * w),
    ];
  }
  const w = 1 - ENV_PEAK_END;
  const u = (x - ENV_PEAK_END) / w;
  return [-smootherstepD1(u) / w, -smootherstepD2(u) / (w * w)];
};

/** 五次 Hermite 插值（值/一阶/二阶双端匹配）—— 换向曲线 */
const hermite5 = (
  u: number,
  p0: number,
  v0: number,
  a0: number,
  p1: number,
  v1: number,
  a1: number,
  span: number,
): number => {
  const u2 = u * u;
  const u3 = u2 * u;
  const u4 = u3 * u;
  const u5 = u4 * u;
  return (
    (1 - 10 * u3 + 15 * u4 - 6 * u5) * p0 +
    (u - 6 * u3 + 8 * u4 - 3 * u5) * span * v0 +
    (0.5 * u2 - 1.5 * u3 + 1.5 * u4 - 0.5 * u5) * span * span * a0 +
    (10 * u3 - 15 * u4 + 6 * u5) * p1 +
    (-4 * u3 + 7 * u4 - 3 * u5) * span * v1 +
    (0.5 * u3 - u4 + 0.5 * u5) * span * span * a1
  );
};

/** 换向并入相位（正渡 5000ms 下为 0.30 — 恰为蓄能段平台点） */
const REVERSAL_JOIN_X = REVERSAL_T / ENTER_T;
/** 并入点自然剖面的值/一阶/二阶（每秒制）— 平台点处为（0.42, 0, 0） */
const REVERSAL_JOIN_D = warpEnvelope(REVERSAL_JOIN_X);
const REVERSAL_JOIN_V = warpEnvelopeD(REVERSAL_JOIN_X)[0] / ENTER_T;
const REVERSAL_JOIN_A = warpEnvelopeD(REVERSAL_JOIN_X)[1] / (ENTER_T * ENTER_T);

/* ===== 积分历史采样器（环形缓冲 + 二分插值 — 缠绕积分共用） =====
 * 单调积分（渡越弧长）采样近期的 (t, v)；残影拖尾层按 t-lag 插值取
 * 历史值 → 弧形拖尾（早于最早样本 → 0：运动开始前）。
 * 时间戳单调递增 → 二分查找 O(log n)；
 * 预分配 Float32Array 环形覆盖写入 → O(1) 零分配（无每帧 push/shift）。 */
const HIST_CAPACITY = 64;

const createIntegralHistory = () => {
  const ts = new Float32Array(HIST_CAPACITY);
  const vs = new Float32Array(HIST_CAPACITY);
  let head = -1; // 最新样本物理索引
  let count = 0;

  /** 最旧样本物理索引（样本未满时为 0） */
  const oldestIndex = (): number => (head - count + 1 + HIST_CAPACITY) % HIST_CAPACITY;

  return {
    push(t: number, v: number): void {
      head = (head + 1) % HIST_CAPACITY;
      ts[head] = t;
      vs[head] = v;
      if (count < HIST_CAPACITY) count++;
    },
    /** 查询 time 时刻的积分值（早于最早样本 → 0：运动开始前） */
    at(time: number): number {
      if (count === 0) return 0;
      const oldest = oldestIndex();
      if (time <= ts[oldest]) return 0;

      /* 虚拟单调序 [0, count) 上二分：定位第一个 t > time 的样本 */
      let lo = 0;
      let hi = count;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (ts[(oldest + mid) % HIST_CAPACITY] <= time) {
          lo = mid + 1;
        } else {
          hi = mid;
        }
      }
      /* time 不早于全部样本 → 返回最新值 */
      if (lo >= count) return vs[head];

      /* 相邻两点线性插值（s = 最后一个 ≤ time，n = 第一个 > time） */
      const idxN = (oldest + lo) % HIST_CAPACITY;
      const idxS = (oldest + lo - 1 + HIST_CAPACITY) % HIST_CAPACITY;
      const span = ts[idxN] - ts[idxS];
      if (span <= 0) return vs[idxN];
      return vs[idxS] + (vs[idxN] - vs[idxS]) * ((time - ts[idxS]) / span);
    },
  };
};

/**
 * 方向性渡越序列引擎（单实例 — 随 ParticleBackground 生命周期）
 *
 * 时钟纪律：所有时钟无条件单调推进，绝不冻结；效果生效与否由
 * 完成标志独立守卫。
 */
export class TransitionEngine {
  /* 渲染域时钟（秒 — 与门控 dt 同基准，跳帧慢放语义统一） */
  private clock = 0;
  /* intro：启动即播放（设计行为 — 星系倒卷成型全屏逆渡） */
  private introClock = 0;
  private introInterruptedAt: number | null = null;
  private introDone = false;
  /* enter：点击进入触发（triggerEnter） */
  private enterClock: number | null = null;
  /* 打断锚点（触发时刻冻结）：抬升剖面起点强度 / 换向起点方向量与其
   * 一/二阶导（动量匹配 — 接缝二阶连续） */
  private launchedLevel = 0;
  private launchedDir = 0;
  private launchedDirV = 0;
  private launchedDirA = 0;
  /* 无障碍：prefers-reduced-motion — 逆渡跳过、正渡停用（无大幅运动） */
  private reducedMotion = false;

  private warpEnvVal = 0;
  private dirWVal = 0;
  private warpDistVal = 0;
  private swirlVal = 0;
  private history = createIntegralHistory();

  /** 无障碍门控（幂等）：开启且逆渡尚未结束时跳过逆渡；正渡由
   *  triggerEnter 拒绝。中途开启不追溯打断进行中的进入序列（避免
   *  跳变）；关闭不重放逆渡。 */
  setReducedMotion(on: boolean): void {
    this.reducedMotion = on;
    if (on && !this.introDone && this.introInterruptedAt === null && this.enterClock === null) {
      this.introDone = true;
    }
  }

  /**
   * 推进一帧：双时间参数
   *   - frameStep（钳制帧步进）：物理积分专用（缠绕/幕布位移），低档位
   *     长间隔被钳制上限保护，不过冲；
   *   - wallStep（墙钟增量）：进度计算专用（时钟/复合序列），不钳制 —
   *     低档位下包络推进与静止漂移速度不随帧率失真。
   * 时钟无条件推进（绝不冻结），返回渲染域时钟（秒）。
   */
  update(frameStep: number, wallStep: number): number {
    this.clock += wallStep;
    this.introClock += wallStep;
    if (this.enterClock !== null) this.enterClock += wallStep;

    let env = 0;
    let dir = 0;

    /* 1) 启动逆渡（自然路径：未点击、未打断、未降级） */
    if (!this.introDone && this.introInterruptedAt === null) {
      if (this.introClock >= INTRO_T) {
        this.introDone = true; // 逆渡自然完成（未被点击打断）
      } else {
        env = warpEnvelope(this.introClock / INTRO_T);
        dir = -env;
      }
    }

    /* 2) 进入正渡：自然（逆渡完成后点击）/ 打断（逆渡期间点击）两条路径 */
    if (this.enterClock !== null) {
      const x = this.enterClock / ENTER_T;
      if (this.introInterruptedAt === null) {
        const e = warpEnvelope(x);
        env = e;
        dir = e; // 自然正渡：强度与方向同剖面
      } else {
        env = this.launchedEnvelope(x);
        dir = this.launchedDirection(this.enterClock);
      }
    }

    /* 合成场强度（收缩/噪声/拖尾/FOV/Z 冲程）与符号方向权重（缠绕/相机方向） */
    this.warpEnvVal = env;
    this.dirWVal = dir;
    /* 幕布位移为符号积分（远景幕布跟随序列方向漂移）——物理积分用帧步进 */
    this.warpDistVal += dir * WARP_SPEED * frameStep;
    /* 符号缠绕积分：正渡正向缠绕、逆渡反向倒卷，角度恒连续（积分量） */
    this.swirlVal += dir * frameStep;
    this.history.push(this.clock, this.swirlVal);
    return this.clock;
  }

  /** 点击进入：正渡自零启动；逆渡进行中则冻结打断锚点（抬升剖面 +
   *  换向曲线起点）。幂等守卫：正渡进行中重复触发直接忽略（防重放跳变）。 */
  triggerEnter(): void {
    if (this.reducedMotion) return; // 无障碍：正渡停用（无大幅运动）
    if (this.enterClock !== null) return; // 幂等守卫
    if (!this.introDone) {
      this.introDone = true;
      this.introInterruptedAt = this.introClock;
      const x = this.introClock / INTRO_T;
      const [d1, d2] = warpEnvelopeD(x);
      this.launchedLevel = warpEnvelope(x);
      this.launchedDir = -this.launchedLevel;
      /* 动量匹配：换向曲线起点一/二阶导 = 来向斜率（每秒制） */
      this.launchedDirV = -d1 / INTRO_T;
      this.launchedDirA = -d2 / (INTRO_T * INTRO_T);
    }
    this.enterClock = 0;
  }

  /** 抬升剖面：e0 处抬升的自然剖面（x≤0.62 单调升档至 1，其后同消散段） */
  private launchedEnvelope(x: number): number {
    return x <= ENV_PEAK_END
      ? this.launchedLevel + (1 - this.launchedLevel) * warpEnvelope(x)
      : warpEnvelope(x);
  }

  /** 换向曲线：单条二阶连续曲线 —— 以打断瞬间的方向量与其一/二阶导为
   *  起点（动量匹配，接缝无速率台阶）、以自然剖面平台点为终点（值/
   *  一阶/二阶三量匹配），窗口内一次穿越零点（无驻停段）；窗口结束后
   *  并入自然剖面。 */
  private launchedDirection(tc: number): number {
    if (tc < REVERSAL_T) {
      return hermite5(
        tc / REVERSAL_T,
        this.launchedDir,
        this.launchedDirV,
        this.launchedDirA,
        REVERSAL_JOIN_D,
        REVERSAL_JOIN_V,
        REVERSAL_JOIN_A,
        REVERSAL_T,
      );
    }
    return warpEnvelope(tc / ENTER_T);
  }

  /** t 时刻缠绕积分采样（残影拖尾历史值 — 早于首样本 → 0：运动开始前） */
  swirlAt(t: number): number {
    return this.history.at(t);
  }

  /** 渲染域时钟（秒）— 粒子轨道/相机漂移/呼吸项统一时间基准 */
  get time(): number {
    return this.clock;
  }
  /** 合成渡越场强度（0-1） */
  get warpEnv(): number {
    return this.warpEnvVal;
  }
  /** 符号方向权重（正渡 − 逆渡 ∈ [-1,1]） */
  get dirW(): number {
    return this.dirWVal;
  }
  /** 幕布位移积分（符号 — 驱动远景着色器环绕推进） */
  get warpDist(): number {
    return this.warpDistVal;
  }
  /** 当前符号缠绕积分（正渡 +/逆渡 −） */
  get swirl(): number {
    return this.swirlVal;
  }
}

/** 组合式入口：组件内创建引擎实例（每组件实例独立，随卸载废弃） */
export function useTransitionEngine(): TransitionEngine {
  return new TransitionEngine();
}