/*
 * useTransitionEngine.ts — 方向性渡越序列引擎（intro 逆渡 / enter 正渡）
 *
 * 从 ParticleBackground.vue 抽离的纯数学状态机（零 THREE 依赖 — 可独立
 * 推演与测试）：双序列 C2 包络求值、符号缠绕积分、幕布位移积分。
 * ParticleBackground 每帧仅调用 update(dt) 并读取结果，
 * renderFrame 不再持有任何序列状态。
 *
 * v3 修复（加载期微颤 — 全量根除）：
 *   旧实现内建相机镜头微颤（envelopeShiver：4.5Hz 高频载波抖动相机
 *   ±260/±190 units）作为「引擎蓄能/满推质感」— 启动 intro 与点击
 *   进入 enter 期间整幅星系画面持续高频微晃 = 用户感知的加载微颤。
 *   根治 = 微颤体系全量删除（常量/包络/求值/门控字段），渡越动感
 *   全部由 C2 连续的包络积分承担（缠绕/收缩/相机弧线 — 速度连续
 *   无高频抖动），加载全程画面恒稳定。
 *   （v2 时钟纪律保留：introClock/enterClock 无条件单调推进、效果由
 *   done 标志守卫 — 「时钟停滞 → 效果残留」类缺陷结构性根除。）
 *
 * 冲突编排（3s 内点击）：intro 残余自打断时刻包络幅度经 0.5s smootherstep
 * 衰减 + enter 自零爬升 → dirW 过零连续；缠绕角为积分量，任何打断时刻
 * 角度恒连续零跳变。
 */

import { ENTER_T_MS } from "../app/constants";

/** 启动逆渡时长（秒）：星系倒卷成型（与 UnlockView 品牌动画 3s 编排同步 — 独立编排，不随正渡时长） */
export const INTRO_T = 3.0;
/** 点击正渡时长（秒）：唯一权威源 = app/constants ENTER_T_MS（页面交接/星河态/crossfade 全部同源派生） */
export const ENTER_T = ENTER_T_MS / 1000;
/** 打断衰减时长（秒）：逆渡中点击 → 残余包络 C2 平滑滑零 */
const INTERRUPT_FADE = 0.5;
/** 渡越峰值速度（units/s，远景幕布位移积分系数） */
const WARP_SPEED = 1200;

/* ===== 包络形状常数（归一化 x∈[0,1] — 三段 smootherstep，全程 C2 连续） ===== */
/** 蓄能段终点（0 → ENV_CHARGE_LEVEL） */
const ENV_CHARGE_END = 0.3;
/** 峰驻段终点（ENV_CHARGE_LEVEL → 1.0；其后为消散段 1.0 → 0） */
const ENV_PEAK_END = 0.62;
/** 蓄能段平台值 */
const ENV_CHARGE_LEVEL = 0.42;

/** smootherstep（五次多项式）：端点一阶/二阶导全零 — 段内平滑、边界 C2 匹配 */
const smootherstep = (u: number): number => u * u * u * (u * (u * 6 - 15) + 10);

/**
 * 复合渡越包络（归一化 x∈[0,1]，三段 smootherstep — 全程 C2 连续：
 *   值/速度/加速度零跳变；intro/enter 共用同一形 = 全屏样式双向一致）：
 *   蓄能段 x<0.30：0 → 0.42
 *   峰驻段 0.30≤x<0.62：0.42 → 1.0
 *   消散段 x≥0.62：1.0 → 0（引力井松开 — 平滑释放，非瞬时弹回）
 * 段边界斜率连续（历史"咯噔"跳越根除）：三段边界值/一阶/二阶导全部
 *   连续 — 收缩减速→保持→平滑释放全程速度连续。
 * 物理场纯净：包络不含任何微颤项（v3 微颤体系全量删除 —
 *   加载全程相机恒稳定，渡越动感由积分量承担）。
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
 * done 标志独立守卫 — 「时钟停滞 → 效果残留」类缺陷
 * 从结构上根除（修复说明附于文件头）。
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

  private warpEnvVal = 0;
  private dirWVal = 0;
  private warpDistVal = 0;
  private swirlVal = 0;
  private history = createIntegralHistory();

  /**
   * 推进一帧：双时间参数
   *   - frameStep（钳制帧步进）：物理积分专用（缠绕/幕布位移），低档位
   *     长间隔被钳制上限保护，不过冲；
   *   - wallStep（墙钟增量）：进度计算专用（时钟/双序列包络），不钳制 —
   *     低档位下包络推进与静止漂移速度不随帧率失真。
   * 时钟无条件推进（绝不冻结 — 微颤残留根治核心），返回渲染域时钟（秒）。
   */
  update(frameStep: number, wallStep: number): number {
    this.clock += wallStep;
    /* 时钟无条件推进（绝不冻结 — v2 微颤残留根治核心） */
    this.introClock += wallStep;
    if (this.enterClock !== null) this.enterClock += wallStep;

    let introEnv = 0;
    if (!this.introDone) {
      if (this.introInterruptedAt === null) {
        if (this.introClock >= INTRO_T) {
          this.introDone = true; // 逆渡自然完成（未被点击打断）
        } else {
          introEnv = warpEnvelope(this.introClock / INTRO_T);
        }
      } else {
        // 打断衰减：自打断时刻的包络幅度平滑滑向零（C2）
        const u = (this.introClock - this.introInterruptedAt) / INTERRUPT_FADE;
        if (u >= 1) {
          this.introDone = true;
        } else {
          const decay = 1 - smootherstep(u);
          introEnv = warpEnvelope(this.introInterruptedAt / INTRO_T) * decay;
        }
      }
    }
    const enterEnv =
      this.enterClock !== null && this.enterClock < ENTER_T
        ? warpEnvelope(this.enterClock / ENTER_T)
        : 0;

    /* 合成场强度（收缩/噪声/拖尾/FOV/Z 冲程）与符号方向权重（缠绕/相机方向） */
    this.warpEnvVal = Math.min(introEnv + enterEnv, 1);
    this.dirWVal = enterEnv - introEnv;
    /* uWarpDist 为符号积分（远景幕布跟随序列方向漂移）——物理积分用帧步进 */
    this.warpDistVal += this.dirWVal * WARP_SPEED * frameStep;
    /* 符号缠绕积分：正渡正向缠绕、逆渡反向倒卷，角度恒连续（积分量）——
     * 物理积分用帧步进，包络进度用墙钟（低档位下角度与包络不失配） */
    this.swirlVal += this.dirWVal * frameStep;
    this.history.push(this.clock, this.swirlVal);
    return this.clock;
  }

  /** 点击进入：正渡自零启动；逆渡进行中则记录打断时刻（残余 0.5s C2 衰减） */
  triggerEnter(): void {
    if (!this.introDone) this.introInterruptedAt = this.introClock;
    this.enterClock = 0;
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
  /** 符号方向权重（enter − intro ∈ [-1,1]） */
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
