/*
 * core/frame-budget.ts — 帧预算监控与自愈机制（性能根治方案 §7）
 * =============================================================================
 * 【设计原则（§7.1）】不强制降低帧率。所有优化目标都是将每帧 CPU/GPU
 * 工作降到预算内（60fps ≈ 16.67ms/帧），仅在硬件确实不足时平滑降级 —
 * 用户感知到的是粒子密度降低而非卡顿。
 *
 * 【监控模型】
 *   - 采样：独立 rAF 循环测量帧间隔（主线程停帧 — 无论来自 JS 还是
 *     GPU 合成反压 — 均表现为 rAF 间隔拉长，是帧预算最可信的代理指标）；
 *   - 评估：60 帧滑窗 P95（兼顾稳态与离群帧）；
 *   - 迟滞：连续 30 次评估超预算 → 降一档；连续 60 次评估低于预算
 *     70% → 升一档（自愈）。中间带计数归零 — 防止在阈值附近抖动。
 *
 * 【降级档位（§7.3 权威表）】
 *   级别 | 粒子密度 | CSS 动画     | backdrop-filter
 *   0    | 100%     | 全部         | 保留
 *   1    | 80%      | 全部         | 保留
 *   2    | 50%      | 核心         | 减少
 *   3    | 20%      | 最少         | 移除
 *
 * 落地通道（策略注入 — 高内聚低耦合，监控器不感知实现细节）：
 *   - 粒子密度 → ParticleDensityController（ParticleBackground 注册，
 *     setDrawRange 等效 InstancedMesh.count）
 *   - CSS 治理 → body 挂载 reduced-motion（≥2）/ minimal-motion（=3）
 *     类，idle-governance.css 承载降级样式（暂停非核心动画 /
 *     移除 backdrop-filter）
 *
 * 【采样守卫（防误判）】
 *   - 仅全局空闲档位为 active 时采样：settling/idle/deep-idle 的有意
 *     降频帧（30/5/1fps）不是性能缺陷，计入会永久误降级；
 *   - 帧间隔 ≥1000ms 丢弃（标签页切换/系统挂起恢复的巨帧）；
 *   - 滑窗未满（启动暖机 <1s）不参与升降级决策 — 启动峰值不触发降级。
 *
 * 【可观测性】档位跃迁 DEV 构建输出日志；getMetrics() 暴露快照
 * （帧样本/P95/当前档位）供诊断面板与测试消费。
 * ========================================================================== */

import { useGlobalIdleScheduler } from "../composables/useGlobalIdleScheduler";

/** 帧指标快照（§7.2 FrameMetrics — gpuTimeMs 为 WebGL timer query 预留位） */
export interface FrameMetrics {
  /** 主线程 JS 时间（帧间隔代理测量，ms） */
  jsTimeMs: number;
  /** GPU 光栅化时间（timer query 未接入时恒为 0 — 预留位） */
  gpuTimeMs: number;
  /** 帧总时间（ms） */
  totalTimeMs: number;
}

/** 降级档位总数（0 完整 / 1 轻度 / 2 中度 / 3 重度） */
export const DEGRADATION_MAX_LEVEL = 3;

/** 各档位粒子密度（§7.3 权威表：1 / 0.8 / 0.5 / 0.2） */
const DENSITY_BY_LEVEL: readonly number[] = [1, 0.8, 0.5, 0.2];

/** 滑窗帧数（60 帧 ≈ 1s @60fps） */
const SAMPLE_WINDOW = 60;

/** 60fps 帧预算（ms） */
const BUDGET_MS = 16.67;

/** 连续超预算评估次数阈值 → 降一档 */
const OVER_BUDGET_EVALS = 30;

/** 连续低预算评估次数阈值 → 升一档（自愈，比降级更保守） */
const UNDER_BUDGET_EVALS = 60;

/** 低预算判定比例（P95 < 预算 × 0.7 → 视为余量充足） */
const RECOVER_RATIO = 0.7;

/** 单帧间隔丢弃上限（ms）— 标签页切换/系统挂起恢复的巨帧不计入 */
const FRAME_GAP_DISCARD_MS = 1000;

/**
 * 粒子密度控制契约。
 *
 * ParticleBackground 构建完成后注册（setDrawRange 语义 = InstancedMesh.count
 * — 尾部截断，粒子均匀随机分布下视觉无偏）；卸载时注销。监控器仅持有
 * 契约不感知 THREE — 依赖倒置（渲染实现细节不侵入监控域）。
 */
export interface ParticleDensityController {
  /** 设置粒子渲染密度（0-1，1 = 全量） */
  setDensity(fraction: number): void;
}

/** 档位跃迁监听器（返回注销函数） */
export type LevelListener = (level: number) => void;

/**
 * 帧预算监控器（单例语义：经模块级 frameBudgetMonitor 导出消费）。
 *
 * 并发安全：状态跃迁仅由 rAF 回调驱动（start/stop/注册 API 幂等），
 * 无跨线程共享可变状态。
 */
export class FrameBudgetMonitor {
  /** 滑窗帧样本（ms） */
  private frameTimes: number[] = [];
  /** 帧预算（ms） */
  private readonly budgetMs = BUDGET_MS;
  /** 当前降级档位（0 = 完整） */
  private degradationLevel = 0;
  /** 连续超预算评估计数 */
  private consecutiveOverBudget = 0;
  /** 连续低预算评估计数 */
  private consecutiveUnderBudget = 0;
  /** rAF 句柄（null = 未启动） */
  private rafId: number | null = null;
  /** 上一帧时间戳（performance 基准） */
  private lastFrameTs = 0;
  /** 粒子密度控制器（未注册时粒子通道空转 — 容错） */
  private particleController: ParticleDensityController | null = null;
  /** 档位跃迁监听器集 */
  private readonly listeners = new Set<LevelListener>();
  /** 全局空闲档位（仅 active 档采样 — 有意降频帧不计入预算评估） */
  private readonly idleLevel = useGlobalIdleScheduler().level;

  /** 启动监控（幂等：重复启动无副作用） */
  start(): void {
    if (this.rafId !== null) return;
    this.lastFrameTs = 0;
    this.rafId = window.requestAnimationFrame(this.tick);
  }

  /** 停止监控（幂等；档位与治理类保持现状 — 停止≠复位） */
  stop(): void {
    if (this.rafId === null) return;
    window.cancelAnimationFrame(this.rafId);
    this.rafId = null;
    this.lastFrameTs = 0;
  }

  /** rAF 采样循环：帧间隔测量 → 守卫过滤 → 记录评估 */
  private readonly tick = (ts: number): void => {
    this.rafId = window.requestAnimationFrame(this.tick);

    if (this.lastFrameTs === 0) {
      this.lastFrameTs = ts;
      return;
    }
    const delta = ts - this.lastFrameTs;
    this.lastFrameTs = ts;

    if (delta <= 0 || delta >= FRAME_GAP_DISCARD_MS) return;
    if (this.idleLevel.value !== "active") return;

    this.recordFrame(delta);
  };

  /**
   * 记录一帧（§7.2 recordFrame — 滑窗入队 + 评估）。
   * 亦开放给外部采样源（如测试注入合成帧序列）。
   */
  recordFrame(totalTimeMs: number): void {
    this.frameTimes.push(totalTimeMs);
    if (this.frameTimes.length > SAMPLE_WINDOW) {
      this.frameTimes.shift();
    }
    this.evaluate();
  }

  /** 滑窗 P95 评估 + 迟滞跃迁决策（§7.2 evaluate） */
  private evaluate(): void {
    /* 暖机守卫：滑窗未满不决策（启动峰值不触发降级） */
    if (this.frameTimes.length < SAMPLE_WINDOW) return;

    const p95 = this.calculateP95();

    if (p95 > this.budgetMs) {
      this.consecutiveUnderBudget = 0;
      this.consecutiveOverBudget++;
      if (this.consecutiveOverBudget > OVER_BUDGET_EVALS) {
        this.degrade();
      }
    } else if (p95 < this.budgetMs * RECOVER_RATIO) {
      this.consecutiveOverBudget = 0;
      this.consecutiveUnderBudget++;
      if (this.consecutiveUnderBudget > UNDER_BUDGET_EVALS) {
        this.upgrade();
      }
    } else {
      /* 中间带：两类计数归零（阈值附近抖动防护） */
      this.consecutiveOverBudget = 0;
      this.consecutiveUnderBudget = 0;
    }
  }

  /** 滑窗 P95（升序取 95 分位，含离群帧） */
  private calculateP95(): number {
    if (this.frameTimes.length === 0) return 0;
    const sorted = [...this.frameTimes].sort((a, b) => a - b);
    const idx = Math.min(
      sorted.length - 1,
      Math.ceil(sorted.length * 0.95) - 1,
    );
    return sorted[Math.max(idx, 0)];
  }

  /** 平滑降级一档（§7.2 degrade — 逐步减少工作，而非骤降帧率） */
  private degrade(): void {
    this.consecutiveOverBudget = 0;
    if (this.degradationLevel >= DEGRADATION_MAX_LEVEL) return;
    this.degradationLevel++;
    this.applyLevel("degrade");
  }

  /** 自愈升级一档（§7.2 upgrade — 逐步恢复） */
  private upgrade(): void {
    this.consecutiveUnderBudget = 0;
    if (this.degradationLevel <= 0) return;
    this.degradationLevel--;
    this.applyLevel("upgrade");
  }

  /** 档位落地：粒子密度 + CSS 治理类 + 可观测通知（单一出口，无部分落地） */
  private applyLevel(direction: "degrade" | "upgrade"): void {
    const level = this.degradationLevel;

    /* 1) 粒子密度（控制器未注册时跳过 — 容错，不阻断其余通道） */
    this.particleController?.setDensity(DENSITY_BY_LEVEL[level]);

    /* 2) CSS 治理类（§7.2 权威类名 — reduced-motion ≥2 / minimal-motion =3；
     *    样式由 idle-governance.css §6 承载） */
    document.body.classList.toggle("reduced-motion", level >= 2);
    document.body.classList.toggle("minimal-motion", level >= 3);

    /* 3) 可观测性：DEV 档位跃迁日志 + 监听器通知 */
    if (import.meta.env.DEV) {
      console.info(
        "[frame-budget] %s → level %d (density %d%%, p95 %sms)",
        direction,
        level,
        Math.round(DENSITY_BY_LEVEL[level] * 100),
        this.calculateP95().toFixed(2),
      );
    }
    for (const listener of this.listeners) {
      try {
        listener(level);
      } catch {
        /* 监听器异常不阻断监控主流程（隔离容错） */
      }
    }
  }

  /**
   * 注册粒子密度控制器（构建完成后调用；立即应用当前档位密度 —
   * 晚注册不漏降级）。传 null 注销。
   */
  setParticleController(controller: ParticleDensityController | null): void {
    this.particleController = controller;
    if (controller) {
      controller.setDensity(DENSITY_BY_LEVEL[this.degradationLevel]);
    }
  }

  /** 订阅档位跃迁（返回注销函数） */
  onLevelChange(listener: LevelListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** 当前档位（0 = 完整） */
  getLevel(): number {
    return this.degradationLevel;
  }

  /** 指标快照（诊断/测试消费 — 不暴露内部可变数组） */
  getMetrics(): FrameMetrics & { p95Ms: number; level: number; samples: number } {
    const p95 = this.calculateP95();
    const last = this.frameTimes.length > 0
      ? this.frameTimes[this.frameTimes.length - 1]
      : 0;
    return {
      jsTimeMs: last,
      gpuTimeMs: 0, // WebGL timer query 预留位（未接入）
      totalTimeMs: last,
      p95Ms: p95,
      level: this.degradationLevel,
      samples: this.frameTimes.length,
    };
  }
}

/** 全局帧预算监控器（模块级单例 — App.vue 生命周期驱动启停） */
export const frameBudgetMonitor = new FrameBudgetMonitor();
