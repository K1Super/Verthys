/*
 * core/frame-budget.ts — 帧预算监控与自愈机制
 * =============================================================================
 * 【设计原则】不强制降低帧率。所有优化目标都是将每帧 CPU/GPU
 * 工作降到预算内（60fps ≈ 16.67ms/帧），仅在硬件确实不足时平滑降级 —
 * 用户感知到的是粒子密度降低而非卡顿。
 *
 * 【监控模型】
 *   - 采样：主渲染循环每执行帧记录「任务总耗时」（mustRun + throttled
 *     实际执行时长，主循环在调用任务前后计时）——独立 rAF 已根除，
 *     本模块不再持有任何帧调度句柄；
 *   - 缓冲：固定长度 Float32Array 环形缓冲（60 样本），head 索引覆盖
 *     写入，O(1) 零分配；
 *   - 评估：每 60 帧（约 1s @60fps）执行一次 P95 排序与升降级决策
 *     （统计与决策不阻塞帧）；迟滞阈值以评估周期计数。
 *
 * 【预算基准】active 档任务总耗时 P95 预算 6ms（jsTimeMs），恢复线
 *   为预算 70%（4.2ms）——任务总耗时只含 JS 执行时间，不含 rAF 等待
 *   与 GPU 合成反压（帧间隔代理测量已废弃）。
 *
 * 【降级档位】
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
 *     降频执行不是性能缺陷，计入会永久误降级；
 *   - 任务总耗时 ≥1000ms 丢弃（标签页切换/系统挂起恢复的巨帧）；
 *   - 滑窗未满（启动暖机 <1s）不参与升降级决策 — 启动峰值不触发降级。
 *
 * 【可观测性】档位跃迁 DEV 构建输出日志；getMetrics() 暴露快照
 * （任务耗时均值/P50/P95/P99/当前档位/样本数/draw call）供诊断与测试消费。
 * ========================================================================== */

import { useGlobalIdleScheduler } from "../composables/useGlobalIdleScheduler";

/** 帧指标快照 */
export interface FrameMetrics {
  /** 最近一帧任务总耗时（ms） */
  jsTimeMs: number;
  /** GPU timer query 预留位（未接入时恒为 0） */
  gpuTimeMs: number;
  /** 帧总时间（ms，与 jsTimeMs 同源 —— 任务总耗时语义） */
  totalTimeMs: number;
}

/** 降级档位总数（0 完整 / 1 轻度 / 2 中度 / 3 重度） */
export const DEGRADATION_MAX_LEVEL = 3;

/** 各档位粒子密度（1 / 0.8 / 0.5 / 0.2） */
const DENSITY_BY_LEVEL: readonly number[] = [1, 0.8, 0.5, 0.2];

/** 环形缓冲容量（帧）—— 约 1s @60fps */
const SAMPLE_WINDOW = 60;

/** 评估周期（帧）—— P95 排序与升降级决策频率（约 1 次/秒 @60fps） */
const EVAL_PERIOD_FRAMES = 60;

/** active 档任务总耗时 P95 预算（ms） */
const BUDGET_P95_MS = 6;

/** 连续超预算评估次数阈值 → 降一档（评估周期 ≈1s） */
const OVER_BUDGET_EVALS = 2;

/** 连续低预算评估次数阈值 → 升一档（自愈，比降级更保守） */
const UNDER_BUDGET_EVALS = 6;

/** 低预算判定比例（P95 < 预算 × 0.7 → 视为余量充足） */
const RECOVER_RATIO = 0.7;

/** 单帧任务总耗时丢弃上限（ms）— 挂起恢复的巨帧不计入 */
const TASK_TOTAL_DISCARD_MS = 1000;

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
 * 并发安全：状态跃迁仅由主渲染循环的 recordFrame 调用驱动
 * （start/stop/注册 API 幂等），无跨线程共享可变状态。
 */
export class FrameBudgetMonitor {
  /** 滑窗环形缓冲（任务总耗时，ms） */
  private readonly ring = new Float32Array(SAMPLE_WINDOW);
  /** 环形写头（下一写入索引） */
  private head = 0;
  /** 已写入样本数（≤ SAMPLE_WINDOW） */
  private samples = 0;
  /** 距下次评估的帧计数 */
  private evalCountdown = EVAL_PERIOD_FRAMES;
  /** 当前降级档位（0 = 完整） */
  private degradationLevel = 0;
  /** 连续超预算评估计数 */
  private consecutiveOverBudget = 0;
  /** 连续低预算评估计数 */
  private consecutiveUnderBudget = 0;
  /** 采样启停标志（App.vue 生命周期驱动） */
  private enabled = false;
  /** 最近一次记录的任务总耗时（ms） */
  private lastTaskTotalMs = 0;
  /** 最近观测到的每执行帧 draw call 数（ParticleBackground 上报） */
  private drawCalls = 0;
  /** 粒子密度控制器（未注册时粒子通道空转 — 容错） */
  private particleController: ParticleDensityController | null = null;
  /** 档位跃迁监听器集 */
  private readonly listeners = new Set<LevelListener>();
  /** 全局空闲档位（仅 active 档采样 — 有意降频执行不计入预算评估） */
  private readonly idleLevel = useGlobalIdleScheduler().level;

  /** 启用采样（幂等；已停止时 recordFrame 为无操作） */
  start(): void {
    this.enabled = true;
  }

  /** 停用采样（幂等；档位与治理类保持现状 — 停止≠复位） */
  stop(): void {
    this.enabled = false;
  }

  /**
   * 记录一执行帧的任务总耗时（由主渲染循环每执行帧调用）。
   * O(1) 环形写入 + 降频评估 — 统计/排序/决策不在每帧执行。
   * 亦开放给外部采样源（如测试注入合成帧序列）。
   */
  recordFrame(totalTaskMs: number): void {
    if (!this.enabled) return;
    /* 巨帧守卫：挂起恢复的一次性异常耗时不计入预算评估 */
    if (totalTaskMs <= 0 || totalTaskMs >= TASK_TOTAL_DISCARD_MS) return;
    /* 采样守卫：仅 active 档采样（有意降频帧不是性能缺陷） */
    if (this.idleLevel.value !== "active") return;

    this.ring[this.head] = totalTaskMs;
    this.head = (this.head + 1) % SAMPLE_WINDOW;
    if (this.samples < SAMPLE_WINDOW) this.samples++;
    this.lastTaskTotalMs = totalTaskMs;

    /* 降频评估：每 EVAL_PERIOD_FRAMES 帧执行一次 P95 排序与决策 */
    this.evalCountdown--;
    if (this.evalCountdown <= 0) {
      this.evalCountdown = EVAL_PERIOD_FRAMES;
      if (this.samples >= SAMPLE_WINDOW) this.evaluate();
    }
  }

  /** 上报每执行帧 draw call 数（ParticleBackground 渲染后采样，无档位守卫） */
  reportDrawCalls(calls: number): void {
    this.drawCalls = calls;
  }

  /** 环形缓冲快照 → 升序数组（仅供评估 / 指标快照消费） */
  private sortedSamples(): number[] {
    const out: number[] = [];
    for (let i = 0; i < this.samples; i++) {
      out.push(this.ring[(this.head - this.samples + i + SAMPLE_WINDOW) % SAMPLE_WINDOW]);
    }
    return out.sort((a, b) => a - b);
  }

  /** 分位数（升序数组；样本不足时回退可用边界） */
  private percentile(sorted: number[], q: number): number {
    if (sorted.length === 0) return 0;
    const idx = Math.min(sorted.length - 1, Math.ceil(sorted.length * q) - 1);
    return sorted[Math.max(idx, 0)];
  }

  /** 滑窗 P95 评估 + 迟滞跃迁决策（每 60 帧调用一次） */
  private evaluate(): void {
    const sorted = this.sortedSamples();
    const p95 = this.percentile(sorted, 0.95);

    if (p95 > BUDGET_P95_MS) {
      this.consecutiveUnderBudget = 0;
      this.consecutiveOverBudget++;
      if (this.consecutiveOverBudget >= OVER_BUDGET_EVALS) {
        this.degrade();
      }
    } else if (p95 < BUDGET_P95_MS * RECOVER_RATIO) {
      this.consecutiveOverBudget = 0;
      this.consecutiveUnderBudget++;
      if (this.consecutiveUnderBudget >= UNDER_BUDGET_EVALS) {
        this.upgrade();
      }
    } else {
      /* 中间带：两类计数归零（阈值附近抖动防护） */
      this.consecutiveOverBudget = 0;
      this.consecutiveUnderBudget = 0;
    }
  }

  /** 平滑降级一档（逐步减少工作，而非骤降帧率） */
  private degrade(): void {
    this.consecutiveOverBudget = 0;
    if (this.degradationLevel >= DEGRADATION_MAX_LEVEL) return;
    this.degradationLevel++;
    this.applyLevel("degrade");
  }

  /** 自愈升级一档（逐步恢复） */
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

    /* 2) CSS 治理类（权威类名 — reduced-motion ≥2 / minimal-motion =3；
     *    样式由 idle-governance.css 承载） */
    document.body.classList.toggle("reduced-motion", level >= 2);
    document.body.classList.toggle("minimal-motion", level >= 3);

    /* 3) 可观测性：DEV 档位跃迁日志 + 监听器通知 */
    if (import.meta.env.DEV) {
      console.info(
        "[frame-budget] %s → level %d (density %d%%, p95 %.2fms)",
        direction,
        level,
        Math.round(DENSITY_BY_LEVEL[level] * 100),
        this.percentile(this.sortedSamples(), 0.95),
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

  /** 指标快照（诊断/测试消费 — 不暴露内部可变状态） */
  getMetrics(): FrameMetrics & {
    meanMs: number;
    p50Ms: number;
    p95Ms: number;
    p99Ms: number;
    level: number;
    samples: number;
    drawCalls: number;
  } {
    const sorted = this.sortedSamples();
    const mean =
      sorted.length > 0 ? sorted.reduce((a, b) => a + b, 0) / sorted.length : 0;
    return {
      jsTimeMs: this.lastTaskTotalMs,
      gpuTimeMs: 0, // GPU timer query 预留位（未接入）
      totalTimeMs: this.lastTaskTotalMs,
      meanMs: mean,
      p50Ms: this.percentile(sorted, 0.5),
      p95Ms: this.percentile(sorted, 0.95),
      p99Ms: this.percentile(sorted, 0.99),
      level: this.degradationLevel,
      samples: this.samples,
      drawCalls: this.drawCalls,
    };
  }
}

/** 全局帧预算监控器（模块级单例 — App.vue 生命周期驱动启停，
 *  采样由主渲染循环每执行帧推送） */
export const frameBudgetMonitor = new FrameBudgetMonitor();