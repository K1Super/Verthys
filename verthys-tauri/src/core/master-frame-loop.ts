/*
 * master-frame-loop.ts — 全应用唯一主渲染循环
 *
 * 职责（单一 rAF 入口 + 帧门控执行层 + 豁免管理）：
 *   - 每帧任务注册制：mustRun（不受帧门控节流，数量 ≤2）/ throttled
 *     （跟随空闲档位节流）；组件禁止自行开 rAF。
 *   - 双时间参数契约：任务签名同时接收
 *       frameStep —— 距离本任务队列上一次实际执行的累积时长，钳制至
 *         MAX_FRAME_STEP_MS（物理积分专用）；
 *       wallClock —— 真实经过时间（性能时钟），不钳制（进度计算专用）。
 *     低档位下 rAF 仍每 16.7ms 回调，但节流任务只在许可帧执行——按 rAF
 *     间隔推导物理 dt 会造成物理时间变慢；frameStep 以「上一次任务实际
 *     执行时刻」为基准并钳制，保证低帧率下积分以正确累积时间推进。
 *   - 整帧跳过语义：当前帧既无 mustRun 任务、节流任务也未到许可时刻时，
 *     整帧跳过且不更新任何基准时刻。
 *   - 豁免（引用计数）：granted 计数与 degraded 计数各自累加，
 *     混合时取最严格帧率（degraded 的降级优先）；释放以 token 幂等；
 *     页面隐藏时请求被拒绝（仅记录）；超时上限 MAX_EXEMPT_DURATION_MS
 *     强制释放兜底（正常路径由使用者主动释放）。
 *   - 每帧任务总耗时测量 → 帧预算监控消费（统计与决策在监控内部
 *     降频执行，不阻塞帧）。
 *   - 错误熔断：任务连续抛错 10 次自动注销，避免错误帧循环刷屏。
 *
 * 页面隐藏时浏览器停发 rAF —— 主循环天然完全停帧，无需自行轮询。
 */

import {
  EXEMPT_DEGRADED_INTERVAL_MS,
  FRAME_INTERVAL_MS,
  MAX_EXEMPT_DURATION_MS,
  MAX_FRAME_STEP_MS,
} from "../config/frame-gate";
import { useGlobalIdleScheduler } from "../composables/useGlobalIdleScheduler";
import { frameBudgetMonitor } from "./frame-budget";

/** 任务上下文：双时间参数（帧步进 / 墙钟），单位均为秒 */
export interface FrameStep {
  /** 距离上一许可帧的累积时长（ms 钳制后换算的秒值）——物理积分专用 */
  frameStep: number;
  /** 真实经过时间（秒）——进度计算专用 */
  wallClock: number;
}

/** 每帧任务签名 */
export type FrameTask = (ctx: FrameStep) => void;

/** 任务类别：mustRun 不受帧门控节流；throttled 跟随空闲档位 */
export type TaskType = "mustRun" | "throttled";

/** 豁免申请结果状态 */
export type ExemptStatus = "granted" | "degraded" | "rejected";

/** 豁免令牌（一次豁免生命周期的句柄——释放幂等，不得跨渡越复用） */
export interface ExemptionToken {
  readonly id: number;
  readonly status: "granted" | "degraded";
  readonly grantedAt: number;
}

/** 豁免申请结果：rejected 时 token 为 null */
export interface ExemptionResult {
  status: ExemptStatus;
  token: ExemptionToken | null;
}

/** 任务注册选项 */
export interface RegisterOptions {
  /** 任务类别（默认 throttled） */
  type?: TaskType;
  /** 任务标签（遥测 / 日志用） */
  label?: string;
}

/** 单个已注册任务记录 */
interface TaskEntry {
  task: FrameTask;
  label: string;
  errors: number;
}

/** rAF 宿主注入（测试注入假调度器；生产默认浏览器 rAF） */
export interface LoopHost {
  requestFrame(cb: (tsMs: number) => void): number;
  cancelFrame(id: number): void;
  nowMs(): number;
}

/** 浏览器默认宿主 */
const browserHost: LoopHost = {
  requestFrame: (cb) => window.requestAnimationFrame(cb),
  cancelFrame: (id) => window.cancelAnimationFrame(id),
  nowMs: () => performance.now(),
};

/** 任务连续抛错上限：达到后自动注销（防错误帧循环刷屏） */
const MAX_TASK_ERRORS = 10;

/** mustRun 常驻任务数量上限（超出时拒绝注册） */
const MUST_RUN_LIMIT = 2;

/** 主渲染循环（工厂创建；模块级导出单例） */
export class MasterFrameLoop {
  /** mustRun 任务表（每帧恒执行） */
  private readonly mustTasks = new Map<number, TaskEntry>();
  /** throttled 任务表（按空闲档位节流） */
  private readonly throttleTasks = new Map<number, TaskEntry>();
  /** 一次性排帧队列（事件驱动的单帧写入 —— 每 rAF 帧执行，不受档位节流） */
  private readonly onceQueue: FrameTask[] = [];
  /** 已授予豁免（按 token id 索引；释放幂等） */
  private readonly granted = new Map<number, ExemptionToken>();
  /** degraded 豁免计数（混合时取最严格帧率） */
  private degradedCount = 0;

  private taskSeq = 0;
  private tokenSeq = 0;
  private rafId: number | null = null;
  private running = false;
  /** mustRun 队列上一执行帧时刻（秒） */
  private lastMustTs = 0;
  /** throttled 队列上一执行帧时刻（秒） */
  private lastThrottleTs = 0;

  /** 全局空闲档位（帧门控节流的唯一权威源） */
  private readonly idleLevel = useGlobalIdleScheduler().level;

  constructor(private readonly host: LoopHost = browserHost) {}

  /** 启动主循环（幂等） */
  start(): void {
    if (this.running) return;
    this.running = true;
    this.lastMustTs = this.nowSec();
    this.lastThrottleTs = this.lastMustTs;
    this.rafId = this.host.requestFrame(this.loop);
  }

  /** 停止主循环（幂等；已注册任务保留，重新 start 继续执行） */
  stop(): void {
    this.running = false;
    if (this.rafId !== null) {
      this.host.cancelFrame(this.rafId);
      this.rafId = null;
    }
  }

  /**
   * 注册每帧任务。
   *
   * @returns 注销函数；mustRun 数量超限时拒绝注册并返回 null
   */
  register(task: FrameTask, options: RegisterOptions = {}): (() => void) | null {
    const type: TaskType = options.type ?? "throttled";
    const table = type === "mustRun" ? this.mustTasks : this.throttleTasks;
    if (type === "mustRun" && table.size >= MUST_RUN_LIMIT) {
      console.warn(
        `[master-frame-loop] mustRun 任务数量已达上限（${MUST_RUN_LIMIT}），拒绝注册：${options.label ?? "anonymous"}`,
      );
      return null;
    }
    const id = ++this.taskSeq;
    table.set(id, { task, label: options.label ?? `task-${id}`, errors: 0 });
    return () => {
      table.delete(id);
    };
  }

  /** 下一 rAF 帧执行一次（事件驱动的单帧写入——不受空闲档位节流） */
  once(task: FrameTask): void {
    this.onceQueue.push(task);
  }

  /**
   * 申请关键动画帧率豁免。
   * granted：帧率提升至每帧，计数 +1；
   * degraded：按降级档帧率执行，计数 +1（与 granted 混合取最严格）；
   * rejected：拒绝（页面隐藏——仅记录，不参与计数）。
   */
  requestExemption(label = "anonymous"): ExemptionResult {
    if (typeof document !== "undefined" && document.visibilityState === "hidden") {
      if (import.meta.env.DEV) {
        console.info(`[master-frame-loop] 豁免申请被拒（页面隐藏）：${label}`);
      }
      return { status: "rejected", token: null };
    }
    const token: ExemptionToken = {
      id: ++this.tokenSeq,
      status: "granted",
      grantedAt: this.nowSec(),
    };
    this.granted.set(token.id, token);
    return { status: "granted", token };
  }

  /** 释放豁免（幂等：重复释放 / 释放未知 token 均被忽略） */
  releaseExemption(token: ExemptionToken | null): void {
    if (!token) return;
    if (token.status === "degraded") {
      if (this.degradedCount > 0) this.degradedCount--;
      return;
    }
    this.granted.delete(token.id);
  }

  /** 当前生效帧间隔（ms）：degraded 优先，其次 granted 每帧，最后档位值 */
  private currentInterval(): number {
    if (this.degradedCount > 0) return EXEMPT_DEGRADED_INTERVAL_MS;
    if (this.granted.size > 0) return 0;
    return FRAME_INTERVAL_MS[this.idleLevel.value];
  }

  /** 超时豁免强制释放（防御性兜底——正常路径由使用者主动释放） */
  private evictExpiredExemptions(): void {
    const now = this.nowSec();
    for (const [id, token] of this.granted) {
      if (now - token.grantedAt > MAX_EXEMPT_DURATION_MS / 1000) {
        this.granted.delete(id);
        console.warn("[master-frame-loop] 豁免超时强制释放（token=%d）", token.id);
      }
    }
  }

  /** 执行单个任务：错误熔断（连续 10 次抛错自动注销） */
  private runTask(entry: TaskEntry, ctx: FrameStep): void {
    try {
      entry.task(ctx);
      entry.errors = 0;
    } catch (error) {
      entry.errors++;
      if (entry.errors >= MAX_TASK_ERRORS) {
        this.mustTasks.forEach((v, k) => {
          if (v === entry) this.mustTasks.delete(k);
        });
        this.throttleTasks.forEach((v, k) => {
          if (v === entry) this.throttleTasks.delete(k);
        });
        console.error(`[master-frame-loop] 任务连续抛错 ${MAX_TASK_ERRORS} 次，已自动注销：${entry.label}`, error);
      } else {
        console.error(`[master-frame-loop] 任务执行异常：${entry.label}`, error);
      }
    }
  }

  private nowSec(): number {
    return this.host.nowMs() / 1000;
  }

  /** 主循环逐帧入口 */
  private readonly loop = (tsMs: number): void => {
    if (!this.running) return;
    this.rafId = this.host.requestFrame(this.loop);

    const now = tsMs / 1000;
    const interval = this.currentInterval();
    const mustDue = this.mustTasks.size > 0 || this.onceQueue.length > 0;
    const throttleDue =
      this.throttleTasks.size > 0 &&
      (interval === 0 || now - this.lastThrottleTs >= interval / 1000);

    /* 整帧跳过：无任何任务待执行时不推进基准时刻（帧步进语义核心） */
    if (!mustDue && !throttleDue) return;

    const t0 = this.host.nowMs();
    const frameStepMust = Math.min(Math.max(now - this.lastMustTs, 0), MAX_FRAME_STEP_MS / 1000);
    const frameStepThrottle = Math.min(
      Math.max(now - this.lastThrottleTs, 0),
      MAX_FRAME_STEP_MS / 1000,
    );

    /* 执行序：mustRun / 一次性排帧 → throttled（豁免超时释放随帧检查） */
    if (mustDue) {
      this.lastMustTs = now;
      const ctx: FrameStep = { frameStep: frameStepMust, wallClock: now };
      for (const entry of this.mustTasks.values()) this.runTask(entry, ctx);
      while (this.onceQueue.length > 0) {
        const task = this.onceQueue.shift();
        if (task) this.runTask({ task, label: "once", errors: 0 }, ctx);
      }
    }

    if (throttleDue) {
      this.lastThrottleTs = now;
      const ctx: FrameStep = { frameStep: frameStepThrottle, wallClock: now };
      for (const entry of this.throttleTasks.values()) this.runTask(entry, ctx);
    }

    this.evictExpiredExemptions();

    /* 任务总耗时 → 帧预算监控（监控内部 O(1) 入环形缓冲 + 降频评估） */
    frameBudgetMonitor.recordFrame(this.host.nowMs() - t0);
  };
}

/** 全应用唯一主渲染循环单例（App.vue 生命周期驱动启停） */
export const masterFrameLoop = new MasterFrameLoop();