/**
 * composables/photo-album/importProgress.ts — 导入进度状态机
 *
 * Comprehensive_optimization：异步批处理流水线 — 进度与 ETA
 *
 * =============================================================================
 * 设计目标
 * =============================================================================
 * 进度与 ETA：滑动窗口加权预测
 *
 * 实现：
 *   1. 记录最近 10~20 张照片的单张处理耗时
 *   2. 采用指数加权移动平均（EWMA）计算实时速率
 *   3. 进度百分比 = 已处理数 / 总数，不进行虚假映射
 *   4. ETA = 剩余数量 × 当前加权平均耗时，随速率变化动态更新
 *   5. 速率骤降检测：卡顿时提前拉长剩余进度，避免「100% 后仍在处理」
 *
 * =============================================================================
 * 帧对齐 UI 更新
 * =============================================================================
 * 流控与 UI：背压队列 + 帧对齐进度：
 *   - 主进程每完成一批即调用 update() 推送实际进度值
 *   - 渲染进程在 requestAnimationFrame 内接收并绘制进度条
 *   - 保证任何时刻最多一帧间隔更新，绝不参与数据处理热路径
 *   - 多次 update() 在同一帧内合并，避免过度渲染
 *
 * =============================================================================
 * 速率骤降检测
 * =============================================================================
 * 当检测到当前批次耗时显著高于 EWMA（如 3 倍以上），判定为卡顿：
 *   - 标记 isStalled = true
 *   - 进度条动画切换为更保守的 ease-out（视觉延后，避免过早到 100%）
 *   - ETA 基于骤降后的最新速率重新计算（而非历史 EWMA）
 *   - 卡顿恢复后（连续 2 批正常耗时）清除 isStalled
 *
 * =============================================================================
 * 使用方式
 * =============================================================================
 *   const progress = new ImportProgressState();
 *   progress.start(totalCount);
 *   // 每完成一批调用：
 *   progress.update(processedInBatch, batchElapsedMs);
 *   // 渲染层读取响应式 ref：
 *   progress.percent.value  // 0~100
 *   progress.etaMs.value    // 剩余毫秒
 *   progress.elapsedMs.value // 已耗毫秒
 *   progress.isStalled.value // 是否卡顿
 *   progress.end();
 */
import { ref, type Ref } from "vue";
import { createLogger } from "../../utils/logger";

const log = createLogger("import-progress");

/** 进度状态配置 */
export interface ImportProgressConfig {
  /** EWMA 滑动窗口大小（记录最近 N 个批次耗时，默认 15） */
  windowSize: number;
  /** EWMA 平滑系数 α（0~1，越小越平滑，默认 0.3） */
  ewmaAlpha: number;
  /** 速率骤降判定阈值（当前耗时 / EWMA > 该值则判定卡顿，默认 3.0） */
  stallThreshold: number;
  /** 卡顿恢复判定阈值（连续 N 批正常耗时后清除卡顿，默认 2） */
  stallRecoverBatches: number;
  /** UI 更新最小间隔（帧对齐，默认 16ms ≈ 60fps） */
  minUpdateIntervalMs: number;
}

/** 单个批次的耗时样本（用于 EWMA 计算） */
interface TimingSample {
  /** 本批次处理记录数 */
  count: number;
  /** 本批次耗时（毫秒） */
  elapsedMs: number;
  /** 单条平均耗时（毫秒） */
  perItemMs: number;
  /** 时间戳 */
  timestamp: number;
}

/** 进度状态快照（供 UI 读取） */
export interface ProgressSnapshot {
  /** 进度百分比（0~100，真实映射，不虚假） */
  percent: number;
  /** 已处理记录数 */
  processed: number;
  /** 总记录数 */
  total: number;
  /** 已耗时（毫秒） */
  elapsedMs: number;
  /** 预计剩余时间（毫秒） */
  etaMs: number;
  /** 当前处理速率（条/秒） */
  rate: number;
  /** 是否卡顿（速率骤降） */
  isStalled: boolean;
  /** 进度文本（供 QuantumProgressFlow.message 使用） */
  text: string;
}

/**
 * 导入进度状态机
 *
 * 滑动窗口加权预测 + 帧对齐进度 + 速率骤降检测：
 * - EWMA 计算实时速率，避免单批次抖动
 * - requestAnimationFrame 帧对齐更新，避免过度渲染
 * - 速率骤降检测，卡顿时视觉延后避免「100% 后仍在处理」
 */
export class ImportProgressState {
  /** 配置 */
  private readonly config: ImportProgressConfig;
  /** 进度开始时间戳 */
  private startAt = 0;
  /** 总记录数 */
  private total = 0;
  /** 已处理记录数（含去重跳过 + 失败） */
  private processed = 0;
  /** 已跳过记录数（去重） */
  private skipped = 0;
  /** 耗时样本环形缓冲区（滑动窗口） */
  private samples: TimingSample[] = [];
  /** 当前 EWMA 单条耗时（毫秒） */
  private ewmaPerItemMs = 0;
  /** 连续正常批次计数（卡顿恢复判定） */
  private normalBatchStreak = 0;
  /** 是否卡顿 */
  private stalled = false;
  /** 最近一次速率骤降后的最新单条耗时（卡顿期间 ETA 基于此值） */
  private stallPerItemMs = 0;

  /** 帧对齐：待刷新标志 */
  private dirty = false;
  /** 帧对齐：最近一次 UI 刷新时间戳 */
  private lastFlushAt = 0;
  /** 帧对齐：requestAnimationFrame 句柄 */
  private rafId: number | null = null;
  /** 帧对齐：强制刷新（end 时立即刷新，跳过节流） */
  private forceFlush = false;

  /** ===== 响应式状态（供 UI 读取） ===== */
  /** 进度百分比（0~100） */
  readonly percent: Ref<number> = ref(0);
  /** 已处理记录数 */
  readonly processedCount: Ref<number> = ref(0);
  /** 总记录数 */
  readonly totalCount: Ref<number> = ref(0);
  /** 已耗时（毫秒） */
  readonly elapsedMs: Ref<number> = ref(0);
  /** 预计剩余时间（毫秒） */
  readonly etaMs: Ref<number> = ref(0);
  /** 当前处理速率（条/秒） */
  readonly rate: Ref<number> = ref(0);
  /** 是否卡顿 */
  readonly isStalled: Ref<boolean> = ref(false);
  /** 进度文本 */
  readonly text: Ref<string> = ref("");

  constructor(config?: Partial<ImportProgressConfig>) {
    this.config = {
      windowSize: config?.windowSize ?? 15,
      ewmaAlpha: config?.ewmaAlpha ?? 0.3,
      stallThreshold: config?.stallThreshold ?? 3.0,
      stallRecoverBatches: config?.stallRecoverBatches ?? 2,
      minUpdateIntervalMs: config?.minUpdateIntervalMs ?? 16,
    };
  }

  /** 开始进度追踪 */
  start(total: number): void {
    this.startAt = performance.now();
    this.total = total;
    this.processed = 0;
    this.skipped = 0;
    this.samples = [];
    this.ewmaPerItemMs = 0;
    this.normalBatchStreak = 0;
    this.stalled = false;
    this.stallPerItemMs = 0;
    this.dirty = false;
    this.lastFlushAt = 0;
    this.forceFlush = false;

    // 初始化响应式状态
    this.percent.value = 0;
    this.processedCount.value = 0;
    this.totalCount.value = total;
    this.elapsedMs.value = 0;
    this.etaMs.value = total > 0 ? 0 : 0;
    this.rate.value = 0;
    this.isStalled.value = false;
    this.text.value = total > 0 ? `准备导入 ${total} 张照片…` : "";

    log.info(`进度追踪开始: total=${total}`);
  }

  /**
   * 更新进度（每完成一批调用）
   *
   * 滑动窗口加权预测：
 *   1. 记录本批次耗时样本到滑动窗口
   *   2. EWMA 更新单条平均耗时
   *   3. 速率骤降检测（当前耗时 / EWMA > stallThreshold）
   *   4. 标记 dirty，requestAnimationFrame 帧对齐刷新
   *
   * @param processedInBatch 本批次处理记录数（含去重跳过 + 失败）
   * @param batchElapsedMs 本批次耗时（毫秒）
   * @param skippedInBatch 本批次去重跳过数（可选）
   */
  update(processedInBatch: number, batchElapsedMs: number, skippedInBatch = 0): void {
    if (this.total === 0) return;

    this.processed += processedInBatch;
    this.skipped += skippedInBatch;

    // 单条平均耗时（防除零）
    const perItemMs = processedInBatch > 0 ? batchElapsedMs / processedInBatch : 0;

    // 记录样本到滑动窗口
    const sample: TimingSample = {
      count: processedInBatch,
      elapsedMs: batchElapsedMs,
      perItemMs,
      timestamp: performance.now(),
    };
    this.samples.push(sample);
    if (this.samples.length > this.config.windowSize) {
      this.samples.shift();
    }

    // EWMA 更新（首次样本直接初始化）
    if (this.ewmaPerItemMs === 0) {
      this.ewmaPerItemMs = perItemMs;
    } else {
      const alpha = this.config.ewmaAlpha;
      this.ewmaPerItemMs = alpha * perItemMs + (1 - alpha) * this.ewmaPerItemMs;
    }

    // 速率骤降检测
    this.detectStall(perItemMs);

    // 标记 dirty，请求帧对齐刷新
    this.dirty = true;
    this.requestFlush();
  }

  /** 速率骤降检测 */
  private detectStall(currentPerItemMs: number): void {
    if (this.ewmaPerItemMs === 0 || currentPerItemMs === 0) return;

    const ratio = currentPerItemMs / this.ewmaPerItemMs;

    if (this.stalled) {
      // 卡顿恢复判定：连续 N 批正常耗时
      if (ratio < this.config.stallThreshold) {
        this.normalBatchStreak++;
        if (this.normalBatchStreak >= this.config.stallRecoverBatches) {
          this.stalled = false;
          this.stallPerItemMs = 0;
          this.normalBatchStreak = 0;
          log.info("卡顿恢复，恢复正常进度计算");
        }
      } else {
        // 仍然卡顿，重置恢复计数
        this.normalBatchStreak = 0;
        // 更新卡顿期间的最新耗时（ETA 基于此值）
        this.stallPerItemMs = currentPerItemMs;
      }
    } else {
      // 卡顿触发判定
      if (ratio > this.config.stallThreshold) {
        this.stalled = true;
        this.stallPerItemMs = currentPerItemMs;
        this.normalBatchStreak = 0;
        log.warn(
          `速率骤降检测: 当前 ${currentPerItemMs.toFixed(1)}ms/张, ` +
            `EWMA ${this.ewmaPerItemMs.toFixed(1)}ms/张, ratio=${ratio.toFixed(1)}, ` +
            `触发卡顿模式`,
        );
      }
    }
  }

  /** 请求帧对齐刷新（requestAnimationFrame） */
  private requestFlush(): void {
    if (this.rafId !== null) return;

    this.rafId = requestAnimationFrame(() => {
      this.rafId = null;
      this.flush();
    });
  }

  /** 刷新响应式状态（帧对齐，节流） */
  private flush(): void {
    const now = performance.now();

    // 节流：非强制刷新时，最小间隔 minUpdateIntervalMs
    if (!this.forceFlush && now - this.lastFlushAt < this.config.minUpdateIntervalMs) {
      // 未到刷新间隔，重新请求下一帧
      this.requestFlush();
      return;
    }

    this.lastFlushAt = now;
    this.dirty = false;
    this.forceFlush = false;

    // 计算当前快照
    const snapshot = this.snapshot();
    this.percent.value = snapshot.percent;
    this.processedCount.value = snapshot.processed;
    this.totalCount.value = snapshot.total;
    this.elapsedMs.value = snapshot.elapsedMs;
    this.etaMs.value = snapshot.etaMs;
    this.rate.value = snapshot.rate;
    this.isStalled.value = snapshot.isStalled;
    this.text.value = snapshot.text;
  }

  /** 计算当前进度快照 */
  snapshot(): ProgressSnapshot {
    const elapsedMs = performance.now() - this.startAt;
    const remaining = Math.max(0, this.total - this.processed);

    // 进度百分比：真实映射，不虚假
    // 卡顿时略微压缩（避免过早到 100%）：卡顿期间 percent 上限设为 95%
    let percent = this.total > 0 ? (this.processed / this.total) * 100 : 0;
    if (this.stalled && percent > 95) {
      percent = 95;
    }
    percent = Math.min(100, Math.max(0, percent));

    // ETA 计算：卡顿期间基于骤降后的最新耗时，否则基于 EWMA
    const effectivePerItemMs = this.stalled && this.stallPerItemMs > 0
      ? this.stallPerItemMs
      : this.ewmaPerItemMs;
    const etaMs = remaining * effectivePerItemMs;

    // 当前速率（条/秒）
    const rate = effectivePerItemMs > 0 ? 1000 / effectivePerItemMs : 0;

    // 进度文本
    let text: string;
    if (this.processed === 0) {
      text = `准备导入 ${this.total} 张照片…`;
    } else if (this.processed >= this.total) {
      text = `完成：${this.total} 张照片已导入`;
    } else if (this.stalled) {
      text = `加密中…${this.processed}/${this.total}（速率波动，优化中）`;
    } else {
      text = `加密中…${this.processed}/${this.total}`;
    }

    return {
      percent: Math.round(percent),
      processed: this.processed,
      total: this.total,
      elapsedMs: Math.round(elapsedMs),
      etaMs: Math.round(etaMs),
      rate: Math.round(rate * 10) / 10,
      isStalled: this.stalled,
      text,
    };
  }

  /** 结束进度追踪（强制刷新最终状态） */
  end(): void {
    // 强制刷新到 100%
    this.forceFlush = true;
    this.flush();

    // 取消待处理的 rAF
    if (this.rafId !== null) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }

    // 最终状态：100%
    this.percent.value = 100;
    this.text.value = `完成：${this.total} 张照片已导入`;

    log.info(
      `进度追踪结束: processed=${this.processed}, skipped=${this.skipped}, ` +
        `elapsed=${this.elapsedMs.value}ms`,
    );
  }

  /** 重置进度状态（用于异常恢复后重新开始） */
  reset(): void {
    if (this.rafId !== null) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
    this.startAt = 0;
    this.total = 0;
    this.processed = 0;
    this.skipped = 0;
    this.samples = [];
    this.ewmaPerItemMs = 0;
    this.normalBatchStreak = 0;
    this.stalled = false;
    this.stallPerItemMs = 0;
    this.dirty = false;
    this.lastFlushAt = 0;
    this.forceFlush = false;

    this.percent.value = 0;
    this.processedCount.value = 0;
    this.totalCount.value = 0;
    this.elapsedMs.value = 0;
    this.etaMs.value = 0;
    this.rate.value = 0;
    this.isStalled.value = false;
    this.text.value = "";
  }
}
