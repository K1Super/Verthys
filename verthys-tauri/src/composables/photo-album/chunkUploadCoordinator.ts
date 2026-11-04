/**
 * chunkUploadCoordinator.ts — 外置块跨照片批量上传协调器
 *
 * =============================================================================
 * 为什么需要协调器
 * =============================================================================
 * 单张照片独立上传分块时，每次上传都触发一次容器事务提交与磁盘刷盘。
 * 实测慢盘上一次提交约 0.5–1.3s；100 张照片即 100 次提交，导入耗时随照片数
 * 线性膨胀，并在命令通道中堆积超过发送超时，产生大量伪失败。
 *
 * 协调器把并发生产者的分块按「条数 + 载荷预算」聚合成批：
 *   - 单条 IPC 覆盖多张照片的块，容器提交次数降为 ⌈块数 / 批上限⌉；
 *   - 并发在途批次有硬上限，命令通道不会堆积到超时；
 *   - 命令级失败（通道繁忙/超时）按幂等块键整批重试，不再直接把照片判死；
 *   - 单块被后端拒绝时只失败该块所属导入项，其余块继续落库。
 *
 * =============================================================================
 * 失败语义
 * =============================================================================
 * - 命令级失败（ok=false / 网络异常）→ 指数退避重试；耗尽后该批全部失败；
 * - 项级失败（ok=true 且 failed_indices 命中）→ 只失败对应导入项；
 * - 会话关闭/取消 → 拒绝所有未决导入项，生产者可立即收尾，不会永久挂起。
 */

import {
  MAX_IPC_PAYLOAD_BYTES,
  MAX_CHUNKS_PER_IPC,
} from "../../constants/crypto_const";
import { createLogger } from "../../utils/logger";

const log = createLogger("chunk-upload");

/** 外置块上传失败（区别于加密失败，可重试；供失败分类识别） */
export class ChunkUploadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChunkUploadError";
  }
}

/** 单块上传请求 */
export interface ChunkUploadItem {
  chunk_key: string;
  data_b64: string;
  /** 记录类型（块/缩略图/块集/文件块；缺省=块） */
  rtype?: number;
}

/** 批量上传响应（与后端 verthys_add_chunk_batch 契约一致） */
export interface ChunkUploadResponse {
  ok: boolean;
  ids: number[];
  failed_indices: number[];
  error?: string | null;
}

/** 底层批量上传函数（测试可注入） */
export type ChunkUploadApi = (
  items: ChunkUploadItem[],
) => Promise<ChunkUploadResponse>;

export interface ChunkUploadCoordinatorOptions {
  /** 单批最大块数（默认跨层预算 MAX_CHUNKS_PER_IPC） */
  maxChunksPerBatch?: number;
  /** 单批最大载荷字符数（默认 IPC 预算的 80%） */
  maxBatchBytes?: number;
  /** 并发在途批次数上限（默认 2） */
  maxInflightBatches?: number;
  /** 命令级失败重试次数（不含首次，默认 2） */
  maxRetries?: number;
  /** 首次重试退避（毫秒，默认 50；后续按次数线性增长） */
  retryDelayMs?: number;
  /** 聚合窗口（毫秒，默认 12；让并发生产者同批上传） */
  coalesceWindowMs?: number;
}

/** 单个导入项（一次 uploadChunks 调用）的上传状态 */
interface UploadJob {
  ids: Array<number | undefined>;
  remaining: number;
  settled: boolean;
  resolve: (ids: number[]) => void;
  reject: (error: Error) => void;
}

/** 待上传块（携带所属导入项与输入序号） */
interface PendingChunk {
  item: ChunkUploadItem;
  bytes: number;
  index: number;
  job: UploadJob;
}

const DEFAULT_OPTIONS: Required<ChunkUploadCoordinatorOptions> = {
  maxChunksPerBatch: MAX_CHUNKS_PER_IPC,
  maxBatchBytes: MAX_IPC_PAYLOAD_BYTES * 0.8,
  maxInflightBatches: 2,
  maxRetries: 2,
  retryDelayMs: 50,
  coalesceWindowMs: 12,
};

/**
 * 外置块批量上传协调器（每个导入会话一个实例）。
 *
 * 生命周期：`runSession` 创建 → 生产者通过 `uploadChunks` 上传 →
 * 会话结束/取消时 `close` 拒绝未决项。实例不可跨会话复用。
 */
export class ChunkUploadCoordinator {
  private readonly opts: Required<ChunkUploadCoordinatorOptions>;
  private pending: PendingChunk[] = [];
  private jobs = new Set<UploadJob>();
  private inflight = 0;
  private pumping = false;
  private closed = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private capacityWaiters: Array<() => void> = [];

  constructor(
    private readonly upload: ChunkUploadApi,
    options: ChunkUploadCoordinatorOptions = {},
  ) {
    this.opts = { ...DEFAULT_OPTIONS, ...options };
  }

  /**
   * 上传一个导入项的全部分块，返回与输入等长、顺序一致的记录 ID。
   *
   * 并发调用会被聚合成更少的后端批次；返回值顺序不受聚合影响。
   */
  uploadChunks(items: ReadonlyArray<ChunkUploadItem>): Promise<number[]> {
    if (this.closed) {
      return Promise.reject(new ChunkUploadError("导入会话已结束"));
    }
    if (items.length === 0) {
      return Promise.resolve([]);
    }

    let resolveJob!: (ids: number[]) => void;
    let rejectJob!: (error: Error) => void;
    const promise = new Promise<number[]>((resolve, reject) => {
      resolveJob = resolve;
      rejectJob = reject;
    });
    const job: UploadJob = {
      ids: new Array<number | undefined>(items.length),
      remaining: items.length,
      settled: false,
      resolve: resolveJob,
      reject: rejectJob,
    };
    this.jobs.add(job);

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      this.pending.push({
        item,
        bytes: item.chunk_key.length + item.data_b64.length,
        index: i,
        job,
      });
    }

    /* 满批立即调度；未满批等待聚合窗口，让同一时间片内的其他导入项
     * 把分块并入同一后端事务。 */
    this.schedule(this.pending.length >= this.opts.maxChunksPerBatch);
    return promise;
  }

  /**
   * 关闭协调器：拒绝所有未决导入项并停止后续调度。
   *
   * 幂等；在途批次返回后只更新已关闭的 job（其 settled=true，结果被忽略）。
   */
  close(reason: string = "导入会话已结束"): void {
    if (this.closed) return;
    this.closed = true;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.pending = [];
    const error = new ChunkUploadError(reason);
    for (const job of this.jobs) {
      if (!job.settled) {
        job.settled = true;
        job.reject(error);
      }
    }
    this.jobs.clear();
    this.wakeCapacityWaiters();
  }

  /** 当前待上传块数（诊断/测试） */
  get pendingCount(): number {
    return this.pending.length;
  }

  /* ------------------------------------------------------------------ *
   * 调度与批量执行                                                      *
   * ------------------------------------------------------------------ */

  /** 调度一次泵送；immediate=true 时立即触发（满批或上一批完成） */
  private schedule(immediate: boolean): void {
    if (this.closed) return;
    if (immediate) {
      if (this.timer !== null) {
        clearTimeout(this.timer);
        this.timer = null;
      }
      void this.pump();
      return;
    }
    if (this.timer !== null) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.pump();
    }, this.opts.coalesceWindowMs);
  }

  private async pump(): Promise<void> {
    if (this.pumping) return;
    this.pumping = true;
    try {
      while (!this.closed) {
        while (
          !this.closed &&
          this.inflight >= this.opts.maxInflightBatches
        ) {
          await new Promise<void>((resolve) => {
            this.capacityWaiters.push(resolve);
          });
        }
        if (this.closed) break;

        const batch = this.takeBatch();
        if (batch.length === 0) break;

        this.inflight++;
        /* 不 await：允许在途批次达到上限后并行执行；每个批次完成时
         * 递减并唤醒下一个泵送者。显式 catch 防止未处理拒绝。 */
        void this.runBatch(batch).catch((error) => {
          log.error("外置块批次异常", error);
          const err = error instanceof Error ? error : new Error(String(error));
          for (const slot of batch) {
            this.failJob(slot.job, err);
          }
        });
      }
    } finally {
      this.pumping = false;
    }
  }

  /** 按 FIFO 取一批（条数 + 载荷双预算），丢弃已失败导入项的残留块 */
  private takeBatch(): PendingChunk[] {
    const batch: PendingChunk[] = [];
    let bytes = 0;
    while (this.pending.length > 0 && batch.length < this.opts.maxChunksPerBatch) {
      const next = this.pending[0];
      if (next.job.settled) {
        this.pending.shift();
        continue;
      }
      if (batch.length > 0 && bytes + next.bytes > this.opts.maxBatchBytes) {
        break;
      }
      this.pending.shift();
      batch.push(next);
      bytes += next.bytes;
    }
    return batch;
  }

  private async runBatch(batch: PendingChunk[]): Promise<void> {
    try {
      let lastError: Error = new ChunkUploadError("外置块上传失败");

      for (let attempt = 0; attempt <= this.opts.maxRetries; attempt++) {
        if (this.closed) {
          lastError = new ChunkUploadError("导入会话已结束");
          break;
        }
        try {
          const response = await this.upload(batch.map((slot) => slot.item));
          if (response.ok) {
            this.applyResponse(batch, response);
            return;
          }
          lastError = new ChunkUploadError(
            response.error || "外置块上传被后端拒绝",
          );
        } catch (e) {
          lastError = e instanceof Error ? e : new ChunkUploadError(String(e));
        }
        if (attempt < this.opts.maxRetries && !this.closed) {
          await sleep(this.opts.retryDelayMs * (attempt + 1));
        }
      }

      for (const slot of batch) {
        this.failJob(slot.job, lastError);
      }
      log.warn(
        `外置块批量上传失败（${batch.length} 块，已重试 ${this.opts.maxRetries} 次）: ${lastError.message}`,
      );
    } finally {
      this.releaseBatch();
    }
  }

  private applyResponse(
    batch: PendingChunk[],
    response: ChunkUploadResponse,
  ): void {
    const failed = new Set(response.failed_indices);
    for (let i = 0; i < batch.length; i++) {
      const slot = batch[i];
      const id = response.ids[i];
      if (failed.has(i) || !Number.isInteger(id) || id <= 0) {
        this.failJob(
          slot.job,
          new ChunkUploadError(
            response.error || "外置块被后端拒绝",
          ),
        );
        continue;
      }
      this.completeSlot(slot, id);
    }
  }

  private completeSlot(slot: PendingChunk, id: number): void {
    const job = slot.job;
    if (job.settled) return;
    job.ids[slot.index] = id;
    job.remaining--;
    if (job.remaining === 0) {
      job.settled = true;
      this.jobs.delete(job);
      job.resolve(job.ids as number[]);
    }
  }

  private failJob(job: UploadJob, error: Error): void {
    if (job.settled) return;
    job.settled = true;
    this.jobs.delete(job);
    job.reject(error);
  }

  private wakeCapacityWaiters(): void {
    while (this.capacityWaiters.length > 0) {
      const waiter = this.capacityWaiters.shift();
      if (waiter) waiter();
    }
  }

  /** 批次完成回调：释放在途配额并继续泵送剩余块 */
  private releaseBatch(): void {
    this.inflight--;
    const waiter = this.capacityWaiters.shift();
    if (waiter) waiter();
    if (!this.closed && this.pending.length > 0) {
      this.schedule(true);
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
