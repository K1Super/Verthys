/**
 * composables/photo-album/importPipeline.ts — 照片导入三阶段异步流水线
 *
 * ★ Comprehensive_optimization：异步批处理流水线 — 核心编排器
 *
 * =============================================================================
 * 架构：三阶段完全解耦流水线
 * =============================================================================
 * | 阶段     | 位置           | 职责                                   | 并发模型              |
 * |---------|----------------|----------------------------------------|-----------------------|
 * | 生产者  | 渲染主线程     | 文件读取、哈希去重、分片打包           | 单线程 + 流式读取     |
 * | 传输器  | Worker 线程池  | AES-256-GCM 加密 + 元数据序列化        | 多线程并发（CPU-1）   |
 * | 消费者  | 主进程（IPC）  | 批量写入存储、同步三层缓存、持久化 WAL | 单线程 + 批量事务     |
 *
 * =============================================================================
 * 背压队列
 * =============================================================================
 * 主进程维护待消费批次计数器，未处理批次数超过阈值（3 批）时，
 * 主动暂停向工作线程投喂新任务，防止内存暴涨。
 * - Worker 池内置背压（maxPendingTasks = poolSize * 4）
 * - 消费者批次数背压（maxInflightBatches = 3）
 * - 双重背压保证内存峰值 < 500MB
 *
 * =============================================================================
 * 数据流路径
 * =============================================================================
 * 1. 生产者读取文件 → ArrayBuffer（transferList 零拷贝到 Worker）
 * 2. 传输器 Worker 池并行加密 → { hash, thumbB64, metaB64, name }
 * 3. 生产者检查 hash 去重（committed_hashes）→ 跳过已导入
 * 4. 消费者积累 N 条 → verthysAddRecordsBatch IPC（N 次加密，1 次 IPC）
 * 5. 消费者更新 batchCacheCoordinator（批量三层缓存同步）
 * 6. 进度状态机 update() → requestAnimationFrame 帧对齐刷新
 * 7. 全部完成 → flush 缓存 → verthysImportEnd(true) → persistVerthys
 *
 * =============================================================================
 * 断点续传
 * =============================================================================
 * - verthysImportBegin 返回 committed_hashes（从遗留 WAL 恢复）
 * - 生产者据此跳过已 committed 的文件（无需重复加密）
 * - 每批次 verthysAddRecordsBatch 后端写 WAL 检查点
 * - 崩溃后重启，verthysWalRecover 恢复 committed_hashes，续传
 */
import { photoWorkerPool } from "../../workers/photoWorkerPool";
import { BatchCacheCoordinator, batchCacheCoordinator } from "../../cache/coordination/batch-cache-coordinator";
import { ImportProgressState } from "./importProgress";
import {
  verthysImportBegin,
  verthysAddRecordsBatch,
  verthysImportEnd,
  verthysWalRecover,
  type ImportBeginResult,
  type AddRecordsBatchResult,
  type ImportBatchProgress,
  type BatchRecordInput,
} from "../../lib/verthys";
import { TYPE_PHOTO_META } from "../../constants/crypto_const";
import type { PhotoCryptoSuccess, PhotoMetaCryptoSuccess } from "../../workers/photo-crypto.worker";
import type { PhotoMeta } from "../../lib/crypto";
import type { PhotoEntry, ParsedPhotoPreview } from "./types";
import { formatSize } from "./utils";
import { createLogger } from "../../utils/logger";
import { yieldToMain } from "../../utils/promise_utils";

const log = createLogger("import-pipeline");

/** 流水线配置 */
export interface ImportPipelineConfig {
  /** 消费者批量大小（每次 IPC 写入的记录数，默认 50） */
  consumerBatchSize: number;
  /** 最大在途批次数（背压阈值，默认 3） */
  maxInflightBatches: number;
  /** 是否启用断点续传（默认 true） */
  enableResume: boolean;
  /** 生产者并发数（并行文件读取，默认 hardwareConcurrency * 2） */
  producerConcurrency: number;
  /** 生产者让出间隔（每处理 N 个文件后 yieldToMain，默认 1） */
  producerYieldInterval: number;
}

/** 单个文件输入（生产者原料） */
export interface ImportFileInput {
  /** 文件名 */
  name: string;
  /** MIME 类型 */
  mime: string;
  /** 读取文件字节（流式，避免一次性加载全部到内存） */
  readBytes: () => Promise<Uint8Array>;
}

/** 单个照片导入结果（用于构建 PhotoEntry） */
export interface ImportedPhotoResult {
  /** verthys 记录 ID（metaId） */
  metaId: number;
  /** 文件名 */
  name: string;
  /** 缩略图 base64 */
  thumbB64: string;
  /** 文件大小（字节） */
  size: number;
  /** MIME 类型 */
  mime: string;
}

/** 流水线执行结果 */
export interface ImportPipelineResult {
  /** 是否成功完成 */
  ok: boolean;
  /** 成功导入的照片列表（用于构建 PhotoEntry） */
  imported: ImportedPhotoResult[];
  /** 去重跳过的照片数 */
  skipped: number;
  /** 失败的照片数 */
  failed: number;
  /** 总耗时（毫秒） */
  elapsedMs: number;
  /** 错误信息（ok=false 时有值） */
  error?: string;
}

/**
 * 照片导入三阶段异步流水线
 *
 * 编排生产者 → 传输器 → 消费者三阶段，落实：
 * - 异步批处理（N 次加密，1 次 IPC）
 * - 背压队列（防止内存暴涨）
 * - 哈希去重（断点续传幂等）
 * - 帧对齐进度反馈
 */
export class ImportPipeline {
  private readonly config: ImportPipelineConfig;
  /** 进度状态机 */
  readonly progress: ImportProgressState;
  /** 批量缓存协调器（独立实例，避免单例污染） */
  readonly batchCache: BatchCacheCoordinator;

  constructor(config?: Partial<ImportPipelineConfig>) {
    this.config = {
      consumerBatchSize: config?.consumerBatchSize ?? 50,
      maxInflightBatches: config?.maxInflightBatches ?? 3,
      enableResume: config?.enableResume ?? true,
      producerConcurrency: config?.producerConcurrency ?? Math.max(2, (navigator.hardwareConcurrency || 4) * 2),
      producerYieldInterval: config?.producerYieldInterval ?? 1,
    };
    this.progress = new ImportProgressState();
    this.batchCache = new BatchCacheCoordinator();
  }

  /**
   * 执行照片导入流水线
   *
   * @param files 待导入文件列表
   * @param photoKey 照片模块独立密钥
   * @returns 导入结果（含成功列表 / 跳过数 / 失败数 / 耗时）
   */
  async run(
    files: ImportFileInput[],
    photoKey: string,
  ): Promise<ImportPipelineResult> {
    if (files.length === 0) {
      return { ok: true, imported: [], skipped: 0, failed: 0, elapsedMs: 0 };
    }

    const startAt = performance.now();
    log.info(`导入流水线启动: ${files.length} 张照片`);

    // ===== 阶段 0：初始化导入会话（WAL + 续传去重哈希集） =====
    let beginResult: ImportBeginResult;
    try {
      beginResult = await this.beginImportSession();
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      log.error("导入会话初始化失败:", e);
      return {
        ok: false,
        imported: [],
        skipped: 0,
        failed: files.length,
        elapsedMs: performance.now() - startAt,
        error: `导入会话初始化失败: ${error}`,
      };
    }

    // committed 哈希集（生产者去重 + 续传幂等）
    const committedHashes = new Set<string>(beginResult.hashes);
    log.info(`导入会话已建立: import_id=${beginResult.import_id}, 已 committed=${committedHashes.size}`);

    // ===== 启动进度追踪 =====
    this.progress.start(files.length);
    this.batchCache.begin();

    // ===== 收集导入结果 =====
    const imported: ImportedPhotoResult[] = [];
    let skipped = 0;
    let failed = 0;

    // ===== 消费者批量缓冲 =====
    let consumerBuffer: BatchRecordInput[] = [];
    let consumerResults: PhotoCryptoSuccess[] = [];

    /** 刷新消费者批量缓冲到后端 IPC */
    const flushConsumer = async (): Promise<void> => {
      if (consumerBuffer.length === 0) return;

      const batch = consumerBuffer.splice(0);
      const batchResults = consumerResults.splice(0);
      const batchStartAt = performance.now();

      try {
        const result = await this.consumeBatch(batch);
        const batchElapsed = performance.now() - batchStartAt;

        // 将 IPC 返回的 ID 映射回导入结果
        for (let i = 0; i < batchResults.length; i++) {
          const success = batchResults[i];
          const metaId = result.ids[i] ?? 0;
          if (metaId > 0) {
            imported.push({
              metaId,
              name: success.name,
              thumbB64: success.thumbB64,
              size: success.size,
              mime: success.mime,
            });
            // 添加到批量缓存协调器（L1/L2/L3 批量同步）
            this.batchCache.addRecord({
              id: metaId,
              type: TYPE_PHOTO_META,
              name: success.name,
              dataB64: success.metaB64,
              dataSize: success.metaB64.length,
            });
          }
        }

        skipped += result.skipped_count;

        // 进度已由生产者逐文件更新（per-file），此处不再重复更新
        log.info(
          `批次 ${result.batch_id} 完成: processed=${result.processed_count}, ` +
            `skipped=${result.skipped_count}, committed=${result.total_count}, ` +
            `elapsed=${batchElapsed.toFixed(1)}ms`,
        );

        // ★ 让出主线程：IPC 完成后 yieldToMain，保证 rAF 进度回调执行
        await yieldToMain();
      } catch (e) {
        const error = e instanceof Error ? e.message : String(e);
        log.error("消费者批次写入失败:", e);
        if (error === "VERTHYS_WRITE_BLOCKED") {
          throw e; // 向上传播，触发格式升级提示
        }
        // 其他错误：该批次全部计入失败
        failed += batch.length;
      }
    };

    // ===== 阶段 1+2：生产者 + 传输器（流式并行 + 主线程让出） =====
    try {
      // 使用信号量控制消费者在途批次数（背压）
      let inflightBatches = 0;
      const maxInflight = this.config.maxInflightBatches;
      const inflightWaiters: Array<() => void> = [];

      /** 等待消费者在途批次数低于阈值（背压） */
      const waitForInflightSlot = (): Promise<void> => {
        if (inflightBatches < maxInflight) {
          return Promise.resolve();
        }
        return new Promise<void>((resolve) => {
          inflightWaiters.push(resolve);
        });
      };

      /** 通知背压等待者（在途批次减少） */
      const notifyInflightSlot = (): void => {
        while (inflightWaiters.length > 0 && inflightBatches < maxInflight) {
          const waiter = inflightWaiters.shift();
          if (waiter) waiter();
        }
      };

      // ★ P0+P1 修复：生产者并行化 + yieldToMain 让出主线程
      //
      // 根因：旧实现 for 循环内 await readBytes() 串行读取，主线程被永久阻塞，
      //       requestAnimationFrame 回调被挤压在任务队列末尾，进度条冻结。
      //
      // 修复：
      //   1. P1：N 个并发生产者（N = hardwareConcurrency * 2），并行 readBytes
      //   2. P0：每处理完一个文件后 yieldToMain()，强制让出主线程，
      //          保证 rAF 进度回调得到执行机会
      //   3. 进度逐文件更新（per-file），而非逐 IPC 批次更新，
      //          用户感知到「真实加密进度」而非「IPC 写入进度」
      const submitPromises: Promise<void>[] = [];

      /** 并发生产者：从共享索引拉取文件 → 读取 → 提交到 Worker 池 → yieldToMain */
      const producerConcurrency = Math.min(
        files.length,
        this.config.producerConcurrency,
      );
      let producerIndex = 0;

      const producer = async (): Promise<void> => {
        let filesSinceYield = 0;

        while (true) {
          // 原子拉取下一个文件索引（JS 单线程，无竞态）
          const i = producerIndex++;
          if (i >= files.length) break;

          const fileInput = files[i];

          // 读取文件字节（生产者阶段，与其他生产者并行）
          let fileBytes: Uint8Array;
          try {
            fileBytes = await fileInput.readBytes();
          } catch (e) {
            log.error(`读取文件失败: ${fileInput.name}`, e);
            failed++;
            this.progress.update(1, 0);
            // ★ 让出主线程，保证 rAF 执行
            await yieldToMain();
            continue;
          }

          // 转为 ArrayBuffer（transferList 零拷贝转让到 Worker）
          const arrayBuffer = fileBytes.buffer.slice(
            fileBytes.byteOffset,
            fileBytes.byteOffset + fileBytes.byteLength,
          ) as ArrayBuffer;

          // 记录提交时间（用于计算单文件加密耗时）
          const submitTime = performance.now();

          // 提交到 Worker 池（传输器阶段，自带背压）
          // ★ 不 await submit()：让加密与下一次文件读取并行（真正的流水线）
          const submitPromise = photoWorkerPool
            .submit({
              fileName: fileInput.name,
              mime: fileInput.mime,
              fileBytes: arrayBuffer,
              photoKey,
            })
            .then(async (success: PhotoCryptoSuccess) => {
              // 计算单文件加密耗时（提交 → 完成）
              const fileElapsed = performance.now() - submitTime;

              // ===== 生产者去重（断点续传幂等） =====
              if (committedHashes.has(success.hash)) {
                skipped++;
                this.progress.update(1, fileElapsed, 1);
                return;
              }

              // ★ 逐文件进度更新：文件加密完成即推进进度
              //   旧实现仅在 IPC 批次完成后更新 → 加密期间进度条冻结
              //   新实现：per-file update → 用户实时感知「正在加密第 N 张」
              this.progress.update(1, fileElapsed);

              // 构造 BatchRecordInput
              const record: BatchRecordInput = {
                rtype: TYPE_PHOTO_META,
                name: success.name,
                hash: success.hash,
                data_b64: success.metaB64,
              };

              // ★ 竞态修复：buffer 已满时仅第一个回调触发 flush，后续回调跳过
              //  JS 单线程 + splice 原子清空保证数据不丢失，此处避免冗余 inflightBatches 操作
              consumerBuffer.push(record);
              consumerResults.push(success);

              // 达到消费者批量大小，触发 IPC 写入
              if (consumerBuffer.length >= this.config.consumerBatchSize) {
                await waitForInflightSlot();
                // ★ 二次检查：await 期间 buffer 可能已被其他回调 flush 清空
                //  若已清空，直接返回（不占用 inflightBatches slot，避免负数）
                if (consumerBuffer.length === 0) {
                  return;
                }
                inflightBatches++;
                try {
                  await flushConsumer();
                } finally {
                  inflightBatches--;
                  notifyInflightSlot();
                }
              }
            })
            .catch((e: Error) => {
              log.error(`加密失败: ${fileInput.name}`, e);
              if (e.message === "VERTHYS_WRITE_BLOCKED") {
                throw e;
              }
              failed++;
              this.progress.update(1, 0);
            });

          submitPromises.push(submitPromise);

          // ★ P0 核心：每处理 N 个文件后 yieldToMain，强制让出主线程
          //   保证 requestAnimationFrame 回调（进度条渲染）得到执行机会
          //   这是让进度条「真正动起来」的唯一解
          filesSinceYield++;
          if (filesSinceYield >= this.config.producerYieldInterval) {
            filesSinceYield = 0;
            await yieldToMain();
          }
        }
      };

      // 启动 N 个并发生产者
      await Promise.allSettled(
        Array.from({ length: producerConcurrency }, () => producer()),
      );

      // 等待所有加密任务完成（生产者已全部退出，但 Worker 池可能仍有在途任务）
      await Promise.allSettled(submitPromises);

      // ===== 阶段 3：刷新剩余消费者缓冲 =====
      if (consumerBuffer.length > 0) {
        await flushConsumer();
      }

      // ===== 刷新批量缓存（三层同步） =====
      await this.batchCache.end();

      // ===== 结束导入会话（WAL 压缩） =====
      await verthysImportEnd(true);

      // ===== 结束进度追踪 =====
      this.progress.end();

      const elapsedMs = performance.now() - startAt;
      log.info(
        `导入流水线完成: imported=${imported.length}, skipped=${skipped}, ` +
          `failed=${failed}, elapsed=${elapsedMs.toFixed(0)}ms`,
      );

      return {
        ok: true,
        imported,
        skipped,
        failed,
        elapsedMs,
      };
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      log.error("导入流水线异常:", e);

      // 异常时结束会话（保留 WAL 供续传）
      try {
        await this.batchCache.end();
        await verthysImportEnd(false);
      } catch {
        // 结束会话失败忽略
      }

      this.progress.end();

      return {
        ok: false,
        imported,
        skipped,
        failed: failed + (files.length - imported.length - skipped - failed),
        elapsedMs: performance.now() - startAt,
        error,
      };
    }
  }

  /**
   * ★ Parsed Import：执行 .venc 解析照片的导入流水线
   *
   * 与 run() 的区别：
   *   - 输入：ParsedPhotoPreview[]（已解密的 meta + 已加密的 chunks）
   *   - 加密：仅重新加密 meta（chunks 已用当前 photoKey 加密，同设备导入）
   *   - 传输器：使用 submitMetaOnly() 而非 submit()
   *   - 无文件读取、无缩略图生成、无 chunk 加密
   *
   * 共享基础设施：
   *   - WAL 断点续传（verthysImportBegin / verthysAddRecordsBatch / verthysImportEnd）
   *   - 批量 IPC（N 次加密，1 次 IPC 写入）
   *   - 背压队列（maxInflightBatches）
   *   - 进度状态机（ImportProgressState，逐文件更新 + rAF 帧对齐）
   *   - 哈希去重（committedHashes，断点续传幂等）
   *   - 批量三层缓存同步（BatchCacheCoordinator）
   *
   * @param parsedPhotos 解析预览列表（doParse 阶段产出）
   * @param photoKey 照片模块独立密钥
   * @returns 导入结果（含成功列表 / 跳过数 / 失败数 / 耗时）
   */
  async runParsed(
    parsedPhotos: ParsedPhotoPreview[],
    photoKey: string,
  ): Promise<ImportPipelineResult> {
    if (parsedPhotos.length === 0) {
      return { ok: true, imported: [], skipped: 0, failed: 0, elapsedMs: 0 };
    }

    const startAt = performance.now();
    log.info(`解析导入流水线启动: ${parsedPhotos.length} 张照片`);

    // ===== 阶段 0：初始化导入会话（WAL + 续传去重哈希集） =====
    let beginResult: ImportBeginResult;
    try {
      beginResult = await this.beginImportSession();
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      log.error("解析导入会话初始化失败:", e);
      return {
        ok: false,
        imported: [],
        skipped: 0,
        failed: parsedPhotos.length,
        elapsedMs: performance.now() - startAt,
        error: `导入会话初始化失败: ${error}`,
      };
    }

    // committed 哈希集（生产者去重 + 续传幂等）
    const committedHashes = new Set<string>(beginResult.hashes);
    log.info(`解析导入会话已建立: import_id=${beginResult.import_id}, 已 committed=${committedHashes.size}`);

    // ===== 启动进度追踪 =====
    this.progress.start(parsedPhotos.length);
    this.batchCache.begin();

    // ===== 收集导入结果 =====
    const imported: ImportedPhotoResult[] = [];
    let skipped = 0;
    let failed = 0;

    // ===== 消费者批量缓冲 =====
    let consumerBuffer: BatchRecordInput[] = [];
    let consumerResults: Array<{ name: string; thumbB64: string; size: number; mime: string }> = [];

    /** 刷新消费者批量缓冲到后端 IPC */
    const flushConsumer = async (): Promise<void> => {
      if (consumerBuffer.length === 0) return;

      const batch = consumerBuffer.splice(0);
      const batchResults = consumerResults.splice(0);
      const batchStartAt = performance.now();

      try {
        const result = await this.consumeBatch(batch);
        const batchElapsed = performance.now() - batchStartAt;

        // 将 IPC 返回的 ID 映射回导入结果
        for (let i = 0; i < batchResults.length; i++) {
          const success = batchResults[i];
          const metaId = result.ids[i] ?? 0;
          if (metaId > 0) {
            imported.push({
              metaId,
              name: success.name,
              thumbB64: success.thumbB64,
              size: success.size,
              mime: success.mime,
            });
            // 添加到批量缓存协调器（L1/L2/L3 批量同步）
            this.batchCache.addRecord({
              id: metaId,
              type: TYPE_PHOTO_META,
              name: success.name,
              dataB64: (batch[i] as BatchRecordInput).data_b64,
              dataSize: (batch[i] as BatchRecordInput).data_b64.length,
            });
          }
        }

        skipped += result.skipped_count;

        log.info(
          `解析批次 ${result.batch_id} 完成: processed=${result.processed_count}, ` +
            `skipped=${result.skipped_count}, committed=${result.total_count}, ` +
            `elapsed=${batchElapsed.toFixed(1)}ms`,
        );

        // ★ 让出主线程：IPC 完成后 yieldToMain，保证 rAF 进度回调执行
        await yieldToMain();
      } catch (e) {
        const error = e instanceof Error ? e.message : String(e);
        log.error("解析消费者批次写入失败:", e);
        if (error === "VERTHYS_WRITE_BLOCKED") {
          throw e; // 向上传播，触发格式升级提示
        }
        // 其他错误：该批次全部计入失败
        failed += batch.length;
      }
    };

    // ===== 阶段 1+2：生产者 + 传输器（meta-only 并行加密 + 主线程让出） =====
    try {
      // 使用信号量控制消费者在途批次数（背压）
      let inflightBatches = 0;
      const maxInflight = this.config.maxInflightBatches;
      const inflightWaiters: Array<() => void> = [];

      /** 等待消费者在途批次数低于阈值（背压） */
      const waitForInflightSlot = (): Promise<void> => {
        if (inflightBatches < maxInflight) {
          return Promise.resolve();
        }
        return new Promise<void>((resolve) => {
          inflightWaiters.push(resolve);
        });
      };

      /** 通知背压等待者（在途批次减少） */
      const notifyInflightSlot = (): void => {
        while (inflightWaiters.length > 0 && inflightBatches < maxInflight) {
          const waiter = inflightWaiters.shift();
          if (waiter) waiter();
        }
      };

      // ★ 并发生产者：从共享索引拉取已解析照片 → 构造新 meta → 提交到 Worker 池 → yieldToMain
      //
      // 与 run() 的区别：
      //   1. 输入是 ParsedPhotoPreview（已解密 meta + 已加密 chunks），无需读取文件
      //   2. 使用 submitMetaOnly() 而非 submit()（仅加密 meta，不加密 chunks）
      //   3. 仅处理 ph.meta 非 null 的照片（同设备导入场景）
      const submitPromises: Promise<void>[] = [];

      /** 并发生产者：从共享索引拉取已解析照片 → 构造新 meta → 提交到 Worker 池 → yieldToMain */
      const producerConcurrency = Math.min(
        parsedPhotos.length,
        this.config.producerConcurrency,
      );
      let producerIndex = 0;
      const importTimestamp = Date.now();

      const producer = async (): Promise<void> => {
        let filesSinceYield = 0;

        while (true) {
          // 原子拉取下一个照片索引（JS 单线程，无竞态）
          const i = producerIndex++;
          if (i >= parsedPhotos.length) break;

          const ph = parsedPhotos[i];

          // ★ 仅处理 meta 非 null 的照片（同设备导入：chunks 已用当前 photoKey 加密）
          //   meta 为 null 的照片（不同设备导入）跳过，由调用方在内存中保留
          if (!ph.meta) {
            failed++;
            this.progress.update(1, 0);
            await yieldToMain();
            continue;
          }

          // 构造新 meta：chunkDataB64 内联已加密的 chunks（不重新加密）
          const newMeta: PhotoMeta = {
            ...ph.meta,
            chunkIds: [],                        // 新格式不再使用单独 chunk 记录
            chunkDataB64: [...ph.chunkB64List], // 内联存储已加密 chunk
            createdAt: importTimestamp + i,      // 保证唯一性
          };

          // 记录名（与旧实现一致：`parsed_${timestamp}_${index}`）
          const recordName = `parsed_${importTimestamp}_${i}`;

          // 记录提交时间（用于计算单文件加密耗时）
          const submitTime = performance.now();

          // 提交到 Worker 池（meta-only 加密，自带背压）
          // ★ 不 await submitMetaOnly()：让加密与下一次构造并行（真正的流水线）
          const submitPromise = photoWorkerPool
            .submitMetaOnly({
              meta: newMeta,
              photoKey,
              recordName,
            })
            .then(async (success: PhotoMetaCryptoSuccess) => {
              // 计算单文件加密耗时（提交 → 完成）
              const fileElapsed = performance.now() - submitTime;

              // ===== 生产者去重（断点续传幂等） =====
              if (committedHashes.has(success.hash)) {
                skipped++;
                this.progress.update(1, fileElapsed, 1);
                return;
              }

              // ★ 逐文件进度更新：meta 加密完成即推进进度
              this.progress.update(1, fileElapsed);

              // 构造 BatchRecordInput
              const record: BatchRecordInput = {
                rtype: TYPE_PHOTO_META,
                name: success.recordName,
                hash: success.hash,
                data_b64: success.metaB64,
              };

              // ★ 竞态修复：buffer 已满时仅第一个回调触发 flush，后续回调跳过
              consumerBuffer.push(record);
              consumerResults.push({
                name: success.name,
                thumbB64: success.thumbB64,
                size: success.size,
                mime: success.mime,
              });

              // 达到消费者批量大小，触发 IPC 写入
              if (consumerBuffer.length >= this.config.consumerBatchSize) {
                await waitForInflightSlot();
                // ★ 二次检查：await 期间 buffer 可能已被其他回调 flush 清空
                if (consumerBuffer.length === 0) {
                  return;
                }
                inflightBatches++;
                try {
                  await flushConsumer();
                } finally {
                  inflightBatches--;
                  notifyInflightSlot();
                }
              }
            })
            .catch((e: Error) => {
              log.error(`meta-only 加密失败: ${recordName}`, e);
              if (e.message === "VERTHYS_WRITE_BLOCKED") {
                throw e;
              }
              failed++;
              this.progress.update(1, 0);
            });

          submitPromises.push(submitPromise);

          // ★ P0 核心：每处理 N 个照片后 yieldToMain，强制让出主线程
          //   保证 requestAnimationFrame 回调（进度条渲染）得到执行机会
          filesSinceYield++;
          if (filesSinceYield >= this.config.producerYieldInterval) {
            filesSinceYield = 0;
            await yieldToMain();
          }
        }
      };

      // 启动 N 个并发生产者
      await Promise.allSettled(
        Array.from({ length: producerConcurrency }, () => producer()),
      );

      // 等待所有加密任务完成（生产者已全部退出，但 Worker 池可能仍有在途任务）
      await Promise.allSettled(submitPromises);

      // ===== 阶段 3：刷新剩余消费者缓冲 =====
      if (consumerBuffer.length > 0) {
        await flushConsumer();
      }

      // ===== 刷新批量缓存（三层同步） =====
      await this.batchCache.end();

      // ===== 结束导入会话（WAL 压缩） =====
      await verthysImportEnd(true);

      // ===== 结束进度追踪 =====
      this.progress.end();

      const elapsedMs = performance.now() - startAt;
      log.info(
        `解析导入流水线完成: imported=${imported.length}, skipped=${skipped}, ` +
          `failed=${failed}, elapsed=${elapsedMs.toFixed(0)}ms`,
      );

      return {
        ok: true,
        imported,
        skipped,
        failed,
        elapsedMs,
      };
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      log.error("解析导入流水线异常:", e);

      // 异常时结束会话（保留 WAL 供续传）
      try {
        await this.batchCache.end();
        await verthysImportEnd(false);
      } catch {
        // 结束会话失败忽略
      }

      this.progress.end();

      return {
        ok: false,
        imported,
        skipped,
        failed: failed + (parsedPhotos.length - imported.length - skipped - failed),
        elapsedMs: performance.now() - startAt,
        error,
      };
    }
  }

  /** 初始化导入会话（含断点续传恢复） */
  private async beginImportSession(): Promise<ImportBeginResult> {
    if (this.config.enableResume) {
      // 先扫描遗留 WAL（续传去重，不创建会话）
      try {
        const recover = await verthysWalRecover();
        if (recover.ok && recover.hashes.length > 0) {
          log.info(
            `检测到遗留 WAL: committed=${recover.hashes.length}, ` +
              `import_id=${recover.import_id ?? "无"}, 将续传去重`,
          );
        }
      } catch (e) {
        log.warn("WAL 恢复扫描失败（忽略，继续新建会话）:", e);
      }
    }

    return await verthysImportBegin();
  }

  /** 消费者：批量写入 N 条已加密记录到后端 */
  private async consumeBatch(records: BatchRecordInput[]): Promise<AddRecordsBatchResult> {
    const batchStartAt = performance.now();

    // 通过 Tauri Channel 接收后端流式进度
    // 但我们在批次级别也更新进度，这里仅记录日志
    const onProgress = (prog: ImportBatchProgress) => {
      log.debug(
        `批次 ${prog.batch_id} 进度: ${prog.processed_in_batch}/${prog.total_in_batch}, ` +
          `committed=${prog.total_committed}, elapsed=${prog.elapsed_ms}ms`,
      );
    };

    const result = await verthysAddRecordsBatch(records, onProgress);

    if (!result.ok) {
      throw new Error(result.error ?? "批量写入失败");
    }

    return result;
  }
}

/**
 * 将导入结果转换为 PhotoEntry 列表（供 photos ref 使用）
 *
 * @param imported 导入结果列表
 * @param startIndex 起始索引（用于生成临时 ID，避免冲突）
 */
export function importedToPhotoEntries(
  imported: ImportedPhotoResult[],
  startIndex = 0,
): PhotoEntry[] {
  return imported.map((item, i) => ({
    id: Date.now() + startIndex + i,
    metaId: item.metaId,
    name: item.name.replace(/^meta_/, ""),
    thumb: `url(data:image/jpeg;base64,${item.thumbB64})`,
    size: formatSize(item.size),
    height: 180 + ((i * 23) % 100),
  }));
}
