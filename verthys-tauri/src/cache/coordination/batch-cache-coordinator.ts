/*
 * cache/coordination/batch-cache-coordinator.ts — 插件化批量缓存协调器（导入流水线专用）
 *
 * ★ 重构设计落地：
 *   插件化写入器 + 背压控制 + 可靠重试 + 事件可观测 + AbortSignal 可取消 +
 *   依赖注入可测试的生产级批量缓存协调器。
 *
 * ★ 根治的十项缺陷（逐条对应）：
 *   1. 缓存层硬编码 → CacheLayerWriter 插件接口，新增/替换缓存层零侵入
 *   2. 缺乏背压控制 → 高/低水位线 + backpressure 事件，上游可暂停/恢复
 *   3. 错误处理粗放 → 失败批次回灌缓冲区前端（不丢数据）+ 逐层重试
 *   4. 无取消机制 → flush(signal)/end(signal) 支持 AbortSignal 中断
 *   5. 可观测性差 → flush:start/flush:success/flush:error/backpressure/
 *      session:start/end/abort 全事件通知
 *   6. Base64 大小估算不精确 → estimateBase64Size 处理填充字符
 *      （共享实现位于 cache/shared/base64-size.ts）
 *   7. createdTime 语义不准确 → BufferedRecord.createdTime? 可传入
 *      原始 EXIF 时间，未传时回退入队时间
 *   8. performance.now() 兼容性风险 → 统一使用 Date.now()
 *   9. 生命周期管理缺陷 → begin() 幂等（重复 begin 不重置统计）、
 *      end() 检查 active、abort() 紧急停止
 *   10. 缺乏依赖注入 → 构造函数注入配置与写入器，单元测试可 mock
 *
 * ★ 构建约束与设计对齐（与 verthys-cache-domain 重构同源决策）：
 *   - Node 'events' 的 EventEmitter 在本 Vite 浏览器 bundle 不可解析
 *     （无 events 包、无 polyfill），以零依赖 TypedEventEmitter 等价替代，
 *     事件名与监听器参数由事件表静态类型化
 *
 * ★ 生产级对齐说明（非语义变更）：
 *   - abort() 重置背压标志并广播 backpressure=false：原始设计未复位，
 *     残留 backpressure=true 会使上游永久暂停（活性缺陷）
 *   - 自动触发（阈值/定时）经 tryFlush()：刷新进行中时静默跳过
     （缓冲区保留，下个周期/下条记录再次触发），避免把并发跳过
 *     误报为 error 级日志噪音；手动 flush() 保持既有契约——并发调用抛错
 *   - 中止/重试耗尽的层按失败处理：批次统一走失败路径回灌缓冲区，
 *     flushed 统计仅在全部层成功时计入（与字段语义"本次刷新写入的
 *     记录数"一致），杜绝"未写入却计数"的遥测失真
 *
 * ★ 评审修复：
 *   1. 自动 begin() 不再重置 totalFlushed：begin(resetStats=true) 显式
 *      控制，addRecord 自动启用会话时传 false，导入中途时序异常不丢累计
 *   2. flushInProgress 重置移至整个 flush 流程最末（return 置于 try 内、
 *      finally 统一复位）：emit 期间监听器同步调用 flush() 不再看到
 *      false → 杜绝事件回调重入并发刷新；finally 复位同时保证异常路径
 *      不泄漏标志（比"函数末尾重置"更强）
 *   3. abort() 经内部 AbortController 中断在途 flush：写器循环检查点
 *      检测信号后提前终止；因 abort() 已按契约清空缓冲区并终止会话，
 *      在途批次直接丢弃而非回灌（回灌会让"应丢弃"数据复活）；外部
 *      signal 中止语义是"停止等待、保留数据"，仍走回灌（分源处理）
 *   4. 失败回灌后补做背压触发检查（缓冲区可能已越过高水位线）
 *   5. end() 仅在最终 flush 成功时结束会话；失败保持 active 原状
 *      （abort 中途终止时 active 已为 false，不被复活）并记录错误，
 *      由调用方决定重试 end() 或 abort() 放弃；flush 失败路径内部已
 *      广播 flush:error，end() 不重复发射（避免监听器双重计数）
 *
 * 写顺序保障（与旧版一致）：
 * - 内存缓冲器使用有序数组（按入队顺序），保证 verthys ID 递增顺序
 * - 批量刷新时按数组顺序依次写入三层缓存，保证索引一致性
 * - flush() 返回 Promise，调用方可 await 确保所有缓存已更新
 *
 * 使用场景（与旧版一致）：
 * 仅用于照片导入流水线消费者阶段。普通单条记录操作（setModuleKey 等）
 * 继续使用 cacheCoordinator.addRecord（即时性要求高，无需批量）。
 */
import { TypedEventEmitter } from "../concurrency/typed-event-emitter";
import { estimateBase64Size } from "../shared/base64-size";
import {
  addSummaryRecord,
  addRecordToScan,
  addFullRecord,
} from "../composition/verthys-cache";
import type { SummaryRecord } from "../../lib/verthys";
import { createLogger } from "../../utils/logger";

const log = createLogger("batch-cache-coordinator");

/* ==================== 类型定义 ==================== */

/**
 * 缓存层写入器接口（插件化扩展点）。
 * 新增/替换缓存层只需实现本接口并注入构造函数，无需修改协调器内部。
 */
export interface CacheLayerWriter {
  /** 层名称（可观测：failedLayers / 事件负载中使用） */
  readonly name: string;
  /** 将一批记录写入该缓存层（同步或异步；失败应抛异常以触发重试） */
  writeBatch(records: BufferedRecord[]): Promise<void> | void;
}

/** 批量缓存配置 */
export interface BatchCacheConfig {
  /** 批量刷新条数阈值（默认 100） */
  batchSize: number;
  /** 批量刷新时间阈值（默认 500ms） */
  flushIntervalMs: number;
  /** 背压高水位线：缓冲区达到该值触发 backpressure=true（上游应暂停入队） */
  highWaterMark: number;
  /** 背压低水位线：缓冲区回落到该值以下触发 backpressure=false（上游恢复） */
  lowWaterMark: number;
  /** 单层写入失败最大重试次数（不含首次尝试） */
  maxRetries: number;
  /** 重试延迟（毫秒，线性） */
  retryDelayMs: number;
}

/** 缓冲区单条记录（有序队列元素） */
export interface BufferedRecord {
  /** verthys 分配的记录 ID */
  id: number;
  /** 记录类型 */
  type: number;
  /** 记录名称 */
  name: string;
  /** 已加密数据 base64 */
  dataB64: string;
  /** 原始数据大小（字节） */
  dataSize: number;
  /** 创建时间（Unix 秒，可选；照片场景传 EXIF 原始时间，未传回退入队时间） */
  createdTime?: number;
  /** 入队时间戳（用于顺序保障 + 延迟监控） */
  enqueuedAt: number;
}

/** 批量刷新结果统计 */
export interface BatchFlushStats {
  /** 本次刷新实际写入的记录数（失败/中止时为 0；失败批次回灌缓冲区，abort 场景丢弃） */
  flushed: number;
  /** 全部缓存层写入是否成功（中止视为未成功） */
  ok: boolean;
  /** 失败的缓存层名称列表 */
  failedLayers: string[];
  /** 本次刷新耗时（毫秒） */
  elapsedMs: number;
  /** 本次刷新触发的重试总次数 */
  retries: number;
}

/** 领域事件表（TypedEventEmitter 静态约束） */
export type BatchCacheCoordinatorEventMap = {
  /** 批量会话开始 */
  "session:start": [];
  /** 批量会话正常结束（负载：累计刷新条数） */
  "session:end": [{ totalFlushed: number }];
  /** 批量会话紧急中止（缓冲区已丢弃） */
  "session:abort": [];
  /** 背压状态变化（true=达到高水位上游应暂停；false=回落低水位可恢复） */
  "backpressure": [boolean];
  /** 刷新开始（负载：本批条数） */
  "flush:start": [{ count: number }];
  /** 刷新成功（负载：条数/耗时/重试次数） */
  "flush:success": [{ count: number; elapsedMs: number; retries: number }];
  /** 刷新失败（负载：失败层/耗时/重试次数；批次已回灌缓冲区，abort 丢弃场景不发射） */
  "flush:error": [{ failedLayers: string[]; elapsedMs: number; retries: number }];
};

/* ==================== 默认配置 ==================== */

const DEFAULT_CONFIG: BatchCacheConfig = {
  batchSize: 100,
  flushIntervalMs: 500,
  highWaterMark: 1000,
  lowWaterMark: 200,
  maxRetries: 2,
  retryDelayMs: 200,
};

/* ==================== 默认缓存层写入器 ==================== */

/** L1 摘要缓存写入器（列表渲染数据源，常驻内存） */
class SummaryCacheWriter implements CacheLayerWriter {
  readonly name = "L1-Summary";

  writeBatch(records: BufferedRecord[]): void {
    for (const rec of records) {
      const summary: SummaryRecord = {
        id: rec.id,
        type: rec.type,
        name: rec.name,
        dataSize: rec.dataSize,
        physicalOffset: 0, // 占位，下次 ensureSummaryScan 覆盖
        merkleLeaf: "",
        createdTime: rec.createdTime ?? Math.floor(rec.enqueuedAt / 1000),
      };
      addSummaryRecord(summary);
    }
  }
}

/** L2 扫描缓存写入器（兼容路径，含 LRU + 大体积管控） */
class ScanCacheWriter implements CacheLayerWriter {
  readonly name = "L2-Scan";

  writeBatch(records: BufferedRecord[]): void {
    for (const rec of records) {
      addRecordToScan(rec.id, rec.type, rec.name, rec.dataB64);
    }
  }
}

/** L3 全量记录缓存写入器（按需 LRU-50，存储完整加密数据） */
class FullRecordCacheWriter implements CacheLayerWriter {
  readonly name = "L3-FullRecord";

  writeBatch(records: BufferedRecord[]): void {
    for (const rec of records) {
      addFullRecord(rec.id, rec.type, rec.name, rec.dataB64, rec.dataSize);
    }
  }
}

/**
 * 批量缓存协调器（插件化、背压、可靠）
 *
 * 落实「三步批量同步 + 写顺序保障」：
 * - 内存缓冲器暂存记录，达到阈值（100 条 / 500ms）批量刷新
 * - 批量更新 L1/L2/L3 三层缓存，减少锁竞争（O(N) → O(N/100)）
 * - 有序队列保证写入顺序
 *
 * 生命周期：
 *   begin() → addRecord() × N → flush()（手动/自动触发）→ end()
 *   紧急停止：abort()（丢弃缓冲区）
 */
export class BatchCacheCoordinator extends TypedEventEmitter<BatchCacheCoordinatorEventMap> {
  private readonly config: BatchCacheConfig;
  private readonly writers: CacheLayerWriter[];

  /** 内存缓冲器（有序数组，保证写入顺序） */
  private buffer: BufferedRecord[] = [];
  /** 定时刷新定时器句柄 */
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  /** 是否处于活跃会话（begin 后 end/abort 前） */
  private active = false;
  /** 累计已刷新记录数（检查点统计用；仅全部层成功时计入） */
  private totalFlushed = 0;
  /** 背压状态（高水位触发，低水位解除） */
  private backpressure = false;
  /** 刷新进行中标志（并发防护：手动 flush 抛错，自动触发静默跳过） */
  private flushInProgress = false;
  /**
   * 会话级中止控制器（评审 #3；begin 时新建）：abort() 触发其信号，
   * 在途 flush 的检查点据此提前终止写器循环。
   * ★ abort 后有意保留已中止的控制器（不置 null）：在途 flush 收尾时
   *   需读取该信号区分"内部中止→丢弃批次"与"外部中止→回灌批次"；
   *   下一次 begin() 会创建全新控制器。
   */
  private abortController: AbortController | null = null;

  /**
   * @param config 配置（部分覆盖默认值）
   * @param writers 缓存层写入器（依赖注入；缺省为 L1/L2/L3 默认三层）
   */
  constructor(config?: Partial<BatchCacheConfig>, writers?: CacheLayerWriter[]) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.writers = writers ?? [
      new SummaryCacheWriter(),
      new ScanCacheWriter(),
      new FullRecordCacheWriter(),
    ];
  }

  /* ==================== 生命周期 ==================== */

  /**
   * 开始批量会话（幂等：重复 begin 忽略并告警）。
   *
   * @param resetStats 是否重置累计统计（默认 true；评审 #1：addRecord
   *   自动启用会话时传 false，导入中途时序异常不丢历史累计）
   */
  begin(resetStats: boolean = true): void {
    if (this.active) {
      log.warn("批量缓存会话已活跃，忽略重复 begin");
      return;
    }
    this.active = true;
    this.buffer = [];
    if (resetStats) this.totalFlushed = 0;
    this.backpressure = false;
    // 新会话配发全新中止控制器（旧控制器可能已被上一会话 abort() 置为已中止）
    this.abortController = new AbortController();
    this.startFlushTimer();
    this.emit("session:start");
    log.debug(`批量缓存会话开始 (batchSize=${this.config.batchSize})`);
  }

  /**
   * 添加记录到缓冲区（未 begin 时自动 begin，并告警提示调用方补齐生命周期）。
   *
   * 达到 batchSize 阈值时自动触发异步刷新（非阻塞，不等待刷新完成）。
   * 达到高水位线时触发 backpressure=true（上游应暂停入队直至低水位解除）。
   * 写顺序保障：记录按调用顺序入队，刷新时按入队顺序写入三层缓存。
   *
   * @param rec 记录数据（id / type / name / dataB64 / dataSize? / createdTime?）
   */
  addRecord(rec: {
    id: number;
    type: number;
    name: string;
    dataB64: string;
    dataSize?: number;
    createdTime?: number;
  }): void {
    if (!this.active) {
      log.warn("批量缓存会话未开始，addRecord 自动启用会话（保留累计统计）");
      this.begin(false); // ★ 评审 #1：自动 begin 不重置 totalFlushed
    }

    this.buffer.push({
      id: rec.id,
      type: rec.type,
      name: rec.name,
      dataB64: rec.dataB64,
      dataSize: rec.dataSize ?? estimateBase64Size(rec.dataB64),
      createdTime: rec.createdTime,
      enqueuedAt: Date.now(),
    });

    // 背压检测（边沿触发：仅低→高沿广播一次）
    if (!this.backpressure && this.buffer.length >= this.config.highWaterMark) {
      this.backpressure = true;
      this.emit("backpressure", true);
      log.warn(`缓冲区达到高水位 ${this.config.highWaterMark}，触发背压`);
    }

    // 阈值触发刷新
    if (this.buffer.length >= this.config.batchSize) {
      this.tryFlush();
    }
  }

  /**
   * 手动刷新（支持取消：外部 AbortSignal + 内部 abortController）。
   *
   * 可靠性设计：
   *   - 逐层串行写入（保持写顺序），单层失败按 maxRetries 线性重试
   *   - 任一层最终失败或被中止 → 按中止来源分流：
   *     · 外部 signal 中止 / 重试耗尽 → 批次整体回灌缓冲区前端（不丢数据，
   *       已写入层为无条件覆盖写，回灌重试幂等）→ 广播 flush:error
   *     · 内部 abortController 中止（abort() 触发）→ 批次按指令丢弃
   *       （abort 已清空缓冲区并终止会话，回灌会让应弃数据复活）
   *   - 失败回灌后补做背压触发检查（评审 #4：缓冲区可能已越过高水位）
   *   - 全部成功 → 计入 totalFlushed → 广播 flush:success
   *   - flushInProgress 在整个流程（写器循环 + 事件广播 + 缓冲区回灌）
   *     结束后经 finally 统一复位（评审 #2：emit 期间监听器同步调用
   *     flush() 不会看到 false，杜绝回调重入并发刷新；异常路径亦复位）
   *
   * @param signal 外部取消信号（中断重试等待；中止的批次不丢数据、不计入统计）
   * @throws 并发调用时抛错（刷新进行中；自动触发走 tryFlush 静默跳过）
   */
  async flush(signal?: AbortSignal): Promise<BatchFlushStats> {
    if (this.flushInProgress) {
      throw new Error("刷新已在进行中，请勿并发调用");
    }
    if (this.buffer.length === 0) {
      return { flushed: 0, ok: true, failedLayers: [], elapsedMs: 0, retries: 0 };
    }

    this.flushInProgress = true;
    try {
      const batch = this.buffer.splice(0); // 取出当前批次（刷新期间可继续入队）
      const startAt = Date.now();
      const failedLayers: string[] = [];
      let retries = 0;
      let aborted = false;

      this.emit("flush:start", { count: batch.length });

      // 依次写入各层（串行保证写顺序）
      for (const writer of this.writers) {
        let attempt = 0;
        let success = false;
        while (attempt <= this.config.maxRetries && !success) {
          // 取消检查（含首次尝试前）：外部 signal 或内部 abortController 任一中止
          if (signal?.aborted || this.abortController?.signal.aborted) {
            aborted = true;
            break;
          }
          if (attempt > 0) {
            retries++;
            await delay(this.config.retryDelayMs);
            if (signal?.aborted || this.abortController?.signal.aborted) {
              aborted = true;
              break;
            }
          }
          try {
            await writer.writeBatch(batch);
            success = true;
          } catch (e) {
            attempt++;
            log.warn(`缓存层 ${writer.name} 写入失败（第 ${attempt} 次尝试）`, e);
          }
        }
        // 重试耗尽或中止 → 记为失败层
        if (!success) {
          failedLayers.push(writer.name);
        }
      }

      const elapsedMs = Date.now() - startAt;
      const ok = failedLayers.length === 0 && !aborted;
      // ★ 区分中止来源——内部中止（abort()）时缓冲区已被清空、
      //   会话已终止，在途批次必须丢弃（回灌会让"应丢弃"数据复活）
      const discardedByAbort = !ok && this.abortController?.signal.aborted === true;

      if (ok) {
        this.totalFlushed += batch.length;
        this.emit("flush:success", { count: batch.length, elapsedMs, retries });
      } else if (discardedByAbort) {
        log.warn(`abort 中止在途刷新，丢弃批次 ${batch.length} 条（会话已终止，不计入统计）`);
      } else {
        // 失败/外部中止：批次数据回灌缓冲区前端（保持入队顺序）
        this.buffer.unshift(...batch);
        // ★ 评审 #4：回灌后补做背压触发检查（缓冲区可能已越过高水位线）
        if (!this.backpressure && this.buffer.length >= this.config.highWaterMark) {
          this.backpressure = true;
          this.emit("backpressure", true);
          log.warn(`失败回灌后缓冲区达到高水位 ${this.config.highWaterMark}，触发背压`);
        }
        this.emit("flush:error", { failedLayers, elapsedMs, retries });
      }

      // 背压解除检测（回灌后缓冲区可能仍高于低水位 → 保持背压，继续节流上游）
      if (this.backpressure && this.buffer.length <= this.config.lowWaterMark) {
        this.backpressure = false;
        this.emit("backpressure", false);
      }

      return {
        flushed: ok ? batch.length : 0,
        ok,
        failedLayers,
        elapsedMs,
        retries,
      };
    } finally {
      // ★ 评审 #2：整个流程（写器循环 + 事件广播 + 缓冲区回灌）结束后才复位
      //   ——return 求值完成后 finally 才执行，emit 期间监听器重入调用将被
      //   正确拒绝/跳过；异常路径同样保证复位（标志不泄漏）。
      this.flushInProgress = false;
    }
  }

  /**
   * 结束会话（刷新剩余缓冲）。
   * 幂等防护：未活跃会话直接返回空统计（不产生日志噪音、不重复刷新）。
   *
   * ★ 评审 #5：仅在最终 flush 全部成功时才结束会话——失败时保持 active
   *   原状（缓冲区仍持有回灌数据；若 abort 中途终止则 active 已为 false，
   *   不被本方法复活），由调用方决定重试 end() 或 abort() 放弃。
   *   flush 失败路径内部已广播 flush:error，此处不重复发射。
   *
   * @param signal 取消信号（透传给最终 flush）
   */
  async end(signal?: AbortSignal): Promise<BatchFlushStats> {
    if (!this.active) {
      return { flushed: 0, ok: true, failedLayers: [], elapsedMs: 0, retries: 0 };
    }
    this.stopFlushTimer();
    const stats = await this.flush(signal);
    if (stats.ok) {
      this.active = false;
      this.emit("session:end", { totalFlushed: this.totalFlushed });
    } else {
      // 保持 active 原状（不复活已被 abort 终止的会话），记录错误供调用方决策
      log.error(
        `end() 最终刷新失败（failedLayers=${stats.failedLayers.join(",") || "已中止"}，` +
        `缓冲区保留 ${this.buffer.length} 条），会话保持活跃——可重试 end() 或 abort() 放弃`,
      );
    }
    return stats;
  }

  /**
   * 紧急停止（丢弃缓冲并终止）。
   *
   * ★ 评审 #3：触发内部中止信号——正在执行的 flush 在下一个检查点提前
   *   终止写器循环，其持有的在途批次按"会话已终止"丢弃（不回灌复活）。
   * ★ 背压复位：广播 backpressure=false，防止上游在会话终止后
   *   因残留背压状态永久暂停（活性保障）。
   */
  abort(): void {
    this.stopFlushTimer();
    this.abortController?.abort(); // ★ 中断正在进行的 flush（在途批次将被丢弃）
    this.buffer = [];
    this.active = false;
    if (this.backpressure) {
      this.backpressure = false;
      this.emit("backpressure", false);
    }
    this.emit("session:abort");
  }

  /* ==================== 内部方法 ==================== */

  /** 启动定时刷新定时器（begin 时调用） */
  private startFlushTimer(): void {
    this.stopFlushTimer();
    this.flushTimer = setInterval(() => {
      // 定时触发：仅在有缓冲数据时刷新
      if (this.buffer.length > 0) {
        this.tryFlush();
      }
    }, this.config.flushIntervalMs);
  }

  /** 停止定时刷新定时器 */
  private stopFlushTimer(): void {
    if (this.flushTimer !== null) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  /**
   * 自动触发刷新（阈值/定时路径专用）：刷新进行中时静默跳过。
   * 缓冲区数据保留，由下个周期或下条记录入队再次触发；
   * 避免把"并发跳过"误报为 error 级日志噪音（手动 flush 仍按契约抛错）。
   */
  private tryFlush(): void {
    if (this.flushInProgress) return;
    this.flush().catch((e) => log.error("自动批量刷新失败:", e));
  }

  /* ==================== 查询接口 ==================== */

  /** 获取当前缓冲区待刷新记录数 */
  get pendingCount(): number {
    return this.buffer.length;
  }

  /** 获取累计已刷新记录数（检查点统计） */
  get flushedCount(): number {
    return this.totalFlushed;
  }

  /** 是否处于活跃会话 */
  get isActive(): boolean {
    return this.active;
  }

  /** 是否处于背压状态（上游应暂停入队） */
  get isBackpressure(): boolean {
    return this.backpressure;
  }
}

/* ==================== 工具函数 ==================== */

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/* ==================== 导出单例 ==================== */

/** 导出便捷单例（导入流水线专用，每次导入 begin/end 控制生命周期） */
export const batchCacheCoordinator = new BatchCacheCoordinator();
