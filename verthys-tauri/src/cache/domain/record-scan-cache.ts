/*
 * cache/domain/record-scan-cache.ts — 记录扫描缓存（游标批量扫描）
 *
 * 职责：把全库记录（索引 + 小体积数据）合并进 LRU-5000 缓存，并提供
 * 按类型取 ID、单条快照、增量续扫、在途扫描取消与清除失效。
 *
 * 并发与一致性约束：
 *   1. 清除与扫描竞态：代际令牌使旧扫描自动失效，非阻塞清除立即生效
 *   2. 游标资源竞争：早停扫描与全量摘要扫描在摘要域互斥（本单元只负责记录域）
 *   3. 扫描状态清理：finally 无条件清空 scanInProgress，保证扫描结束后可重新触发
 *   4. 属主保护收尾：仍持有游标时必关（堵资源泄漏）；被后继扫描顶替时不关
 *      不清（防误杀后继游标，残留资源由后继 scan_open 自动顶替或 worker
 *      销毁兜底释放）
 *   5. 路径切换：批次合并前校验令牌 + 路径，不一致立即失效并终止扫描
 *
 * maxScannedId 仅由 setCacheEntry 维护；扫描结束不基于缓存键重算覆盖
 *   （LRU 淘汰会使重算值偏小 → 增量扫描从错误 ID 开始 → 大量重复扫描）。
 *   invalidate() 在删除当前最大 ID 时仍需定向重算（ID 复用语义不同，保留）。
 */
import type { ScannedRecord } from "../../types/key_manager";
import { AsyncMutex } from "../concurrency/async-mutex";
import { LRUCache } from "../concurrency/lru-cache";
import { markFrontendIpcActive } from "../../core/frontend-ipc-priority";
import { createLogger } from "../../utils/logging/logger";
import { DATAB64_CACHE_MAX_BYTES } from "../../constants/photo_budget.generated";
import type { ScanProgress, ScanToken, VerthysCacheApi } from "./cache-contracts";
import {
  RECORD_CACHE_LRU_THRESHOLD,
  SCAN_BATCH_SIZE,
  ScanTokenRegistry,
} from "./cache-contracts";
import { TypeIndex } from "./type-index";

const log = createLogger("verthys-cache-record-scan");

export class RecordScanCache {
  /** 记录扫描缓存（LRU-5000，淘汰时同步移除类型索引） */
  private readonly cache: LRUCache<number, ScannedRecord>;
  /** 按类型索引（O(1) 查询，取值时排序） */
  private readonly index = new TypeIndex();
  /**
   * 扫描期发现的损坏条目 ID（后端按 lid 记账的解密失败/索引不一致）。
   *
   * 这些条目数据不可读，不进入扫描缓存；此处留档供完整性巡检与诊断使用，
   * 使"损坏"与"不存在"在前端可区分。仅在清除时重置。
   */
  private readonly failedIds = new Set<number>();
  private readonly tokens = new ScanTokenRegistry();
  private scanInProgress: Promise<void> | null = null;
  private scanVerthysPath: string | null = null;
  private maxScannedId = 0;
  private readonly mutex = new AsyncMutex();

  constructor(
    private readonly api: VerthysCacheApi,
    private readonly getCurrentPath: () => string | null,
    private readonly pendingDeletionIds: Set<number>,
    private readonly onCleared: () => void,
    private readonly onIdsStale: (type?: number) => void,
  ) {
    this.cache = new LRUCache(RECORD_CACHE_LRU_THRESHOLD, (id, rec) => {
      // 淘汰回调同步移除类型索引，杜绝索引悬挂 ID
      this.index.remove(id, rec.type);
    });
  }

  /**
   * 确保记录扫描缓存覆盖最新记录。
   * 使用游标批量扫描（双缓冲流水线预取 + 共享内存零拷贝）。
   *
   * 并发安全：mutex 保证检查-登记原子性；多个模块同时调用时只执行一次扫描
   * （复用同一 Promise）。进行中的扫描经 scanInProgress 暴露给并发调用方。
   *
   * @param onProgress 批次粒度进度回调（可选）。仅在本次调用真正发起扫描时
   *   被注册；复用进行中扫描的场景拿不到回调（上层以阶段文案兜底，
   *   不伪造完成度）。
   *
   * 回退策略：scan_open 依赖 v2 B+ 树游标。.verthys 为 v1 格式时
   *   Verthys_ScanOpen 返回 VERTHYS_ERR_INVALID，回退流式枚举
   *   （逐批 Channel 推送，单批有界）。
   */
  async ensure(onProgress?: (progress: ScanProgress) => void): Promise<void> {
    // 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
    markFrontendIpcActive();
    const release = await this.mutex.acquire();
    let wrapped: Promise<void>;
    try {
      // 已有扫描在进行中 → 复用同一 Promise（避免并发重复扫描）
      if (this.scanInProgress) return this.scanInProgress;

      const scanPromise = this.run(onProgress);
      // finally 无条件清空，保证扫描结束后能重新触发
      wrapped = scanPromise.finally(() => {
        this.scanInProgress = null;
      });
      this.scanInProgress = wrapped;
    } finally {
      release();
    }
    return wrapped;
  }

  /**
   * 请求取消进行中的记录扫描（协作式：在批次边界生效）。
   *
   * 已合并入缓存的批次保留（增量扫描语义：下次扫描自 maxScannedId+1 继续，
   * 取消不会造成重复搬运）；游标关闭由 run 的 finally 按属主关系完成，
   * 此处只置取消标志，不动状态引用（避免误杀后继扫描）。
   * 无进行中扫描时为 no-op。
   */
  cancel(): void {
    // 活动令牌即本域当前扫描（无扫描时 no-op）；只置取消标志，不动状态引用
    this.tokens.invalidateActive();
  }

  /** 属主保护的扫描自检失效（路径变化 / 批次校验失败时调用） */
  private invalidateIfCurrent(token: ScanToken | null): void {
    this.tokens.invalidateIfCurrent(token);
  }

  /** 路径是否已变化（切换 verthys / lockAll 时触发） */
  private isPathChanged(expectedPath: string | null): boolean {
    return expectedPath !== this.getCurrentPath();
  }

  /** 实际执行记录扫描（令牌校验 + 路径校验 + 逐批合并） */
  private async run(onProgress?: (progress: ScanProgress) => void): Promise<void> {
    const token = this.tokens.create();
    this.scanVerthysPath = this.getCurrentPath();
    if (!this.scanVerthysPath) return;

    const startId = this.maxScannedId > 0 ? this.maxScannedId + 1 : 0;
    // 本次扫描读取条数（含损坏条目）：与缓存条数共同构成真实完成度
    let scanned = 0;
    let failed = 0;
    const report = (): void => {
      if (onProgress) {
        onProgress({ cached: this.cache.size, scanned, failed });
      }
    };

    try {
      // 优先使用游标批量扫描（v2 格式，双缓冲流水线预取 + 共享内存零拷贝）
      // 投影：本缓存只保留"索引 + 不超过管控阈值的数据"，故请求索引投影并
      //   以缓存管控阈值作为内联阈值——超过阈值的记录（MB 级分块等）由后端
      //   跳过解密与搬运，含大记录的库也能完整扫描（避免整批超容失败）。
      const first = await this.api.scanOpen(startId, SCAN_BATCH_SIZE, {
        project: "index",
        inlineMaxBytes: DATAB64_CACHE_MAX_BYTES,
      });
      this.recordFailedIds(first.failedIds, token);
      this.mergeBatch(first.records, token);
      scanned += first.records.length + first.failedIds.length;
      failed += first.failedIds.length;
      report();

      // 后续批次（双缓冲流水线：A 区消费时 B 区已预取就绪）
      let exhausted = first.exhausted;
      while (!exhausted) {
        if (!this.tokens.isValid(token) || this.isPathChanged(this.scanVerthysPath)) {
          this.invalidateIfCurrent(token);
          return;
        }
        const next = await this.api.scanNext(SCAN_BATCH_SIZE);
        this.recordFailedIds(next.failedIds, token);
        this.mergeBatch(next.records, token);
        scanned += next.records.length + next.failedIds.length;
        failed += next.failedIds.length;
        report();
        exhausted = next.exhausted;
      }
    } catch {
      // 回退：v1 格式不支持游标扫描（Verthys_ScanOpen 返回 VERTHYS_ERR_INVALID）
      await this.runFallback(token, startId, (batchCount) => {
        scanned += batchCount;
        report();
      });
    } finally {
      // 属主保护收尾：
      //   - 仍是活动令牌：游标所有权在本扫描（正常完成，或路径变化自检失效
      //     但无人顶替）→ 必须 scanClose 释放共享内存/C 游标/预取任务
      //     （无人顶替时不关即泄漏），并清理状态引用。
      //   - 已被后继扫描顶替或被清除：不可关闭（会误杀后继游标），也不可
      //     清状态引用；残留资源由后继 scan_open 自动顶替或 worker 销毁兜底。
      if (this.tokens.isOwner(token)) {
        await this.api.scanClose().catch(() => {});
        // maxScannedId 由 setCacheEntry 维护，
        //   此处不基于缓存键重算覆盖（LRU 淘汰会使重算值偏小）。
        this.scanVerthysPath = null;
        this.tokens.clearActive();
      } else {
        log.debug("记录扫描令牌已失效（游标由后继 scan_open 顶替或缓存清除），scanClose 移交后继/后端兜底");
      }
    }
  }

  /**
   * 回退路径：游标扫描失败时使用流式枚举（逐批 Channel 推送，单批有界）。
   *
   * 不先试一次性全量枚举：单次枚举把 startId 起的全部记录塞进一行 JSON，
   * 照片等 MB 级记录会让响应行越过 worker 单行上限并导致子进程被判死；
   * 流式枚举按批拉取，单批载荷可控，v1/v2 容器走同一 op，能力不缺失。
   *
   * @param onBatch 每批合并后回调本批条数（供上层推进真实进度）
   */
  private async runFallback(
    token: ScanToken,
    startId: number,
    onBatch?: (batchCount: number) => void,
  ): Promise<void> {
    if (!this.tokens.isValid(token) || this.isPathChanged(this.scanVerthysPath)) {
      this.invalidateIfCurrent(token);
      return;
    }
    const fallbackStart = startId > 0 ? startId : 1;
    await this.api.enumerateRecordsStream(fallbackStart, SCAN_BATCH_SIZE, (batch) => {
      // Channel 回调中再次检查（扫描期间若 verthys 已切换或锁定 → 丢弃结果）
      this.mergeBatch(batch.records, token);
      if (onBatch) onBatch(batch.records.length);
    });
  }

  /** 合并一批扫描记录（逐条校验令牌与路径 + 过滤待删 ID + 内存优先合并） */
  private mergeBatch(records: ScannedRecord[], token: ScanToken): void {
    for (const r of records) {
      if (!this.tokens.isValid(token) || this.isPathChanged(this.scanVerthysPath)) {
        // 属主保护失效（非属主 no-op，防误杀后继扫描）
        this.invalidateIfCurrent(token);
        return;
      }
      // 过滤待删除 ID（磁盘存在也不写入前端缓存，防止删除记录回填）
      if (this.pendingDeletionIds.has(r.id)) continue;
      // 内存优先合并（不覆盖已有缓存，仅补充缺失项）
      this.mergeEntry(r.id, r.type, r.name, r.dataB64);
    }
  }

  /**
   * 记账一批扫描期发现的损坏条目 ID（后端按 lid 透传的解密失败/索引不一致）。
   *
   * 与记录合并同源校验：令牌失效或路径已切换时丢弃，不污染新会话留档；
   * 这些条目数据不可读（未进入缓存），留档使前端可区分"损坏"与"不存在"。
   */
  private recordFailedIds(ids: readonly number[], token: ScanToken): void {
    if (ids.length === 0) return;
    if (!this.tokens.isValid(token) || this.isPathChanged(this.scanVerthysPath)) {
      this.invalidateIfCurrent(token);
      return;
    }
    for (const id of ids) this.failedIds.add(id);
    log.warn(`记录扫描发现 ${ids.length} 条损坏记录（数据不可读，未进入缓存；ID 已留档）`);
  }

  /** 读取扫描期发现的损坏条目 ID（升序；供完整性巡检与诊断使用） */
  getFailedIds(): number[] {
    return [...this.failedIds].sort((a, b) => a - b);
  }

  /**
   * 内存优先合并 — 磁盘扫描不覆盖已有缓存条目。
   *
   * 内存缓存是权威数据源，磁盘仅为持久化备份。仅补充缓存中缺失的记录；
   * 已有条目仅同步索引（防止类型变更后索引不一致），不覆盖数据。
   */
  private mergeEntry(id: number, type: number, name: string, dataB64: string): void {
    if (this.cache.has(id)) {
      const old = this.cache.peek(id);
      if (old && old.type !== type) {
        this.index.remove(id, old.type);
        this.index.add(id, type);
      }
      return;
    }
    this.setCacheEntry(id, type, name, dataB64);
  }

  /**
   * 将记录写入缓存（无条件覆盖；用户主动 add/edit 后同步用）。
   * 含大体积 dataB64 管控 + LRU 淘汰（淘汰回调同步移除类型索引）。
   */
  private setCacheEntry(id: number, type: number, name: string, dataB64: string): void {
    // 大体积 dataB64 不缓存（置空），调用方通过 IPC 获取
    const safeDataB64 = dataB64.length > DATAB64_CACHE_MAX_BYTES ? "" : dataB64;
    // 若已有同 ID 旧记录且类型不同，先从旧类型索引中移除
    const old = this.cache.peek(id);
    if (old && old.type !== type) {
      this.index.remove(id, old.type);
    }
    this.cache.set(id, { id, type, name, dataB64: safeDataB64 });
    this.index.add(id, type);
    // maxScannedId 唯一维护点：仅单调递增，
    //   不做基于缓存键的重算覆盖（invalidate 的定向重算除外）
    if (id > this.maxScannedId) this.maxScannedId = id;
  }

  /** 从扫描缓存中按类型获取记录 ID 列表（O(1) 索引查询，已排序） */
  idsByType(type: number): number[] {
    return this.index.idsByType(type);
  }

  /** 从扫描缓存中获取单条记录数据（无 IPC 调用；LRU 访问触碰） */
  get(id: number): ScannedRecord | null {
    // 待删除 ID 不返回（磁盘存在也不写入前端缓存）
    if (this.pendingDeletionIds.has(id)) return null;
    // LRU get：命中即移到末尾（标记为最近使用）
    return this.cache.get(id) ?? null;
  }

  /** 记录快照（name/type/dataB64；LRU peek 只读，不触碰 recency） */
  snapshot(id: number): { name: string; type: number; dataB64: string } | null {
    const rec = this.cache.peek(id);
    if (!rec) return null;
    return { name: rec.name, type: rec.type, dataB64: rec.dataB64 };
  }

  /**
   * 使扫描缓存中的单条记录失效（删除记录后调用）。
   * 删除后该 ID 不会出现在 idsByType 的结果中，杜绝"删除复活"。
   *
   * ID 复用保护：若被删除的记录 ID 等于当前 maxScannedId，
   * 必须重新遍历缓存计算新的 maxScannedId。否则 verthys 后端复用该 ID
   * 分配新记录时，ensure 的增量扫描会从旧 maxScannedId+1 开始，
   * 永远扫描不到复用 ID 的新记录 → 缓存永久缺失数据。
   */
  invalidate(id: number): void {
    /* 删除/编辑后类型索引已变化：保守失效全部类型 ID 缓存，下一次
     * 列表加载重新走后端类型盲索引，杜绝已删 ID 从缓存复活。 */
    this.onIdsStale();
    const rec = this.cache.peek(id);
    if (rec) {
      this.index.remove(id, rec.type);
      this.cache.delete(id);
      // ID 复用保护：删除的是当前最大 ID → 重新计算 maxScannedId
      // （定向重算，与扫描结束时全量重算覆盖不同）
      if (id === this.maxScannedId) {
        this.recomputeMaxScannedId();
      }
    }
  }

  /**
   * 重新计算 maxScannedId（仅删除最大 ID 记录时调用）。
   * 遍历缓存中所有 ID 取最大值。O(n)，频率极低。
   * 注意：LRU 淘汰可能已移除真实最大 ID，重算值偏小时只会导致下次
   * 扫描从更小的 ID 开始（幂等重复合并，内存优先，无副作用）。
   */
  private recomputeMaxScannedId(): void {
    let newMax = 0;
    for (const id of this.cache.keys()) {
      if (id > newMax) newMax = id;
    }
    this.maxScannedId = newMax;
  }

  /**
   * 将新增记录同步到扫描缓存（添加记录后调用）。
   * 避免新记录 ID <= maxScannedId 时 ensure 增量扫描遗漏。
   * 统一经 setCacheEntry 写入（LRU + 大体积管控）。
   */
  add(id: number, type: number, name: string, dataB64: string): void {
    this.onIdsStale(type);
    this.setCacheEntry(id, type, name, dataB64);
  }

  /**
   * 非阻塞清除扫描缓存。
   *
   * 立即使当前扫描失效（代际令牌），清空缓存与索引并允许新扫描立即启动，
   * 不等待旧扫描结束。旧扫描在每个批次合并前校验令牌与路径，
   * 失效后不再写入任何数据；旧游标资源由后继 scan_open 的自动顶替
   * （Rust verthys_scan_open 先关闭并 abort 旧游标，已验证）或 worker
   * 销毁兜底释放。
   */
  clear(): void {
    // 1. 立即使当前扫描失效
    this.tokens.invalidateActive();
    this.tokens.clearActive();
    this.scanInProgress = null; // 允许新扫描立即启动
    this.scanVerthysPath = null;
    // 损坏条目留档随缓存一并清除（重新扫描会重新记账）
    this.failedIds.clear();

    // 2. 清空缓存和索引（LRU clear 逐条触发淘汰回调同步移除索引，幂等）
    this.cache.clear();
    this.index.clear();
    this.maxScannedId = 0;

    this.onCleared();
  }
}
