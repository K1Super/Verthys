/*
 * cache/domain/summary-cache.ts — 摘要缓存（第一层：常驻，无淘汰）
 *
 * 仅扫描元数据（lid/type/name/data_size/physical_offset/merkle_leaf/
 * created_time），不解密数据块，列表渲染 + 搜索 + 删除完全基于它。
 *
 * 并发与一致性约束：
 *   1. 摘要游标互斥：全量摘要扫描与早停扫描共用 mutex，保证同一时刻
 *      最多打开一个摘要游标（worker 每类游标仅支持单个 ScanState）
 *   2. 早停先等待进行中的全量扫描完成并复查缓存，再持锁打开游标
 *   3. 代际令牌 + 路径校验：清除 / 路径切换立即使在途扫描失效
 *   4. 属主保护收尾：仍持有游标时必关；被后继扫描顶替时不关不清
 */
import type { SummaryRecord } from "../../lib/verthys";
import { AsyncMutex } from "../concurrency/async-mutex";
import { markFrontendIpcActive } from "../../core/frontend-ipc-priority";
import { createLogger } from "../../utils/logging/logger";
import type { ScanToken, VerthysCacheApi } from "./cache-contracts";
import {
  EARLY_STOP_MAX_BATCHES,
  SCAN_BATCH_SIZE,
  ScanTokenRegistry,
} from "./cache-contracts";
import { TypeIndex } from "./type-index";

const log = createLogger("verthys-cache-summary");

export class SummaryCache {
  /** 摘要缓存（第一层：常驻内存，永久存在，无 LRU 淘汰） */
  private readonly cache = new Map<number, SummaryRecord>();
  /** 按类型索引（O(1) 查询，取值时排序） */
  private readonly index = new TypeIndex();
  private readonly tokens = new ScanTokenRegistry();
  private scanInProgress: Promise<void> | null = null;
  private scanVerthysPath: string | null = null;
  private maxSummaryId = 0;
  private readonly mutex = new AsyncMutex();

  constructor(
    private readonly api: VerthysCacheApi,
    private readonly getCurrentPath: () => string | null,
    private readonly pendingDeletionIds: Set<number>,
    private readonly onCleared: () => void,
    private readonly onIdsStale: (type?: number) => void,
  ) {}

  /* ==================== 写入与索引 ==================== */

  /** 将摘要记录写入缓存（无条件覆盖，用于 add/edit 后同步） */
  private setEntry(rec: SummaryRecord): void {
    // 若已有同 ID 旧记录且类型不同，先从旧类型索引中移除
    const old = this.cache.get(rec.id);
    if (old && old.type !== rec.type) {
      this.index.remove(rec.id, old.type);
    }
    this.cache.set(rec.id, rec);
    this.index.add(rec.id, rec.type);
    // maxSummaryId 唯一维护点（与 maxScannedId 同源策略，单调递增）
    if (rec.id > this.maxSummaryId) this.maxSummaryId = rec.id;
  }

  /**
   * 内存优先合并 — 磁盘摘要扫描不覆盖已有缓存条目（增量加载用）。
   * 已有条目仅同步索引，不覆盖数据。
   */
  private mergeEntry(rec: SummaryRecord): void {
    if (this.cache.has(rec.id)) {
      const old = this.cache.get(rec.id);
      if (old && old.type !== rec.type) {
        this.index.remove(rec.id, old.type);
        this.index.add(rec.id, rec.type);
      }
      return;
    }
    this.setEntry(rec);
  }

  /* ==================== 全量摘要扫描 ==================== */

  /**
   * 确保摘要缓存覆盖全部记录（解锁后 1-2 秒内完成）。
   *
   * 并发安全：mutex 保证检查-登记原子性；多模块复用同一 Promise。
   * 竞态保护：代际令牌 + 路径校验，clear() 立即使进行中扫描失效。
   *
   * 回退策略：摘要扫描失败（v1 格式 / 熔断）时静默返回——缓存保持空，
   * 调用方取类型 ID 得到空数组时自行回退流式枚举（v1 内存路径）。
   * 不回退全量扫描：避免 v1 容器关键路径全量解密（20-30s 延迟）。
   */
  async ensure(): Promise<void> {
    // 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
    markFrontendIpcActive();
    const release = await this.mutex.acquire();
    let wrapped: Promise<void>;
    try {
      // 已有扫描在进行中 → 复用同一 Promise（避免并发重复扫描）
      if (this.scanInProgress) return this.scanInProgress;

      const scanPromise = this.run();
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

  /** 请求取消进行中的摘要扫描（批次边界生效；语义同记录扫描） */
  cancel(): void {
    this.tokens.invalidateActive();
  }

  /** 实际执行摘要扫描（令牌校验 + 路径校验 + 逐批合并） */
  private async run(): Promise<void> {
    const token = this.tokens.create();
    this.scanVerthysPath = this.getCurrentPath();
    if (!this.scanVerthysPath) return;

    const startId = this.maxSummaryId > 0 ? this.maxSummaryId + 1 : 0;

    try {
      // 摘要游标批量扫描（v2 格式，双缓冲流水线 + 共享内存零拷贝）
      const first = await this.api.scanSummaryOpen(startId, SCAN_BATCH_SIZE);
      this.mergeBatch(first.records, token);

      let exhausted = first.exhausted;
      while (!exhausted) {
        if (!this.tokens.isValid(token) || this.isPathChanged(this.scanVerthysPath)) {
          this.tokens.invalidateIfCurrent(token);
          return;
        }
        const next = await this.api.scanSummaryNext(SCAN_BATCH_SIZE);
        this.mergeBatch(next.records, token);
        exhausted = next.exhausted;
      }
    } catch {
      // 摘要扫描失败（v1 格式 / 熔断）→ 静默返回，不触发任何全量扫描
      // （回退策略同 ensure 头注释）
    } finally {
      // 属主保护收尾（语义同记录扫描）：仍是活动令牌 → 关闭摘要游标并
      // 清理状态引用；已被后继 scan_summary_open 顶替或被 clear() 清理
      // → 不关不清（防误杀后继游标，资源由后继自动顶替或 worker 兜底）。
      if (this.tokens.isOwner(token)) {
        await this.api.scanSummaryClose().catch(() => {});
        // maxSummaryId 不重算（同 maxScannedId 策略）
        this.scanVerthysPath = null;
        this.tokens.clearActive();
      } else {
        log.debug("摘要扫描令牌已失效（游标由后继 scan_summary_open 顶替或缓存清除），scanSummaryClose 移交后继/后端兜底");
      }
    }
  }

  /** 合并一批摘要记录（校验令牌与路径 + 过滤待删 ID + 内存优先合并） */
  private mergeBatch(records: SummaryRecord[], token: ScanToken): void {
    for (const r of records) {
      if (!this.tokens.isValid(token) || this.isPathChanged(this.scanVerthysPath)) {
        // 属主保护失效（非属主 no-op，防误杀后继扫描）
        this.tokens.invalidateIfCurrent(token);
        return;
      }
      // 过滤待删除 ID（磁盘存在也不写入前端缓存，防止删除记录回填）
      if (this.pendingDeletionIds.has(r.id)) continue;
      this.mergeEntry(r);
    }
  }

  private isPathChanged(expectedPath: string | null): boolean {
    return expectedPath !== this.getCurrentPath();
  }

  /* ==================== 读取 ==================== */

  /**
   * 从摘要缓存中按类型获取记录 ID 列表（O(1) 索引查询，已排序）。
   *
   * 仅保留给历史迁移/诊断路径。摘要 type 恒为 0，业务列表必须使用
   * 权威类型 ID；不得把本方法作为新代码的类型 ID 来源。
   */
  idsByType(type: number): number[] {
    return this.index.idsByType(type);
  }

  /** 从摘要缓存获取单条记录（无 IPC 调用；仅返回元数据，用于列表项渲染） */
  get(id: number): SummaryRecord | null {
    // 待删除 ID 不返回（磁盘存在也不返回，杜绝删除复活）
    if (this.pendingDeletionIds.has(id)) return null;
    return this.cache.get(id) ?? null;
  }

  /** 获取摘要缓存中所有记录 ID（用于完整性巡检、全量遍历，已排序） */
  allIds(): number[] {
    return [...this.cache.keys()].sort((a, b) => a - b);
  }

  /** 获取摘要缓存当前条目数（调试/监控用） */
  size(): number {
    return this.cache.size;
  }

  /* ==================== 早停扫描 ==================== */

  /**
   * 按类型查找首条记录 LID（早停扫描，关键路径专用）。
   *
   * 与 ensure 的区别：找到首条匹配即返回（典型 <0.3s），全量摘要扫描需 2-3s。
   * 使用场景：仅需找到全局密钥记录的 LID，无需等待列表渲染就绪。
   *
   * 游标互斥：底层 worker 每类游标仅支持单个 ScanState，本方法与 ensure
   * 经同一 mutex 互斥，且在打开游标前先等待进行中的全量摘要扫描完成
   * 并复查缓存，杜绝同时打开多个摘要游标。
   *
   * 流程：
   *   1. 先查常驻缓存 → O(1)
   *   2. 有全量摘要扫描进行中 → 等待完成后复查缓存
   *   3. 仍未命中 → 持 mutex 打开摘要游标逐批扫描（早停）
   *   4. 全部批次无匹配 → 返回 null（调用方回退流式枚举）
   */
  async findLidByTypeEarlyStop(type: number): Promise<number | null> {
    const fromCache = (): number | null => {
      const ids = this.idsByType(type);
      return ids.length > 0 ? ids[0] : null;
    };

    // 1. 先查常驻缓存（O(1)，若已被 ensure 填充则直接命中）
    const cached = fromCache();
    if (cached !== null) return cached;

    for (;;) {
      // 2. 已有全量摘要扫描进行中 → 等待完成后复查缓存（不持锁等待，避免阻塞）
      if (this.scanInProgress) {
        await this.scanInProgress.catch(() => {});
        const hit = fromCache();
        if (hit !== null) return hit;
        continue; // 重新评估（扫描可能已被 clear，进入互斥分支）
      }

      // 3. 持互斥锁执行早停游标扫描（与 ensure 的登记段互斥，
      //    保证同一时刻最多一个摘要游标打开）
      const release = await this.mutex.acquire();
      try {
        // double-check：等待互斥锁期间状态可能已变化
        if (this.scanInProgress) continue; // finally 释放锁，回循环等待
        const hit = fromCache();
        if (hit !== null) return hit;
        return await this.earlyStopCursor(type);
      } finally {
        release();
      }
    }
  }

  /** 早停游标扫描主体（调用方须已持 mutex） */
  private async earlyStopCursor(type: number): Promise<number | null> {
    const pathAtStart = this.getCurrentPath();
    if (!pathAtStart) return null;

    try {
      const first = await this.api.scanSummaryOpen(0, SCAN_BATCH_SIZE);
      for (const r of first.records) {
        if (this.pendingDeletionIds.has(r.id)) continue;
        if (r.type === type) return r.id;
      }
      let exhausted = first.exhausted;
      let batchCount = 1;
      while (!exhausted) {
        // 迭代上限保护：超过上限仍未找到，终止扫描
        // （防后端异常返回 exhausted=false 但 records 为空导致无限循环）
        if (batchCount >= EARLY_STOP_MAX_BATCHES) {
          log.warn(`早停扫描达到迭代上限 ${EARLY_STOP_MAX_BATCHES} 批（${EARLY_STOP_MAX_BATCHES * SCAN_BATCH_SIZE} 条），终止扫描`);
          return null;
        }
        // 扫描期间若 verthys 已切换或锁定 → 丢弃结果
        if (pathAtStart !== this.getCurrentPath()) return null;
        const next = await this.api.scanSummaryNext(SCAN_BATCH_SIZE);
        batchCount++;
        for (const r of next.records) {
          if (this.pendingDeletionIds.has(r.id)) continue;
          if (r.type === type) return r.id;
        }
        exhausted = next.exhausted;
      }
    } catch {
      // 摘要扫描失败（v1 格式 / 熔断）→ 返回 null，调用方回退到流式枚举
      return null;
    } finally {
      // 确保游标关闭（早停命中 / 上限终止 / 路径切换 / 异常 / 正常结束全路径覆盖）
      await this.api.scanSummaryClose().catch(() => {});
    }
    return null;
  }

  /* ==================== 写入与失效（对外） ==================== */

  /**
   * 将新增/编辑记录的摘要同步到缓存（add/edit 后立即调用）。
   * 确保 ensure 增量扫描不遗漏新记录。
   */
  add(rec: SummaryRecord): void {
    this.onIdsStale(rec.type);
    this.setEntry(rec);
  }

  /**
   * 使摘要缓存中的单条记录失效（删除记录后调用）。
   * 删除后该 ID 不会出现在 idsByType 的结果中，杜绝"删除复活"。
   *
   * ID 复用保护：删除最大 ID 时重算 maxSummaryId。
   */
  invalidate(id: number): void {
    /* 摘要失效通常来自删除/编辑，类型索引可能变化：失效全部类型 ID。 */
    this.onIdsStale();
    const rec = this.cache.get(id);
    if (rec) {
      this.index.remove(id, rec.type);
      this.cache.delete(id);
      if (id === this.maxSummaryId) {
        this.recomputeMaxSummaryId();
      }
    }
  }

  /** 重新计算 maxSummaryId（仅删除最大 ID 记录时调用） */
  private recomputeMaxSummaryId(): void {
    let newMax = 0;
    for (const id of this.cache.keys()) {
      if (id > newMax) newMax = id;
    }
    this.maxSummaryId = newMax;
  }

  /** 清空整个摘要缓存（lockAll / flush 后调用；立即失效进行中扫描） */
  clear(): void {
    this.tokens.invalidateActive();
    this.tokens.clearActive();
    this.scanInProgress = null;
    this.scanVerthysPath = null;
    this.cache.clear();
    this.index.clear();
    this.maxSummaryId = 0;
    this.onCleared();
  }
}
