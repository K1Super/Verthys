/*
 * cache/domain/full-record-cache.ts — 全量记录缓存（第二层：LRU-50）与删除标记
 *
 * 按需加载完整记录：不受大体积管控限制，永远返回完整 dataB64；
 * LRU-50 容量；解密失败的记录不缓存；同 ID 并发请求复用同一 IPC Promise。
 *
 * 删除标记与本单元同源：pendingDeletionIds / committedDeletionIds 与
 * VerthysFlushService 共享同一实例（绑定层注入），保持"冲刷队列 ↔ 缓存
 * 读取"单一权威源，杜绝两套集合漂移导致删除复活。
 *
 * 锁粒度：仅在"写入缓存前"获取 deletionMutex 做检查-写入原子段，
 * 避免长时间持锁阻塞删除标记操作。
 */
import type { ScannedRecord } from "../../types/key_manager";
import { AsyncMutex } from "../concurrency/async-mutex";
import { LRUCache } from "../concurrency/lru-cache";
import { yieldIfFrontendBusy } from "../../core/frontend-ipc-priority";
import type { VerthysCacheApi } from "./cache-contracts";
import { FULL_RECORD_CACHE_CAPACITY } from "./cache-contracts";

export class FullRecordCache {
  /** 全量记录缓存（LRU-50，永不截断 dataB64） */
  private readonly cache: LRUCache<number, ScannedRecord>;
  /** 防并发重复 IPC：同 ID 多次请求复用同一 Promise */
  private readonly loaders = new Map<number, Promise<ScannedRecord | null>>();
  /** 保护待删集合相关的"检查-写入"原子段 */
  private readonly deletionMutex = new AsyncMutex();

  constructor(
    private readonly api: VerthysCacheApi,
    readonly pendingDeletionIds: Set<number>,
    readonly committedDeletionIds: Set<number>,
    private readonly shouldAbortBackgroundWork: () => boolean,
  ) {
    // 容量 50，淘汰时安全覆写 dataB64（缩短明文暴露窗口）
    this.cache = new LRUCache(FULL_RECORD_CACHE_CAPACITY, (_id, rec) => {
      rec.dataB64 = "";
    });
  }

  /**
   * 获取单条记录的完整数据（按需加载，含 LRU 缓存）。
   *
   * 与记录扫描缓存的区别：不受大体积管控限制，永远返回完整 dataB64。
   */
  async get(id: number): Promise<ScannedRecord | null> {
    // 快速路径：初步检查不持锁（最终一致性由写入时锁保证）
    if (this.pendingDeletionIds.has(id)) return null;

    // 1. 命中缓存：LRU 移到末尾（标记为最近使用）
    const cached = this.cache.get(id);
    if (cached) return cached;

    // 2. 防并发：同 ID 已有加载任务 → 复用同一 Promise
    const existing = this.loaders.get(id);
    if (existing) return existing;

    // 3. 未命中：发起 IPC 加载完整数据
    const loader = (async (): Promise<ScannedRecord | null> => {
      try {
        const r = await this.api.getRecord(id);
        if (!r) return null;
        // 写入前获取 deletionMutex 原子检查，避免将已删除记录写入缓存
        const release = await this.deletionMutex.acquire();
        try {
          if (this.pendingDeletionIds.has(id)) return null;
          const rec: ScannedRecord = { id, type: r.type, name: r.name, dataB64: r.dataB64 };
          this.cache.set(id, rec);
          return rec;
        } finally {
          release();
        }
      } catch {
        // 加载失败不缓存（避免缓存错误数据），也不向上抛（调用方按空结果处理）
        return null;
      } finally {
        this.loaders.delete(id);
      }
    })();

    this.loaders.set(id, loader);
    return loader;
  }

  /** 检查缓存中是否已存在指定 ID 的记录（不触发加载） */
  has(id: number): boolean {
    return this.cache.has(id);
  }

  /**
   * 预加载多条记录（被动补齐机制）。
   *
   * 低优先级：串行加载，每条之间让出主线程；会话结束立即停止；
   * 单条失败不影响后续。
   */
  async prefetch(ids: number[]): Promise<void> {
    for (const id of ids) {
      // 已缓存 / 待删除 → 跳过
      if (this.cache.has(id) || this.pendingDeletionIds.has(id)) continue;
      // 让出主线程，避免阻塞 UI（低优先级后台任务）
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      // 会话已结束（lockAll 触发 cacheTimersCancelled）→ 停止预加载
      if (this.shouldAbortBackgroundWork()) return;
      // 前端 IPC 优先级门控：前端活跃时让出 worker 通道（逐条让位，
      //   否则单条 MB 级记录会在串行 Actor 上排在前端请求之前，造成可感知卡顿）
      await yieldIfFrontendBusy();
      if (this.shouldAbortBackgroundWork()) return;
      try {
        await this.get(id);
      } catch {
        // 单条失败不影响后续
      }
    }
  }

  /** 使单条记录失效（编辑/删除后调用；安全覆写） */
  invalidate(id: number): void {
    const rec = this.cache.peek(id);
    if (rec) {
      rec.dataB64 = ""; // 安全覆写
      this.cache.delete(id);
    }
  }

  /** 直接写入完整记录（导入/新增后调用；含 LRU 淘汰） */
  set(rec: ScannedRecord): void {
    this.cache.set(rec.id, rec);
  }

  /** 清空全量缓存（clear 逐条安全覆写） */
  clear(): void {
    this.cache.clear();
    this.loaders.clear();
  }

  /** 当前条目数（调试/监控用） */
  size(): number {
    return this.cache.size;
  }

  /**
   * 标记记录进入待删除状态：加入共享过滤集合并立即移除可能已缓存的
   * 全量记录（防止在途加载在标记完成后写入已删记录）。
   * 注意：主删除路径由 VerthysFlushService.deleteAndPersist 直接入集合；
   * 本方法供独立使用领域 API 的调用方/测试使用。
   */
  async markForDeletion(id: number): Promise<void> {
    const release = await this.deletionMutex.acquire();
    try {
      this.pendingDeletionIds.add(id);
      // 立即移除可能已缓存的全量记录
      const cached = this.cache.peek(id);
      if (cached) {
        cached.dataB64 = "";
        this.cache.delete(id);
      }
    } finally {
      release();
    }
  }

  /** 解除待删除标记（回滚场景） */
  async unmarkForDeletion(id: number): Promise<void> {
    const release = await this.deletionMutex.acquire();
    try {
      this.pendingDeletionIds.delete(id);
      this.committedDeletionIds.delete(id);
    } finally {
      release();
    }
  }

  /** 清空待删除标记集合（新会话初始化；主路径经 VerthysFlushService 同步清空） */
  async clearPendingDeletionIds(): Promise<void> {
    const release = await this.deletionMutex.acquire();
    try {
      this.pendingDeletionIds.clear();
      this.committedDeletionIds.clear();
    } finally {
      release();
    }
  }
}
