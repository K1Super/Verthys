/*
 * cache/domain/type-id-cache.ts — 权威类型 ID 缓存（类型盲索引）
 *
 * 为什么不能读摘要 type：摘要不读记录密文，type 恒为未知 0；
 * 业务类型在写入时已进入 VTY_KS_TYPE 盲索引，本单元分页读取该索引，
 * 不依赖解密，跨重启稳定。
 *
 * 并发：同类型在途枚举复用同一 Promise；路径切换或 clear()
 * 会递增代际令牌，旧结果不得写回缓存。
 */
import type { VerthysCacheApi } from "./cache-contracts";
import { TYPE_ID_BATCH_SIZE } from "./cache-contracts";

export class TypeIdCache {
  /** 每个业务类型的完整 ID 列表（升序）；key 存在即代表该类型已成功枚举 */
  private readonly cache = new Map<number, number[]>();
  /** 同类型并发枚举复用同一 Promise，避免重复分页 IPC */
  private readonly inProgress = new Map<number, Promise<number[]>>();
  /** 类型 ID 缓存绑定的容器路径：路径变化即整体失效 */
  private boundPath: string | null = null;
  /** 全量代际令牌：清空/路径切换时递增，丢弃在途旧结果 */
  private generation = 0;
  /** 单类型代际令牌：只失效指定类型的在途枚举，不误伤其他类型 */
  private readonly generationByType = new Map<number, number>();

  constructor(
    private readonly api: VerthysCacheApi,
    private readonly getCurrentPath: () => string | null,
    private readonly pendingDeletionIds: Set<number>,
  ) {}

  /**
   * 枚举并缓存指定业务类型的完整记录 ID 列表。
   *
   * @throws 容器未解锁或枚举代际失效时抛出（调用方按失败处理，不得缓存旧结果）
   */
  async ensure(type: number): Promise<number[]> {
    const path = this.getCurrentPath();
    if (!path) throw new Error("容器未解锁，无法枚举类型 ID");

    if (this.boundPath !== path) {
      this.clearInternal();
      this.boundPath = path;
    }
    const cached = this.cache.get(type);
    if (cached !== undefined) return cached;
    const existing = this.inProgress.get(type);
    if (existing) return existing;

    const generation = this.generation;
    const typeGeneration = this.generationByType.get(type) ?? 0;
    const pending = this.fetch(type, path, generation, typeGeneration);
    this.inProgress.set(type, pending);
    try {
      return await pending;
    } finally {
      if (this.inProgress.get(type) === pending) {
        this.inProgress.delete(type);
      }
    }
  }

  /** 实际分页枚举（调用方保证同类型单飞） */
  private async fetch(
    type: number,
    path: string,
    generation: number,
    typeGeneration: number,
  ): Promise<number[]> {
    const ids: number[] = [];
    let afterId = 0;
    let exhausted = false;

    while (!exhausted) {
      const page = await this.api.listIdsByType(type, afterId, TYPE_ID_BATCH_SIZE);
      if (
        generation !== this.generation ||
        typeGeneration !== (this.generationByType.get(type) ?? 0) ||
        path !== this.getCurrentPath()
      ) {
        throw new Error("类型 ID 枚举代际失效（容器已切换或缓存已清空）");
      }

      let last = afterId;
      for (const id of page.ids) {
        if (!Number.isSafeInteger(id) || id <= last) {
          throw new Error("类型 ID 枚举返回非单调 ID");
        }
        last = id;
        if (!this.pendingDeletionIds.has(id)) ids.push(id);
      }
      exhausted = page.exhausted;
      if (!exhausted && page.ids.length === 0) {
        throw new Error("类型 ID 枚举返回空页但未标记结束");
      }
      afterId = last;
    }

    this.cache.set(type, ids);
    return ids;
  }

  /** 清空类型 ID 缓存；传 type 只失效该类型。 */
  clear(type?: number): void {
    if (type !== undefined) {
      this.cache.delete(type);
      this.inProgress.delete(type);
      this.generationByType.set(type, (this.generationByType.get(type) ?? 0) + 1);
      return;
    }
    this.clearInternal();
  }

  private clearInternal(): void {
    this.cache.clear();
    this.inProgress.clear();
    this.generationByType.clear();
    this.boundPath = null;
    this.generation += 1;
  }
}
