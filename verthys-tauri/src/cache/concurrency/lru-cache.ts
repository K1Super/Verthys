/*
 * cache/concurrency/lru-cache.ts — 泛型 LRU 缓存（Map 插入顺序实现）
 *
 * ★ verthys-cache 并发重构（verthys-cache-refactor-concurrency-fix.md §3.2）：
 *   为 VerthysCacheDomain 提供带淘汰回调的 LRU 容器，替代散落在
 *   verthys-cache.ts 中的两处手写 delete+re-set 逻辑（recordScanCache 5000 /
 *   fullRecordCache 50），收敛为单一权威实现。
 *
 * 设计要点：
 *   1. O(1) 读写：Map 保持插入顺序，get 命中即 delete+set 移到末尾（最近使用）
 *   2. set 超容量即淘汰队首（最久未使用），并触发 onEvict 回调
 *   3. onEvict 双用途：
 *      - recordScanCache：淘汰时同步移除类型索引，杜绝索引悬挂 ID
 *      - fullRecordCache：淘汰时安全覆写 dataB64（缩短明文暴露窗口，方案 7.1 同源思想）
 *   4. clear() 同样逐条触发 onEvict（与手写版 clearFullRecordCache 的
 *      「清空前安全覆写」语义一致）
 *   5. peek(key)：只读不触碰 recency——供删除快照提供者使用，
 *      避免 deleteAndPersist 入队时取快照扰动正常访问的 LRU 顺序
 */
export class LRUCache<K, V> {
  private map = new Map<K, V>();

  constructor(
    /** 容量上限（必须 >= 1；超出即淘汰最久未使用条目） */
    private capacity: number,
    /** 淘汰回调（溢出淘汰与 clear 均触发；delete 不触发，由调用方自行善后） */
    private onEvict?: (key: K, value: V) => void,
  ) {
    if (capacity < 1) {
      throw new Error(`LRUCache capacity must be >= 1, got ${capacity}`);
    }
  }

  /** 读取并触碰 recency（命中则移到末尾，标记为最近使用） */
  get(key: K): V | undefined {
    if (!this.map.has(key)) return undefined;
    const val = this.map.get(key)!;
    this.map.delete(key);
    this.map.set(key, val); // 移到末尾（最近使用）
    return val;
  }

  /** 只读读取：不触碰 recency（快照提供者 / 探测场景使用） */
  peek(key: K): V | undefined {
    return this.map.get(key);
  }

  /** 写入（已存在则更新并移到末尾；超容量则淘汰最久未使用条目） */
  set(key: K, value: V): void {
    if (this.map.has(key)) {
      this.map.delete(key);
    } else if (this.map.size >= this.capacity) {
      const oldestKey = this.map.keys().next().value;
      // 容量 >= 1 时此处必然存在队首；防御式判空避免极端情况下崩溃
      if (oldestKey !== undefined) {
        const oldestVal = this.map.get(oldestKey)!;
        this.map.delete(oldestKey);
        this.onEvict?.(oldestKey, oldestVal);
      }
    }
    this.map.set(key, value);
  }

  has(key: K): boolean { return this.map.has(key); }

  /** 删除指定条目（不触发 onEvict；调用方需要善后时自行处理） */
  delete(key: K): boolean { return this.map.delete(key); }

  /** 清空全部条目，逐条触发 onEvict（保证资源善后语义与溢出淘汰一致） */
  clear(): void {
    if (this.onEvict) {
      for (const [k, v] of this.map) this.onEvict(k, v);
    }
    this.map.clear();
  }

  get size(): number { return this.map.size; }

  keys(): IterableIterator<K> { return this.map.keys(); }

  values(): IterableIterator<V> { return this.map.values(); }
}
