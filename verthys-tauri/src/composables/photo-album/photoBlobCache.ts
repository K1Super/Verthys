/**
 * photo-album/photoBlobCache.ts — 查看器预览/原图 Blob URL 有界缓存
 *
 * 只缓存解密后的展示字节（Blob URL），不持久化、不写入 localStorage/
 * IndexedDB。容量按字节与条目数双重限制，淘汰顺序为最近最少使用。
 *
 * 所有权：进入缓存的 URL 由缓存负责 revoke；调用方不得在缓存外再次
 * revoke（重复 revoke 是 no-op，但会让缓存命中返回失效地址）。
 */

export interface ViewerBlobEntry {
  url: string;
  bytes: number;
}

export class PhotoBlobCache {
  private entries = new Map<string, ViewerBlobEntry>();
  private totalBytes = 0;

  constructor(
    private readonly maxBytes: number = 64 * 1024 * 1024,
    private readonly maxEntries: number = 5,
  ) {}

  /** 命中并刷新最近使用顺序；未命中返回 undefined */
  get(key: string): string | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.url;
  }

  /** 写入并触发淘汰；同键旧 URL 会被释放 */
  put(key: string, url: string, bytes: number): void {
    this.delete(key);
    if (!url) return;
    const size = Number.isFinite(bytes) && bytes > 0 ? bytes : 0;
    this.entries.set(key, { url, bytes: size });
    this.totalBytes += size;
    this.evict(key);
  }

  /** 删除单个键（照片删除/替换时调用） */
  delete(key: string): void {
    const entry = this.entries.get(key);
    if (!entry) return;
    this.entries.delete(key);
    this.totalBytes = Math.max(0, this.totalBytes - entry.bytes);
    URL.revokeObjectURL(entry.url);
  }

  /** 清空（锁定/登出/模块卸载时调用） */
  clear(): void {
    for (const entry of this.entries.values()) {
      URL.revokeObjectURL(entry.url);
    }
    this.entries.clear();
    this.totalBytes = 0;
  }

  get size(): number {
    return this.entries.size;
  }

  get bytes(): number {
    return this.totalBytes;
  }

  /**
   * 淘汰旧条目，但保护本次刚写入的键。
   *
   * 单张原图可能大于 maxBytes（大图 >64MiB）：若无保护，刚写入的条目会
   * 立即被自己淘汰，调用方随后使用已被 revoke 的 URL 破图且不再重试。
   * 容量因此对单个超大条目是软上限；下一张小图写入时会优先淘汰它。
   */
  private evict(protectedKey?: string): void {
    while (
      this.entries.size > this.maxEntries ||
      this.totalBytes > this.maxBytes
    ) {
      let victim: string | undefined;
      for (const key of this.entries.keys()) {
        if (key !== protectedKey) {
          victim = key;
          break;
        }
      }
      if (victim === undefined) break;
      this.delete(victim);
    }
  }
}

/** 预览与原图使用独立键空间，避免互相淘汰或误命中 */
export function previewCacheKey(metaId: number): string {
  return `preview:${metaId}`;
}

export function fullCacheKey(metaId: number): string {
  return `full:${metaId}`;
}

/** 全局单例：模块会话期内有效，锁定/卸载/删除时显式清理 */
export const photoViewerCache = new PhotoBlobCache();
