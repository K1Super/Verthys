/*
 * cache/domain/type-index.ts — 类型 ID 索引
 *
 * 记录扫描缓存与摘要缓存共用：以 Map<type, Set<id>> 提供 O(1) 的
 * 按类型取值能力，消除全量遍历 + 排序开销。取值时排序保证调用方
 * 得到升序 ID 列表，无需各自再排序。
 */
export class TypeIndex {
  private byType = new Map<number, Set<number>>();

  /** 将记录 ID 添加到类型索引 */
  add(id: number, type: number): void {
    let set = this.byType.get(type);
    if (!set) {
      set = new Set();
      this.byType.set(type, set);
    }
    set.add(id);
  }

  /** 将记录 ID 从类型索引中移除 */
  remove(id: number, type: number): void {
    this.byType.get(type)?.delete(id);
  }

  /** 按类型取出升序 ID 列表（无该类型时返回空数组） */
  idsByType(type: number): number[] {
    const set = this.byType.get(type);
    if (!set) return [];
    return [...set].sort((a, b) => a - b);
  }

  /** 清空全部索引 */
  clear(): void {
    this.byType.clear();
  }
}
