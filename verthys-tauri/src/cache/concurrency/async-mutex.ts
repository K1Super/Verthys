/*
 * cache/concurrency/async-mutex.ts — 异步互斥锁（FIFO 公平锁）
 *
 * 并发重构：
 *   为 VerthysCacheDomain 提供临界区保护原语，避免并发扫描 / 删除标记操作
 *   互相踩踏（缓存层竞态根治的底层构件）。
 *
 * 设计要点：
 *   1. FIFO 公平：acquire() 按调用顺序排队，先到先得，杜绝饥饿
 *   2. Promise 链实现：无自旋、无轮询，等待即挂起，零 CPU 开销
 *   3. release 即返回释放函数：调用方在 finally 中释放，保证异常路径不漏锁
 *
 * 使用示例：
 *   const release = await mutex.acquire();
 *   try {
 *     // ... 临界区 ...
 *   } finally {
 *     release();
 *   }
 *
 * 嵌套警告：同一线性执行流内不可重复 acquire 同一把锁（会自我死锁）。
 *   VerthysCacheDomain 中各锁分工明确（scanMutex / summaryScanMutex /
 *   deletionMutex 互不嵌套），getFullRecord 仅在写入缓存前的原子检查段
 *   持 deletionMutex，不与 markForDeletion 的持锁段嵌套。
 */
export class AsyncMutex {
  /** 锁尾：所有后继等待者都挂在这个 Promise 链上 */
  private tail: Promise<void> = Promise.resolve();

  /**
   * 获取锁，返回释放函数。
   *
   * 实现：每次 acquire 把自己的「turn Promise」挂到 tail 链上；
   * await 前一个 tail，等前一个持有者 release（resolve 其 turn）后自己才返回。
   */
  async acquire(): Promise<() => void> {
    let release!: () => void;
    const next = new Promise<void>(res => (release = res));
    const prev = this.tail;
    this.tail = this.tail.then(() => next);
    await prev;
    return () => release();
  }
}
