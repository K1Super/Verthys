/**
 * chunk-filter.ts — 异步分片过滤工具
 *
 * 适用场景：大数组（>1000 条）的搜索/过滤计算
 *
 * 背景：
 *   `computed(() => arr.value.filter(predicate))` 是同步 O(n) 计算。
 *   当数组超过 1000 条时，单次过滤耗时 > 16ms（60fps 一帧预算），
 *   连续快速输入搜索关键词时主线程被阻塞，输入框卡顿。
 *
 * 方案：
 *   将过滤任务分片执行，每批处理 chunkSize 条后通过 setTimeout(0) 让出主线程，
 *   允许浏览器处理 UI 事件（输入、滚动、动画）。
 *   过滤完成后通过回调返回完整结果。
 *
 * 使用方式：
 *   - 小列表（<=1000 条）：保留同步 computed（零延迟，最佳体验）
 *   - 大列表（>1000 条）：用 chunkFilter 异步分片（输入流畅，结果稍延迟）
 */

/**
 * 异步分片过滤
 *
 * @param arr 待过滤的数组
 * @param predicate 谓词函数（返回 true 表示保留）
 * @param chunkSize 每批处理条数（默认 200，让出频率与性能平衡）
 * @param onBatch 每批完成后的回调（可用于进度展示）
 * @returns 过滤后的完整结果（Promise）
 *
 * @example
 * const result = await chunkFilter(accounts.value, a => a.name.includes(keyword), 200);
 * replaceShallowArray(filteredAccounts, result);
 */
export function chunkFilter<T>(
  arr: readonly T[],
  predicate: (item: T, index: number) => boolean,
  chunkSize: number = 200,
  onBatch?: (processed: number, total: number) => void,
): Promise<T[]> {
  return new Promise<T[]>((resolve) => {
    const result: T[] = [];
    const total = arr.length;
    let cursor = 0;

    const processChunk = (): void => {
      const end = Math.min(cursor + chunkSize, total);
      for (let i = cursor; i < end; i++) {
        if (predicate(arr[i], i)) {
          result.push(arr[i]);
        }
      }
      cursor = end;
      if (onBatch) {
        onBatch(cursor, total);
      }
      if (cursor < total) {
        // 让出主线程：setTimeout(0) 比 requestAnimationFrame 更适合长任务分片，
        // 因为 rAF 会在下一帧渲染前执行，可能延迟 UI 事件处理；
        // setTimeout(0) 让浏览器优先处理已排队的 UI 事件。
        setTimeout(processChunk, 0);
      } else {
        resolve(result);
      }
    };

    if (total === 0) {
      resolve(result);
    } else {
      processChunk();
    }
  });
}

/**
 * 异步分片遍历（不返回结果，仅用于副作用）
 *
 * 适用场景：大数组的批量解密、批量缓存预加载等
 *
 * @param arr 待遍历的数组
 * @param fn 每个元素的处理函数（支持 async）
 * @param chunkSize 每批处理条数
 * @param onBatch 每批完成后的回调
 */
export async function chunkForEach<T>(
  arr: readonly T[],
  fn: (item: T, index: number) => void | Promise<void>,
  chunkSize: number = 200,
  onBatch?: (processed: number, total: number) => void,
): Promise<void> {
  const total = arr.length;
  for (let start = 0; start < total; start += chunkSize) {
    const end = Math.min(start + chunkSize, total);
    for (let i = start; i < end; i++) {
      await fn(arr[i], i);
    }
    if (onBatch) {
      onBatch(end, total);
    }
    // 让出主线程
    if (end < total) {
      await new Promise<void>(resolve => setTimeout(resolve, 0));
    }
  }
}
