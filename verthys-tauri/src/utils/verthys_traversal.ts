/*
 * utils/verthys_traversal.ts — Verthys 记录遍历通用工具
 *
 * 消除 keyManager.ts 中 4 处重复的 for 循环：
 *   - findGlobalKeyRecord
 *   - findModuleKeyRecord
 *   - loadModuleKeyStatus
 *   - findModuleKeyConfigRecord
 *
 * 统一为 scanVerthysRecords + findVerthysRecord 两个通用函数
 *
 * 双路径策略（兼顾性能与稳健性）：
 *   1. 快速路径：ensureRecordScan() 一次性批量加载全部记录到缓存（1 次 IPC），
 *      后续从缓存读取（零 IPC）。适用于正常场景。
 *   2. 回退路径：ensureRecordScan() 失败时，回退到逐条 verthysGetRecord(id)。
 *      兼容所有场景（worker 未就绪、游标不支持、v1 格式等），最稳健。
 *
 * 关键设计：回退路径的 verthysGetRecord(id) 调用必须捕获异常，
 *   避免单条 IPC 失败导致整个遍历崩溃（worker 在生产环境可能因路径解析、
 *   时序、状态不一致等原因返回异常，必须按 null 处理而非抛出）。
 */
import { verthysGetRecord } from "../lib/verthys";
import { ensureRecordScan, getRecordFromScan } from "../cache/composition/verthys-cache";

/** verthys 记录条目（遍历回调参数） */
export interface VerthysRecordEntry {
  id: number;
  type: number;
  name: string;
  dataB64: string;
}

/**
 * 遍历 verthys 中所有记录，对每条记录调用 handler
 *
 * 双路径策略：
 *   1. 快速路径：ensureRecordScan() 批量加载 → getRecordFromScan(id) 缓存读取
 *   2. 回退路径：ensureRecordScan() 失败 → verthysGetRecord(id) 逐条 IPC 读取
 *
 * 两条路径均使用连续 null 终止策略（默认 5 次连续 null 视为遍历结束）。
 * 回退路径确保在缓存扫描不可用时（worker 未就绪、游标不支持、v1 格式等），
 * 仍能正常遍历记录，不会导致应用崩溃。
 *
 * 回退路径的容错：verthysGetRecord(id) 抛出异常时按 null 处理，
 *   仅记录首次错误日志（避免 100000 次循环刷爆日志），
 *   确保生产环境单条 IPC 失败不会传播到上层导致初始化崩溃。
 *
 * @param handler 回调函数，返回 true 则提前终止遍历
 * @param options.maxId 最大遍历 ID（默认 100000）
 * @param options.nullStreakLimit 连续 null 终止阈值（默认 5）
 */
export async function scanVerthysRecords(
  handler: (entry: VerthysRecordEntry) => boolean | void,
  options?: { maxId?: number; nullStreakLimit?: number },
): Promise<void> {
  const maxId = options?.maxId ?? 100000;
  const nullStreakLimit = options?.nullStreakLimit ?? 5;
  let nullStreak = 0;

  // 快速路径：尝试批量加载到缓存（1 次 IPC 调用）
  let cacheReady = false;
  try {
    await ensureRecordScan();
    cacheReady = true;
  } catch (e) {
    console.warn("[scanVerthysRecords] 缓存扫描失败，回退到逐条 IPC 读取", e);
  }

  if (cacheReady) {
    // 快速路径：从缓存遍历（零 IPC 调用，纯内存读取）
    for (let id = 1; id <= maxId; id++) {
      const r = getRecordFromScan(id);
      if (r === null) {
        if (++nullStreak >= nullStreakLimit) break;
        continue;
      }
      nullStreak = 0;

      const entry: VerthysRecordEntry = { id, type: r.type, name: r.name, dataB64: r.dataB64 };
      if (handler(entry)) break;
    }
  } else {
    // 回退路径：逐条 IPC 读取（兼容所有场景，最稳健）
    // 关键容错：verthysGetRecord 在 IPC 失败时会抛出 VerthysError，
    // 必须捕获并按 null 处理，否则会导致上层 initCreate/initUnlock 崩溃。
    let ipcErrorLogged = false;
    for (let id = 1; id <= maxId; id++) {
      let r: { type: number; name: string; dataB64: string } | null;
      try {
        r = await verthysGetRecord(id);
      } catch (e) {
        // 仅记录首次 IPC 错误，避免 100000 次循环刷爆日志
        if (!ipcErrorLogged) {
          console.warn(`[scanVerthysRecords] verthysGetRecord(${id}) IPC 异常，按 null 处理`, e);
          ipcErrorLogged = true;
        }
        r = null;
      }
      if (r === null) {
        if (++nullStreak >= nullStreakLimit) break;
        continue;
      }
      nullStreak = 0;

      const entry: VerthysRecordEntry = { id, type: r.type, name: r.name, dataB64: r.dataB64 };
      if (handler(entry)) break;
    }
  }
}

/**
 * 查找第一条满足谓词的 verthys 记录
 *
 * @param predicate 谓词函数，返回非 null 表示匹配
 * @returns 匹配的记录条目，或 null
 */
export async function findVerthysRecord<T>(
  predicate: (entry: VerthysRecordEntry) => T | null,
): Promise<{ entry: VerthysRecordEntry; result: T } | null> {
  let found: { entry: VerthysRecordEntry; result: T } | null = null;
  await scanVerthysRecords((entry) => {
    const result = predicate(entry);
    if (result !== null) {
      found = { entry, result };
      return true; // stop
    }
    return false;
  });
  return found;
}
