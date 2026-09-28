/**
 * file-verthys/useFileDelete.ts — 清藏删除管道
 *
 * 职责：把一条文件条目的记录集合（外置块引用 + 元数据）以单次批量事务
 * 删除，并在删除提交后完成立即落盘、文件级去重键释放与孤儿块回收，
 * 保证"要么全部收口、要么保留条目并可重试"。
 *
 * 设计要点：
 * - 单次批量事务：块引用与元数据 ID 合并为一次批量删除调用（单事务提交，
 *   磁盘写入量与条目数解耦）；结果未确认前，缓存与列表零变化；
 * - 失败可收敛：删除失败保持原状（重新执行即重试，零副作用）；落盘失败
 *   保持条目并给出仅重放落盘的入口——删除已提交，批量删除对缺失条目
 *   整体拒绝并零副作用返回，删除步骤不可重放；
 * - 去重键释放：删除落盘成功后释放文件级去重键（释放实现内置一次即时
 *   重试）；历史条目无键则跳过并留日志；仍失败转入待重试队列，由下次
 *   导入开始前统一补释放，不改变删除结论；
 * - 孤儿回收：全部收口后 best-effort 触发一次，失败仅推迟到下次触发时机；
 * - 依赖注入：批量删除、落盘、释放、缓存失效、回收均由调用方提供，
 *   便于单元测试。
 */

/** 删除失败原因分类（调用方据此决定文案与后续动作） */
export type FileDeleteErrorCode = "E_DELETE_FAILED" | "E_PERSIST_FAILED";

/** 删除输入：从列表条目收敛出的最小字段集 */
export interface DeleteSourceEntry {
  /** 列表条目本地 ID（调用方定位用） */
  id: number;
  /** 展示名（日志定位用） */
  name: string;
  /** 元数据记录 ID（列表条目必有；缺省视为无后端记录） */
  metaId?: number;
  /** 外置块记录 ID 列表（当前写入形态） */
  chunkIds?: number[];
  /** 历史内联块密文（旧形态：块密文在元数据记录内，无独立块记录） */
  chunkDataB64?: string[];
  /** 文件级去重键（删除落盘后须释放，否则重导被跳过；历史条目缺省） */
  fileHash?: string;
}

/** 删除依赖集合（生产实现由模块装配处提供；测试以桩替换） */
export interface FileDeleteDeps {
  /** 单次批量事务删除（含待删过滤与入库前复用校验）；成功返回 true */
  deleteRecords: (ids: number[]) => Promise<boolean>;
  /** 立即落盘（取消防抖并等待落盘完成）；返回数据是否已落盘 */
  persist: () => Promise<boolean>;
  /** 释放文件级去重键（实现内置一次即时重试，仍失败即抛） */
  forgetHashes: (hashes: string[]) => Promise<void>;
  /** 同步失效摘要 / 全量 / 扫描三层缓存（删除提交后调用，杜绝回填复活） */
  invalidateRecords: (ids: number[]) => void;
  /** 孤儿块回收：返回本次清除条数（best-effort，不改变删除结论） */
  gcOrphanChunks: () => Promise<number>;
  /** 释放失败（含一次即时重试仍失败）的键转入待重试队列 */
  enqueuePendingRelease: (hash: string) => void;
}

export interface FileDeleteSuccess {
  ok: true;
  /** 删除与落盘已完成、仅去重键释放失败并转入待重试队列时的告警文案 */
  warning?: string;
}

export interface FileDeleteFailure {
  ok: false;
  code: FileDeleteErrorCode;
  /** 面向用户的说明（含可执行的下一步动作） */
  message: string;
}

export type FileDeleteResult = FileDeleteSuccess | FileDeleteFailure;

/** 删除未发生：原状保持，重新执行即重试 */
const DELETE_FAILED_MESSAGE = "删除失败，请重试";

/** 删除已提交但未落盘：重启后记录可能恢复，仅需重放落盘 */
const PERSIST_FAILED_MESSAGE = "删除已提交但落盘失败，重启后文件可能恢复；请点击重试完成落盘";

/** 删除结论不受影响：释放由待重试队列在下次导入前补做 */
const DEFERRED_RELEASE_MESSAGE =
  "文件已删除，但去重状态释放失败：重新导入同一文件会被跳过。系统将在下次导入前自动重试释放";

/**
 * 收敛待删除记录 ID：外置块引用 + 元数据 ID，单次批量调用删除。
 *
 * 历史内联形态的块密文在元数据记录内，不产生独立块记录，因此只删元数据；
 * 结果去重——同一 ID 重复出现会让批量删除对缺失条目整体拒绝并零副作用返回。
 */
function collectRecordIds(entry: DeleteSourceEntry): number[] {
  const ids: number[] = [];
  const inlineForm = Array.isArray(entry.chunkDataB64) && entry.chunkDataB64.length > 0;
  if (!inlineForm && Array.isArray(entry.chunkIds) && entry.chunkIds.length > 0) {
    ids.push(...entry.chunkIds);
  }
  if (typeof entry.metaId === "number" && entry.metaId > 0) {
    ids.push(entry.metaId);
  }
  return [...new Set(ids)];
}

/**
 * 执行删除。
 *
 * @param entry 列表条目（含块引用、元数据 ID 与去重键）
 * @param deps 依赖集合
 * @returns 成功（可携去重释放告警）/ 失败（含分类与可执行文案）
 */
export async function runFileDelete(
  entry: DeleteSourceEntry,
  deps: FileDeleteDeps,
): Promise<FileDeleteResult> {
  const ids = collectRecordIds(entry);
  // 无后端记录（如浏览器演示条目）：视为已收口，不做任何后端动作
  if (ids.length === 0) return { ok: true };

  let deleted: boolean;
  try {
    deleted = await deps.deleteRecords(ids);
  } catch {
    deleted = false;
  }
  if (!deleted) {
    return { ok: false, code: "E_DELETE_FAILED", message: DELETE_FAILED_MESSAGE };
  }

  // 删除已提交：立即失效三层缓存，杜绝磁盘回填使条目复活
  deps.invalidateRecords(ids);
  return finishAfterDelete(entry, deps);
}

/**
 * 落盘失败后的重试入口：删除已提交，仅重放落盘与其后的收尾步骤。
 *
 * 不得重放删除步骤——批量删除对缺失条目整体拒绝并零副作用返回。
 */
export async function retryFileDeletePersist(
  entry: DeleteSourceEntry,
  deps: FileDeleteDeps,
): Promise<FileDeleteResult> {
  return finishAfterDelete(entry, deps);
}

/** 删除提交后的收尾：落盘 → 去重键释放 → 孤儿回收 */
async function finishAfterDelete(
  entry: DeleteSourceEntry,
  deps: FileDeleteDeps,
): Promise<FileDeleteResult> {
  let persisted: boolean;
  try {
    persisted = await deps.persist();
  } catch {
    persisted = false;
  }
  if (!persisted) {
    return { ok: false, code: "E_PERSIST_FAILED", message: PERSIST_FAILED_MESSAGE };
  }

  let warning: string | undefined;
  const hash = entry.fileHash;
  if (typeof hash === "string" && hash.length > 0) {
    try {
      await deps.forgetHashes([hash]);
    } catch {
      deps.enqueuePendingRelease(hash);
      warning = DEFERRED_RELEASE_MESSAGE;
    }
  } else {
    console.info(`[useFileDelete] 历史条目未携带去重键，跳过释放: ${entry.name}`);
  }

  try {
    await deps.gcOrphanChunks();
  } catch {
    /* 孤儿回收为 best-effort：失败仅推迟到下次触发时机，不改变删除结论 */
  }

  return warning === undefined ? { ok: true } : { ok: true, warning };
}

/** 待重试释放队列：删除落盘成功但释放失败的去重键暂存于此 */
export interface DedupeReleaseQueue {
  /** 暂存一个待释放的键 */
  enqueue(hash: string): void;
  /** 当前待释放键数 */
  size(): number;
  /** 重试全部待释放键；仍失败的保留在队列等待下次机会 */
  flush(): Promise<void>;
}

/**
 * 建立去重键释放待重试队列（进程内）。
 *
 * 释放失败会让被删文件重新导入时被静默跳过，因此不以"失败即日志"收场：
 * 暂存的键在下次导入开始前统一补释放，避免该状态在进程内残留为永久。
 * 跨重启不持久化（释放失败本身极少发生，队列仅覆盖"先删后导"的主要窗口）：
 * 极端情况下重启后再导入同一文件仍会命中跳过并提示，需再执行一次删除
 * 以补释放。
 */
export function createDedupeReleaseQueue(
  forgetHashes: (hashes: string[]) => Promise<void>,
): DedupeReleaseQueue {
  const pending = new Set<string>();
  return {
    enqueue(hash: string): void {
      pending.add(hash);
    },
    size(): number {
      return pending.size;
    },
    async flush(): Promise<void> {
      if (pending.size === 0) return;
      const batch = [...pending];
      try {
        await forgetHashes(batch);
        for (const h of batch) pending.delete(h);
      } catch (e) {
        console.warn("[useFileDelete] 待重试的去重键释放仍失败，保留至下次导入", e);
      }
    },
  };
}