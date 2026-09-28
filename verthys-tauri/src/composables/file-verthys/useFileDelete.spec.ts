/**
 * useFileDelete 单测 — 删除管道收敛矩阵
 *
 * 覆盖：批量事务失败（零副作用、保持原状、恢复后重试可完成）、落盘失败
 * （删除已提交、仅重放落盘与收尾、不重放删除）、去重键释放（成功后释放、
 * 失败转待重试队列并在下次导入前补释放、历史条目跳过）、成功路径
 * （块引用与元数据合并单次调用、缓存失效、孤儿回收、删除后可重导）。
 * 断言口径：任一失败步骤之后不得发生其后步骤；删除失败必须零副作用。
 */
import { describe, expect, it, vi } from "vitest";
import {
  createDedupeReleaseQueue,
  retryFileDeletePersist,
  runFileDelete,
  type DeleteSourceEntry,
  type FileDeleteDeps,
} from "./useFileDelete";

/** 外置形态条目：两个块记录 + 元数据记录，单次批量调用的期望 ID 集合 */
const IDS = [101, 102, 7];
const FILE_HASH = "9f2c4d1e8a3b5c7d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d";
const ENTRY: DeleteSourceEntry = {
  id: 7,
  name: "report.pdf",
  metaId: 7,
  chunkIds: [101, 102],
  fileHash: FILE_HASH,
};

interface HarnessOptions {
  /** 批量删除依次返回（最后一项重复生效；false = 失败） */
  deleteResults?: boolean[];
  /** 批量删除抛出异常 */
  deleteThrows?: boolean;
  /** 落盘依次返回（最后一项重复生效） */
  persistResults?: boolean[];
  /** 去重键释放依次返回（最后一项重复生效；false = 抛出） */
  forgetResults?: boolean[];
  /** 会话日志中已提交的去重键集合（重导判定的模拟口径） */
  committedHashes?: string[];
}

/** 顺序取值：队列仅剩一项时重复生效（模拟"随后恢复正常"的故障注入） */
function nextFrom<T>(queue: T[]): T {
  return queue.length > 1 ? (queue.shift() as T) : queue[0];
}

function makeHarness(opts: HarnessOptions = {}) {
  const deleteQueue = [...(opts.deleteResults ?? [true])];
  const persistQueue = [...(opts.persistResults ?? [true])];
  const forgetQueue = [...(opts.forgetResults ?? [true])];

  const calls = {
    delete: [] as number[][],
    invalidate: [] as number[][],
    persist: 0,
    forget: [] as string[][],
    gc: 0,
    enqueued: [] as string[],
  };
  const committed = new Set<string>(opts.committedHashes ?? []);

  /* 释放行为：管道直连与队列补释放共用同一实现（与生产装配一致） */
  const releaseHashes = async (hashes: string[]): Promise<void> => {
    calls.forget.push([...hashes]);
    if (!nextFrom(forgetQueue)) throw new Error("注入的释放失败");
    for (const h of hashes) committed.delete(h);
  };
  const releaseQueue = createDedupeReleaseQueue(releaseHashes);

  const deps: FileDeleteDeps = {
    deleteRecords: async (ids) => {
      calls.delete.push([...ids]);
      if (opts.deleteThrows) throw new Error("注入的批量删除异常");
      return nextFrom(deleteQueue);
    },
    persist: async () => {
      calls.persist += 1;
      return nextFrom(persistQueue);
    },
    forgetHashes: releaseHashes,
    invalidateRecords: (ids) => {
      calls.invalidate.push([...ids]);
    },
    gcOrphanChunks: async () => {
      calls.gc += 1;
      return 0;
    },
    enqueuePendingRelease: (hash) => {
      calls.enqueued.push(hash);
      releaseQueue.enqueue(hash);
    },
  };

  return { deps, calls, committed, releaseQueue };
}

describe("runFileDelete", () => {
  it("批量删除失败（返回失败 / 抛出异常）：收尾零变化、保持原状、恢复后重试可完成", async () => {
    const h = makeHarness({ deleteResults: [false, true] });
    const first = await runFileDelete(ENTRY, h.deps);

    expect(first).toMatchObject({ ok: false, code: "E_DELETE_FAILED" });
    expect(h.calls.delete).toEqual([IDS]);
    expect(h.calls.invalidate).toEqual([]);
    expect(h.calls.persist).toBe(0);
    expect(h.calls.forget).toEqual([]);
    expect(h.calls.gc).toBe(0);
    expect(h.calls.enqueued).toEqual([]);

    // 故障恢复后由同一入口重试：完整链路重新执行并收口
    const retry = await runFileDelete(ENTRY, h.deps);
    expect(retry).toEqual({ ok: true });
    expect(h.calls.delete).toEqual([IDS, IDS]);
    expect(h.calls.invalidate).toEqual([IDS]);

    // 异常形态：同样按删除失败分类且零副作用
    const h2 = makeHarness({ deleteThrows: true });
    const thrown = await runFileDelete(ENTRY, h2.deps);
    expect(thrown).toMatchObject({ ok: false, code: "E_DELETE_FAILED" });
    expect(h2.calls.invalidate).toEqual([]);
    expect(h2.calls.persist).toBe(0);
    expect(h2.calls.forget).toEqual([]);
    expect(h2.calls.gc).toBe(0);
  });

  it("落盘失败：删除已提交不重删，仅重放落盘与收尾；重试成功后收口", async () => {
    const h = makeHarness({ persistResults: [false, true] });
    const first = await runFileDelete(ENTRY, h.deps);

    expect(first).toMatchObject({ ok: false, code: "E_PERSIST_FAILED" });
    expect(h.calls.delete).toEqual([IDS]);
    expect(h.calls.invalidate).toEqual([IDS]);
    expect(h.calls.persist).toBe(1);
    expect(h.calls.forget).toEqual([]);
    expect(h.calls.gc).toBe(0);

    const retry = await retryFileDeletePersist(ENTRY, h.deps);
    expect(retry).toEqual({ ok: true });
    // 删除步骤不重放；落盘、释放、回收按序补做
    expect(h.calls.delete).toEqual([IDS]);
    expect(h.calls.persist).toBe(2);
    expect(h.calls.forget).toEqual([[FILE_HASH]]);
    expect(h.calls.gc).toBe(1);
  });

  it("去重键释放：成功后重导不再跳过；释放失败转待重试队列，下次导入前补释放清除", async () => {
    // 正常释放：删除完成即释放，重导判定集合同步移除
    const h1 = makeHarness({ committedHashes: [FILE_HASH] });
    const ok = await runFileDelete(ENTRY, h1.deps);
    expect(ok).toEqual({ ok: true });
    expect(h1.calls.forget).toEqual([[FILE_HASH]]);
    expect(h1.committed.has(FILE_HASH)).toBe(false);

    // 释放失败：删除结论不变 + 告警 + 入队；补释放成功后集合移除
    const h2 = makeHarness({ committedHashes: [FILE_HASH], forgetResults: [false, true] });
    const deferred = await runFileDelete(ENTRY, h2.deps);
    expect(deferred).toMatchObject({ ok: true, warning: expect.stringContaining("去重") });
    expect(h2.calls.enqueued).toEqual([FILE_HASH]);
    expect(h2.releaseQueue.size()).toBe(1);
    expect(h2.committed.has(FILE_HASH)).toBe(true);

    await h2.releaseQueue.flush();
    expect(h2.releaseQueue.size()).toBe(0);
    expect(h2.committed.has(FILE_HASH)).toBe(false);

    // 历史条目无去重键：跳过释放，不产生告警
    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
    const h3 = makeHarness();
    const legacy = await runFileDelete({ ...ENTRY, fileHash: undefined }, h3.deps);
    infoSpy.mockRestore();
    expect(legacy).toEqual({ ok: true });
    expect(h3.calls.forget).toEqual([]);
    expect(h3.calls.enqueued).toEqual([]);
  });

  it("成功路径：块引用与元数据合并单次调用、缓存失效、孤儿回收；删除后可重导", async () => {
    const h = makeHarness({ committedHashes: [FILE_HASH] });
    const result = await runFileDelete(ENTRY, h.deps);

    expect(result).toEqual({ ok: true });
    // 单次批量事务：两个块 + 元数据一次调用，无逐条删除
    expect(h.calls.delete).toEqual([IDS]);
    expect(h.calls.invalidate).toEqual([IDS]);
    expect(h.calls.persist).toBe(1);
    expect(h.calls.forget).toEqual([[FILE_HASH]]);
    expect(h.calls.gc).toBe(1);
    expect(h.committed.has(FILE_HASH)).toBe(false);

    // 历史内联形态：块密文在元数据记录内，仅删元数据
    const inline = makeHarness();
    const inlineResult = await runFileDelete(
      { ...ENTRY, chunkIds: [201, 202], chunkDataB64: ["ZmFrZQ=="] },
      inline.deps,
    );
    expect(inlineResult).toEqual({ ok: true });
    expect(inline.calls.delete).toEqual([[7]]);

    // 无后端记录的条目（浏览器演示）：视为已收口，零后端动作
    const demo = makeHarness();
    const demoResult = await runFileDelete({ id: 1, name: "demo.pdf" }, demo.deps);
    expect(demoResult).toEqual({ ok: true });
    expect(demo.calls.delete).toEqual([]);
    expect(demo.calls.persist).toBe(0);
  });
});