/**
 * useFileImport 单测 — 导入管道矩阵
 *
 * 覆盖：单遍上传与元数据闭包、续传非内容条目键去重跳过、同内容不同路径
 * 各自导入（无内容级去重）、元数据失败守卫、块批失败、用户取消、0 字节文件、
 * 批边界身份复查、分片读取长度不符、结束身份复查、会话冲突确认（允许/拒绝）、
 * 加密形态的键口径。
 * 断言口径：成功必以 success 结束会话并触发孤儿回收；失败必以未成功结束
 * 会话且不写元数据；一切"少读/走样"都表现为显式失败而非静默降级。
 */
import { describe, expect, it } from "vitest";
import { createBLAKE3 } from "hash-wasm";
import { sha256 } from "@noble/hashes/sha2";
import { MAX_FILE_CHUNK_SIZE_BYTES } from "../../constants/photo_budget.generated";
import {
  TYPE_FILEVERTHYS_CHUNK,
  TYPE_FILEVERTHYS_META,
} from "../../constants/record_types";
import { base64ToBytes, bytesToBase64, bytesToHex } from "../../utils/binary_codec";
import {
  blocksPerBatchBudget,
  fileHashSuffix,
  runFileImport,
  type FileImportDeps,
  type FileKeySuite,
  type ImportProgress,
} from "./useFileImport";
import type {
  BatchRecordInput,
  ChunkBlobInput,
  ImportBeginResult,
} from "../../types/verthys";

const CHUNK = MAX_FILE_CHUNK_SIZE_BYTES;

async function expectedFileHash(plain: Uint8Array, encrypted: boolean): Promise<string> {
  const h = await createBLAKE3();
  h.init();
  h.update(plain);
  h.update(fileHashSuffix(encrypted));
  return h.digest("hex");
}

/** 复算生产者口径的非内容条目键（路径 + 长度 + 修改时间） */
function entryKeyOf(path: string, size: number, mtime: number): string {
  return bytesToHex(sha256(new TextEncoder().encode(`file|${path}|${size}|${mtime}`)));
}

/** 复算生产者口径的非内容块键（条目键 + 块序号） */
function chunkKeyOf(entryKey: string, seq: number): string {
  return bytesToHex(sha256(new TextEncoder().encode(`chunk|${entryKey}|${seq}`)));
}

function makeBytes(len: number, fill: number): Uint8Array {
  const b = new Uint8Array(len);
  b.fill(fill);
  return b;
}

function okBegin(entryKeys: string[] = []): ImportBeginResult {
  return { ok: true, import_id: "imp-1", entry_keys: entryKeys, total_count: 0 };
}

interface VFile {
  bytes: Uint8Array;
  mtime: number;
}

interface HarnessOptions {
  /** 遗留会话的已提交条目键集（命中即续传跳过） */
  legacyKeys?: string[];
  /** 会话创建返回序列（依次出队；耗尽后返回成功且无遗留集合） */
  beginQueue?: ImportBeginResult[];
  /** 块批写入注入失败 */
  chunkBatchFails?: boolean;
  /** 块批写入注入传输层异常 */
  chunkBatchThrows?: boolean;
  /** 元数据写入注入失败 */
  metaFails?: boolean;
  /** 元数据写入注入传输层异常 */
  recordsBatchThrows?: boolean;
  /** 元数据被后端按会话日志去重跳过（结构化 skipped_count 路径） */
  metaSkippedByBackend?: boolean;
  /** 会话冲突确认结果 */
  sessionBusyAllowed?: boolean;
  /** 统计覆盖序列（依次出队，用于模拟身份复查时的文件变化） */
  statOverrides?: Array<{ size: number; mtime_ms: number }>;
  /** 分片读取覆盖（返回 undefined 表示走默认读取） */
  onRead?: (callIndex: number, path: string, offset: number, length: number) => Uint8Array | undefined;
  /** 元数据写入成功后的回调（如触发取消信号） */
  onRecordBatch?: (records: BatchRecordInput[]) => void;
  /** 桩套件的注入失败点 */
  suiteFails?: { create?: boolean; encrypt?: boolean; check?: boolean };
  /** 容器卷可用空间注入（缺省=充裕；null=读数不可得） */
  freeSpace?: number | null;
}

/**
 * 桩密钥套件：保持真实结构形状（kdf/密文长度）与确定性变换，
 * 并对派生/加密/校验块生成计数，供"每文件一次派生"等断言。
 */
function makeSuiteStub(opts: { failCreate?: boolean; failEncrypt?: boolean; failCheck?: boolean } = {}) {
  const stats = { createFileKdf: 0, encryptChunk: 0, buildPasswordCheck: 0 };
  const suite: FileKeySuite = {
    createFileKdf: async () => {
      stats.createFileKdf += 1;
      if (opts.failCreate) throw new Error("注入的派生失败");
      return {
        version: 2,
        saltB64: bytesToBase64(new Uint8Array(16).fill(3)),
        iterations: 150000,
      };
    },
    encryptChunk: async (plain) => {
      stats.encryptChunk += 1;
      if (opts.failEncrypt) throw new Error("注入的加密失败");
      // 密文 = iv(12 占位) ‖ 明文 ‖ 标签(16 占位)：与 v2 形态同构
      const cipher = new Uint8Array(12 + plain.length + 16);
      cipher.set(plain, 12);
      return cipher;
    },
    buildPasswordCheck: async () => {
      stats.buildPasswordCheck += 1;
      if (opts.failCheck) throw new Error("注入的校验块失败");
      return bytesToBase64(new TextEncoder().encode("password-check"));
    },
  };
  return { suite, stats };
}

function makeHarness(opts: HarnessOptions = {}) {
  const vfs = new Map<string, VFile>();
  const beginQueue = [...(opts.beginQueue ?? [])];
  const stats = [...(opts.statOverrides ?? [])];
  const events: string[] = [];
  const chunkBatches: ChunkBlobInput[][] = [];
  const recordBatches: BatchRecordInput[][] = [];
  const endCalls: boolean[] = [];
  const statCalls: number[] = [];
  const progress: ImportProgress[] = [];
  const stub = makeSuiteStub({
    failCreate: opts.suiteFails?.create,
    failEncrypt: opts.suiteFails?.encrypt,
    failCheck: opts.suiteFails?.check,
  });
  let readCalls = 0;
  let cancelled = false;
  let nextChunkId = 1000;
  let nextMetaId = 2000;

  const deps: FileImportDeps = {
    statFile: async (path) => {
      statCalls.push(statCalls.length + 1);
      if (stats.length > 0) return stats.shift() as { size: number; mtime_ms: number };
      const f = vfs.get(path);
      if (!f) throw new Error("文件不存在");
      return { size: f.bytes.length, mtime_ms: f.mtime };
    },
    readChunk: async (path, offset, length) => {
      readCalls += 1;
      const override = opts.onRead?.(readCalls, path, offset, length);
      if (override) return override;
      const f = vfs.get(path);
      if (!f) throw new Error("文件不存在");
      return f.bytes.slice(offset, offset + length);
    },
    v2: stub.suite,
    freeSpaceBytes: async () => {
      if (opts.freeSpace === null) throw new Error("空间读数不可得");
      return opts.freeSpace ?? Number.MAX_SAFE_INTEGER;
    },
    walRecover: async () => ({ ok: true, entry_keys: [] }),
    importBegin: async () => beginQueue.shift() ?? okBegin(opts.legacyKeys ?? []),
    importEnd: async (success) => {
      endCalls.push(success);
      events.push(`end:${success}`);
      return { ok: true };
    },
    forceCloseSession: async () => {
      events.push("force-close");
      return true;
    },
    chunkBatch: async (chunks) => {
      chunkBatches.push(chunks);
      if (opts.chunkBatchThrows) {
        throw new Error("注入的通道异常");
      }
      if (opts.chunkBatchFails) {
        return { ok: false, ids: [], failed_indices: [], error: "注入的块批失败" };
      }
      return { ok: true, ids: chunks.map(() => nextChunkId++), failed_indices: [] };
    },
    recordsBatch: async (records) => {
      recordBatches.push(records);
      opts.onRecordBatch?.(records);
      if (opts.recordsBatchThrows) {
        throw new Error("注入的通道异常");
      }
      if (opts.metaFails) {
        return {
          ok: false,
          ids: [],
          batch_id: 1,
          failed_indices: [0],
          processed_count: 1,
          total_count: 0,
          skipped_count: 0,
          error: "注入的元数据失败",
        };
      }
      return {
        ok: true,
        ids: opts.metaSkippedByBackend ? [0] : [nextMetaId++],
        batch_id: 1,
        failed_indices: [],
        processed_count: records.length,
        total_count: records.length,
        skipped_count: opts.metaSkippedByBackend ? 1 : 0,
      };
    },
    gcOrphanChunks: async () => {
      events.push("gc");
      return 0;
    },
    onSessionBusy: async () => {
      events.push("ask");
      return opts.sessionBusyAllowed ?? false;
    },
    isCancelled: () => cancelled,
    onProgress: (p) => {
      progress.push(p);
    },
  };

  return {
    deps,
    vfs,
    events,
    chunkBatches,
    recordBatches,
    endCalls,
    statCalls,
    progress,
    suiteStats: stub.stats,
    get readCalls() {
      return readCalls;
    },
    cancel: () => {
      cancelled = true;
    },
  };
}

function fileOf(name: string): { path: string; name: string; mime: string } {
  return { path: `C:\\in\\${name}`, name, mime: "application/octet-stream" };
}

describe("blocksPerBatchBudget", () => {
  it("按载荷与块数双预算推导（当前常量为 2 块/批）", () => {
    // 4 MiB 块 base64 约 5.33 MiB，12 MiB 载荷上限可容纳 2 块、容不下 3 块
    expect(blocksPerBatchBudget()).toBe(2);
    expect(blocksPerBatchBudget()).toBeLessThanOrEqual(8);
  });
});

describe("runFileImport", () => {
  it("单遍多块：块批按预算切分，元数据闭包与去重键口径一致", async () => {
    const h = makeHarness();
    const bytes = makeBytes(CHUNK * 2 + 10, 7);
    h.vfs.set("C:\\in\\big.bin", { bytes, mtime: 1000 });

    const result = await runFileImport([fileOf("big.bin")], null, h.deps);

    expect(result.ok).toBe(true);
    expect(result.successCount).toBe(1);
    expect(result.entries).toHaveLength(1);
    expect(h.chunkBatches.map((b) => b.length)).toEqual([2, 1]);
    expect(h.endCalls).toEqual([true]);
    expect(h.events).toContain("gc");

    const entry = result.entries[0];
    expect(entry.metaId).toBe(2000);
    expect(entry.metaName).toBe("meta_big.bin");
    expect(entry.totalChunks).toBe(3);
    expect(entry.chunkIds).toEqual([1000, 1001, 1002]);
    expect(entry.fileHash).toBe(await expectedFileHash(bytes, false));
    // 条目键为非内容身份键：路径 + 长度 + 修改时间，与内容摘要无关
    const entryKey = entryKeyOf("C:\\in\\big.bin", bytes.length, 1000);
    expect(entry.entryKey).toBe(entryKey);
    expect(entry.entryKey).not.toBe(entry.fileHash);

    // 块载荷：键为条目键 + 序号派生的非内容块键，记录角色为清藏文件块
    const blobs = h.chunkBatches.flat();
    for (let i = 0; i < blobs.length; i++) {
      const blob = blobs[i];
      expect(blob.rtype).toBe(TYPE_FILEVERTHYS_CHUNK);
      expect(blob.chunk_key).toBe(chunkKeyOf(entryKey, i));
    }
    expect(new Set(blobs.map((b) => b.chunk_key)).size).toBe(3);
    // 内容摘要仅留在元数据引用中（完整性校验用），不作块名/去重键
    expect(entry.chunkHashes).toHaveLength(3);

    // 元数据记录：类型 / 名称 / 引用 / 条目键
    expect(h.recordBatches).toHaveLength(1);
    const metaRec = h.recordBatches[0][0];
    expect(metaRec.rtype).toBe(TYPE_FILEVERTHYS_META);
    expect(metaRec.name).toBe("meta_big.bin");
    expect(metaRec.entry_key).toBe(entryKey);
    expect(metaRec.chunk_ids).toEqual(entry.chunkIds);
    expect(metaRec.chunk_hashes).toEqual(entry.chunkHashes);
    const metaJson = JSON.parse(new TextDecoder().decode(base64ToBytes(metaRec.data_b64)));
    expect(metaJson.size).toBe(bytes.length);
    expect(metaJson.chunkIds).toEqual(entry.chunkIds);
    expect(metaJson.encrypted).toBe(false);
    // 明文条目无口令校验面：kdf 与 passwordCheck 均不写
    expect(metaJson.kdf).toBeUndefined();
    expect(metaJson.passwordCheck).toBeUndefined();
    expect(entry.kdf).toBeUndefined();
    expect(entry.passwordCheck).toBeUndefined();

    // 身份复查：文件开始 + 每个块批边界 + 文件结束
    expect(h.statCalls.length).toBe(4);
    // 进度收敛到该文件完成
    expect(h.progress[h.progress.length - 1].fileFraction).toBe(1);
    expect(h.progress.length).toBeGreaterThan(0);
  });

  it("续传命中同一条目键：不读取不上传，显式跳过", async () => {
    const bytes = makeBytes(CHUNK + 5, 3);
    const entryKey = entryKeyOf("C:\\in\\dup.bin", bytes.length, 1000);
    const h = makeHarness({ legacyKeys: [entryKey] });
    h.vfs.set("C:\\in\\dup.bin", { bytes, mtime: 1000 });

    const result = await runFileImport([fileOf("dup.bin")], null, h.deps);

    expect(result.skippedCount).toBe(1);
    expect(result.skipped).toEqual(["dup.bin"]);
    expect(result.entries).toHaveLength(0);
    expect(result.failCount).toBe(0);
    // 命中条目键后零读取、零块上传、零元数据写入
    expect(h.readCalls).toBe(0);
    expect(h.chunkBatches).toEqual([]);
    expect(h.recordBatches).toEqual([]);
    expect(h.endCalls).toEqual([true]);
  });

  it("同内容不同路径：各自导入，不做内容级去重（不构成存在性预言机）", async () => {
    const bytes = makeBytes(64, 5);
    const h = makeHarness();
    h.vfs.set("C:\\in\\a.bin", { bytes, mtime: 1000 });
    h.vfs.set("C:\\in\\b.bin", { bytes, mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin"), fileOf("b.bin")], null, h.deps);

    expect(result.successCount).toBe(2);
    expect(result.skippedCount).toBe(0);
    expect(result.entries.map((e) => e.name)).toEqual(["a.bin", "b.bin"]);
    // 同内容但不同路径 → 条目键与块键均不同，两次都完整上传
    const [ea, eb] = result.entries;
    expect(ea.entryKey).not.toBe(eb.entryKey);
    expect(h.chunkBatches).toHaveLength(2);
    expect(h.chunkBatches[0][0].chunk_key).not.toBe(h.chunkBatches[1][0].chunk_key);
    // 内容摘要一致（完整性口径），但不再作为去重依据
    expect(ea.fileHash).toBe(eb.fileHash);
  });

  it("同一会话内同路径/长度/时间重试：第二次按条目键跳过，不重复落库", async () => {
    const bytes = makeBytes(32, 6);
    const h = makeHarness();
    h.vfs.set("C:\\in\\retry.bin", { bytes, mtime: 1000 });

    // 同一文件连续两次进入管道（模拟同批重复选择）
    const result = await runFileImport(
      [fileOf("retry.bin"), fileOf("retry.bin")],
      null,
      h.deps,
    );

    expect(result.successCount).toBe(1);
    expect(result.skippedCount).toBe(1);
    expect(h.chunkBatches).toHaveLength(1);
    expect(h.recordBatches).toHaveLength(1);
    expect(h.readCalls).toBe(1);
  });

  it("元数据写入失败：不计成功、不入条目、会话按未成功结束", async () => {
    const h = makeHarness({ metaFails: true });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(10, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.ok).toBe(false);
    expect(result.successCount).toBe(0);
    expect(result.entries).toHaveLength(0);
    expect(result.failCount).toBe(1);
    expect(result.failures[0].code).toBe("E_META_FAILED");
    expect(h.endCalls).toEqual([false]);
    expect(h.events).not.toContain("gc");
  });

  it("块批写入失败：定位块序号并中止，不写元数据", async () => {
    const h = makeHarness({ chunkBatchFails: true });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(10, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.failCount).toBe(1);
    expect(result.failures[0].code).toBe("E_CHUNK_FAILED");
    expect(result.failures[0].message).toContain("第 1 块");
    expect(h.recordBatches).toEqual([]);
    expect(h.endCalls).toEqual([false]);
  });

  it("块批传输层异常：按块写入失败分类，不写元数据", async () => {
    const h = makeHarness({ chunkBatchThrows: true });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(10, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.failCount).toBe(1);
    expect(result.failures[0].code).toBe("E_CHUNK_FAILED");
    expect(result.failures[0].message).toContain("第 1 块批次写入失败");
    expect(h.recordBatches).toEqual([]);
    expect(h.endCalls).toEqual([false]);
  });

  it("进度不先于落库上报：块批失败时进度停在本批之前", async () => {
    const h = makeHarness({ chunkBatchFails: true });
    // 两块：一批写入即失败，任何块都不应被计为已完成
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(CHUNK + 4, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.failCount).toBe(1);
    expect(h.progress.length).toBeGreaterThan(0);
    expect(h.progress.every((p) => p.doneInFile === 0)).toBe(true);
  });

  it("未分类异常独立归类为 E_UNKNOWN（不冒充读取失败）", async () => {
    const h = makeHarness();
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(10, 1), mtime: 1000 });
    // 进度回调抛出属管道外异常：既非读取也非块写入
    h.deps.onProgress = () => {
      throw new Error("进度回调注入异常");
    };

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.failCount).toBe(1);
    expect(result.failures[0].code).toBe("E_UNKNOWN");
    expect(h.endCalls).toEqual([false]);
  });

  it("元数据传输层异常：按元数据失败分类（不退化为读取失败）", async () => {
    const h = makeHarness({ recordsBatchThrows: true });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(10, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.failCount).toBe(1);
    expect(result.failures[0].code).toBe("E_META_FAILED");
    expect(result.entries).toHaveLength(0);
    expect(h.endCalls).toEqual([false]);
  });

  it("后端按会话日志跳过元数据：按跳过入账而非失败", async () => {
    const h = makeHarness({ metaSkippedByBackend: true });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(10, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.skippedCount).toBe(1);
    expect(result.failCount).toBe(0);
    expect(result.entries).toHaveLength(0);
    expect(result.ok).toBe(true);
    expect(h.endCalls).toEqual([true]);
  });

  it("用户取消：当前文件后停止投喂，已提交文件保留", async () => {
    const h = makeHarness({
      onRecordBatch: () => {
        h.cancel();
      },
    });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(10, 1), mtime: 1000 });
    h.vfs.set("C:\\in\\b.bin", { bytes: makeBytes(20, 2), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin"), fileOf("b.bin")], null, h.deps);

    expect(result.cancelled).toBe(true);
    expect(result.successCount).toBe(1);
    expect(result.failCount).toBe(0);
    expect(result.entries[0].name).toBe("a.bin");
    expect(h.readCalls).toBe(1);
    expect(h.endCalls).toEqual([false]);
    expect(h.events).not.toContain("gc");
  });

  it("0 字节文件：零读取、零块批，元数据携带空引用", async () => {
    const h = makeHarness();
    h.vfs.set("C:\\in\\empty.bin", { bytes: new Uint8Array(0), mtime: 1000 });

    const result = await runFileImport([fileOf("empty.bin")], null, h.deps);

    expect(result.ok).toBe(true);
    expect(h.readCalls).toBe(0);
    expect(h.chunkBatches).toEqual([]);
    const metaRec = h.recordBatches[0][0];
    expect(metaRec.chunk_ids).toEqual([]);
    expect(metaRec.chunk_hashes).toEqual([]);
    const entry = result.entries[0];
    expect(entry.totalChunks).toBe(0);
    expect(entry.chunkIds).toEqual([]);
    expect(h.endCalls).toEqual([true]);
  });

  it("批边界修改时间变化：中止该文件，不写元数据", async () => {
    const h = makeHarness({
      statOverrides: [
        { size: CHUNK * 2 + 10, mtime_ms: 1000 },
        { size: CHUNK * 2 + 10, mtime_ms: 2000 },
      ],
    });
    h.vfs.set("C:\\in\\big.bin", { bytes: makeBytes(CHUNK * 2 + 10, 5), mtime: 1000 });

    const result = await runFileImport([fileOf("big.bin")], null, h.deps);

    expect(result.failCount).toBe(1);
    expect(result.failures[0].code).toBe("E_FILE_CHANGED");
    expect(h.chunkBatches).toHaveLength(1);
    expect(h.recordBatches).toEqual([]);
    expect(h.endCalls).toEqual([false]);
  });

  it("分片读取长度不符：显式失败而非静默截断", async () => {
    const h = makeHarness({
      onRead: (callIndex, _path, _offset, length) =>
        callIndex === 2 ? makeBytes(5, 9) : makeBytes(length, 9),
    });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(CHUNK * 2, 9), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.failCount).toBe(1);
    expect(result.failures[0].code).toBe("E_READ_FAILED");
    expect(result.failures[0].message).toContain("第 2 块");
    expect(h.chunkBatches).toEqual([]);
    expect(h.endCalls).toEqual([false]);
  });

  it("结束身份复查发现长度变化：中止该文件", async () => {
    const h = makeHarness({
      statOverrides: [
        { size: 10, mtime_ms: 1000 },
        { size: 11, mtime_ms: 1000 },
      ],
    });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(10, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.failures[0].code).toBe("E_FILE_CHANGED");
    expect(h.recordBatches).toEqual([]);
    expect(h.endCalls).toEqual([false]);
  });

  it("会话冲突且用户允许结束：结束上一会话后继续导入", async () => {
    const h = makeHarness({
      sessionBusyAllowed: true,
      beginQueue: [
        { ok: false, import_id: "", entry_keys: [], total_count: 0, error: "已有导入会话进行中，请先结束当前会话", error_code: "E_IMPORT_SESSION_BUSY" },
        okBegin(),
      ],
    });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(10, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.successCount).toBe(1);
    expect(h.events).toContain("ask");
    // 先以未成功结束上一会话，再以成功结束本次会话
    expect(h.endCalls).toEqual([false, true]);
  });

  it("会话冲突且用户拒绝：不处理任何文件，返回初始化失败", async () => {
    const h = makeHarness({
      sessionBusyAllowed: false,
      beginQueue: [
        { ok: false, import_id: "", entry_keys: [], total_count: 0, error: "已有导入会话进行中，请先结束当前会话", error_code: "E_IMPORT_SESSION_BUSY" },
      ],
    });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(10, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.error).toContain("已有导入会话");
    expect(result.successCount).toBe(0);
    expect(result.failures).toEqual([]);
    expect(h.readCalls).toBe(0);
    expect(h.endCalls).toEqual([]);
  });

  it("会话冲突判定以结构化错误码为准：无码的初始化失败不做冲突确认", async () => {
    const h = makeHarness({
      beginQueue: [
        { ok: false, import_id: "", entry_keys: [], total_count: 0, error: "创建导入会话失败: 磁盘异常" },
      ],
    });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(10, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.error).toContain("创建导入会话失败");
    expect(h.events).not.toContain("ask");
    expect(h.readCalls).toBe(0);
  });

  it("加密形态：文件级密钥每文件派生一次，块键非内容派生，meta 携派生参数与口令校验块", async () => {
    const plain = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
    const h = makeHarness();
    h.vfs.set("C:\\in\\secret.bin", { bytes: plain, mtime: 1000 });

    const result = await runFileImport([fileOf("secret.bin")], "pwd-123", h.deps);

    expect(result.successCount).toBe(1);
    const entry = result.entries[0];
    expect(entry.encrypted).toBe(true);

    // 派生参数与口令校验块（唯一判定点）随条目与 meta 落库
    expect(entry.kdf?.version).toBe(2);
    expect(entry.kdf?.iterations).toBe(150000);
    expect(entry.passwordCheck).toBe(
      bytesToBase64(new TextEncoder().encode("password-check")),
    );
    const metaJson = JSON.parse(
      new TextDecoder().decode(base64ToBytes(h.recordBatches[0][0].data_b64)),
    );
    expect(metaJson.kdf).toEqual(entry.kdf);
    expect(metaJson.passwordCheck).toBe(entry.passwordCheck);

    // 块键与内容无关：加密形态下同样只由条目键 + 序号派生
    const blobs = h.chunkBatches.flat();
    const cipher = new Uint8Array(12 + plain.length + 16);
    cipher.set(plain, 12);
    expect(blobs[0].chunk_key).toBe(chunkKeyOf(entry.entryKey, 0));
    expect(blobs[0].data_b64).toBe(bytesToBase64(cipher));

    // 内容摘要按"明文 + 形态标志"口径（不含任何密钥材料），仅用于完整性
    expect(entry.fileHash).toBe(await expectedFileHash(plain, true));
    expect(entry.fileHash).not.toBe(await expectedFileHash(plain, false));

    // 每文件一次派生；口令校验块一次生成
    expect(h.suiteStats.createFileKdf).toBe(1);
    expect(h.suiteStats.buildPasswordCheck).toBe(1);
  });

  it("体量预检：超过单文件上限的文件在读块之前拒绝（GB 读数文案）", async () => {
    const h = makeHarness({
      statOverrides: [{ size: 2 * 1024 * 1024 * 1024 + 1, mtime_ms: 1000 }],
    });
    h.vfs.set("C:\\in\\huge.bin", { bytes: makeBytes(8, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("huge.bin")], null, h.deps);

    expect(result.failCount).toBe(1);
    expect(result.failures[0].code).toBe("E_FILE_TOO_LARGE");
    expect(result.failures[0].message).toContain("超过单文件上限 2 GB");
    expect(h.readCalls).toBe(0);
    expect(h.chunkBatches).toEqual([]);
    expect(h.recordBatches).toEqual([]);
    expect(h.endCalls).toEqual([false]);
  });

  it("容器空间不足：前置拒绝且零读取零落库", async () => {
    const h = makeHarness({ freeSpace: 1024 });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(4096, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.failCount).toBe(1);
    expect(result.failures[0].code).toBe("E_DISK_FULL");
    expect(result.failures[0].message).toContain("容器磁盘空间不足");
    expect(h.readCalls).toBe(0);
    expect(h.chunkBatches).toEqual([]);
    expect(h.recordBatches).toEqual([]);
    expect(h.endCalls).toEqual([false]);
  });

  it("空间读数不可得：不阻断导入（前置预检为尽力而为）", async () => {
    const h = makeHarness({ freeSpace: null });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(8, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], null, h.deps);

    expect(result.successCount).toBe(1);
    expect(result.failCount).toBe(0);
  });

  it("加密导入多文件：每文件各自一次派生（不跨文件复用密钥）", async () => {
    const h = makeHarness();
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(8, 1), mtime: 1000 });
    h.vfs.set("C:\\in\\b.bin", { bytes: makeBytes(8, 2), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin"), fileOf("b.bin")], "pwd-123", h.deps);

    expect(result.successCount).toBe(2);
    expect(h.suiteStats.createFileKdf).toBe(2);
    expect(h.suiteStats.buildPasswordCheck).toBe(2);
  });

  it("文件密钥派生失败：整文件失败、不读块、不写元数据", async () => {
    const h = makeHarness({ suiteFails: { create: true } });
    h.vfs.set("C:\\in\\a.bin", { bytes: makeBytes(8, 1), mtime: 1000 });

    const result = await runFileImport([fileOf("a.bin")], "pwd-123", h.deps);

    expect(result.failCount).toBe(1);
    expect(result.failures[0].code).toBe("E_ENCRYPT_FAILED");
    expect(result.entries).toHaveLength(0);
    expect(h.chunkBatches).toEqual([]);
    expect(h.recordBatches).toEqual([]);
    expect(h.endCalls).toEqual([false]);
  });
});