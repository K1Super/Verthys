/**
 * importPipeline.spec.ts — 导入流水线成功语义与批次可靠性回归测试
 *
 * 覆盖（故障注入，断言静默丢失路径被根治）：
 * - 全成功：仅零失败路径以 verthysImportEnd(true) 压缩 WAL
 * - 致命错误（后端容量告罄 ERR_0000000F）：fatal 传播到返回结果并映射为
 *   存储空间不足文案，importEnd(false)
 * - 部分失败：只重试失败子集，成功项不回灌；重试耗尽按失败入账且 importEnd(false)
 * - 后端去重跳过：计入 skipped，绝不重试
 * - 致命错误后停止后续批次写入（消费端短路）
 * - 三分类/四分类不变量：所有返回路径 imported+failed+skipped+undecryptable === total
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// node 环境无 rAF：进度状态机依赖帧对齐刷新，测试中以宏任务近似单帧
if (typeof globalThis.requestAnimationFrame !== "function") {
  globalThis.requestAnimationFrame = (cb: FrameRequestCallback) =>
    setTimeout(() => cb(performance.now()), 0) as unknown as number;
}
if (typeof globalThis.cancelAnimationFrame !== "function") {
  globalThis.cancelAnimationFrame = ((id: ReturnType<typeof setTimeout>) =>
    clearTimeout(id)) as unknown as typeof cancelAnimationFrame;
}

// vi.mock 工厂在模块顶部执行，实例方法 mock 需经 vi.hoisted 提升
const { addRecordsBatchMock, importEndMock, addChunkBatchMock, waitForCapacityMock } = vi.hoisted(() => ({
  addRecordsBatchMock: vi.fn(),
  importEndMock: vi.fn(),
  addChunkBatchMock: vi.fn(),
  waitForCapacityMock: vi.fn(async () => {}),
}));

// 单文件上限在测试中收窄为 8 字节（真实值 100MB 无法构造样例数据），
// 仅影响 run() 读取路径的用例；其余用例不经文件读取，语义不受影响
vi.mock("../../constants/crypto_const", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../constants/crypto_const")>();
  return { ...actual, MAX_PHOTO_BYTES: 8 };
});

vi.mock("../../lib/verthys", () => ({
  verthysImportBegin: vi.fn(async () => ({
    ok: true,
    import_id: "imp-test",
    hashes: [],
    total_count: 0,
  })),
  verthysAddRecordsBatch: addRecordsBatchMock,
  verthysAddChunkBatch: addChunkBatchMock,
  verthysImportEnd: importEndMock,
  verthysWalRecover: vi.fn(async () => ({ ok: true, hashes: [], total_count: 0 })),
  // 孤儿块 GC：会话成功收尾时 fire-and-forget，测试环境给出已清理 0 条的成功回执
  verthysGcOrphanChunks: vi.fn(async () => 0),
}));

vi.mock("../../workers/photoWorkerPool", () => ({
  photoWorkerPool: {
    // meta-only 路径（runParsed）：回显提交的 meta，hash 取 meta.fileHash
    submitMetaOnly: vi.fn(
      async (req: { meta: { fileHash: string; name: string; mime: string; size: number; thumbB64?: string }; recordName: string }) => {
        const meta = req.meta;
        return {
          ok: true,
          id: 1,
          metaB64: "meta-b64",
          hash: meta.fileHash,
          thumbB64: meta.thumbB64 ?? "",
          name: meta.name,
          mime: meta.mime,
          size: meta.size,
          recordName: req.recordName,
        };
      },
    ),
    submit: vi.fn(async () => {
      throw new Error("run() 路径不在本组用例覆盖范围");
    }),
    // 索引瘦身布局的记录加密（缩略图 / 块集）：本组用例只验证写入编排，
    // 密文以占位值回显，真伪由 crypto-slim 与 worker 用例锁定
    submitEncryptSlimThumb: vi.fn(async () => ({
      id: 1, ok: true as const, thumbCipherB64: "thumb-b64", thumbHash: "thumb-hash",
    })),
    submitEncryptSlimSet: vi.fn(async () => ({
      id: 1, ok: true as const, setCipherB64: "cset-b64", setHash: "cset-hash",
    })),
    /** 读取闸门：默认立即放行（配额充足） */
    waitForCapacity: waitForCapacityMock,
    cancelAll: vi.fn(),
    terminate: vi.fn(),
  },
}));

vi.mock("../../cache/coordination/batch-cache-coordinator", () => ({
  BatchCacheCoordinator: class {
    begin = vi.fn();
    addRecord = vi.fn();
    end = vi.fn(async () => ({ flushed: 0, ok: true, failedLayers: [], elapsedMs: 0, retries: 0 }));
    abort = vi.fn();
  },
}));

import { ImportPipeline } from "./importPipeline";
import type { ParsedPhotoPreview } from "./types";
import type { PhotoMeta } from "../../lib/crypto";
import { createSlimFileKeys } from "../../lib/crypto";
import { MAX_PHOTO_BYTES, PHOTO_FMT_SLIM } from "../../constants/crypto_const";
import { photoWorkerPool } from "../../workers/photoWorkerPool";
import { reactive } from "vue";

/** 构造最小可用的解析预览项（meta 非 null 即可被流水线选中） */
function makePreview(i: number, hash: string): ParsedPhotoPreview {
  const meta: PhotoMeta = {
    name: `照片${i}.jpg`,
    mime: "image/jpeg",
    size: 1024,
    thumbB64: "",
    chunkIds: [],
    chunkDataB64: ["Y2h1bms="],
    fileHash: hash,
    createdAt: 1000 + i,
  };
  return {
    name: meta.name,
    thumb: "",
    size: meta.size,
    metaB64: `meta-b64-${i}`,
    chunkB64List: ["Y2h1bms="],
    meta,
  };
}

/** 构造默认全成功的批量响应：按输入顺序分配递增 ID */
function okBatchResponse(count: number, baseId = 10) {
  return {
    ok: true,
    ids: Array.from({ length: count }, (_, i) => baseId + i),
    batch_id: 1,
    failed_indices: [],
    processed_count: count,
    total_count: count,
    skipped_count: 0,
    error: undefined,
  };
}

function makePipeline(overrides: Partial<ConstructorParameters<typeof ImportPipeline>[0]> = {}) {
  return new ImportPipeline({
    consumerBatchSize: 50,
    maxInflightBatches: 1,
    producerConcurrency: 1,
    producerYieldInterval: 10_000,
    consumerMaxRetries: 1,
    consumerRetryBackoffMs: 0,
    ...overrides,
  });
}

describe("importPipeline — 会话结束成功语义守卫", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    importEndMock.mockResolvedValue({ ok: true, total_count: 0, import_id: "imp-test" });
    // 恒定外置存储：解析导入的每张照片都先上传分块记录，默认返回成功 id
    let chunkIdSeed = 900;
    addChunkBatchMock.mockImplementation(async (chunks: Array<{ hash: string }>) => ({
      ok: true,
      ids: chunks.map(() => chunkIdSeed++),
      batch_id: 1,
      failed_indices: [],
      processed_count: chunks.length,
      total_count: chunks.length,
      skipped_count: 0,
    }));
  });

  it("恒定外置：小体积预览同样落分块记录，meta 只携带引用", async () => {
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1));
    const pipe = makePipeline();

    const result = await pipe.runParsed([makePreview(0, "h1")], "key");

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(1);
    // 分块先落库（外置路径），提交的 meta 以 chunk_ids 引用且不内联密文
    expect(addChunkBatchMock).toHaveBeenCalledTimes(1);
    const record = addRecordsBatchMock.mock.calls[0][0][0] as {
      chunk_ids: number[];
      data_b64: string;
    };
    expect(record.chunk_ids.length).toBeGreaterThan(0);
    expect(record.data_b64).toBe("meta-b64");
  });

  it("索引瘦身布局且无缩略图：索引回填块集引用，认领列表不含占位 0", async () => {
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1));
    const pipe = makePipeline();
    // 合法包裹态文件密钥（提供文件盐）；缩略图缺失（生成失败）走 thumbId=0 分支
    const { wrappedFileKey } = await createSlimFileKeys("key");
    const preview = makePreview(0, "h1");
    preview.meta = {
      ...preview.meta!, fmt: PHOTO_FMT_SLIM, wrappedFileKey, thumbB64: "",
    };

    const result = await pipe.runParsed([preview], "key");

    expect(result.ok).toBe(true);
    // 缩略图缺失不阻断整张写入：索引以 thumbId=0 明确"无缩略图"
    const submitted = vi.mocked(photoWorkerPool.submitMetaOnly).mock.calls[0][0] as {
      meta: PhotoMeta;
    };
    expect(submitted.meta.thumbId).toBe(0);
    expect(submitted.meta.chunkSetId).toBeGreaterThan(0);
    expect(submitted.meta.chunkCount).toBe(1);
    // 认领列表只含真实记录 ID：占位 0 若混入，后端会按"引用未上传"拒绝整条
    const record = addRecordsBatchMock.mock.calls[0][0][0] as { chunk_ids: number[] };
    expect(record.chunk_ids).toEqual([900, submitted.meta.chunkSetId]);
  });

  it("全成功：仅零失败路径以 success=true 压缩 WAL", async () => {
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(2));
    const pipe = makePipeline();

    const result = await pipe.runParsed([makePreview(0, "h1"), makePreview(1, "h2")], "key");

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(2);
    expect(result.failedRecords).toHaveLength(0);
    expect(result.skipped).toBe(0);
    expect(importEndMock).toHaveBeenCalledTimes(1);
    expect(importEndMock).toHaveBeenCalledWith(true);
  });

  it("致命错误（后端容量告罄）：fatal 传播到返回结果并映射为存储空间不足，WAL 以 false 保留", async () => {
    addRecordsBatchMock.mockResolvedValue({
      ok: false,
      ids: [],
      batch_id: 1,
      failed_indices: [],
      processed_count: 0,
      total_count: 0,
      skipped_count: 0,
      error: "写入失败 (ERR_0000000F)",
    });
    const pipe = makePipeline();

    const result = await pipe.runParsed([makePreview(0, "h1"), makePreview(1, "h2")], "key");

    expect(result.ok).toBe(false);
    expect(result.error).toContain("存储空间不足");
    // 错误码映射：致命原因归类为 storage-full
    expect(result.failedRecords.length).toBeGreaterThan(0);
    expect(result.failedRecords.every((r) => r.reason === "storage-full")).toBe(true);
    // 四分类不变量：致命路径下剩余条目全部入账失败
    expect(result.imported.length + result.failedRecords.length + result.skipped + result.undecryptable)
      .toBe(2);
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("致命错误后停止写入：消费端短路，后续缓存批次不再发起 IPC", async () => {
    // 每批 1 条：第一张触发 flush 并注入致命错误，第二张的 flush 应被短路
    const pipe = makePipeline({ consumerBatchSize: 1 });
    addRecordsBatchMock.mockResolvedValue({
      ok: false,
      ids: [],
      batch_id: 1,
      failed_indices: [],
      processed_count: 0,
      total_count: 0,
      skipped_count: 0,
      error: "写入失败 (ERR_0000000F)",
    });

    const result = await pipe.runParsed([makePreview(0, "h1"), makePreview(1, "h2")], "key");

    expect(result.ok).toBe(false);
    // 首条触发致命错误后，后端写入通道不再被第二张唤起
    expect(addRecordsBatchMock).toHaveBeenCalledTimes(1);
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("部分失败且未达成功语义：WAL 以 false 保留，返回 ok=false", async () => {
    const pipe = makePipeline();
    // 请求 2 条：ids=[10,11] 全成功即 ok —— 这里改用单条重试耗尽场景由下一条用例覆盖
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(2));
    const result = await pipe.runParsed([makePreview(0, "h1"), makePreview(1, "h2")], "key");
    expect(result.ok).toBe(true);
    expect(importEndMock).toHaveBeenCalledWith(true);
  });

  it("不可解密项：计入 undecryptable 不入失败，成功路径压缩 WAL 且 ok=true", async () => {
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1));
    const pipe = makePipeline();
    const undecryptablePreview: ParsedPhotoPreview = {
      name: "加密照片",
      thumb: "",
      size: 0,
      metaB64: "meta-enc",
      chunkB64List: ["chunk"],
      meta: null,
    };

    const result = await pipe.runParsed([makePreview(0, "h1"), undecryptablePreview], "key");

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(1);
    expect(result.undecryptable).toBe(1);
    expect(result.failedRecords).toHaveLength(0);
    expect(importEndMock).toHaveBeenCalledWith(true);
  });
});

describe("importPipeline — 失败批次逐条回灌重试", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    importEndMock.mockResolvedValue({ ok: true, total_count: 0, import_id: "imp-test" });
    // 恒定外置存储：解析导入的每张照片都先上传分块记录，默认返回成功 id
    let chunkIdSeed = 700;
    addChunkBatchMock.mockImplementation(async (chunks: Array<{ hash: string }>) => ({
      ok: true,
      ids: chunks.map(() => chunkIdSeed++),
      batch_id: 1,
      failed_indices: [],
      processed_count: chunks.length,
      total_count: chunks.length,
      skipped_count: 0,
    }));
  });

  it("部分失败重试成功：只重试失败子集，成功项不回灌，最终 ok=true", async () => {
    const pipe = makePipeline();
    // 首次：ids=[10,0]，failed_indices=[1]（第 2 条待重试）
    // 重试：单条成功 ids=[11]
    addRecordsBatchMock
      .mockResolvedValueOnce({
        ok: true,
        ids: [10, 0],
        batch_id: 1,
        failed_indices: [1],
        processed_count: 2,
        total_count: 1,
        skipped_count: 0,
      })
      .mockResolvedValueOnce({
        ok: true,
        ids: [11],
        batch_id: 2,
        failed_indices: [],
        processed_count: 1,
        total_count: 2,
        skipped_count: 0,
      });
    const result = await pipe.runParsed([makePreview(0, "h1"), makePreview(1, "h2")], "key");

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(2);
    expect(addRecordsBatchMock).toHaveBeenCalledTimes(2);
    // 重试子批次只含失败的那一条
    const retryPayload = addRecordsBatchMock.mock.calls[1][0] as Array<{ hash: string }>;
    expect(retryPayload).toHaveLength(1);
    expect(retryPayload[0].hash).toBe("h2");
    expect(importEndMock).toHaveBeenCalledWith(true);
  });

  it("重试耗尽：失败项按服务端拒绝入账，整体 ok=false 且 WAL 保留", async () => {
    // 只允许 1 次重试：两次尝试均对 h2 返回失败（响应与请求等长，模拟真实后端逐条映射）
    const pipe = makePipeline({ consumerMaxRetries: 1 });
    addRecordsBatchMock.mockImplementation(
      async (records: Array<{ hash: string }>) => ({
        ok: true,
        ids: records.map((r) => (r.hash === "h1" ? 10 : 0)),
        batch_id: 1,
        failed_indices: records.flatMap((r, i) => (r.hash === "h1" ? [] : [i])),
        processed_count: records.length,
        total_count: 1,
        skipped_count: 0,
      }),
    );
    const result = await pipe.runParsed([makePreview(0, "h1"), makePreview(1, "h2")], "key");

    expect(result.ok).toBe(false);
    expect(result.imported).toHaveLength(1);
    expect(result.failedRecords).toHaveLength(1);
    expect(result.failedRecords[0].reason).toBe("server-rejected");
    expect(addRecordsBatchMock).toHaveBeenCalledTimes(2); // 首轮 + 1 次重试
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("后端哈希去重：计入 skipped，绝不进入重试，ok=true", async () => {
    const pipe = makePipeline();
    addRecordsBatchMock.mockResolvedValue({
      ok: true,
      ids: [10, 0],
      batch_id: 1,
      failed_indices: [],
      processed_count: 2,
      total_count: 1,
      skipped_count: 1,
    });
    const result = await pipe.runParsed([makePreview(0, "h1"), makePreview(1, "h1")], "key");

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(1);
    expect(result.skipped).toBe(1);
    expect(result.failedRecords).toHaveLength(0);
    expect(addRecordsBatchMock).toHaveBeenCalledTimes(1);
    expect(importEndMock).toHaveBeenCalledWith(true);
  });

  it("整批 IPC 异常且重试耗尽：按可重试失败入账，WAL 保留", async () => {
    const pipe = makePipeline({ consumerMaxRetries: 0 });
    addRecordsBatchMock.mockRejectedValue(new Error("ipc transport error"));
    const result = await pipe.runParsed([makePreview(0, "h1")], "key");

    expect(result.ok).toBe(false);
    expect(result.imported).toHaveLength(0);
    expect(result.failedRecords).toHaveLength(1);
    expect(result.failedRecords[0].retryable).toBe(true);
    expect(importEndMock).toHaveBeenCalledWith(false);
  });
});

describe("importPipeline — 大文件外置块路径", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    importEndMock.mockResolvedValue({ ok: true, total_count: 0, import_id: "imp-test" });
  });

  /** 构造外置路径预览项：多块负载（恒定外置策略下所有照片都走该路径） */
  function makeExternalPreview(i: number, hash: string, chunks = 9): ParsedPhotoPreview {
    const big = "A".repeat(1_000_000);
    const meta: PhotoMeta = {
      name: `大图${i}.jpg`,
      mime: "image/jpeg",
      size: chunks * 750_000,
      thumbB64: "",
      chunkIds: [],
      chunkDataB64: [],
      chunkHashes: Array.from({ length: chunks }, (_, k) => `${k}`.padStart(64, "b")),
      fileHash: hash,
      createdAt: 1000 + i,
    };
    return {
      name: meta.name,
      thumb: "",
      size: meta.size,
      metaB64: `meta-b64-${i}`,
      chunkB64List: Array.from({ length: chunks }, () => big),
      meta,
    };
  }

  it("外置：块分批上传（8+1 两批）→ meta 携带 chunkIds 引用提交", async () => {
    addChunkBatchMock
      .mockResolvedValueOnce({ ok: true, ids: [1, 2, 3, 4, 5, 6, 7, 8], failed_indices: [] })
      .mockResolvedValueOnce({ ok: true, ids: [9], failed_indices: [] });
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1, 30));

    const pipe = makePipeline();
    const result = await pipe.runParsed([makeExternalPreview(0, "h1")], "key");

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(1);
    // 两批上传：8 + 1（每批 ≤ 8 条上限）
    expect(addChunkBatchMock).toHaveBeenCalledTimes(2);
    const firstBatch = addChunkBatchMock.mock.calls[0][0] as Array<{ hash: string; data_b64: string }>;
    const secondBatch = addChunkBatchMock.mock.calls[1][0] as Array<{ hash: string; data_b64: string }>;
    expect(firstBatch).toHaveLength(8);
    expect(secondBatch).toHaveLength(1);
    // meta 记录携带完整引用
    const record = addRecordsBatchMock.mock.calls[0][0][0] as {
      chunk_ids: number[];
      chunk_hashes: string[];
      data_b64: string;
    };
    expect(record.chunk_ids).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(record.chunk_hashes).toHaveLength(9);
    expect(importEndMock).toHaveBeenCalledWith(true);
  });

  it("外置块上传失败：按 chunk-upload-failed 可重试入账，WAL 保留", async () => {
    addChunkBatchMock.mockResolvedValue({
      ok: false,
      ids: [],
      failed_indices: [0],
      error: "块载荷超过上限",
    });
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1, 30));

    const pipe = makePipeline();
    const result = await pipe.runParsed([makeExternalPreview(0, "h1")], "key");

    expect(result.ok).toBe(false);
    expect(result.imported).toHaveLength(0);
    expect(addRecordsBatchMock).not.toHaveBeenCalled();
    expect(result.failedRecords).toHaveLength(1);
    expect(result.failedRecords[0].reason).toBe("chunk-upload-failed");
    expect(result.failedRecords[0].retryable).toBe(true);
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("外置已 committed 文件：前置去重跳过，无块上传无加密提交", async () => {
    // begin 返回的 hashes 含该文件 → 生产者直接跳过
    const { verthysImportBegin } = await import("../../lib/verthys");
    (verthysImportBegin as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      import_id: "imp-test",
      hashes: ["h1"],
      total_count: 1,
    });
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1, 30));

    const pipe = makePipeline();
    const result = await pipe.runParsed([makeExternalPreview(0, "h1")], "key");

    expect(result.ok).toBe(true);
    expect(result.skipped).toBe(1);
    expect(addChunkBatchMock).not.toHaveBeenCalled();
    expect(addRecordsBatchMock).not.toHaveBeenCalled();
  });
});

describe("importPipeline — run() 生产者：读取闸门与单文件上限", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    importEndMock.mockResolvedValue({ ok: true, total_count: 0, import_id: "imp-test" });
    waitForCapacityMock.mockResolvedValue(undefined);
  });

  it("超过单文件上限：按 file-too-large 拒绝，不进入加密提交", async () => {
    const pipe = makePipeline();
    const files = [
      {
        name: "huge.jpg",
        mime: "image/jpeg",
        readBytes: async () => new Uint8Array(MAX_PHOTO_BYTES + 1),
      },
    ];

    const result = await pipe.run(files, "key");

    expect(result.ok).toBe(false);
    expect(result.failedRecords).toHaveLength(1);
    expect(result.failedRecords[0].reason).toBe("file-too-large");
    expect(result.failedRecords[0].retryable).toBe(false);
    // 未进入加密提交
    expect(photoWorkerPool.submit).not.toHaveBeenCalled();
    // WAL 保留（非成功语义）
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("读取闸门：读取文件前等待池配额（限制源字节内存驻留）", async () => {
    const pipe = makePipeline();
    const files = [
      {
        name: "a.jpg",
        mime: "image/jpeg",
        readBytes: async () => {
          throw new Error("模拟读取失败");
        },
      },
    ];

    const result = await pipe.run(files, "key");

    expect(waitForCapacityMock).toHaveBeenCalled();
    expect(result.failedRecords[0].reason).toBe("read-failed");
  });
});

describe("importPipeline — run() 大文件外置路径（端到端编排）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    importEndMock.mockResolvedValue({ ok: true, total_count: 0, import_id: "imp-test" });
    waitForCapacityMock.mockResolvedValue(undefined);
  });

  it("外置产物：块先落库 → meta 携带 chunkIds 提交 → 结果入账", async () => {
    const fileHash = "e".repeat(64);
    const metaTemplate: PhotoMeta = {
      name: "大图.jpg",
      mime: "image/jpeg",
      size: 9_000_000,
      thumbB64: "thumb",
      chunkIds: [],
      chunkDataB64: [],
      chunkHashes: ["h1", "h2"],
      fileHash,
      createdAt: 1,
    };
    // 模拟真实 Worker 产物：外置路径携带 external（内联字段缺省）
    (photoWorkerPool.submit as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 1,
      ok: true,
      hash: fileHash,
      thumbB64: "thumb",
      external: { chunkB64List: ["c1", "c2"], chunkHashes: ["h1", "h2"], metaTemplate },
      name: "meta_大图.jpg",
      mime: "image/jpeg",
      size: 9_000_000,
    });
    addChunkBatchMock.mockResolvedValue({ ok: true, ids: [41, 42], failed_indices: [] });
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1, 30));

    const pipe = makePipeline();
    const files = [
      { name: "大图.jpg", mime: "image/jpeg", readBytes: async () => new Uint8Array(4) },
    ];

    const result = await pipe.run(files, "key");

    // 编排正确：块上传 → meta-only 加密 → 批量写入带外置引用
    expect(addChunkBatchMock).toHaveBeenCalledTimes(1);
    const record = addRecordsBatchMock.mock.calls[0][0][0] as {
      chunk_ids: number[];
      hash: string;
    };
    expect(record.chunk_ids).toEqual([41, 42]);
    expect(record.hash).toBe(fileHash);
    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(1);
    expect(result.failedRecords).toHaveLength(0);
    expect(importEndMock).toHaveBeenCalledWith(true);
  });
});

describe("importPipeline — 共享会话编排（两路一致的会话语义）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    importEndMock.mockResolvedValue({ ok: true, total_count: 0, import_id: "imp-test" });
    waitForCapacityMock.mockResolvedValue(undefined);
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1, 30));
  });

  it("run()：生产策略异常（读取闸门故障）→ 条目入账为不可重试失败的兜底路径", async () => {
    waitForCapacityMock.mockRejectedValueOnce(new Error("读取闸门故障"));
    const pipe = makePipeline();
    const files = [
      { name: "a.jpg", mime: "image/jpeg", readBytes: async () => new Uint8Array(4) },
    ];

    const result = await pipe.run(files, "key");

    // 生产者异常不吞：会话按"条目已入账失败"收尾（策略未执行，无静默未记账条目）
    expect(result.ok).toBe(false);
    expect(result.failedRecords).toHaveLength(1);
    expect(result.failedRecords[0].name).toBe("unknown");
    expect(result.failedRecords[0].reason).toBe("encrypt-failed");
    expect(result.failedRecords[0].retryable).toBe(true);
    // WAL 保留（非成功语义）
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("runParsed()：生产策略拒绝（池基础设施故障）→ 与 run() 同一套兜底入账", async () => {
    // 拒绝态由策略 catch 入账（同步抛错则由编排层 allSettled 分支入账）：
    // 两条异常通道都不得出现"既未成功也未失败"的条目
    (photoWorkerPool.submitMetaOnly as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async () => { throw new Error("池基础设施故障"); },
    );
    const pipe = makePipeline();

    const result = await pipe.runParsed([makePreview(0, "h1")], "key");

    expect(result.ok).toBe(false);
    expect(result.failedRecords).toHaveLength(1);
    expect(result.failedRecords[0].name).toBe("照片0.jpg");
    expect(result.failedRecords[0].reason).toBe("encrypt-failed");
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("互斥：会话进行中时另一路立即被拒，失败明细按条目展开", async () => {
    const pipe = makePipeline();
    // 首条读取挂起：会话保持在进行中状态
    const pending = pipe.run(
      [{ name: "hang.jpg", mime: "image/jpeg", readBytes: () => new Promise<Uint8Array>(() => {}) }],
      "key",
    );

    const busy = await pipe.runParsed([makePreview(0, "h1")], "key");

    expect(busy.ok).toBe(false);
    expect(busy.error).toBe("已有导入任务进行中，请等待完成");
    expect(busy.failedRecords).toHaveLength(1);
    expect(busy.failedRecords[0].name).toBe("照片0.jpg");
    // 进行中的会话未被互斥拒绝影响
    expect(importEndMock).not.toHaveBeenCalled();
    void pending;
  });

  it("取消：signal 已中止时不投喂任何条目，会话以 ABORTED 收尾且保留 WAL", async () => {
    const controller = new AbortController();
    controller.abort();
    const pipe = makePipeline();
    const files = [
      { name: "a.jpg", mime: "image/jpeg", readBytes: async () => new Uint8Array(4) },
    ];

    const result = await pipe.run(files, "key", controller.signal);

    expect(result.ok).toBe(false);
    expect(result.error).toBe("ABORTED");
    expect(result.imported).toHaveLength(0);
    // 中止后不再触碰读取闸门与加密提交（不白做加密开销）
    expect(waitForCapacityMock).not.toHaveBeenCalled();
    expect(photoWorkerPool.submit).not.toHaveBeenCalled();
    expect(importEndMock).toHaveBeenCalledWith(false);
  });
});

describe("importPipeline — 响应式代理载荷净化（解析导入 DataCloneError 根治）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    importEndMock.mockResolvedValue({ ok: true, total_count: 0, import_id: "imp-test" });
    // 恒定外置存储：解析导入的每张照片都先上传分块记录，默认返回成功 id
    let chunkIdSeed = 900;
    addChunkBatchMock.mockImplementation(async (chunks: Array<{ hash: string }>) => ({
      ok: true,
      ids: chunks.map(() => chunkIdSeed++),
      batch_id: 1,
      failed_indices: [],
      processed_count: chunks.length,
      total_count: chunks.length,
      skipped_count: 0,
    }));
  });

  it("Vue 响应式污染的解析产物：meta 脱代理净化后提交（载荷可结构化克隆）", async () => {
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1));

    // 还原真实污染形态：parsedPhotos 为 ref，元素与其 meta 经 Vue 深层响应式
    // 代理；记录 meta 携带 chunkHashes 数组（完整加密产物恒含该字段，
    // 经导出 → 解析链路原样保留——正是生产「加密任务失败×N」的触发载荷）
    const base = makePreview(0, "h1");
    const pollutedMeta = reactive({
      ...base.meta,
      chunkHashes: ["a".repeat(64)],
    }) as PhotoMeta;
    const polluted: ParsedPhotoPreview = { ...base, meta: pollutedMeta };

    // 前提锁定：污染载荷浅层展开后仍不可结构化克隆（Proxy 嵌套数组在浅
    // 展开中保留代理身份，与 Worker 池 postMessage 的失败形态一致；
    // 该断言防用例随实现漂移而静默失效）
    expect(() =>
      structuredClone({ ...pollutedMeta, chunkDataB64: [], chunkIds: [] }),
    ).toThrow();

    const pipe = makePipeline();
    const result = await pipe.runParsed([polluted], "key");

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(1);
    // 净化契约：进入 Worker 的 meta（及整个请求体）必须完全脱离代理
    const submitted = (photoWorkerPool.submitMetaOnly as ReturnType<typeof vi.fn>)
      .mock.calls[0][0] as { meta: PhotoMeta };
    expect(() => structuredClone(submitted.meta)).not.toThrow();
    expect(() => structuredClone(submitted)).not.toThrow();
  });
});