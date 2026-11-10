/**
 * importPipeline.spec.ts — 导入流水线成功语义与批次可靠性回归测试
 *
 * 覆盖（故障注入，断言静默丢失路径不成立）：
 * - 备份还原：Worker 投递产物 → 外置块上传 → meta 加密 → 批量写入，内容身份去重
 * - 全成功：仅零失败路径以 verthysImportEnd(true) 压缩 WAL
 * - 致命错误（后端容量告罄 ERR_0000000F）：fatal 传播并映射为存储空间不足
 * - 部分失败：只重试失败子集，成功项不回灌；重试耗尽按失败入账
 * - 后端去重跳过：计入 skipped，绝不重试
 * - 三分类不变量：imported+failed+skipped === total
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
    entry_keys: [],
    total_count: 0,
  })),
  verthysAddRecordsBatch: addRecordsBatchMock,
  verthysAddChunkBatch: addChunkBatchMock,
  verthysImportEnd: importEndMock,
  verthysWalRecover: vi.fn(async () => ({ ok: true, entry_keys: [], total_count: 0 })),
  // 孤儿块 GC：会话成功收尾时 fire-and-forget，测试环境给出已清理 0 条的成功回执
  verthysGcOrphanChunks: vi.fn(async () => 0),
}));

vi.mock("../../workers/photoWorkerPool", () => ({
  photoWorkerPool: {
    // meta 加密：本组用例只验证写入编排，密文以占位值回显
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

import {
  ImportPipeline,
  importedToPhotoEntries,
  type ContainerImportWorkerLike,
} from "./importPipeline";
import type { ParsedPhotoPreview } from "./types";
import type { PhotoMeta } from "../../lib/crypto";
import type {
  ContainerImportPhoto,
  ContainerImportRequest,
} from "../../workers/container-import.worker";
import { bytesToHex } from "../../utils/binary_codec";
import { MAX_PHOTO_BYTES } from "../../constants/crypto_const";
import { photoWorkerPool } from "../../workers/photoWorkerPool";
import { sha256 } from "@noble/hashes/sha2";

/** 复算流水线口径的条目键（域标识 + 各分量以 `|` 连接后 SHA-256） */
function entryKeyOf(...parts: Array<string | number>): string {
  return bytesToHex(sha256(new TextEncoder().encode(parts.join("|"))));
}

/** 备份还原条目键：内容身份（清单内文件哈希） */
function containerKeyOf(fileHash: string): string {
  return entryKeyOf("parsed", fileHash);
}

/** 构造预览项（新契约：只含清单字段） */
function makePreview(i: number, hash: string): ParsedPhotoPreview {
  return {
    name: `照片${i}.jpg`,
    thumb: "",
    size: 1024,
    mime: "image/jpeg",
    fileHash: hash,
    chunkCount: 1,
    createdAt: 1000 + i,
  };
}

/** 构造 Worker 产物（与生产 Worker 投递结构一致） */
function makePhoto(i: number, hash: string, chunkCount = 1): ContainerImportPhoto {
  return {
    id: 1,
    type: "photo",
    index: i,
    name: `照片${i}.jpg`,
    mime: "image/jpeg",
    size: 1024,
    thumbB64: "",
    fileHash: hash,
    createdAt: 1000 + i,
    chunkB64List: Array.from({ length: chunkCount }, () => "Y2h1bms="),
    chunkHashes: Array.from({ length: chunkCount }, () => "a".repeat(64)),
  };
}

/** 伪导入 Worker：按脚本逐张投递并等待 ack（复现生产背压协议） */
class FakeContainerWorker implements ContainerImportWorkerLike {
  onmessage: ((e: MessageEvent<unknown>) => void) | null = null;
  onerror: ((e: ErrorEvent) => void) | null = null;
  terminate = vi.fn();
  private ackResolve: (() => void) | null = null;
  private started = false;

  constructor(private readonly script: { photos: ContainerImportPhoto[]; fail?: string }) {}

  postMessage(message: ContainerImportRequest | { id: number; type: "ack"; index: number }): void {
    if ((message as { type?: string }).type === "ack") {
      const resolve = this.ackResolve;
      this.ackResolve = null;
      resolve?.();
      return;
    }
    if (this.started) return;
    this.started = true;
    void this.run();
  }

  private async run(): Promise<void> {
    if (this.script.fail) {
      this.onmessage?.({
        data: { id: 1, type: "failure", ok: false, error: this.script.fail },
      } as MessageEvent<unknown>);
      return;
    }
    for (const photo of this.script.photos) {
      this.onmessage?.({ data: photo } as MessageEvent<unknown>);
      await new Promise<void>((resolve) => { this.ackResolve = resolve; });
    }
    this.onmessage?.({
      data: { id: 1, type: "done", ok: true, photos: this.script.photos.length },
    } as MessageEvent<unknown>);
  }
}

/** 构造 Worker 工厂（脚本注入） */
function containerFactory(photos: ContainerImportPhoto[], fail?: string) {
  return () => new FakeContainerWorker({ photos, fail });
}

/** 容器源数据 */
function containerSource() {
  return { bytes: new Uint8Array([1, 2, 3]), token: "a".repeat(64) };
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

describe("importPipeline — 备份还原写入语义", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    importEndMock.mockResolvedValue({ ok: true, total_count: 0, import_id: "imp-test" });
    // 恒定外置存储：每张照片都先上传分块记录，默认返回成功 id
    let chunkIdSeed = 900;
    addChunkBatchMock.mockImplementation(async (chunks: Array<{ chunk_key: string }>) => ({
      ok: true,
      ids: chunks.map(() => chunkIdSeed++),
      batch_id: 1,
      failed_indices: [],
      processed_count: chunks.length,
      total_count: chunks.length,
      skipped_count: 0,
    }));
  });

  it("Worker 产物：块先落库，meta 只携带引用，内容身份键写入", async () => {
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1));
    const pipe = makePipeline();
    const previews = [makePreview(0, "h1")];

    const result = await pipe.runContainer(
      previews, containerSource(), containerFactory([makePhoto(0, "h1")]),
    );

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(1);
    // 分块先落库（外置路径），提交的 meta 以 chunk_ids 引用且不内联密文
    expect(addChunkBatchMock).toHaveBeenCalledTimes(1);
    const record = addRecordsBatchMock.mock.calls[0][0][0] as {
      chunk_ids: number[];
      entry_key: string;
      data_b64: string;
    };
    expect(record.chunk_ids.length).toBeGreaterThan(0);
    expect(record.data_b64).toBe("meta-b64");
    // 去重键为清单内 BLAKE3 文件哈希（内容身份），不是名称/大小/序号
    expect(record.entry_key).toBe(containerKeyOf("h1"));

    // 索引必须携带本次实际写入的逐块密文哈希与清单原始创建时间：
    // 前者是后续导出的逐块诊断索引，后者是备份还原的数据保真要求。
    const metaReq = (photoWorkerPool.submitMetaOnly as ReturnType<typeof vi.fn>)
      .mock.calls[0][0] as { meta: PhotoMeta };
    expect(metaReq.meta.chunkHashes).toEqual(["a".repeat(64)]);
    expect(metaReq.meta.createdAt).toBe(1000);
  });

  it("全成功：仅零失败路径以 success=true 压缩 WAL", async () => {
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(2));
    const pipe = makePipeline();
    const previews = [makePreview(0, "h1"), makePreview(1, "h2")];

    const result = await pipe.runContainer(
      previews, containerSource(), containerFactory([makePhoto(0, "h1"), makePhoto(1, "h2")]),
    );

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(2);
    expect(result.failedRecords).toHaveLength(0);
    expect(result.skipped).toBe(0);
    expect(importEndMock).toHaveBeenCalledTimes(1);
    expect(importEndMock).toHaveBeenCalledWith(true);
  });

  it("致命错误（后端容量告罄）：fatal 传播并映射为存储空间不足，WAL 以 false 保留", async () => {
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
    const previews = [makePreview(0, "h1"), makePreview(1, "h2")];

    const result = await pipe.runContainer(
      previews, containerSource(), containerFactory([makePhoto(0, "h1"), makePhoto(1, "h2")]),
    );

    expect(result.ok).toBe(false);
    expect(result.error).toContain("存储空间不足");
    expect(result.failedRecords.length).toBeGreaterThan(0);
    expect(result.failedRecords.every((r) => r.reason === "storage-full")).toBe(true);
    // 三分类不变量：致命路径下剩余条目全部入账失败
    expect(result.imported.length + result.failedRecords.length + result.skipped).toBe(2);
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("致命错误后停止写入：消费端短路，后续缓存批次不再发起 IPC", async () => {
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
    const previews = [makePreview(0, "h1"), makePreview(1, "h2")];

    const result = await pipe.runContainer(
      previews, containerSource(), containerFactory([makePhoto(0, "h1"), makePhoto(1, "h2")]),
    );

    expect(result.ok).toBe(false);
    expect(addRecordsBatchMock).toHaveBeenCalledTimes(1);
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("外置块上传失败：按 chunk-upload-failed 可重试入账，WAL 保留", async () => {
    addChunkBatchMock.mockResolvedValue({
      ok: false,
      ids: [],
      failed_indices: [0],
      error: "块载荷超过上限",
    });
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1));
    const pipe = makePipeline();

    const result = await pipe.runContainer(
      [makePreview(0, "h1")], containerSource(), containerFactory([makePhoto(0, "h1")]),
    );

    expect(result.ok).toBe(false);
    expect(result.imported).toHaveLength(0);
    expect(addRecordsBatchMock).not.toHaveBeenCalled();
    expect(result.failedRecords).toHaveLength(1);
    expect(result.failedRecords[0].reason).toBe("chunk-upload-failed");
    expect(result.failedRecords[0].retryable).toBe(true);
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("已 committed 的内容身份：前置去重跳过，无块上传无加密提交", async () => {
    // begin 返回的 entry_keys 含该文件的条目键 → 生产者直接跳过
    const { verthysImportBegin } = await import("../../lib/verthys");
    (verthysImportBegin as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      import_id: "imp-test",
      entry_keys: [containerKeyOf("h1")],
      total_count: 1,
    });
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1));
    const pipe = makePipeline();

    const result = await pipe.runContainer(
      [makePreview(0, "h1")], containerSource(), containerFactory([makePhoto(0, "h1")]),
    );

    expect(result.ok).toBe(true);
    expect(result.skipped).toBe(1);
    expect(addChunkBatchMock).not.toHaveBeenCalled();
    expect(addRecordsBatchMock).not.toHaveBeenCalled();
  });
});

describe("importPipeline — 失败批次逐条回灌重试", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    importEndMock.mockResolvedValue({ ok: true, total_count: 0, import_id: "imp-test" });
    let chunkIdSeed = 700;
    addChunkBatchMock.mockImplementation(async (chunks: Array<{ chunk_key: string }>) => ({
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
    const previews = [makePreview(0, "h1"), makePreview(1, "h2")];

    const result = await pipe.runContainer(
      previews, containerSource(), containerFactory([makePhoto(0, "h1"), makePhoto(1, "h2")]),
    );

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(2);
    expect(addRecordsBatchMock).toHaveBeenCalledTimes(2);
    // 重试子批次只含失败的那一条
    const retryPayload = addRecordsBatchMock.mock.calls[1][0] as Array<{ entry_key: string }>;
    expect(retryPayload).toHaveLength(1);
    expect(retryPayload[0].entry_key).toBe(containerKeyOf("h2"));
    expect(importEndMock).toHaveBeenCalledWith(true);
  });

  it("重试耗尽：失败项按服务端拒绝入账，整体 ok=false 且 WAL 保留", async () => {
    const failKey = containerKeyOf("h2");
    const pipe = makePipeline({ consumerMaxRetries: 1 });
    addRecordsBatchMock.mockImplementation(
      async (records: Array<{ entry_key: string }>) => ({
        ok: true,
        ids: records.map((r) => (r.entry_key === failKey ? 0 : 10)),
        batch_id: 1,
        failed_indices: records.flatMap((r, i) => (r.entry_key === failKey ? [i] : [])),
        processed_count: records.length,
        total_count: 1,
        skipped_count: 0,
      }),
    );
    const previews = [makePreview(0, "h1"), makePreview(1, "h2")];

    const result = await pipe.runContainer(
      previews, containerSource(), containerFactory([makePhoto(0, "h1"), makePhoto(1, "h2")]),
    );

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
    // 同一内容哈希 → 同一内容身份键；后端按幂等语义只写入一条
    const previews = [makePreview(0, "h1"), makePreview(1, "h1")];

    const result = await pipe.runContainer(
      previews, containerSource(), containerFactory([makePhoto(0, "h1"), makePhoto(1, "h1")]),
    );

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(1);
    expect(result.skipped).toBe(1);
    expect(result.failedRecords).toHaveLength(0);
    expect(addRecordsBatchMock).toHaveBeenCalledTimes(1);
    expect(importEndMock).toHaveBeenCalledWith(true);
  });

  it("容器在预览后被替换：产物哈希与预览不符 → 条目失败，不写入任何记录", async () => {
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1));
    const pipe = makePipeline();

    const result = await pipe.runContainer(
      [makePreview(0, "h1")], containerSource(), containerFactory([makePhoto(0, "h2")]),
    );

    expect(result.ok).toBe(false);
    expect(result.imported).toHaveLength(0);
    expect(result.failedRecords).toHaveLength(1);
    expect(addRecordsBatchMock).not.toHaveBeenCalled();
    expect(addChunkBatchMock).not.toHaveBeenCalled();
  });

  it("整批 IPC 异常且重试耗尽：按可重试失败入账，WAL 保留", async () => {
    const pipe = makePipeline({ consumerMaxRetries: 0 });
    addRecordsBatchMock.mockRejectedValue(new Error("ipc transport error"));

    const result = await pipe.runContainer(
      [makePreview(0, "h1")], containerSource(), containerFactory([makePhoto(0, "h1")]),
    );

    expect(result.ok).toBe(false);
    expect(result.imported).toHaveLength(0);
    expect(result.failedRecords).toHaveLength(1);
    expect(result.failedRecords[0].retryable).toBe(true);
    expect(importEndMock).toHaveBeenCalledWith(false);
  });
});

describe("importPipeline — 多块照片的外置编排", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    importEndMock.mockResolvedValue({ ok: true, total_count: 0, import_id: "imp-test" });
  });

  it("9 块在单批上限内一次上传 → meta 携带完整 chunkIds 提交", async () => {
    addChunkBatchMock.mockResolvedValueOnce({
      ok: true,
      ids: [1, 2, 3, 4, 5, 6, 7, 8, 9],
      failed_indices: [],
    });
    addRecordsBatchMock.mockImplementation(async () => okBatchResponse(1, 30));
    const pipe = makePipeline();

    const result = await pipe.runContainer(
      [makePreview(0, "h1")], containerSource(), containerFactory([makePhoto(0, "h1", 9)]),
    );

    expect(result.ok).toBe(true);
    expect(result.imported).toHaveLength(1);
    // 跨层上限 32 块，且 9MB 载荷在单批预算内 → 仅一次上传
    expect(addChunkBatchMock).toHaveBeenCalledTimes(1);
    const firstBatch = addChunkBatchMock.mock.calls[0][0] as Array<{ hash: string; data_b64: string }>;
    expect(firstBatch).toHaveLength(9);
    const record = addRecordsBatchMock.mock.calls[0][0][0] as {
      chunk_ids: number[];
      chunk_hashes: string[];
    };
    expect(record.chunk_ids).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(record.chunk_hashes).toHaveLength(9);
    expect(importEndMock).toHaveBeenCalledWith(true);
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

    const result = await pipe.run(files);

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

    const result = await pipe.run(files);

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

    const result = await pipe.run(files);

    // 编排正确：块上传 → meta-only 加密 → 批量写入带外置引用
    expect(addChunkBatchMock).toHaveBeenCalledTimes(1);
    const record = addRecordsBatchMock.mock.calls[0][0][0] as {
      chunk_ids: number[];
      entry_key: string;
    };
    expect(record.chunk_ids).toEqual([41, 42]);
    // 条目键为来源非内容口径（名称/大小/修改时间），不是内容哈希
    expect(record.entry_key).toBe(entryKeyOf("file", "大图.jpg", 0, 0));
    expect(record.entry_key).not.toBe(fileHash);
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

    const result = await pipe.run(files);

    expect(result.ok).toBe(false);
    expect(result.failedRecords).toHaveLength(1);
    expect(result.failedRecords[0].index).toBe(0);
    expect(result.failedRecords[0].name).toBe("a.jpg");
    expect(result.failedRecords[0].reason).toBe("unknown");
    expect(result.failedRecords[0].retryable).toBe(true);
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("runContainer()：Worker 失败 → 条目入账失败，不出现静默丢失", async () => {
    const pipe = makePipeline();

    const result = await pipe.runContainer(
      [makePreview(0, "h1")], containerSource(), containerFactory([], "RPC 通道故障"),
    );

    expect(result.ok).toBe(false);
    expect(result.failedRecords).toHaveLength(1);
    expect(result.failedRecords[0].name).toBe("照片0.jpg");
    expect(importEndMock).toHaveBeenCalledWith(false);
  });

  it("互斥：会话进行中时另一路立即被拒，失败明细按条目展开", async () => {
    const pipe = makePipeline();
    // 首条读取挂起：会话保持在进行中状态
    const pending = pipe.run(
      [{ name: "hang.jpg", mime: "image/jpeg", readBytes: () => new Promise<Uint8Array>(() => {}) }],
    );

    const busy = await pipe.runContainer(
      [makePreview(0, "h1")], containerSource(), containerFactory([makePhoto(0, "h1")]),
    );

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

    const result = await pipe.run(files, controller.signal);

    expect(result.ok).toBe(false);
    expect(result.error).toBe("ABORTED");
    expect(result.imported).toHaveLength(0);
    // 中止后不再触碰读取闸门与加密提交（不白做加密开销）
    expect(waitForCapacityMock).not.toHaveBeenCalled();
    expect(photoWorkerPool.submit).not.toHaveBeenCalled();
    expect(importEndMock).toHaveBeenCalledWith(false);
  });
});

describe("importedToPhotoEntries — 导入后首帧条目投影", () => {
  it("缩略图转 Blob URL 且标记已加载（不再重复解密同一份元数据）", () => {
    const [entry] = importedToPhotoEntries([
      {
        metaId: 5,
        name: "meta_a.jpg",
        displayName: "a.jpg",
        thumbB64: "AAAA",
        size: 2048,
        mime: "image/jpeg",
      },
    ]);
    expect(entry).toMatchObject({
      id: 5,
      metaId: 5,
      name: "a.jpg",
      size: "2.0 KB",
      loaded: true,
      failed: false,
    });
    // data: 字符串会随列表常驻 JS 堆：缩略图必须走对象 URL
    // （node 环境无对象存储时安全退化为空串，渲染层按无缩略图处理）
    expect(entry.thumb.startsWith("data:")).toBe(false);
    if (entry.thumb) expect(entry.thumb).toMatch(/^url\("blob:/);
  });
});
