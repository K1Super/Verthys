/**
 * photo-decrypt-bridge.spec.ts — 读取侧解密桥策略测试
 *
 * 覆盖：
 * - Worker 池成功：直接返回产物，主线程不执行解密（不下沉就失去意义）
 * - Worker 明确拒绝（TaskRejectedError）：确定性失败，不回退主线程
 * - 池基础设施失败（超时/毒丸/已终止）：回退主线程实现并返回一致结果
 * - 回退路径失败：向上抛出原始错误（不吞异常、不伪造成功）
 * - 数据块路径：明文以视图返回且顺序与输入一致；池故障时逐块回退
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { PhotoMeta } from "../types/crypto";

vi.mock("./photoWorkerPool", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./photoWorkerPool")>();
  return {
    ...actual,
    photoWorkerPool: {
      submitDecryptMeta: vi.fn(),
      submitDecryptChunks: vi.fn(),
    },
  };
});

vi.mock("../lib/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/crypto")>();
  return {
    ...actual,
    decryptMeta: vi.fn(),
    decryptChunk: vi.fn(),
  };
});

import { photoWorkerPool, TaskRejectedError, TaskTimeoutError } from "./photoWorkerPool";
import { decryptMeta, decryptChunk } from "../lib/crypto";
import { decryptMetaPreferWorker, decryptChunksPreferWorker } from "./photo-decrypt-bridge";

/** 构造完整元数据（字段齐备，避免类型断言掩盖字段缺失） */
function makeMeta(name = "a.jpg"): PhotoMeta {
  return {
    name,
    mime: "image/jpeg",
    size: 3,
    thumbB64: "thumb",
    chunkIds: [11, 12],
    chunkHashes: ["h1", "h2"],
    fileHash: "f".repeat(64),
    createdAt: 1,
  };
}

describe("decryptMetaPreferWorker — Worker 优先与回退策略", () => {
  beforeEach(() => {
    // 重置（而非仅清空调用记录）：避免上一用例的 mock 实现泄漏到下一用例
    vi.resetAllMocks();
  });

  it("池成功：返回解密结果，主线程不执行解密", async () => {
    const meta = makeMeta();
    vi.mocked(photoWorkerPool.submitDecryptMeta).mockResolvedValue({ id: 1, ok: true, meta });

    await expect(decryptMetaPreferWorker("meta-b64", "key", "42")).resolves.toEqual({ meta });
    expect(photoWorkerPool.submitDecryptMeta).toHaveBeenCalledWith({
      metaB64: "meta-b64",
      photoKey: "key",
      label: "42",
      thumbCipherB64: undefined,
    });
    expect(decryptMeta).not.toHaveBeenCalled();
  });

  it("索引瘦身布局：缩略图明文随元数据结果一并返回", async () => {
    const meta = makeMeta();
    const thumbBytes = new Uint8Array([0xff, 0xd8, 0xff]).buffer;
    vi.mocked(photoWorkerPool.submitDecryptMeta).mockResolvedValue({
      id: 1, ok: true, meta, thumbBytes,
    });

    await expect(
      decryptMetaPreferWorker("meta-b64", "key", "42", "thumb-cipher"),
    ).resolves.toEqual({ meta, thumbBytes });
    expect(photoWorkerPool.submitDecryptMeta).toHaveBeenCalledWith({
      metaB64: "meta-b64",
      photoKey: "key",
      label: "42",
      thumbCipherB64: "thumb-cipher",
    });
  });

  it("Worker 明确拒绝：确定性失败直接抛出，不回退主线程", async () => {
    const rejection = new TaskRejectedError(1, "元数据标签校验失败");
    vi.mocked(photoWorkerPool.submitDecryptMeta).mockRejectedValue(rejection);

    await expect(decryptMetaPreferWorker("meta-b64", "key", "42")).rejects.toBe(rejection);
    expect(decryptMeta).not.toHaveBeenCalled();
  });

  it("池基础设施失败（超时）：回退主线程并返回结果", async () => {
    vi.mocked(photoWorkerPool.submitDecryptMeta).mockRejectedValue(new TaskTimeoutError(1, 60_000));
    const meta = makeMeta("fallback.jpg");
    vi.mocked(decryptMeta).mockResolvedValue(meta);

    await expect(decryptMetaPreferWorker("meta-b64", "key", "42")).resolves.toEqual({ meta });
    expect(decryptMeta).toHaveBeenCalledWith("meta-b64", "key");
  });

  it("回退路径失败：抛出主线程原始错误（不吞异常）", async () => {
    vi.mocked(photoWorkerPool.submitDecryptMeta).mockRejectedValue(new TaskTimeoutError(2, 60_000));
    const fallbackError = new Error("元数据密文过短");
    vi.mocked(decryptMeta).mockRejectedValue(fallbackError);

    await expect(decryptMetaPreferWorker("meta-b64", "key", "42")).rejects.toBe(fallbackError);
  });
});

describe("decryptChunksPreferWorker — Worker 优先与回退策略", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("池成功：明文以视图返回且顺序与输入一致", async () => {
    const first = new Uint8Array([1, 2]).buffer;
    const second = new Uint8Array([3]).buffer;
    vi.mocked(photoWorkerPool.submitDecryptChunks).mockResolvedValue({
      id: 5,
      ok: true,
      plaintexts: [first, second],
    });

    const result = await decryptChunksPreferWorker(["c1", "c2"], "key", "f".repeat(64), "a.jpg");
    expect(result).toHaveLength(2);
    expect(Array.from(result[0])).toEqual([1, 2]);
    expect(Array.from(result[1])).toEqual([3]);
    expect(photoWorkerPool.submitDecryptChunks).toHaveBeenCalledWith({
      chunksB64: ["c1", "c2"],
      photoKey: "key",
      fileHashHex: "f".repeat(64),
      label: "a.jpg",
    });
    expect(decryptChunk).not.toHaveBeenCalled();
  });

  it("Worker 明确拒绝：不回退主线程", async () => {
    const rejection = new TaskRejectedError(5, "第 1/2 块解密失败: 标签校验失败");
    vi.mocked(photoWorkerPool.submitDecryptChunks).mockRejectedValue(rejection);

    await expect(
      decryptChunksPreferWorker(["c1", "c2"], "key", "f".repeat(64), "a.jpg"),
    ).rejects.toBe(rejection);
    expect(decryptChunk).not.toHaveBeenCalled();
  });

  it("池基础设施失败：回退主线程逐块解密", async () => {
    vi.mocked(photoWorkerPool.submitDecryptChunks).mockRejectedValue(new TaskTimeoutError(5, 60_000));
    vi.mocked(decryptChunk)
      .mockResolvedValueOnce({ plaintext: new Uint8Array([7]), seq: 0, total: 2 })
      .mockResolvedValueOnce({ plaintext: new Uint8Array([8, 9]), seq: 1, total: 2 });

    const result = await decryptChunksPreferWorker(["c1", "c2"], "key", "f".repeat(64), "a.jpg");
    expect(result.map((p) => Array.from(p))).toEqual([[7], [8, 9]]);
    expect(decryptChunk).toHaveBeenCalledTimes(2);
    expect(decryptChunk).toHaveBeenNthCalledWith(1, "c1", "key", "f".repeat(64));
  });

  it("回退路径任一块失败：整体失败并携带块序号", async () => {
    vi.mocked(photoWorkerPool.submitDecryptChunks).mockRejectedValue(new TaskTimeoutError(6, 60_000));
    vi.mocked(decryptChunk)
      .mockResolvedValueOnce({ plaintext: new Uint8Array([7]), seq: 0, total: 2 })
      .mockRejectedValueOnce(new Error("标签校验失败"));

    await expect(
      decryptChunksPreferWorker(["c1", "c2"], "key", "f".repeat(64), "a.jpg"),
    ).rejects.toThrow("第 2/2 块解密失败: 标签校验失败");
  });

  it("回退路径块自描述位置与列表不符：拼接前拒绝（与 Worker 路径同一判定）", async () => {
    vi.mocked(photoWorkerPool.submitDecryptChunks).mockRejectedValue(new TaskTimeoutError(7, 60_000));
    // 两块密文彼此自洽（seq/total 连续），但声明总数 3 与列表长度 2 不符：
    // 属被截断的列表，必须在拼接前拒绝而非产出错误顺序的整图
    vi.mocked(decryptChunk)
      .mockResolvedValueOnce({ plaintext: new Uint8Array([7]), seq: 0, total: 3 })
      .mockResolvedValueOnce({ plaintext: new Uint8Array([8]), seq: 1, total: 3 });

    await expect(
      decryptChunksPreferWorker(["c1", "c2"], "key", "f".repeat(64), "a.jpg"),
    ).rejects.toThrow("第 1/2 块解密失败: 数据块顺序校验失败");
  });

  it("回退路径保持同等校验标准：逐块哈希不符即拒绝（不进入解密）", async () => {
    vi.mocked(photoWorkerPool.submitDecryptChunks).mockRejectedValue(new TaskTimeoutError(8, 60_000));

    await expect(
      decryptChunksPreferWorker(
        ["Y2g=", "ZGU="], "key", "f".repeat(64), "a.jpg", undefined,
        { expectedHashes: ["0".repeat(64), "0".repeat(64)] },
      ),
    ).rejects.toThrow("块密文哈希校验失败");
    expect(decryptChunk).not.toHaveBeenCalled();
  });
});