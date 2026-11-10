/**
 * photo-decrypt-bridge.spec.ts — 读取侧解密桥策略测试
 *
 * 覆盖：
 * - Worker 池成功：直接返回产物，主线程不发起 Tauri 调用
 * - 池基础设施失败：回退到主线程直连同一组 module 命令
 * - Worker 明确拒绝：确定性失败直接上抛，不回退主线程重算
 * - 直连失败：向上抛出原始错误（不吞异常、不伪造成功）
 * - 数据块路径：明文以视图返回且顺序与输入一致；池故障时逐块直连
 * - 完整性校验：整图明文哈希为权威值；逐块密文哈希失配仅在无整图哈希时拒绝
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { blake3 } from "@noble/hashes/blake3";
import type { PhotoMeta } from "../types/crypto";
import { bytesToBase64, bytesToHex } from "../utils/binary_codec";

vi.mock("./photoWorkerPool", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./photoWorkerPool")>();
  return {
    ...actual,
    photoWorkerPool: {
      submitDecryptMeta: vi.fn(),
      submitDecryptThumb: vi.fn(),
      submitDecryptSlimSet: vi.fn(),
      submitDecryptChunks: vi.fn(),
    },
  };
});

vi.mock("../lib/module_crypto", () => ({
  openRecord: vi.fn(),
}));

import { photoWorkerPool, TaskRejectedError, TaskTimeoutError } from "./photoWorkerPool";
import { openRecord } from "../lib/module_crypto";
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

function metaB64(meta: PhotoMeta): string {
  return bytesToBase64(new TextEncoder().encode(JSON.stringify(meta)));
}

describe("decryptMetaPreferWorker — Worker 优先与回退策略", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("池成功：返回解密结果，主线程不发起直连调用", async () => {
    const meta = makeMeta();
    vi.mocked(photoWorkerPool.submitDecryptMeta).mockResolvedValue({ id: 1, ok: true, meta });

    await expect(decryptMetaPreferWorker("meta-b64", "42")).resolves.toEqual({ meta });
    expect(photoWorkerPool.submitDecryptMeta).toHaveBeenCalledWith({
      metaB64: "meta-b64",
      label: "42",
    });
    expect(openRecord).not.toHaveBeenCalled();
  });

  it("池基础设施失败：主线程直连同一命令并解析元数据", async () => {
    vi.mocked(photoWorkerPool.submitDecryptMeta).mockRejectedValue(new TaskTimeoutError(1, 60_000));
    const meta = makeMeta("fallback.jpg");
    vi.mocked(openRecord).mockResolvedValue({ dataB64: metaB64(meta) });

    await expect(decryptMetaPreferWorker("meta-b64", "42")).resolves.toEqual({ meta });
    expect(openRecord).toHaveBeenCalledWith("photo", "meta", "meta-b64");
  });

  it("Worker 明确拒绝：确定性失败直接上抛，不回退主线程重算", async () => {
    const rejected = new TaskRejectedError(7, "标签校验失败");
    vi.mocked(photoWorkerPool.submitDecryptMeta).mockRejectedValue(rejected);

    await expect(decryptMetaPreferWorker("meta-b64", "42")).rejects.toBe(rejected);
    expect(openRecord).not.toHaveBeenCalled();
  });

  it("直连失败：抛出原始错误（不吞异常）", async () => {
    vi.mocked(photoWorkerPool.submitDecryptMeta).mockRejectedValue(new TaskTimeoutError(2, 60_000));
    const fallbackError = new Error("元数据密文过短");
    vi.mocked(openRecord).mockRejectedValue(fallbackError);

    await expect(decryptMetaPreferWorker("meta-b64", "42")).rejects.toBe(fallbackError);
  });

  it("瘦身布局缩略图：元数据解密后按包裹态密钥直连/池解密", async () => {
    const meta = { ...makeMeta(), fmt: 2, wrappedFileKey: "wrapped", thumbId: 9 };
    vi.mocked(photoWorkerPool.submitDecryptMeta).mockResolvedValue({ id: 1, ok: true, meta });
    const thumbBytes = new Uint8Array([0xff, 0xd8, 0xff]).buffer;
    vi.mocked(photoWorkerPool.submitDecryptThumb).mockResolvedValue({
      id: 2, ok: true, thumbBytes,
    });

    const outcome = await decryptMetaPreferWorker("meta-b64", "42", "thumb-cipher");
    expect(Array.from(new Uint8Array(outcome.thumbBytes!))).toEqual([0xff, 0xd8, 0xff]);
    expect(photoWorkerPool.submitDecryptThumb).toHaveBeenCalledWith({
      thumbCipherB64: "thumb-cipher",
      wrappedFileKey: "wrapped",
      fileHashHex: meta.fileHash,
      label: "42:thumb",
    });
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

    const result = await decryptChunksPreferWorker(["c1", "c2"], "f".repeat(64), "a.jpg");
    expect(result.map((p) => Array.from(p))).toEqual([[1, 2], [3]]);
    expect(photoWorkerPool.submitDecryptChunks).toHaveBeenCalledWith({
      chunksB64: ["c1", "c2"],
      fileHashHex: "f".repeat(64),
      label: "a.jpg",
    });
    expect(openRecord).not.toHaveBeenCalled();
  });

  it("池失败：逐块直连同一命令并校验位置", async () => {
    vi.mocked(photoWorkerPool.submitDecryptChunks).mockRejectedValue(new TaskTimeoutError(5, 60_000));
    vi.mocked(openRecord)
      .mockResolvedValueOnce({ dataB64: "Bw==", seq: 0, total: 2 })
      .mockResolvedValueOnce({ dataB64: "CAk=", seq: 1, total: 2 });

    const result = await decryptChunksPreferWorker(["c1", "c2"], "f".repeat(64), "a.jpg");
    expect(result.map((p) => Array.from(p))).toEqual([[7], [8, 9]]);
    expect(openRecord).toHaveBeenNthCalledWith(1, "photo", "chunk", "c1", {
      fileHash: "f".repeat(64),
    });
  });

  it("直连位置与列表不符：拼接前拒绝", async () => {
    vi.mocked(photoWorkerPool.submitDecryptChunks).mockRejectedValue(new TaskTimeoutError(6, 60_000));
    vi.mocked(openRecord)
      .mockResolvedValueOnce({ dataB64: "Bw==", seq: 0, total: 3 })
      .mockResolvedValueOnce({ dataB64: "CA==", seq: 1, total: 3 });

    await expect(
      decryptChunksPreferWorker(["c1", "c2"], "f".repeat(64), "a.jpg"),
    ).rejects.toThrow("数据块顺序校验失败");
  });

  it("直连路径：哈希失配但整图哈希匹配 -> 接受（轮换兼容）", async () => {
    vi.mocked(photoWorkerPool.submitDecryptChunks).mockRejectedValue(new TaskTimeoutError(8, 60_000));
    vi.mocked(openRecord)
      .mockResolvedValueOnce({ dataB64: "Bw==", seq: 0, total: 2 })
      .mockResolvedValueOnce({ dataB64: "CA==", seq: 1, total: 2 });
    const fileHash = bytesToHex(
      blake3(new Uint8Array([7, 8]), { dkLen: 32 }),
    );

    const result = await decryptChunksPreferWorker(
      ["Y2g=", "ZGU="], fileHash, "a.jpg", undefined,
      {
        expectedHashes: ["0".repeat(64), "0".repeat(64)],
        expectedFileHash: fileHash,
      },
    );

    expect(result.map((p) => Array.from(p))).toEqual([[7], [8]]);
    expect(openRecord).toHaveBeenCalledTimes(2);
  });

  it("直连路径：哈希失配且无整图哈希 -> 拒绝", async () => {
    vi.mocked(photoWorkerPool.submitDecryptChunks).mockRejectedValue(new TaskTimeoutError(9, 60_000));
    vi.mocked(openRecord)
      .mockResolvedValueOnce({ dataB64: "Bw==", seq: 0, total: 2 })
      .mockResolvedValueOnce({ dataB64: "CA==", seq: 1, total: 2 });

    await expect(
      decryptChunksPreferWorker(
        ["Y2g=", "ZGU="], "f".repeat(64), "a.jpg", undefined,
        { expectedHashes: ["0".repeat(64), "0".repeat(64)] },
      ),
    ).rejects.toThrow("块密文哈希校验失败");
    // 哈希只是诊断信号：AEAD 解密已执行，最终因缺少整图哈希权威值拒绝
    expect(openRecord).toHaveBeenCalledTimes(2);
  });

  it("瘦身布局：解密请求携带包裹态密钥而非句柄", async () => {
    vi.mocked(photoWorkerPool.submitDecryptChunks).mockRejectedValue(new TaskTimeoutError(9, 60_000));
    vi.mocked(openRecord).mockResolvedValue({ dataB64: "Bw==" });

    const result = await decryptChunksPreferWorker(
      ["c1"], "f".repeat(64), "a.jpg",
      { wrappedFileKey: "wrapped", chunkTotal: 1 },
    );
    expect(result.map((p) => Array.from(p))).toEqual([[7]]);
    expect(openRecord).toHaveBeenCalledWith("photo", "slim_chunk", "c1", {
      fileHash: "f".repeat(64),
      seq: 0,
      total: 1,
      wrappedKey: "wrapped",
    });
  });
});
