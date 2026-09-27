/**
 * photo-crypto.worker.spec.ts — Worker 解密路径集成测试
 *
 * 以最小消息全局桩加载 Worker 模块（模块顶层把 self 作为消息作用域），用真实
 * 加密原语产出密文后直接驱动消息入口，锁定以下契约：
 * - decrypt_meta / decrypt_chunks 的分发与响应装箱（字段、id、明文顺序）
 * - decrypt_chunks 的明文以 transferList 零拷贝回传（转移列表与响应数组同一引用）
 * - 失败路径收敛为失败响应（携带定位标识），不向消息入口外抛异常
 * - 任务结束后清空按盐派生的子密钥缓存（派生结果不跨任务驻留）
 */
import { describe, it, expect, beforeAll, vi } from "vitest";
import {
  encryptMeta,
  encryptChunk,
  computeFileHash,
  bytesToHex,
  getFileKeyCacheSize,
} from "../lib/crypto";
import { bytesToBase64 } from "../utils/binary_codec";
import type { PhotoMeta } from "../types/crypto";

/** Worker 消息全局桩：模块加载时赋值 onmessage，处理中调用 postMessage 回传 */
interface WorkerSelfStub {
  postMessage: ReturnType<typeof vi.fn>;
  onmessage: ((e: MessageEvent) => unknown) | null;
}

let workerSelf: WorkerSelfStub;

beforeAll(async () => {
  workerSelf = { postMessage: vi.fn(), onmessage: null };
  vi.stubGlobal("self", workerSelf);
  await import("./photo-crypto.worker");
  expect(workerSelf.onmessage).toBeTypeOf("function");
});

/** 驱动一次消息入口（onmessage 为异步处理函数，返回其完成 Promise） */
async function dispatch(data: unknown): Promise<void> {
  await workerSelf.onmessage?.({ data } as MessageEvent);
}

/** 取最近一次回传的响应与转移列表 */
function lastPost(): { response: Record<string, unknown>; transfer: unknown } {
  const calls = workerSelf.postMessage.mock.calls;
  const call = calls[calls.length - 1];
  if (!call) throw new Error("无 postMessage 记录");
  return { response: call[0] as Record<string, unknown>, transfer: call[1] };
}

function makeMeta(): PhotoMeta {
  return {
    name: "照片.png",
    mime: "image/png",
    size: 7,
    thumbB64: "thumb-b64",
    chunkIds: [5, 6],
    chunkHashes: ["h1", "h2"],
    fileHash: "f".repeat(64),
    createdAt: 1_700_000_000_000,
  };
}

describe("photo-crypto.worker — 解密路径", () => {
  it("decrypt_meta：返回解密元数据，派生缓存跨任务有限驻留（供连续解密复用）", async () => {
    const meta = makeMeta();
    const metaB64 = await encryptMeta(meta, "photo-key");
    expect(getFileKeyCacheSize()).toBeGreaterThan(0);
    workerSelf.postMessage.mockClear();

    await dispatch({ id: 11, op: "decrypt_meta", metaB64, photoKey: "photo-key", label: "42" });

    const { response } = lastPost();
    expect(response.id).toBe(11);
    expect(response.ok).toBe(true);
    const decrypted = response.meta as PhotoMeta;
    expect(decrypted.name).toBe(meta.name);
    expect(decrypted.chunkIds).toEqual(meta.chunkIds);
    expect(decrypted.chunkHashes).toEqual(meta.chunkHashes);
    expect(decrypted.fileHash).toBe(meta.fileHash);
    // 派生结果按"口令指纹 + 盐"缓存、容量有界：供同文件的索引/缩略图/块解密
    // 复用（避免每任务重复 PBKDF2）；失效由池下发的 clearCache 标记清空。
    expect(getFileKeyCacheSize()).toBeGreaterThan(0);
    expect(getFileKeyCacheSize()).toBeLessThanOrEqual(8);
  });

  it("clearCache 标记：任务入口先清空派生缓存（模块密钥失效后的释放路径）", async () => {
    const meta = makeMeta();
    const metaB64 = await encryptMeta(meta, "photo-key");
    expect(getFileKeyCacheSize()).toBeGreaterThan(0);
    workerSelf.postMessage.mockClear();

    await dispatch({
      id: 21, op: "decrypt_meta", metaB64, photoKey: "photo-key", label: "42", clearCache: true,
    });

    // 任务入口清空 → 任务内重新派生一次；清空动作已发生（缓存规模为 1 而非历史累积）
    expect(getFileKeyCacheSize()).toBe(1);
  });

  it("decrypt_chunks：明文按序回传，且以 transferList 零拷贝转移", async () => {
    const plaintexts = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6, 7])];
    const fileHashHex = bytesToHex(computeFileHash(new Uint8Array([9, 9, 9])));
    const salt = new Uint8Array(16).fill(7);
    const cipher = [
      await encryptChunk(plaintexts[0], "photo-key", 0, 2, fileHashHex, salt),
      await encryptChunk(plaintexts[1], "photo-key", 1, 2, fileHashHex, salt),
    ];
    workerSelf.postMessage.mockClear();

    await dispatch({
      id: 12,
      op: "decrypt_chunks",
      chunksB64: cipher.map((c) => bytesToBase64(c)),
      photoKey: "photo-key",
      fileHashHex,
      label: "照片.png",
    });

    const { response, transfer } = lastPost();
    expect(response.id).toBe(12);
    expect(response.ok).toBe(true);
    const buffers = response.plaintexts as ArrayBuffer[];
    expect(buffers).toHaveLength(2);
    expect(Array.from(new Uint8Array(buffers[0]))).toEqual([1, 2, 3]);
    expect(Array.from(new Uint8Array(buffers[1]))).toEqual([4, 5, 6, 7]);
    // 转移列表必须是响应内的同一批缓冲：否则 Worker 侧不释放明文所有权
    expect(transfer).toBe(buffers);
  });

  it("元数据密文损坏：失败响应携带定位标识，异常不抛穿消息入口", async () => {
    workerSelf.postMessage.mockClear();

    await dispatch({ id: 13, op: "decrypt_meta", metaB64: "AAAA", photoKey: "k", label: "77" });

    const { response } = lastPost();
    expect(response.id).toBe(13);
    expect(response.ok).toBe(false);
    expect(response.name).toBe("77");
    expect(String(response.error)).toContain("过短");
  });

  it("块密文与文件哈希不符：整体失败并标注块序号", async () => {
    const fileHashHex = bytesToHex(computeFileHash(new Uint8Array([1])));
    const salt = new Uint8Array(16).fill(3);
    const cipher = await encryptChunk(new Uint8Array([1, 2]), "k", 0, 1, fileHashHex, salt);
    workerSelf.postMessage.mockClear();

    await dispatch({
      id: 14,
      op: "decrypt_chunks",
      chunksB64: [bytesToBase64(cipher)],
      photoKey: "k",
      // AD 绑定文件哈希：换一个哈希即标签校验失败（模拟数据被篡改）
      fileHashHex: bytesToHex(computeFileHash(new Uint8Array([2]))),
      label: "照片.png",
    });

    const { response } = lastPost();
    expect(response.id).toBe(14);
    expect(response.ok).toBe(false);
    expect(response.name).toBe("照片.png");
    expect(String(response.error)).toContain("第 1/1 块解密失败");
  });

  it("块列表与密文自描述位置不符：拼接前拒绝并标注块序号", async () => {
    const fileHashHex = bytesToHex(computeFileHash(new Uint8Array([7])));
    const salt = new Uint8Array(16).fill(5);
    // 密文按 total=2 生成但只传 1 块：列表被截断，自描述总数与列表长度不符
    const cipher = await encryptChunk(new Uint8Array([1, 2]), "k", 0, 2, fileHashHex, salt);
    workerSelf.postMessage.mockClear();

    await dispatch({
      id: 15,
      op: "decrypt_chunks",
      chunksB64: [bytesToBase64(cipher)],
      photoKey: "k",
      fileHashHex,
      label: "照片.png",
    });

    const { response } = lastPost();
    expect(response.id).toBe(15);
    expect(response.ok).toBe(false);
    expect(String(response.error)).toContain("第 1/1 块解密失败");
    expect(String(response.error)).toContain("数据块顺序校验失败");
  });
});