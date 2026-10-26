/**
 * photo-crypto.worker.spec.ts — Worker 解密路径集成测试
 *
 * 以最小消息全局桩加载 Worker 模块（模块顶层把 self 作为消息作用域），
 * Worker 发出的记录加解密 RPC 由测试内置的应答器处理（固定明文/故障注入），
 * 锁定以下契约：
 * - decrypt_meta / decrypt_chunks 的分发与响应装箱（字段、id、明文顺序）
 * - decrypt_chunks 的明文以 transferList 零拷贝回传
 * - 失败路径收敛为失败响应（携带定位标识），不向消息入口外抛异常
 * - 完整性校验（逐块密文哈希、整图明文哈希）在 Worker 侧先行生效
 */
import { describe, it, expect, beforeAll, beforeEach, vi } from "vitest";
import { bytesToBase64, bytesToHex } from "../utils/binary_codec";
import { blake3 } from "@noble/hashes/blake3";
import type { PhotoMeta } from "../types/crypto";

const META: PhotoMeta = {
  name: "照片.png",
  mime: "image/png",
  size: 7,
  thumbB64: "thumb-b64",
  chunkIds: [5, 6],
  chunkHashes: ["h1", "h2"],
  fileHash: "f".repeat(64),
  createdAt: 1_700_000_000_000,
};

/** 应答器故障注入与位置覆盖 */
let failNextChunkOpen = false;
/** 应答器声明的块总数（与调用方列表长度对齐时通过位置校验） */
let listTotal = 1;

interface WorkerSelfStub {
  postMessage: ReturnType<typeof vi.fn>;
  onmessage: ((e: MessageEvent) => unknown) | null;
}

let workerSelf: WorkerSelfStub;

async function answerRpc(call: Record<string, unknown>): Promise<Record<string, unknown>> {
  const kind = String(call.kind);
  if (call.op === "open" && kind === "meta") {
    if (String(call.data) === "AAAA") throw new Error("元数据密文过短");
    return {
      dataB64: bytesToBase64(new TextEncoder().encode(JSON.stringify(META))),
    };
  }
  if (call.op === "open" && kind === "chunk") {
    if (failNextChunkOpen) {
      failNextChunkOpen = false;
      throw new Error("标签校验失败");
    }
    return {
      dataB64: bytesToBase64(new Uint8Array([1, 2])),
      seq: Number(call.data === "c2" ? 1 : 0),
      total: listTotal,
    };
  }
  throw new Error(`应答器不支持的操作: ${String(call.op)}/${kind}`);
}

beforeAll(async () => {
  workerSelf = { postMessage: vi.fn(), onmessage: null };
  workerSelf.postMessage.mockImplementation((message: Record<string, unknown>) => {
    if (message?.__verthysRpc !== true) return;
    queueMicrotask(() => {
      void answerRpc(message.call as Record<string, unknown>)
        .then((result) => {
          workerSelf.onmessage?.({
            data: {
              __verthysRpcResult: true,
              rpcId: message.rpcId,
              ok: true,
              result,
            },
          } as MessageEvent);
        })
        .catch((e) => {
          workerSelf.onmessage?.({
            data: {
              __verthysRpcResult: true,
              rpcId: message.rpcId,
              ok: false,
              error: e instanceof Error ? e.message : String(e),
            },
          } as MessageEvent);
        });
    });
  });
  vi.stubGlobal("self", workerSelf);
  await import("./photo-crypto.worker");
  expect(workerSelf.onmessage).toBeTypeOf("function");
});

beforeEach(() => {
  failNextChunkOpen = false;
  listTotal = 1;
  workerSelf.postMessage.mockClear();
});

async function dispatch(data: unknown): Promise<void> {
  await workerSelf.onmessage?.({ data } as MessageEvent);
}

function lastPost(): { response: Record<string, unknown>; transfer: unknown } {
  const calls = workerSelf.postMessage.mock.calls.filter(
    (call) => (call[0] as Record<string, unknown>)?.__verthysRpc !== true,
  );
  const call = calls[calls.length - 1];
  if (!call) throw new Error("无 postMessage 记录");
  return { response: call[0] as Record<string, unknown>, transfer: call[1] };
}

function hashOf(text: string): string {
  return bytesToHex(blake3(new TextEncoder().encode(text), { dkLen: 32 }));
}

describe("photo-crypto.worker — 解密路径", () => {
  it("decrypt_meta：经主线程 RPC 解出元数据并原样装箱", async () => {
    await dispatch({ id: 11, op: "decrypt_meta", metaB64: "meta-cipher", label: "42" });

    const { response } = lastPost();
    expect(response.id).toBe(11);
    expect(response.ok).toBe(true);
    expect(response.meta).toEqual(META);
  });

  it("decrypt_chunks：明文按序回传，且以 transferList 零拷贝转移", async () => {
    listTotal = 2;
    await dispatch({
      id: 12,
      op: "decrypt_chunks",
      chunksB64: ["c1", "c2"],
      fileHashHex: "f".repeat(64),
      label: "照片.png",
    });

    const { response, transfer } = lastPost();
    expect(response.id).toBe(12);
    expect(response.ok).toBe(true);
    const buffers = response.plaintexts as ArrayBuffer[];
    expect(buffers).toHaveLength(2);
    expect(Array.from(new Uint8Array(buffers[0]))).toEqual([1, 2]);
    expect(Array.from(new Uint8Array(buffers[1]))).toEqual([1, 2]);
    // 转移列表必须是响应内的同一批缓冲：否则 Worker 侧不释放明文所有权
    expect(transfer).toBe(buffers);
  });

  it("元数据密文损坏：失败响应携带定位标识，异常不抛穿消息入口", async () => {
    await dispatch({ id: 13, op: "decrypt_meta", metaB64: "AAAA", label: "77" });

    const { response } = lastPost();
    expect(response.id).toBe(13);
    expect(response.ok).toBe(false);
    expect(response.name).toBe("77");
    expect(String(response.error)).toContain("过短");
  });

  it("块标签校验失败：整体失败并标注块序号", async () => {
    failNextChunkOpen = true;
    await dispatch({
      id: 14,
      op: "decrypt_chunks",
      chunksB64: ["c1"],
      fileHashHex: "f".repeat(64),
      label: "照片.png",
    });

    const { response } = lastPost();
    expect(response.id).toBe(14);
    expect(response.ok).toBe(false);
    expect(response.name).toBe("照片.png");
    expect(String(response.error)).toContain("第 1/1 块解密失败");
  });

  it("块列表与密文自描述位置不符：拼接前拒绝并标注块序号", async () => {
    listTotal = 2;
    await dispatch({
      id: 15,
      op: "decrypt_chunks",
      chunksB64: ["c1"],
      fileHashHex: "f".repeat(64),
      label: "照片.png",
    });

    const { response } = lastPost();
    expect(response.id).toBe(15);
    expect(response.ok).toBe(false);
    expect(String(response.error)).toContain("数据块顺序校验失败");
  });

  it("逐块密文哈希与权威值不符：解密前拒绝并标注块序号", async () => {
    await dispatch({
      id: 16,
      op: "decrypt_chunks",
      chunksB64: ["c1"],
      fileHashHex: "f".repeat(64),
      label: "照片.png",
      expectedHashes: ["0".repeat(64)],
    });

    const { response } = lastPost();
    expect(response.id).toBe(16);
    expect(response.ok).toBe(false);
    expect(String(response.error)).toContain("块密文哈希校验失败");
  });

  it("整图明文哈希与权威值不符：整体失败（解密产物被拒绝）", async () => {
    await dispatch({
      id: 17,
      op: "decrypt_chunks",
      chunksB64: ["c1"],
      fileHashHex: "f".repeat(64),
      label: "照片.png",
      expectedFileHash: hashOf("not-the-content"),
    });

    const { response } = lastPost();
    expect(response.id).toBe(17);
    expect(response.ok).toBe(false);
    expect(String(response.error)).toContain("整图哈希校验失败");
  });
});
