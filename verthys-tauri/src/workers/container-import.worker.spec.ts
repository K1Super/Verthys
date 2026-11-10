/**
 * container-import.worker.spec.ts — 正式导入 Worker 任务内核测试
 *
 * 覆盖：
 * - 逐块重封装：块数以清单为准，产物与密封结果一一对应
 * - 背压：上一张未 ack 前不得投递下一张
 * - 全量校验：块级 AEAD 失败（篡改）进入 failure，不产出 done
 * - 令牌错误：解封失败即终止，不残留半成品消息
 */
import { describe, it, expect, vi } from "vitest";
import { blake3 } from "@noble/hashes/blake3";
import { installBase64Polyfill } from "../test-utils/base64-polyfill";

installBase64Polyfill();

// Worker 模块在顶层读写 self；node 环境需要先补齐全局再动态导入
(globalThis as unknown as { self: unknown }).self = globalThis;

const { runContainerImportJob } = await import("./container-import.worker");

import { packVenc } from "../lib/crypto";
import { bytesToHex, bytesToBase64 } from "../utils/binary_codec";
import { FILE_HASH_LEN, VENC_OUTER_HEADER_BYTES, VENC_WRAPPED_KEY_BYTES, VENC_FRAME_HEADER_BYTES, NONCE_LEN, TAG_LEN } from "../constants/crypto_const";
import type { LightMeta, VencPhotoSpec } from "../types/crypto";
import type {
  ContainerImportDeps,
  ContainerImportResponse,
} from "./container-import.worker";

const TOKEN = "a".repeat(64);

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function makeSpec(name: string, chunks: Uint8Array[]): VencPhotoSpec {
  const all = concat(chunks);
  const lightMeta: LightMeta = {
    name,
    mime: "image/jpeg",
    size: all.length,
    thumbB64: "",
    fileHash: bytesToHex(blake3(all, { dkLen: FILE_HASH_LEN })),
    createdAt: 10,
    chunkCount: chunks.length,
  };
  return { lightMeta, chunkBytes: chunks.map((c) => c.slice()) };
}

function makeDeps(overrides: Partial<ContainerImportDeps> = {}): {
  deps: ContainerImportDeps;
  posts: ContainerImportResponse[];
  sealCalls: Array<{ dataB64: string; fileHash: string; seq: number; total: number }>;
} {
  const posts: ContainerImportResponse[] = [];
  const sealCalls: Array<{ dataB64: string; fileHash: string; seq: number; total: number }> = [];
  const deps: ContainerImportDeps = {
    post: (m) => { posts.push(m); },
    sealChunk: async (call) => {
      sealCalls.push(call);
      // 合法 base64（单字节序号）：Worker 会对密文复算 BLAKE3
      return bytesToBase64(new Uint8Array([call.seq + 1]));
    },
    waitAck: async () => {},
    ...overrides,
  };
  return { deps, posts, sealCalls };
}

const CHUNK_A = new Uint8Array([1, 2, 3]);
const CHUNK_B = new Uint8Array([4, 5]);

describe("container-import.worker — 逐块重封装与背压", () => {
  it("两张照片：按清单块数逐块密封，投递产物并完成", async () => {
    const encoded = await packVenc(
      [makeSpec("一.jpg", [CHUNK_A]), makeSpec("二.jpg", [CHUNK_B, CHUNK_A])],
      TOKEN,
    );
    const { deps, posts, sealCalls } = makeDeps();

    await runContainerImportJob(
      { id: 1, fileBytes: encoded.slice().buffer as ArrayBuffer, token: TOKEN, expectedPhotos: 2 },
      deps,
    );

    const photos = posts.filter((p) => p.type === "photo");
    expect(photos).toHaveLength(2);
    expect(photos[0].index).toBe(0);
    expect(photos[1].index).toBe(1);
    if (photos[0].type !== "photo" || photos[1].type !== "photo") throw new Error("类型收窄失败");
    expect(photos[0].chunkB64List).toEqual([bytesToBase64(new Uint8Array([1]))]);
    expect(photos[1].chunkB64List).toEqual([
      bytesToBase64(new Uint8Array([1])),
      bytesToBase64(new Uint8Array([2])),
    ]);
    expect(photos[0].chunkHashes).toHaveLength(1);
    expect(photos[1].chunkHashes).toHaveLength(2);
    // 密封入参：明文为原始块字节，文件哈希与块位置来自清单
    expect(sealCalls.map((c) => c.seq)).toEqual([0, 0, 1]);
    expect(sealCalls.map((c) => c.total)).toEqual([1, 2, 2]);
    expect(sealCalls[1].dataB64).toBe(bytesToBase64(CHUNK_B));
    expect(posts[posts.length - 1]).toMatchObject({ id: 1, type: "done", ok: true, photos: 2 });
  });

  it("背压：上一张未 ack 前不投递下一张", async () => {
    const encoded = await packVenc(
      [makeSpec("一.jpg", [CHUNK_A]), makeSpec("二.jpg", [CHUNK_B])],
      TOKEN,
    );
    const ackGate: { release: (() => void) | null } = { release: null };
    let ackCount = 0;
    const { deps, posts } = makeDeps({
      waitAck: () => {
        ackCount += 1;
        // 仅第一张需要手动确认；第二张自动放行，测试不额外等待
        if (ackCount > 1) return Promise.resolve();
        return new Promise<void>((resolve) => { ackGate.release = resolve; });
      },
    });

    const job = runContainerImportJob(
      { id: 1, fileBytes: encoded.slice().buffer as ArrayBuffer, token: TOKEN, expectedPhotos: 2 },
      deps,
    );

    await vi.waitFor(() => {
      expect(posts.filter((p) => p.type === "photo")).toHaveLength(1);
    });
    // 第一张已投递但未确认：第二张不得出现
    expect(posts.filter((p) => p.type === "photo")).toHaveLength(1);

    ackGate.release?.();
    await job;

    const photos = posts.filter((p) => p.type === "photo");
    expect(photos).toHaveLength(2);
    expect(posts[posts.length - 1]).toMatchObject({ type: "done", ok: true });
  });
});

describe("container-import.worker — 预览后容器被替换", () => {
  it("容器照片数多于预览：第二张清单即失败，不得静默错位", async () => {
    const encoded = await packVenc(
      [makeSpec("一.jpg", [CHUNK_A]), makeSpec("二.jpg", [CHUNK_B])],
      TOKEN,
    );
    const { deps, posts } = makeDeps();
    await runContainerImportJob(
      { id: 3, fileBytes: encoded.slice().buffer as ArrayBuffer, token: TOKEN, expectedPhotos: 1 },
      deps,
    );
    const failure = posts[posts.length - 1];
    if (failure.type !== "failure") throw new Error("类型收窄失败");
    expect(failure.error).toMatch(/照片数与预览结果不一致/);
  });

  it("容器照片数少于预览：尾部校验后失败，不产出 done", async () => {
    const encoded = await packVenc([makeSpec("一.jpg", [CHUNK_A])], TOKEN);
    const { deps, posts } = makeDeps();
    await runContainerImportJob(
      { id: 4, fileBytes: encoded.slice().buffer as ArrayBuffer, token: TOKEN, expectedPhotos: 2 },
      deps,
    );
    expect(posts.filter((p) => p.type === "done")).toHaveLength(0);
    const failure = posts[posts.length - 1];
    if (failure.type !== "failure") throw new Error("类型收窄失败");
    expect(failure.error).toMatch(/照片数与预览结果不一致/);
  });
});

describe("container-import.worker — 全量校验失败语义", () => {
  it("块帧密文篡改：块级 AEAD 失败 → failure，无 photo/done", async () => {
    const encoded = await packVenc([makeSpec("篡改.jpg", [CHUNK_A])], TOKEN);
    // 定位块帧并篡改密文首字节
    const manifestOffset = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
    const manifestLen = new DataView(
      encoded.buffer, encoded.byteOffset, encoded.byteLength,
    ).getUint32(manifestOffset + 5, false);
    const chunkOffset = manifestOffset + VENC_FRAME_HEADER_BYTES + NONCE_LEN + manifestLen + TAG_LEN;
    const tampered = encoded.slice();
    tampered[chunkOffset + VENC_FRAME_HEADER_BYTES + NONCE_LEN] ^= 0xff;

    const { deps, posts } = makeDeps();
    await runContainerImportJob(
      { id: 9, fileBytes: tampered.buffer as ArrayBuffer, token: TOKEN, expectedPhotos: 1 },
      deps,
    );

    expect(posts.filter((p) => p.type === "photo")).toHaveLength(0);
    expect(posts[posts.length - 1]).toMatchObject({ type: "failure", ok: false });
    const failure = posts[posts.length - 1];
    if (failure.type !== "failure") throw new Error("类型收窄失败");
    expect(failure.error).toMatch(/标签校验失败|TAG_VERIFICATION_FAILED/);
  });

  it("密封产物为空：拒绝投递，不产出任何照片", async () => {
    const encoded = await packVenc([makeSpec("空密文.jpg", [CHUNK_A])], TOKEN);
    const { deps, posts } = makeDeps({
      sealChunk: async () => "",
    });

    await runContainerImportJob(
      { id: 10, fileBytes: encoded.slice().buffer as ArrayBuffer, token: TOKEN, expectedPhotos: 1 },
      deps,
    );

    expect(posts.filter((p) => p.type === "photo")).toHaveLength(0);
    expect(posts[posts.length - 1]).toMatchObject({ type: "failure", ok: false });
    const failure = posts[posts.length - 1];
    if (failure.type !== "failure") throw new Error("类型收窄失败");
    expect(failure.error).toMatch(/密封产物为空/);
  });

  it("令牌错误：解封失败即终止，不产出任何照片", async () => {
    const encoded = await packVenc([makeSpec("令牌.jpg", [CHUNK_A])], TOKEN);
    const { deps, posts } = makeDeps();

    await runContainerImportJob(
      { id: 2, fileBytes: encoded.slice().buffer as ArrayBuffer, token: "b".repeat(64), expectedPhotos: 1 },
      deps,
    );

    expect(posts.filter((p) => p.type === "photo")).toHaveLength(0);
    expect(posts[posts.length - 1]).toMatchObject({ type: "failure", ok: false });
  });
});
