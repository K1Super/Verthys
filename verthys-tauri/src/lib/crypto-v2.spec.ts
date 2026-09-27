/**
 * crypto-v2.spec.ts — .venc v2 容器格式往返与拒绝语义测试
 *
 * 覆盖（真实加密实现，不 mock）：
 * - 打包/解包往返：单照片与多照片多块的字段级等价
 * - 内容密钥封装：令牌错误、头部篡改均导致解封失败
 * - 帧完整性：块密文篡改导致标签校验失败
 * - 结构拒绝：魔数不符 / 版本不支持 / 帧序号不连续 / 帧负载超上限 / 尾部残留
 * - 逐块哈希校验：chunkHashes 与块负载不符被拒
 * - KDF 参数自描述：头部迭代次数参与派生并可被安全读取
 */
import { describe, it, expect } from "vitest";
import {
  packVencV2,
  packVencV2Streamed,
  estimateVencTotalBytes,
  unpackVencV2,
  toLightMeta,
  computeChunkHashesForB64,
  generateRandomToken,
} from "./crypto";
import { bytesToBase64, base64ToBytes } from "../utils/binary_codec";
import {
  VENC_OUTER_HEADER_BYTES,
  VENC_WRAPPED_KEY_BYTES,
  VENC_FRAME_HEADER_BYTES,
  VENC_FRAME_TYPE_LIGHT_META,
  VENC_FRAME_TYPE_CHUNK,
  VENC_FRAME_TYPE_TRAILER,
  NONCE_LEN,
  TAG_LEN,
} from "../constants/crypto_const";
import type { PhotoMeta, VencPhotoSpecV2 } from "../types/crypto";

const TOKEN = "a".repeat(64);

/** 构造最小照片元数据（本地存储形状） */
function makeLocalMeta(name: string, chunks: Uint8Array[], hashHex: string): PhotoMeta {
  const b64List = chunks.map((c) => bytesToBase64(c));
  return {
    name,
    mime: "image/jpeg",
    size: chunks.reduce((s, c) => s + c.length, 0),
    thumbB64: "",
    chunkIds: [],
    chunkDataB64: b64List,
    chunkHashes: computeChunkHashesForB64(b64List),
    fileHash: hashHex,
    createdAt: 1000,
  };
}

/** 由本地元数据构造容器输入 */
function makeSpec(name: string, chunks: Uint8Array[], hashHex: string): VencPhotoSpecV2 {
  const local = makeLocalMeta(name, chunks, hashHex);
  return { lightMeta: toLightMeta(local), chunkBytes: chunks.map((c) => c.slice()) };
}

const CHUNK_A = new Uint8Array([1, 2, 3, 4, 5]);
const CHUNK_B = new Uint8Array([6, 7, 8, 9, 10]);
const HASH_X = "f".repeat(64);
const HASH_Y = "e".repeat(64);

describe("venc v2 — 往返等价", () => {
  it("单照片单块：打包再解包，轻量头与块字节逐字段一致", async () => {
    const spec = makeSpec("单张.jpg", [CHUNK_A], HASH_X);
    const encoded = await packVencV2([spec], TOKEN);
    const decoded = await unpackVencV2(encoded, TOKEN);

    expect(decoded).toHaveLength(1);
    expect(decoded[0].lightMeta).toEqual({
      ...spec.lightMeta,
      chunkHashes: spec.lightMeta.chunkHashes,
    });
    expect(decoded[0].chunkBytes).toHaveLength(1);
    expect(decoded[0].chunkBytes[0]).toEqual(CHUNK_A);
  });

  it("多照片多块：往返保持顺序与内容", async () => {
    const specs = [
      makeSpec("第一张.jpg", [CHUNK_A, CHUNK_B], HASH_X),
      makeSpec("第二张.jpg", [CHUNK_B, CHUNK_A, CHUNK_B], HASH_Y),
    ];
    const encoded = await packVencV2(specs, TOKEN);
    const decoded = await unpackVencV2(encoded, TOKEN);

    expect(decoded).toHaveLength(2);
    expect(decoded[0].lightMeta.name).toBe("第一张.jpg");
    expect(decoded[0].chunkBytes.map((c) => Array.from(c))).toEqual([
      Array.from(CHUNK_A),
      Array.from(CHUNK_B),
    ]);
    expect(decoded[1].lightMeta.name).toBe("第二张.jpg");
    expect(decoded[1].chunkBytes).toHaveLength(3);
  });

  it("打包结果头部自描述：魔数、版本与迭代次数按规范写入", async () => {
    const encoded = await packVencV2([makeSpec("头.jpg", [CHUNK_A], HASH_X)], TOKEN);
    const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
    expect(new TextDecoder().decode(encoded.slice(0, 4))).toBe("VENC");
    expect(view.getUint16(4, false)).toBe(2);
    expect(view.getUint16(8, false)).toBe(1); // PBKDF2-SHA256
    expect(view.getUint32(10, false)).toBeGreaterThanOrEqual(10_000);
  });
});

describe("venc v2 — 封装与帧完整性拒绝语义", () => {
  it("令牌错误：内容密钥解封失败", async () => {
    const encoded = await packVencV2([makeSpec("a.jpg", [CHUNK_A], HASH_X)], TOKEN);
    await expect(unpackVencV2(encoded, "b".repeat(64))).rejects.toThrow(/TAG_VERIFICATION_FAILED|解封失败/);
  });

  it("头部篡改：外层头部进入 AD，任一字节变化即解封失败", async () => {
    const encoded = await packVencV2([makeSpec("b.jpg", [CHUNK_A], HASH_X)], TOKEN);
    const tampered = encoded.slice();
    tampered[12] ^= 0xff; // 篡改 header 内一字节（salt 区域）
    await expect(unpackVencV2(tampered, TOKEN)).rejects.toThrow(/解封失败|TAG_VERIFICATION_FAILED/);
  });

  it("块帧密文篡改：标签校验失败", async () => {
    const encoded = await packVencV2([makeSpec("c.jpg", [CHUNK_A], HASH_X)], TOKEN);
    const tampered = encoded.slice();
    // 最后一个字节位于 trailer 帧密文内：翻转后解密必失败
    tampered[encoded.length - 1] ^= 0xff;
    await expect(unpackVencV2(tampered, TOKEN)).rejects.toThrow(/标签校验失败|TAG_VERIFICATION_FAILED/);
  });

  it("乱序帧：seq 不连续被拒", async () => {
    const encoded = await packVencV2([makeSpec("d.jpg", [CHUNK_A, CHUNK_B], HASH_X)], TOKEN);
    const tampered = encoded.slice();
    // 帧头是明文：将第二个数据帧（LM 帧后）的 seq 改写为 0 制造不连续
    const firstFrameOffset = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
    const firstFrameLen = viewGetLen(tampered, firstFrameOffset);
    const secondFrameOffset = firstFrameOffset + VENC_FRAME_HEADER_BYTES + NONCE_LEN + firstFrameLen + TAG_LEN;
    const view = new DataView(tampered.buffer, tampered.byteOffset, tampered.byteLength);
    view.setUint32(secondFrameOffset + 1, 0, false);
    await expect(unpackVencV2(tampered, TOKEN)).rejects.toThrow(/帧序号不连续/);
  });

  it("帧负载长度字段超上限：显式拒绝且不进入解密", async () => {
    const encoded = await packVencV2([makeSpec("e.jpg", [CHUNK_A], HASH_X)], TOKEN);
    const tampered = encoded.slice();
    const firstFrameOffset = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
    const view = new DataView(tampered.buffer, tampered.byteOffset, tampered.byteLength);
    view.setUint32(firstFrameOffset + 5, 64 * 1024 * 1024 + 1, false); // 超过 PARSE_MAX_FRAME_BYTES
    await expect(unpackVencV2(tampered, TOKEN)).rejects.toThrow(/帧负载超过上限/);
  });

  it("尾部残留数据：trailer 之后不允许存在任何字节", async () => {
    const encoded = await packVencV2([makeSpec("f.jpg", [CHUNK_A], HASH_X)], TOKEN);
    const appended = new Uint8Array(encoded.length + 3);
    appended.set(encoded, 0);
    await expect(unpackVencV2(appended, TOKEN)).rejects.toThrow(/未识别数据|越界/);
  });

  it("魔数不符 / 版本不支持：给出分类错误", async () => {
    const encoded = await packVencV2([makeSpec("g.jpg", [CHUNK_A], HASH_X)], TOKEN);
    const badMagic = encoded.slice();
    badMagic[0] = 0x58; // 'X'
    await expect(unpackVencV2(badMagic, TOKEN)).rejects.toThrow(/魔数不匹配/);

    const badVersion = encoded.slice();
    const view = new DataView(badVersion.buffer, badVersion.byteOffset, badVersion.byteLength);
    view.setUint16(4, 99, false);
    await expect(unpackVencV2(badVersion, TOKEN)).rejects.toThrow(/不支持的容器版本/);
  });

  it("逐块哈希不符：块负载与声明 chunkHashes 不一致被拒", async () => {
    // 构造与 chunkHashes 不一致的输入：直接经 pack（其前置校验也会拦截）
    const local = makeLocalMeta("h.jpg", [CHUNK_A], HASH_X);
    const badSpec: VencPhotoSpecV2 = {
      lightMeta: { ...toLightMeta(local), chunkHashes: ["0".repeat(64)] },
      chunkBytes: [CHUNK_A.slice()],
    };
    await expect(packVencV2([badSpec], TOKEN)).rejects.toThrow(/块哈希声明不符|块数字段不一致/);
  });
});

describe("venc v2 — KDF 参数与工具", () => {
  it("generateRandomToken 产出 64 位 hex 且高熵互异", () => {
    const t1 = generateRandomToken(32);
    const t2 = generateRandomToken(32);
    expect(t1).toMatch(/^[0-9a-f]{64}$/);
    expect(t1).not.toBe(t2);
  });

  it("computeChunkHashesForB64 稳定性：同一负载幂等，不同负载互异", () => {
    const h1 = computeChunkHashesForB64([bytesToBase64(CHUNK_A)]);
    const h2 = computeChunkHashesForB64([bytesToBase64(CHUNK_A)]);
    const h3 = computeChunkHashesForB64([bytesToBase64(CHUNK_B)]);
    expect(h1).toEqual(h2);
    expect(h1).not.toEqual(h3);
    expect(h1[0]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("base64 编解码往返：块字节无损（polyfill 与生产实现一致性基础）", () => {
    const b64 = bytesToBase64(CHUNK_A);
    expect(base64ToBytes(b64)).toEqual(CHUNK_A);
  });
});

describe("venc v2 — 流式打包", () => {
  it("流式产出的段按序拼接后与整包打包同构，可完整解包", async () => {
    const specs = [
      makeSpec("流式一.jpg", [CHUNK_A], HASH_X),
      makeSpec("流式二.jpg", [CHUNK_B, CHUNK_A], HASH_Y),
    ];
    const parts: Uint8Array[] = [];
    await packVencV2Streamed(specs, TOKEN, async (part) => {
      parts.push(part);
    });

    const total = parts.reduce((s, p) => s + p.length, 0);
    expect(total).toBe(estimateVencTotalBytes(specs));

    const joined = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { joined.set(p, off); off += p.length; }
    const decoded = await unpackVencV2(joined, TOKEN);
    expect(decoded).toHaveLength(2);
    expect(decoded[0].chunkBytes[0]).toEqual(CHUNK_A);
    expect(decoded[1].chunkBytes).toHaveLength(2);
  });

  it("首段为头部+封装密钥，其后帧序严格递增且类型正确", async () => {
    const parts: Uint8Array[] = [];
    await packVencV2Streamed(
      [makeSpec("帧序.jpg", [CHUNK_A, CHUNK_B], HASH_X)],
      TOKEN,
      async (p) => { parts.push(p); },
    );

    expect(parts[0].length).toBe(VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES);
    // 1 个轻量头帧 + 2 个块帧 + 1 个尾部帧
    const frames = parts.slice(1);
    expect(frames).toHaveLength(4);
    const types: number[] = [];
    const seqs: number[] = [];
    for (const f of frames) {
      const view = new DataView(f.buffer, f.byteOffset, f.byteLength);
      types.push(view.getUint8(0));
      seqs.push(view.getUint32(1, false));
    }
    expect(types).toEqual([
      VENC_FRAME_TYPE_LIGHT_META,
      VENC_FRAME_TYPE_CHUNK,
      VENC_FRAME_TYPE_CHUNK,
      VENC_FRAME_TYPE_TRAILER,
    ]);
    expect(seqs).toEqual([0, 1, 2, 3]);
  });

  it("emit 回调抛错：打包中止且错误向上传播（不产出后续段）", async () => {
    const boom = new Error("写盘失败");
    const specs = [makeSpec("中止.jpg", [CHUNK_A, CHUNK_B], HASH_X)];
    let emitted = 0;
    await expect(
      packVencV2Streamed(specs, TOKEN, async () => {
        emitted += 1;
        if (emitted >= 2) throw boom;
      }),
    ).rejects.toBe(boom);
  });

  it("estimateVencTotalBytes 与整包实际字节数一致（进度分母零偏差）", async () => {
    const specs = [makeSpec("预估.jpg", [CHUNK_A, CHUNK_B, CHUNK_A], HASH_X)];
    const encoded = await packVencV2(specs, TOKEN);
    expect(encoded.length).toBe(estimateVencTotalBytes(specs));
  });
});

/** 读取某帧明文头中的 len 字段（帧头为明文，直接可读） */
function viewGetLen(buf: Uint8Array, offset: number): number {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return view.getUint32(offset + 5, false);
}