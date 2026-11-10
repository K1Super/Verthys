/**
 * crypto-venc.spec.ts — .venc 备份容器格式往返与拒绝语义测试
 *
 * 覆盖（真实加密实现，不 mock）：
 * - 打包/解包往返：单照片与多照片多块的字段级等价
 * - 内容密钥封装：令牌错误、头部篡改均导致解封失败
 * - 帧完整性：块帧密文篡改导致标签校验失败
 * - 结构拒绝：魔数不符 / 版本不支持 / 帧序号不连续 / 帧负载超上限 / 尾部残留
 * - 内容身份：整图 BLAKE3 与清单 fileHash 不一致被拒
 * - 流式解码与预览：块回调、预览不做块级认证
 * - KDF 参数自描述：头部迭代次数参与派生并可被安全读取
 */
import { describe, it, expect } from "vitest";
import { blake3 } from "@noble/hashes/blake3";
import {
  packVenc,
  packVencStreamed,
  estimateVencTotalBytes,
  unpackVenc,
  unpackVencPreview,
  unpackVencStream,
  toLightMeta,
  generateRandomToken,
  vencPhotoFramesBytes,
  VENC_CONTAINER_FIXED_BYTES,
} from "./crypto";
import { bytesToBase64, base64ToBytes, bytesToHex } from "../utils/binary_codec";
import {
  CHUNK_SIZE,
  FILE_HASH_LEN,
  VENC_KDF_ITERATIONS,
  VENC_OUTER_HEADER_BYTES,
  VENC_WRAPPED_KEY_BYTES,
  VENC_FRAME_HEADER_BYTES,
  VENC_FRAME_TYPE_LIGHT_META,
  VENC_FRAME_TYPE_CHUNK,
  VENC_FRAME_TYPE_TRAILER,
  NONCE_LEN,
  TAG_LEN,
  PHOTO_FMT_SLIM,
} from "../constants/crypto_const";
import type { LightMeta, PhotoMeta, VencPhotoSpec } from "../types/crypto";

const TOKEN = "a".repeat(64);

/** 拼接块字节 */
function concatChunks(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** 整图 BLAKE3（与容器校验口径一致） */
function contentHash(chunks: Uint8Array[]): string {
  return bytesToHex(blake3(concatChunks(chunks), { dkLen: FILE_HASH_LEN }));
}

/** 构造容器清单（真实整图哈希） */
function makeLightMeta(name: string, chunks: Uint8Array[]): LightMeta {
  return {
    name,
    mime: "image/jpeg",
    size: chunks.reduce((s, c) => s + c.length, 0),
    thumbB64: "",
    fileHash: contentHash(chunks),
    createdAt: 1000,
    chunkCount: chunks.length,
  };
}

/** 由块字节构造容器输入 */
function makeSpec(name: string, chunks: Uint8Array[]): VencPhotoSpec {
  return {
    lightMeta: makeLightMeta(name, chunks),
    chunkBytes: chunks.map((c) => c.slice()),
  };
}

const CHUNK_A = new Uint8Array([1, 2, 3, 4, 5]);
const CHUNK_B = new Uint8Array([6, 7, 8, 9, 10]);

describe("venc — 往返等价", () => {
  it("单照片单块：打包再解包，清单与块字节逐字段一致", async () => {
    const spec = makeSpec("单张.jpg", [CHUNK_A]);
    const encoded = await packVenc([spec], TOKEN);
    const decoded = await unpackVenc(encoded, TOKEN);

    expect(decoded).toHaveLength(1);
    expect(decoded[0].lightMeta).toEqual(spec.lightMeta);
    expect(decoded[0].chunkBytes).toHaveLength(1);
    expect(decoded[0].chunkBytes[0]).toEqual(CHUNK_A);
  });

  it("多照片多块：往返保持顺序与内容", async () => {
    const specs = [
      makeSpec("第一张.jpg", [CHUNK_A, CHUNK_B]),
      makeSpec("第二张.jpg", [CHUNK_B, CHUNK_A, CHUNK_B]),
    ];
    const encoded = await packVenc(specs, TOKEN);
    const decoded = await unpackVenc(encoded, TOKEN);

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
    const encoded = await packVenc([makeSpec("头.jpg", [CHUNK_A])], TOKEN);
    const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
    expect(new TextDecoder().decode(encoded.slice(0, 4))).toBe("VENC");
    expect(view.getUint16(4, false)).toBe(3);
    expect(view.getUint16(8, false)).toBe(1); // PBKDF2-SHA256
    expect(view.getUint32(10, false)).toBe(VENC_KDF_ITERATIONS);
  });

  it("toLightMeta 只投影清单字段，不携带布局与密钥信息", () => {
    const local: PhotoMeta = {
      name: "投影.jpg",
      mime: "image/png",
      size: 3,
      thumbB64: "AA==",
      chunkIds: [7],
      chunkDataB64: ["AQID"],
      chunkHashes: ["0".repeat(64)],
      fmt: PHOTO_FMT_SLIM,
      wrappedFileKey: "x".repeat(64),
      fileHash: "f".repeat(64),
      createdAt: 42,
    };
    expect(toLightMeta(local, 1)).toEqual({
      name: "投影.jpg",
      mime: "image/png",
      size: 3,
      thumbB64: "AA==",
      fileHash: "f".repeat(64),
      createdAt: 42,
      chunkCount: 1,
    });
  });
});

describe("venc — 封装与帧完整性拒绝语义", () => {
  it("令牌错误：内容密钥解封失败", async () => {
    const encoded = await packVenc([makeSpec("a.jpg", [CHUNK_A])], TOKEN);
    await expect(unpackVenc(encoded, "b".repeat(64))).rejects.toThrow(/TAG_VERIFICATION_FAILED|解封失败/);
  });

  it("头部篡改：外层头部进入 AD，任一字节变化即解封失败", async () => {
    const encoded = await packVenc([makeSpec("b.jpg", [CHUNK_A])], TOKEN);
    const tampered = encoded.slice();
    tampered[12] ^= 0xff; // 篡改 header 内一字节（salt 区域）
    await expect(unpackVenc(tampered, TOKEN)).rejects.toThrow(/解封失败|TAG_VERIFICATION_FAILED/);
  });

  it("块帧密文篡改：标签校验失败", async () => {
    const encoded = await packVenc([makeSpec("c.jpg", [CHUNK_A])], TOKEN);
    const tampered = encoded.slice();
    // 定位块帧负载起点：外层头 + 封装密钥 + 清单帧
    const manifestFrame = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
    const chunkFrame = manifestFrame + VENC_FRAME_HEADER_BYTES + NONCE_LEN
      + viewGetLen(tampered, manifestFrame) + TAG_LEN;
    tampered[chunkFrame + VENC_FRAME_HEADER_BYTES + NONCE_LEN] ^= 0xff;
    await expect(unpackVenc(tampered, TOKEN)).rejects.toThrow(/标签校验失败|TAG_VERIFICATION_FAILED/);
  });

  it("乱序帧：seq 不连续被拒", async () => {
    const encoded = await packVenc([makeSpec("d.jpg", [CHUNK_A, CHUNK_B])], TOKEN);
    const tampered = encoded.slice();
    const firstFrameOffset = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
    const firstFrameLen = viewGetLen(tampered, firstFrameOffset);
    const secondFrameOffset = firstFrameOffset + VENC_FRAME_HEADER_BYTES + NONCE_LEN + firstFrameLen + TAG_LEN;
    const view = new DataView(tampered.buffer, tampered.byteOffset, tampered.byteLength);
    view.setUint32(secondFrameOffset + 1, 0, false);
    await expect(unpackVenc(tampered, TOKEN)).rejects.toThrow(/帧序号不连续/);
  });

  it("帧负载长度字段超上限：显式拒绝且不进入解密", async () => {
    const encoded = await packVenc([makeSpec("e.jpg", [CHUNK_A])], TOKEN);
    const tampered = encoded.slice();
    const firstFrameOffset = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
    const view = new DataView(tampered.buffer, tampered.byteOffset, tampered.byteLength);
    view.setUint32(firstFrameOffset + 5, 64 * 1024 * 1024 + 1, false); // 超过 PARSE_MAX_FRAME_BYTES
    await expect(unpackVenc(tampered, TOKEN)).rejects.toThrow(/帧负载超过上限/);
  });

  it("尾部残留数据：trailer 之后不允许存在任何字节", async () => {
    const encoded = await packVenc([makeSpec("f.jpg", [CHUNK_A])], TOKEN);
    const appended = new Uint8Array(encoded.length + 3);
    appended.set(encoded, 0);
    await expect(unpackVenc(appended, TOKEN)).rejects.toThrow(/未识别数据|越界/);
  });

  it("魔数不符 / 版本不支持：给出分类错误", async () => {
    const encoded = await packVenc([makeSpec("g.jpg", [CHUNK_A])], TOKEN);
    const badMagic = encoded.slice();
    badMagic[0] = 0x58; // 'X'
    await expect(unpackVenc(badMagic, TOKEN)).rejects.toThrow(/魔数不匹配/);

    const badVersion = encoded.slice();
    const view = new DataView(badVersion.buffer, badVersion.byteOffset, badVersion.byteLength);
    view.setUint16(4, 2, false); // 旧格式版本必须拒绝
    await expect(unpackVenc(badVersion, TOKEN)).rejects.toThrow(/不支持的备份格式版本/);
  });

  it("整图哈希不符：清单 fileHash 与块负载不一致被拒", async () => {
    const chunks = [CHUNK_A.slice()];
    const badSpec: VencPhotoSpec = {
      lightMeta: {
        ...makeLightMeta("h.jpg", chunks),
        fileHash: "0".repeat(64),
      },
      chunkBytes: chunks,
    };
    await expect(packVenc([badSpec], TOKEN)).rejects.toThrow(/文件哈希不符/);
  });

  it("清单字段越出导入契约：打包前拒绝，不产出自身无法导入的容器", async () => {
    const longName = "a".repeat(1025);
    await expect(
      packVenc([makeSpec(longName, [CHUNK_A])], TOKEN),
    ).rejects.toThrow(/清单字段非法|清单 name 非法/);

    const bigThumb = makeSpec("超限缩略图.jpg", [CHUNK_A]);
    bigThumb.lightMeta.thumbB64 = bytesToBase64(new Uint8Array(2 * 1024 * 1024 + 1));
    await expect(
      packVenc([bigThumb], TOKEN),
    ).rejects.toThrow(/清单字段非法|缩略图超过上限/);
  });

  it("块数声明不符 / 块长为空 / 块超上限：打包前拒绝", async () => {
    const spec = makeSpec("i.jpg", [CHUNK_A]);
    await expect(
      packVenc([{ ...spec, lightMeta: { ...spec.lightMeta, chunkCount: 2 } }], TOKEN),
    ).rejects.toThrow(/块数不一致/);

    const empty = makeSpec("j.jpg", [new Uint8Array(0)]);
    await expect(
      packVenc([{ ...empty, lightMeta: { ...empty.lightMeta, size: 1 } }], TOKEN),
    ).rejects.toThrow(/块长度非法/);

    const huge = makeSpec("k.jpg", [new Uint8Array(CHUNK_SIZE + 1)]);
    await expect(packVenc([huge], TOKEN)).rejects.toThrow(/块长度非法/);
  });
});

describe("venc — 流式解码与预览", () => {
  it("流式解码：按序回调清单、块与照片完成事件", async () => {
    const specs = [
      makeSpec("流式一.jpg", [CHUNK_A]),
      makeSpec("流式二.jpg", [CHUNK_B, CHUNK_A]),
    ];
    const encoded = await packVenc(specs, TOKEN);

    const manifests: string[] = [];
    const chunks: number[] = [];
    const completed: string[] = [];
    const result = await unpackVencStream(encoded, TOKEN, {
      onManifest: (manifest) => { manifests.push(manifest.name); },
      onChunk: (_manifest, _index, chunk) => { chunks.push(chunk.length); },
      onPhotoComplete: (manifest) => { completed.push(manifest.name); },
    });

    expect(result.photos).toBe(2);
    expect(manifests).toEqual(["流式一.jpg", "流式二.jpg"]);
    expect(chunks).toEqual([CHUNK_A.length, CHUNK_B.length, CHUNK_A.length]);
    expect(completed).toEqual(["流式一.jpg", "流式二.jpg"]);
  });

  it("预览：只解清单与尾部，不做块级认证（篡改块密文仍可预览）", async () => {
    const encoded = await packVenc([makeSpec("预览.jpg", [CHUNK_A])], TOKEN);
    const tampered = encoded.slice();
    const manifestFrame = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
    const chunkFrame = manifestFrame + VENC_FRAME_HEADER_BYTES + NONCE_LEN
      + viewGetLen(tampered, manifestFrame) + TAG_LEN;
    tampered[chunkFrame + VENC_FRAME_HEADER_BYTES + NONCE_LEN] ^= 0xff;

    const previews = await unpackVencPreview(tampered, TOKEN);
    expect(previews).toHaveLength(1);
    expect(previews[0].lightMeta.name).toBe("预览.jpg");
    expect(previews[0].verified).toBe(false);

    // 正式导入路径必须拒绝同一份被篡改的容器
    await expect(unpackVenc(tampered, TOKEN)).rejects.toThrow(/标签校验失败|TAG_VERIFICATION_FAILED/);
  });
});

describe("venc — KDF 参数与工具", () => {
  it("generateRandomToken 产出 64 位 hex 且高熵互异", () => {
    const t1 = generateRandomToken(32);
    const t2 = generateRandomToken(32);
    expect(t1).toMatch(/^[0-9a-f]{64}$/);
    expect(t1).not.toBe(t2);
  });

  it("base64 编解码往返：块字节无损（polyfill 与生产实现一致性基础）", () => {
    const b64 = bytesToBase64(CHUNK_A);
    expect(base64ToBytes(b64)).toEqual(CHUNK_A);
  });
});

describe("venc — 流式打包", () => {
  it("流式产出的段按序拼接后与整包打包同构，可完整解包", async () => {
    const specs = [
      makeSpec("流式一.jpg", [CHUNK_A]),
      makeSpec("流式二.jpg", [CHUNK_B, CHUNK_A]),
    ];
    const parts: Uint8Array[] = [];
    await packVencStreamed(specs, TOKEN, async (part) => {
      parts.push(part);
    });

    const total = parts.reduce((s, p) => s + p.length, 0);
    expect(total).toBe(estimateVencTotalBytes(specs));

    const joined = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { joined.set(p, off); off += p.length; }
    const decoded = await unpackVenc(joined, TOKEN);
    expect(decoded).toHaveLength(2);
    expect(decoded[0].chunkBytes[0]).toEqual(CHUNK_A);
    expect(decoded[1].chunkBytes).toHaveLength(2);
  });

  it("首段为头部+封装密钥，其后帧序严格递增且类型正确", async () => {
    const parts: Uint8Array[] = [];
    await packVencStreamed(
      [makeSpec("帧序.jpg", [CHUNK_A, CHUNK_B])],
      TOKEN,
      async (p) => { parts.push(p); },
    );

    expect(parts[0].length).toBe(VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES);
    // 1 个清单帧 + 2 个块帧 + 1 个尾部帧
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
    const specs = [makeSpec("中止.jpg", [CHUNK_A, CHUNK_B])];
    let emitted = 0;
    await expect(
      packVencStreamed(specs, TOKEN, async () => {
        emitted += 1;
        if (emitted >= 2) throw boom;
      }),
    ).rejects.toBe(boom);
  });

  it("estimateVencTotalBytes 与整包实际字节数一致（进度分母零偏差）", async () => {
    const specs = [makeSpec("预估.jpg", [CHUNK_A, CHUNK_B, CHUNK_A])];
    const encoded = await packVenc(specs, TOKEN);
    expect(encoded.length).toBe(estimateVencTotalBytes(specs));
  });

  it("惰性体积预算与整包实际字节数逐字节一致（超限判定不误伤）", async () => {
    const specs = [
      makeSpec("预算一.jpg", [CHUNK_A, CHUNK_B]),
      makeSpec("预算二.jpg", [CHUNK_B]),
    ];
    const budget = VENC_CONTAINER_FIXED_BYTES + specs.reduce(
      (sum, spec) => sum + vencPhotoFramesBytes(
        spec.lightMeta,
        spec.chunkBytes.map((chunk) => chunk.length),
      ),
      0,
    );
    const encoded = await packVenc(specs, TOKEN);
    expect(encoded.length).toBe(budget);
  });
});

/** 读取某帧明文头中的 len 字段（帧头为明文，直接可读） */
function viewGetLen(buf: Uint8Array, offset: number): number {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return view.getUint32(offset + 5, false);
}
