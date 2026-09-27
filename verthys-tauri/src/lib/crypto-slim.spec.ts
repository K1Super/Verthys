/**
 * crypto-slim.spec.ts — 索引瘦身布局原语契约测试
 *
 * 锁定四条不变式：
 *   1. 双布局并存：既有布局原语行为不变（同文件既有用例），瘦身布局自洽往返；
 *   2. 密钥层级收敛：索引/缩略图/密钥解封共用同一文件盐 → 读取侧一次派生；
 *   3. AD 绑定完整：块顺序、缩略图归属、包裹密钥上下文任一被换用即解密失败；
 *   4. 写入开关默认关（回退前提），布局判定为纯函数且缺失引用即回落既有布局。
 */
import { describe, it, expect, beforeEach } from "vitest";
import {
  createSlimFileKeys,
  extractSlimFileSalt,
  unwrapSlimFileKey,
  encryptSlimMeta,
  encryptSlimChunk,
  decryptSlimChunk,
  encryptSlimThumb,
  decryptSlimThumb,
  encryptSlimChunkSet,
  decryptSlimChunkSet,
  decryptMeta,
  computeFileHash,
  bytesToHex,
  clearFileKeyCache,
  getFileKeyCacheSize,
  packVencV2,
  unpackVencV2,
  toLightMeta,
  computeChunkHashesForB64,
} from "./crypto";
import {
  PHOTO_FMT_LEGACY,
  PHOTO_FMT_SLIM,
  PHOTO_WRITE_FMT,
  isSlimPhotoMeta,
} from "../constants/crypto_const";
import { PHOTO_INDEX_MAX_BYTES } from "../constants/photo_budget.generated";
import { bytesToBase64 } from "../utils/binary_codec";
import type { PhotoMeta } from "../types/crypto";

const PASSWORD = "module-key-for-slim-layout";
const OTHER_PASSWORD = "another-module-key";

/** 构造瘦身布局索引（缩略图独立、块引用、包裹密钥） */
function slimMeta(fileHashHex: string, wrappedFileKey: string, thumbId = 42): PhotoMeta {
  return {
    fmt: PHOTO_FMT_SLIM,
    name: "photo.jpg",
    mime: "image/jpeg",
    size: 3,
    thumbB64: "",
    thumbId,
    chunkIds: [7, 8],
    chunkHashes: ["a".repeat(64), "b".repeat(64)],
    fileHash: fileHashHex,
    wrappedFileKey,
    createdAt: 1_700_000_000_000,
  };
}

describe("索引瘦身布局：密钥与记录往返", () => {
  beforeEach(() => clearFileKeyCache());

  it("包裹密钥可解封出同一文件密钥，盐与索引同源", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    const salt = extractSlimFileSalt(keys.wrappedFileKey);
    expect(salt).toEqual(keys.fileSalt);

    const unwrapped = await unwrapSlimFileKey(keys.wrappedFileKey, PASSWORD);
    expect(unwrapped).toEqual(keys.fileKey);
  });

  it("索引按指定盐加密后可由既有解密路径读回（密文布局不变）", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    const fileHash = bytesToHex(computeFileHash(new Uint8Array([1, 2, 3])));
    const meta = slimMeta(fileHash, keys.wrappedFileKey);
    const metaB64 = await encryptSlimMeta(meta, PASSWORD, keys.fileSalt);

    // 索引密文与既有布局同构：salt|nonce|密文，既有解密函数直接可读
    const decrypted = await decryptMeta(metaB64, PASSWORD);
    expect(decrypted.fmt).toBe(PHOTO_FMT_SLIM);
    expect(decrypted.thumbId).toBe(meta.thumbId);
    expect(decrypted.wrappedFileKey).toBe(keys.wrappedFileKey);
    expect(decrypted.chunkIds).toEqual(meta.chunkIds);
  });

  it("块密文只含 nonce 与密文（较既有布局少 salt|seq|total 三个字段）", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    const fileHash = bytesToHex(computeFileHash(new Uint8Array([4, 5, 6])));
    const plain = new Uint8Array([9, 9, 9, 9, 9]);
    const cipher = encryptSlimChunk(plain, keys.fileKey, 0, 1, fileHash);
    expect(cipher.length).toBe(24 + plain.length + 16);

    const restored = decryptSlimChunk(bytesToBase64(cipher), keys.fileKey, fileHash, 0, 1);
    expect(restored).toEqual(plain);
  });

  it("缩略图记录往返（密文仅 nonce|密文）", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    const fileHash = bytesToHex(computeFileHash(new Uint8Array([7, 8])));
    const thumb = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3]);
    const cipher = await encryptSlimThumb(thumb, PASSWORD, keys.fileSalt, fileHash);
    expect(cipher.length).toBe(24 + thumb.length + 16);

    const restored = await decryptSlimThumb(
      bytesToBase64(cipher), PASSWORD, keys.wrappedFileKey, fileHash,
    );
    expect(restored).toEqual(thumb);
  });

  it("读取侧每文件一次派生：索引 / 缩略图 / 密钥解封共用同一盐", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    clearFileKeyCache();

    const fileHash = bytesToHex(computeFileHash(new Uint8Array([1])));
    const meta = slimMeta(fileHash, keys.wrappedFileKey);
    const metaB64 = await encryptSlimMeta(meta, PASSWORD, keys.fileSalt);
    const thumbCipher = await encryptSlimThumb(
      new Uint8Array([1, 2, 3]), PASSWORD, keys.fileSalt, fileHash,
    );

    await decryptMeta(metaB64, PASSWORD);
    await decryptSlimThumb(bytesToBase64(thumbCipher), PASSWORD, keys.wrappedFileKey, fileHash);
    await unwrapSlimFileKey(keys.wrappedFileKey, PASSWORD);

    expect(getFileKeyCacheSize()).toBe(1);
  });
});

describe("索引瘦身布局：AD 绑定与失败分类", () => {
  beforeEach(() => clearFileKeyCache());

  it("缩略图归属绑定：跨照片换用缩略图记录即解密失败", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    const fileHashA = bytesToHex(computeFileHash(new Uint8Array([1])));
    const fileHashB = bytesToHex(computeFileHash(new Uint8Array([2])));
    const cipher = await encryptSlimThumb(new Uint8Array([1, 2, 3]), PASSWORD, keys.fileSalt, fileHashA);

    await expect(
      decryptSlimThumb(bytesToBase64(cipher), PASSWORD, keys.wrappedFileKey, fileHashB),
    ).rejects.toThrow();
  });

  it("块顺序绑定：错位或跨文件拼接即解密失败", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    const fileHash = bytesToHex(computeFileHash(new Uint8Array([1])));
    const cipher = bytesToBase64(encryptSlimChunk(new Uint8Array([1, 2]), keys.fileKey, 1, 3, fileHash));

    expect(() => decryptSlimChunk(cipher, keys.fileKey, fileHash, 0, 3)).toThrow();
    expect(() => decryptSlimChunk(cipher, keys.fileKey, fileHash, 1, 9)).toThrow();
    expect(decryptSlimChunk(cipher, keys.fileKey, fileHash, 1, 3)).toEqual(new Uint8Array([1, 2]));
  });

  it("包裹密钥绑定：密码不符或包裹被篡改即解封失败", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    await expect(unwrapSlimFileKey(keys.wrappedFileKey, OTHER_PASSWORD)).rejects.toThrow();

    const tampered = keys.wrappedFileKey.slice(0, -6) + "AAAAAA";
    await expect(unwrapSlimFileKey(tampered, PASSWORD)).rejects.toThrow();
  });

  it("结构校验：过短的包裹密钥被拒绝", () => {
    expect(() => extractSlimFileSalt("AAAA")).toThrow();
    expect(() => extractSlimFileSalt("")).toThrow();
  });
});

describe("索引瘦身布局：块集记录", () => {
  beforeEach(() => clearFileKeyCache());

  it("块集记录往返（密文仅 nonce|密文，逐块 ID 与哈希原样解回）", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    const fileHash = bytesToHex(computeFileHash(new Uint8Array([9, 9])));
    const set = { ids: [101, 102, 103], hashes: ["a".repeat(64), "b".repeat(64), "c".repeat(64)] };
    const cipher = await encryptSlimChunkSet(set, PASSWORD, keys.fileSalt, fileHash);
    expect(cipher.length).toBe(24 + JSON.stringify(set).length + 16);

    const restored = await decryptSlimChunkSet(
      bytesToBase64(cipher), PASSWORD, keys.wrappedFileKey, fileHash,
    );
    expect(restored).toEqual(set);
  });

  it("块集归属绑定：跨照片换用块集记录即解密失败", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    const fileHashA = bytesToHex(computeFileHash(new Uint8Array([1])));
    const fileHashB = bytesToHex(computeFileHash(new Uint8Array([2])));
    const cipher = await encryptSlimChunkSet(
      { ids: [1], hashes: ["a".repeat(64)] }, PASSWORD, keys.fileSalt, fileHashA,
    );

    await expect(
      decryptSlimChunkSet(bytesToBase64(cipher), PASSWORD, keys.wrappedFileKey, fileHashB),
    ).rejects.toThrow();
  });

  it("结构与写入侧同规：空集 / 项数不一致 / 非法 ID 或哈希一律拒绝", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    const fileHash = bytesToHex(computeFileHash(new Uint8Array([3])));
    const h = "a".repeat(64);

    await expect(
      encryptSlimChunkSet({ ids: [], hashes: [] }, PASSWORD, keys.fileSalt, fileHash),
    ).rejects.toThrow();
    await expect(
      encryptSlimChunkSet({ ids: [1, 2], hashes: [h] }, PASSWORD, keys.fileSalt, fileHash),
    ).rejects.toThrow();
    await expect(
      encryptSlimChunkSet({ ids: [0], hashes: [h] }, PASSWORD, keys.fileSalt, fileHash),
    ).rejects.toThrow();
    await expect(
      encryptSlimChunkSet({ ids: [1], hashes: ["not-hex"] }, PASSWORD, keys.fileSalt, fileHash),
    ).rejects.toThrow();
  });

  it("一次派生覆盖四类消费：索引 / 缩略图 / 块集 / 密钥解封共用同一盐", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    clearFileKeyCache();

    const fileHash = bytesToHex(computeFileHash(new Uint8Array([4])));
    const meta = slimMeta(fileHash, keys.wrappedFileKey);
    const metaB64 = await encryptSlimMeta(meta, PASSWORD, keys.fileSalt);
    const thumbCipher = await encryptSlimThumb(new Uint8Array([1, 2]), PASSWORD, keys.fileSalt, fileHash);
    const setCipher = await encryptSlimChunkSet(
      { ids: [7], hashes: ["a".repeat(64)] }, PASSWORD, keys.fileSalt, fileHash,
    );

    await decryptMeta(metaB64, PASSWORD);
    await decryptSlimThumb(bytesToBase64(thumbCipher), PASSWORD, keys.wrappedFileKey, fileHash);
    await decryptSlimChunkSet(bytesToBase64(setCipher), PASSWORD, keys.wrappedFileKey, fileHash);
    await unwrapSlimFileKey(keys.wrappedFileKey, PASSWORD);

    expect(getFileKeyCacheSize()).toBe(1);
  });
});

describe("布局分流与写入开关", () => {
  it("写入开关默认关：新导入回到既有布局（可回退）", () => {
    expect(PHOTO_WRITE_FMT).toBe(PHOTO_FMT_LEGACY);
  });

  it("索引瘦身判定：需布局标记与缩略图引用同时成立", () => {
    expect(isSlimPhotoMeta({ fmt: PHOTO_FMT_SLIM, thumbId: 9 })).toBe(true);
    expect(isSlimPhotoMeta({ fmt: PHOTO_FMT_SLIM })).toBe(false);
    expect(isSlimPhotoMeta({ fmt: PHOTO_FMT_SLIM, thumbId: 0 })).toBe(false);
    expect(isSlimPhotoMeta({ fmt: PHOTO_FMT_LEGACY, thumbId: 9 })).toBe(false);
    expect(isSlimPhotoMeta({ thumbId: 9 })).toBe(false);
  });

  it("索引预算边界：超出预算的索引被拒绝（不静默写入使缓存失效）", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    const fileHash = bytesToHex(computeFileHash(new Uint8Array([1])));
    // 构造超预算索引：块引用列表长度足以越过明文上界
    const oversize = slimMeta(fileHash, keys.wrappedFileKey);
    oversize.chunkIds = Array.from({ length: 1200 }, (_, i) => 1_000_000_000 + i);
    expect(JSON.stringify(oversize).length).toBeGreaterThan(PHOTO_INDEX_MAX_BYTES);

    await expect(encryptSlimMeta(oversize, PASSWORD, keys.fileSalt)).rejects.toThrow();
  });
});

describe("容器随来源布局携带标记（迁移保真的前提）", () => {
  beforeEach(() => clearFileKeyCache());

  it("索引瘦身布局：容器轻量头携带布局标记与包裹密钥，解包逐字段一致", async () => {
    const keys = await createSlimFileKeys(PASSWORD);
    const fileHash = bytesToHex(computeFileHash(new Uint8Array([5, 5])));
    const chunkBytes = [
      encryptSlimChunk(new Uint8Array([1, 2]), keys.fileKey, 0, 1, fileHash),
    ];
    const chunkB64 = bytesToBase64(chunkBytes[0]);
    const meta = slimMeta(fileHash, keys.wrappedFileKey);
    // 轻量头声明与负载同源的逐块哈希（打包侧会逐块校验，声明不符即拒绝产出）
    const lightMeta = toLightMeta({
      ...meta,
      chunkDataB64: [chunkB64],
      chunkHashes: computeChunkHashesForB64([chunkB64]),
    });

    expect(lightMeta.fmt).toBe(PHOTO_FMT_SLIM);
    expect(lightMeta.wrappedFileKey).toBe(keys.wrappedFileKey);

    const venc = await packVencV2([{ lightMeta, chunkBytes }], "export-token");
    const [restored] = await unpackVencV2(venc, "export-token");

    expect(restored.lightMeta.fmt).toBe(PHOTO_FMT_SLIM);
    expect(restored.lightMeta.wrappedFileKey).toBe(keys.wrappedFileKey);
    expect(restored.chunkBytes[0]).toEqual(chunkBytes[0]);
    // 接收端按同一布局解封并解出首块（可导入性预检口径）
    const fileKey = await unwrapSlimFileKey(restored.lightMeta.wrappedFileKey!, PASSWORD);
    expect(
      decryptSlimChunk(bytesToBase64(restored.chunkBytes[0]), fileKey, fileHash, 0, 1),
    ).toEqual(new Uint8Array([1, 2]));
    fileKey.fill(0);
  });

  it("既有布局：容器轻量头不携带布局字段（结构向后兼容）", () => {
    const legacyHash = bytesToHex(computeFileHash(new Uint8Array([6])));
    const lightMeta = toLightMeta({
      name: "a.jpg", mime: "image/jpeg", size: 2, thumbB64: "t",
      chunkIds: [], chunkDataB64: ["x"], chunkHashes: ["h"],
      fileHash: legacyHash, createdAt: 1,
    });
    expect(lightMeta.fmt).toBeUndefined();
    expect(lightMeta.wrappedFileKey).toBeUndefined();
  });
});