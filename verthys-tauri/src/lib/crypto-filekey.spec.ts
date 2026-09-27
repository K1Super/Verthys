/**
 * crypto-filekey.spec.ts — 文件子密钥按盐复用的行为契约测试
 *
 * 覆盖（真实加密实现，不 mock）：
 * - 同文件多块共用盐：派生只发生一次（缓存条目数恒为 1），读取侧同样只派生一次
 * - 不同盐各自派生（存量"每块独立盐"数据不受影响，互不命中）
 * - 缓存容量有界（超出淘汰最旧条目）
 * - 显式清理后再解密仍正确（重新派生）
 * - 共享盐不影响 AD 绑定：块序号被篡改即拒绝
 */
import { describe, it, expect, beforeEach } from "vitest";
import {
  encryptChunk, decryptChunk, clearFileKeyCache, getFileKeyCacheSize,
} from "./crypto";
import { bytesToBase64, base64ToBytes } from "../utils/binary_codec";
import { FILE_HASH_LEN, SALT_LEN } from "../constants/crypto_const";

const MODULE_KEY = "photo-module-key";
const FILE_HASH = "a".repeat(FILE_HASH_LEN * 2);

function plainChunks(count: number): Uint8Array[] {
  return Array.from({ length: count }, (_, i) =>
    new Uint8Array([i, i + 1, i + 2, i + 3]),
  );
}

describe("文件子密钥按盐复用", () => {
  beforeEach(() => {
    clearFileKeyCache();
  });

  it("同文件多块共用盐：写入与读取各只派生一次", async () => {
    const chunks = plainChunks(5);
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));

    const encrypted: string[] = [];
    for (let i = 0; i < chunks.length; i++) {
      const out = await encryptChunk(chunks[i], MODULE_KEY, i, chunks.length, FILE_HASH, salt);
      encrypted.push(bytesToBase64(out));
    }
    // 5 块共用一盐 → 缓存仅 1 条（即仅 1 次 PBKDF2）
    expect(getFileKeyCacheSize()).toBe(1);

    for (let i = 0; i < encrypted.length; i++) {
      const { plaintext, seq, total } = await decryptChunk(encrypted[i], MODULE_KEY, FILE_HASH);
      expect(Array.from(plaintext)).toEqual(Array.from(chunks[i]));
      expect(seq).toBe(i);
      expect(total).toBe(chunks.length);
    }
    // 读取侧命中同一缓存条目，不产生新的派生
    expect(getFileKeyCacheSize()).toBe(1);
  });

  it("不同盐各自派生：存量每块独立盐的数据互不命中", async () => {
    const chunks = plainChunks(3);
    for (let i = 0; i < chunks.length; i++) {
      await encryptChunk(chunks[i], MODULE_KEY, i, chunks.length, FILE_HASH);
    }
    expect(getFileKeyCacheSize()).toBe(3);
  });

  it("缓存容量有界：超出上限后淘汰最旧条目", async () => {
    const saltCount = 12;
    for (let i = 0; i < saltCount; i++) {
      const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
      await encryptChunk(new Uint8Array([i]), MODULE_KEY, 0, 1, FILE_HASH, salt);
    }
    expect(getFileKeyCacheSize()).toBeLessThanOrEqual(8);
  });

  it("显式清理后仍可解密（重新派生）", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const enc = await encryptChunk(new Uint8Array([1, 2, 3]), MODULE_KEY, 0, 1, FILE_HASH, salt);
    expect(getFileKeyCacheSize()).toBe(1);

    clearFileKeyCache();
    expect(getFileKeyCacheSize()).toBe(0);

    const { plaintext } = await decryptChunk(bytesToBase64(enc), MODULE_KEY, FILE_HASH);
    expect(Array.from(plaintext)).toEqual([1, 2, 3]);
    expect(getFileKeyCacheSize()).toBe(1);
  });

  it("共享盐不削弱 AD 绑定：块序号被篡改即拒绝", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const enc = await encryptChunk(new Uint8Array([9, 9]), MODULE_KEY, 1, 2, FILE_HASH, salt);

    // 篡改序号字段（salt 之后 4 字节，大端）→ AD 不匹配 → 标签校验失败
    const tampered = new Uint8Array(enc);
    tampered[SALT_LEN + 3] ^= 0x01;

    await expect(
      decryptChunk(bytesToBase64(tampered), MODULE_KEY, FILE_HASH),
    ).rejects.toThrow();
  });
});