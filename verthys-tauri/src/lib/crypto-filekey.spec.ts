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
  createFileKeyV2, unlockFileKeyV2, encryptChunkV2, decryptChunkV2,
  buildPasswordCheckV2, verifyPasswordCheckV2,
  encryptPasswordField, decryptPasswordField,
  FILE_KDF_V2_VERSION, FILE_V2_IV_LEN,
} from "./crypto";
import { bytesToBase64, base64ToBytes } from "../utils/binary_codec";
import { FILE_HASH_LEN, SALT_LEN, TAG_LEN, PBKDF2_ITER } from "../constants/crypto_const";

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

describe("文件级密钥层（清藏外置块：一次派生 + 逐块 AES-GCM）", () => {
  it("v2 多块往返：派生参数契约成立、块密文结构固定、明文逐字节还原", async () => {
    const key = await createFileKeyV2("pwd-一号");

    expect(key.kdf.version).toBe(FILE_KDF_V2_VERSION);
    expect(key.kdf.iterations).toBe(PBKDF2_ITER);
    expect(base64ToBytes(key.kdf.saltB64)).toHaveLength(SALT_LEN);

    const chunks = [new Uint8Array([1, 2, 3]), new Uint8Array(1000).fill(7)];
    for (const plain of chunks) {
      const cipher = await encryptChunkV2(plain, key);
      // iv(12) + 密文 + 认证标签(16)
      expect(cipher.length).toBe(FILE_V2_IV_LEN + plain.length + TAG_LEN);
      const back = await decryptChunkV2(cipher, key);
      expect(Array.from(back)).toEqual(Array.from(plain));
    }
  });

  it("v2 篡改检测：块密文任一字节被改即拒绝", async () => {
    const key = await createFileKeyV2("pwd-tamper");
    const cipher = await encryptChunkV2(new Uint8Array([9, 9, 9]), key);

    const tampered = new Uint8Array(cipher);
    tampered[FILE_V2_IV_LEN] ^= 0x01;
    await expect(decryptChunkV2(tampered, key)).rejects.toThrow();
  });

  it("passwordCheck：正确口令通过、错误口令不通过、篡改即不通过（不抛错）", async () => {
    const key = await createFileKeyV2("right-pwd");
    const check = await buildPasswordCheckV2(key);
    expect(await verifyPasswordCheckV2(check, key)).toBe(true);

    // 同盐同口令重新解锁 → 仍通过（判定与派生批次无关）
    const same = await unlockFileKeyV2("right-pwd", key.kdf);
    expect(await verifyPasswordCheckV2(check, same)).toBe(true);

    // 错误口令 → 不通过，且不抛错（供前置分支消费）
    const wrong = await unlockFileKeyV2("wrong-pwd", key.kdf);
    expect(await verifyPasswordCheckV2(check, wrong)).toBe(false);

    // 校验块被篡改 → 不通过
    const bytes = base64ToBytes(check);
    bytes[bytes.length - 1] ^= 0x01;
    expect(await verifyPasswordCheckV2(bytesToBase64(bytes), key)).toBe(false);
  });

  it("解锁参数校验：盐长度非法即拒绝（不进入派生）", async () => {
    await expect(
      unlockFileKeyV2("pwd", {
        version: FILE_KDF_V2_VERSION,
        saltB64: bytesToBase64(new Uint8Array(3)),
        iterations: PBKDF2_ITER,
      }),
    ).rejects.toThrow();
  });

  it("v1 兼容：历史逐块盐形态（salt|iv|ct）仍可往返，错误口令即失败", async () => {
    const plain = bytesToBase64(new TextEncoder().encode("legacy-payload"));
    const enc = await encryptPasswordField(plain, "pwd-legacy");

    expect(await decryptPasswordField(enc, "pwd-legacy")).toBe(plain);
    await expect(decryptPasswordField(enc, "pwd-other")).rejects.toThrow();
  });
});