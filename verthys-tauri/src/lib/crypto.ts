/*
 * crypto.ts — 前端独立加密层（XChaCha20-Poly1305 + BLAKE3）
 *
 * 设计原则（对照用户提供的加密存储方案）：
 *   - 机密性：原始文件名、类型、大小、缩略图均加密，外部无法获取明文
 *   - 完整性：每个块独立附加 Poly1305 认证标签（AEAD 内置）
 *   - Nonce 唯一：每块 24 字节随机 Nonce（CSPRNG），碰撞概率可忽略
 *   - 块顺序绑定：块序号 + 总块数 + 文件哈希 作为 AEAD 附加数据（AD）
 *   - 密钥派生：PBKDF2-SHA256(150000) → 主密钥；HKDF-SHA256 → 文件子密钥
 *   - 内存安全：密钥使用后立即 fill(0) 清零（Zeroize 等价）
 *
 * 记录类型约定（verthys record type）：
 *   0x01 — 照片元数据（加密的 JSON：名称/MIME/大小/缩略图/块ID/哈希）
 *   0x05 — 照片数据块（加密的原始图片块）
 *
 * 数据块格式（base64 解码后）：
 *   [salt(16)] [seq(4 大端)] [total(4 大端)] [nonce(24)] [ciphertext+tag(变长)]
 *   AD = "VERTHYSPHOTO_CHUNK_v1" || seq(4) || total(4) || fileHash(32)
 *
 * 元数据格式（base64 解码后）：
 *   [salt(16)] [nonce(24)] [ciphertext+tag(变长)]
 *   AD = "VERTHYSPHOTO_META_v1"
 *   明文 = JSON { name, mime, size, thumbB64, chunkIds, fileHash, createdAt }
 *
 * 分层架构：
 *   constants/crypto_const.ts  ← 常量集中定义
 *   types/crypto.ts            ← 类型接口抽离
 *   utils/binary_codec.ts      ← 二进制编解码工具
 *   lib/crypto_error.ts        ← 标准化错误封装
 *   lib/crypto.ts              ← 加密层主逻辑（本文件）
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { blake3 } from "@noble/hashes/blake3";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToBase64, base64ToBytes } from "../utils/binary_codec";

import {
  PBKDF2_ITER, KEY_LEN, SALT_LEN, NONCE_LEN,
  SEQ_LEN, TOTAL_LEN, CHUNK_SIZE, FILE_HASH_LEN,
  META_AD_TEXT, CHUNK_AD_PREFIX_TEXT, FILE_KEY_INFO_TEXT,
  VENC_MAGIC_TEXT, VENC_VERSION,
  TYPE_PHOTO_META, TYPE_PHOTO_CHUNK,
} from "../constants/crypto_const";
import type { PhotoMeta, VencPhotoData } from "../types/crypto";
import {
  hexToBytes, bytesToHex, isValidHex, toArrayBuffer,
} from "../utils/binary_codec";
import {
  CryptoError, CryptoErrorKind,
  invalidInput, keyDerivationFailed, tagVerificationFailed,
  formatCorrupted, unsupportedVersion, wrapAsCryptoError,
} from "./crypto_error";

/* ------------------------------------------------------------------ *
 * 模块级预计算常量（AD 字节序列，避免重复编码）                       *
 * ------------------------------------------------------------------ */

const META_AD = new TextEncoder().encode(META_AD_TEXT);
const CHUNK_AD_PREFIX = new TextEncoder().encode(CHUNK_AD_PREFIX_TEXT);
const FILE_KEY_INFO = new TextEncoder().encode(FILE_KEY_INFO_TEXT);
const VENC_MAGIC = new TextEncoder().encode(VENC_MAGIC_TEXT);

/* ------------------------------------------------------------------ *
 * 密钥派生（公共函数，消除两处 PBKDF2 重复逻辑）                      *
 * ------------------------------------------------------------------ */

/**
 * 通用 PBKDF2-SHA256 密钥派生（公共函数）
 *
 * 统一 deriveMasterKey 与 encryptExportFile/decryptExportFile 中
 * 重复的 PBKDF2 逻辑：导入 baseKey → deriveBits。
 *
 * @param password 用户密码或令牌
 * @param salt 盐值（长度不限，由调用方保证）
 * @param iterations 迭代次数（默认 150000，与后端一致）
 * @param keyLengthBits 派生密钥位数（默认 256）
 * @returns 派生密钥的 ArrayBuffer
 * @throws CryptoError(INVALID_INPUT) 密码为空或盐值非法
 * @throws CryptoError(KEY_DERIVATION_FAILED) Web Crypto API 派生失败
 */
async function derivePBKDF2Bits(
  password: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITER,
  keyLengthBits: number = KEY_LEN * 8,
): Promise<ArrayBuffer> {
  if (!password || password.length === 0) {
    throw invalidInput("密码/令牌不能为空");
  }
  if (!salt || salt.length === 0) {
    throw invalidInput("盐值不能为空");
  }

  try {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]
    );
    return await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: toArrayBuffer(salt), iterations, hash: "SHA-256" },
      baseKey, keyLengthBits
    );
  } catch (e) {
    throw wrapAsCryptoError(e, CryptoErrorKind.KEY_DERIVATION_FAILED, "PBKDF2 密钥派生失败");
  }
}

/**
 * 从用户密码派生主密钥（PBKDF2-SHA256，150000 迭代）
 *
 * 与 verthys.ts 的 deriveFieldKey 不同：此处用于照片文件级主密钥。
 */
async function deriveMasterKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const bits = await derivePBKDF2Bits(password, salt);
  return new Uint8Array(bits);
}

/**
 * 从主密钥派生文件子密钥（HKDF-SHA256）
 * 每个文件独立的密钥，防止跨文件密钥重用
 */
function deriveFileKey(masterKey: Uint8Array, fileSalt: Uint8Array): Uint8Array {
  // HKDF: extract + expand
  const ikm = masterKey;
  const salt = fileSalt;
  const info = FILE_KEY_INFO;
  return hkdf(sha256, ikm, salt, info, KEY_LEN);
}

/* ------------------------------------------------------------------ *
 * 内存安全                                                            *
 * ------------------------------------------------------------------ */

/** 安全清零（Zeroize 等价） */
function zeroize(buf: Uint8Array): void {
  buf.fill(0);
}

/* ------------------------------------------------------------------ *
 * 哈希                                                                *
 * ------------------------------------------------------------------ */

/** 计算 BLAKE3 文件哈希（32 字节，用于完整性 + AD 绑定） */
export function computeFileHash(data: Uint8Array): Uint8Array {
  if (!data || data.length === 0) {
    throw invalidInput("待哈希数据不能为空");
  }
  return blake3(data, { dkLen: FILE_HASH_LEN });
}

/* ------------------------------------------------------------------ *
 * 元数据加密/解密                                                     *
 * ------------------------------------------------------------------ */

/** 加密元数据，返回 base64 串 */
export async function encryptMeta(meta: PhotoMeta, password: string): Promise<string> {
  if (!password || password.length === 0) {
    throw invalidInput("密码不能为空");
  }
  if (!meta || typeof meta !== "object") {
    throw invalidInput("元数据对象非法");
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const masterKey = await deriveMasterKey(password, salt);
  const fileKey = deriveFileKey(masterKey, salt);

  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify(meta));

  const cipher = xchacha20poly1305(fileKey, nonce, META_AD);
  const ciphertext = cipher.encrypt(plaintext);  // 末尾含 16 字节 tag

  // 组合: salt(16) | nonce(24) | ciphertext+tag
  const combined = new Uint8Array(SALT_LEN + NONCE_LEN + ciphertext.length);
  combined.set(salt, 0);
  combined.set(nonce, SALT_LEN);
  combined.set(ciphertext, SALT_LEN + NONCE_LEN);

  zeroize(masterKey);
  zeroize(fileKey);
  return bytesToBase64(combined);
}

/** 解密元数据，返回 PhotoMeta */
export async function decryptMeta(b64: string, password: string): Promise<PhotoMeta> {
  if (!password || password.length === 0) {
    throw invalidInput("密码不能为空");
  }
  if (!b64 || b64.length === 0) {
    throw invalidInput("密文 base64 不能为空");
  }

  const combined = base64ToBytes(b64);
  if (combined.length < SALT_LEN + NONCE_LEN) {
    throw formatCorrupted(`元数据密文过短（${combined.length} < ${SALT_LEN + NONCE_LEN}）`);
  }

  const salt = combined.slice(0, SALT_LEN);
  const nonce = combined.slice(SALT_LEN, SALT_LEN + NONCE_LEN);
  const ciphertext = combined.slice(SALT_LEN + NONCE_LEN);

  const masterKey = await deriveMasterKey(password, salt);
  const fileKey = deriveFileKey(masterKey, salt);

  const cipher = xchacha20poly1305(fileKey, nonce, META_AD);
  let plaintext: Uint8Array;
  try {
    plaintext = cipher.decrypt(ciphertext);  // 验证 tag，失败抛错
  } catch (e) {
    throw wrapAsCryptoError(e, CryptoErrorKind.TAG_VERIFICATION_FAILED, "元数据标签校验失败（密码错误或数据被篡改）");
  }

  zeroize(masterKey);
  zeroize(fileKey);
  const dec = new TextDecoder();

  let meta: PhotoMeta;
  try {
    meta = JSON.parse(dec.decode(plaintext)) as PhotoMeta;
  } catch (e) {
    throw formatCorrupted("解密后的元数据 JSON 解析失败", e);
  }
  return meta;
}

/* ------------------------------------------------------------------ *
 * 数据块加密/解密                                                     *
 * ------------------------------------------------------------------ */

/** 构造块 AD: "VERTHYSPHOTO_CHUNK_v1" || seq(4) || total(4) || fileHash(32) */
function buildChunkAD(seq: number, total: number, fileHashBytes: Uint8Array): Uint8Array {
  const ad = new Uint8Array(CHUNK_AD_PREFIX.length + SEQ_LEN + TOTAL_LEN + FILE_HASH_LEN);
  ad.set(CHUNK_AD_PREFIX, 0);
  const view = new DataView(ad.buffer);
  view.setUint32(CHUNK_AD_PREFIX.length, seq, false);     // 大端
  view.setUint32(CHUNK_AD_PREFIX.length + SEQ_LEN, total, false);
  ad.set(fileHashBytes, CHUNK_AD_PREFIX.length + SEQ_LEN + TOTAL_LEN);
  return ad;
}

/**
 * 加密单个数据块
 * 返回组合后的 Uint8Array: salt(16) | seq(4) | total(4) | nonce(24) | ciphertext+tag
 */
export async function encryptChunk(
  plaintext: Uint8Array,
  password: string,
  seq: number,
  total: number,
  fileHashHex: string
): Promise<Uint8Array> {
  if (!password || password.length === 0) {
    throw invalidInput("密码不能为空");
  }
  if (!plaintext || plaintext.length === 0) {
    throw invalidInput("待加密数据块不能为空");
  }
  if (!isValidHex(fileHashHex)) {
    throw invalidInput(`文件哈希 hex 非法: 长度=${fileHashHex?.length ?? 0}`);
  }
  if (fileHashHex.length !== FILE_HASH_LEN * 2) {
    throw invalidInput(`文件哈希长度不符（期望 ${FILE_HASH_LEN * 2} 字符，实际 ${fileHashHex.length}）`);
  }
  if (!Number.isInteger(seq) || seq < 0) {
    throw invalidInput(`块序号非法: ${seq}`);
  }
  if (!Number.isInteger(total) || total <= 0) {
    throw invalidInput(`总块数非法: ${total}`);
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const masterKey = await deriveMasterKey(password, salt);
  const fileKey = deriveFileKey(masterKey, salt);

  // 文件哈希 hex → bytes（用于 AD 绑定，防重放）
  const fileHashBytes = hexToBytes(fileHashHex);
  const ad = buildChunkAD(seq, total, fileHashBytes);

  const cipher = xchacha20poly1305(fileKey, nonce, ad);
  const ciphertext = cipher.encrypt(plaintext);  // 含 tag

  // 组合: salt(16) | seq(4) | total(4) | nonce(24) | ciphertext+tag
  const combined = new Uint8Array(SALT_LEN + SEQ_LEN + TOTAL_LEN + NONCE_LEN + ciphertext.length);
  combined.set(salt, 0);
  const view = new DataView(combined.buffer);
  view.setUint32(SALT_LEN, seq, false);
  view.setUint32(SALT_LEN + SEQ_LEN, total, false);
  combined.set(nonce, SALT_LEN + SEQ_LEN + TOTAL_LEN);
  combined.set(ciphertext, SALT_LEN + SEQ_LEN + TOTAL_LEN + NONCE_LEN);

  zeroize(masterKey);
  zeroize(fileKey);
  zeroize(ad);
  return combined;
}

/** 解密单个数据块，返回明文 Uint8Array */
export async function decryptChunk(
  combinedB64: string,
  password: string,
  fileHashHex: string
): Promise<{ plaintext: Uint8Array; seq: number; total: number }> {
  if (!password || password.length === 0) {
    throw invalidInput("密码不能为空");
  }
  if (!combinedB64 || combinedB64.length === 0) {
    throw invalidInput("密文 base64 不能为空");
  }
  if (!isValidHex(fileHashHex)) {
    throw invalidInput(`文件哈希 hex 非法: 长度=${fileHashHex?.length ?? 0}`);
  }
  if (fileHashHex.length !== FILE_HASH_LEN * 2) {
    throw invalidInput(`文件哈希长度不符（期望 ${FILE_HASH_LEN * 2} 字符，实际 ${fileHashHex.length}）`);
  }

  const combined = base64ToBytes(combinedB64);
  const minLen = SALT_LEN + SEQ_LEN + TOTAL_LEN + NONCE_LEN;
  if (combined.length < minLen) {
    throw formatCorrupted(`数据块密文过短（${combined.length} < ${minLen}）`);
  }

  const salt = combined.slice(0, SALT_LEN);
  const view = new DataView(combined.buffer, combined.byteOffset);
  const seq = view.getUint32(SALT_LEN, false);
  const total = view.getUint32(SALT_LEN + SEQ_LEN, false);
  const nonce = combined.slice(SALT_LEN + SEQ_LEN + TOTAL_LEN, SALT_LEN + SEQ_LEN + TOTAL_LEN + NONCE_LEN);
  const ciphertext = combined.slice(SALT_LEN + SEQ_LEN + TOTAL_LEN + NONCE_LEN);

  const masterKey = await deriveMasterKey(password, salt);
  const fileKey = deriveFileKey(masterKey, salt);

  const fileHashBytes = hexToBytes(fileHashHex);
  const ad = buildChunkAD(seq, total, fileHashBytes);

  const cipher = xchacha20poly1305(fileKey, nonce, ad);
  let plaintext: Uint8Array;
  try {
    plaintext = cipher.decrypt(ciphertext);  // 验证 tag + 序号
  } catch (e) {
    throw wrapAsCryptoError(e, CryptoErrorKind.TAG_VERIFICATION_FAILED, "数据块标签校验失败（密码错误、哈希不匹配或数据被篡改）");
  }

  zeroize(masterKey);
  zeroize(fileKey);
  zeroize(ad);
  return { plaintext, seq, total };
}

/* ------------------------------------------------------------------ *
 * 导出文件格式（.venc — Verthys Encrypted）                         *
 *                                                                    *
 * 单照片与多照片使用统一格式（count=1 即单照片），保证可被反向解析：    *
 *   [魔数 8B "VERTHYSPHOTO"] [版本 4B 大端] [照片数 4B 大端]              *
 *   for each photo:                                                   *
 *     [元数据长度 4B] [元数据 bytes]                                  *
 *     [块数 4B]                                                       *
 *     for each chunk: [块长度 4B] [块 bytes]                          *
 * ------------------------------------------------------------------ */

/** 将单张照片的加密元数据 + 块列表打包为 .venc 二进制格式（统一使用多照片格式，count=1，保证可解析） */
export async function packVencFile(
  metaB64: string,
  chunkB64List: string[]
): Promise<Uint8Array> {
  return packVencMultiFile([{ metaB64, chunkB64List }]);
}

/* ------------------------------------------------------------------ *
 * 多照片导出格式（.venc v2 — 多照片打包 + 外层 AES-GCM 加密）         *
 *                                                                    *
 * 文件结构:                                                           *
 *   [魔数 8B "VERTHYSPHOTO"] [版本 4B] [照片数 4B]                       *
 *   [外层 salt(16)] [外层 nonce(12)] [密文长度 4B]                    *
 *   [AES-GCM 密文 = 加密后的多照片打包数据]                            *
 *                                                                    *
 *   内层明文（加密前）:                                                *
 *     for each photo:                                                 *
 *       [元数据长度 4B] [元数据 bytes]                                 *
 *       [块数 4B]                                                     *
 *       for each chunk: [块长度 4B] [块 bytes]                        *
 * ------------------------------------------------------------------ */

/** 将多张照片的加密数据打包为 .venc 二进制（内层，未外层加密） */
export function packVencMultiFile(photos: VencPhotoData[]): Uint8Array {
  if (!photos || photos.length === 0) {
    throw invalidInput("照片数据列表不能为空");
  }

  const parts: Uint8Array[] = [];
  for (const photo of photos) {
    if (!photo.metaB64 || !photo.chunkB64List) {
      throw invalidInput("照片数据字段缺失（metaB64 或 chunkB64List 为空）");
    }

    const metaBytes = base64ToBytes(photo.metaB64);
    const metaLenBuf = new Uint8Array(4);
    new DataView(metaLenBuf.buffer).setUint32(0, metaBytes.length, false);
    parts.push(metaLenBuf, metaBytes);

    const chunkCountBuf = new Uint8Array(4);
    new DataView(chunkCountBuf.buffer).setUint32(0, photo.chunkB64List.length, false);
    parts.push(chunkCountBuf);

    for (const chunkB64 of photo.chunkB64List) {
      const chunkBytes = base64ToBytes(chunkB64);
      const chunkLenBuf = new Uint8Array(4);
      new DataView(chunkLenBuf.buffer).setUint32(0, chunkBytes.length, false);
      parts.push(chunkLenBuf, chunkBytes);
    }
  }

  let innerLen = 0;
  for (const p of parts) innerLen += p.length;

  const inner = new Uint8Array(innerLen);
  let off = 0;
  for (const p of parts) { inner.set(p, off); off += p.length; }

  const headerLen = VENC_MAGIC.length + 4 + 4;
  const out = new Uint8Array(headerLen + innerLen);
  off = 0;
  out.set(VENC_MAGIC, off); off += VENC_MAGIC.length;
  new DataView(out.buffer).setUint32(off, VENC_VERSION, false); off += 4;
  new DataView(out.buffer).setUint32(off, photos.length, false); off += 4;
  out.set(inner, off);
  return out;
}

/** 用随机令牌加密导出文件（AES-GCM 外层加密） */
export async function encryptExportFile(
  data: Uint8Array,
  token: string
): Promise<Uint8Array> {
  if (!token || token.length === 0) {
    throw invalidInput("加密令牌不能为空");
  }
  if (!data || data.length === 0) {
    throw invalidInput("待加密数据不能为空");
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // 复用公共 PBKDF2 派生函数，消除重复逻辑
  const rawKeyBits = await derivePBKDF2Bits(token, salt);
  const key = await crypto.subtle.importKey(
    "raw", rawKeyBits, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
  );

  let ct: ArrayBuffer;
  try {
    ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv) },
      key,
      toArrayBuffer(data)
    );
  } catch (e) {
    throw wrapAsCryptoError(e, CryptoErrorKind.KEY_DERIVATION_FAILED, "AES-GCM 外层加密失败");
  }

  // 格式: salt(16) | iv(12) | ct
  const out = new Uint8Array(SALT_LEN + 12 + ct.byteLength);
  out.set(salt, 0);
  out.set(iv, SALT_LEN);
  out.set(new Uint8Array(ct), SALT_LEN + 12);
  return out;
}

/**
 * 解密导出文件的外层 AES-256-GCM 加密（与 encryptExportFile 互逆）
 * 格式: salt(16) | iv(12) | ciphertext
 * @param encryptedData 加密数据（含 salt + iv + 密文）
 * @param token 加密令牌（导出时生成的 hex 字符串）
 * @returns 解密后的 .venc 容器字节数组
 */
export async function decryptExportFile(encryptedData: Uint8Array, token: string): Promise<Uint8Array> {
  if (!token || token.length === 0) {
    throw invalidInput("加密令牌不能为空");
  }
  if (!encryptedData || encryptedData.length < SALT_LEN + 12) {
    throw formatCorrupted(`加密数据过短（${encryptedData?.length ?? 0} < ${SALT_LEN + 12}）`);
  }

  // 读取 salt(16) 与 iv(12)，剩余为密文
  const salt = encryptedData.slice(0, SALT_LEN);
  const iv = encryptedData.slice(SALT_LEN, SALT_LEN + 12);
  const ct = encryptedData.slice(SALT_LEN + 12);

  // 复用公共 PBKDF2 派生函数，消除重复逻辑
  const rawKeyBits = await derivePBKDF2Bits(token, salt);
  const key = await crypto.subtle.importKey(
    "raw", rawKeyBits, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );

  let decrypted: ArrayBuffer;
  try {
    decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv) },
      key,
      toArrayBuffer(ct)
    );
  } catch (e) {
    throw wrapAsCryptoError(e, CryptoErrorKind.TAG_VERIFICATION_FAILED, "AES-GCM 外层解密失败（令牌错误或数据被篡改）");
  }
  return new Uint8Array(decrypted);
}

/**
 * 拆包 .venc 多照片容器（与 packVencMultiFile 互逆）
 * 单照片容器（packVencFile，count=1）同样适用此函数
 * @param vencBytes .venc 容器字节数组（已解外层加密）
 * @returns 照片数据数组（metaB64 与 chunkB64List 均为加密后的 base64）
 */
export function unpackVencMultiFile(vencBytes: Uint8Array): VencPhotoData[] {
  if (!vencBytes || vencBytes.length === 0) {
    throw formatCorrupted("venc 数据为空");
  }

  // 校验 magic 头（8 字节 "VERTHYSPHOTO"）
  const magicLen = VENC_MAGIC.length;
  if (vencBytes.length < magicLen + 8) {
    throw formatCorrupted(`venc 数据过短（${vencBytes.length} < ${magicLen + 8}）`);
  }
  const magic = new TextDecoder().decode(vencBytes.slice(0, magicLen));
  if (magic !== VENC_MAGIC_TEXT) {
    throw formatCorrupted(`venc magic 不匹配（期望 "${VENC_MAGIC_TEXT}"，实际 "${magic}"）`);
  }

  // 使用 DataView 读取大端整数（注意 byteOffset，避免切片视图问题）
  const view = new DataView(vencBytes.buffer, vencBytes.byteOffset, vencBytes.byteLength);
  let offset = magicLen;

  // 版本号 (u32 大端)
  const version = view.getUint32(offset, false); offset += 4;
  if (version !== VENC_VERSION) {
    throw unsupportedVersion(`不支持的 venc 版本: ${version}（当前支持 ${VENC_VERSION}）`);
  }

  // 照片数 (u32 大端)
  const count = view.getUint32(offset, false); offset += 4;
  if (count === 0) {
    throw formatCorrupted("venc 照片数为 0");
  }

  const photos: VencPhotoData[] = [];
  for (let i = 0; i < count; i++) {
    // 元数据长度 + 元数据 bytes
    if (offset + 4 > vencBytes.length) {
      throw formatCorrupted(`第 ${i + 1} 张照片元数据长度字段越界`);
    }
    const metaLen = view.getUint32(offset, false); offset += 4;
    if (offset + metaLen > vencBytes.length) {
      throw formatCorrupted(`第 ${i + 1} 张照片元数据越界（offset=${offset}, metaLen=${metaLen}）`);
    }
    const metaBytes = vencBytes.slice(offset, offset + metaLen);
    offset += metaLen;
    const metaB64 = bytesToBase64(metaBytes);

    // 块数 (u32 大端)
    if (offset + 4 > vencBytes.length) {
      throw formatCorrupted(`第 ${i + 1} 张照片块数字段越界`);
    }
    const chunkCount = view.getUint32(offset, false); offset += 4;
    const chunkB64List: string[] = [];
    for (let c = 0; c < chunkCount; c++) {
      if (offset + 4 > vencBytes.length) {
        throw formatCorrupted(`第 ${i + 1} 张照片第 ${c + 1} 块长度字段越界`);
      }
      const chunkLen = view.getUint32(offset, false); offset += 4;
      if (offset + chunkLen > vencBytes.length) {
        throw formatCorrupted(`第 ${i + 1} 张照片第 ${c + 1} 块数据越界（offset=${offset}, chunkLen=${chunkLen}）`);
      }
      const chunkBytes = vencBytes.slice(offset, offset + chunkLen);
      offset += chunkLen;
      chunkB64List.push(bytesToBase64(chunkBytes));
    }
    photos.push({ metaB64, chunkB64List });
  }
  return photos;
}

/**
 * 拆包 .venc 单照片容器（与 packVencFile 互逆）
 * 单照片容器使用统一格式（count=1），直接复用多照片解析
 * @param vencBytes .venc 容器字节数组（已解外层加密）
 * @returns 单张照片数据（metaB64 与 chunkB64List 均为加密后的 base64）
 */
export function unpackVencFile(vencBytes: Uint8Array): VencPhotoData {
  const photos = unpackVencMultiFile(vencBytes);
  if (photos.length === 0) {
    throw formatCorrupted("空的照片容器");
  }
  return photos[0];
}

/** 生成随机令牌（默认 32 bytes hex） */
export function generateRandomToken(bytes: number = 32): string {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw invalidInput(`令牌字节数非法: ${bytes}`);
  }
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}

/* ------------------------------------------------------------------ *
 * 独立密码加密层（per-field AES-GCM）                                  *
 *                                                                    *
 * 与 DLL 的加密库主加密相互独立：                                      *
 *   - DLL 负责 verthys 级别的整体加密（主密码派生）                      *
 *   - 此层为单条密码追加的细粒度加密，需用户独立密钥才能解密           *
 *   - encKey 不存储明文，仅存 salt + iv + ciphertext                  *
 *                                                                    *
 * 从 verthys.ts 迁移至此，verthys.ts 仅保留纯 IPC 调用                    *
 * ------------------------------------------------------------------ */

/** 从用户密钥派生 AES-GCM 密钥 */
async function deriveFieldKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: toArrayBuffer(salt), iterations: PBKDF2_ITER, hash: "SHA-256" },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

/** 加密单个密码字段，返回 { salt, iv, ct } 的 base64 组合串 */
export async function encryptPasswordField(plain: string, passphrase: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveFieldKey(passphrase, salt);
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plain));
  // 组合格式: salt(16) | iv(12) | ct
  const combined = new Uint8Array(salt.length + iv.length + ct.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ct), salt.length + iv.length);
  return bytesToBase64(combined);
}

/** 解密单个密码字段 */
export async function decryptPasswordField(b64: string, passphrase: string): Promise<string> {
  const combined = base64ToBytes(b64);
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ct = combined.slice(28);
  const key = await deriveFieldKey(passphrase, salt);
  const dec = new TextDecoder();
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return dec.decode(pt);
}

/* ------------------------------------------------------------------ *
 * 再导出（保持原有 API 完全不变）                                     *
 *                                                                    *
 * 上层组件（PhotoAlbum.vue 等）通过 `from "../../lib/crypto"` 导入   *
 * 常量与类型，此处再导出确保无需修改调用方。                          *
 * ------------------------------------------------------------------ */

export { CHUNK_SIZE, TYPE_PHOTO_META, TYPE_PHOTO_CHUNK };
export { bytesToHex };
export type { PhotoMeta, VencPhotoData };
