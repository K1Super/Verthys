/*
 * crypto/venc_common.ts — VENC 容器共享基础：密钥派生、清零、帧头/AD 构造、
 * 清单契约校验与公开结构解析。
 *
 * 打包侧与解包侧共用同一份常量与校验，避免两侧契约漂移。
 * 本模块不持有模块密钥或文件密钥。
 */
import { base64ToBytes, isValidHex, toArrayBuffer } from "../../utils/codec/binary_codec";

import {
  PBKDF2_ITER, KEY_LEN, SALT_LEN, NONCE_LEN, TAG_LEN,
  FILE_HASH_LEN, MAX_PHOTO_BYTES,
  VENC_MAGIC_TEXT,
  VENC_FRAME_HEADER_BYTES, PARSE_MAX_FRAME_COUNT,
} from "../../constants/crypto_const";
import type { PhotoMeta, LightMeta } from "../../types/crypto";
import {
  CryptoErrorKind,
  invalidInput, formatCorrupted, wrapAsCryptoError,
} from "../util/crypto_error";

/* ------------------------------------------------------------------ *
 * 模块级预计算常量                                                    *
 * ------------------------------------------------------------------ */

export const VENC_MAGIC = new TextEncoder().encode(VENC_MAGIC_TEXT);

/* ------------------------------------------------------------------ *
 * 密钥派生                                                            *
 * ------------------------------------------------------------------ */

/**
 * 通用 PBKDF2-SHA256 密钥派生。
 *
 * @param password 用户密码或导出令牌
 * @param salt 盐值（长度不限，由调用方保证）
 * @param iterations 迭代次数（默认 150000）
 * @param keyLengthBits 派生密钥位数（默认 256）
 * @returns 派生密钥的 ArrayBuffer
 * @throws CryptoError(INVALID_INPUT) 密码为空或盐值非法
 * @throws CryptoError(KEY_DERIVATION_FAILED) Web Crypto API 派生失败
 */
export async function derivePBKDF2Bits(
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

/* ------------------------------------------------------------------ *
 * 内存安全                                                            *
 * ------------------------------------------------------------------ */

/** 安全清零（Zeroize 等价） */
export function zeroize(buf: Uint8Array): void {
  buf.fill(0);
}

/* ------------------------------------------------------------------ *
 * 公开结构解析                                                        *
 * ------------------------------------------------------------------ */

/** 取出包裹态文件密钥内的文件盐（公开数据，不接触密钥材料） */
export function extractSlimFileSalt(wrappedFileKeyB64: string): Uint8Array {
  if (!wrappedFileKeyB64) {
    throw invalidInput("包裹态文件密钥不能为空");
  }
  const combined = base64ToBytes(wrappedFileKeyB64);
  if (combined.length < SALT_LEN + NONCE_LEN + TAG_LEN) {
    throw formatCorrupted("包裹态文件密钥过短");
  }
  return combined.slice(0, SALT_LEN);
}

/* ------------------------------------------------------------------ *
 * 可移植备份容器（自描述信封 + 内容密钥封装 + 逐帧 AEAD）              *
 *                                                                    *
 * 布局：                                                              *
 *   [Outer Header 42B 明文]：magic(4) version(2) flags(2) kdf_id(2)   *
 *                            iterations(4) salt(16) iv(12)           *
 *   [Wrapped Content Key 48B]：AES-256-GCM 加密 payload_key(32)，     *
 *      密钥 = PBKDF2(token, salt, iterations)，nonce = iv，           *
 *      AD = Outer Header 全字节                                       *
 *   [Frame]*：帧头 [type(1) seq(4 大端) len(4 大端)] +                *
 *             [nonce(24)] + [ciphertext+tag]                          *
 *      帧密钥 = payload_key（XChaCha20-Poly1305），                   *
 *      帧 AD = 帧头(9B) | salt(16B)                                   *
 *   [Trailer 帧]：frame_count(u32) + body_bytes(u64) 交叉校验         *
 *                                                                    *
 * 帧类型：1=清单（明文 JSON，经内容密钥逐帧加密）、                    *
 *         2=原始明文块负载（不依赖任何模块密钥）、                     *
 *         3=尾部校验帧                                                *
 *                                                                    *
 * KDF 参数自描述：iterations 写入头部，解密端按读取值执行派生。       *
 * ------------------------------------------------------------------ */

/** 把本地存储元数据投影为容器清单（不携带布局/密钥/块哈希） */
export function toLightMeta(local: PhotoMeta, chunkCount: number): LightMeta {
  if (!Number.isInteger(chunkCount) || chunkCount <= 0) {
    throw invalidInput(`照片 "${local.name}" 块数非法: ${chunkCount}`);
  }
  const meta: LightMeta = {
    name: local.name,
    mime: local.mime,
    size: local.size,
    thumbB64: local.thumbB64,
    fileHash: local.fileHash,
    createdAt: local.createdAt,
    chunkCount,
  };
  /* 打包侧与解包侧使用同一字段契约：本地元数据可能来自历史记录，
   * 任何超出容器清单上限的字段都必须在产出前拒绝，不得生成注定
   * 无法被自身导入器接受的备份文件。 */
  assertLightMetaShape(meta);
  return meta;
}

/** 帧头编码：type(1) + seq(4 大端) + len(4 大端) */
export function encodeFrameHeader(type: number, seq: number, len: number): Uint8Array {
  const buf = new Uint8Array(VENC_FRAME_HEADER_BYTES);
  buf[0] = type;
  const view = new DataView(buf.buffer);
  view.setUint32(1, seq, false);
  view.setUint32(5, len, false);
  return buf;
}

/** 帧 AD：帧头 + 容器盐（跨容器拼接帧会因盐不同而认证失败） */
export function buildFrameAd(
  type: number,
  seq: number,
  len: number,
  salt: Uint8Array,
): Uint8Array {
  const ad = new Uint8Array(VENC_FRAME_HEADER_BYTES + SALT_LEN);
  ad.set(encodeFrameHeader(type, seq, len), 0);
  ad.set(salt, VENC_FRAME_HEADER_BYTES);
  return ad;
}

/** 清单的精确字段集合：拒绝未知字段，保证格式契约唯一 */
const LIGHT_META_KEYS = [
  "chunkCount", "createdAt", "fileHash", "mime", "name", "size", "thumbB64",
];

/** 清单形状校验（解包侧防御，结构来自外部输入） */
export function assertLightMetaShape(lm: unknown): asserts lm is LightMeta {
  if (typeof lm !== "object" || lm === null || Array.isArray(lm)) {
    throw formatCorrupted("清单结构非法");
  }
  const keys = Object.keys(lm).sort();
  if (keys.length !== LIGHT_META_KEYS.length || keys.join(",") !== LIGHT_META_KEYS.join(",")) {
    throw formatCorrupted(`清单字段集合非法: ${keys.join(",")}`);
  }
  const meta = lm as Record<string, unknown>;
  if (typeof meta.name !== "string" || meta.name.length === 0
    || new TextEncoder().encode(meta.name).length > 1024) {
    throw formatCorrupted("清单 name 非法");
  }
  if (typeof meta.mime !== "string" || new TextEncoder().encode(meta.mime).length > 128) {
    throw formatCorrupted("清单 mime 非法");
  }
  if (!Number.isInteger(meta.size) || (meta.size as number) <= 0
    || (meta.size as number) > MAX_PHOTO_BYTES) {
    throw formatCorrupted(`清单 size 非法: ${String(meta.size)}`);
  }
  if (typeof meta.thumbB64 !== "string") {
    throw formatCorrupted("清单 thumbB64 非法");
  }
  let thumbBytes = 0;
  if (meta.thumbB64.length > 0) {
    try {
      thumbBytes = base64ToBytes(meta.thumbB64).length;
    } catch {
      throw formatCorrupted("清单 thumbB64 不是合法 base64");
    }
    if (thumbBytes > 2 * 1024 * 1024) {
      throw formatCorrupted(`清单缩略图超过上限: ${thumbBytes}`);
    }
  }
  if (typeof meta.fileHash !== "string" || !isValidHex(meta.fileHash)
    || meta.fileHash.length !== FILE_HASH_LEN * 2) {
    throw formatCorrupted("清单 fileHash 非法");
  }
  if (!Number.isFinite(meta.createdAt) || (meta.createdAt as number) < 0) {
    throw formatCorrupted(`清单 createdAt 非法: ${String(meta.createdAt)}`);
  }
  if (!Number.isInteger(meta.chunkCount) || (meta.chunkCount as number) <= 0
    || (meta.chunkCount as number) > PARSE_MAX_FRAME_COUNT) {
    throw formatCorrupted(`清单 chunkCount 非法: ${String(meta.chunkCount)}`);
  }
}
