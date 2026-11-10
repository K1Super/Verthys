/*
 * crypto.ts — 前端剩余密码学能力（VENC 备份容器 + 字段密码 + BLAKE3）
 *
 * 职责边界：
 *   - VENC 备份容器：用户导出令牌 → PBKDF2 → 封装内容密钥 → 逐帧 XChaCha20-Poly1305
 *   - 独立密码字段：per-field AES-GCM（清单密码等既有记录）
 *   - BLAKE3 完整性校验与公开结构解析（包裹态密钥盐等）
 *
 * 照片/文件记录的内容加密不在本文件：已下沉到 Tauri worker 的 module_crypto 模块。
 * 本文件不执行模块密钥派生，也不持有模块密钥或文件密钥。
 *
 * 容器布局（导出文件）：
 *   外层头 42B（magic/version/flags/kdf/iterations/salt/iv）+ 包裹内容密钥 48B + 逐帧
 *   帧 AD = type(1) || seq(4 大端) || len(4 大端) || salt(16)
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { blake3 } from "@noble/hashes/blake3";
import { bytesToBase64, base64ToBytes, bytesToHex, isValidHex, toArrayBuffer } from "../utils/binary_codec";

import {
  PBKDF2_ITER, KEY_LEN, SALT_LEN, NONCE_LEN, TAG_LEN,
  CHUNK_SIZE, FILE_HASH_LEN, MAX_PHOTO_BYTES,
  VENC_MAGIC_TEXT, VENC_VERSION, VENC_KDF_ITERATIONS,
  VENC_OUTER_HEADER_BYTES, VENC_WRAPPED_KEY_BYTES, VENC_FRAME_HEADER_BYTES,
  VENC_TRAILER_PAYLOAD_BYTES,
  VENC_KDF_ID_PBKDF2_SHA256,
  VENC_FRAME_TYPE_LIGHT_META, VENC_FRAME_TYPE_CHUNK, VENC_FRAME_TYPE_TRAILER,
  PARSE_MAX_FRAME_COUNT, PARSE_MAX_FRAME_BYTES, PARSE_MAX_CONTAINER_BYTES,
  TYPE_PHOTO_META, TYPE_PHOTO_CHUNK,
} from "../constants/crypto_const";
import type {
  PhotoMeta, LightMeta, VencPhotoSpec,
} from "../types/crypto";
import {
  CryptoErrorKind,
  invalidInput, formatCorrupted, unsupportedVersion, wrapAsCryptoError,
} from "./crypto_error";

/* ------------------------------------------------------------------ *
 * 模块级预计算常量                                                    *
 * ------------------------------------------------------------------ */

const VENC_MAGIC = new TextEncoder().encode(VENC_MAGIC_TEXT);

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

/* ------------------------------------------------------------------ *
 * 内存安全                                                            *
 * ------------------------------------------------------------------ */

/** 安全清零（Zeroize 等价） */
function zeroize(buf: Uint8Array): void {
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
function encodeFrameHeader(type: number, seq: number, len: number): Uint8Array {
  const buf = new Uint8Array(VENC_FRAME_HEADER_BYTES);
  buf[0] = type;
  const view = new DataView(buf.buffer);
  view.setUint32(1, seq, false);
  view.setUint32(5, len, false);
  return buf;
}

/** 帧 AD：帧头 + 容器盐（跨容器拼接帧会因盐不同而认证失败） */
function buildFrameAd(type: number, seq: number, len: number, salt: Uint8Array): Uint8Array {
  const ad = new Uint8Array(VENC_FRAME_HEADER_BYTES + SALT_LEN);
  ad.set(encodeFrameHeader(type, seq, len), 0);
  ad.set(salt, VENC_FRAME_HEADER_BYTES);
  return ad;
}

/** 逐帧加密：帧头 + nonce + ciphertext+tag 拼装 */
function encryptFrame(
  contentKey: Uint8Array,
  salt: Uint8Array,
  type: number,
  seq: number,
  payload: Uint8Array,
): Uint8Array {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const ad = buildFrameAd(type, seq, payload.length, salt);
  const cipher = xchacha20poly1305(contentKey, nonce, ad);
  const ct = cipher.encrypt(payload); // 末尾含 16B tag

  const out = new Uint8Array(VENC_FRAME_HEADER_BYTES + NONCE_LEN + ct.length);
  out.set(encodeFrameHeader(type, seq, payload.length), 0);
  out.set(nonce, VENC_FRAME_HEADER_BYTES);
  out.set(ct, VENC_FRAME_HEADER_BYTES + NONCE_LEN);
  zeroize(ad);
  return out;
}

/** 容器照片输入的结构前置校验（打包侧防御，避免容量字段自相矛盾或发出即损坏） */
function assertVencPhotoShape(photo: VencPhotoSpec): void {
  const lm = photo.lightMeta;
  if (!lm || !Array.isArray(photo.chunkBytes)) {
    throw invalidInput("照片容器数据字段缺失");
  }
  /* 与解包侧共享同一清单契约：名称/类型/缩略图/时间/块数上限均在此
   * 一次性校验，避免打包成功但导入必然被拒的产物。 */
  try {
    assertLightMetaShape(lm);
  } catch (e) {
    throw invalidInput(
      `照片清单字段非法: ${e instanceof Error ? e.message : String(e)}`,
      e,
    );
  }
  if (lm.chunkCount !== photo.chunkBytes.length) {
    throw invalidInput(
      `照片 "${lm.name}" 块数不一致: chunkCount=${lm.chunkCount}, 实际块=${photo.chunkBytes.length}`,
    );
  }
  if (!Number.isFinite(lm.size) || lm.size <= 0 || lm.size > MAX_PHOTO_BYTES) {
    throw invalidInput(`照片 "${lm.name}" 字节数非法: ${lm.size}`);
  }
  if (!isValidHex(lm.fileHash) || lm.fileHash.length !== FILE_HASH_LEN * 2) {
    throw invalidInput(`照片 "${lm.name}" 文件哈希非法`);
  }
  let total = 0;
  const hasher = blake3.create({ dkLen: FILE_HASH_LEN });
  for (let i = 0; i < photo.chunkBytes.length; i++) {
    const chunk = photo.chunkBytes[i];
    if (!(chunk instanceof Uint8Array) || chunk.length === 0 || chunk.length > CHUNK_SIZE) {
      throw invalidInput(`照片 "${lm.name}" 第 ${i + 1} 块长度非法: ${chunk?.length}`);
    }
    total += chunk.length;
    hasher.update(chunk);
  }
  if (total !== lm.size) {
    throw invalidInput(`照片 "${lm.name}" 块长之和与 size 不一致: ${total} ≠ ${lm.size}`);
  }
  const actualHash = bytesToHex(hasher.digest());
  if (actualHash !== lm.fileHash) {
    throw invalidInput(
      `照片 "${lm.name}" 文件哈希不符: 期望 ${lm.fileHash}，实际 ${actualHash}`,
    );
  }
}

/** 清单的精确字段集合：拒绝未知字段，保证格式契约唯一 */
const LIGHT_META_KEYS = [
  "chunkCount", "createdAt", "fileHash", "mime", "name", "size", "thumbB64",
];

/** 清单形状校验（解包侧防御，结构来自外部输入） */
function assertLightMetaShape(lm: unknown): asserts lm is LightMeta {
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

/**
 * 将照片容器数据打包为 .venc 备份文件。
 *
 * 收集全部输出段后一次性拼接返回；大文件单文件导出应改用
 * {@link packVencStreamed} 流式产出以压低内存峰值。
 *
 * @param photos 照片容器数据（清单 + 原始明文块字节）
 * @param token 导出令牌（外层内容密钥封装的凭据）
 * @returns .venc 完整字节（头部 + 封装密钥 + 帧序列 + 尾部校验帧）
 */
export async function packVenc(
  photos: VencPhotoSpec[],
  token: string,
): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  await packVencInternal(photos, token, async (part) => {
    parts.push(part);
  });
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/**
 * 将照片容器数据流式打包为 .venc 备份文件，逐段交给写入回调。
 *
 * 与 {@link packVenc} 共享同一打包核心：不缓存帧序列，每产生一段
 * （首段为头部 + 封装密钥，其后为单个加密帧，末尾为尾部校验帧）即
 * `await emit(part)`，由调用方决定落盘 / 拼接策略；回调返回 Promise
 * 以支持背压（如流式追加落盘）。回调抛错即中止打包并向上传播。
 *
 * 注意：本入口要求全部块字节已在内存（`photos[*].chunkBytes`）。容器体积
 * 与内存同阶；GB 级单文件导出应改用 {@link packVencStreamedLazy}。
 *
 * @param photos 照片容器数据（清单 + 原始明文块字节）
 * @param token 导出令牌（外层内容密钥封装的凭据）
 * @param emit 分段写出回调（按容器字节顺序调用）
 */
export async function packVencStreamed(
  photos: VencPhotoSpec[],
  token: string,
  emit: (part: Uint8Array) => Promise<void>,
): Promise<void> {
  await packVencInternal(photos, token, emit);
}

/**
 * 惰性流式打包：不持有全部块字节，逐张加载、逐帧写出。
 *
 * Why：单文件容器的体积可达 GB 级。若先把每张照片的块密文全部解码驻留，
 * 内存峰值与容器总字节同阶（base64→字节还会瞬时翻倍），大库导出会在体积
 * 上限校验之前就把进程打满。本入口在打包循环内调用一次 `loadPhoto`，
 * 该照片的帧写出后引用即失效，峰值收敛到「一张照片 + 一个输出段」。
 *
 * 结构校验：每张加载结果仍走 `assertVencPhotoShape`（块数/哈希声明与负载
 * 逐块核对），任何不符立即拒绝，绝不产出「注定无法解析」的容器。
 *
 * 逐张跳过：加载函数返回 null 表示该张不可导出（元数据/块缺失），该张不产生
 * 任何帧、不占位；尾部校验帧按实际产出的帧计数，容器仍然自洽。调用方据此
 * 保留「个别照片失败、其余照常导出」的既有语义，而不必为跳过而在内存里
 * 预先装配全部照片。
 *
 * @param count 照片数（进度与循环上界）
 * @param token 导出令牌
 * @param loadPhoto 按序号加载该照片的完整容器数据（含块字节）；返回 null 表示跳过
 * @param emit 分段写出回调（按容器字节顺序调用）
 */
export async function packVencStreamedLazy(
  count: number,
  token: string,
  loadPhoto: (index: number) => Promise<VencPhotoSpec | null>,
  emit: (part: Uint8Array) => Promise<void>,
): Promise<void> {
  if (!Number.isInteger(count) || count <= 0) {
    throw invalidInput("照片数据列表不能为空");
  }
  await packVencCore(
    count,
    async (index) => {
      const spec = await loadPhoto(index);
      if (spec === null) return null;
      assertVencPhotoShape(spec);
      return spec;
    },
    token,
    emit,
  );
}

/** 预估 .venc 容器总字节数（打包前进度分母）。 */
export function estimateVencTotalBytes(photos: VencPhotoSpec[]): number {
  const frameOverhead = VENC_FRAME_HEADER_BYTES + NONCE_LEN + TAG_LEN;
  let total = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
  for (const photo of photos) {
    const lmBytes = new TextEncoder().encode(JSON.stringify(photo.lightMeta)).length;
    total += frameOverhead + lmBytes;
    for (const chunk of photo.chunkBytes) {
      total += frameOverhead + chunk.length;
    }
  }
  return total + frameOverhead + VENC_TRAILER_PAYLOAD_BYTES;
}

/**
 * 容器固定开销（前缀 + 尾部校验帧），与打包核心逐字节一致。
 *
 * 供调用方在惰性导出前做体积预算：容器实际产出 = 本常量 + Σ单张帧字节。
 */
export const VENC_CONTAINER_FIXED_BYTES =
  VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES
  + VENC_FRAME_HEADER_BYTES + NONCE_LEN + TAG_LEN + VENC_TRAILER_PAYLOAD_BYTES;

/**
 * 单张照片在容器内的帧字节数（轻量头帧 + 逐块帧），与打包核心逐字节一致。
 *
 * 惰性出口的调用方据此累计体积预算：超限即可在写出该张之前中止，
 * 不会留下超限产物。
 *
 * @param lightMeta 轻量头（明文，按 JSON 序列化计入）
 * @param chunkLengths 逐块密文字节长度（顺序无关，仅求和）
 */
export function vencPhotoFramesBytes(
  lightMeta: LightMeta,
  chunkLengths: readonly number[],
): number {
  const frameOverhead = VENC_FRAME_HEADER_BYTES + NONCE_LEN + TAG_LEN;
  let total = frameOverhead + new TextEncoder().encode(JSON.stringify(lightMeta)).length;
  for (const len of chunkLengths) total += frameOverhead + len;
  return total;
}

/**
 * 打包入口（快照式）：先对全部照片做结构预检，再走共享核心。
 *
 * @param photos 照片容器数据（块字节已全部驻留）
 * @param token 导出令牌
 * @param emit 分段写出回调
 */
async function packVencInternal(
  photos: VencPhotoSpec[],
  token: string,
  emit: (part: Uint8Array) => Promise<void>,
): Promise<void> {
  if (!photos || photos.length === 0) {
    throw invalidInput("照片数据列表不能为空");
  }
  for (const photo of photos) assertVencPhotoShape(photo);
  await packVencCore(photos.length, async (index) => photos[index], token, emit);
}

/**
 * 打包核心（快照式 / 惰性式共用）：外层头部 + 内容密钥封装 + 逐帧 AEAD
 * + 尾部校验帧，全程逐段向 `emit` 产出，不缓存帧序列。
 *
 * 照片数据经 `loadPhoto` 逐张取用：惰性入口因此只驻留当前照片的块字节，
 * 帧写出后即由作用域释放。
 */
async function packVencCore(
  count: number,
  loadPhoto: (index: number) => Promise<VencPhotoSpec | null>,
  token: string,
  emit: (part: Uint8Array) => Promise<void>,
): Promise<void> {
  if (!token || token.length === 0) {
    throw invalidInput("加密令牌不能为空");
  }

  // 1. 外层头部（明文，42B）
  const header = new Uint8Array(VENC_OUTER_HEADER_BYTES);
  header.set(VENC_MAGIC, 0);
  const hv = new DataView(header.buffer);
  hv.setUint16(4, VENC_VERSION, false);
  hv.setUint16(6, 0, false); // flags 保留
  hv.setUint16(8, VENC_KDF_ID_PBKDF2_SHA256, false);
  hv.setUint32(10, VENC_KDF_ITERATIONS, false);
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  header.set(salt, 14);
  header.set(iv, 30);

  // 2. 随机内容密钥（帧负载加密钥，仅封装后落盘）
  const contentKey = crypto.getRandomValues(new Uint8Array(KEY_LEN));

  // 3. 封装内容密钥：AES-256-GCM，AD 绑定完整头部字节
  const kebBits = await derivePBKDF2Bits(token, salt, VENC_KDF_ITERATIONS);
  const kek = await crypto.subtle.importKey(
    "raw", kebBits, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  // 派生中间量仅用于导入 WebCrypto 密钥对象，用毕立即清零
  zeroize(new Uint8Array(kebBits));
  let wrappedBuf: ArrayBuffer;
  try {
    wrappedBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: toArrayBuffer(header) },
      kek,
      toArrayBuffer(contentKey),
    );
  } catch (e) {
    zeroize(contentKey);
    throw wrapAsCryptoError(e, CryptoErrorKind.KEY_DERIVATION_FAILED, "内容密钥封装失败");
  }

  try {
    // 首段：外层头部 + 封装密钥（容器前 90 字节，明密结合无帧头）
    const prefix = new Uint8Array(VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES);
    prefix.set(header, 0);
    prefix.set(new Uint8Array(wrappedBuf), VENC_OUTER_HEADER_BYTES);
    await emit(prefix);

    // 4. 帧序列：每张照片一个轻量头帧 + 逐块一个块帧，全局 seq 单调递增
    let seq = 0;
    let frameCount = 0;
    let bodyBytes = 0;
    for (let pi = 0; pi < count; pi++) {
      // 逐张取用：惰性入口在此刻才加载块字节，帧写出后由作用域释放。
      //   加载结果为 null 表示该张不可导出：不产生任何帧（尾部帧计数按实际产出）。
      const photo = await loadPhoto(pi);
      if (!photo) continue;
      const lmBytes = new TextEncoder().encode(JSON.stringify(photo.lightMeta));
      try {
        await emit(encryptFrame(contentKey, salt, VENC_FRAME_TYPE_LIGHT_META, seq++, lmBytes));
      } finally {
        // 清单含文件名/缩略图：加密写出后立即清零，不在打包器堆中驻留
        zeroize(lmBytes);
      }
      frameCount += 1;
      bodyBytes += lmBytes.length;
      for (const chunk of photo.chunkBytes) {
        await emit(encryptFrame(contentKey, salt, VENC_FRAME_TYPE_CHUNK, seq++, chunk));
        frameCount += 1;
        bodyBytes += chunk.length;
      }
    }

    // 5. 尾部校验帧：frame_count(u32) + body_bytes(u64) 交叉校验
    const trailerPayload = new Uint8Array(VENC_TRAILER_PAYLOAD_BYTES);
    const tv = new DataView(trailerPayload.buffer);
    tv.setUint32(0, frameCount, false);
    tv.setBigUint64(4, BigInt(bodyBytes), false);
    await emit(encryptFrame(contentKey, salt, VENC_FRAME_TYPE_TRAILER, seq, trailerPayload));
  } finally {
    zeroize(contentKey);
  }
}

/** 已打开的容器上下文 */
interface VencContext {
  contentKey: Uint8Array;
  salt: Uint8Array;
  view: DataView;
  offset: number;
  end: number;
}

/** 单个帧的元信息（不包含解密后的负载） */
interface VencFrameMeta {
  type: number;
  seq: number;
  len: number;
  nextOffset: number;
}

/** 流式解码回调：导入链路逐块重封装，避免整包明文驻留 */
export interface VencStreamHandlers {
  /** 遇到清单帧（照片开始） */
  onManifest?(manifest: LightMeta, index: number): void | Promise<void>;
  /** 遇到块帧（明文块，index 为照片序号，chunkIndex 为块序号） */
  onChunk?(manifest: LightMeta, index: number, chunk: Uint8Array, chunkIndex: number): void | Promise<void>;
  /** 单张照片完整校验通过（块数、字节数、整图哈希） */
  onPhotoComplete?(manifest: LightMeta, index: number): void | Promise<void>;
}

/** 预览产物：结构校验通过的照片清单（不携带块载荷） */
export interface VencPreview {
  lightMeta: LightMeta;
  /** 是否完成整图哈希校验（预览阶段恒为 false） */
  verified: boolean;
}

/** 打开容器并解封内容密钥；完成头部与尺寸校验 */
async function openVencContext(encoded: Uint8Array, token: string): Promise<VencContext> {
  if (!encoded || encoded.length === 0) {
    throw formatCorrupted("备份数据为空");
  }
  if (encoded.length > PARSE_MAX_CONTAINER_BYTES) {
    throw formatCorrupted(`容器超过大小上限（${encoded.length} > ${PARSE_MAX_CONTAINER_BYTES}）`);
  }
  const minLen = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES
    + VENC_FRAME_HEADER_BYTES + NONCE_LEN + TAG_LEN;
  if (encoded.length < minLen) {
    throw formatCorrupted(`备份数据过短（${encoded.length} < ${minLen}）`);
  }

  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  const magic = new TextDecoder().decode(encoded.slice(0, VENC_MAGIC.length));
  if (magic !== VENC_MAGIC_TEXT) {
    throw formatCorrupted(`备份魔数不匹配（期望 "${VENC_MAGIC_TEXT}"，实际 "${magic}"）`);
  }
  const version = view.getUint16(4, false);
  if (version !== VENC_VERSION) {
    throw unsupportedVersion(`不支持的备份格式版本: ${version}（当前支持 ${VENC_VERSION}）`);
  }
  if (view.getUint16(6, false) !== 0) {
    throw formatCorrupted("备份头保留字段非零");
  }
  const kdfId = view.getUint16(8, false);
  if (kdfId !== VENC_KDF_ID_PBKDF2_SHA256) {
    throw unsupportedVersion(`不支持的密钥派生算法标识: ${kdfId}`);
  }
  const iterations = view.getUint32(10, false);
  if (iterations < 100_000 || iterations > 10_000_000) {
    throw formatCorrupted(`头部迭代次数非法: ${iterations}`);
  }

  const salt = encoded.slice(14, 14 + SALT_LEN);
  const iv = encoded.slice(30, 30 + 12);
  const header = encoded.slice(0, VENC_OUTER_HEADER_BYTES);

  const kebBits = await derivePBKDF2Bits(token, salt, iterations);
  const kek = await crypto.subtle.importKey(
    "raw", kebBits, { name: "AES-GCM", length: 256 }, false, ["decrypt"],
  );
  // 派生中间量仅用于导入 WebCrypto 密钥对象，用毕立即清零
  zeroize(new Uint8Array(kebBits));
  const wrapped = encoded.slice(
    VENC_OUTER_HEADER_BYTES,
    VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES,
  );
  let contentKey: Uint8Array;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: toArrayBuffer(header) },
      kek,
      toArrayBuffer(wrapped),
    );
    contentKey = new Uint8Array(pt);
  } catch (e) {
    throw wrapAsCryptoError(e, CryptoErrorKind.TAG_VERIFICATION_FAILED, "内容密钥解封失败（令牌错误或文件被篡改）");
  }
  if (contentKey.length !== KEY_LEN) {
    zeroize(contentKey);
    throw formatCorrupted(`内容密钥长度非法: ${contentKey.length}`);
  }
  return {
    contentKey,
    salt,
    view,
    offset: VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES,
    end: encoded.length,
  };
}

/** 读取帧头并推进偏移；只做结构与边界校验，不解密 */
function readFrameMeta(ctx: VencContext, expectSeq: number): VencFrameMeta {
  const { view, offset } = ctx;
  if (offset + VENC_FRAME_HEADER_BYTES > ctx.end) {
    throw formatCorrupted("帧头越界");
  }
  const type = view.getUint8(offset);
  const seq = view.getUint32(offset + 1, false);
  const len = view.getUint32(offset + 5, false);
  if (type !== VENC_FRAME_TYPE_LIGHT_META
    && type !== VENC_FRAME_TYPE_CHUNK
    && type !== VENC_FRAME_TYPE_TRAILER) {
    throw formatCorrupted(`未知帧类型: ${type}`);
  }
  if (seq !== expectSeq) {
    throw formatCorrupted(`帧序号不连续: seq=${seq}，期望 ${expectSeq}`);
  }
  if (len > PARSE_MAX_FRAME_BYTES) {
    throw formatCorrupted(`帧负载超过上限: ${len}`);
  }
  const frameTotal = VENC_FRAME_HEADER_BYTES + NONCE_LEN + len + TAG_LEN;
  if (offset + frameTotal > ctx.end) {
    throw formatCorrupted(`帧负载越界（offset=${offset}, len=${len}）`);
  }
  return { type, seq, len, nextOffset: offset + frameTotal };
}

/** 解密单个帧，AD 绑定帧头与容器盐 */
function decryptVencFrame(
  ctx: VencContext,
  encoded: Uint8Array,
  frame: VencFrameMeta,
): Uint8Array {
  const nonceStart = ctx.offset + VENC_FRAME_HEADER_BYTES;
  const ctStart = nonceStart + NONCE_LEN;
  const nonce = encoded.subarray(nonceStart, ctStart);
  const ct = encoded.subarray(ctStart, frame.nextOffset);
  const ad = buildFrameAd(frame.type, frame.seq, frame.len, ctx.salt);
  try {
    const plain = xchacha20poly1305(ctx.contentKey, nonce, ad).decrypt(ct);
    if (plain.length !== frame.len) {
      throw formatCorrupted(`帧 ${frame.seq} 负载长度不符`);
    }
    return plain;
  } catch (e) {
    // 已分类错误原样上抛；其余（标签校验）统一归为篡改/密钥错误
    throw wrapAsCryptoError(
      e, CryptoErrorKind.TAG_VERIFICATION_FAILED,
      `帧 ${frame.seq} 标签校验失败（数据被篡改）`,
    );
  } finally {
    zeroize(ad);
  }
}

/** 解析清单帧负载 */
function parseManifestPayload(payload: Uint8Array): LightMeta {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(payload));
  } catch (e) {
    throw formatCorrupted("清单 JSON 解析失败", e);
  } finally {
    // 清单明文含文件名/缩略图：解析后立即清零，不随帧缓冲驻留
    zeroize(payload);
  }
  assertLightMetaShape(parsed);
  return parsed;
}

/**
 * 流式解包可移植备份：逐帧校验并按回调交付明文块。
 *
 * 校验链：头部/密钥 → 帧序与边界 → 逐帧标签 → 清单字段 →
 * 每张照片块数/字节数/整图 BLAKE3 → 尾部交叉校验 → 无尾随数据。
 */
export async function unpackVencStream(
  encoded: Uint8Array,
  token: string,
  handlers: VencStreamHandlers = {},
): Promise<{ photos: number; chunks: number }> {
  const ctx = await openVencContext(encoded, token);
  try {
    let expectSeq = 0;
    let frameCount = 0;
    let bodyBytes = 0;
    let photoCount = 0;
    let chunkTotal = 0;
    let trailer: { frameCount: number; bodyBytes: number } | null = null;
    let cur: {
      manifest: LightMeta;
      index: number;
      chunks: number;
      size: number;
      hasher: ReturnType<typeof blake3.create>;
    } | null = null;

    const closePhoto = async (): Promise<void> => {
      if (!cur) return;
      if (cur.chunks !== cur.manifest.chunkCount) {
        throw formatCorrupted(
          `照片 "${cur.manifest.name}" 块数不符: 声明 ${cur.manifest.chunkCount}，实际 ${cur.chunks}`,
        );
      }
      if (cur.size !== cur.manifest.size) {
        throw formatCorrupted(
          `照片 "${cur.manifest.name}" 字节数不符: 声明 ${cur.manifest.size}，实际 ${cur.size}`,
        );
      }
      const actualHash = bytesToHex(cur.hasher.digest());
      if (actualHash !== cur.manifest.fileHash) {
        throw formatCorrupted(
          `照片 "${cur.manifest.name}" 整图哈希不符: 期望 ${cur.manifest.fileHash}，实际 ${actualHash}`,
        );
      }
      await handlers.onPhotoComplete?.(cur.manifest, cur.index);
      photoCount += 1;
      cur = null;
    };

    while (ctx.offset < ctx.end) {
      const frame = readFrameMeta(ctx, expectSeq);
      if (trailer) {
        throw formatCorrupted("尾部校验帧之后存在未识别数据");
      }

      if (frame.type === VENC_FRAME_TYPE_TRAILER) {
        if (frame.len !== VENC_TRAILER_PAYLOAD_BYTES) {
          throw formatCorrupted(`尾部帧负载长度非法: ${frame.len}`);
        }
        const payload = decryptVencFrame(ctx, encoded, frame);
        ctx.offset = frame.nextOffset;
        expectSeq += 1;
        if (ctx.offset !== ctx.end) {
          throw formatCorrupted("尾部校验帧之后存在未识别数据");
        }
        const tv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
        trailer = {
          frameCount: tv.getUint32(0, false),
          bodyBytes: Number(tv.getBigUint64(4, false)),
        };
        break;
      }

      frameCount += 1;
      bodyBytes += frame.len;
      if (frameCount > PARSE_MAX_FRAME_COUNT) {
        throw formatCorrupted(`帧数超过上限（${frameCount} > ${PARSE_MAX_FRAME_COUNT}）`);
      }

      if (frame.type === VENC_FRAME_TYPE_LIGHT_META) {
        await closePhoto();
        const manifest = parseManifestPayload(decryptVencFrame(ctx, encoded, frame));
        ctx.offset = frame.nextOffset;
        expectSeq += 1;
        cur = {
          manifest,
          index: photoCount,
          chunks: 0,
          size: 0,
          hasher: blake3.create({ dkLen: FILE_HASH_LEN }),
        };
        await handlers.onManifest?.(manifest, photoCount);
        continue;
      }

      // 块帧
      if (!cur) {
        throw formatCorrupted("块帧先于清单帧出现");
      }
      if (cur.chunks >= cur.manifest.chunkCount) {
        throw formatCorrupted(`照片 "${cur.manifest.name}" 块数超过清单声明`);
      }
      const chunk = decryptVencFrame(ctx, encoded, frame);
      ctx.offset = frame.nextOffset;
      expectSeq += 1;
      if (chunk.length === 0 || chunk.length > CHUNK_SIZE) {
        throw formatCorrupted(
          `照片 "${cur.manifest.name}" 第 ${cur.chunks + 1} 块长度非法: ${chunk.length}`,
        );
      }
      cur.hasher.update(chunk);
      cur.size += chunk.length;
      const chunkIndex = cur.chunks;
      cur.chunks += 1;
      chunkTotal += 1;
      await handlers.onChunk?.(cur.manifest, cur.index, chunk, chunkIndex);
    }

    await closePhoto();
    if (!trailer) {
      throw formatCorrupted("缺少尾部校验帧");
    }
    if (photoCount === 0) {
      throw formatCorrupted("容器内无照片");
    }
    if (trailer.frameCount !== frameCount) {
      throw formatCorrupted(`尾部帧数校验不符: 声明 ${trailer.frameCount}，实际 ${frameCount}`);
    }
    if (trailer.bodyBytes !== bodyBytes) {
      throw formatCorrupted(`尾部字节数校验不符: 声明 ${trailer.bodyBytes}，实际 ${bodyBytes}`);
    }
    return { photos: photoCount, chunks: chunkTotal };
  } finally {
    zeroize(ctx.contentKey);
  }
}

/**
 * 预览扫描：只解密清单与尾部，不保留块载荷、不做整图哈希。
 *
 * 用于导入前展示缩略图与数量；块级完整性与整图哈希在正式导入时校验。
 */
export async function unpackVencPreview(
  encoded: Uint8Array,
  token: string,
  onManifest?: (manifest: LightMeta, index: number) => void,
): Promise<VencPreview[]> {
  const ctx = await openVencContext(encoded, token);
  try {
    let expectSeq = 0;
    let frameCount = 0;
    let bodyBytes = 0;
    let trailer: { frameCount: number; bodyBytes: number } | null = null;
    let cur: { manifest: LightMeta; chunks: number; size: number } | null = null;
    const previews: VencPreview[] = [];

    const closePhoto = (): void => {
      if (!cur) return;
      if (cur.chunks !== cur.manifest.chunkCount) {
        throw formatCorrupted(
          `照片 "${cur.manifest.name}" 块数不符: 声明 ${cur.manifest.chunkCount}，实际 ${cur.chunks}`,
        );
      }
      if (cur.size !== cur.manifest.size) {
        throw formatCorrupted(
          `照片 "${cur.manifest.name}" 字节数不符: 声明 ${cur.manifest.size}，实际 ${cur.size}`,
        );
      }
      previews.push({ lightMeta: cur.manifest, verified: false });
      cur = null;
    };

    while (ctx.offset < ctx.end) {
      const frame = readFrameMeta(ctx, expectSeq);
      if (trailer) {
        throw formatCorrupted("尾部校验帧之后存在未识别数据");
      }
      if (frame.type === VENC_FRAME_TYPE_TRAILER) {
        if (frame.len !== VENC_TRAILER_PAYLOAD_BYTES) {
          throw formatCorrupted(`尾部帧负载长度非法: ${frame.len}`);
        }
        const payload = decryptVencFrame(ctx, encoded, frame);
        ctx.offset = frame.nextOffset;
        expectSeq += 1;
        if (ctx.offset !== ctx.end) {
          throw formatCorrupted("尾部校验帧之后存在未识别数据");
        }
        const tv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
        trailer = {
          frameCount: tv.getUint32(0, false),
          bodyBytes: Number(tv.getBigUint64(4, false)),
        };
        break;
      }

      frameCount += 1;
      bodyBytes += frame.len;
      if (frameCount > PARSE_MAX_FRAME_COUNT) {
        throw formatCorrupted(`帧数超过上限（${frameCount} > ${PARSE_MAX_FRAME_COUNT}）`);
      }

      if (frame.type === VENC_FRAME_TYPE_LIGHT_META) {
        closePhoto();
        const manifest = parseManifestPayload(decryptVencFrame(ctx, encoded, frame));
        ctx.offset = frame.nextOffset;
        expectSeq += 1;
        cur = { manifest, chunks: 0, size: 0 };
        onManifest?.(manifest, previews.length);
        continue;
      }

      if (!cur) {
        throw formatCorrupted("块帧先于清单帧出现");
      }
      if (cur.chunks >= cur.manifest.chunkCount) {
        throw formatCorrupted(`照片 "${cur.manifest.name}" 块数超过清单声明`);
      }
      // 预览不消费块密文：仅按帧头长度累计，块级认证留给导入阶段
      if (frame.len === 0 || frame.len > CHUNK_SIZE) {
        throw formatCorrupted(
          `照片 "${cur.manifest.name}" 第 ${cur.chunks + 1} 块长度非法: ${frame.len}`,
        );
      }
      ctx.offset = frame.nextOffset;
      expectSeq += 1;
      cur.chunks += 1;
      cur.size += frame.len;
    }

    closePhoto();
    if (!trailer) {
      throw formatCorrupted("缺少尾部校验帧");
    }
    if (previews.length === 0) {
      throw formatCorrupted("容器内无照片");
    }
    if (trailer.frameCount !== frameCount) {
      throw formatCorrupted(`尾部帧数校验不符: 声明 ${trailer.frameCount}，实际 ${frameCount}`);
    }
    if (trailer.bodyBytes !== bodyBytes) {
      throw formatCorrupted(`尾部字节数校验不符: 声明 ${trailer.bodyBytes}，实际 ${bodyBytes}`);
    }
    return previews;
  } finally {
    zeroize(ctx.contentKey);
  }
}

/**
 * 解包可移植备份并返回全部明文块（测试与需要整包数据的调用方使用）。
 *
 * 正式导入链路应使用 {@link unpackVencStream} 逐照片消费，避免整包驻留。
 */
export async function unpackVenc(
  encoded: Uint8Array,
  token: string,
): Promise<VencPhotoSpec[]> {
  const photos: VencPhotoSpec[] = [];
  await unpackVencStream(encoded, token, {
    onManifest: (manifest) => {
      photos.push({ lightMeta: manifest, chunkBytes: [] });
    },
    onChunk: (_manifest, index, chunk) => {
      photos[index].chunkBytes.push(chunk);
    },
  });
  return photos;
}

/** 生成随机令牌（默认 32 bytes hex） */
export function generateRandomToken(bytes: number = 32): string {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw invalidInput(`令牌字节数非法: ${bytes}`);
  }
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  const token = bytesToHex(arr);
  zeroize(arr);
  return token;
}

/* ------------------------------------------------------------------ *
 * 独立密码加密层（per-field AES-GCM）                                  *
 *                                                                    *
 * 与 DLL 的加密库主加密相互独立：                                      *
 *   - DLL 负责 verthys 级别的整体加密（主密码派生）                      *
 *   - 此层为单条密码追加的细粒度加密，需用户独立密钥才能解密           *
 *   - encKey 不存储明文，仅存 salt + iv + ciphertext                  *
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
 * 再导出                                                              *
 *                                                                    *
 * 上层组件（PhotoAlbum.vue 等）通过 `from "../../lib/crypto"` 导入     *
 * 常量与类型。                                                        *
 * ------------------------------------------------------------------ */

export { CHUNK_SIZE, TYPE_PHOTO_META, TYPE_PHOTO_CHUNK };
export { bytesToHex };
export type { PhotoMeta, LightMeta, VencPhotoSpec };
