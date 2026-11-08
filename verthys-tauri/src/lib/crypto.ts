/*
 * crypto.ts — 前端剩余密码学能力（VENC 导出容器 + 字段密码 + BLAKE3）
 *
 * 职责边界：
 *   - VENC v2 导出容器：用户导出令牌 → PBKDF2 → 内容密钥 → 逐帧 XChaCha20-Poly1305
 *   - 独立密码字段：per-field AES-GCM（清单密码等既有记录）
 *   - BLAKE3 哈希与公开结构解析（文件哈希、包裹态密钥盐、容器轻量头）
 *
 * 照片/文件记录的内容加密不在本文件：已下沉到 Tauri worker 的 module_crypto 模块。
 * 本文件不执行模块密钥派生，也不持有模块密钥或文件密钥。
 *
 * 容器布局（导出文件）：
 *   外层头 42B（magic/version/flags/kdf/iterations/salt/iv）+ 包裹内容密钥 48B + 逐帧
 * 帧 AD = type(1) || seq(4 大端) || len(4 大端)
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { blake3 } from "@noble/hashes/blake3";
import { bytesToBase64, base64ToBytes, bytesToHex, isValidHex, toArrayBuffer } from "../utils/binary_codec";

import {
  PBKDF2_ITER, KEY_LEN, SALT_LEN, NONCE_LEN, TAG_LEN,
  CHUNK_SIZE, FILE_HASH_LEN,
  PHOTO_FMT_SLIM,
  VENC_MAGIC_TEXT, VENC_VERSION,
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
 * .venc v2 容器（自描述信封 + 内容密钥封装 + 逐帧 AEAD）              *
 *                                                                    *
 * 布局：                                                              *
 *   [Outer Header 42B 明文]：magic(4) version(2) flags(2) kdf_id(2)   *
 *                            iterations(4) salt(16) iv(12)           *
 *   [Wrapped Content Key 48B]：AES-256-GCM 加密 content_key(32)，     *
 *      密钥 = PBKDF2(token, salt, iterations)，nonce = iv，           *
 *      AD = Outer Header 全字节（头部被篡改即解封失败）               *
 *   [Frame]*：帧头 [type(1) seq(4 大端) len(4 大端)] +                *
 *             [nonce(24)] + [ciphertext+tag]                          *
 *      帧密钥 = content_key（XChaCha20-Poly1305），                   *
 *      帧 AD = type|seq|len（大端）                                    *
 *   [Trailer 帧]：frame_count(u32) + body_bytes(u64) 交叉校验         *
 *                                                                    *
 * 帧类型：1=轻量头（明文 JSON 结构，经内容密钥逐帧加密）、             *
 *         2=加密块负载（保持模块密钥加密态原样搬运）、                 *
 *         3=尾部校验帧                                                *
 *                                                                    *
 * KDF 参数自描述：iterations 写入头部，解密端按读取值执行派生，       *
 * 提升迭代次数不会使历史文件永久不可解。                               *
 * ------------------------------------------------------------------ */

/** 把本地存储元数据投影为容器轻量头（不携带内联块负载） */
export function toLightMeta(local: PhotoMeta): LightMeta {
  return {
    name: local.name,
    mime: local.mime,
    size: local.size,
    thumbB64: local.thumbB64,
    fileHash: local.fileHash,
    createdAt: local.createdAt,
    chunkCount: local.chunkDataB64?.length ?? 0,
    chunkHashes: local.chunkHashes ?? [],
    // 来源布局与包裹态密钥随容器携带：接收端按同一布局分流；
    // 既有布局两项为空（JSON 序列化时被省略，不改变既有容器结构）
    fmt: local.fmt,
    wrappedFileKey: local.wrappedFileKey,
  };
}

/** 计算加密块 base64 数组的逐块 BLAKE3 hex（容器打包与完整性校验用） */
export function computeChunkHashesForB64(chunkB64List: string[]): string[] {
  return chunkB64List.map((cb) =>
    bytesToHex(blake3(base64ToBytes(cb), { dkLen: FILE_HASH_LEN })),
  );
}

/** 帧头 / 帧 AD 编码：type(1) + seq(4 大端) + len(4 大端)，两者同型 */
function encodeFrameHeader(type: number, seq: number, len: number): Uint8Array {
  const buf = new Uint8Array(VENC_FRAME_HEADER_BYTES);
  buf[0] = type;
  const view = new DataView(buf.buffer);
  view.setUint32(1, seq, false);
  view.setUint32(5, len, false);
  return buf;
}

/** 逐帧加密：帧头 + nonce + ciphertext+tag 拼装，AD 绑定 type/seq/len */
function encryptFrame(
  contentKey: Uint8Array,
  type: number,
  seq: number,
  payload: Uint8Array,
): Uint8Array {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const ad = encodeFrameHeader(type, seq, payload.length);
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
  if (!lm || !photo.chunkBytes) {
    throw invalidInput("照片容器数据字段缺失");
  }
  if (lm.chunkCount !== photo.chunkBytes.length || lm.chunkHashes.length !== photo.chunkBytes.length) {
    throw invalidInput(
      `照片 "${lm.name}" 块数字段不一致: chunkCount=${lm.chunkCount}, ` +
        `chunkHashes=${lm.chunkHashes.length}, 实际块=${photo.chunkBytes.length}`,
    );
  }
  // 打包前逐块校验哈希声明：写入容器的 chunkHashes 必须是负载的真实摘要，
  // 否则接收端必然拒绝——fail-fast 避免产出「注定无法解析」的文件
  for (let i = 0; i < photo.chunkBytes.length; i++) {
    const actual = bytesToHex(blake3(photo.chunkBytes[i], { dkLen: FILE_HASH_LEN }));
    if (actual !== lm.chunkHashes[i]) {
      throw invalidInput(
        `照片 "${lm.name}" 第 ${i + 1} 块哈希声明不符: ` +
          `期望 ${lm.chunkHashes[i]}，实际 ${actual}`,
      );
    }
  }
}

/** 轻量头形状校验（解包侧防御，结构来自外部输入） */
function assertLightMetaShape(lm: LightMeta): void {
  if (typeof lm !== "object" || lm === null) {
    throw formatCorrupted("轻量头结构非法");
  }
  if (typeof lm.name !== "string" || typeof lm.mime !== "string" || typeof lm.thumbB64 !== "string") {
    throw formatCorrupted("轻量头字段类型非法");
  }
  if (!Number.isFinite(lm.size) || lm.size < 0 || lm.size > PARSE_MAX_CONTAINER_BYTES) {
    throw formatCorrupted(`轻量头 size 非法: ${lm.size}`);
  }
  if (!Number.isInteger(lm.chunkCount) || lm.chunkCount < 0 || lm.chunkCount > PARSE_MAX_FRAME_COUNT) {
    throw formatCorrupted(`轻量头 chunkCount 非法: ${lm.chunkCount}`);
  }
  if (!Array.isArray(lm.chunkHashes) || lm.chunkHashes.length !== lm.chunkCount) {
    throw formatCorrupted("轻量头 chunkHashes 数组长度与 chunkCount 不一致");
  }
  if (!isValidHex(lm.fileHash) || lm.fileHash.length !== FILE_HASH_LEN * 2) {
    throw formatCorrupted("轻量头 fileHash 非法");
  }
  // 布局标记与包裹态密钥必须成对出现：索引瘦身布局的块密文只能按包裹密钥
  // 解封，缺失即无法导入，此处前置拒绝（避免产出"注定无法解析"的中间态）
  if (lm.fmt === PHOTO_FMT_SLIM) {
    if (typeof lm.wrappedFileKey !== "string" || lm.wrappedFileKey.length === 0) {
      throw formatCorrupted("轻量头声明索引瘦身布局但缺少包裹态文件密钥");
    }
  } else if (lm.wrappedFileKey !== undefined) {
    throw formatCorrupted("轻量头携带包裹态文件密钥但未声明索引瘦身布局");
  }
}

/** 逐块完整性校验：块帧负载的 BLAKE3 与轻量头声明的 chunkHashes 逐一比对 */
function assertChunkHashesMatched(photo: { lightMeta: LightMeta; chunkBytes: Uint8Array[] }): void {
  for (let i = 0; i < photo.chunkBytes.length; i++) {
    const actual = bytesToHex(blake3(photo.chunkBytes[i], { dkLen: FILE_HASH_LEN }));
    if (actual !== photo.lightMeta.chunkHashes[i]) {
      throw formatCorrupted(
        `照片 "${photo.lightMeta.name}" 第 ${i + 1} 块哈希不符: ` +
          `期望 ${photo.lightMeta.chunkHashes[i]}，实际 ${actual}`,
      );
    }
  }
}

/**
 * 将照片容器数据打包为 .venc v2 加密文件。
 *
 * 收集全部输出段后一次性拼接返回；大文件单文件导出应改用
 * {@link packVencStreamed} 流式产出以压低内存峰值。
 *
 * @param photos 照片容器数据（轻量头 + 加密块字节）
 * @param token 导出令牌（外层内容密钥封装的凭据）
 * @returns .venc v2 完整字节（头部 + 封装密钥 + 帧序列 + 尾部校验帧）
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
 * 将照片容器数据流式打包为 .venc v2 加密文件，逐段交给写入回调。
 *
 * 与 {@link packVenc} 共享同一打包核心：不缓存帧序列，每产生一段
 * （首段为头部 + 封装密钥，其后为单个加密帧，末尾为尾部校验帧）即
 * `await emit(part)`，由调用方决定落盘 / 拼接策略；回调返回 Promise
 * 以支持背压（如流式追加落盘）。回调抛错即中止打包并向上传播。
 *
 * 注意：本入口要求全部块字节已在内存（`photos[*].chunkBytes`）。容器体积
 * 与内存同阶；GB 级单文件导出应改用 {@link packVencStreamedLazy}。
 *
 * @param photos 照片容器数据（轻量头 + 加密块字节）
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

/** 预估 .venc v2 容器总字节数（打包前进度分母）。 */
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
  hv.setUint32(10, PBKDF2_ITER, false);
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  header.set(salt, 14);
  header.set(iv, 30);

  // 2. 随机内容密钥（帧负载加密钥，仅封装后落盘）
  const contentKey = crypto.getRandomValues(new Uint8Array(KEY_LEN));

  // 3. 封装内容密钥：AES-256-GCM，AD 绑定完整头部字节
  const kebBits = await derivePBKDF2Bits(token, salt);
  const kek = await crypto.subtle.importKey(
    "raw", kebBits, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
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
      await emit(encryptFrame(contentKey, VENC_FRAME_TYPE_LIGHT_META, seq++, lmBytes));
      frameCount += 1;
      bodyBytes += lmBytes.length;
      for (const chunk of photo.chunkBytes) {
        await emit(encryptFrame(contentKey, VENC_FRAME_TYPE_CHUNK, seq++, chunk));
        frameCount += 1;
        bodyBytes += chunk.length;
      }
    }

    // 5. 尾部校验帧：frame_count(u32) + body_bytes(u64) 交叉校验
    const trailerPayload = new Uint8Array(VENC_TRAILER_PAYLOAD_BYTES);
    const tv = new DataView(trailerPayload.buffer);
    tv.setUint32(0, frameCount, false);
    tv.setBigUint64(4, BigInt(bodyBytes), false);
    await emit(encryptFrame(contentKey, VENC_FRAME_TYPE_TRAILER, seq, trailerPayload));
  } finally {
    zeroize(contentKey);
  }
}

/**
 * 解包 .venc v2 加密文件并完成全链路校验。
 *
 * 校验链（任一步失败即以分类错误拒绝，不产出部分结果）：
 *   1. 容器大小上限与最小长度；
 *   2. 魔数 / 版本 / KDF 标识 / 迭代次数（头部自描述）；
 *   3. 内容密钥解封（AEAD 标签校验，AD 绑定完整头部 → 头部篡改即失败）；
 *   4. 逐帧解析：帧序严格递增、帧类型合法、帧负载上限、标签校验；
 *   5. 尾部帧交叉校验：frame_count 与 body_bytes 与实解数据一致；
 *   6. 逐块完整性：块帧负载 BLAKE3 与轻量头 chunkHashes 逐一比对；
 *   7. 尾部无残留数据、容器内至少一张照片。
 *
 * @param encoded .venc v2 完整字节
 * @param token 导出令牌
 * @returns 照片容器数据数组（轻量头 + 加密块字节）
 */
export async function unpackVenc(
  encoded: Uint8Array,
  token: string,
): Promise<VencPhotoSpec[]> {
  if (!encoded || encoded.length === 0) {
    throw formatCorrupted("venc 数据为空");
  }
  if (encoded.length > PARSE_MAX_CONTAINER_BYTES) {
    throw formatCorrupted(`容器超过大小上限（${encoded.length} > ${PARSE_MAX_CONTAINER_BYTES}）`);
  }
  const minLen = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES + VENC_FRAME_HEADER_BYTES + NONCE_LEN + 16;
  if (encoded.length < minLen) {
    throw formatCorrupted(`venc 数据过短（${encoded.length} < ${minLen}）`);
  }

  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);

  // 1. 外层头部校验
  const magic = new TextDecoder().decode(encoded.slice(0, VENC_MAGIC.length));
  if (magic !== VENC_MAGIC_TEXT) {
    throw formatCorrupted(`venc 魔数不匹配（期望 "${VENC_MAGIC_TEXT}"，实际 "${magic}"）`);
  }
  const version = view.getUint16(4, false);
  if (version !== VENC_VERSION) {
    throw unsupportedVersion(`不支持的容器版本: ${version}（当前支持 ${VENC_VERSION}）`);
  }
  const kdfId = view.getUint16(8, false);
  if (kdfId !== VENC_KDF_ID_PBKDF2_SHA256) {
    throw unsupportedVersion(`不支持的密钥派生算法标识: ${kdfId}`);
  }
  const iterations = view.getUint32(10, false);
  if (iterations < 10_000) {
    throw formatCorrupted(`头部迭代次数非法: ${iterations}`);
  }
  const salt = encoded.slice(14, 14 + SALT_LEN);
  const iv = encoded.slice(30, 30 + 12);
  const header = encoded.slice(0, VENC_OUTER_HEADER_BYTES);

  // 2. 内容密钥解封（AD = 头部全字节）
  const kebBits = await derivePBKDF2Bits(token, salt, iterations);
  const kek = await crypto.subtle.importKey(
    "raw", kebBits, { name: "AES-GCM", length: 256 }, false, ["decrypt"],
  );
  const wrapped = encoded.slice(VENC_OUTER_HEADER_BYTES, VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES);
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

  // 3. 逐帧解析
  try {
    let offset = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
    const photos: { lightMeta: LightMeta; chunkBytes: Uint8Array[] }[] = [];
    let cur: { lightMeta: LightMeta; chunkBytes: Uint8Array[] } | null = null;
    let expectSeq = 0;
    let frameCount = 0;
    let bodyBytes = 0;
    let trailer: { frameCount: number; bodyBytes: number } | null = null;

    while (offset < encoded.length) {
      if (offset + VENC_FRAME_HEADER_BYTES > encoded.length) {
        throw formatCorrupted("帧头越界");
      }
      const type = encoded[offset];
      const seq = view.getUint32(offset + 1, false);
      const len = view.getUint32(offset + 5, false);
      if (type !== VENC_FRAME_TYPE_LIGHT_META && type !== VENC_FRAME_TYPE_CHUNK && type !== VENC_FRAME_TYPE_TRAILER) {
        throw formatCorrupted(`未知帧类型: ${type}`);
      }
      if (seq !== expectSeq) {
        throw formatCorrupted(`帧序号不连续: seq=${seq}，期望 ${expectSeq}`);
      }
      if (len > PARSE_MAX_FRAME_BYTES) {
        throw formatCorrupted(`帧负载超过上限: ${len}`);
      }
      const frameTotal = VENC_FRAME_HEADER_BYTES + NONCE_LEN + len + TAG_LEN;
      if (offset + frameTotal > encoded.length) {
        throw formatCorrupted(`帧负载越界（offset=${offset}, len=${len}）`);
      }
      const nonce = encoded.slice(offset + VENC_FRAME_HEADER_BYTES, offset + VENC_FRAME_HEADER_BYTES + NONCE_LEN);
      const ct = encoded.slice(offset + VENC_FRAME_HEADER_BYTES + NONCE_LEN, offset + frameTotal);
      const ad = encodeFrameHeader(type, seq, len);
      const cipher = xchacha20poly1305(contentKey, nonce, ad);
      let payload: Uint8Array;
      try {
        payload = cipher.decrypt(ct);
      } catch (e) {
        throw wrapAsCryptoError(e, CryptoErrorKind.TAG_VERIFICATION_FAILED, `帧 ${seq} 标签校验失败（数据被篡改）`);
      } finally {
        zeroize(ad);
      }
      offset += frameTotal;
      expectSeq += 1;

      if (type === VENC_FRAME_TYPE_TRAILER) {
        if (offset !== encoded.length) {
          throw formatCorrupted("尾部校验帧之后存在未识别数据");
        }
        if (payload.length < 12) {
          throw formatCorrupted("尾部校验帧负载过短");
        }
        const tv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
        trailer = {
          frameCount: tv.getUint32(0, false),
          bodyBytes: Number(tv.getBigUint64(4, false)),
        };
        break;
      }

      frameCount += 1;
      bodyBytes += payload.length;
      if (frameCount > PARSE_MAX_FRAME_COUNT) {
        throw formatCorrupted(`帧数超过上限（${frameCount} > ${PARSE_MAX_FRAME_COUNT}）`);
      }

      if (type === VENC_FRAME_TYPE_LIGHT_META) {
        if (cur) {
          // 上一张照片收尾：逐块哈希校验
          assertChunkHashesMatched(cur);
          photos.push(cur);
        }
        let lightMeta: unknown;
        try {
          lightMeta = JSON.parse(new TextDecoder().decode(payload));
        } catch (e) {
          throw formatCorrupted("轻量头 JSON 解析失败", e);
        }
        assertLightMetaShape(lightMeta as LightMeta);
        cur = { lightMeta: lightMeta as LightMeta, chunkBytes: [] };
      } else {
        if (!cur) {
          throw formatCorrupted("块帧先于轻量头出现");
        }
        cur.chunkBytes.push(payload);
      }
    }

    if (!trailer) {
      throw formatCorrupted("缺少尾部校验帧");
    }
    if (cur) {
      assertChunkHashesMatched(cur);
      photos.push(cur);
    }
    if (photos.length === 0) {
      throw formatCorrupted("容器内无照片");
    }
    // 尾部交叉校验：实解帧数与字节数必须与 trailer 声明一致
    if (trailer.frameCount !== frameCount) {
      throw formatCorrupted(`尾部帧数校验不符: 声明 ${trailer.frameCount}，实际 ${frameCount}`);
    }
    if (trailer.bodyBytes !== bodyBytes) {
      throw formatCorrupted(`尾部字节数校验不符: 声明 ${trailer.bodyBytes}，实际 ${bodyBytes}`);
    }
    return photos.map((p) => ({ lightMeta: p.lightMeta, chunkBytes: p.chunkBytes }));
  } finally {
    zeroize(contentKey);
  }
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
export type { PhotoMeta, LightMeta, VencPhotoSpec };
