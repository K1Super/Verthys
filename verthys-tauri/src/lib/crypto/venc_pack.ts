/*
 * crypto/venc_pack.ts — VENC 备份容器打包：外层头 + 内容密钥封装 + 逐帧 AEAD
 * + 尾部校验帧，并提供体积预估与惰性流式出口。
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, isValidHex, toArrayBuffer } from "../../utils/codec/binary_codec";

import {
  KEY_LEN, SALT_LEN, NONCE_LEN, TAG_LEN,
  CHUNK_SIZE, FILE_HASH_LEN, MAX_PHOTO_BYTES,
  VENC_VERSION, VENC_KDF_ITERATIONS,
  VENC_OUTER_HEADER_BYTES, VENC_WRAPPED_KEY_BYTES, VENC_FRAME_HEADER_BYTES,
  VENC_TRAILER_PAYLOAD_BYTES,
  VENC_KDF_ID_PBKDF2_SHA256,
  VENC_FRAME_TYPE_LIGHT_META, VENC_FRAME_TYPE_CHUNK, VENC_FRAME_TYPE_TRAILER,
} from "../../constants/crypto_const";
import type { LightMeta, VencPhotoSpec } from "../../types/crypto";
import {
  CryptoErrorKind,
  invalidInput, wrapAsCryptoError,
} from "../util/crypto_error";
import {
  VENC_MAGIC, derivePBKDF2Bits, zeroize,
  encodeFrameHeader, buildFrameAd, assertLightMetaShape,
} from "./venc_common";

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
