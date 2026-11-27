/*
 * crypto/venc_unpack.ts — VENC 备份容器解包：头部/密钥校验、逐帧认证、
 * 清单解析、逐照片完整性校验（块数/字节数/BLAKE3）、尾部交叉校验。
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, toArrayBuffer } from "../../utils/codec/binary_codec";

import {
  KEY_LEN, SALT_LEN, NONCE_LEN, TAG_LEN,
  CHUNK_SIZE, FILE_HASH_LEN,
  VENC_MAGIC_TEXT, VENC_VERSION,
  VENC_OUTER_HEADER_BYTES, VENC_WRAPPED_KEY_BYTES, VENC_FRAME_HEADER_BYTES,
  VENC_TRAILER_PAYLOAD_BYTES,
  VENC_KDF_ID_PBKDF2_SHA256,
  VENC_FRAME_TYPE_LIGHT_META, VENC_FRAME_TYPE_CHUNK, VENC_FRAME_TYPE_TRAILER,
  PARSE_MAX_FRAME_COUNT, PARSE_MAX_FRAME_BYTES, PARSE_MAX_CONTAINER_BYTES,
} from "../../constants/crypto_const";
import type { LightMeta, VencPhotoSpec } from "../../types/crypto";
import {
  CryptoErrorKind,
  formatCorrupted, unsupportedVersion, wrapAsCryptoError,
} from "../util/crypto_error";
import {
  VENC_MAGIC, derivePBKDF2Bits, zeroize,
  buildFrameAd, assertLightMetaShape,
} from "./venc_common";

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
