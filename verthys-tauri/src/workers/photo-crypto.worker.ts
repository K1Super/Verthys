/**
 * workers/photo-crypto.worker.ts — 照片加密 Web Worker
 *
 * Comprehensive_optimization：异步批处理流水线 — 传输器阶段（Web Worker 池）
 *
 * =============================================================================
 * 职责
 * =============================================================================
 * 在独立 Web Worker 线程中执行 CPU 密集型加密任务，避免阻塞渲染进程主线程：
 *   1. BLAKE3 文件哈希计算（去重 + AD 绑定）
 *   2. OffscreenCanvas 缩略图生成（400×400 JPEG 0.85）
 *   3. XChaCha20-Poly1305 分块加密（meta + chunks 内联）
 *   4. 元数据加密（encryptMeta）
 *
 * 加密产物与现有解密路径（decryptMeta / decryptChunk）字节兼容：
 *   - 复用 lib/crypto.ts 的 encryptMeta / encryptChunk / computeFileHash
 *   - 不改变加密算法、AD 构造、密钥派生流程
 *   - 已加密的照片仍可被现有 decryptMeta/decryptChunk 正常解密
 *
 * =============================================================================
 * 零拷贝传输
 * =============================================================================
 * - 输入：fileBytes 通过 transferList 零所有权转让到 Worker（主线程失去访问权）
 * - 输出：加密后的 chunk bytes 等不再回传（仅回传 base64 字符串 + 元数据）
 *   避免 transferList 反向传输的复杂性，base64 字符串序列化开销可接受
 *
 * =============================================================================
 * 消息协议
 * =============================================================================
 * 主线程 → Worker：
 *   { id, fileName, mime, fileBytes: ArrayBuffer, photoKey: string }
 *
 * Worker → 主线程：
 *   { id, ok: true, hash, thumbB64, metaB64, name, mime, size }
 *   { id, ok: false, error, name }
 *
 * =============================================================================
 * 安全边界
 * =============================================================================
 * - photoKey 在 Worker 内存中使用后立即 zeroize（由 encryptMeta/encryptChunk 内部完成）
 * - fileBytes 使用后 fill(0) 清零
 * - Worker 不接触 verthys 句柄、不发起 IPC，仅做纯加密计算
 */

/// <reference lib="webworker" />

import {
  encryptMeta,
  encryptChunk,
  computeFileHash,
  bytesToHex,
  TYPE_PHOTO_META,
  CHUNK_SIZE,
  type PhotoMeta,
} from "../lib/crypto";
import { bytesToBase64 } from "../utils/binary_codec";

/* ------------------------------------------------------------------ *
 * 消息类型定义                                                        *
 * ------------------------------------------------------------------ */

/** 主线程 → Worker 请求 */
export interface PhotoCryptoRequest {
  /** 任务 ID（用于关联请求与响应） */
  id: number;
  /** 文件名（用于 meta.name + 记录名） */
  fileName: string;
  /** MIME 类型 */
  mime: string;
  /** 文件原始字节（通过 transferList 零拷贝转让） */
  fileBytes: ArrayBuffer;
  /** 照片模块独立密钥 */
  photoKey: string;
}

/** Worker → 主线程 响应（成功） */
export interface PhotoCryptoSuccess {
  id: number;
  ok: true;
  /** BLAKE3 文件哈希 hex（去重 + WAL 幂等） */
  hash: string;
  /** 缩略图 base64（JPEG 0.85，最大 400×400） */
  thumbB64: string;
  /** 已加密的元数据 base64（XChaCha20-Poly1305） */
  metaB64: string;
  /** 记录名（`meta_${fileName}`） */
  name: string;
  /** MIME 类型 */
  mime: string;
  /** 原始文件大小（字节） */
  size: number;
}

/** Worker → 主线程 响应（失败） */
export interface PhotoCryptoFailure {
  id: number;
  ok: false;
  /** 文件名（用于错误提示） */
  name: string;
  /** 错误信息 */
  error: string;
}

/* ------------------------------------------------------------------ *
 * Parsed Import：meta-only 加密消息类型                             *
 *                                                                    *
 * 解析 .venc 文件后，chunks 已用当前 photoKey 加密（同设备导入场景），  *
 * 仅需重新加密元数据（meta 在 doParse 阶段被解密用于预览）。            *
 * 复用 Worker 池并行加密，避免主线程串行 encryptMeta 阻塞 UI。          *
 * ------------------------------------------------------------------ */

/** 主线程 → Worker 请求（meta-only 加密） */
export interface PhotoMetaCryptoRequest {
  /** 任务 ID（用于关联请求与响应） */
  id: number;
  /** 已解密的元数据对象（doParse 阶段解密，此处重新加密） */
  meta: PhotoMeta;
  /** 照片模块独立密钥 */
  photoKey: string;
  /** 记录名（`parsed_${timestamp}_${index}`，由调用方生成保证唯一） */
  recordName: string;
}

/** Worker → 主线程 响应（meta-only 加密成功） */
export interface PhotoMetaCryptoSuccess {
  id: number;
  ok: true;
  /** 已加密的元数据 base64（XChaCha20-Poly1305） */
  metaB64: string;
  /** BLAKE3 文件哈希 hex（从 meta.fileHash 提取，去重 + WAL 幂等） */
  hash: string;
  /** 缩略图 base64（从 meta.thumbB64 提取） */
  thumbB64: string;
  /** 记录名 */
  name: string;
  /** MIME 类型（从 meta.mime 提取） */
  mime: string;
  /** 原始文件大小（从 meta.size 提取） */
  size: number;
  /** 记录名（`parsed_${timestamp}_${index}`，用于 verthys 记录名） */
  recordName: string;
}

/** Worker 响应联合类型 */
export type PhotoCryptoResponse = PhotoCryptoSuccess | PhotoCryptoFailure | PhotoMetaCryptoSuccess;

/* ------------------------------------------------------------------ *
 * OffscreenCanvas 缩略图生成（Worker 兼容，无 DOM 依赖）              *
 * ------------------------------------------------------------------ */

/**
 * 在 Worker 中生成缩略图（使用 createImageBitmap + OffscreenCanvas）。
 *
 * 与主线程 generateThumbnail（Image + Canvas）的产物保持一致：
 *   - 最大 400×400，等比缩放
 *   - JPEG 0.85 质量
 *   - 返回 base64 字符串（不含 data: 前缀）
 *
 * OffscreenCanvas 在所有现代浏览器（Chromium 69+）的 Web Worker 中可用，
 * Tauri 使用 WebView2（Chromium 内核），完全支持。
 *
 * @param fileBytes 文件原始字节
 * @param mime MIME 类型
 * @returns 缩略图 base64 字符串（失败返回空字符串）
 */
async function generateThumbnailWorker(
  fileBytes: ArrayBuffer,
  mime: string,
): Promise<string> {
  try {
    // 创建 Blob → createImageBitmap 解码图片（无需 DOM Image 对象）
    const blob = new Blob([fileBytes], { type: mime || "image/png" });
    const bitmap = await createImageBitmap(blob);

    // 等比缩放到最大 400×400
    const maxW = 400, maxH = 400;
    let w = bitmap.width, h = bitmap.height;
    if (w > maxW) { h = Math.round(h * (maxW / w)); w = maxW; }
    if (h > maxH) { w = Math.round(w * (maxH / h)); h = maxH; }

    // OffscreenCanvas 绘制
    const canvas = new OffscreenCanvas(w, h);
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      bitmap.close();
      return "";
    }
    ctx.drawImage(bitmap, 0, 0, w, h);
    bitmap.close();

    // 转为 Blob → base64（OffscreenCanvas.convertToBlob 替代 canvas.toDataURL）
    const thumbBlob = await canvas.convertToBlob({ type: "image/jpeg", quality: 0.85 });
    const thumbBuf = await thumbBlob.arrayBuffer();
    return bytesToBase64(new Uint8Array(thumbBuf));
  } catch (e) {
    // 缩略图生成失败不阻塞导入（返回空字符串，前端显示占位图）
    console.warn("[photo-crypto.worker] 缩略图生成失败:", e);
    return "";
  }
}

/* ------------------------------------------------------------------ *
 * 单张照片加密处理（复用 lib/crypto.ts，保证字节兼容）                *
 * ------------------------------------------------------------------ */

/**
 * 处理单张照片加密：
 *   1. 计算 BLAKE3 文件哈希
 *   2. 生成缩略图
 *   3. 分块加密（CHUNK_SIZE 切片，XChaCha20-Poly1305）
 *   4. 构造 PhotoMeta + 加密元数据
 *
 * @param fileName 文件名
 * @param mime MIME 类型
 * @param fileBytes 文件原始字节
 * @param photoKey 照片模块独立密钥
 * @returns { hash, thumbB64, metaB64, name, mime, size }
 */
async function processPhoto(
  fileName: string,
  mime: string,
  fileBytes: ArrayBuffer,
  photoKey: string,
): Promise<{
  hash: string;
  thumbB64: string;
  metaB64: string;
  name: string;
  mime: string;
  size: number;
}> {
  const origBytes = new Uint8Array(fileBytes);
  const size = origBytes.length;

  // 1. 计算 BLAKE3 文件哈希（去重 + AD 绑定）
  const fileHashBytes = computeFileHash(origBytes);
  const fileHashHex = bytesToHex(fileHashBytes);

  // 2. 生成缩略图（OffscreenCanvas，失败返回空字符串）
  const thumbB64 = await generateThumbnailWorker(fileBytes, mime);

  // 3. 分块加密（CHUNK_SIZE 切片，XChaCha20-Poly1305）
  const totalChunks = Math.ceil(size / CHUNK_SIZE);
  const chunkDataB64: string[] = [];

  for (let c = 0; c < totalChunks; c++) {
    const start = c * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, size);
    const chunkPlain = origBytes.slice(start, end);

    const encryptedChunk = await encryptChunk(
      chunkPlain, photoKey, c, totalChunks, fileHashHex,
    );
    chunkDataB64.push(bytesToBase64(encryptedChunk));

    // 安全清零明文块
    chunkPlain.fill(0);
  }

  // 4. 构造 PhotoMeta + 加密元数据（chunkDataB64 内联到 meta）
  const meta: PhotoMeta = {
    name: fileName,
    mime,
    size,
    thumbB64,
    chunkIds: [],
    chunkDataB64,
    fileHash: fileHashHex,
    createdAt: Date.now(),
  };
  const metaB64 = await encryptMeta(meta, photoKey);

  // 安全清零原始字节
  origBytes.fill(0);

  return {
    hash: fileHashHex,
    thumbB64,
    metaB64,
    name: `meta_${fileName}`,
    mime,
    size,
  };
}

/* ------------------------------------------------------------------ *
 * Parsed Import：meta-only 加密（复用 encryptMeta，不重复加密 chunks）*
 * ------------------------------------------------------------------ */

/**
 * 处理 meta-only 加密：
 *   1. 从已解密的 PhotoMeta 中提取 fileHash / thumbB64 / name / mime / size
 *   2. 调用 encryptMeta 用当前 photoKey 重新加密元数据
 *   3. 返回加密后的 metaB64 + 去重哈希 + 缩略图
 *
 * 与 processPhoto 的区别：
 *   - 不读取文件字节（已通过 .venc 解密获得）
 *   - 不计算文件哈希（复用 meta.fileHash，保证去重一致性）
 *   - 不生成缩略图（复用 meta.thumbB64）
 *   - 不分块加密 chunks（chunks 已加密，直接内联到新 meta）
 *
 * @param meta 已解密的元数据
 * @param photoKey 照片模块独立密钥
 * @param recordName verthys 记录名
 * @returns { metaB64, hash, thumbB64, name, mime, size, recordName }
 */
async function processPhotoMetaOnly(
  meta: PhotoMeta,
  photoKey: string,
  recordName: string,
): Promise<{
  metaB64: string;
  hash: string;
  thumbB64: string;
  name: string;
  mime: string;
  size: number;
  recordName: string;
}> {
  // 重新加密元数据（chunks 已加密，内联到 meta）
  const metaB64 = await encryptMeta(meta, photoKey);

  return {
    metaB64,
    hash: meta.fileHash,
    thumbB64: meta.thumbB64 ?? "",
    name: meta.name,
    mime: meta.mime,
    size: meta.size,
    recordName,
  };
}

/* ------------------------------------------------------------------ *
 * Worker 消息入口（区分完整加密 / meta-only 加密）                     *
 * ------------------------------------------------------------------ */

/** 判断是否为 meta-only 加密请求（含 meta 字段且不含 fileBytes） */
function isMetaOnlyRequest(data: unknown): data is PhotoMetaCryptoRequest {
  return (
    typeof data === "object" &&
    data !== null &&
    "meta" in data &&
    "photoKey" in data &&
    "recordName" in data &&
    !("fileBytes" in data)
  );
}

self.onmessage = async (e: MessageEvent<PhotoCryptoRequest | PhotoMetaCryptoRequest>) => {
  const req = e.data;

  // ===== meta-only 加密路径（Parsed Import） =====
  if (isMetaOnlyRequest(req)) {
    const { id, meta, photoKey, recordName } = req;
    try {
      const result = await processPhotoMetaOnly(meta, photoKey, recordName);
      const response: PhotoMetaCryptoSuccess = {
        id,
        ok: true,
        metaB64: result.metaB64,
        hash: result.hash,
        thumbB64: result.thumbB64,
        name: result.name,
        mime: result.mime,
        size: result.size,
        recordName: result.recordName,
      };
      (self as unknown as DedicatedWorkerGlobalScope).postMessage(response);
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      console.error(`[photo-crypto.worker] meta-only 加密失败: ${recordName}`, e);
      const response: PhotoCryptoFailure = {
        id,
        ok: false,
        name: recordName,
        error,
      };
      (self as unknown as DedicatedWorkerGlobalScope).postMessage(response);
    }
    return;
  }

  // ===== 完整加密路径（常规导入） =====
  const { id, fileName, mime, fileBytes, photoKey } = req as PhotoCryptoRequest;

  try {
    const result = await processPhoto(fileName, mime, fileBytes, photoKey);

    const response: PhotoCryptoSuccess = {
      id,
      ok: true,
      hash: result.hash,
      thumbB64: result.thumbB64,
      metaB64: result.metaB64,
      name: result.name,
      mime: result.mime,
      size: result.size,
    };
    (self as unknown as DedicatedWorkerGlobalScope).postMessage(response);
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    console.error(`[photo-crypto.worker] 加密失败: ${fileName}`, e);

    const response: PhotoCryptoFailure = {
      id,
      ok: false,
      name: fileName,
      error,
    };
    (self as unknown as DedicatedWorkerGlobalScope).postMessage(response);
  }
};

// 导出消息类型供主线程使用（类型仅，运行时无副作用）
export {};
