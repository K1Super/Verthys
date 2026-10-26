/**
 * workers/photo-crypto.worker.ts — 照片加密 Web Worker
 *
 * Comprehensive_optimization：异步批处理流水线 — 传输器阶段（Web Worker 池）
 *
 * =============================================================================
 * 职责
 * =============================================================================
 * 在独立 Web Worker 线程中执行 CPU 密集型准备任务，避免阻塞渲染进程主线程：
 *   加密（导入链路）：
 *     1. BLAKE3 文件哈希计算（去重 + AD 绑定）
 *     2. OffscreenCanvas 缩略图生成（400×400 JPEG 0.85）
 *     3. 分块循环与密文哈希（加解密本身经 RPC 下沉到 Tauri worker）
 *   解密（读取链路：列表按需解密 / 查看原图）：
 *     4. 元数据与数据块的 RPC 调度、完整性校验、明文零拷贝回传
 *
 * 密钥边界：本线程不接收模块密钥、不执行 PBKDF2/HKDF、不持有任何长驻密钥；
 * 每次记录加解密都是一次主线程 RPC（WorkerRpcClient），由 Tauri worker
 * 在其进程内完成派生与 AEAD。
 *
 * =============================================================================
 * 零拷贝传输
 * =============================================================================
 * - 输入：fileBytes 通过 transferList 零所有权转让到 Worker（主线程失去访问权）
 * - 输出：加密块仅回传 base64 字符串与元数据
 * - 解密输出：明文块以 transferList 零拷贝回传（主线程是唯一消费方，
 *   Worker 侧转移后即失去访问权，明文不在工作线程多驻留一份）
 *
 * =============================================================================
 * 消息协议（类型与响应装配集中定义于 photo-crypto-protocol）
 * =============================================================================
 * 主线程 → Worker：
 *   { id, fileName, mime, fileBytes: ArrayBuffer, slim? }   （完整加密）
 *   { id, meta, recordName, slim? }                         （meta-only 加密）
 *   { id, op: "encrypt_slim_thumb", thumbB64, wrappedFileKey, fileHashHex, label }
 *   { id, op: "encrypt_slim_set", set, wrappedFileKey, fileHashHex, label }
 *   { id, op: "encrypt_slim_photo", fileBytes, fileHashHex, ..., slim }（重打包）
 *   { id, op: "decrypt_meta", metaB64, label }               （元数据解密）
 *   { id, op: "decrypt_thumb", thumbCipherB64, wrappedFileKey, fileHashHex, label }
 *   { id, op: "decrypt_slim_set", setCipherB64, wrappedFileKey, fileHashHex, label }
 *   { id, op: "decrypt_chunks", chunksB64, fileHashHex, label, wrappedFileKey? }（数据块解密）
 *
 * Worker → 主线程：
 *   完整加密：{ id, ok: true, hash, thumbB64, metaB64?, external?, name, mime, size }
 *     - external 为外置块产物（{ chunkB64List, chunkHashes, metaTemplate }）：
 *       块密文总量超过内联阈值时携带，此时 metaB64 缺省（元数据待主线程
 *       回填块引用后重新加密）；响应装配必须逐字段透传，禁止裁剪
 *   meta-only：{ id, ok: true, metaB64, hash, thumbB64, name, mime, size, recordName }
 *   元数据解密：{ id, ok: true, meta }
 *   数据块解密：{ id, ok: true, plaintexts: ArrayBuffer[] }（transferList 零拷贝回传）
 *   失败：{ id, ok: false, error, name }
 *
 * =============================================================================
 * 安全边界
 * =============================================================================
 * - 本线程只处理密文、公开参数与当前任务明文；明文缓冲用毕即时清零
 * - 模块密钥、文件密钥、派生结果全部留在 Tauri worker 进程内
 * - Worker 不接触 verthys 句柄；仅通过主线程 RPC 间接使用内容层命令
 */

/// <reference lib="webworker" />

import { blake3 } from "@noble/hashes/blake3";
import type { PhotoMeta, SlimChunkSet } from "../types/crypto";
import {
  FILE_HASH_LEN, MAX_INLINE_META_BYTES, SALT_LEN, CHUNK_SIZE,
  PHOTO_FMT_SLIM,
} from "../constants/crypto_const";
import { PHOTO_THUMB_MAX_CHARS } from "../constants/photo_budget.generated";
import { bytesToBase64, base64ToBytes, bytesToHex } from "../utils/binary_codec";
import { WorkerRpcClient } from "./worker-rpc";

/* ------------------------------------------------------------------ *
 * 消息类型与响应装配（集中定义于 photo-crypto-protocol）               *
 *                                                                    *
 * 本文件 re-export 全部消息类型，保持既有导入路径（worker / 池 /       *
 * 流水线）不变；装配函数在该模块内实现并被单元测试锁定，核心不变式：     *
 * 完整加密响应必须原样透传处理产物（含 external），禁止裁剪字段。       *
 * ------------------------------------------------------------------ */

import {
  assemblePhotoCryptoSuccess,
  assemblePhotoCryptoFailure,
  assemblePhotoMetaCryptoSuccess,
  assemblePhotoSlimThumbSuccess,
  assemblePhotoSlimSetSuccess,
  assemblePhotoDecryptMetaSuccess,
  assemblePhotoDecryptThumbSuccess,
  assemblePhotoDecryptSlimSetSuccess,
  assemblePhotoDecryptChunksSuccess,
  type PhotoCryptoRequest,
  type PhotoCryptoRequestEnvelope,
  type PhotoDecryptChunksRequest,
  type PhotoDecryptMetaRequest,
  type PhotoDecryptThumbRequest,
  type PhotoDecryptSlimSetRequest,
  type PhotoMetaCryptoRequest,
  type PhotoMetaProcessResult,
  type PhotoProcessResult,
  type PhotoSlimThumbRequest,
  type PhotoSlimSetRequest,
  type PhotoSlimRepackRequest,
  type SlimSetResult,
  type SlimThumbResult,
  type SlimWorkerKeys,
} from "./photo-crypto-protocol";

export type {
  PhotoCryptoRequest,
  PhotoCryptoResponse,
  PhotoCryptoSuccess,
  PhotoCryptoFailure,
  PhotoExternalParts,
  PhotoMetaCryptoRequest,
  PhotoMetaCryptoSuccess,
  PhotoDecryptMetaRequest,
  PhotoDecryptMetaSuccess,
  PhotoDecryptThumbRequest,
  PhotoDecryptThumbSuccess,
  PhotoDecryptSlimSetRequest,
  PhotoDecryptSlimSetSuccess,
  PhotoDecryptChunksRequest,
  PhotoDecryptChunksSuccess,
  PhotoSlimThumbRequest,
  PhotoSlimThumbSuccess,
  PhotoSlimSetRequest,
  PhotoSlimSetSuccess,
  PhotoSlimRepackRequest,
  SlimThumbResult,
  SlimSetResult,
} from "./photo-crypto-protocol";

/** Worker 全局作用域（DOM lib 下 self 不含 transfer 重载，统一收敛于此） */
const workerScope = self as unknown as DedicatedWorkerGlobalScope;

/** 记录加解密 RPC：密钥与派生在 Tauri worker 进程内完成 */
const workerRpc = new WorkerRpcClient((message) => workerScope.postMessage(message));

/* ------------------------------------------------------------------ *
 * OffscreenCanvas 缩略图生成（Worker 兼容，无 DOM 依赖）              *
 * ------------------------------------------------------------------ */

/** 缩略图编码档位（质量优先、逐档降级）：任选一档必须落在缩略图字符预算内 */
const THUMB_CANDIDATES: ReadonlyArray<{ maxSide: number; quality: number }> = [
  { maxSide: 400, quality: 0.85 },
  { maxSide: 400, quality: 0.7 },
  { maxSide: 320, quality: 0.75 },
  { maxSide: 256, quality: 0.7 },
  { maxSide: 192, quality: 0.6 },
];

/**
 * 按档位编码一帧缩略图（等比缩放到 maxSide 内，JPEG 指定质量）。
 *
 * @returns base64 字符串（画布不可用返回空串）
 */
async function encodeThumbCandidate(
  bitmap: ImageBitmap,
  maxSide: number,
  quality: number,
): Promise<string> {
  let w = bitmap.width, h = bitmap.height;
  if (w > maxSide) { h = Math.round(h * (maxSide / w)); w = maxSide; }
  if (h > maxSide) { w = Math.round(w * (maxSide / h)); h = maxSide; }
  if (w <= 0 || h <= 0) return "";

  const canvas = new OffscreenCanvas(w, h);
  const ctx = canvas.getContext("2d");
  if (!ctx) return "";
  ctx.drawImage(bitmap, 0, 0, w, h);

  // 转为 Blob → base64（OffscreenCanvas.convertToBlob 替代 canvas.toDataURL）
  const thumbBlob = await canvas.convertToBlob({ type: "image/jpeg", quality });
  const thumbBuf = await thumbBlob.arrayBuffer();
  return bytesToBase64(new Uint8Array(thumbBuf));
}

/**
 * 在 Worker 中生成缩略图（使用 createImageBitmap + OffscreenCanvas）。
 *
 * 与主线程 generateThumbnail（Image + Canvas）的产物语义一致（等比缩放 +
 * JPEG），差异在于本函数按缩略图字符预算收敛编码档位：
 *
 * Why 预算收敛：缩略图与引用同处一条元数据记录，读取侧按缓存管控阈值决定
 * 是否缓存记录数据；缩略图一旦越预算，含缩略图的记录就会超出管控阈值，
 * 每次渲染都要重新搬运并解密整条记录（缓存对缩略图永远失效）。此处从
 * 编码侧保证记录体积可被缓存承载，降级只发生在超出预算的少数照片上。
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

    let smallest = "";
    try {
      for (const cand of THUMB_CANDIDATES) {
        const b64 = await encodeThumbCandidate(bitmap, cand.maxSide, cand.quality);
        if (!b64) continue;
        smallest = b64;
        if (b64.length <= PHOTO_THUMB_MAX_CHARS) return b64;
      }
    } finally {
      bitmap.close();
    }

    // 全部档位仍越预算：返回最小产物并留痕（说明档位表需要随预算调整）
    console.warn(
      `[photo-crypto.worker] 缩略图仍超出预算（${smallest.length} > ${PHOTO_THUMB_MAX_CHARS} 字符）`,
    );
    return smallest;
  } catch (e) {
    // 缩略图生成失败不阻塞导入（返回空字符串，前端显示占位图）
    console.warn("[photo-crypto.worker] 缩略图生成失败:", e);
    return "";
  }
}

/* ------------------------------------------------------------------ *
 * 单张照片加密处理（分块与索引加解密经 RPC，密钥留在 Tauri worker）
 * ------------------------------------------------------------------ */

/**
 * 处理单张照片加密：
 *   1. 计算 BLAKE3 文件哈希
 *   2. 生成缩略图
 *   3. 经 RPC 逐块加密（密钥与派生在 Tauri worker 进程内）
 *   4. 构造 PhotoMeta 并加密索引
 *
 * @param fileName 文件名
 * @param mime MIME 类型
 * @param fileBytes 文件原始字节
 * @param slim 索引瘦身布局的公开参数与包裹态文件密钥（缺省 = 既有布局）
 * @returns { hash, thumbB64, metaB64, name, mime, size }
 */
async function processPhoto(
  fileName: string,
  mime: string,
  fileBytes: ArrayBuffer,
  slim?: SlimWorkerKeys,
): Promise<PhotoProcessResult> {
  const origBytes = new Uint8Array(fileBytes);
  const size = origBytes.length;

  // 1. 计算 BLAKE3 文件哈希（去重 + AD 绑定）
  const fileHashHex = bytesToHex(blake3(origBytes, { dkLen: FILE_HASH_LEN }));

  // 2. 生成缩略图（OffscreenCanvas，失败返回空字符串）
  const thumbB64 = await generateThumbnailWorker(fileBytes, mime);

  // 3. 分块加密（CHUNK_SIZE 切片）：布局由调用方给定的瘦身参数决定
  const totalChunks = Math.ceil(size / CHUNK_SIZE);
  const chunkDataB64: string[] = [];
  const chunkHashes: string[] = [];
  let encryptedBytesTotal = 0;
  const slimLayout = slim !== undefined;
  // 既有布局一次派生覆盖全文件块：盐由 worker 生成后随每块密文携带
  const fileSaltB64 = slim?.fileSaltB64
    ?? bytesToBase64(crypto.getRandomValues(new Uint8Array(SALT_LEN)));

  for (let c = 0; c < totalChunks; c++) {
    const start = c * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, size);
    const chunkPlain = origBytes.slice(start, end);
    try {
      const sealed = await workerRpc.request({
        op: "seal",
        module: "photo",
        kind: slimLayout ? "slim_chunk" : "chunk",
        data: bytesToBase64(chunkPlain),
        salt: slimLayout ? undefined : fileSaltB64,
        fileHash: fileHashHex,
        seq: c,
        total: totalChunks,
        wrappedKey: slim?.wrappedFileKey,
      });
      const cipherBytes = base64ToBytes(sealed.dataB64);
      chunkDataB64.push(sealed.dataB64);
      encryptedBytesTotal += cipherBytes.length;
      // 每块密文的 BLAKE3：容器导出的逐块完整性校验权威值（与负载同步产生）
      chunkHashes.push(bytesToHex(blake3(cipherBytes, { dkLen: FILE_HASH_LEN })));
    } finally {
      // 安全清零明文块
      chunkPlain.fill(0);
    }
  }

  // 4. 内联/外置判定：块密文总量超过内联阈值 → 外置（块先落独立记录，
  //    meta 只存引用）；否则内联进 meta（原路径，单记录自包含）
  const external = encryptedBytesTotal > MAX_INLINE_META_BYTES;

  const metaTemplate: PhotoMeta = {
    name: fileName,
    mime,
    size,
    // 索引瘦身布局的缩略图独立成记录，索引内不留缩略图数据
    thumbB64: slimLayout ? "" : thumbB64,
    chunkIds: [],
    chunkDataB64: external ? [] : chunkDataB64,
    chunkHashes,
    fileHash: fileHashHex,
    createdAt: Date.now(),
    ...(slim
      ? { fmt: PHOTO_FMT_SLIM, wrappedFileKey: slim.wrappedFileKey }
      : {}),
  };

  // 安全清零原始字节
  origBytes.fill(0);

  if (!external) {
    // 内联路径：元数据即刻加密回传（与旧行为一致）
    const metaPlain = new TextEncoder().encode(JSON.stringify(metaTemplate));
    try {
      const sealed = await workerRpc.request({
        op: "seal",
        module: "photo",
        kind: slimLayout ? "slim_meta" : "meta",
        data: bytesToBase64(metaPlain),
        salt: slim?.fileSaltB64,
      });
      return {
        hash: fileHashHex,
        thumbB64,
        metaB64: sealed.dataB64,
        name: `meta_${fileName}`,
        mime,
        size,
      };
    } finally {
      metaPlain.fill(0);
    }
  }

  // 外置路径：块与元数据模板回传主线程——块上传获得记录 ID 后，
  // 主线程回填 chunkIds（索引瘦身布局另需回填缩略图记录 ID）并经
  // meta-only 加密生成最终 meta。
  return {
    hash: fileHashHex,
    thumbB64,
    external: {
      chunkB64List: chunkDataB64,
      chunkHashes,
      metaTemplate,
    },
    name: `meta_${fileName}`,
    mime,
    size,
  };
}

/* ------------------------------------------------------------------ *
 * Parsed Import：meta-only 加密（只重写索引，不重复处理已加密块）     *
 * ------------------------------------------------------------------ */

/**
 * 处理 meta-only 加密：
 *   1. 从已解密的 PhotoMeta 中提取 fileHash / thumbB64 / name / mime / size
 *   2. 经 RPC 用 Tauri worker 托管的模块密钥重新加密元数据
 *   3. 返回加密后的 metaB64 + 去重哈希 + 缩略图
 *
 * 与 processPhoto 的区别：
 *   - 不读取文件字节（已通过 .venc 解密获得）
 *   - 不计算文件哈希（复用 meta.fileHash，保证去重一致性）
 *   - 不生成缩略图（复用 meta.thumbB64）
 *   - 不分块加密 chunks（chunks 已加密，直接内联到新 meta）
 *
 * @param meta 已解密的元数据
 * @param recordName verthys 记录名
 * @param slim 索引瘦身布局的公开参数与包裹态文件密钥（来源布局为瘦身时必须沿用）
 * @returns { metaB64, hash, thumbB64, name, mime, size, recordName }
 */
async function processPhotoMetaOnly(
  meta: PhotoMeta,
  recordName: string,
  slim?: SlimWorkerKeys,
): Promise<PhotoMetaProcessResult> {
  // 索引瘦身布局：索引按文件盐加密（与包裹态密钥同盐），且索引内不保留
  //   缩略图数据（缩略图已独立成记录）；既有布局维持原行为。
  const payload = slim ? { ...meta, thumbB64: "" } : meta;
  const metaPlain = new TextEncoder().encode(JSON.stringify(payload));
  try {
    const sealed = await workerRpc.request({
      op: "seal",
      module: "photo",
      kind: slim ? "slim_meta" : "meta",
      data: bytesToBase64(metaPlain),
      salt: slim?.fileSaltB64,
    });
    return {
      metaB64: sealed.dataB64,
      hash: meta.fileHash,
      thumbB64: meta.thumbB64 ?? "",
      recordName,
    };
  } finally {
    metaPlain.fill(0);
  }
}

/**
 * 索引瘦身布局：加密缩略图记录载荷。
 *
 * 与索引任务共用同一文件盐，读取侧索引解密即可派生出同一把包裹密钥，
 * 缩略图解密不再产生第二次密钥派生。密文哈希（BLAKE3）随产物返回：
 * 记录去重与完整性校验共用该权威值。
 */
async function processEncryptSlimThumb(
  thumbB64: string,
  wrappedFileKey: string,
  fileHashHex: string,
): Promise<SlimThumbResult> {
  if (!thumbB64) {
    throw new Error("缩略图数据缺失，无法加密缩略图记录");
  }
  const sealed = await workerRpc.request({
    op: "seal",
    module: "photo",
    kind: "thumb",
    data: thumbB64,
    fileHash: fileHashHex,
    wrappedKey: wrappedFileKey,
  });
  const cipher = base64ToBytes(sealed.dataB64);
  return {
    thumbCipherB64: sealed.dataB64,
    thumbHash: bytesToHex(blake3(cipher, { dkLen: FILE_HASH_LEN })),
  };
}

/**
 * 索引瘦身布局：加密块集记录载荷（逐块引用与逐块哈希）。
 *
 * 与索引/缩略图共用同一文件盐 → 读取侧索引解密即可解封块集，不额外派生。
 */
async function processEncryptSlimSet(
  set: SlimChunkSet,
  wrappedFileKey: string,
  fileHashHex: string,
): Promise<SlimSetResult> {
  const payload = new TextEncoder().encode(JSON.stringify(set));
  try {
    const sealed = await workerRpc.request({
      op: "seal",
      module: "photo",
      kind: "chunkset",
      data: bytesToBase64(payload),
      fileHash: fileHashHex,
      wrappedKey: wrappedFileKey,
    });
    const cipher = base64ToBytes(sealed.dataB64);
    return {
      setCipherB64: sealed.dataB64,
      setHash: bytesToHex(blake3(cipher, { dkLen: FILE_HASH_LEN })),
    };
  } finally {
    payload.fill(0);
  }
}

/**
 * 索引瘦身布局：把既有布局照片的明文重加密为布局二产物（重打包专用）。
 *
 * 与常规导入的差异：不重新生成缩略图（沿用源索引内的缩略图，避免重编码漂移）；
 * 文件哈希沿用源索引值（同一内容的同一哈希，去重语义与去重锁不受影响）。
 * 产物形状与常规导入一致（外置块 + 元数据模板），主线程复用同一写入链路。
 */
async function processSlimRepack(
  fileBytes: ArrayBuffer,
  fileHashHex: string,
  name: string,
  mime: string,
  declaredSize: number,
  createdAt: number,
  thumbB64: string,
  slim: SlimWorkerKeys,
): Promise<PhotoProcessResult> {
  const origBytes = new Uint8Array(fileBytes);
  // 实际字节长度是唯一权威分块口径：源索引声明的 size 可能滞后（历史记录/
  //   异常中断），按声明值分块会截断末块或产出多余空块，新索引的 size 也随之失真。
  const size = origBytes.length;
  if (declaredSize !== size) {
    console.warn(`[slim-repack] 源索引声明大小与实得字节不一致（${declaredSize} ≠ ${size}），以实际为准`);
  }
  try {
    // 源校验：明文哈希必须与源索引声明一致（不一致即源数据损坏，拒绝重打包）
    const actualHash = bytesToHex(blake3(origBytes, { dkLen: FILE_HASH_LEN }));
    if (actualHash !== fileHashHex) {
      throw new Error(`源数据哈希不符（期望 ${fileHashHex}，实际 ${actualHash}），拒绝重打包`);
    }

    const totalChunks = Math.ceil(size / CHUNK_SIZE);
    const chunkDataB64: string[] = [];
    const chunkHashes: string[] = [];
    for (let c = 0; c < totalChunks; c++) {
      const start = c * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, size);
      const chunkPlain = origBytes.slice(start, end);
      try {
        const sealed = await workerRpc.request({
          op: "seal",
          module: "photo",
          kind: "slim_chunk",
          data: bytesToBase64(chunkPlain),
          fileHash: fileHashHex,
          seq: c,
          total: totalChunks,
          wrappedKey: slim.wrappedFileKey,
        });
        const cipher = base64ToBytes(sealed.dataB64);
        chunkDataB64.push(sealed.dataB64);
        chunkHashes.push(bytesToHex(blake3(cipher, { dkLen: FILE_HASH_LEN })));
      } finally {
        chunkPlain.fill(0);
      }
    }

    const metaTemplate: PhotoMeta = {
      name,
      mime,
      size,
      // 模板内保留明文缩略图：写入链路的缩略图记录上传需要，索引加密时会置空
      thumbB64,
      chunkIds: [],
      chunkDataB64: [],
      chunkHashes,
      fileHash: fileHashHex,
      createdAt,
      fmt: PHOTO_FMT_SLIM,
      wrappedFileKey: slim.wrappedFileKey,
    };

    return {
      hash: fileHashHex,
      thumbB64,
      external: { chunkB64List: chunkDataB64, chunkHashes, metaTemplate },
      name: `meta_${name}`,
      mime,
      size,
    };
  } finally {
    origBytes.fill(0);
  }
}

/* ------------------------------------------------------------------ *
 * 读取链路解密（列表按需解密 / 查看原图）                             *
 *                                                                    *
 * 主线程只发起请求并消费产物：base64 解码、密钥派生、AEAD 解密全部在   *
 * 本文件内完成，避免 MB 级载荷解密占用渲染线程。                       *
 * ------------------------------------------------------------------ */

/**
 * 提取可独立转移的 ArrayBuffer。
 *
 * 明文视图可能只是更大缓冲上的切片（偏移或长度未覆盖整体），此时直接转移
 * 底层缓冲会连带转移无关字节、并让接收端失去范围信息；仅在视图独占缓冲时
 * 零拷贝复用，否则切出精确范围。
 */
function toTransferableBuffer(view: Uint8Array): ArrayBuffer {
  if (view.byteOffset === 0 && view.byteLength === view.buffer.byteLength) {
    return view.buffer as ArrayBuffer;
  }
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
}

/**
 * 解密元数据。
 *
 * 摘要派生与 AEAD 全部由主线程 RPC 转交 Tauri worker；本线程只做 base64
 * 解码与 JSON 解析，明文缓冲用毕立即清零，不持有任何密钥材料。
 */
async function processDecryptMeta(metaB64: string): Promise<PhotoMeta> {
  const opened = await workerRpc.request({
    op: "open",
    module: "photo",
    kind: "meta",
    data: metaB64,
  });
  const plain = base64ToBytes(opened.dataB64);
  try {
    return JSON.parse(new TextDecoder().decode(plain)) as PhotoMeta;
  } catch {
    throw new Error("解密后的元数据 JSON 解析失败");
  } finally {
    plain.fill(0);
  }
}

/**
 * 解密瘦身布局的缩略图记录（列表路径的补取）。
 *
 * @param wrappedFileKey 包裹态文件密钥（主线程从索引取得）
 */
async function processDecryptThumb(
  thumbCipherB64: string,
  wrappedFileKey: string,
  fileHashHex: string,
): Promise<Uint8Array> {
  const opened = await workerRpc.request({
    op: "open",
    module: "photo",
    kind: "thumb",
    data: thumbCipherB64,
    fileHash: fileHashHex,
    wrappedKey: wrappedFileKey,
  });
  return base64ToBytes(opened.dataB64);
}

/**
 * 解密瘦身布局的块集记录并做结构校验。
 *
 * 结构来自本机写入，但读取侧仍按外部输入对待：项数不一致或含非法 ID
 * 即判损坏，避免把错位块序号带入后续 AD 校验。
 */
async function processDecryptSlimSet(
  setCipherB64: string,
  wrappedFileKey: string,
  fileHashHex: string,
): Promise<SlimChunkSet> {
  const opened = await workerRpc.request({
    op: "open",
    module: "photo",
    kind: "chunkset",
    data: setCipherB64,
    fileHash: fileHashHex,
    wrappedKey: wrappedFileKey,
  });
  const plain = base64ToBytes(opened.dataB64);
  try {
    const raw = JSON.parse(new TextDecoder().decode(plain)) as SlimChunkSet;
    if (!raw || !Array.isArray(raw.ids) || !Array.isArray(raw.hashes)) {
      throw new Error("块集结构非法");
    }
    if (raw.ids.length === 0 || raw.ids.length !== raw.hashes.length) {
      throw new Error(`块集项数不一致（id=${raw.ids.length}，hash=${raw.hashes.length}）`);
    }
    for (const id of raw.ids) {
      if (!Number.isInteger(id) || id <= 0) {
        throw new Error(`块集包含非法记录 ID: ${id}`);
      }
    }
    return raw;
  } finally {
    plain.fill(0);
  }
}

/**
 * 逐块解密并按输入顺序回传明文。
 *
 * 任一块失败即整体失败：残缺块拼接会渲染出半张图，与主线程"逐块尝试后
 * 统计失败"的语义一致（两条路径都拒绝产出不完整结果）；错误信息携带块
 * 序号，便于定位损坏块。
 *
 * @param wrappedFileKey 瘦身布局的包裹态文件密钥：提供时按 nonce|密文
 *   布局逐块解密（AD 绑定由序号位置给出）
 * @param chunkTotal 瘦身布局声明的块总数（必须与密文列表长度一致）
 * @param verify 完整性权威值：逐块密文哈希在解密前比对；
 *   整图明文哈希在解密后按序增量比对。任一不符即拒绝该任务。
 */
async function processDecryptChunks(
  chunksB64: string[],
  fileHashHex: string,
  wrappedFileKey?: string,
  chunkTotal?: number,
  verify?: { expectedHashes?: string[]; expectedFileHash?: string },
): Promise<ArrayBuffer[]> {
  if (chunksB64.length === 0) {
    throw new Error("待解密块列表为空");
  }
  const expectedHashes = verify?.expectedHashes;
  if (expectedHashes && expectedHashes.length > 0 && expectedHashes.length !== chunksB64.length) {
    throw new Error(
      `哈希项数与块数不一致（哈希 ${expectedHashes.length}，块 ${chunksB64.length}）`,
    );
  }
  const slim = wrappedFileKey !== undefined;
  if (slim && (!Number.isInteger(chunkTotal) || chunkTotal !== chunksB64.length)) {
    throw new Error(`块总数与密文数量不一致（声明 ${chunkTotal}，实得 ${chunksB64.length}）`);
  }

  // 已解密的明文块：失败路径必须逐块覆写清零（明文不得留在 Worker 堆中）
  const plaintexts: ArrayBuffer[] = [];
  try {
    // 整图哈希增量计算：不拼接大缓冲，逐块喂入哈希器
    const fileHasher = verify?.expectedFileHash
      ? blake3.create({ dkLen: FILE_HASH_LEN })
      : null;
    for (let c = 0; c < chunksB64.length; c++) {
      try {
        if (expectedHashes && expectedHashes.length > 0) {
          // 逐块密文哈希在解密前校验：先证密文与权威值一致，再解明文；
          // 不一致即拒绝该任务（确定性失败，主线程不重算）。
          const actual = bytesToHex(blake3(base64ToBytes(chunksB64[c]), { dkLen: FILE_HASH_LEN }));
          if (actual !== expectedHashes[c]) {
            throw new Error(`块密文哈希校验失败（第 ${c + 1}/${chunksB64.length} 块）`);
          }
        }
        const opened = await workerRpc.request(
          slim
            ? {
                op: "open",
                module: "photo",
                kind: "slim_chunk",
                data: chunksB64[c],
                fileHash: fileHashHex,
                seq: c,
                total: chunksB64.length,
                wrappedKey: wrappedFileKey,
              }
            : {
                op: "open",
                module: "photo",
                kind: "chunk",
                data: chunksB64[c],
                fileHash: fileHashHex,
              },
        );
        if (!slim) {
          // 自描述位置校验：块密文头部声明必须与列表位置一致。乱序/重复/截断
          // 的列表在拼接前即拒绝，避免把错误顺序带入后续整图哈希比对（既有
          // 布局的 seq/total 由加密端写入并被 AD 覆盖，故该判定不受篡改影响）
          if (opened.seq !== c || opened.total !== chunksB64.length) {
            throw new Error(
              `数据块顺序校验失败（seq=${opened.seq} total=${opened.total}，期望 ${c}/${chunksB64.length}）`,
            );
          }
        }
        const plaintext = base64ToBytes(opened.dataB64);
        fileHasher?.update(plaintext);
        plaintexts.push(toTransferableBuffer(plaintext));
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(`第 ${c + 1}/${chunksB64.length} 块解密失败: ${msg}`);
      }
    }
    if (fileHasher && verify?.expectedFileHash) {
      const actualFileHash = bytesToHex(fileHasher.digest());
      if (actualFileHash !== verify.expectedFileHash) {
        throw new Error(
          `整图哈希校验失败（期望 ${verify.expectedFileHash}，实际 ${actualFileHash}）`,
        );
      }
    }
    return plaintexts;
  } catch (e) {
    // 任一块失败（含整图哈希不符）时，此前已解密的块不再返回给调用方：
    //   在抛出前就地清零，杜绝明文在 Worker 堆中按 GC 时序残留。
    for (const buf of plaintexts) new Uint8Array(buf).fill(0);
    throw e;
  }
}

/* ------------------------------------------------------------------ *
 * Worker 消息入口（解密 / meta-only 加密 / 完整加密）                  *
 * ------------------------------------------------------------------ */

/** 判断是否为 meta-only 加密请求（含 meta 字段且不含 fileBytes） */
function isMetaOnlyRequest(data: unknown): data is PhotoMetaCryptoRequest {
  return (
    typeof data === "object" &&
    data !== null &&
    "meta" in data &&
    "recordName" in data &&
    !("fileBytes" in data)
  );
}

/** 判断是否为元数据解密请求（显式 op 标识，与加密请求无歧义） */
function isDecryptMetaRequest(data: unknown): data is PhotoDecryptMetaRequest {
  return typeof data === "object" && data !== null && "op" in data && data.op === "decrypt_meta";
}

/** 判断是否为数据块解密请求（显式 op 标识，与加密请求无歧义） */
function isDecryptChunksRequest(data: unknown): data is PhotoDecryptChunksRequest {
  return typeof data === "object" && data !== null && "op" in data && data.op === "decrypt_chunks";
}

/** 判断是否为索引瘦身布局的缩略图加密请求（显式 op 标识） */
function isSlimThumbRequest(data: unknown): data is PhotoSlimThumbRequest {
  return typeof data === "object" && data !== null && "op" in data && data.op === "encrypt_slim_thumb";
}

/** 判断是否为索引瘦身布局的缩略图解密请求（显式 op 标识） */
function isDecryptThumbRequest(data: unknown): data is PhotoDecryptThumbRequest {
  return typeof data === "object" && data !== null && "op" in data && data.op === "decrypt_thumb";
}

/** 判断是否为索引瘦身布局的块集加密请求（显式 op 标识） */
function isSlimSetRequest(data: unknown): data is PhotoSlimSetRequest {
  return typeof data === "object" && data !== null && "op" in data && data.op === "encrypt_slim_set";
}

/** 判断是否为索引瘦身布局的块集解密请求（显式 op 标识） */
function isDecryptSlimSetRequest(data: unknown): data is PhotoDecryptSlimSetRequest {
  return typeof data === "object" && data !== null && "op" in data && data.op === "decrypt_slim_set";
}

/** 判断是否为重打包加密请求（显式 op 标识） */
function isSlimRepackRequest(data: unknown): data is PhotoSlimRepackRequest {
  return typeof data === "object" && data !== null && "op" in data && data.op === "encrypt_slim_photo";
}

self.onmessage = async (e: MessageEvent<PhotoCryptoRequestEnvelope>) => {
  // RPC 结果由客户端消费；其余消息才是任务请求
  if (workerRpc.handleMessage(e.data)) return;
  const req = e.data;

  // ===== 元数据解密路径（列表按需解密 / 查看原图回填） =====
  if (isDecryptMetaRequest(req)) {
    const { id, metaB64, label } = req;
    try {
      const meta = await processDecryptMeta(metaB64);
      workerScope.postMessage(assemblePhotoDecryptMetaSuccess(id, meta));
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      console.error(`[photo-crypto.worker] 元数据解密失败: ${label}`, e);
      workerScope.postMessage(assemblePhotoCryptoFailure(id, label, error));
    }
    return;
  }

  // ===== 数据块解密路径（查看原图） =====
  if (isDecryptChunksRequest(req)) {
    const {
      id, chunksB64, fileHashHex, label,
      wrappedFileKey, chunkTotal, expectedHashes, expectedFileHash,
    } = req;
    try {
      const plaintexts = await processDecryptChunks(
        chunksB64, fileHashHex, wrappedFileKey, chunkTotal, { expectedHashes, expectedFileHash },
      );
      // 明文随 transferList 零拷贝回传：转移后 Worker 侧失去访问权，
      // 明文不在工作线程多驻留一份
      workerScope.postMessage(assemblePhotoDecryptChunksSuccess(id, plaintexts), plaintexts);
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      console.error(`[photo-crypto.worker] 数据块解密失败: ${label}`, e);
      workerScope.postMessage(assemblePhotoCryptoFailure(id, label, error));
    }
    return;
  }

  // ===== 索引瘦身布局：缩略图记录加密（导入链路） =====
  if (isSlimThumbRequest(req)) {
    const { id, thumbB64, fileHashHex, wrappedFileKey, label } = req;
    try {
      const result = await processEncryptSlimThumb(thumbB64, wrappedFileKey, fileHashHex);
      workerScope.postMessage(assemblePhotoSlimThumbSuccess(id, result));
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      console.error(`[photo-crypto.worker] 缩略图记录加密失败: ${label}`, e);
      workerScope.postMessage(assemblePhotoCryptoFailure(id, label, error));
    }
    return;
  }

  // ===== 索引瘦身布局：缩略图记录解密（列表路径的补取） =====
  if (isDecryptThumbRequest(req)) {
    const { id, thumbCipherB64, wrappedFileKey, fileHashHex, label } = req;
    try {
      const thumb = await processDecryptThumb(thumbCipherB64, wrappedFileKey, fileHashHex);
      const bytes = toTransferableBuffer(thumb);
      workerScope.postMessage(assemblePhotoDecryptThumbSuccess(id, bytes), [bytes]);
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      console.error(`[photo-crypto.worker] 缩略图记录解密失败: ${label}`, e);
      workerScope.postMessage(assemblePhotoCryptoFailure(id, label, error));
    }
    return;
  }

  // ===== 索引瘦身布局：块集记录加密（导入/重打包链路） =====
  if (isSlimSetRequest(req)) {
    const { id, set, fileHashHex, wrappedFileKey, label } = req;
    try {
      const result = await processEncryptSlimSet(set, wrappedFileKey, fileHashHex);
      workerScope.postMessage(assemblePhotoSlimSetSuccess(id, result));
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      console.error(`[photo-crypto.worker] 块集记录加密失败: ${label}`, e);
      workerScope.postMessage(assemblePhotoCryptoFailure(id, label, error));
    }
    return;
  }

  // ===== 索引瘦身布局：块集记录解密（查看原图 / 导出 / 删除级联） =====
  if (isDecryptSlimSetRequest(req)) {
    const { id, setCipherB64, wrappedFileKey, fileHashHex, label } = req;
    try {
      const set = await processDecryptSlimSet(setCipherB64, wrappedFileKey, fileHashHex);
      workerScope.postMessage(assemblePhotoDecryptSlimSetSuccess(id, set));
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      console.error(`[photo-crypto.worker] 块集记录解密失败: ${label}`, e);
      workerScope.postMessage(assemblePhotoCryptoFailure(id, label, error));
    }
    return;
  }

  // ===== 重打包加密路径（既有布局 → 索引瘦身布局） =====
  if (isSlimRepackRequest(req)) {
    const {
      id, fileBytes, fileHashHex, name, mime, size, createdAt, thumbB64, slim,
    } = req;
    try {
      const result = await processSlimRepack(
        fileBytes, fileHashHex, name, mime, size, createdAt, thumbB64, slim,
      );
      workerScope.postMessage(assemblePhotoCryptoSuccess(id, result));
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      console.error(`[photo-crypto.worker] 重打包加密失败: ${name}`, e);
      workerScope.postMessage(assemblePhotoCryptoFailure(id, name, error));
    }
    return;
  }

  // ===== meta-only 加密路径（Parsed Import） =====
  if (isMetaOnlyRequest(req)) {
    const { id, meta, recordName, slim } = req;
    try {
      const result = await processPhotoMetaOnly(meta, recordName, slim);
      const response = assemblePhotoMetaCryptoSuccess(id, result, meta);
      workerScope.postMessage(response);
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      console.error(`[photo-crypto.worker] meta-only 加密失败: ${recordName}`, e);
      const response = assemblePhotoCryptoFailure(id, recordName, error);
      workerScope.postMessage(response);
    }
    return;
  }

  // ===== 完整加密路径（常规导入） =====
  const { id, fileName, mime, fileBytes, slim } = req as PhotoCryptoRequest;

  try {
    const result = await processPhoto(fileName, mime, fileBytes, slim);
    // 逐字段装箱：产物含外部块输出（external）时必须一并回传，
    // 漏传会让主线程走内联分支并以「加密产物缺少元数据」失败
    const response = assemblePhotoCryptoSuccess(id, result);
    workerScope.postMessage(response);
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    console.error(`[photo-crypto.worker] 加密失败: ${fileName}`, e);

    const response = assemblePhotoCryptoFailure(id, fileName, error);
    workerScope.postMessage(response);
  }
};

// 导出消息类型供主线程使用（类型仅，运行时无副作用）
export {};
