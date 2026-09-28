/**
 * workers/photo-crypto.worker.ts — 照片加密 Web Worker
 *
 * Comprehensive_optimization：异步批处理流水线 — 传输器阶段（Web Worker 池）
 *
 * =============================================================================
 * 职责
 * =============================================================================
 * 在独立 Web Worker 线程中执行 CPU 密集型密码学任务，避免阻塞渲染进程主线程：
 *   加密（导入链路）：
 *     1. BLAKE3 文件哈希计算（去重 + AD 绑定）
 *     2. OffscreenCanvas 缩略图生成（400×400 JPEG 0.85）
 *     3. XChaCha20-Poly1305 分块加密（meta + chunks 内联）
 *     4. 元数据加密（encryptMeta）
 *   解密（读取链路：列表按需解密 / 查看原图）：
 *     5. 元数据解密（decrypt_meta）
 *     6. 数据块解密（decrypt_chunks，逐块明文零拷贝回传）
 *
 * 两条链路复用 lib/crypto.ts 的同一套原语（encryptMeta / encryptChunk /
 * computeFileHash / decryptMeta / decryptChunk），字节兼容：不改变加密算法、
 * AD 构造、密钥派生流程与密文布局。
 *
 * =============================================================================
 * 零拷贝传输
 * =============================================================================
 * - 输入：fileBytes 通过 transferList 零所有权转让到 Worker（主线程失去访问权）
 * - 输出：加密后的 chunk bytes 等不再回传（仅回传 base64 字符串 + 元数据）
 *   避免 transferList 反向传输的复杂性，base64 字符串序列化开销可接受
 * - 解密输出：明文块以 transferList 零拷贝回传（主线程是唯一消费方，
 *   Worker 侧转移后即失去访问权，明文不在工作线程多驻留一份）
 *
 * =============================================================================
 * 消息协议（类型与响应装配集中定义于 photo-crypto-protocol）
 * =============================================================================
 * 主线程 → Worker：
 *   { id, fileName, mime, fileBytes: ArrayBuffer, photoKey: string }
 *   { id, meta, photoKey, recordName }                     （meta-only 加密）
 *   { id, op: "decrypt_meta", metaB64, photoKey, label }   （元数据解密）
 *   { id, op: "decrypt_chunks", chunksB64, photoKey, fileHashHex, label }（数据块解密）
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
 * - photoKey 在 Worker 内存中使用后立即 zeroize（由 encryptMeta/encryptChunk 内部完成）
 * - fileBytes 使用后 fill(0) 清零
 * - 解密任务结束清空按盐派生的子密钥缓存，派生结果不跨任务驻留；密钥字符串
 *   本身受 JS 不可变字符串限制无法原地清零，故以"任务内使用、不跨任务持有引用"约束
 * - Worker 不接触 verthys 句柄、不发起 IPC，仅做纯加密计算
 */

/// <reference lib="webworker" />

import { blake3 } from "@noble/hashes/blake3";
import {
  encryptMeta,
  encryptChunk,
  computeFileHash,
  decryptMeta,
  decryptChunk,
  createSlimFileKeys,
  encryptSlimMeta,
  encryptSlimChunk,
  decryptSlimChunk,
  encryptSlimThumb,
  decryptSlimThumb,
  encryptSlimChunkSet,
  decryptSlimChunkSet,
  unwrapSlimFileKey,
  clearFileKeyCache,
  bytesToHex,
  TYPE_PHOTO_META,
  CHUNK_SIZE,
  type PhotoMeta,
  type SlimChunkSet,
} from "../lib/crypto";
import {
  FILE_HASH_LEN, MAX_INLINE_META_BYTES, SALT_LEN,
  PHOTO_WRITE_FMT, PHOTO_FMT_SLIM,
} from "../constants/crypto_const";
import { PHOTO_THUMB_MAX_CHARS } from "../constants/photo_budget.generated";
import { bytesToBase64, base64ToBytes } from "../utils/binary_codec";

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
  type SlimMetaParams,
  type SlimSetResult,
  type SlimThumbResult,
} from "./photo-crypto-protocol";

/** 元数据解密产物（缩略图明文为可转移缓冲，既有布局为 undefined） */
interface PhotoDecryptMetaResult {
  meta: PhotoMeta;
  thumbBytes?: ArrayBuffer;
}

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
): Promise<PhotoProcessResult> {
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
  const chunkHashes: string[] = [];
  let encryptedBytesTotal = 0;

  // 写入布局由开关决定（默认既有布局）：
  //   既有布局：每文件一个盐派生文件子密钥，块密文携带 salt|seq|total|nonce；
  //   索引瘦身布局：随机文件密钥包裹后随索引保存，块密文只携带 nonce|密文。
  const slimLayout = PHOTO_WRITE_FMT === PHOTO_FMT_SLIM;
  const slimKeys = slimLayout ? await createSlimFileKeys(photoKey) : null;
  const fileSalt = slimKeys?.fileSalt ?? crypto.getRandomValues(new Uint8Array(SALT_LEN));

  try {
    for (let c = 0; c < totalChunks; c++) {
      const start = c * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, size);
      const chunkPlain = origBytes.slice(start, end);

      const encryptedChunk = slimKeys
        ? encryptSlimChunk(chunkPlain, slimKeys.fileKey, c, totalChunks, fileHashHex)
        : await encryptChunk(chunkPlain, photoKey, c, totalChunks, fileHashHex, fileSalt);
      chunkDataB64.push(bytesToBase64(encryptedChunk));
      encryptedBytesTotal += encryptedChunk.length;
      // 每块密文的 BLAKE3：容器导出的逐块完整性校验权威值（与负载同步产生）
      chunkHashes.push(bytesToHex(blake3(encryptedChunk, { dkLen: FILE_HASH_LEN })));

      // 安全清零明文块
      chunkPlain.fill(0);
    }
  } finally {
    // 文件密钥仅在本次块加密内有效；索引只保存其包裹态。
    // 文件盐属公开数据（已随包裹态密钥与索引密文头部携带），不参与清零。
    slimKeys?.fileKey.fill(0);
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
    ...(slimKeys
      ? { fmt: PHOTO_FMT_SLIM, wrappedFileKey: slimKeys.wrappedFileKey }
      : {}),
  };

  // 安全清零原始字节
  origBytes.fill(0);

  if (!external) {
    // 内联路径：元数据即刻加密回传（与旧行为一致）
    const metaB64 = await encryptMeta(metaTemplate, photoKey);
    return {
      hash: fileHashHex,
      thumbB64,
      metaB64,
      name: `meta_${fileName}`,
      mime,
      size,
    };
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
  slim?: SlimMetaParams,
): Promise<PhotoMetaProcessResult> {
  // 索引瘦身布局：索引按文件盐加密（与包裹态密钥同盐），且索引内不保留
  //   缩略图数据（缩略图已独立成记录）；既有布局维持原行为。
  const metaB64 = slim
    ? await encryptSlimMeta({ ...meta, thumbB64: "" }, photoKey, base64ToBytes(slim.fileSaltB64))
    : await encryptMeta(meta, photoKey);

  return {
    metaB64,
    hash: meta.fileHash,
    thumbB64: meta.thumbB64 ?? "",
    recordName,
  };
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
  fileSaltB64: string,
  fileHashHex: string,
  photoKey: string,
): Promise<SlimThumbResult> {
  if (!thumbB64) {
    throw new Error("缩略图数据缺失，无法加密缩略图记录");
  }
  const raw = base64ToBytes(thumbB64);
  try {
    const cipher = await encryptSlimThumb(
      raw, photoKey, base64ToBytes(fileSaltB64), fileHashHex,
    );
    return {
      thumbCipherB64: bytesToBase64(cipher),
      thumbHash: bytesToHex(blake3(cipher, { dkLen: FILE_HASH_LEN })),
    };
  } finally {
    raw.fill(0);
  }
}

/**
 * 索引瘦身布局：加密块集记录载荷（逐块引用与逐块哈希）。
 *
 * 与索引/缩略图共用同一文件盐 → 读取侧索引解密即可解封块集，不额外派生。
 */
async function processEncryptSlimSet(
  set: SlimChunkSet,
  fileSaltB64: string,
  fileHashHex: string,
  photoKey: string,
): Promise<SlimSetResult> {
  const cipher = await encryptSlimChunkSet(
    set, photoKey, base64ToBytes(fileSaltB64), fileHashHex,
  );
  return {
    setCipherB64: bytesToBase64(cipher),
    setHash: bytesToHex(blake3(cipher, { dkLen: FILE_HASH_LEN })),
  };
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
  size: number,
  createdAt: number,
  thumbB64: string,
  photoKey: string,
): Promise<PhotoProcessResult> {
  const origBytes = new Uint8Array(fileBytes);
  try {
    // 源校验：明文哈希必须与源索引声明一致（不一致即源数据损坏，拒绝重打包）
    const actualHash = bytesToHex(computeFileHash(origBytes));
    if (actualHash !== fileHashHex) {
      throw new Error(`源数据哈希不符（期望 ${fileHashHex}，实际 ${actualHash}），拒绝重打包`);
    }

    const totalChunks = Math.ceil(size / CHUNK_SIZE);
    const slimKeys = await createSlimFileKeys(photoKey);
    const chunkDataB64: string[] = [];
    const chunkHashes: string[] = [];
    try {
      for (let c = 0; c < totalChunks; c++) {
        const start = c * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, size);
        const chunkPlain = origBytes.slice(start, end);
        const encryptedChunk = encryptSlimChunk(
          chunkPlain, slimKeys.fileKey, c, totalChunks, fileHashHex,
        );
        chunkDataB64.push(bytesToBase64(encryptedChunk));
        chunkHashes.push(bytesToHex(blake3(encryptedChunk, { dkLen: FILE_HASH_LEN })));
        chunkPlain.fill(0);
      }
    } finally {
      slimKeys.fileKey.fill(0);
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
      wrappedFileKey: slimKeys.wrappedFileKey,
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
 * 解密元数据（复用 lib/crypto 的 decryptMeta，与主线程实现字节兼容）。
 *
 * 派生缓存跨任务有限驻留：Worker 常驻且池按任务轮转，每任务清空会让
 * "索引 + 缩略图"这类共享同一文件盐的连续解密各付一次 PBKDF2(150k)；
 * 缓存按"口令指纹 + 盐"键控（口令变更不会误命中）、容量有界、淘汰即零填充，
 * 并在模块密钥失效时由池下发标记、于该 Worker 下一任务入口清空。
 * 密钥字符串受 JS 不可变字符串限制无法原地清零，以"不跨会话持有密钥字符串 +
 * 缓存随失效清空"约束其生命周期。
 *
 * @param thumbCipherB64 索引瘦身布局的缩略图密文（提供时同任务解密：
 *   索引解密已派生同一把包裹密钥，缩略图解密不再额外派生）
 */
async function processDecryptMeta(
  metaB64: string,
  photoKey: string,
  thumbCipherB64?: string,
): Promise<PhotoDecryptMetaResult> {
  const meta = await decryptMeta(metaB64, photoKey);
  if (!thumbCipherB64) return { meta };
  if (!meta.wrappedFileKey) {
    throw new Error("索引缺少包裹态文件密钥，无法解密缩略图记录");
  }
  const thumb = await decryptSlimThumb(
    thumbCipherB64, photoKey, meta.wrappedFileKey, meta.fileHash,
  );
  return { meta, thumbBytes: toTransferableBuffer(thumb) };
}

/**
 * 逐块解密并按输入顺序回传明文。
 *
 * 任一块失败即整体失败：残缺块拼接会渲染出半张图，与主线程"逐块尝试后
 * 统计失败"的语义一致（两条路径都拒绝产出不完整结果）；错误信息携带块
 * 序号，便于定位损坏块。
 *
 * @param slim 索引瘦身布局参数（包裹态文件密钥与块总数）：提供时先解封
 *   随机文件密钥，再按 nonce|密文 布局逐块解密（AD 绑定由序号位置给出）
 * @param verify 完整性权威值：逐块密文哈希在解密前比对；
 *   整图明文哈希在解密后按序增量比对。任一不符即拒绝该任务，
 *   主线程不再重算（确定性失败）。
 */
async function processDecryptChunks(
  chunksB64: string[],
  photoKey: string,
  fileHashHex: string,
  slim?: { wrappedFileKey: string; chunkTotal: number },
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
  if (slim && (!Number.isInteger(slim.chunkTotal) || slim.chunkTotal !== chunksB64.length)) {
    throw new Error(`块总数与密文数量不一致（声明 ${slim.chunkTotal}，实得 ${chunksB64.length}）`);
  }

  let fileKey: Uint8Array | null = null;
  try {
    if (slim) {
      fileKey = await unwrapSlimFileKey(slim.wrappedFileKey, photoKey);
    }
    const plaintexts: ArrayBuffer[] = [];
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
        if (fileKey) {
          const plaintext = decryptSlimChunk(chunksB64[c], fileKey, fileHashHex, c, chunksB64.length);
          fileHasher?.update(plaintext);
          plaintexts.push(toTransferableBuffer(plaintext));
        } else {
          const { plaintext, seq, total } = await decryptChunk(chunksB64[c], photoKey, fileHashHex);
          // 自描述位置校验：块密文头部声明必须与列表位置一致。乱序/重复/截断
          // 的列表在拼接前即拒绝，避免把错误顺序带入后续整图哈希比对（既有
          // 布局的 seq/total 由加密端写入并被 AD 覆盖，故该判定不受篡改影响）
          if (seq !== c || total !== chunksB64.length) {
            throw new Error(
              `数据块顺序校验失败（seq=${seq} total=${total}，期望 ${c}/${chunksB64.length}）`,
            );
          }
          fileHasher?.update(plaintext);
          plaintexts.push(toTransferableBuffer(plaintext));
        }
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
  } finally {
    fileKey?.fill(0);
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
    "photoKey" in data &&
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
  const req = e.data;

  // 模块密钥失效后池会在此标记：本任务先行清空按盐派生缓存，再执行任务
  // （缓存键含口令指纹，正常换钥不会误命中；此处保证失效即释放）
  if ((req as { clearCache?: boolean }).clearCache === true) {
    clearFileKeyCache();
  }

  // ===== 元数据解密路径（列表按需解密 / 查看原图回填） =====
  if (isDecryptMetaRequest(req)) {
    const { id, metaB64, photoKey, label, thumbCipherB64 } = req;
    try {
      const { meta, thumbBytes } = await processDecryptMeta(metaB64, photoKey, thumbCipherB64);
      // 缩略图明文随 transferList 零拷贝回传（转移后 Worker 侧失去访问权）
      workerScope.postMessage(
        assemblePhotoDecryptMetaSuccess(id, meta, thumbBytes),
        thumbBytes ? [thumbBytes] : [],
      );
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
      id, chunksB64, photoKey, fileHashHex, label,
      wrappedFileKey, chunkTotal, expectedHashes, expectedFileHash,
    } = req;
    try {
      const slim = wrappedFileKey !== undefined && chunkTotal !== undefined
        ? { wrappedFileKey, chunkTotal }
        : undefined;
      const plaintexts = await processDecryptChunks(
        chunksB64, photoKey, fileHashHex, slim, { expectedHashes, expectedFileHash },
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
    const { id, thumbB64, fileSaltB64, fileHashHex, photoKey, label } = req;
    try {
      const result = await processEncryptSlimThumb(thumbB64, fileSaltB64, fileHashHex, photoKey);
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
    const { id, thumbCipherB64, wrappedFileKey, fileHashHex, photoKey, label } = req;
    try {
      const thumb = await decryptSlimThumb(thumbCipherB64, photoKey, wrappedFileKey, fileHashHex);
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
    const { id, set, fileSaltB64, fileHashHex, photoKey, label } = req;
    try {
      const result = await processEncryptSlimSet(set, fileSaltB64, fileHashHex, photoKey);
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
    const { id, setCipherB64, wrappedFileKey, fileHashHex, photoKey, label } = req;
    try {
      const set = await decryptSlimChunkSet(setCipherB64, photoKey, wrappedFileKey, fileHashHex);
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
      id, fileBytes, fileHashHex, name, mime, size, createdAt, thumbB64, photoKey,
    } = req;
    try {
      const result = await processSlimRepack(
        fileBytes, fileHashHex, name, mime, size, createdAt, thumbB64, photoKey,
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
    const { id, meta, photoKey, recordName, slim } = req;
    try {
      const result = await processPhotoMetaOnly(meta, photoKey, recordName, slim);
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
  const { id, fileName, mime, fileBytes, photoKey } = req as PhotoCryptoRequest;

  try {
    const result = await processPhoto(fileName, mime, fileBytes, photoKey);
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
