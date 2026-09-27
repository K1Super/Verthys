/**
 * workers/parse-crypto.worker.ts — 解析预览还原 Web Worker
 *
 * 职责：把 .venc 容器的解包与逐张可导入性预检移出渲染主线程。
 * 主线程仅负责进度渲染与结果装载；容器解包（令牌派生 + 逐帧 AEAD）、
 * 首块密钥预检、逐块 base64 转换全部在本 Worker 内完成。
 *
 * =============================================================================
 * 消息协议
 * =============================================================================
 * 主线程 → Worker：
 *   { id, fileBytes: ArrayBuffer（transferList 零拷贝转让）, token, photoKey }
 * Worker → 主线程：
 *   { id, type: "progress", current, total }            逐张进度
 *   { id, ok: true, previews, undecryptable }           完成
 *   { id, ok: false, error }                            失败（令牌错误/容器损坏等）
 *
 * =============================================================================
 * 安全边界
 * =============================================================================
 * - Worker 仅接触容器字节与密钥字符串，不发起 IPC、不触碰 DOM。
 * - 解析产物（每张照片的密文块列表与轻量元数据）回传主线程后进入
 *   导入流水线，密文不在 Worker 之外解密。
 */

/// <reference lib="webworker" />

import {
  unpackVencV2,
  decryptChunk,
  decryptSlimChunk,
  unwrapSlimFileKey,
  type PhotoMeta,
} from "../lib/crypto";
import { bytesToBase64 } from "../utils/binary_codec";
import { PARSE_MAX_FRAME_COUNT, PHOTO_FMT_SLIM } from "../constants/crypto_const";

/** 主线程 → Worker 请求 */
export interface ParseCryptoRequest {
  /** 任务 ID（关联请求与响应） */
  id: number;
  /** 容器字节（transferList 零拷贝转让） */
  fileBytes: ArrayBuffer;
  /** 导出令牌（容器外层封装凭据） */
  token: string;
  /** 照片模块密钥（可导入性预检用；空串时全部计入不可解密） */
  photoKey: string;
}

/** 逐张进度（Worker → 主线程） */
export interface ParseCryptoProgress {
  id: number;
  type: "progress";
  /** 已完成预览数（含不可解密项） */
  current: number;
  /** 容器内照片总数 */
  total: number;
}

/** 单张预览还原结果（与主线程 ParsedPhotoPreview 结构同构） */
export interface ParseCryptoPreview {
  /** 显示名（轻量头直接可得，不经模块密钥） */
  name: string;
  /** 缩略图 data URI（无缩略图为空串） */
  thumb: string;
  /** 原始文件大小（字节） */
  size: number;
  /** 占位（容器内 meta 密文不回传，导入时重加密） */
  metaB64: string;
  /** 加密块 base64 列表（导入载荷） */
  chunkB64List: string[];
  /** 可导入性预检通过时组装的完整元数据；否则为 null */
  meta: PhotoMeta | null;
}

/** 完成响应（Worker → 主线程） */
export interface ParseCryptoSuccess {
  id: number;
  type: "success";
  ok: true;
  /** 预览列表（与容器照片顺序一致） */
  previews: ParseCryptoPreview[];
  /** 无法用当前模块密钥解密的照片数 */
  undecryptable: number;
  /** 空数据记录数（容器内无内容块）：与密钥不匹配分列，供 UI 准确归因 */
  emptyCount: number;
}

/** 失败响应（Worker → 主线程） */
export interface ParseCryptoFailure {
  id: number;
  type: "failure";
  ok: false;
  /** 分类错误文案（主线程据此映射用户提示） */
  error: string;
}

/** Worker 响应联合类型 */
export type ParseCryptoResponse =
  | ParseCryptoProgress
  | ParseCryptoSuccess
  | ParseCryptoFailure;

/** 终态响应（主线程 Promise 的 resolve 类型：进度消息在监听器内消费） */
export type ParseCryptoCompletion = ParseCryptoSuccess | ParseCryptoFailure;

self.onmessage = async (e: MessageEvent<ParseCryptoRequest>) => {
  const req = e.data;

  try {
    // 1. 解包 .venc 容器（令牌派生 + 逐帧 AEAD + 全链路校验）
    const containers = await unpackVencV2(new Uint8Array(req.fileBytes), req.token);

    // 2. 逐张预览还原 + 可导入性预检（模块密钥匹配时首块可解且 total 吻合）
    const previews: ParseCryptoPreview[] = [];
    const total = containers.length;
    let undecryptable = 0;
    /** 空数据记录数（无内容块）：既非可导入、也与密钥无关，必须与"密钥不匹配"分开归类 */
    let emptyCount = 0;

    for (let i = 0; i < containers.length; i++) {
      const container = containers[i];
      const lm = container.lightMeta;
      const chunkB64List = container.chunkBytes.map((b) => bytesToBase64(b));

      // 空数据记录（chunkCount = 0）：容器内本就不含内容块，无法也不应
      // 归因"密钥不匹配"——单独计数，避免向用户报错误原因
      const isEmptyRecord = lm.chunkCount === 0;

      let importable = false;
      // 索引瘦身布局：块密文按包裹态文件密钥解封（来源布局随容器携带），
      //   可导入性预检与本地导入采用同一判定口径
      const slim = lm.fmt === PHOTO_FMT_SLIM && typeof lm.wrappedFileKey === "string";
      if (!isEmptyRecord && req.photoKey && chunkB64List.length === lm.chunkCount) {
        try {
          if (slim) {
            const fileKey = await unwrapSlimFileKey(lm.wrappedFileKey!, req.photoKey);
            try {
              decryptSlimChunk(chunkB64List[0], fileKey, lm.fileHash, 0, lm.chunkCount);
              importable = true;
            } finally {
              fileKey.fill(0);
            }
          } else {
            const first = await decryptChunk(chunkB64List[0], req.photoKey, lm.fileHash);
            importable = first.seq === 0 && first.total === lm.chunkCount;
          }
        } catch {
          // 模块密钥不匹配或首块损坏：计入不可解密分类，不阻断其他照片预览
        }
      }

      // 可导入时预组装完整元数据（含内联块与逐块哈希），导入流水线仅重加密 meta；
      // 来源布局随元数据保留：块密文无法在缺少来源密钥时重写
      const meta: PhotoMeta | null = importable
        ? {
            name: lm.name,
            mime: lm.mime,
            size: lm.size,
            thumbB64: lm.thumbB64,
            chunkIds: [],
            chunkDataB64: chunkB64List,
            chunkHashes: lm.chunkHashes,
            fileHash: lm.fileHash,
            createdAt: lm.createdAt,
            ...(slim ? { fmt: PHOTO_FMT_SLIM, wrappedFileKey: lm.wrappedFileKey } : {}),
          }
        : null;

      if (isEmptyRecord) emptyCount++;
      else if (!importable) undecryptable++;
      previews.push({
        name: lm.name,
        thumb: lm.thumbB64 ? `url(data:image/jpeg;base64,${lm.thumbB64})` : "",
        size: lm.size,
        metaB64: "",
        chunkB64List,
        meta,
      });

      // 逐张进度（主线程 rAF 去重渲染）
      (self as unknown as DedicatedWorkerGlobalScope).postMessage({
        id: req.id,
        type: "progress",
        current: i + 1,
        total,
      } satisfies ParseCryptoProgress);
    }

    // 帧数防御（解包层已有 PARSE_MAX_FRAME_COUNT 校验，此处为双保险断言）
    if (previews.length > PARSE_MAX_FRAME_COUNT) {
      throw new Error("容器帧数超过解析上限");
    }

    (self as unknown as DedicatedWorkerGlobalScope).postMessage({
      id: req.id,
      type: "success",
      ok: true,
      previews,
      undecryptable,
      emptyCount,
    } satisfies ParseCryptoSuccess);
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    console.error("[parse-crypto.worker] 解析失败:", error);
    (self as unknown as DedicatedWorkerGlobalScope).postMessage({
      id: req.id,
      type: "failure",
      ok: false,
      error,
    } satisfies ParseCryptoFailure);
  }
};

// 导出协议类型供主线程使用（类型仅，运行时无副作用）
export {};