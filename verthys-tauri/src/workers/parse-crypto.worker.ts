/**
 * workers/parse-crypto.worker.ts — 备份预览还原 Web Worker
 *
 * 职责：把 .venc 可移植容器的预览扫描移出渲染主线程。
 * 主线程仅负责进度渲染与结果装载；令牌派生、清单解密、帧序与尾部计数
 * 校验全部在本 Worker 内完成。
 *
 * 预览阶段不保留任何块载荷：块级 AEAD、整图哈希与模块密钥重封装在
 * 正式导入阶段由 container-import.worker 完成。
 *
 * =============================================================================
 * 消息协议
 * =============================================================================
 * 主线程 → Worker：
 *   { id, fileBytes: ArrayBuffer（transferList 零拷贝转让）, token }
 * Worker → 主线程：
 *   { id, type: "progress", current }                   逐张进度（已扫描张数）
 *   { id, type: "success", ok: true, previews }         完成
 *   { id, type: "failure", ok: false, error }           失败（令牌错误/容器损坏等）
 */

/// <reference lib="webworker" />

import { unpackVencPreview } from "../lib/crypto";

/** 主线程 → Worker 请求 */
export interface ParseCryptoRequest {
  /** 任务 ID（关联请求与响应） */
  id: number;
  /** 容器字节（transferList 零拷贝转让） */
  fileBytes: ArrayBuffer;
  /** 导出令牌（容器外层封装凭据） */
  token: string;
}

/** 逐张进度（Worker → 主线程） */
export interface ParseCryptoProgress {
  id: number;
  type: "progress";
  /** 已扫描照片数（容器未提供总数，仅作已处理计数） */
  current: number;
}

/** 单张预览结果（与主线程 ParsedPhotoPreview 结构同构，不含块载荷） */
export interface ParseCryptoPreview {
  /** 显示名 */
  name: string;
  /** 缩略图 data URI（无缩略图为空串） */
  thumb: string;
  /** 原始文件大小（字节） */
  size: number;
  /** MIME 类型 */
  mime: string;
  /** BLAKE3 文件哈希（内容身份，导入去重使用） */
  fileHash: string;
  /** 数据块总数 */
  chunkCount: number;
  /** 创建时间戳（毫秒） */
  createdAt: number;
}

/** 完成响应（Worker → 主线程） */
export interface ParseCryptoSuccess {
  id: number;
  type: "success";
  ok: true;
  /** 预览列表（与容器照片顺序一致） */
  previews: ParseCryptoPreview[];
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

const workerScope = self as unknown as DedicatedWorkerGlobalScope;

self.onmessage = async (e: MessageEvent<ParseCryptoRequest>) => {
  const req = e.data;

  try {
    const previews = await unpackVencPreview(
      new Uint8Array(req.fileBytes),
      req.token,
      (_manifest, index) => {
        workerScope.postMessage({
          id: req.id,
          type: "progress",
          current: index + 1,
        } satisfies ParseCryptoProgress);
      },
    );

    workerScope.postMessage({
      id: req.id,
      type: "success",
      ok: true,
      previews: previews.map(({ lightMeta }) => ({
        name: lightMeta.name,
        thumb: lightMeta.thumbB64 ? `url(data:image/jpeg;base64,${lightMeta.thumbB64})` : "",
        size: lightMeta.size,
        mime: lightMeta.mime,
        fileHash: lightMeta.fileHash,
        chunkCount: lightMeta.chunkCount,
        createdAt: lightMeta.createdAt,
      })),
    } satisfies ParseCryptoSuccess);
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    console.error("[parse-crypto.worker] 解析失败:", error);
    workerScope.postMessage({
      id: req.id,
      type: "failure",
      ok: false,
      error,
    } satisfies ParseCryptoFailure);
  }
};

// 导出协议类型供主线程使用（类型仅，运行时无副作用）
export {};
