/**
 * workers/container-import.worker.ts — 备份容器正式导入 Worker
 *
 * 职责：在 Worker 内逐帧解密 .venc 容器，校验每张照片的块数/字节数/整图
 * BLAKE3，并把原始明文块经 RPC 交给 Tauri 侧用当前模块 MDEK 重新封装。
 *
 * 与预览 Worker 的分工：
 *   - 预览只解清单与尾部，不保留块载荷、不做块级认证；
 *   - 本 Worker 做全量块级 AEAD、整图哈希，并逐块重封装为本地存储密文。
 *
 * 背压：每张照片封装完成后立即投递给主线程，并等待主线程 `ack` 后才处理
 * 下一张。容器字节与单张照片的密文载荷是全部驻留上限，不随照片总数增长。
 *
 * =============================================================================
 * 消息协议
 * =============================================================================
 * 主线程 → Worker：
 *   { id, fileBytes: ArrayBuffer（transferList 零拷贝转让）, token, expectedPhotos }
 *   { id, type: "ack", index }                          上一张处理完毕
 * Worker → 主线程：
 *   { __verthysRpc: true, ... }                         加解密 RPC（由主线程桥接）
 *   { id, type: "photo", index, chunkB64List, ... }     单张封装产物
 *   { id, type: "done", ok: true, photos }              完成
 *   { id, type: "failure", ok: false, error }           失败（容器损坏/令牌错误）
 */

/// <reference lib="webworker" />

import { blake3 } from "@noble/hashes/blake3";
import { unpackVencStream } from "../lib/crypto";
import type { LightMeta } from "../types/crypto";
import { CHUNK_SIZE, FILE_HASH_LEN } from "../constants/crypto_const";
import { base64ToBytes, bytesToBase64, bytesToHex } from "../utils/binary_codec";
import { WorkerRpcClient } from "./worker-rpc";

/** 主线程 → Worker 请求 */
export interface ContainerImportRequest {
  /** 任务 ID（关联请求与响应） */
  id: number;
  /** 容器字节（transferList 零拷贝转让） */
  fileBytes: ArrayBuffer;
  /** 导出令牌（容器外层封装凭据） */
  token: string;
  /** 预览阶段的照片数：容器在预览后被替换时必须显式失败，不得静默错位 */
  expectedPhotos: number;
}

/** 主线程 → Worker 背压确认 */
export interface ContainerImportAck {
  id: number;
  type: "ack";
  /** 已处理完毕的照片序号 */
  index: number;
}

/** 单张照片的封装产物（块已用当前模块 MDEK 重新加密） */
export interface ContainerImportPhoto {
  id: number;
  type: "photo";
  /** 照片序号（与预览列表一致） */
  index: number;
  name: string;
  mime: string;
  size: number;
  thumbB64: string;
  fileHash: string;
  createdAt: number;
  /** 逐块密文 base64（按块序号） */
  chunkB64List: string[];
  /** 逐块密文 BLAKE3 hex（与 chunkB64List 等长） */
  chunkHashes: string[];
}

/** 完成响应 */
export interface ContainerImportDone {
  id: number;
  type: "done";
  ok: true;
  /** 已完整校验并处理完成的照片数 */
  photos: number;
}

/** 失败响应 */
export interface ContainerImportFailure {
  id: number;
  type: "failure";
  ok: false;
  /** 分类错误文案（主线程据此映射用户提示） */
  error: string;
}

/** Worker 响应联合类型 */
export type ContainerImportResponse =
  | ContainerImportPhoto
  | ContainerImportDone
  | ContainerImportFailure;

/** 正式导入任务的依赖注入（测试以伪实现替代 RPC 与消息通道） */
export interface ContainerImportDeps {
  /** 向主线程投递消息 */
  post: (message: ContainerImportResponse) => void;
  /** 用当前模块 MDEK 封装单块，返回密文 base64 */
  sealChunk: (call: {
    dataB64: string;
    fileHash: string;
    seq: number;
    total: number;
  }) => Promise<string>;
  /** 等待主线程确认上一张已消费（背压） */
  waitAck: (index: number) => Promise<void>;
}

/** 逐张封装状态 */
interface ActivePhoto {
  index: number;
  manifest: LightMeta;
  chunkB64List: string[];
  chunkHashes: string[];
}

/**
 * 执行一次正式导入任务。
 *
 * 校验链由 `unpackVencStream` 承担：帧序/边界 → 逐帧标签 → 清单字段 →
 * 每张照片块数/字节数/整图 BLAKE3 → 尾部交叉校验 → 无尾随数据。
 * 本函数只负责逐块重封装与向主线程投递。
 */
export async function runContainerImportJob(
  req: ContainerImportRequest,
  deps: ContainerImportDeps,
): Promise<void> {
  const { id } = req;
  let active: ActivePhoto | null = null;
  let photos = 0;

  try {
    const result = await unpackVencStream(
      new Uint8Array(req.fileBytes),
      req.token,
      {
        onManifest(manifest) {
          // 预览后容器被替换时，照片数会偏离预览结果：显式失败，不得静默错位
          if (photos >= req.expectedPhotos) {
            throw new Error(`容器照片数与预览结果不一致: 预览 ${req.expectedPhotos} 张`);
          }
          active = {
            index: photos,
            manifest,
            chunkB64List: [],
            chunkHashes: [],
          };
        },
        async onChunk(_manifest, _index, chunk, chunkIndex) {
          const photo = active;
          if (!photo) {
            throw new Error("块帧先于清单帧出现");
          }
          if (chunk.length === 0 || chunk.length > CHUNK_SIZE) {
            throw new Error(`第 ${chunkIndex + 1} 块长度非法: ${chunk.length}`);
          }
          try {
            const sealed = await deps.sealChunk({
              dataB64: bytesToBase64(chunk),
              fileHash: photo.manifest.fileHash,
              seq: chunkIndex,
              total: photo.manifest.chunkCount,
            });
            /* 密封产物是后续落库的权威密文：空载荷一旦被接受，索引会引用
             * 一个永远无法解密的块，且导入阶段曾报告成功。 */
            if (typeof sealed !== "string" || sealed.length === 0) {
              throw new Error(`第 ${chunkIndex + 1} 块密封产物为空`);
            }
            const sealedBytes = base64ToBytes(sealed);
            if (sealedBytes.length === 0) {
              throw new Error(`第 ${chunkIndex + 1} 块密封产物解码后为空`);
            }
            photo.chunkB64List.push(sealed);
            photo.chunkHashes.push(
              bytesToHex(blake3(sealedBytes, { dkLen: FILE_HASH_LEN })),
            );
          } finally {
            // 明文块已完成 AEAD 与哈希消费：用毕立即清零，缩短明文驻留期
            chunk.fill(0);
          }
        },
        async onPhotoComplete(manifest, index) {
          const photo = active;
          if (!photo || photo.index !== index) {
            throw new Error("照片完成事件与清单不匹配");
          }
          active = null;
          deps.post({
            id,
            type: "photo",
            index,
            name: manifest.name,
            mime: manifest.mime,
            size: manifest.size,
            thumbB64: manifest.thumbB64,
            fileHash: manifest.fileHash,
            createdAt: manifest.createdAt,
            chunkB64List: photo.chunkB64List,
            chunkHashes: photo.chunkHashes,
          });
          // 背压：主线程消费完该张并确认后才继续解密下一张
          await deps.waitAck(index);
          photos += 1;
        },
      },
    );

    if (result.photos !== photos) {
      throw new Error(`照片计数不一致: 解码 ${result.photos}，投递 ${photos}`);
    }
    // 预览后容器被替换（照片更少）时，尾部计数会低于预览结果
    if (result.photos !== req.expectedPhotos) {
      throw new Error(
        `容器照片数与预览结果不一致: 预览 ${req.expectedPhotos} 张，实际 ${result.photos} 张`,
      );
    }
    deps.post({ id, type: "done", ok: true, photos });
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    deps.post({ id, type: "failure", ok: false, error });
  }
}

/* ===== 真实 Worker 接线：RPC 桥 + 背压 ack ===== */

const workerScope = self as unknown as DedicatedWorkerGlobalScope;

const rpc = new WorkerRpcClient((message) => workerScope.postMessage(message));

let ackIndex: number | null = null;
let ackResolve: (() => void) | null = null;

/** 等待主线程确认指定照片已消费 */
function waitAck(index: number): Promise<void> {
  return new Promise<void>((resolve) => {
    ackIndex = index;
    ackResolve = resolve;
  });
}

workerScope.onmessage = (e: MessageEvent<ContainerImportRequest | ContainerImportAck>) => {
  const data = e.data;

  if (data && (data as ContainerImportAck).type === "ack") {
    const ack = data as ContainerImportAck;
    if (ackIndex === ack.index && ackResolve) {
      const resolve = ackResolve;
      ackIndex = null;
      ackResolve = null;
      resolve();
    }
    return;
  }

  // RPC 结果消息只由客户端消费，其余才是任务请求
  if (rpc.handleMessage(data)) return;

  const req = data as ContainerImportRequest;
  void runContainerImportJob(req, {
    post: (message) => workerScope.postMessage(message),
    sealChunk: async (call) => {
      const sealed = await rpc.request({
        op: "seal",
        module: "photo",
        kind: "chunk",
        data: call.dataB64,
        fileHash: call.fileHash,
        seq: call.seq,
        total: call.total,
      });
      return sealed.dataB64;
    },
    waitAck,
  });
};

export {};
