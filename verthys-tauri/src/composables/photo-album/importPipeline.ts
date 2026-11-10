/**
 * composables/photo-album/importPipeline.ts — 照片导入三阶段异步流水线
 *
 * =============================================================================
 * 架构：三阶段完全解耦流水线
 * =============================================================================
 * | 阶段     | 位置           | 职责                                   | 并发模型              |
 * |---------|----------------|----------------------------------------|-----------------------|
 * | 生产者  | 渲染主线程     | 文件读取、哈希去重、分片打包           | 单线程 + 流式读取     |
 * | 传输器  | Web Worker 池  | 哈希/缩略图/分块调度；AEAD 经 RPC 在 Tauri worker 内完成 | 多线程并发（CPU-1）   |
 * | 消费者  | 主进程（IPC）  | 批量写入存储、同步三层缓存、持久化 WAL | 单线程 + 批量事务     |
 *
 * =============================================================================
 * 背压队列
 * =============================================================================
 * 主进程维护待消费批次计数器，未处理批次数超过阈值（3 批）时，
 * 主动暂停向工作线程投喂新任务，防止内存暴涨。
 * - Worker 池内置背压（maxPendingTasks = poolSize * 4）
 * - 消费者批次数背压（maxInflightBatches = 3）
 * - 外置块协调器并发批次上限（2 批）+ 单批条数/载荷双预算
 * - 生产者并发钳制 2..8，读取字节预算 256MB
 *
 * =============================================================================
 * 外置块上传
 * =============================================================================
 * 照片分块由 ChunkUploadCoordinator 跨照片聚合（≤32 块 / ≤80% IPC 预算）后
 * 单次提交：容器事务次数从「每张照片一次」降为「每批一次」。命令级失败
 * 按幂等块键重试，不再把慢盘背压误判为照片导入失败。
 *
 * =============================================================================
 * 数据流路径
 * =============================================================================
 * 1. 生产者读取文件 → ArrayBuffer（transferList 零拷贝到 Worker）
 * 2. 传输器 Worker 池并行加密 → { thumbB64, metaB64, name }
 * 3. 生产者检查非内容条目键（entry_key）是否已 committed → 跳过已导入
 * 4. 消费者积累 N 条 → verthysAddRecordsBatch IPC（N 次加密，1 次 IPC）
 * 5. 消费者更新 BatchCacheCoordinator（批量三层缓存同步）
 * 6. 进度状态机 update() → requestAnimationFrame 帧对齐刷新
 * 7. 会话收尾：仅零致命且零失败时 verthysImportEnd(true) 压缩 WAL，
 *    其余路径 importEnd(false) 保留检查点供续传
 *
 * =============================================================================
 * 断点续传
 * =============================================================================
 * - verthysImportBegin 返回已 committed 的非内容条目键（从遗留 WAL 恢复）
 * - 生产者据此跳过已 committed 的文件（无需重复加密）
 * - 每批次 verthysAddRecordsBatch 后端写 WAL 检查点
 * - 崩溃后重启，verthysWalRecover 恢复条目键集，续传
 */
import { photoWorkerPool } from "../../workers/photoWorkerPool";
import { BatchCacheCoordinator } from "../../cache/coordination/batch-cache-coordinator";
import { ImportProgressState } from "./importProgress";
import {
  verthysImportBegin,
  verthysAddRecordsBatch,
  verthysAddChunkBatch,
  verthysImportEnd,
  verthysForceCloseImportSession,
  verthysGcOrphanChunks,
  IMPORT_SESSION_BUSY_CODE,
  VERTHYS_NOT_READY_CODE,
  type ImportBeginResult,
  type AddRecordsBatchResult,
  type ImportBatchProgress,
  type BatchRecordInput,
} from "../../lib/verthys";
import {
  TYPE_PHOTO_META,
  TYPE_PHOTO_THUMB,
  TYPE_PHOTO_CHUNK_SET,
  MAX_CHUNKS_PER_IPC,
  MAX_IPC_PAYLOAD_BYTES,
  MAX_PHOTO_BYTES,
  PHOTO_FMT_SLIM,
} from "../../constants/crypto_const";
import { estimateBase64Size } from "../../cache/shared/base64-size";
import {
  ChunkUploadCoordinator,
  ChunkUploadError,
} from "./chunkUploadCoordinator";
import type { PhotoCryptoSuccess } from "../../workers/photo-crypto.worker";
import type { SlimWorkerKeys } from "../../workers/photo-crypto-protocol";
import { extractSlimFileSalt, type PhotoMeta } from "../../lib/crypto";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToBase64, bytesToHex } from "../../utils/binary_codec";
import type { PhotoEntry, ParsedPhotoPreview } from "./types";
import type {
  ContainerImportAck,
  ContainerImportPhoto,
  ContainerImportRequest,
  ContainerImportResponse,
} from "../../workers/container-import.worker";
import { handleWorkerRpc, isWorkerRpcRequest } from "../../workers/rpc-bridge";
import { formatSize, makeThumbCssValue } from "./utils";
import { createLogger } from "../../utils/logger";
import { yieldToMain } from "../../utils/promise_utils";

const log = createLogger("import-pipeline");

/** 备份还原批次时间戳序：单调递增保证 recordName 跨批次唯一 */
let lastImportTimestamp = 0;
function nextImportTimestamp(): number {
  const now = Date.now();
  lastImportTimestamp = Math.max(now, lastImportTimestamp + 1);
  return lastImportTimestamp;
}

/** 流水线配置 */
export interface ImportPipelineConfig {
  /** 消费者批量大小（每次 IPC 写入的记录数，默认 50） */
  consumerBatchSize: number;
  /** 最大在途批次数（背压阈值，默认 3） */
  maxInflightBatches: number;
  /** 生产者并发数（并行文件读取；默认按核心数折半并钳制在 2..8） */
  producerConcurrency: number;
  /** 生产者让出间隔（每处理 N 个文件后 yieldToMain，默认 1） */
  producerYieldInterval: number;
  /** 消费者批次最大重试次数（不含首次尝试，默认 2，耗尽后按失败入账） */
  consumerMaxRetries: number;
  /** 消费者批次重试退避基数（毫秒，线性递增，默认 200） */
  consumerRetryBackoffMs: number;
}

/** 单个文件输入（生产者原料） */
export interface ImportFileInput {
  /** 文件名 */
  name: string;
  /** MIME 类型 */
  mime: string;
  /**
   * 文件字节数（导入前的 stat 预检结果）。
   *
   * 用于在读取前占用内存预算：仅按任务数背压在「少量超大文件」下仍会把
   * 内存顶满（任务数 × 单文件上限）；未知大小时按单文件上限保守预估。
   */
  size?: number;
  /** 读取文件字节（流式，避免一次性加载全部到内存） */
  readBytes: () => Promise<Uint8Array>;
  /** 源文件最后修改时间（Unix 毫秒；用于非内容续传键，不参与内容哈希） */
  lastModified?: number;
}

/**
 * 生成非内容条目键：文件元数据（名称/大小/修改时间）的 SHA-256。
 *
 * 该键只用于断点续传幂等，不是文件内容哈希，不能作为内容存在性预言机。
 */
function makeEntryKey(...parts: Array<string | number>): string {
  return bytesToHex(sha256(new TextEncoder().encode(parts.join("|"))));
}

/** 由条目键与块序号派生非内容块键（同一导入项重试稳定，不跨文件复用）。 */
function makeChunkKey(entryKey: string, seq: number | string): string {
  return bytesToHex(sha256(new TextEncoder().encode(`chunk|${entryKey}|${seq}`)));
}

/** 备份容器导入 Worker 最小接口（依赖注入：测试以伪实现替代真实 Worker） */
export interface ContainerImportWorkerLike {
  postMessage(
    message: ContainerImportRequest | ContainerImportAck,
    transfer?: Transferable[],
  ): void;
  onmessage: ((e: MessageEvent<unknown>) => void) | null;
  onerror: ((e: ErrorEvent) => void) | null;
  terminate(): void;
}

/** 默认导入 Worker 工厂：一次导入一个实例，会话结束即终止 */
function defaultContainerImportWorkerFactory(): ContainerImportWorkerLike {
  return new Worker(
    new URL("../../workers/container-import.worker.ts", import.meta.url),
    { type: "module" },
  );
}

/** 容器导入的源数据（Tauri 模式：主线程按路径重读后转让给 Worker） */
export interface ContainerImportSource {
  /** 容器完整字节（转让后主线程不可再用） */
  bytes: Uint8Array;
  /** 导出令牌 */
  token: string;
}

/**
 * 容器导入通道：主线程与 Worker 的照片级交接。
 *
 * Worker 逐张解密并重封装，投递后等待 `ack`；主线程按序号取用（背压窗口 1）。
 */
interface ContainerImportBridge {
  /** 等待指定序号的封装产物（Worker 失败时拒绝） */
  acquire(index: number): Promise<ContainerImportPhoto>;
  /** 确认该张已消费，允许 Worker 处理下一张 */
  ack(index: number): void;
  /** 终止 Worker 并拒绝所有等待者 */
  dispose(): void;
}

/** 启动容器导入 Worker，建立序号级交接队列 */
function startContainerImportWorker(
  source: ContainerImportSource,
  factory: () => ContainerImportWorkerLike,
  total: number,
): ContainerImportBridge {
  const worker = factory();
  /** 已投递但尚未被取用的照片（正常情况下最多 1 张） */
  const ready = new Map<number, ContainerImportPhoto>();
  const waiters = new Map<
    number,
    { resolve: (photo: ContainerImportPhoto) => void; reject: (error: Error) => void }
  >();
  let failure: Error | null = null;
  let disposed = false;

  const failAll = (error: Error): void => {
    failure = error;
    for (const waiter of waiters.values()) waiter.reject(error);
    waiters.clear();
    ready.clear();
  };

  worker.onmessage = (e: MessageEvent<unknown>) => {
    if (isWorkerRpcRequest(e.data)) {
      void handleWorkerRpc(worker, e.data);
      return;
    }
    const message = e.data as ContainerImportResponse;
    if (message.type === "photo") {
      const waiter = waiters.get(message.index);
      if (waiter) {
        waiters.delete(message.index);
        waiter.resolve(message);
      } else {
        ready.set(message.index, message);
      }
      return;
    }
    if (message.type === "failure") {
      failAll(new Error(message.error));
      return;
    }
    if (message.type === "done") {
      // 完成后不得再有取用请求：残留等待或迟到的 acquire 都会永久挂起，
      // 统一置为失败（正常情况下此刻已无等待者，不会误伤）
      failAll(new Error("容器照片数量与解析结果不一致"));
    }
  };
  worker.onerror = (e: ErrorEvent) => {
    failAll(new Error(e.message || "导入 Worker 异常终止"));
  };

  // ArrayBuffer 精确覆盖时直接转让；存在视图偏移时先复制，避免连带转让无关内存
  const buffer = source.bytes.buffer as ArrayBuffer;
  const transfer =
    source.bytes.byteOffset === 0 && source.bytes.byteLength === buffer.byteLength
      ? buffer
      : (source.bytes.slice().buffer as ArrayBuffer);
  try {
    worker.postMessage(
      { id: 1, fileBytes: transfer, token: source.token, expectedPhotos: total },
      [transfer],
    );
  } catch (e) {
    // 转让失败（缓冲区已分离等）：必须终止刚创建的 Worker，避免后台实例泄漏
    try {
      worker.terminate();
    } catch {
      /* 终止失败随引用释放回收 */
    }
    throw e;
  }

  return {
    acquire(index: number): Promise<ContainerImportPhoto> {
      if (failure) return Promise.reject(failure);
      const photo = ready.get(index);
      if (photo) {
        ready.delete(index);
        return Promise.resolve(photo);
      }
      return new Promise<ContainerImportPhoto>((resolve, reject) => {
        waiters.set(index, { resolve, reject });
      });
    },
    ack(index: number): void {
      if (disposed) return;
      worker.postMessage({ id: 1, type: "ack", index });
    },
    dispose(): void {
      if (disposed) return;
      disposed = true;
      failAll(new Error("导入会话已结束"));
      try {
        worker.terminate();
      } catch {
        /* 终止失败不影响会话收尾 */
      }
    },
  };
}

/** 单个照片导入结果（用于构建 PhotoEntry） */
export interface ImportedPhotoResult {
  /** verthys 记录 ID（metaId） */
  metaId: number;
  /** 文件名 */
  name: string;
  /** 展示名（真实文件名，独立于记录名前缀；缺失时回退 name 剥离前缀） */
  displayName?: string;
  /** 缩略图 base64 */
  thumbB64: string;
  /** 文件大小（字节） */
  size: number;
  /** MIME 类型 */
  mime: string;
}

/** 单条失败记录（无论失败发生在哪个阶段） */
export interface FailedRecord {
  /** 文件序号（输入文件列表下标） */
  index: number;
  /** 文件名（用于错误提示） */
  name: string;
  /** 失败原因分类 */
  reason:
    | "read-failed"
    | "file-too-large"
    | "encrypt-failed"
    | "chunk-upload-failed"
    | "server-rejected"
    | "storage-full"
    | "unknown";
  /** 是否可通过重试恢复（服务端拒绝可重试；本地读取/加密失败需用户介入） */
  retryable: boolean;
}

/**
 * 后端容量告罄错误识别：统一错误码字符串含 ERR_0000000F（内存预算/
 * 容器容量/磁盘空间耗尽）。该失败重试无法好转，须终止会话并按
 * 不可重试失败入账。
 */
function isStorageFullMessage(message: string): boolean {
  return message.includes("ERR_0000000F");
}

/** 致命错误集合 → 剩余条目入库原因归类（出现容量告罄即整体归类） */
function fatalReason(errors: Error[]): FailedRecord["reason"] {
  return errors.some((e) => isStorageFullMessage(e.message)) ? "storage-full" : "unknown";
}

/** 失败原因的用户可读文案（聚合摘要用，不暴露内部实现细节） */
const FAILURE_REASON_LABELS: Record<FailedRecord["reason"], string> = {
  "read-failed": "读取失败",
  "file-too-large": "文件超限",
  "encrypt-failed": "加密任务失败",
  "chunk-upload-failed": "块上传失败",
  "server-rejected": "写入被拒绝",
  "storage-full": "存储空间不足",
  unknown: "写入失败",
};

/** 失败构成摘要：按原因聚合计数（如「加密任务失败×15、写入被拒绝×2」） */
function summarizeFailures(failedRecords: FailedRecord[]): string {
  const counts = new Map<string, number>();
  for (const r of failedRecords) {
    const label = FAILURE_REASON_LABELS[r.reason] ?? "未知原因";
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return [...counts.entries()].map(([label, n]) => `${label}×${n}`).join("、");
}

/**
 * 加密工作线程基础设施类故障的错误类名（按 Error.name 精确匹配，避免文案耦合）：
 * 这些故障与数据本身无关，池自愈重建后可重试，需在文案中单列提示。
 */
const WORKER_INFRA_ERROR_NAMES = new Set([
  "PoolTerminatedError",
  "PoisonPillError",
  "TaskTimeoutError",
]);

/**
 * 组装「部分失败」会话错误文案：保留稳定的语义前缀，附失败构成摘要。
 *
 * 固定文案「部分记录写入失败」无法区分加密失败、写入被拒、工作线程异常
 * 等成因，线上问题只能靠复现定位；此处按失败原因聚合计数，并对工作线程类
 * 故障追加自愈提示（可重试语义）。
 */
function partialFailureError(
  failedRecords: FailedRecord[],
  importedCount: number,
  firstErrorName?: string,
): string {
  const summary = summarizeFailures(failedRecords);
  const parts = [`部分记录写入失败，已保留断点续传状态（失败 ${failedRecords.length} 张：${summary}`];
  if (importedCount > 0) {
    parts.push(`，已成功 ${importedCount} 张`);
  }
  parts.push("）");
  if (firstErrorName && WORKER_INFRA_ERROR_NAMES.has(firstErrorName)) {
    parts.push("；加密工作线程已自愈重建，请重试");
  }
  return parts.join("");
}

/**
 * 导入会话建立失败的用户可读文案（按后端结构化错误码分流）。
 *
 * Why：后端拒绝 begin 的原因决定用户下一步动作——会话冲突需等待或重启、
 *   库未就绪需重新解锁、其余属未知故障需上报；统一文案会让用户与排障
 *   都无法判断。
 */
function classifyBeginFailure(error: string | undefined, errorCode?: string | null): string {
  // 按后端结构化错误码分流（不做文案判定）：码值决定用户下一步动作
  if (errorCode === IMPORT_SESSION_BUSY_CODE) {
    return "检测到未结束的导入会话（可能来自上次中断或另一模块正在导入）：本次导入已中止，请稍候重试；若持续存在，请重新打开应用以清理会话";
  }
  if (errorCode === VERTHYS_NOT_READY_CODE) {
    return "加密库未就绪，请返回重新解锁后再导入";
  }
  return `导入初始化失败：${error ?? "未知原因"}`;
}

/** 消费者在途条目：待写记录与其渲染元信息并排，保证逐条状态可回朔到输入下标 */
interface ConsumerItem {
  /** 输入下标（用于失败记录定位，语义与生产者路径一致） */
  index: number;
  /** 待写入后端的加密记录 */
  record: BatchRecordInput;
  /** 渲染名（随写入结果显示） */
  name: string;
  /** 真实展示名（列表文件名，独立于记录名 meta_ 前缀） */
  displayName: string;
  /** 缩略图 base64 */
  thumbB64: string;
  /** 文件大小（字节） */
  size: number;
  /** MIME 类型 */
  mime: string;
}

/** 逐条重试消费的记账回调集（成功/失败/去重三分类互斥入账） */
interface ConsumeBatchLedger {
  /** 单条成功落库（metaId 为后端分配记录 ID） */
  onImported: (item: ConsumerItem, metaId: number) => void;
  /** 单条失败入账（重试耗尽或会话级失败时调用） */
  onFailed: (item: ConsumerItem, reason: FailedRecord["reason"], retryable: boolean) => void;
  /** 单条后端去重跳过（ids=0 且未在失败下标；按条入账，杜绝批次计数错位） */
  onSkipped: (item: ConsumerItem) => void;
}

/** 线性退避等待（消费者批次重试间隔，避免失败风暴直击后端） */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * 外置块上传：贪心分片（每批 ≤ MAX_CHUNKS_PER_IPC，且载荷 ≤ 上限 80% 预算）
 * 后逐批经 verthys_add_chunk_batch 落库，返回与输入等长的块记录 ID 列表。
 *
 * 仅用于**非导入会话**的重打包路径（writeRepackedPhoto）：无跨照片并发，
 * 无法聚合成更少事务。导入会话必须走 ChunkUploadCoordinator。
 *
 * 幂等依据：后端以非内容块键做会话内幂等，同块键重传复用既有记录 ID；
 * 不同文件/不同块即使内容相同也不共享 ID，不构成内容存在性预言机。
 *
 * @param chunkB64List 加密块 base64 列表
 * @param chunkKeys 逐块非内容块键（与 chunkB64List 等长）
 * @returns 块记录 ID 列表（与输入顺序一致）
 */
async function uploadExternalChunks(
  chunkB64List: string[],
  chunkKeys: string[],
): Promise<number[]> {
  if (chunkB64List.length !== chunkKeys.length) {
    throw new ChunkUploadError("外置块键数与块数不一致");
  }
  const payloadBudget = MAX_IPC_PAYLOAD_BYTES * 0.8;
  const ids: number[] = [];
  let batch: Array<{ chunk_key: string; data_b64: string }> = [];
  let batchBytes = 0;

  const flush = async (): Promise<void> => {
    if (batch.length === 0) return;
    const resp = await verthysAddChunkBatch(batch);
    if (!resp.ok || resp.failed_indices.length > 0) {
      throw new ChunkUploadError(
        resp.error ?? `外置块上传失败（${resp.failed_indices.length} 块被拒绝）`,
      );
    }
    // 响应必须与请求一一对应：缺陷响应若被放行，索引会引用缺失/错位的块 ID
    if (resp.ids.length !== batch.length) {
      throw new ChunkUploadError(
        `外置块上传响应不完整（请求 ${batch.length} 块，返回 ${resp.ids.length} 个 ID）`,
      );
    }
    for (const id of resp.ids) ids.push(id);
    batch = [];
    batchBytes = 0;
  };

  for (let i = 0; i < chunkB64List.length; i++) {
    const item = { chunk_key: chunkKeys[i], data_b64: chunkB64List[i] };
    const itemBytes = item.chunk_key.length + item.data_b64.length;
    const batchFull = batch.length >= MAX_CHUNKS_PER_IPC;
    const budgetFull = batch.length > 0 && batchBytes + itemBytes > payloadBudget;
    if (batchFull || budgetFull) {
      await flush();
    }
    batch.push(item);
    batchBytes += itemBytes;
  }
  await flush();
  return ids;
}

/**
 * 外置小载荷上传（缩略图 / 块集共用）。
 *
 * 与块同一上传通道、同一幂等语义（后端按非内容块键复用既有 ID），
 * 记录类型由角色决定；缩略图/块集记录随索引引用一并被台账认领。
 *
 * @param cipherB64 载荷密文 base64
 * @param chunkKey 非内容块键（同一导入项重试稳定）
 * @param rtype 记录类型（缩略图 / 块集）
 * @param label 定位文案（错误提示）
 * @returns 记录 ID
 */
async function uploadSlimRecord(
  cipherB64: string,
  chunkKey: string,
  rtype: number,
  label: string,
): Promise<number> {
  const resp = await verthysAddChunkBatch([
    { chunk_key: chunkKey, data_b64: cipherB64, rtype },
  ]);
  if (!resp.ok || resp.failed_indices.length > 0 || resp.ids.length !== 1 || resp.ids[0] <= 0) {
    throw new ChunkUploadError(resp.error ?? `${label}记录上传失败`);
  }
  return resp.ids[0];
}

/**
 * 索引瘦身布局：上传缩略图记录（与块同一上传通道）。
 *
 * 缩略图密文由 Worker 用与索引同盐的包裹密钥加密（池按盐命中派生缓存，
 * 不额外产生 PBKDF2）；记录类型为缩略图类型，随响应返回记录 ID 供索引回填。
 *
 * @param thumbB64 明文缩略图 base64（导入产物或解析结果，索引内不保存该数据）
 * @param wrappedFileKey 包裹态文件密钥（提供文件盐，与索引同盐）
 * @param fileHashHex 文件哈希 hex（缩略图 AD 绑定）
 * @param recordName 记录名（错误提示与日志定位）
 * @returns 缩略图记录 ID
 */
async function uploadSlimThumb(
  thumbB64: string,
  wrappedFileKey: string,
  fileHashHex: string,
  recordName: string,
  chunkKey: string,
): Promise<number> {
  if (!thumbB64) {
    throw new ChunkUploadError("缩略图数据缺失，无法写入缩略图记录");
  }
  const { thumbCipherB64 } = await photoWorkerPool.submitEncryptSlimThumb({
    thumbB64,
    fileHashHex,
    wrappedFileKey,
    label: recordName,
  });
  return uploadSlimRecord(thumbCipherB64, chunkKey, TYPE_PHOTO_THUMB, "缩略图");
}

/**
 * 索引瘦身布局：上传块集记录（逐块引用与逐块哈希）。
 *
 * Why 独立记录：逐块项随分块数线性增长，留在索引会让索引体积与照片大小挂钩；
 * 列表路径不需要逐块引用，移出后索引与照片大小解耦。
 *
 * @param chunkIds 已上传的块记录 ID（顺序即块序号）
 * @param chunkHashes 逐块密文哈希（与 chunkIds 等长）
 * @param wrappedFileKey 包裹态文件密钥（提供文件盐，与索引同盐）
 * @param fileHashHex 文件哈希 hex（块集 AD 绑定）
 * @param recordName 记录名（错误提示与日志定位）
 * @returns 块集记录 ID
 */
async function uploadSlimChunkSet(
  chunkIds: number[],
  chunkHashes: string[],
  wrappedFileKey: string,
  fileHashHex: string,
  recordName: string,
  chunkKey: string,
): Promise<number> {
  const { setCipherB64 } = await photoWorkerPool.submitEncryptSlimSet({
    set: { ids: chunkIds, hashes: chunkHashes },
    fileHashHex,
    wrappedFileKey,
    label: recordName,
  });
  return uploadSlimRecord(setCipherB64, chunkKey, TYPE_PHOTO_CHUNK_SET, "块集");
}

/** 流水线执行结果 */
export interface ImportPipelineResult {
  /** 是否成功完成（无任何失败记录） */
  ok: boolean;
  /** 成功导入的照片列表（用于构建 PhotoEntry） */
  imported: ImportedPhotoResult[];
  /** 失败记录明细（imported + failedRecords + skipped === total 恒成立） */
  failedRecords: FailedRecord[];
  /** 去重跳过的照片数（前端哈希命中 + 后端已提交） */
  skipped: number;
  /** 提交总数（输入文件数） */
  total: number;
  /** 总耗时（毫秒） */
  elapsedMs: number;
  /** 错误信息（会话级失败或取消时有值） */
  error?: string;
}

/**
 * 导入结果三分类不变量校验：
 * imported + failedRecords + skipped 必须与总提交数一致，三类互斥。
 * 违约时记录错误日志但不中断流程（所有环境均记录，保证生产可观测）。
 */
function assertResultInvariant(
  importedCount: number,
  failedCount: number,
  skippedCount: number,
  total: number,
  logger: { error: (msg: string, ...args: unknown[]) => void },
): void {
  // 记账不变量：任何环境都记录违约——若仅在 DEV 校验、生产静默，
  // 分类错位会以"导入数量对不上"的形式暴露却无日志可查，故障不可定位。
  if (importedCount + failedCount + skippedCount !== total) {
    logger.error(
      `导入结果不变量违约: imported=${importedCount} failed=${failedCount} ` +
        `skipped=${skippedCount} total=${total}`,
    );
  }
}

/**
 * 生产者单条处理上下文：会话状态全部由编排层持有，生产策略只经此投喂与记账。
 *
 * 文件导入与解析导入的差异被收敛为"单条生产策略"，会话语义（取消、背压、
 * 去重、进度、失败归因、不变量兜底）只有一份实现——修复会话语义时不存在
 * 两处同步漏改的风险。
 */
interface ProduceContext {
  /** 登记在途提交任务：会话收尾统一消费拒绝原因（策略内部已 catch，不落空） */
  addSubmit(promise: Promise<void>): void;
  /** 入列消费者缓冲：达到批量阈值即按背压约束触发刷新 */
  enqueue(item: ConsumerItem): Promise<void>;
  /** 命中会话已提交条目键（生产者续传幂等；不是内容哈希） */
  isCommitted(entryKey: string): boolean;
  /** 记一次哈希去重跳过（进度按跳过口径推进） */
  recordSkipped(index: number, elapsedMs: number): void;
  /** 推进一个条目的处理进度（读取/加密完成即推进；幂等） */
  recordProgress(index: number, elapsedMs: number): void;
  /** 记一个条目写入/加密失败：按错误类型分类，并完成致命错误收集与归因采集 */
  recordProduceError(error: Error, index: number, name: string): void;
  /** 记一个条目本地拒绝（读取失败 / 超限）：显式原因分类，不进致命集合 */
  recordLocalFailure(
    index: number,
    name: string,
    reason: "read-failed" | "file-too-large" | "encrypt-failed",
  ): void;
  /**
   * 占用在途源字节预算（读取前调用），返回幂等的释放函数。
   *
   * 任务数背压无法约束单文件体积：并发生产者各自读取一个大文件即可顶满
   * 内存。预算覆盖「读取 → 提交 → 加密任务 settle」整段驻留期。
   */
  acquireBytes(bytes: number): Promise<() => void>;
  /** 请求中止会话（取消信号确认后停止投喂新条目，已提交任务照常收尾） */
  abort(): void;
}

/** 会话编排配置：调用方只提供差异部分（标签 / 条目名 / 取消信号 / 单条生产策略） */
interface SessionRunConfig {
  /** 会话标签（日志与错误文案），如「导入」「解析导入」 */
  label: string;
  /** 条目总数（进度分母与结果不变量的权威值） */
  total: number;
  /** 取条目显示名（失败明细与错误文案用） */
  nameOf: (index: number) => string;
  /** 取消信号（文件导入可用；解析导入无取消） */
  signal?: AbortSignal;
  /** 单条生产策略：读取/构造 → 提交 → 入列（编排层保证互斥与让出节奏） */
  produce: (index: number, ctx: ProduceContext) => Promise<void>;
}

/**
 * 照片导入三阶段异步流水线
 *
 * 编排生产者 → 传输器 → 消费者三阶段：
 * - 异步批处理（N 次加密，1 次 IPC）
 * - 背压队列（防止内存暴涨）
 * - 哈希去重（断点续传幂等）
 * - 帧对齐进度反馈
 */
export class ImportPipeline {
  private readonly config: ImportPipelineConfig;
  /** 进度状态机 */
  readonly progress: ImportProgressState;
  /** 批量缓存协调器（独立实例，避免单例污染） */
  readonly batchCache: BatchCacheCoordinator;
  /** 进行中标志：同一实例仅允许一个导入会话，防止并发的 begin/end 破坏 WAL 会话配对 */
  private running = false;

  constructor(config?: Partial<ImportPipelineConfig>) {
    this.config = {
      consumerBatchSize: config?.consumerBatchSize ?? 50,
      maxInflightBatches: config?.maxInflightBatches ?? 3,
      producerConcurrency:
        config?.producerConcurrency ??
        Math.max(2, Math.min(8, Math.floor((navigator.hardwareConcurrency || 4) / 2))),
      producerYieldInterval: config?.producerYieldInterval ?? 1,
      consumerMaxRetries: config?.consumerMaxRetries ?? 2,
      consumerRetryBackoffMs: config?.consumerRetryBackoffMs ?? 200,
    };
    this.progress = new ImportProgressState();
    this.batchCache = new BatchCacheCoordinator();
  }

  /**
   * 执行照片导入流水线（文件导入）
   *
   * 会话编排（会话建立、并发调度、背压、取消、失败归因、结束分支与不变量
   * 兜底）全部在 runSession 内实现，本方法只提供文件导入的差异部分。
   *
   * @param files 待导入文件列表
   * @param signal 取消信号（中止后停止投喂新文件，已提交批次照常收尾并保留 WAL）
   * @returns 导入结果（含成功列表 / 跳过数 / 失败数 / 耗时）
   */
  async run(
    files: ImportFileInput[],
    signal?: AbortSignal,
  ): Promise<ImportPipelineResult> {
    const nameOf = (i: number): string => files[i].name;
    return await this.runExclusive(files.length, nameOf, () =>
      this.runSession({
        label: "导入",
        total: files.length,
        nameOf,
        signal,
        produce: (i, ctx) => this.produceFileImportItem(files, i, signal, ctx),
      }),
    );
  }

  /**
   * 互斥包装：普通导入与解析导入共用同一实例，running 标记保证 WAL 会话唯一。
   *
   * @param total 条目总数（互斥拒绝时按条目展开失败明细）
   * @param nameOf 取条目显示名
   * @param exec 互斥保护下的会话执行体
   */
  private async runExclusive(
    total: number,
    nameOf: (index: number) => string,
    exec: () => Promise<ImportPipelineResult>,
  ): Promise<ImportPipelineResult> {
    if (total === 0) {
      return { ok: true, imported: [], failedRecords: [], skipped: 0, total: 0, elapsedMs: 0 };
    }
    if (this.running) {
      return {
        ok: false,
        imported: [],
        failedRecords: Array.from({ length: total }, (_, i) => ({
          index: i, name: nameOf(i), reason: "unknown", retryable: false,
        })),
        skipped: 0,
        total,
        elapsedMs: 0,
        error: "已有导入任务进行中，请等待完成",
      };
    }
    this.running = true;
    try {
      return await exec();
    } finally {
      this.running = false;
    }
  }

  /** 导入会话期间的外置块协调器（跨照片聚合提交；非会话路径为 null） */
  private chunkUploads: ChunkUploadCoordinator | null = null;

  /** 备份还原会话的 Worker 交接通道（非还原路径为 null） */
  private containerImport: ContainerImportBridge | null = null;

  /**
   * 导入会话编排骨架（文件导入与解析导入共享）。
   *
   * 职责：会话建立 → 并发生产者调度（取消检查 / 让出节奏）→ 在途提交收尾 →
   * 消费者缓冲刷新 → 会话结束四分支（取消 / 致命 / 部分失败 / 成功）→
   * 结果不变量兜底。两条链路的差异（条目来源、单条生产策略、取消信号）
   * 全部由 config 注入；会话语义修复只需改本方法一处。
   */
  private async runSession(config: SessionRunConfig): Promise<ImportPipelineResult> {
    const { label, total, nameOf, signal, produce } = config;
    const startAt = performance.now();
    log.info(`${label}流水线启动: ${total} 张照片`);

    /** 会话未启动时的整批失败展开（会话初始化失败 / 建立被拒绝 / 互斥拒绝） */
    const allFailed = (reason: FailedRecord["reason"], retryable: boolean): FailedRecord[] =>
      Array.from({ length: total }, (_, i) => ({ index: i, name: nameOf(i), reason, retryable }));

    // ===== 阶段 0：初始化导入会话（WAL + 续传去重哈希集） =====
    /* 进度追踪提前启动：会话恢复也可能耗时（大 WAL），先给用户可见反馈，
     * 后续 begin 失败路径显式 end(false) 收尾。 */
    this.progress.start(total);
    this.progress.note("正在恢复导入会话…");
    let beginResult: ImportBeginResult;
    try {
      beginResult = await this.beginImportSession();
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      log.error(`${label}会话初始化失败:`, e);
      this.progress.end(false);
      return {
        ok: false,
        imported: [],
        failedRecords: allFailed("unknown", false),
        skipped: 0,
        total,
        elapsedMs: performance.now() - startAt,
        error: `导入会话初始化失败: ${error}`,
      };
    }

    // 会话建立被后端拒绝（如「已有导入会话进行中」「无法确定加密库路径」）：
    // 必须立即中止并透出真实原因。若继续执行，生产者会白做全部加密开销、
    // 消费者每批被后端拒绝，最终以「部分记录写入失败」掩盖真实原因。
    if (!beginResult.ok) {
      log.error(`${label}会话建立被拒绝:`, beginResult.error);
      this.progress.end(false);
      return {
        ok: false,
        imported: [],
        failedRecords: allFailed("unknown", true),
        skipped: 0,
        total,
        elapsedMs: performance.now() - startAt,
        error: classifyBeginFailure(beginResult.error, beginResult.error_code),
      };
    }

    // committed 哈希集（生产者去重 + 续传幂等）
    const committedKeys = new Set<string>(beginResult.entry_keys ?? []);
    log.info(`${label}会话已建立: import_id=${beginResult.import_id}, 已 committed=${committedKeys.size}`);

    // ===== 启动消费者与块协调器 =====
    this.progress.note("正在读取并加密照片…");
    this.batchCache.begin();
    /* 外置块协调器：按条数 + 载荷预算跨照片聚合上传，把「每张照片一次
     * 容器事务」压到「每批块一次事务」，并在命令级失败时按幂等块键重试。 */
    const chunkUploads = new ChunkUploadCoordinator((items) =>
      verthysAddChunkBatch(items),
    );
    this.chunkUploads = chunkUploads;

    // ===== 收集导入结果 =====
    const imported: ImportedPhotoResult[] = [];
    const failedRecords: FailedRecord[] = [];
    let skipped = 0;
    /** 取消标志：signal 中止后停止投喂新条目，进行收尾 */
    let aborted = false;
    /** 会话级致命错误收集器：后端容量告罄等不可恢复错误在此集合 */
    const fatalErrors: Error[] = [];
    /** 首个生产者/消费者错误的错误类名（会话错误文案归因用，取首次非空值） */
    let firstErrorName: string | undefined;

    /**
     * 逐条目记账位图：每个输入下标只能落入 imported / failed / skipped
     * 三类之一。以真实下标为准，未入账兜底不再用计数差推算下标
     * （计数差在批量去重跳过时会把失败记录标到错误文件上）。
     */
    const accounted = new Uint8Array(total);
    /**
     * 逐条目进度位图：读取/加密阶段即推进进度（首个条目立即给用户反馈），
     * 后续落盘失败不得再次 update，否则同一条目进度重复计数。
     */
    const progressed = new Uint8Array(total);

    /** 推进一个条目的处理进度（幂等；skippedDelta 仅用于去重跳过口径） */
    const advanceProgress = (index: number, elapsedMs: number, skippedDelta = 0): void => {
      if (progressed[index]) return;
      progressed[index] = 1;
      this.progress.update(1, elapsedMs, skippedDelta);
    };

    /** 未入账兜底：把"既未成功也未跳过也无失败记录"的条目补记为失败（不变量兜底） */
    const padUnaccounted = (reason: FailedRecord["reason"], retryable: boolean): void => {
      for (let i = 0; i < total; i++) {
        if (accounted[i]) continue;
        accounted[i] = 1;
        failedRecords.push({ index: i, name: nameOf(i), reason, retryable });
      }
    };

    // ===== 消费者批量缓冲 =====
    let consumerItems: ConsumerItem[] = [];
    /** 缓冲内记录的近似 IPC 载荷字节（name + entry_key + data_b64 字符数） */
    let consumerBytes = 0;
    /** 单批聚合载荷预算：留 20% 余量给 IPC 包装与进度通道 */
    const CONSUMER_BYTE_BUDGET = MAX_IPC_PAYLOAD_BYTES * 0.8;

    /** 刷新消费者批量缓冲到后端 IPC（逐条状态重试 + 致命错误收集） */
    const flushConsumer = async (): Promise<void> => {
      if (consumerItems.length === 0) return;
      const batch = consumerItems.splice(0);
      consumerBytes = 0;

      try {
        await this.consumeBatchReliable(
          batch,
          {
            onImported: (item, metaId) => {
              accounted[item.index] = 1;
              imported.push({
                metaId,
                name: item.name,
                displayName: item.displayName,
                thumbB64: item.thumbB64,
                size: item.size,
                mime: item.mime,
              });
              // 添加到批量缓存协调器（L1/L2/L3 批量同步）
              // dataSize 口径：摘要缓存记录的是原始数据字节数，由密文 base64
              // 精确反推（而非取 base64 字符串长度，后者偏大约 33%）
              // 缓存同步失败不影响已入库记录：后续扫描会重建缓存，仅记录日志
              try {
                this.batchCache.addRecord({
                  id: metaId,
                  type: TYPE_PHOTO_META,
                  name: item.name,
                  dataB64: item.record.data_b64,
                  dataSize: estimateBase64Size(item.record.data_b64),
                });
              } catch (cacheError) {
                log.warn(
                  `${label}批量缓存同步失败（记录已入库）: index=${item.index}`,
                  cacheError,
                );
              }
            },
            onFailed: (item, reason, retryable) => {
              accounted[item.index] = 1;
              failedRecords.push({ index: item.index, name: item.name, reason, retryable });
              log.warn(
                `${label}记录写入失败: index=${item.index} name=${item.name} reason=${reason}`,
              );
            },
            onSkipped: (item) => {
              // 后端以条目键去重跳过：按条入账，跳过数不再依赖批次聚合计数
              accounted[item.index] = 1;
              skipped++;
            },
          },
          fatalErrors,
        );
      } catch (e) {
        // 未预期异常：本批未被回调入账的条目按可重试失败兜底。
        // 批次已被 splice 出缓冲，若不在此处记账将永远无人认领（不变量违约）。
        log.error(`${label}消费者批次异常:`, e);
        for (const item of batch) {
          if (accounted[item.index]) continue;
          accounted[item.index] = 1;
          failedRecords.push({
            index: item.index,
            name: item.name,
            reason: "unknown",
            retryable: true,
          });
        }
      }

      // 让出主线程：IPC 完成后 yieldToMain，保证 rAF 进度回调执行
      await yieldToMain();
    };

    // ===== 阶段 1+2：生产者 + 传输器（流式并行 + 主线程让出） =====
    try {
      // 使用信号量控制消费者在途批次数（背压）
      let inflightBatches = 0;
      const maxInflight = this.config.maxInflightBatches;
      const inflightWaiters: Array<() => void> = [];

      /** 等待消费者在途批次数低于阈值（背压；唤醒后必须重检，防止超额占槽） */
      const waitForInflightSlot = async (): Promise<void> => {
        while (inflightBatches >= maxInflight) {
          await new Promise<void>((resolve) => {
            inflightWaiters.push(resolve);
          });
        }
      };

      /** 通知背压等待者（在途批次减少）：每次释放只唤醒一个，由被唤醒者重检 */
      const notifyInflightSlot = (): void => {
        const waiter = inflightWaiters.shift();
        if (waiter) waiter();
      };

      const submitPromises: Promise<void>[] = [];

      /* 在途源字节预算：读取后的源字节被在途加密任务引用，直到 settle 才释放。
       * 仅按任务数背压无法约束单文件体积——并发生产者各读一个大文件即可顶满
       * 内存；此处按字节总量闸门，未知大小的文件按单文件上限保守占用。 */
      const IN_FLIGHT_BYTE_BUDGET = 256 * 1024 * 1024;
      let inFlightBytes = 0;
      const byteWaiters: Array<() => void> = [];

      /** 占用字节预算（返回幂等释放函数；单文件超预算时独占放行，避免死锁） */
      const acquireBytes = async (bytes: number): Promise<() => void> => {
        const reserved = Math.min(Math.max(bytes, 0), MAX_PHOTO_BYTES);
        while (inFlightBytes > 0 && inFlightBytes + reserved > IN_FLIGHT_BYTE_BUDGET) {
          await new Promise<void>((resolve) => byteWaiters.push(resolve));
        }
        inFlightBytes += reserved;
        let released = false;
        return () => {
          if (released) return;
          released = true;
          inFlightBytes = Math.max(0, inFlightBytes - reserved);
          const waiters = byteWaiters.splice(0);
          for (const w of waiters) w();
        };
      };

      /**
       * 入列消费者缓冲：达到批量阈值即按背压约束触发刷新。
       *
       * 竞态说明：JS 单线程 + splice 原子清空保证数据不丢失；await 期间
       * buffer 可能已被其他回调 flush 清空，二次检查后直接返回（不占用
       * inflightBatches 槽位，避免计数为负）。
       */
      const enqueue = async (item: ConsumerItem): Promise<void> => {
        consumerItems.push(item);
        consumerBytes +=
          item.record.name.length + item.record.entry_key.length + item.record.data_b64.length;
        const batchFull = consumerItems.length >= this.config.consumerBatchSize;
        const payloadFull = consumerBytes >= CONSUMER_BYTE_BUDGET;
        if (batchFull || payloadFull) {
          await waitForInflightSlot();
          if (consumerItems.length === 0) {
            return;
          }
          inflightBatches++;
          try {
            await flushConsumer();
          } finally {
            inflightBatches--;
            notifyInflightSlot();
          }
        }
      };

      /** 单条生产上下文：策略经此投喂与记账，会话状态只由本方法持有 */
      const ctx: ProduceContext = {
        addSubmit: (promise) => { submitPromises.push(promise); },
        enqueue,
        isCommitted: (key) => committedKeys.has(key),
        recordSkipped: (index, elapsedMs) => {
          accounted[index] = 1;
          skipped++;
          advanceProgress(index, elapsedMs, 1);
        },
        recordProgress: (index, elapsedMs) => { advanceProgress(index, elapsedMs); },
        recordProduceError: (error, index, name) => {
          accounted[index] = 1;
          failedRecords.push({
            index,
            name,
            reason: error instanceof ChunkUploadError ? "chunk-upload-failed" : "encrypt-failed",
            retryable: error instanceof ChunkUploadError,
          });
          // 归因采集：仅记录首个错误类名（文案用类名而非文案，避免耦合）
          if (firstErrorName === undefined && error.name) {
            firstErrorName = error.name;
          }
          advanceProgress(index, 0);
        },
        recordLocalFailure: (index, name, reason) => {
          accounted[index] = 1;
          failedRecords.push({ index, name, reason, retryable: false });
          advanceProgress(index, 0);
        },
        acquireBytes,
        abort: () => { aborted = true; },
      };

      // 生产者并行化 + yieldToMain 让出主线程
      //
      // 串行处理（for 循环内 await 逐条）会让主线程被永久占用，
      //       requestAnimationFrame 回调被挤压在任务队列末尾，进度条冻结。
      //
      // 要点：
      //   1. 并发生产：N 个并发生产者（默认核心数折半并钳制在 2..8），并行读取与提交；
      //      读取并发不按 2×核心数放大：磁盘与单写者吞吐是瓶颈，过量读取
      //      只会放大内存驻留与命令队列压力
      //   2. 让出主线程：每处理完 N 个条目后 yieldToMain()，强制让出主线程，
      //          保证 rAF 进度回调得到执行机会
      //   3. 进度逐条目更新（per-item），而非逐 IPC 批次更新，
      //          用户感知到「真实加密进度」而非「IPC 写入进度」
      const producerConcurrency = Math.min(total, this.config.producerConcurrency);
      let producerIndex = 0;

      /** 并发生产者：按索引拉取条目 → 委托生产策略 → 按让出节奏交还主线程 */
      const producer = async (): Promise<void> => {
        let filesSinceYield = 0;

        while (true) {
          // 取消检查：中止后不再投喂新条目（已提交任务由 submitPromises 收尾）
          if (signal?.aborted) {
            aborted = true;
            break;
          }
          // 会话级致命错误（容量告罄等）：停止投喂新条目，避免为注定失败的
          // 写入继续读取与加密全部剩余文件；在途任务照常收尾并入账
          if (fatalErrors.length > 0) break;
          // 原子拉取下一个条目索引（JS 单线程，无竞态）
          const i = producerIndex++;
          if (i >= total) break;

          // 委托生产策略（读取/加密/入列；策略内部完成记账，不向编排层抛出）
          await produce(i, ctx);

          // P0 核心：每处理 N 个条目后 yieldToMain，强制让出主线程
          //   保证 requestAnimationFrame 回调（进度条渲染）得到执行机会
          //   这是让进度条「真正动起来」的唯一解
          filesSinceYield++;
          if (filesSinceYield >= this.config.producerYieldInterval) {
            filesSinceYield = 0;
            await yieldToMain();
          }
        }
      };

      // 启动 N 个并发生产者
      // 显式消费生产者拒绝原因：allSettled 会静默吸收生产者异常，
      // 只有日志可观测；未产出的剩余下标由会话末尾未入账兜底按真实下标登记。
      const settledProducers = await Promise.allSettled(
        Array.from({ length: producerConcurrency }, () => producer()),
      );
      for (const s of settledProducers) {
        if (s.status === "rejected") {
          const detail = s.reason instanceof Error ? s.reason.message : String(s.reason);
          log.warn(`[importPipeline] 生产者异常，剩余记录未处理: ${detail}`);
        }
      }

      /* 取消/致命：立即关闭块协调器并拒绝未决块任务，让仍在等待块 ID 的
       * 生产者立刻收尾；若等到 allSettled 之后再关，生产者会永久等待。 */
      if (aborted || fatalErrors.length > 0) {
        chunkUploads.close(aborted ? "导入已取消" : "导入因致命错误终止");
      }

      // 等待所有加密任务完成（生产者已全部退出，但 Worker 池可能仍有在途任务）
      // 显式消费拒绝原因：allSettled 会静默吸收生产者异常，使"既未成功也未失败"
      // 的记录不被入账（结果不变量违约）；此处至少保证异常可观测。
      const settledSubmits = await Promise.allSettled(submitPromises);
      for (const s of settledSubmits) {
        if (s.status === "rejected") {
          log.warn(
            `[importPipeline] 加密任务异常: ${s.reason instanceof Error ? s.reason.message : String(s.reason)}`,
          );
        }
      }

      // ===== 阶段 3：刷新剩余消费者缓冲 =====
      if (consumerItems.length > 0) {
        await flushConsumer();
      }

      // ===== 刷新批量缓存（三层同步） =====
      await this.batchCache.end();

      /* 未入账兜底：生产异常 / 取消 / 消费者异常导致的未产出条目按真实下标
       * 补记，保证 imported + failed + skipped === total 在取消、致命、
       * 部分失败与成功四条返回路径上恒成立。 */
      if (fatalErrors.length > 0) {
        padUnaccounted(fatalReason(fatalErrors), false);
      } else {
        padUnaccounted("unknown", true);
      }

      if (aborted) {
        // 取消路径：已提交批次照常落库（哈希去重保证续传幂等），
        // 以 importEnd(false) 保留 WAL 检查点，下次导入自动续传去重
        await this.endSessionSafely(false, "import");
        this.progress.end(false);
        assertResultInvariant(imported.length, failedRecords.length, skipped, total, log);
        return {
          ok: false,
          imported,
          failedRecords,
          skipped,
          total,
          elapsedMs: performance.now() - startAt,
          error: "ABORTED",
        };
      }

      // ===== 结束导入会话：成功语义守卫（零致命 + 零失败才压缩 WAL） =====
      // 任何未达标的会话都不能以 success=true 结束，否则后端会压缩 WAL
      // 并丢弃 pending 记录，造成「已提示部分失败但数据无法续传」的静默丢失
      if (fatalErrors.length > 0) {
        await this.endSessionSafely(false, "import");
        this.progress.end(false);
        // 未入账条目已在统一兜底处按致命原因登记，此处不再重复补记
        return {
          ok: false,
          imported,
          failedRecords,
          skipped,
          total,
          elapsedMs: performance.now() - startAt,
          error: fatalReason(fatalErrors) === "storage-full"
            ? "存储空间不足，请释放空间后重试（已保留断点续传状态）"
            : fatalErrors[0].message,
        };
      }

      if (failedRecords.length > 0) {
        // 部分失败：保留 WAL 供续传，向下游透出错误语义而非成功
        await this.endSessionSafely(false, "import");
        this.progress.end(false);
        assertResultInvariant(imported.length, failedRecords.length, skipped, total, log);
        const allStorageFailed = failedRecords.every((r) => r.reason === "storage-full");
        return {
          ok: false,
          imported,
          failedRecords,
          skipped,
          total,
          elapsedMs: performance.now() - startAt,
          error: allStorageFailed
            ? "存储空间不足，请释放空间后重试（已保留断点续传状态）"
            : partialFailureError(failedRecords, imported.length, firstErrorName),
        };
      }

      // ===== 结束导入会话（WAL 压缩：仅零失败路径可达） =====
      await this.endSessionSafely(true, "import");

      // 会话成功收敛后触发孤儿块 GC（崩溃残留块清理；best-effort，失败不阻断成功语义）
      verthysGcOrphanChunks().catch((e) => {
        log.warn(`${label}孤儿块清理失败（不影响已完成的导入）:`, e);
      });

      // ===== 结束进度追踪 =====
      this.progress.end(true);

      const elapsedMs = performance.now() - startAt;
      assertResultInvariant(imported.length, failedRecords.length, skipped, total, log);
      log.info(
        `${label}流水线完成: imported=${imported.length}, failed=${failedRecords.length}, ` +
          `skipped=${skipped}, elapsed=${elapsedMs.toFixed(0)}ms`,
      );

      return {
        ok: true,
        imported,
        failedRecords,
        skipped,
        total,
        elapsedMs,
      };
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      log.error(`${label}流水线异常:`, e);

      // 异常终止：先拒绝未决块任务，再结束会话（避免生产者永久等待块 ID）
      this.chunkUploads?.close("导入异常终止");

      // 异常时结束会话（保留 WAL 供续传）
      try {
        await this.batchCache.end();
        await this.endSessionSafely(false, "import");
      } catch {
        // 结束会话失败忽略
      }

      this.progress.end(false);

      // 异常路径：未入账条目（既未成功也未跳过也无失败记录）统一记为未知失败，
      // 保证三分类不变量在任何返回路径成立
      padUnaccounted("unknown", true);

      return {
        ok: false,
        imported,
        failedRecords,
        skipped,
        total,
        elapsedMs: performance.now() - startAt,
        error,
      };
    }
  }

  /**
   * 文件导入的单条生产策略：读取闸门 → 读文件 → 完整加密（外置/内联）→ 入列。
   *
   * 与解析导入的差异：需要读取源文件字节、生成缩略图并分块加密（submit），
   * 且受"读取闸门"约束（在途任务达池配额前不读下一个文件，限制源字节驻留）；
   * 取消信号在读取前再检查一次（编排层在循环入口已检查一次）。
   * 会话编排（背压 / 去重 / 进度 / 结束分支）由 runSession 统一承担。
   *
   * @param files 待导入文件列表（会话内共享，按索引取用）
   * @param i 条目下标（编排层保证唯一）
   * @param signal 取消信号（会话级；读取前被中止则不再读取该文件）
   * @param ctx 生产上下文（记账与入列的唯一通道）
   */
  private async produceFileImportItem(
    files: ImportFileInput[],
    i: number,
    signal: AbortSignal | undefined,
    ctx: ProduceContext,
  ): Promise<void> {
    const fileInput = files[i];

    // 读取前占用在途字节预算（未知大小按单文件上限保守占用）：
    //   预算覆盖「读取 → 提交 → 加密任务 settle」整段字节驻留期
    const releaseBytes = await ctx.acquireBytes(fileInput.size ?? MAX_PHOTO_BYTES);

    /* 非内容条目键：名称/大小/修改时间的 SHA-256。命中已 committed 的
     * 同一来源文件时直接跳过读取与加密；不是内容哈希，不能确认内容存在性。 */
    const entryKey = makeEntryKey(
      "file",
      fileInput.name,
      fileInput.size ?? 0,
      fileInput.lastModified ?? 0,
    );
    if (ctx.isCommitted(entryKey)) {
      ctx.recordSkipped(i, 0);
      releaseBytes();
      await yieldToMain();
      return;
    }

    // 读取闸门：在途任务达到池配额前不读取下一个文件。读取结果会被
    // 在途任务引用至 settle，若无闸门则全部源文件字节同时驻留内存，
    // 大批量导入易触发内存暴涨
    await photoWorkerPool.waitForCapacity();
    if (signal?.aborted) {
      ctx.abort();
      releaseBytes();
      return;
    }

    // 读取文件字节（生产者阶段，与其他生产者并行）
    let fileBytes: Uint8Array;
    try {
      fileBytes = await fileInput.readBytes();
    } catch (e) {
      log.error(`读取文件失败: ${fileInput.name}`, e);
      ctx.recordLocalFailure(i, fileInput.name, "read-failed");
      releaseBytes();
      // 让出主线程，保证 rAF 执行
      await yieldToMain();
      return;
    }

    // 单文件硬上限：超限直接拒绝（不进入加密与写入，防内存峰值失控）
    if (fileBytes.byteLength > MAX_PHOTO_BYTES) {
      log.warn(
        `文件超过单文件上限: ${fileInput.name} (${fileBytes.byteLength} > ${MAX_PHOTO_BYTES} 字节)`,
      );
      ctx.recordLocalFailure(i, fileInput.name, "file-too-large");
      releaseBytes();
      await yieldToMain();
      return;
    }

    // 转为 ArrayBuffer（transferList 零拷贝转让到 Worker）。
    //   全量读取（readUserFile）返回的视图覆盖整个 buffer：此时直接转让原
    //   buffer，省去 slice 的一次整文件拷贝；仅当视图是 buffer 的子区间时
    //   才切片（转让整 buffer 会把区间外的字节一并送进 Worker）。
    const wholeBuffer = fileBytes.byteOffset === 0
      && fileBytes.byteLength === fileBytes.buffer.byteLength;
    const arrayBuffer = wholeBuffer
      ? (fileBytes.buffer as ArrayBuffer)
      : (fileBytes.buffer.slice(
          fileBytes.byteOffset,
          fileBytes.byteOffset + fileBytes.byteLength,
        ) as ArrayBuffer);

    // 记录提交时间（用于计算单文件加密耗时）
    const submitTime = performance.now();

    /* 新导入固定使用自包含布局；瘦身布局仅保留读取/来源保留路径，
     * 不再在导入时创建包裹文件密钥。 */
    const slim: SlimWorkerKeys | undefined = undefined;

    // 提交到 Worker 池（传输器阶段，自带背压）
    // 不 await submit()：让加密与下一次文件读取并行（真正的流水线）
    // 池内部拷贝源字节权威副本（可重放），此处以视图零成本传入
    const submitPromise = photoWorkerPool
      .submit({
        fileBytes: new Uint8Array(arrayBuffer),
        request: {
          fileName: fileInput.name,
          mime: fileInput.mime,
          slim,
          entryKey,
        },
      })
      .then(async (success: PhotoCryptoSuccess) => {
        // 计算单文件加密耗时（提交 → 完成）
        const fileElapsed = performance.now() - submitTime;

        // ===== 生产者幂等（断点续传；键为来源元数据，不是内容哈希） =====
        if (ctx.isCommitted(entryKey)) {
          ctx.recordSkipped(i, fileElapsed);
          return;
        }

        /* 加密完成即推进进度：首个条目立刻给用户反馈，不再等待块上传与
         * 磁盘提交（后续落盘失败由 advanceProgress 幂等保护，不重复计数）。 */
        ctx.recordProgress(i, fileElapsed);

        // 构造 BatchRecordInput（外置大文件：块先落库 → 回填引用 → meta-only 加密）
        const record: BatchRecordInput = success.external
          ? await this.finalizeExternalRecord(
              success.external.chunkB64List,
              success.external.chunkHashes,
              success.external.metaTemplate,
              success.thumbB64,
              success.name,
              entryKey,
            )
          : (() => {
              if (!success.metaB64) {
                throw new Error("加密产物缺少元数据");
              }
              return {
                rtype: TYPE_PHOTO_META,
                name: success.name,
                entry_key: entryKey,
                data_b64: success.metaB64,
              };
            })();

        await ctx.enqueue({
          index: i,
          record,
          name: success.name,
          displayName: fileInput.name,
          thumbB64: success.thumbB64,
          size: success.size,
          mime: success.mime,
        });
      })
      .catch((e: Error) => {
        log.error(`加密失败: ${fileInput.name}`, e);
        ctx.recordProduceError(e, i, fileInput.name);
      })
      // 加密任务 settle 后才释放源字节预算（读取结果在 settle 前一直被任务引用）
      .finally(releaseBytes);

    ctx.addSubmit(submitPromise);
  }

  /**
   * 备份还原：执行 .venc 容器的正式导入流水线
   *
   * 与文件导入的区别（全部收敛在 produceContainerItem 一处）：
   *   - 输入：预览列表（已校验结构的清单）+ 容器字节（转让给导入 Worker）
   *   - 解密/校验/重封装：Worker 内逐帧完成，主线程只消费单张产物
   *   - 传输器：复用外置块上传（块已用当前模块 MDEK 重新加密）
   *   - 无文件读取、无缩略图生成、无取消信号
   *
   * 共享基础设施：会话编排（runSession）统一承担——WAL 断点续传、批量 IPC、
   * 背压队列、生产者调度与让出、进度状态机、哈希去重、失败归因与结束分支、
   * 批量三层缓存同步。
   *
   * @param previews 预览列表（doParse 阶段产出，按容器顺序）
   * @param source 容器字节与令牌（字节所有权转让给 Worker）
   * @param workerFactory 导入 Worker 工厂（测试注入点；默认真实 Worker）
   * @returns 导入结果（含成功列表 / 跳过数 / 失败数 / 耗时）
   */
  async runContainer(
    previews: ParsedPhotoPreview[],
    source: ContainerImportSource,
    workerFactory: () => ContainerImportWorkerLike = defaultContainerImportWorkerFactory,
  ): Promise<ImportPipelineResult> {
    if (previews.length === 0) {
      return {
        ok: true, imported: [], failedRecords: [], skipped: 0, total: 0, elapsedMs: 0,
      };
    }
    const nameOf = (i: number): string => previews[i].name;
    // 会话级批次时间戳：仅用于生成跨批次唯一的记录名；照片创建时间保留清单原值
    const importTimestamp = nextImportTimestamp();
    return await this.runExclusive(previews.length, nameOf, async () => {
      // 互斥通过后才启动 Worker 并挂载通道：并发调用不得改写正在运行会话的
      // 通道引用，否则先到的会话会因通道被置空而整批失败
      const b = startContainerImportWorker(source, workerFactory, previews.length);
      this.containerImport = b;
      try {
        return await this.runSession({
          label: "备份还原",
          total: previews.length,
          nameOf,
          produce: (i, ctx) => this.produceContainerItem(previews, i, importTimestamp, ctx),
        });
      } finally {
        this.containerImport = null;
        b.dispose();
      }
    });
  }

  /**
   * 备份还原的单条生产策略：取 Worker 产物 → 外置块上传 → meta 加密 → 入列。
   *
   * 去重键为清单内 BLAKE3 文件哈希（内容身份）：同一内容在任意备份文件、
   * 任意设备上重导都会命中同一条目键。Worker 的块级 AEAD 与整图哈希校验
   * 已在产物投递前完成，本方法不再重复校验载荷。
   *
   * @param previews 预览列表（会话内共享，按索引取用）
   * @param i 条目下标（与 Worker 投递序号一致）
   * @param importTimestamp 会话级批次时间戳（记录名唯一化；照片 createdAt 保留清单原值）
   * @param ctx 生产上下文（记账与入列的唯一通道）
   */
  private async produceContainerItem(
    previews: ParsedPhotoPreview[],
    i: number,
    importTimestamp: number,
    ctx: ProduceContext,
  ): Promise<void> {
    const ph = previews[i];
    const bridge = this.containerImport;
    if (!bridge) {
      ctx.recordProduceError(new Error("导入通道未就绪"), i, ph.name);
      return;
    }

    try {
      // 背压：Worker 逐张投递并等待 ack，主线程按序号取用
      const photo = await bridge.acquire(i);

      // 预览与产物必须指向同一内容：容器在预览后被替换时显式失败，
      // 否则条目键与落库内容会指向不同照片（静默错位）
      if (photo.fileHash !== ph.fileHash) {
        throw new Error("备份文件在预览后已变更，请重新选择文件");
      }

      // 内容身份键：与备份文件、来源设备、导出批次均无关
      const entryKey = makeEntryKey("parsed", photo.fileHash);

      if (ctx.isCommitted(entryKey)) {
        ctx.recordSkipped(i, 0);
        return;
      }

      const recordName = `parsed_${importTimestamp}_${i}`;
      const submitTime = performance.now();
      const metaTemplate: PhotoMeta = {
        name: photo.name,
        mime: photo.mime,
        size: photo.size,
        thumbB64: photo.thumbB64,
        chunkIds: [],
        chunkDataB64: [],
        chunkHashes: photo.chunkHashes,
        fileHash: photo.fileHash,
        // 备份是数据迁移而非新建：创建时间按容器清单还原，不从导入时刻重造
        createdAt: photo.createdAt,
      };

      ctx.recordProgress(i, performance.now() - submitTime);
      const record = await this.finalizeExternalRecord(
        photo.chunkB64List,
        photo.chunkHashes,
        metaTemplate,
        photo.thumbB64,
        recordName,
        entryKey,
      );
      // 前置幂等检查后此处必然未命中；保留复核兜底
      if (ctx.isCommitted(record.entry_key)) {
        ctx.recordSkipped(i, 0);
        return;
      }
      await ctx.enqueue({
        index: i,
        record,
        name: photo.name,
        displayName: photo.name,
        thumbB64: photo.thumbB64,
        size: photo.size,
        mime: photo.mime,
      });
    } catch (e) {
      const error = e instanceof Error ? e : new Error(String(e));
      log.error(`备份还原失败: ${ph.name}`, error);
      ctx.recordProduceError(error, i, ph.name);
    } finally {
      bridge.ack(i);
    }
  }

  /**
   * 初始化导入会话（含断点续传恢复）。
   *
   * `verthysImportBegin` 本身会在创建会话时加载遗留 WAL 快照并返回
   * committed 条目键；额外调用 `verthysWalRecover` 会让同一份 WAL 被
   * 完整解析两次，大 WAL（多次中断后的续传）下是“准备导入”阶段的可观
   * 开销，故此处不再重复扫描。
   */
  private async beginImportSession(): Promise<ImportBeginResult> {
    return await verthysImportBegin();
  }

  /**
   * 外置块照片的最终记录构造：块上传 → 回填 chunkIds → meta-only 加密。
   *
   * 块上传与 meta 写入共用后端单写者 FIFO（块先落库、引用后校验），
   * 上传失败抛 ChunkUploadError 由调用方按可重试失败分类。
   *
   * @param chunkB64List 加密块 base64 列表（外置块记录载荷）
   * @param chunkHashes 逐块密文哈希（与 chunkB64List 等长）
   * @param metaTemplate 元数据模板（chunkDataB64 已置空，待回填引用）
   * @param recordName verthys 记录名
   * @param entryKey 非内容条目键（WAL 续传幂等）
   * @returns 最终写入记录（含外置引用字段）
   */
  private async finalizeExternalRecord(
    chunkB64List: string[],
    chunkHashes: string[],
    metaTemplate: PhotoMeta,
    plainThumbB64: string,
    recordName: string,
    entryKey: string,
  ): Promise<BatchRecordInput> {
    // 分块产物结构校验：块为空或哈希项数与块数不符时，写出的索引会携带
    //   无法一一对应的逐块诊断值，后续读取/导出无法按块定位，必须在写入前拒绝。
    if (chunkB64List.length === 0) {
      throw new Error(`照片 "${recordName}" 无可写入数据块`);
    }
    if (chunkHashes.length > 0 && chunkHashes.length !== chunkB64List.length) {
      throw new Error(
        `照片 "${recordName}" 块哈希项数与块数不一致（哈希 ${chunkHashes.length} ≠ 块 ${chunkB64List.length}）`,
      );
    }

    // 索引瘦身布局：缩略图与块集先落独立记录（获得 ID 后回填索引），
    //   索引随后按同一文件盐加密；既有布局维持"块 + 索引"两步。
    const slimLayout = metaTemplate.fmt === PHOTO_FMT_SLIM && !!metaTemplate.wrappedFileKey;
    const chunkKeys = chunkB64List.map((_, seq) => makeChunkKey(entryKey, seq));

    const chunkIds = this.chunkUploads
      ? await this.chunkUploads.uploadChunks(
          chunkB64List.map((dataB64, seq) => ({
            chunk_key: chunkKeys[seq],
            data_b64: dataB64,
          })),
        )
      : await uploadExternalChunks(chunkB64List, chunkKeys);
    // 缩略图可选：源照片无缩略图（生成失败）时索引不携带缩略图引用，
    //   读取侧据此回落"无缩略图"展示，而不是让整张迁移失败
    const thumbId = slimLayout && plainThumbB64
      ? await uploadSlimThumb(
          plainThumbB64, metaTemplate.wrappedFileKey!, metaTemplate.fileHash, recordName,
          makeChunkKey(entryKey, "thumb"),
        )
      : 0;
    const chunkSetId = slimLayout
      ? await uploadSlimChunkSet(
          chunkIds, chunkHashes, metaTemplate.wrappedFileKey!, metaTemplate.fileHash, recordName,
          makeChunkKey(entryKey, "cset"),
        )
      : 0;

    // 瘦身索引只保留聚合引用：逐块 ID 与逐块哈希移入块集记录
    //   （内联数组会让索引体积随照片大小线性增长）；既有布局必须把本次
    //   实际写入的块哈希同步进索引，保证后续导出可做逐块密文校验。
    const hashesForMeta = chunkHashes.length > 0 ? chunkHashes : metaTemplate.chunkHashes;
    const metaForWrite: PhotoMeta = slimLayout
      ? {
          ...metaTemplate,
          entryKey,
          thumbB64: "",
          chunkIds: [],
          chunkDataB64: [],
          chunkHashes: undefined,
          thumbId,
          chunkSetId,
          chunkCount: chunkIds.length,
        }
      : {
          ...metaTemplate,
          entryKey,
          chunkIds,
          ...(hashesForMeta ? { chunkHashes: hashesForMeta } : {}),
        };

    const metaFinal = await photoWorkerPool.submitMetaOnly({
      meta: metaForWrite,
      recordName,
      entryKey,
      ...(slimLayout
        ? {
            slim: {
              fileSaltB64: bytesToBase64(extractSlimFileSalt(metaTemplate.wrappedFileKey!)),
              wrappedFileKey: metaTemplate.wrappedFileKey!,
            },
          }
        : {}),
    });
    return {
      rtype: TYPE_PHOTO_META,
      name: recordName,
      entry_key: entryKey,
      data_b64: metaFinal.metaB64,
      // 外置记录（块 / 缩略图 / 块集）随索引引用一并纳入台账认领
      // （孤儿候选转正，不被 GC 回收）；无缩略图时占位值 0 不参与认领，
      // 否则写者会按"引用未上传"拒绝整条记录
      chunk_ids: slimLayout
        ? [...chunkIds, thumbId, chunkSetId].filter((id) => id > 0)
        : chunkIds,
      chunk_hashes: chunkHashes,
    };
  }

  /**
   * 开启重打包写入会话。
   *
   * 重打包复用导入通道（块 / 缩略图 / 块集 / 索引同走单写者 FIFO 与台账），
   * 故与导入一样需要显式会话；会话由调用方在整轮重打包前后成对开启与结束。
   * 返回会话建立结果（与导入同一契约）：调用方必须检查 `ok` —— 被后端拒绝时
   * 继续逐张写入只会让每一项都失败，真实原因（已有会话/路径不可确定）被掩盖。
   */
  async beginRepackSession(): Promise<ImportBeginResult> {
    return await this.beginImportSession();
  }

  /**
   * 结束重打包会话。
   *
   * @param ok 会话内是否零失败：仅零失败压缩 WAL，其余保留检查点
   */
  async endRepackSession(ok: boolean): Promise<void> {
    await this.endSessionSafely(ok, "repack");
  }

  /**
   * 安全结束导入会话：失败重试一次，仍失败则主动强制清理（自愈）。
   *
   * Why：会话结束失败会让会话残留在 AppState，下一次导入的 begin 会被直接
   *   拒绝（级联失败，需重启应用恢复）。此处把「失败即残留」收敛为自愈：
   *   重试一次后仍失败，调用后端幂等的强制清理入口（丢弃会话但保留 WAL
   *   断点续传状态，不压缩、不丢数据），让下一次导入可直接继续。
   *
   * @param success 会话内是否零失败（仅零失败压缩 WAL）
   * @param label 调用场景标记（仅用于日志定位）
   */
  private async endSessionSafely(success: boolean, label: string): Promise<void> {
    // 外层会话收口前先关闭块协调器：未决块任务一律拒绝，避免生产者悬挂
    this.chunkUploads?.close(success ? "导入会话已结束" : "导入会话已终止");
    this.chunkUploads = null;
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        const r = await verthysImportEnd(success);
        if (r.ok) {
          if (attempt > 1) {
            log.info(`[import-pipeline] 会话结束在第 ${attempt} 次尝试成功（${label}）`);
          }
          return;
        }
        log.warn(
          `[import-pipeline] 会话结束失败（${label}）第 ${attempt}/2 次: ${r.error ?? "未知错误"}`,
        );
      } catch (e) {
        log.warn(`[import-pipeline] 会话结束异常（${label}）第 ${attempt}/2 次`, e);
      }
      if (attempt < 2) {
        await new Promise<void>((resolve) => setTimeout(resolve, 500));
      }
    }
    try {
      const closed = await verthysForceCloseImportSession();
      if (closed) {
        log.warn(`[import-pipeline] 会话结束连续失败，已强制清理残留会话（${label}）`);
      } else {
        log.error(`[import-pipeline] 会话结束连续失败且强制清理未生效（${label}），下次导入可能被拒绝`);
      }
    } catch (e) {
      log.error(`[import-pipeline] 强制清理残留会话异常（${label}）`, e);
    }
  }

  /**
   * 重打包写入单张：把布局二加密产物经外置写入链路落库，返回新索引记录 ID。
   *
   * @param success 重打包加密产物（外置块 + 元数据模板）
   * @param recordName 新记录名
   * @returns 新索引记录 ID（> 0）
   * @throws Error 写入被拒绝（含后端按哈希去重跳过：错误消息为 DUPLICATE_SKIPPED）
   */
  async writeRepackedPhoto(
    success: PhotoCryptoSuccess,
    recordName: string,
  ): Promise<number> {
    if (!success.external) {
      throw new Error("重打包产物缺少外置块（布局二必须外部化分块）");
    }
    const entryKey = makeEntryKey("repack", recordName);
    const record = await this.finalizeExternalRecord(
      success.external.chunkB64List,
      success.external.chunkHashes,
      success.external.metaTemplate,
      success.thumbB64,
      recordName,
      entryKey,
    );
    const resp = await this.consumeBatch([record]);
    const id = resp.ids.length > 0 ? resp.ids[0] : 0;
    if (id > 0) return id;
    // 0 且未在失败下标 = 后端按内容哈希去重跳过（遗留 WAL 已含该哈希）：
    // 非失败语义，调用方按"跳过"记账并保留源记录
    throw new Error(resp.failed_indices.length > 0 ? "重打包写入被拒绝" : "DUPLICATE_SKIPPED");
  }

  /** 消费者：批量写入 N 条已加密记录到后端 */
  private async consumeBatch(records: BatchRecordInput[]): Promise<AddRecordsBatchResult> {
    // 通过 Tauri Channel 接收后端流式进度
    // 但我们在批次级别也更新进度，这里仅记录日志
    const onProgress = (prog: ImportBatchProgress) => {
      log.debug(
        `批次 ${prog.batch_id} 进度: ${prog.processed_in_batch}/${prog.total_in_batch}, ` +
          `committed=${prog.total_committed}, elapsed=${prog.elapsed_ms}ms`,
      );
    };

    const result = await verthysAddRecordsBatch(records, onProgress);

    if (!result.ok) {
      throw new Error(result.error ?? "批量写入失败");
    }

    return result;
  }

  /**
   * 提交批次并按逐条状态重试失败子集（幂等安全）。
   *
   * 逐条状态推导规则（与后端响应语义对齐）：
   *   - ids[i] > 0：成功落库，入账 imported；
   *   - ids[i] === 0 且 failed_indices 命中 i：服务端拒绝，若重试配额未耗尽则入重试子集；
   *   - ids[i] === -1（响应缺失该下标）：未知异常，同上按可重试处理；
   *   - ids[i] === 0 且未在 failed_indices：后端哈希去重，计入 skipped，绝不重试。
   *
   * 重试幂等依据：后端以记录哈希去重，已成功提交的项在重试子批次中会返回
   * ids=0 且不计入 failed_indices（按去重跳过入账），因此只重试失败项不会重复入库。
   *
   * 致命错误（后端容量告罄）：推入 fatalErrors 后立即停止后续写入，
   * 剩余条目按不可重试失败入账，由调用方走导入结束决策。
   *
   * @param items 待写条目（含渲染元信息与输入下标）
   * @param ledger 三分类入账回调
   * @param fatalErrors 会话级致命错误收集器（与生产者侧共享同一数组）
   */
  private async consumeBatchReliable(
    items: ConsumerItem[],
    ledger: ConsumeBatchLedger,
    fatalErrors: Error[],
  ): Promise<void> {
    let pending = items;
    let attempt = 0;

    while (pending.length > 0) {
      // 会话已被致命错误终止：剩余条目全部入账，不再发起写入
      if (fatalErrors.length > 0) {
        for (const it of pending) ledger.onFailed(it, fatalReason(fatalErrors), false);
        return;
      }

      let resp: AddRecordsBatchResult;
      try {
        resp = await this.consumeBatch(pending.map((it) => it.record));
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        const err = e instanceof Error ? e : new Error(msg);
        if (isStorageFullMessage(msg)) {
          // 致命：后端容量告罄（内存预算/容器容量/磁盘空间），重试无法好转
          fatalErrors.push(err);
          for (const it of pending) ledger.onFailed(it, "storage-full", false);
          return;
        }
        if (attempt >= this.config.consumerMaxRetries) {
          // 重试耗尽：整批按可重试失败入账（WAL 保留待续传）
          for (const it of pending) ledger.onFailed(it, "unknown", true);
          return;
        }
        attempt += 1;
        await sleep(this.config.consumerRetryBackoffMs * attempt);
        continue;
      }

      const retrySubset: ConsumerItem[] = [];
      for (let i = 0; i < pending.length; i++) {
        const metaId = i < resp.ids.length ? resp.ids[i] : -1;
        if (metaId > 0) {
          ledger.onImported(pending[i], metaId);
        } else if (metaId === -1 || resp.failed_indices.includes(i)) {
          if (attempt < this.config.consumerMaxRetries) {
            retrySubset.push(pending[i]);
          } else {
            ledger.onFailed(
              pending[i],
              metaId === -1 ? "unknown" : "server-rejected",
              metaId !== -1,
            );
          }
        } else {
          // ids=0 且未在失败下标：后端按条目键去重跳过；
          // 按条目入账（不再依赖批次聚合 skipped_count，避免下标错位）
          ledger.onSkipped(pending[i]);
        }
      }

      if (retrySubset.length === 0) return;
      pending = retrySubset;
      attempt += 1;
      await sleep(this.config.consumerRetryBackoffMs * attempt);
    }
  }
}

/**
 * 将导入结果转换为 PhotoEntry 列表（供 photos ref 使用）
 *
 * @param imported 导入结果列表
 */
export function importedToPhotoEntries(
  imported: ImportedPhotoResult[],
): PhotoEntry[] {
  return imported.map((item, i) => ({
    // id 直接复用后端记录 ID（metaId）：与加载路径同源，跨重启稳定且全局唯一，
    // 消除 Date.now()+偏移 构造在同一毫秒批量导入时的碰撞隐患
    id: item.metaId,
    metaId: item.metaId,
    // 展示名以结构化 displayName 为权威（真实文件名），仅缺失时回退记录名剥离前缀
    name: item.displayName || item.name.replace(/^meta_/, ""),
    // 缩略图走 Blob URL：data URL 的 base64 字符串会随列表常驻 JS 堆（每张数十 KB），
    //   且与 meta 内的同一份数据重复；Blob 数据不进字符串，释放点与生成点成对。
    thumb: makeThumbCssValue(item.thumbB64),
    size: formatSize(item.size),
    height: 180 + ((i * 23) % 100),
    // 刚导入项的名称/尺寸/缩略图均来自本次写入结果，无需再解密一遍元数据：
    //   标记已加载，避免进入可视区后被按需解密重复处理（点击查看时仍会按需补齐 meta）。
    loaded: true,
    failed: false,
  }));
}
