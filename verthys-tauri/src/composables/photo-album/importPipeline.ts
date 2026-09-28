/**
 * composables/photo-album/importPipeline.ts — 照片导入三阶段异步流水线
 *
 * Comprehensive_optimization：异步批处理流水线 — 核心编排器
 *
 * =============================================================================
 * 架构：三阶段完全解耦流水线
 * =============================================================================
 * | 阶段     | 位置           | 职责                                   | 并发模型              |
 * |---------|----------------|----------------------------------------|-----------------------|
 * | 生产者  | 渲染主线程     | 文件读取、哈希去重、分片打包           | 单线程 + 流式读取     |
 * | 传输器  | Worker 线程池  | AES-256-GCM 加密 + 元数据序列化        | 多线程并发（CPU-1）   |
 * | 消费者  | 主进程（IPC）  | 批量写入存储、同步三层缓存、持久化 WAL | 单线程 + 批量事务     |
 *
 * =============================================================================
 * 背压队列
 * =============================================================================
 * 主进程维护待消费批次计数器，未处理批次数超过阈值（3 批）时，
 * 主动暂停向工作线程投喂新任务，防止内存暴涨。
 * - Worker 池内置背压（maxPendingTasks = poolSize * 4）
 * - 消费者批次数背压（maxInflightBatches = 3）
 * - 双重背压保证内存峰值 < 500MB
 *
 * =============================================================================
 * 数据流路径
 * =============================================================================
 * 1. 生产者读取文件 → ArrayBuffer（transferList 零拷贝到 Worker）
 * 2. 传输器 Worker 池并行加密 → { hash, thumbB64, metaB64, name }
 * 3. 生产者检查 hash 去重（committed_hashes）→ 跳过已导入
 * 4. 消费者积累 N 条 → verthysAddRecordsBatch IPC（N 次加密，1 次 IPC）
 * 5. 消费者更新 BatchCacheCoordinator（批量三层缓存同步）
 * 6. 进度状态机 update() → requestAnimationFrame 帧对齐刷新
 * 7. 会话收尾：仅零致命且零失败时 verthysImportEnd(true) 压缩 WAL，
 *    其余路径 importEnd(false) 保留检查点供续传
 *
 * =============================================================================
 * 断点续传
 * =============================================================================
 * - verthysImportBegin 返回 committed_hashes（从遗留 WAL 恢复）
 * - 生产者据此跳过已 committed 的文件（无需重复加密）
 * - 每批次 verthysAddRecordsBatch 后端写 WAL 检查点
 * - 崩溃后重启，verthysWalRecover 恢复 committed_hashes，续传
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
  verthysWalRecover,
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
  MAX_INLINE_META_BYTES,
  MAX_CHUNKS_PER_IPC,
  MAX_IPC_PAYLOAD_BYTES,
  MAX_PHOTO_BYTES,
  PHOTO_FMT_SLIM,
} from "../../constants/crypto_const";
import { estimateBase64Size } from "../../cache/shared/base64-size";
import type { PhotoCryptoSuccess, PhotoMetaCryptoSuccess } from "../../workers/photo-crypto.worker";
import { computeChunkHashesForB64, extractSlimFileSalt, type PhotoMeta } from "../../lib/crypto";
import { bytesToBase64 } from "../../utils/binary_codec";
import type { PhotoEntry, ParsedPhotoPreview } from "./types";
import { formatSize } from "./utils";
import { createLogger } from "../../utils/logger";
import { yieldToMain } from "../../utils/promise_utils";

const log = createLogger("import-pipeline");

/** 解析导入批次时间戳序：单调递增保证 createdAt 与 recordName 跨批次唯一 */
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
  /** 是否启用断点续传（默认 true） */
  enableResume: boolean;
  /** 生产者并发数（并行文件读取，默认 hardwareConcurrency * 2） */
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
  /** 读取文件字节（流式，避免一次性加载全部到内存） */
  readBytes: () => Promise<Uint8Array>;
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
 * 历史实现只透出固定文案「部分记录写入失败」，调用方无法区分加密失败、
 * 写入被拒、工作线程异常等成因，线上问题只能靠复现定位；此处按失败原因
 * 聚合计数，并对工作线程类故障追加自愈提示（可重试语义）。
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
  /** 后端去重跳过数累计（以响应 skipped_count 为权威） */
  onSkipped: (count: number) => void;
}

/** 线性退避等待（消费者批次重试间隔，避免失败风暴直击后端） */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** 外置块上传失败（区别于加密失败，可重试；供失败分类识别） */
class ChunkUploadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChunkUploadError";
  }
}

/**
 * 脱代理净化：把可能被 Vue 响应式代理包裹的纯 JSON 载荷复制为普通数据对象。
 *
 * Why：解析产物存入 `parsedPhotos`（ref）后，其嵌套字段（chunkDataB64 /
 *   chunkHashes 等数组与对象）在读取时是响应式 Proxy。Proxy 不是结构化
 *   克隆的合法载荷——Worker 池 `postMessage` 会抛 DataCloneError
 *   （"[object Array] could not be cloned"），使 meta-only 加密任务对
 *   每一张照片系统性失败（表现为「加密任务失败×N」的整体失败）。
 *   浅层展开（`{...meta}`）不能消除嵌套代理，必须整对象深复制。
 *
 * 实现选择：JSON 往返是最可靠的脱代理手段（Vue 代理的 get/ownKeys 陷阱
 *   对 JSON.stringify 透明，输出纯数据）。载荷本为纯 JSON 类型，一次
 *   序列化成本远小于随后的 PBKDF2 加密；不引入深拷贝工具依赖。
 *
 * 语义说明：与 JSON 语义一致——值为 undefined 的字段净化后消失
 *   （跨线程结构化克隆与后端 JSON 解析后，缺失与 undefined 本就不可区分，
 *   调用方对两者的处理必须等价）。
 *
 * @param payload 可能含响应式代理的纯 JSON 载荷
 * @returns 与输入值相等的深复制（完全脱离代理）
 */
function toPlainPayload<T>(payload: T): T {
  return JSON.parse(JSON.stringify(payload)) as T;
}

/**
 * 外置块上传：贪心分片（每批 ≤ MAX_CHUNKS_PER_IPC，且载荷 ≤ 上限 80% 预算）
 * 后逐批经 verthys_add_chunk_batch 落库，返回与输入等长的块记录 ID 列表。
 *
 * 幂等依据：后端以块密文哈希去重，同哈希重传复用既有记录 ID，
 * 消费者批次重试重复上传不会产生重复块记录。
 *
 * @param chunkB64List 加密块 base64 列表
 * @param chunkHashes 逐块密文哈希（与 chunkB64List 等长）
 * @returns 块记录 ID 列表（与输入顺序一致）
 */
async function uploadExternalChunks(
  chunkB64List: string[],
  chunkHashes: string[],
): Promise<number[]> {
  if (chunkB64List.length !== chunkHashes.length) {
    throw new ChunkUploadError("外置块哈希数与块数不一致");
  }
  const payloadBudget = MAX_IPC_PAYLOAD_BYTES * 0.8;
  const ids: number[] = [];
  let batch: Array<{ hash: string; data_b64: string }> = [];
  let batchBytes = 0;

  const flush = async (): Promise<void> => {
    if (batch.length === 0) return;
    const resp = await verthysAddChunkBatch(batch);
    if (!resp.ok || resp.failed_indices.length > 0) {
      throw new ChunkUploadError(
        resp.error ?? `外置块上传失败（${resp.failed_indices.length} 块被拒绝）`,
      );
    }
    for (const id of resp.ids) ids.push(id);
    batch = [];
    batchBytes = 0;
  };

  for (let i = 0; i < chunkB64List.length; i++) {
    const item = { hash: chunkHashes[i], data_b64: chunkB64List[i] };
    const itemBytes = item.hash.length + item.data_b64.length;
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
 * 与块同一上传通道、同一幂等语义（后端按密文哈希去重，批次重试复用既有 ID），
 * 记录类型由角色决定；缩略图/块集记录随索引引用一并被台账认领。
 *
 * @param cipherB64 载荷密文 base64
 * @param cipherHash 载荷密文的 BLAKE3 hex
 * @param rtype 记录类型（缩略图 / 块集）
 * @param label 定位文案（错误提示）
 * @returns 记录 ID
 */
async function uploadSlimRecord(
  cipherB64: string,
  cipherHash: string,
  rtype: number,
  label: string,
): Promise<number> {
  const resp = await verthysAddChunkBatch([
    { hash: cipherHash, data_b64: cipherB64, rtype },
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
 * @param photoKey 照片模块独立密钥
 * @param recordName 记录名（错误提示与日志定位）
 * @returns 缩略图记录 ID
 */
async function uploadSlimThumb(
  thumbB64: string,
  wrappedFileKey: string,
  fileHashHex: string,
  photoKey: string,
  recordName: string,
): Promise<number> {
  if (!thumbB64) {
    throw new ChunkUploadError("缩略图数据缺失，无法写入缩略图记录");
  }
  const fileSaltB64 = bytesToBase64(extractSlimFileSalt(wrappedFileKey));
  const { thumbCipherB64, thumbHash } = await photoWorkerPool.submitEncryptSlimThumb({
    thumbB64,
    fileSaltB64,
    fileHashHex,
    photoKey,
    label: recordName,
  });
  return uploadSlimRecord(thumbCipherB64, thumbHash, TYPE_PHOTO_THUMB, "缩略图");
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
 * @param photoKey 照片模块独立密钥
 * @param recordName 记录名（错误提示与日志定位）
 * @returns 块集记录 ID
 */
async function uploadSlimChunkSet(
  chunkIds: number[],
  chunkHashes: string[],
  wrappedFileKey: string,
  fileHashHex: string,
  photoKey: string,
  recordName: string,
): Promise<number> {
  const fileSaltB64 = bytesToBase64(extractSlimFileSalt(wrappedFileKey));
  const { setCipherB64, setHash } = await photoWorkerPool.submitEncryptSlimSet({
    set: { ids: chunkIds, hashes: chunkHashes },
    fileSaltB64,
    fileHashHex,
    photoKey,
    label: recordName,
  });
  return uploadSlimRecord(setCipherB64, setHash, TYPE_PHOTO_CHUNK_SET, "块集");
}

/** 流水线执行结果 */
export interface ImportPipelineResult {
  /** 是否成功完成（无任何失败记录且无不可解密项） */
  ok: boolean;
  /** 成功导入的照片列表（用于构建 PhotoEntry） */
  imported: ImportedPhotoResult[];
  /** 失败记录明细（imported + failedRecords + skipped + undecryptable === total 恒成立） */
  failedRecords: FailedRecord[];
  /** 去重跳过的照片数（前端哈希命中 + 后端已提交） */
  skipped: number;
  /** 无法用当前模块密钥解密的照片数（解析导入专属；非失败、不可重试、不入列） */
  undecryptable: number;
  /** 提交总数（输入文件数） */
  total: number;
  /** 总耗时（毫秒） */
  elapsedMs: number;
  /** 错误信息（会话级失败或取消时有值） */
  error?: string;
}

/**
 * 导入结果四分类不变量校验：
 * imported + failedRecords + skipped + undecryptable 必须与总提交数一致，四分类互斥。
 * 违约时记录错误日志但不中断流程（所有环境均记录，保证生产可观测）。
 */
function assertResultInvariant(
  importedCount: number,
  failedCount: number,
  skippedCount: number,
  total: number,
  logger: { error: (msg: string, ...args: unknown[]) => void },
  undecryptableCount = 0,
): void {
  // 四分类记账不变量：任何环境都记录违约——历史实现仅在 DEV 校验，生产静默，
  // 分类错位会以"导入数量对不上"的形式暴露却无日志可查，故障不可定位。
  if (importedCount + failedCount + skippedCount + undecryptableCount !== total) {
    logger.error(
      `导入结果不变量违约: imported=${importedCount} failed=${failedCount} ` +
        `skipped=${skippedCount} undecryptable=${undecryptableCount} total=${total}`,
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
  /** 命中会话已提交哈希（生产者去重；断点续传幂等） */
  isCommitted(hash: string): boolean;
  /** 记一次哈希去重跳过（进度按跳过口径推进） */
  recordSkipped(elapsedMs: number): void;
  /** 推进一个条目的处理进度 */
  recordProgress(elapsedMs: number): void;
  /** 记一个不可解密条目（非失败、不重试、不写入列表；解析导入专用） */
  recordUndecryptable(): void;
  /** 记一个条目写入/加密失败：按错误类型分类，并完成致命错误收集与归因采集 */
  recordProduceError(error: Error, index: number, name: string): void;
  /** 记一个条目本地拒绝（读取失败 / 超限）：显式原因分类，不进致命集合 */
  recordLocalFailure(index: number, name: string, reason: "read-failed" | "file-too-large"): void;
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
      enableResume: config?.enableResume ?? true,
      producerConcurrency: config?.producerConcurrency ?? Math.max(2, (navigator.hardwareConcurrency || 4) * 2),
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
   * @param photoKey 照片模块独立密钥
   * @param signal 取消信号（中止后停止投喂新文件，已提交批次照常收尾并保留 WAL）
   * @returns 导入结果（含成功列表 / 跳过数 / 失败数 / 耗时）
   */
  async run(
    files: ImportFileInput[],
    photoKey: string,
    signal?: AbortSignal,
  ): Promise<ImportPipelineResult> {
    const nameOf = (i: number): string => files[i].name;
    return await this.runExclusive(files.length, nameOf, () =>
      this.runSession({
        label: "导入",
        total: files.length,
        nameOf,
        signal,
        produce: (i, ctx) => this.produceFileImportItem(files, i, photoKey, signal, ctx),
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
      return { ok: true, imported: [], failedRecords: [], skipped: 0, undecryptable: 0, total: 0, elapsedMs: 0 };
    }
    if (this.running) {
      return {
        ok: false,
        imported: [],
        failedRecords: Array.from({ length: total }, (_, i) => ({
          index: i, name: nameOf(i), reason: "unknown", retryable: false,
        })),
        skipped: 0,
        undecryptable: 0,
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
    let beginResult: ImportBeginResult;
    try {
      beginResult = await this.beginImportSession();
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      log.error(`${label}会话初始化失败:`, e);
      return {
        ok: false,
        imported: [],
        failedRecords: allFailed("unknown", false),
        skipped: 0,
        undecryptable: 0,
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
      return {
        ok: false,
        imported: [],
        failedRecords: allFailed("unknown", true),
        skipped: 0,
        undecryptable: 0,
        total,
        elapsedMs: performance.now() - startAt,
        error: classifyBeginFailure(beginResult.error, beginResult.error_code),
      };
    }

    // committed 哈希集（生产者去重 + 续传幂等）
    const committedHashes = new Set<string>(beginResult.hashes);
    log.info(`${label}会话已建立: import_id=${beginResult.import_id}, 已 committed=${committedHashes.size}`);

    // ===== 启动进度追踪 =====
    this.progress.start(total);
    this.batchCache.begin();

    // ===== 收集导入结果 =====
    const imported: ImportedPhotoResult[] = [];
    const failedRecords: FailedRecord[] = [];
    let skipped = 0;
    /** 不可解密条目数（解析导入专用：非失败、不重试、不写入列表；文件导入恒为 0） */
    let undecryptable = 0;
    /** 取消标志：signal 中止后停止投喂新条目，进行收尾 */
    let aborted = false;
    /** 会话级致命错误收集器：后端容量告罄等不可恢复错误在此集合 */
    const fatalErrors: Error[] = [];
    /** 首个生产者/消费者错误的错误类名（会话错误文案归因用，取首次非空值） */
    let firstErrorName: string | undefined;

    /** 未入账兜底：把"既未成功也未跳过也无失败记录"的条目补记为失败（不变量兜底） */
    const padUnaccounted = (reason: FailedRecord["reason"], retryable: boolean): void => {
      let unaccounted = total - imported.length - skipped - failedRecords.length - undecryptable;
      while (unaccounted-- > 0) {
        failedRecords.push({
          index: imported.length + skipped + failedRecords.length,
          name: "unknown",
          reason,
          retryable,
        });
      }
    };

    // ===== 消费者批量缓冲 =====
    let consumerItems: ConsumerItem[] = [];

    /** 刷新消费者批量缓冲到后端 IPC（逐条状态重试 + 致命错误收集） */
    const flushConsumer = async (): Promise<void> => {
      if (consumerItems.length === 0) return;
      const batch = consumerItems.splice(0);

      await this.consumeBatchReliable(
        batch,
        {
          onImported: (item, metaId) => {
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
            this.batchCache.addRecord({
              id: metaId,
              type: TYPE_PHOTO_META,
              name: item.name,
              dataB64: item.record.data_b64,
              dataSize: estimateBase64Size(item.record.data_b64),
            });
          },
          onFailed: (item, reason, retryable) => {
            failedRecords.push({ index: item.index, name: item.name, reason, retryable });
            log.warn(
              `${label}记录写入失败: index=${item.index} name=${item.name} reason=${reason}`,
            );
          },
          onSkipped: (count) => {
            // 批次级去重跳过以后端响应 skipped_count 为权威，前端哈希命中另行累计
            skipped += count;
          },
        },
        fatalErrors,
      );

      // 让出主线程：IPC 完成后 yieldToMain，保证 rAF 进度回调执行
      await yieldToMain();
    };

    // ===== 阶段 1+2：生产者 + 传输器（流式并行 + 主线程让出） =====
    try {
      // 使用信号量控制消费者在途批次数（背压）
      let inflightBatches = 0;
      const maxInflight = this.config.maxInflightBatches;
      const inflightWaiters: Array<() => void> = [];

      /** 等待消费者在途批次数低于阈值（背压） */
      const waitForInflightSlot = (): Promise<void> => {
        if (inflightBatches < maxInflight) {
          return Promise.resolve();
        }
        return new Promise<void>((resolve) => {
          inflightWaiters.push(resolve);
        });
      };

      /** 通知背压等待者（在途批次减少） */
      const notifyInflightSlot = (): void => {
        while (inflightWaiters.length > 0 && inflightBatches < maxInflight) {
          const waiter = inflightWaiters.shift();
          if (waiter) waiter();
        }
      };

      const submitPromises: Promise<void>[] = [];

      /**
       * 入列消费者缓冲：达到批量阈值即按背压约束触发刷新。
       *
       * 竞态说明：JS 单线程 + splice 原子清空保证数据不丢失；await 期间
       * buffer 可能已被其他回调 flush 清空，二次检查后直接返回（不占用
       * inflightBatches 槽位，避免计数为负）。
       */
      const enqueue = async (item: ConsumerItem): Promise<void> => {
        consumerItems.push(item);
        if (consumerItems.length >= this.config.consumerBatchSize) {
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
        isCommitted: (hash) => committedHashes.has(hash),
        recordSkipped: (elapsedMs) => {
          skipped++;
          this.progress.update(1, elapsedMs, 1);
        },
        recordProgress: (elapsedMs) => { this.progress.update(1, elapsedMs); },
        recordUndecryptable: () => {
          undecryptable++;
          this.progress.update(1, 0);
        },
        recordProduceError: (error, index, name) => {
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
          this.progress.update(1, 0);
        },
        recordLocalFailure: (index, name, reason) => {
          failedRecords.push({ index, name, reason, retryable: false });
          this.progress.update(1, 0);
        },
        abort: () => { aborted = true; },
      };

      // P0+P1 修复：生产者并行化 + yieldToMain 让出主线程
      //
      // 根因：旧实现 for 循环内 await 逐条串行处理，主线程被永久阻塞，
      //       requestAnimationFrame 回调被挤压在任务队列末尾，进度条冻结。
      //
      // 修复：
      //   1. P1：N 个并发生产者（N = hardwareConcurrency * 2），并行读取与提交
      //   2. P0：每处理完 N 个条目后 yieldToMain()，强制让出主线程，
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
      // 使记录"既未成功也未失败"，结果不变量随之违约且现场不可见。
      const settledProducers = await Promise.allSettled(
        Array.from({ length: producerConcurrency }, () => producer()),
      );
      for (const s of settledProducers) {
        if (s.status === "rejected") {
          const detail = s.reason instanceof Error ? s.reason.message : String(s.reason);
          // 生产者异常会中断该生产者的剩余记录：显式登记为失败，避免出现
          // "既未成功也未失败"的记录使结果不变量违约，同时保留现场供排查
          log.warn(`[importPipeline] 生产者异常，剩余记录未处理: ${detail}`);
          failedRecords.push({
            index: imported.length + skipped + failedRecords.length,
            name: "unknown",
            reason: "encrypt-failed",
            retryable: true,
          });
        }
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

      if (aborted) {
        // 取消路径：已提交批次照常落库（哈希去重保证续传幂等），
        // 以 importEnd(false) 保留 WAL 检查点，下次导入自动续传去重
        await this.endSessionSafely(false, "import");
        this.progress.end(false);
        assertResultInvariant(
          imported.length, failedRecords.length, skipped, total, log, undecryptable,
        );
        return {
          ok: false,
          imported,
          failedRecords,
          skipped,
          undecryptable,
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
        // 致命路径下未入账条目统一按不可重试失败入账，保证三分类不变量成立
        padUnaccounted(fatalReason(fatalErrors), false);
        return {
          ok: false,
          imported,
          failedRecords,
          skipped,
          undecryptable,
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
        assertResultInvariant(
          imported.length, failedRecords.length, skipped, total, log, undecryptable,
        );
        const allStorageFailed = failedRecords.every((r) => r.reason === "storage-full");
        return {
          ok: false,
          imported,
          failedRecords,
          skipped,
          undecryptable,
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
      verthysGcOrphanChunks().catch(() => {});

      // ===== 结束进度追踪 =====
      this.progress.end(true);

      const elapsedMs = performance.now() - startAt;
      assertResultInvariant(
        imported.length, failedRecords.length, skipped, total, log, undecryptable,
      );
      log.info(
        `${label}流水线完成: imported=${imported.length}, failed=${failedRecords.length}, ` +
          `skipped=${skipped}` +
          (undecryptable > 0 ? `, undecryptable=${undecryptable}` : "") +
          `, elapsed=${elapsedMs.toFixed(0)}ms`,
      );

      return {
        ok: true,
        imported,
        failedRecords,
        skipped,
        undecryptable,
        total,
        elapsedMs,
      };
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      log.error(`${label}流水线异常:`, e);

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
        undecryptable,
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
   * @param photoKey 照片模块独立密钥
   * @param signal 取消信号（会话级；读取前被中止则不再读取该文件）
   * @param ctx 生产上下文（记账与入列的唯一通道）
   */
  private async produceFileImportItem(
    files: ImportFileInput[],
    i: number,
    photoKey: string,
    signal: AbortSignal | undefined,
    ctx: ProduceContext,
  ): Promise<void> {
    const fileInput = files[i];

    // 读取闸门：在途任务达到池配额前不读取下一个文件。读取结果会被
    // 在途任务引用至 settle，若无闸门则全部源文件字节同时驻留内存，
    // 大批量导入易触发内存暴涨
    await photoWorkerPool.waitForCapacity();
    if (signal?.aborted) {
      ctx.abort();
      return;
    }

    // 读取文件字节（生产者阶段，与其他生产者并行）
    let fileBytes: Uint8Array;
    try {
      fileBytes = await fileInput.readBytes();
    } catch (e) {
      log.error(`读取文件失败: ${fileInput.name}`, e);
      ctx.recordLocalFailure(i, fileInput.name, "read-failed");
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
      await yieldToMain();
      return;
    }

    // 转为 ArrayBuffer（transferList 零拷贝转让到 Worker）
    const arrayBuffer = fileBytes.buffer.slice(
      fileBytes.byteOffset,
      fileBytes.byteOffset + fileBytes.byteLength,
    ) as ArrayBuffer;

    // 记录提交时间（用于计算单文件加密耗时）
    const submitTime = performance.now();

    // 提交到 Worker 池（传输器阶段，自带背压）
    // 不 await submit()：让加密与下一次文件读取并行（真正的流水线）
    // 池内部拷贝源字节权威副本（可重放），此处以视图零成本传入
    const submitPromise = photoWorkerPool
      .submit({
        fileBytes: new Uint8Array(arrayBuffer),
        request: {
          fileName: fileInput.name,
          mime: fileInput.mime,
          photoKey,
        },
      })
      .then(async (success: PhotoCryptoSuccess) => {
        // 计算单文件加密耗时（提交 → 完成）
        const fileElapsed = performance.now() - submitTime;

        // ===== 生产者去重（断点续传幂等） =====
        if (ctx.isCommitted(success.hash)) {
          ctx.recordSkipped(fileElapsed);
          return;
        }

        // 逐条目进度更新：文件加密完成即推进进度
        //   旧实现仅在 IPC 批次完成后更新 → 加密期间进度条冻结
        //   新实现：per-item update → 用户实时感知「正在加密第 N 张」
        // 等权推进：流式读取下总字节不可预知，按文件数等权计数是最小失真方案，
        //   进度文本含 n/M 真值，不虚报百分比
        ctx.recordProgress(fileElapsed);

        // 构造 BatchRecordInput（外置大文件：块先落库 → 回填引用 → meta-only 加密）
        const record: BatchRecordInput = success.external
          ? await this.finalizeExternalRecord(
              success.external.chunkB64List,
              success.external.chunkHashes,
              success.external.metaTemplate,
              success.thumbB64,
              photoKey,
              success.name,
            )
          : (() => {
              if (!success.metaB64) {
                throw new Error("加密产物缺少元数据");
              }
              return {
                rtype: TYPE_PHOTO_META,
                name: success.name,
                hash: success.hash,
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
      });

    ctx.addSubmit(submitPromise);
  }

  /**
   * Parsed Import：执行 .venc 解析照片的导入流水线
   *
   * 与 run() 的区别（全部收敛在 produceParsedItem 一处）：
   *   - 输入：ParsedPhotoPreview[]（已解密的 meta + 已加密的 chunks）
   *   - 加密：仅重新加密 meta（chunks 已用当前 photoKey 加密，同设备导入）
   *   - 传输器：使用 submitMetaOnly() 而非 submit()
   *   - 无文件读取、无缩略图生成、无 chunk 加密、无取消信号
   *
   * 共享基础设施：会话编排（runSession）统一承担——WAL 断点续传、批量 IPC、
   * 背压队列、生产者调度与让出、进度状态机、哈希去重、失败归因与结束分支、
   * 批量三层缓存同步。
   *
   * @param parsedPhotos 解析预览列表（doParse 阶段产出）
   * @param photoKey 照片模块独立密钥
   * @returns 导入结果（含成功列表 / 跳过数 / 失败数 / 耗时）
   */
  async runParsed(
    parsedPhotos: ParsedPhotoPreview[],
    photoKey: string,
  ): Promise<ImportPipelineResult> {
    const nameOf = (i: number): string => parsedPhotos[i].name;
    // 会话级批次时间戳：createdAt 与记录名同源，跨条目共享同一基准
    const importTimestamp = nextImportTimestamp();
    return await this.runExclusive(parsedPhotos.length, nameOf, () =>
      this.runSession({
        label: "解析导入",
        total: parsedPhotos.length,
        nameOf,
        produce: (i, ctx) => this.produceParsedItem(parsedPhotos, i, importTimestamp, photoKey, ctx),
      }),
    );
  }

  /**
   * 解析导入的单条生产策略：外置判定 → 块上传 / 内联 → meta-only 加密 → 入列。
   *
   * 与文件导入的差异：输入是已解密 meta + 已加密块（无需读文件与缩略图生成），
   * 加密只重写 meta；meta 缺失（来源模块密钥不匹配）计入不可解密分类。
   * 会话编排（取消 / 背压 / 去重 / 进度 / 结束分支）由 runSession 统一承担。
   *
   * @param parsedPhotos 解析预览列表（会话内共享，按索引取用）
   * @param i 条目下标（编排层保证唯一）
   * @param importTimestamp 会话级批次时间戳（createdAt 与记录名同源）
   * @param photoKey 照片模块独立密钥
   * @param ctx 生产上下文（记账与入列的唯一通道）
   */
  private async produceParsedItem(
    parsedPhotos: ParsedPhotoPreview[],
    i: number,
    importTimestamp: number,
    photoKey: string,
    ctx: ProduceContext,
  ): Promise<void> {

    const ph = parsedPhotos[i];

    // 仅处理 meta 非 null 的照片（同设备导入：chunks 已用当前 photoKey 加密）
    //   meta 为 null 的照片（模块密钥不匹配）计入不可解密分类：
    //   非失败（不可重试也无重试意义）、不写入列表，由调用方展示原因
    if (!ph.meta) {
      ctx.recordUndecryptable();
      await yieldToMain();
      return;
    }
    // 提升为 const 局部：闭包内保留非空收窄（属性级收窄不进嵌套函数）；
    // 一并脱代理净化——解析产物经 Vue ref 存储，meta 及其嵌套数组字段是
    // 响应式 Proxy，直接进 Worker 载荷会使 postMessage 抛 DataCloneError
    // （meta-only 加密任务对每张照片系统性失败）。此处一次净化覆盖本条目
    // 后续全部派生（metaTemplate / 内联提交 / 外置提交）与模块引用。
    const meta: PhotoMeta = toPlainPayload(ph.meta);

    // 外置判定（按块密文总量：b64 长度 × 3/4 ≈ 原始字节）
    const b64Total = ph.chunkB64List.reduce((s, c) => s + c.length, 0);
    const approximateRawBytes = Math.floor((b64Total * 3) / 4);
    const external = approximateRawBytes > MAX_INLINE_META_BYTES;

    // 外置路径先去重：避免为已 committed 文件做块上传与加密
    if (external && ctx.isCommitted(meta.fileHash)) {
      ctx.recordSkipped(0);
      await yieldToMain();
      return;
    }

    // 逐块密文哈希（仅外置路径使用）：优先取解析产物（doParse 阶段与
    // 块负载同步计算），缺失时现场补算（与块密文同源）
    let parsedChunkHashes: string[] | null = null;
    if (external) {
      parsedChunkHashes =
        meta.chunkHashes && meta.chunkHashes.length === ph.chunkB64List.length
          ? meta.chunkHashes
          : computeChunkHashesForB64(ph.chunkB64List);
    }

    // 记录名（与旧实现一致：`parsed_${timestamp}_${index}`）
    const recordName = `parsed_${importTimestamp}_${i}`;

    // 记录提交时间（用于计算单文件加密耗时）
    const submitTime = performance.now();

    // 构造写入记录：外置路径经块上传 + meta-only 加密；内联原路径
    // 不 await：让加密/上传与下一次构造并行（真正的流水线）
    const submitPromise: Promise<void> = external
      ? (async () => {
          if (!parsedChunkHashes) {
            throw new ChunkUploadError("外置块哈希缺失，无法上传块");
          }
          const record = await this.finalizeExternalRecord(
            ph.chunkB64List,
            parsedChunkHashes,
            // 缩略图引用由本次写入的记录决定：清空来源设备的记录 ID，
            // 由流水线在缩略图记录落库后回填（来源 ID 在本地无意义）
            { ...meta, chunkDataB64: [], chunkIds: [], thumbId: undefined, createdAt: importTimestamp + i },
            meta.thumbB64 || "",
            photoKey,
            recordName,
          );
          const fileElapsed = performance.now() - submitTime;
          // 哈希与 meta.fileHash 同源，前置去重后此处必然未命中；保留复核兜底
          if (ctx.isCommitted(record.hash)) {
            ctx.recordSkipped(fileElapsed);
            return;
          }
          ctx.recordProgress(fileElapsed);
          await ctx.enqueue({
            index: i,
            record,
            name: ph.name,
            displayName: meta.name,
            thumbB64: meta.thumbB64 || "",
            size: meta.size,
            mime: meta.mime,
          });
        })()
      : photoWorkerPool
          .submitMetaOnly({
            meta: {
              ...meta,
              chunkIds: [],                       // 内联存储，不使用单独块记录
              chunkDataB64: [...ph.chunkB64List], // 内联已加密块
              createdAt: importTimestamp + i,     // 保证唯一性
            },
            photoKey,
            recordName,
          })
          .then(async (success: PhotoMetaCryptoSuccess) => {
            // 计算单文件加密耗时（提交 → 完成）
            const fileElapsed = performance.now() - submitTime;

            // ===== 生产者去重（断点续传幂等） =====
            if (ctx.isCommitted(success.hash)) {
              ctx.recordSkipped(fileElapsed);
              return;
            }

            // 逐条目进度更新：meta 加密完成即推进进度
            ctx.recordProgress(fileElapsed);

            // 构造 BatchRecordInput
            const record: BatchRecordInput = {
              rtype: TYPE_PHOTO_META,
              name: success.recordName,
              hash: success.hash,
              data_b64: success.metaB64,
            };

            await ctx.enqueue({
              index: i,
              record,
              name: success.name,
              displayName: meta.name,
              thumbB64: success.thumbB64,
              size: success.size,
              mime: success.mime,
            });
          });

    const guarded = submitPromise.catch((e: Error) => {
      log.error(`meta-only 加密失败: ${recordName}`, e);
      ctx.recordProduceError(e, i, ph.name);
    });
    ctx.addSubmit(guarded);
  }

  /** 初始化导入会话（含断点续传恢复） */
  private async beginImportSession(): Promise<ImportBeginResult> {
    if (this.config.enableResume) {
      // 先扫描遗留 WAL（续传去重，不创建会话）
      try {
        const recover = await verthysWalRecover();
        if (recover.ok && recover.hashes.length > 0) {
          log.info(
            `检测到遗留 WAL: committed=${recover.hashes.length}, ` +
              `import_id=${recover.import_id ?? "无"}, 将续传去重`,
          );
        }
      } catch (e) {
        log.warn("WAL 恢复扫描失败（忽略，继续新建会话）:", e);
      }
    }

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
   * @param photoKey 照片模块独立密钥
   * @param recordName verthys 记录名
   * @returns 最终写入记录（含外置引用字段）
   */
  private async finalizeExternalRecord(
    chunkB64List: string[],
    chunkHashes: string[],
    metaTemplate: PhotoMeta,
    plainThumbB64: string,
    photoKey: string,
    recordName: string,
  ): Promise<BatchRecordInput> {
    // 索引瘦身布局：缩略图与块集先落独立记录（获得 ID 后回填索引），
    //   索引随后按同一文件盐加密；既有布局维持"块 + 索引"两步。
    const slimLayout = metaTemplate.fmt === PHOTO_FMT_SLIM && !!metaTemplate.wrappedFileKey;

    const chunkIds = await uploadExternalChunks(chunkB64List, chunkHashes);
    // 缩略图可选：源照片无缩略图（生成失败）时索引不携带缩略图引用，
    //   读取侧据此回落"无缩略图"展示，而不是让整张迁移失败
    const thumbId = slimLayout && plainThumbB64
      ? await uploadSlimThumb(
          plainThumbB64, metaTemplate.wrappedFileKey!, metaTemplate.fileHash,
          photoKey, recordName,
        )
      : 0;
    const chunkSetId = slimLayout
      ? await uploadSlimChunkSet(
          chunkIds, chunkHashes, metaTemplate.wrappedFileKey!, metaTemplate.fileHash,
          photoKey, recordName,
        )
      : 0;

    // 瘦身索引只保留聚合引用：逐块 ID 与逐块哈希移入块集记录
    //   （内联数组会让索引体积随照片大小线性增长）
    const metaForWrite: PhotoMeta = slimLayout
      ? {
          ...metaTemplate,
          thumbB64: "",
          chunkIds: [],
          chunkDataB64: [],
          chunkHashes: undefined,
          thumbId,
          chunkSetId,
          chunkCount: chunkIds.length,
        }
      : { ...metaTemplate, chunkIds };

    const metaFinal = await photoWorkerPool.submitMetaOnly({
      meta: metaForWrite,
      photoKey,
      recordName,
      ...(slimLayout
        ? { slim: { fileSaltB64: bytesToBase64(extractSlimFileSalt(metaTemplate.wrappedFileKey!)) } }
        : {}),
    });
    return {
      rtype: TYPE_PHOTO_META,
      name: recordName,
      hash: metaTemplate.fileHash,
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
   */
  async beginRepackSession(): Promise<void> {
    await this.beginImportSession();
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
   * @param photoKey 照片模块独立密钥
   * @param recordName 新记录名
   * @returns 新索引记录 ID（> 0）
   * @throws Error 写入被拒绝（含后端按哈希去重跳过：错误消息为 DUPLICATE_SKIPPED）
   */
  async writeRepackedPhoto(
    success: PhotoCryptoSuccess,
    photoKey: string,
    recordName: string,
  ): Promise<number> {
    if (!success.external) {
      throw new Error("重打包产物缺少外置块（布局二必须外部化分块）");
    }
    const record = await this.finalizeExternalRecord(
      success.external.chunkB64List,
      success.external.chunkHashes,
      success.external.metaTemplate,
      success.thumbB64,
      photoKey,
      recordName,
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
    const batchStartAt = performance.now();

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

      ledger.onSkipped(resp.skipped_count);

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
        }
        // ids=0 且未在失败下标：后端哈希去重，已通过 onSkipped 入账
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
    thumb: `url(data:image/jpeg;base64,${item.thumbB64})`,
    size: formatSize(item.size),
    height: 180 + ((i * 23) % 100),
  }));
}
