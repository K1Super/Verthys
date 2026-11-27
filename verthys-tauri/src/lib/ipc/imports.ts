/*
 * ipc/imports.ts — 导入会话/批次写入/存储统计与压缩
 */

import { Channel } from "@tauri-apps/api/core";
import {
  SESSION_BEGIN_TIMEOUT_MS,
  SESSION_FORCE_CLOSE_TIMEOUT_MS,
} from "../../constants/photo_budget.generated";
import { invokeWithTimeout } from "../../utils/ipc/invoke_wrapper";
import { markFrontendIpcActive } from "../../core/frontend-ipc-priority";
import { ipc } from "./internal";
import type {
  VerthysResponse,
  ImportBeginResult,
  BatchRecordInput,
  ImportBatchProgress,
  AddRecordsBatchResult,
  ChunkBlobInput,
  AddChunkBatchResult,
  StorageStats,
} from "../../types/verthys";

/** 强制关闭（丢弃）当前活跃的导入会话（异常/中断清理）
 *
 *  语义：不写 end、不压缩 WAL——会话被直接丢弃，盘面 WAL 保留，
 *  断点续传状态在下次 begin 时可恢复。无活跃会话时幂等返回 true。 */
export async function verthysForceCloseImportSession(): Promise<boolean> {
  // 强制清理超时（跨层预算常量）：清理为幂等轻操作，超时视为未生效（返回 false）
  try {
    const r = await invokeWithTimeout<VerthysResponse>(
      "verthys_force_close_import_session",
      undefined,
      SESSION_FORCE_CLOSE_TIMEOUT_MS,
    );
    return r.ok;
  } catch (e) {
    console.warn("[verthysForceCloseImportSession] 调用失败/超时:", e);
    return false;
  }
}

/** 新增记录（返回分配的 ID） */
export async function verthysAddRecord(
  type: number,
  name: string,
  dataB64: string
): Promise<number | null> {
  const r = await ipc<VerthysResponse>("verthys_add_record", {
    rtype: type,
    name,
    dataB64,
  });
  return r.ok && r.id !== undefined ? r.id : null;
}

/* ================================================================== *
 * 照片导入异步批处理流水线 IPC 封装                                 *
 *                                                                  *
 * 五个命令对应后端 controller::verthys_batch_controller：             *
 *   - verthysImportBegin：创建导入会话（WAL + 续传去重哈希集）         *
 *   - verthysAddRecordsBatch：批量写入 N 条已加密记录（流式进度）      *
 *   - verthysImportEnd：关闭导入会话（success 触发 WAL 压缩）         *
 *   - verthysImportCheckpoint：查询当前检查点状态                     *
 *   - verthysWalRecover：扫描遗留 WAL（续传去重，不创建会话）         *
 *                                                                  *
 * 「N 次加密，1 次 IPC 传输」：前端 Worker 池并行加密 N 条记录  *
 * 后，单次 IPC 调用 verthysAddRecordsBatch 写入。WAL 保证断点续传幂等。*
 * ================================================================== */

/**
 * 创建导入会话：初始化 WAL + 从既有快照恢复非内容条目键（续传幂等）。
 *
 * 流程：
 *   1. 防重入：后端检查是否已存在活跃会话，存在则拒绝
 *   2. 创建 ImportSession：加载遗留 WAL 快照 → 恢复参与续传的条目键 → 截断 WAL 写 begin
 *   3. 返回 import_id + entry_keys（供生产者续传幂等）
 *
 * @param verthysPath 可选 verthys 路径（不传则从当前会话守卫读取）
 * @returns { ok, import_id, entry_keys, total_count }
 */
export async function verthysImportBegin(
  verthysPath?: string,
): Promise<ImportBeginResult> {
  // 会话开始超时（跨层预算常量）：worker 挂死时不再无限等待——超时按可重试
  // 失败返回（非抛出），由调用方按"导入初始化失败"提示并可重试
  try {
    const r = await invokeWithTimeout<VerthysResponse>(
      "verthys_import_begin",
      { verthysPath: verthysPath ?? null },
      SESSION_BEGIN_TIMEOUT_MS,
    );
    return {
      ok: r.ok,
      import_id: r.import_id ?? "",
      entry_keys: r.entry_keys ?? [],
      total_count: r.total_count ?? 0,
      error: r.error,
      error_code: r.error_code ?? undefined,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.warn("[verthysImportBegin] 调用失败/超时:", msg);
    return { ok: false, import_id: "", entry_keys: [], total_count: 0, error: `导入初始化超时或失败: ${msg}` };
  }
}

/**
 * 批量写入 N 条已加密记录（WAL pending → worker 批量 add_records → WAL committed → 检查点）。
 *
 * 「N 次加密，1 次 IPC 传输」：前端 Worker 池并行加密 N 条记录后，单次 IPC 写入。
 * 后端单写者按子批调用 worker 批量 add_records（单次事务提交），WAL committed
 * 按子批一次 fsync，批次结束写检查点。通过 onProgress Channel 流式推送进度，
 * 前端在 requestAnimationFrame 内绘制进度条。
 *
 * @param records 已加密记录列表（前端 Worker 池产出）
 * @param onProgress 进度回调（每条记录处理后触发）
 * @returns { ok, ids, batch_id, failed_indices, processed_count, total_count, skipped_count }
 */
export async function verthysAddRecordsBatch(
  records: BatchRecordInput[],
  onProgress?: (progress: ImportBatchProgress) => void,
): Promise<AddRecordsBatchResult> {
  // 创建 Tauri Channel 用于流式接收进度（与 verthysUnlock 模式一致）
  const channel = new Channel<ImportBatchProgress>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }

  // 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
  markFrontendIpcActive();

  const r = await ipc<VerthysResponse>("verthys_add_records_batch", {
    records,
    onProgress: channel,
  });
  return {
    ok: r.ok,
    ids: r.ids ?? [],
    batch_id: r.batch_id ?? 0,
    failed_indices: r.failed_indices ?? [],
    processed_count: r.processed_count ?? 0,
    total_count: r.total_count ?? 0,
    skipped_count: r.skipped_count ?? 0,
    error: r.error,
  };
}

/**
 * 上传外置加密块（大文件分块记录，经后端单写者通道串行落库）。
 *
 * 大文件照片的块密文总量超过内联阈值时，块先经本命令落为独立记录，
 * 随后 meta 记录携带 chunk_ids 引用。后端校验块已上传（与 meta 写入
 * 同 FIFO），同哈希重复上传幂等复用既有记录 ID。
 *
 * @param chunks 块列表（单批 ≤ 8 条，载荷受后端上限校验）
 * @returns { ok, ids, failed_indices }
 */
export async function verthysAddChunkBatch(
  chunks: ChunkBlobInput[],
): Promise<AddChunkBatchResult> {
  if (chunks.length === 0) {
    return { ok: true, ids: [], failed_indices: [] };
  }
  const r = await ipc<VerthysResponse>("verthys_add_chunk_batch", { chunks });
  return {
    ok: r.ok,
    ids: r.ids ?? [],
    failed_indices: r.failed_indices ?? [],
    error: r.error,
  };
}

/**
 * 删除照片后释放续传幂等锁（后端 WAL 追加删除墓碑，删除后可重新导入）。
 *
 * @param entryKeys 已删除照片的非内容条目键（来源元数据派生）
 * @param recordIds 已删除的记录 ID（meta 不可解密/历史条目缺键时按 ID 释放）
 */
export async function verthysForgetImportKeys(
  entryKeys: string[],
  recordIds: number[] = [],
): Promise<void> {
  if (entryKeys.length === 0 && recordIds.length === 0) return;
  // 幂等锁释放失败会让被删文件在重新导入时被静默跳过（用户只看到"导入 0 张"
  // 且无任何失败提示）：失败重试一次，仍失败则上抛，由调用方记录或提示。
  for (let attempt = 1; attempt <= 2; attempt++) {
    const r = await ipc<VerthysResponse>("verthys_forget_import_keys", {
      entryKeys,
      recordIds,
    });
    if (r.ok) return;
    if (attempt === 2) {
      throw new Error(`续传幂等锁释放失败: ${r.error ?? "unknown error"}`);
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 200));
  }
}

/**
 * 清理孤儿外置块记录（GC）。
 *
 * 删除台账中 owner=0（已上传但未被任何 meta 引用）的块记录——典型来源
 * 是「块已落库、meta 提交前崩溃」的残留。仅在无活跃导入会话时可用
 * （活跃会话台账在内存，文件视图滞后）。调用方按维护时机 best-effort
 * 触发：导入会话成功结束后、批量删除成功后。
 *
 * @returns 本次清除的块记录数
 */
export async function verthysGcOrphanChunks(): Promise<number> {
  const r = await ipc<VerthysResponse>("verthys_gc_orphan_chunks");
  return r.ok ? (r.processed_count ?? 0) : 0;
}

/**
 * 读取容器存储统计（活数据 / 可回收字节）。
 */
export async function verthysStorageStats(): Promise<StorageStats> {
  const r = await ipc<VerthysResponse>("verthys_storage_stats");
  if (!r.ok || !r.storage_stats) {
    throw new Error(r.error ?? "存储统计失败");
  }
  return r.storage_stats;
}

