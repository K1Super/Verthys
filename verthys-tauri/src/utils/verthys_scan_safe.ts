/*
 * utils/verthys_scan_safe.ts — 安全的记录扫描包装（永不抛出）
 *
 * 问题：
 *   ensureRecordScan() 在生产环境可能因 worker 路径解析、时序、
 *   v1 格式不支持游标等原因抛出异常。Vue 组件直接调用 ensureRecordScan()
 *   时若未 try-catch，会导致组件加载函数抛出、UI 白屏或应用崩溃。
 *
 * 做法：
 *   ensureRecordScanSafe() 包装 ensureRecordScan()，失败时回退到
 *   scanVerthysRecords 逐条 IPC 扫描（兼容所有场景），将结果写入缓存。
 *   永不抛出异常，调用方无需 try-catch。
 *
 *   1. 快速路径：ensureRecordScan() 批量加载（1 次 IPC）
 *   2. 回退路径：scanVerthysRecords 逐条 verthysGetRecord（带 IPC 异常容错）
 *      扫描结果通过 addRecordToScan 写入缓存，后续 getRecordIdsByType /
 *      getRecordFromScan 可正常工作
 *
 * 新增 ensureSummaryScanSafe()
 *   包装 ensureSummaryScan()，失败时回退到 ensureRecordScanSafe()
 *   （旧全量扫描兜底）。用于 Vue 组件的列表渲染路径，1-2 秒内完成。
 *
 * 依赖关系（无循环）：
 *   verthys_scan_safe.ts → verthys-cache.ts（clearRecordScanCache / addRecordToScan）
 *   verthys_scan_safe.ts → verthys_traversal.ts（scanVerthysRecords）
 *   verthys_traversal.ts → verthys-cache.ts（ensureRecordScan / getRecordFromScan）
 *   无反向依赖，不构成循环
 */
import { ensureRecordScan, ensureSummaryScan, clearRecordScanCache, addRecordToScan, clearSummaryCache } from "../cache/composition/verthys-cache";
import { scanVerthysRecords } from "./verthys_traversal";

/**
 * 安全的记录扫描：确保缓存已加载，永不抛出异常。
 *
 * 调用链：
 *   1. ensureRecordScan() — 批量游标扫描（v2）或 verthysEnumerateRecords（v1 回退）
 *   2. 若失败 → clearRecordScanCache() + scanVerthysRecords() 逐条 IPC 扫描
 *      scanVerthysRecords 内部已对 verthysGetRecord IPC 异常做 try-catch，
 *      确保最坏情况下也只是返回空结果，不会抛出。
 *
 * 调用方（Vue 组件）只需：
 *   await ensureRecordScanSafe();
 *   const ids = getRecordIdsByType(TYPE_XXX);
 *   for (const id of ids) { const r = getRecordFromScan(id); ... }
 *
 * 无需 try-catch，生产环境稳健。
 */
export async function ensureRecordScanSafe(): Promise<void> {
  try {
    await ensureRecordScan();
    return;
  } catch (e) {
    console.warn("[ensureRecordScanSafe] 批量扫描失败，回退到逐条 IPC 扫描", e);
  }

  // 回退路径：清空可能不一致的缓存，逐条 IPC 扫描并写入缓存
  clearRecordScanCache();
  try {
    await scanVerthysRecords((entry) => {
      // 将逐条扫描结果写入缓存，供 getRecordIdsByType / getRecordFromScan 使用
      addRecordToScan(entry.id, entry.type, entry.name, entry.dataB64);
      return false; // 继续遍历
    });
  } catch (e) {
    // scanVerthysRecords 内部已对 verthysGetRecord 异常做 try-catch，
    // 此处仅作为最终兜底，确保永不抛出
    console.error("[ensureRecordScanSafe] 逐条 IPC 扫描也失败（缓存将为空）", e);
  }
}

/**
 * 安全的摘要扫描包装（永不抛出，Vue 组件列表渲染专用）。
 *
 * 目标：前端拿到轻量元数据后即刻渲染出完整列表。
 *
 * 调用链：
 *   1. ensureSummaryScan() — 摘要游标批量扫描（v2，仅元数据，1-2 秒内完成）
 *   2. 若失败 → ensureRecordScanSafe() 旧全量扫描兜底
 *      （内部已处理所有回退路径，将结果写入 recordScanCache）
 *
 * 调用方（Vue 组件）只需：
 *   await ensureSummaryScanSafe();
 *   const ids = getSummaryIdsByType(TYPE_XXX);
 *   for (const id of ids) {
 *     const summary = getSummaryRecord(id);     // 元数据（名称/类型/大小）
 *     const full = await getFullRecord(id);     // 完整数据（按需加载）
 *   }
 *
 * 无需 try-catch，生产环境稳健。
 */
export async function ensureSummaryScanSafe(): Promise<void> {
  try {
    await ensureSummaryScan();
    return;
  } catch (e) {
    console.warn("[ensureSummaryScanSafe] 摘要扫描失败，回退到全量扫描兜底", e);
  }

  // 回退路径：清空可能不一致的摘要缓存，使用全量扫描兜底
  // 全量扫描会将结果写入 recordScanCache（旧缓存），
  // Vue 组件应优先使用 summaryCache，若为空则回退到 recordScanCache
  clearSummaryCache();
  try {
    await ensureRecordScanSafe();
  } catch (e) {
    // ensureRecordScanSafe 内部已处理所有回退路径，
    // 此处仅作为最终兜底，确保永不抛出
    console.error("[ensureSummaryScanSafe] 全量扫描兜底也失败（摘要缓存将为空）", e);
  }
}
