/*
 * key/global/shared.ts — 全局密钥域共享类型、常量与内部辅助
 *
 * 职责：
 *   1. 全局密钥记录识别与权威解析（类型索引优先，最新 id 为权威）
 *   2. 历史残留收敛
 *   3. 会话守卫启动与密钥管理器状态原子重置
 */
import {
  verthysListIdsByType, verthysGetRecord, verthysEnumerateRecords,
  verthysDeleteRecord,
  securitySessionStart, securitySessionStop,
} from "../../lib/verthys";
import { resetAllState } from "../../state/key_state";
import { TYPE_GLOBAL_KEY } from "../../constants/key_manager_const";
import { withTimeout } from "../../utils/ipc/promise_utils";
import {
  clearModuleKeyCache, clearRecordScanCache, resetFlushChain,
  clearSummaryCache, clearFullRecordCache,
  invalidateSummaryRecord, invalidateScannedRecord,
  flushVerthysNow,
} from "../../cache/composition/verthys-cache";
import { stopBackgroundTasks } from "../../core/background-tasks";
import { clearSessionTimer, securityHardeningFailedRef } from "../../session/security-session";
import { createLogger } from "../../utils/logging/logger";

export const log = createLogger("global-verthys");

/**
 * 启动系统会话守卫（锁屏/挂起/显示器关闭锁定）。
 *
 * 任何成功建立会话（新建或解锁）都必须调用；不能只在全局密钥验证
 * 路径调用，否则无全局密钥的库在解锁后不会接线下发挂起守卫位，
 * 防御面板会如实显示「挂起绕过 · 降级（挂起看门狗未启用）」。
 * 守卫启动失败时置位 hardening 降级标志并继续，不阻断解锁。
 */
export async function startSessionGuard(): Promise<void> {
  try {
    await withTimeout(securitySessionStart(), 5000, "securitySessionStart");
    securityHardeningFailedRef.value = false;
  } catch (e) {
    securityHardeningFailedRef.value = true;
    log.warn("启动会话守卫失败/超时（非致命）", e);
  }
}

/* ------------------------------------------------------------------ *
 * 全局密钥记录解析（唯一权威）                                         *
 * ------------------------------------------------------------------ */

/** 记录识别常量（与 worker / 记录写入方一致） */
const GLOBAL_KEY_NAME = "global-key";
const GLOBAL_KEY_RECORD_BYTES = 124;
const GLOBAL_KEY_PAGE_SIZE = 64;
const GLOBAL_KEY_MAX_CANDIDATES = 256;

export interface GlobalKeyRecordRef {
  id: number;
  recordB64: string;
}

/** 解析结果：最新有效记录 + 更旧残留 id */
export interface GlobalKeyResolution {
  /** 最新有效记录；null 表示不存在 */
  record: GlobalKeyRecordRef | null;
  /** 比最新记录更旧的有效记录（历史中断残留，待收敛） */
  duplicates: number[];
}

/** 判断记录是否为全局密钥记录：名称精确 + 解码后固定 124 字节 */
function isGlobalKeyRecord(name: string, dataB64: string): boolean {
  if (name !== GLOBAL_KEY_NAME) return false;
  try {
    return atob(dataB64.replace(/\s+/g, "")).length === GLOBAL_KEY_RECORD_BYTES;
  } catch {
    return false;
  }
}

/** 分页枚举 TYPE_GLOBAL_KEY 的全部候选 id（升序；跳过墓碑） */
async function listGlobalKeyCandidateIds(): Promise<number[]> {
  const ids: number[] = [];
  let after = 0;
  for (;;) {
    const page = await verthysListIdsByType(TYPE_GLOBAL_KEY, after, GLOBAL_KEY_PAGE_SIZE);
    if (page.ids.length === 0) break;
    ids.push(...page.ids);
    after = page.ids[page.ids.length - 1];
    if (ids.length > GLOBAL_KEY_MAX_CANDIDATES) {
      throw new Error("全局密钥候选记录过多，容器索引异常");
    }
    if (page.exhausted) break;
  }
  return ids;
}

/** 解析全局密钥记录：类型索引优先，取最新（最大 id）的有效记录。
 *
 * 不再依赖通用摘要缓存（其 first-id 语义与"最新权威"冲突）；类型索引不可用时
 * 回退全量枚举。读取失败向上抛出，由调用方决定回退策略（fail-closed）。
 */
export async function resolveGlobalKeyRecord(): Promise<GlobalKeyResolution> {
  let ids: number[];
  try {
    ids = await listGlobalKeyCandidateIds();
  } catch (e) {
    log.warn("resolveGlobalKeyRecord: 类型索引不可用，回退全量枚举", e);
    const records = await verthysEnumerateRecords(1);
    ids = records.filter((r) => r.type === TYPE_GLOBAL_KEY).map((r) => r.id);
  }

  const valid: GlobalKeyRecordRef[] = [];
  for (const id of ids.sort((a, b) => a - b)) {
    const rec = await verthysGetRecord(id);
    if (!rec || !rec.dataB64) continue;
    if (!isGlobalKeyRecord(rec.name, rec.dataB64)) continue;
    valid.push({ id, recordB64: rec.dataB64 });
  }
  if (valid.length === 0) return { record: null, duplicates: [] };
  const record = valid[valid.length - 1];
  return { record, duplicates: valid.slice(0, -1).map((v) => v.id) };
}

/** 收敛历史残留：保留最新有效记录，删除更旧的有效记录。
 *
 * 仅由解锁关键路径调用（容器已解锁、会话已建立）。失败只告警不阻断；
 * 删除后逐条读回确认，并失效对应缓存条目。
 */
async function convergeGlobalKeyDuplicates(duplicateIds: number[]): Promise<void> {
  if (duplicateIds.length === 0) return;
  let deleted = 0;
  for (const id of duplicateIds) {
    try {
      const removed = await verthysDeleteRecord(id);
      if (!removed) {
        log.warn(`收敛全局密钥残留失败（删除未确认） lid=${id}`);
        continue;
      }
      const ghost = await verthysGetRecord(id).catch(() => null);
      if (ghost !== null) {
        log.warn(`收敛全局密钥残留失败（读回仍存在） lid=${id}`);
        continue;
      }
      invalidateSummaryRecord(id);
      invalidateScannedRecord(id);
      deleted += 1;
    } catch (e) {
      log.warn(`收敛全局密钥残留异常 lid=${id}`, e);
    }
  }
  if (deleted > 0) {
    log.warn(`全局密钥历史残留已收敛 ${deleted} 条（最新记录为唯一权威）`);
    try {
      await flushVerthysNow();
    } catch (e) {
      log.warn("全局密钥残留收敛后 flush 失败（非阻断）", e);
    }
  }
}

/** 解析 + 收敛 + probe 回退：解锁路径专用 */
export async function resolveAndConvergeGlobalKey(
  fallback: GlobalKeyRecordRef | null,
): Promise<GlobalKeyResolution> {
  try {
    const resolution = await resolveGlobalKeyRecord();
    await convergeGlobalKeyDuplicates(resolution.duplicates);
    return resolution;
  } catch (e) {
    log.warn("resolveAndConvergeGlobalKey: 解析失败，回退解锁响应探测结果", e);
    return { record: fallback, duplicates: [] };
  }
}

/**
 * 重置密钥管理器全部状态（异步原子化版本）
 *
 * 异步原子化重置生命周期
 *
 * 清理顺序（严格串行，每步 await 完成）：
 *   1. securitySessionStop() — 解除系统锁屏监听，防止监听器残留
 *   2. stopBackgroundTasks() — 等待所有后台任务实际终止
 *   3. resetAllState() — 重置所有 refs + currentVerthysPath
 *   4. clearModuleKeyCache() — 清零模块独立密钥会话缓存
 *   5. clearRecordScanCache() — 清零扫描缓存
 *   6. clearSummaryCache() — 清空摘要缓存
 *   7. clearFullRecordCache() — 清空全量记录缓存
 *   8. resetFlushChain() — 重置 flush 队列
 *   9. clearSessionTimer() — 清零会话空闲计时器
 *
 * 顺序约束：
 *   - 解除系统锁屏监听必须先于状态重置，否则监听器残留；
 *   - stopBackgroundTasks 必须 await 到后台任务实际终止，否则任务可能访问已释放缓存。
 */
export async function resetKeyManagerState(): Promise<void> {
  // 1. 解除系统锁屏监听（必须在状态重置前完成，避免监听器残留）
  try {
    await withTimeout(securitySessionStop(), 5000, "securitySessionStop");
  } catch (e) {
    log.warn("securitySessionStop 失败（继续清理）", e);
  }

  // 2. 等待后台任务实际终止（stopBackgroundTasks 为 async）
  try {
    await stopBackgroundTasks();
  } catch (e) {
    log.warn("stopBackgroundTasks 异常（继续清理）", e);
  }

  // 3-N. 同步清理（顺序不变）
  resetAllState();
  clearModuleKeyCache();
  clearRecordScanCache();
  clearSummaryCache();
  clearFullRecordCache();
  resetFlushChain();
  clearSessionTimer();
}
