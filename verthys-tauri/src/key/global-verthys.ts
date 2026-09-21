/*
 * key/global-verthys.ts — 全局加密库与 GMK 管理层
 *
 * 职责：
 *   1. 加密库初始化（checkInitStatus / initCreate / initUnlock / initAndUnlock）
 *   2. 全局根密钥 CRUD（initGlobalKey / changeGlobalKey / verifyGlobalKey / verifyGlobalKeyWithBruteForce）
 *   3. 设备绑定（bindDevice / verifyDeviceBinding / getDeviceFingerprintShort）
 *   4. .bin 文件读取（readBinFile）
 *
 */
import {
  ensureWorkerReady,
  ensureCleanWorkerState,
  verthysUnlock, verthysCreate, verthysPreflight,
  verthysAddRecord, verthysDeleteRecord, verthysInitStatus,
  verthysDeriveGlobalKey, verthysVerifyGlobalKey,
  verthysReconcileKeyPresence,
  verthysGetRecord, verthysEnumerateRecords,
  bytesToBase64, readUserFile,
  setDeviceBinding, checkDeviceBinding, getDeviceFingerprint,
  securityBruteCheck,
  securitySessionStart, securitySessionStop,
  type PreflightResult, type InitStatusResult,
  type BruteForceCheckResponse,
  type UnlockProgress,
} from "../lib/verthys";

// 再导出 Worker 预启动接口，供 SecurityCenter 等上层组件使用
export { preloadWorker, invalidateWorkerPreload } from "../lib/verthys";
import { keyState, setCurrentVerthysPath, resetAllState } from "../state/key_state";
import { TYPE_GLOBAL_KEY, VERTHYS_DEFAULT_PASSWORD, INIT_TIMEOUT_MS, CREATE_TIMEOUT_MS, UNLOCK_SOFT_TIMEOUT_MS, UNLOCK_HARD_TIMEOUT_MS } from "../constants/key_manager_const";
import { withTimeout, withGradedTimeout } from "../utils/promise_utils";
import { isTauriEnvironment } from "../utils/tauri_env";
import {
  persistVerthys, clearModuleKeyCache, clearRecordScanCache, resetFlushChain,
  clearSummaryCache, clearFullRecordCache,
  findLidByTypeEarlyStop,
  enqueueFlush, flushVerthysNow,
  ensureSummaryScan, ensureRecordScan,
} from "../cache/composition/verthys-cache";
// ★ 后台任务 API 直连 core 层（单向化：不再转发 start/stop）
import { startBackgroundTasks, stopBackgroundTasks } from "../core/background-tasks";
import {
  ok, err, errFromUnknown,
  VerthysErrorCode, type VerthysResult,
  wrapAsVerthysError,
} from "../lib/verthys_error";
import { resetSessionTimer, clearSessionTimer, applySecurityPreset, checkBruteForceGate, awaitLockAllIfInProgress } from "../session/security-session";
import type { VerifyGlobalKeyResult } from "../types/key_manager";
import { loadModuleKeyStatus } from "./module-auth";
import { migrateRecordTypes, isAccountRecordB64 } from "./type-migration";
import { createLogger } from "../utils/logger";

const log = createLogger("global-verthys");

/* ------------------------------------------------------------------ *
 * 内部工具                                                            *
 * ------------------------------------------------------------------ */

/** 在 verthys 中查找全局密钥记录
 *  返回 { id, recordB64 } — 不解析内部结构，由 worker 验证
 *
 *
 *  原实现调用 ensureRecordScan() 全量解密所有记录（含照片数据块），
 *  仅为查找一条全局密钥记录 → 数千条记录的 verthys 耗时 20-30s。
 *
 *  新实现分两级查找，将关键路径上的数据解密从 O(N) 降至 O(1)：
 *
 *  全量扫描（ensureRecordScan）仍由 startBackgroundTasks 后台执行，不阻塞关键路径。
 */
async function findGlobalKeyRecord(): Promise<{ id: number; recordB64: string } | null> {
  try {
    const lid = await findLidByTypeEarlyStop(TYPE_GLOBAL_KEY);
    if (lid !== null) {
      const record = await verthysGetRecord(lid);
      if (record && record.dataB64) {
        return { id: lid, recordB64: record.dataB64 };
      }
      return null;
    }
  } catch {
    // findLidByTypeEarlyStop 异常 → 进入路径 2 回退
  }

  // ★ 路径 2：v1 回退路径 — verthysEnumerateRecords（单次 IPC）
  try {
    const records = await verthysEnumerateRecords(1);
    for (const r of records) {
      if (r.type === TYPE_GLOBAL_KEY) {
        return { id: r.id, recordB64: r.dataB64 };
      }
    }
  } catch {
    // verthysEnumerateRecords 也失败 → 返回 null
  }

  return null;
}

/* ------------------------------------------------------------------ *
 * ★ 企业级根治：解锁响应内联探测结果（已废弃前端 probe 链路）       *
 *                                                                    *
 * 原缺陷（已根治）：解锁成功后前端需发起 3~4 次 IPC 往返              *
 *   (verthysHasRecordByType → findLidByTypeEarlyStop → verthysGetRecord)  *
 * 才能判断是否存在全局主密钥记录并取回数据。该链路存在两类致命问题：   *
 *   1. v1 容器：Verthys_HasRecordByType 返回 VERTHYS_ERR_FORMAT 假阴性，  *
 *      前端 probe 抛异常 → globalKeyRecordLoading 永驻 true           *
 *      → UI 卡死在 "loading" 视图，无法进入身份验证窗口               *
 *   2. IPC 竞态：多次往返任意一环超时/失败均导致 initUnlock 永不完成   *
 *                                                                    *
 * 根治策略：worker 解锁成功分支进程内一次性完成                       *
 *   has_record(Verthys_FindFirstLidByType) + get_record(Verthys_GetRecord) *
 *   结果内联到 unlock 响应的 has_global_key/global_key_id/             *
 *   global_key_record 三字段。前端 initUnlock 直接消费，零 IPC 往返。  *
 *                                                                    *
 * 原 probeGlobalKeyRecord / confirmGlobalKeyRecordAsync / ProbeResult  *
 * 三件套已整体移除。globalKeyRecordLoading 状态不再被设置（恒 false）。*
 * findGlobalKeyRecord 保留，仅供 initCreate / changeGlobalKey /        *
 * verifyGlobalKey 缓存未命中回退使用（单函数调用，非多步 IPC 链路）。  *
 * ------------------------------------------------------------------ */

/**
 * ★ 异步冲刷（不阻塞调用方）
 *
 * 用于非关键路径的延迟持久化：initGlobalKey 调用此方法，
 * 不等待落盘完成，立即返回。落盘失败通过日志记录；
 * 数据已在 worker 内存中，应用退出时 waitForFlush 兜底。
 *
 * @param immediate true=立即同步冲刷（flushVerthysNow），false=异步入队
 * @returns VerthysResult<void>
 */
async function flushVerthysAsync(immediate: boolean): Promise<VerthysResult<void>> {
  if (immediate) {
    return flushVerthysNow();
  }
  // 非阻塞：入队 persistVerthys，立即返回 ok
  // persistVerthys 内部通过 flushChain 串行执行，防抖合并
  void persistVerthys().catch((e) => {
    log.warn("异步 flush 失败（数据已在内存，后续 waitForFlush 兜底）", e);
  });
  return ok(undefined);
}

/**
 * 重置密钥管理器全部状态（异步原子化版本）
 *
 * ★ 异步原子化重置生命周期
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
 * 关键修复：
 *   - 旧实现 clearSessionTimer 未解除系统锁屏监听 → 监听器残留
 *   - 旧实现 stopBackgroundTasks 仅置取消标志 → 旧任务可能仍在运行访问已释放缓存
 */
async function resetKeyManagerState(): Promise<void> {
  // 1. 解除系统锁屏监听（旧实现遗漏，异步冲刷核心修复）
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

/* ------------------------------------------------------------------ *
 * 加密库初始化                                                        *
 * ------------------------------------------------------------------ */

/**
 * 查询初始化状态（读取 .verthys_state 文件）
 * 供 SecurityCenter 在 onMounted 时调用，确定走哪个分支：
 *   none   → 全新用户，显示路径选择
 *   ready  → 老用户，自动填充路径并解锁
 *   broken → 损坏残留，已自动清理，按全新用户处理
 *
 * @returns 状态结果，Tauri 不可用时返回 "none"
 */
export async function checkInitStatus(): Promise<InitStatusResult> {
  if (!isTauriEnvironment()) {
    keyState.initStatus.value = "none";
    keyState.storedVerthysPath.value = "";
    keyState.initDetail.value = "浏览器模式";
    return { status: "none", verthys_path: null, detail: "浏览器模式" };
  }
  try {
    const result = await withTimeout(verthysInitStatus(), 5000, "状态查询");
    keyState.initStatus.value = result.status;
    keyState.storedVerthysPath.value = result.verthys_path ?? "";
    keyState.initDetail.value = result.detail;
    log.info("status:", result.status, "path:", result.verthys_path, "detail:", result.detail);
    return result;
  } catch (e) {
    log.error("查询失败", e);
    keyState.initStatus.value = "none";
    keyState.storedVerthysPath.value = "";
    keyState.initDetail.value = `查询失败: ${e}`;
    return { status: "none", verthys_path: null, detail: `查询失败: ${e}` };
  }
}

/**
 * 解锁 Channel 进度提示词精准映射（单一数据源）
 *
 * 后端 C DLL（core/src/api/verthys_v2_lifecycle.c verthys_emit_unlock_progress）
 * emit 的 p.message 不可控（可能英文/冗长），基于后端原始 p.percent 精准
 * 映射为精简高级文案，消除前后端提示词不一致问题。
 *
 * 后端 C 层 percent 节点：
 *   5%  - 读取超级块
 *   10% - Argon2 派生开始（含心跳至 45%）
 *   50% - Argon2 完成 / 索引映射
 *   60% - B+树解密开始
 *   85% - B+树完成
 *   95% - 摘要完成
 *   100% - Merkle 校验完成
 *
 * @param rawPercent 后端 C 层 emit 的原始 percent（0~100）
 * @returns 精简高级文案
 */
const UNLOCK_CHANNEL_TEXT_MAP: ReadonlyArray<readonly [number, string]> = [
  [0, '读取索引'],
  [5, '读取索引'],
  [10, '派生密钥'],
  [50, '校验完整性'],
  [60, '解密数据'],
  [85, '重建索引'],
  [95, '生成摘要'],
  [100, '校验完成'],
];

function pickUnlockChannelText(rawPercent: number): string {
  let text = UNLOCK_CHANNEL_TEXT_MAP[0][1];
  for (const [threshold, t] of UNLOCK_CHANNEL_TEXT_MAP) {
    if (rawPercent >= threshold) text = t;
  }
  return text;
}

/**
 * 首次创建加密库（严格遵循「先落地、后状态」原则）
 *
 * ★ 返回 VerthysResult<void>，携带结构化错误码
 *
 * 流程：
 *   1. 路径预检（目录存在性、可写性、系统保护目录）
 *   2. worker_init（启动子进程，加载 DLL）
 *   3. verthys_create（unlock→lock→unlock，文件落地）
 *   4. 检查全局密钥记录
 *   5. 更新全局状态（仅在前面全部成功后）
 *
 * 失败回滚：
 *   - 后端 verthys_create 已自动删除不完整文件 + 销毁 worker
 *   - 前端重置所有状态（await resetKeyManagerState）
 *
 * @param verthysPath .verthys 文件路径
 * @param preflightResult 调用方已执行的路径预检结果（可选）
 * @returns VerthysResult<void>
 */
export async function initCreate(
  verthysPath: string,
  preflightResult?: PreflightResult,
  onProgress?: (progress: UnlockProgress) => void,
): Promise<VerthysResult<void>> {
  // ★ 企业级根治（Issue 2：新建 verthys 进度条无响应）
  //
  // 原缺陷：initCreate 完全不接受 onProgress，也不推送任何进度。创建流程
  //   （路径预检→worker_init→create→lock→unlock→findGlobalKeyRecord→
  //    ensureSummaryScan→loadModuleKeyStatus）期间 UI 进度条恒停留在
  //   "正在启动安全核心…" 0%，用户误以为"创建卡死/按钮无反应/无法创建"。
  //
  // 修复：与 initUnlock 一致的 emit 单调递增闸门，在各阶段推送进度。
  //   后端 verthys_create 内部 create→lock→unlock 三步为单次 IPC（无 Channel
  //   流式进度），故采用阶段式离散推送（非连续），覆盖关键节点即可。
  const t0 = Date.now();
  let lastEmittedPercent = 0;
  const emit = (stage: number, percent: number, message: string) => {
    const clamped = Math.max(percent, lastEmittedPercent);
    lastEmittedPercent = clamped;
    if (onProgress) {
      onProgress({
        stage,
        percent: clamped,
        elapsed_ms: Date.now() - t0,
        message,
      });
    }
  };

  try {
    // ★ 企业级根治D：确保创建前 worker 处于干净状态
    //
    // 根治"回退重选 verthys 卡死"根因：
    //   用户回退 → goBackToUnlock → lockAll（异步，40s 超时）→
    //   doLockAll 同步置 verthysReady=false → UI 立即显示解锁视图 →
    //   用户重选 verthys → doUnlock → initCreate → ensureWorkerReady
    //   复用旧 workerReadyPromise → verthys_create IPC 发往正在被 lockAll
    //   销毁的 worker → 永久卡死。
    //
    // 双重防护：
    //   1. awaitLockAllIfInProgress：等待正在进行的 lockAll 完成（最多 45s）
    //      确保 worker 销毁、缓存清空、状态重置全部落地
    //   2. ensureCleanWorkerState：兜底清理 — 即使 lockAll 超时未完成，
    //      若 workerHasBeenUsed=true 且预启动缓存残留，强制销毁旧 worker
    await awaitLockAllIfInProgress();
    await ensureCleanWorkerState();

    // 1. 路径预检
    emit(1, 2, "校验路径");
    let preflight: PreflightResult;
    if (preflightResult) {
      preflight = preflightResult;
    } else {
      log.info("步骤 1/4：路径预检", verthysPath);
      try {
        preflight = await withTimeout(verthysPreflight(verthysPath), 5000, "路径预检");
      } catch (e) {
        await resetKeyManagerState();
        return errFromUnknown(e, VerthysErrorCode.E_PATH_INVALID);
      }
    }
    if (!preflight.ok) {
      await resetKeyManagerState();
      return err(VerthysErrorCode.E_PATH_INVALID, "访问异常，请检查权限与存储状态");
    }
    if (preflight.file_exists) {
      await resetKeyManagerState();
      return err(VerthysErrorCode.E_PATH_EXISTS, "文件已存在，请使用打开而非创建");
    }

    // 2. ensureWorkerReady
    emit(1, 5, "启动安全核心");
    log.info("步骤 2/4：启动 worker 子进程");
    let ok1: boolean;
    try {
      ok1 = await withTimeout(ensureWorkerReady(), INIT_TIMEOUT_MS, "worker_init");
    } catch (e) {
      await resetKeyManagerState();
      return errFromUnknown(e, VerthysErrorCode.E_WORKER_INIT_FAILED);
    }
    if (!ok1) {
      await resetKeyManagerState();
      return err(VerthysErrorCode.E_WORKER_INIT_FAILED, "安全核心启动失败");
    }

    // 3. verthys_create
    emit(2, 10, "创建加密库");
    log.info("步骤 3/4：创建加密库并写盘");
    let ok2: boolean;
    try {
      ok2 = await withTimeout(verthysCreate(verthysPath, VERTHYS_DEFAULT_PASSWORD), CREATE_TIMEOUT_MS, "verthys_create");
    } catch (e) {
      await resetKeyManagerState();
      return errFromUnknown(e, VerthysErrorCode.E_VERTHYS_CREATE_FAILED);
    }
    if (!ok2) {
      await resetKeyManagerState();
      return err(VerthysErrorCode.E_VERTHYS_CREATE_FAILED, "创建加密库失败");
    }

    // 4. 检查全局密钥记录 + 更新状态
    emit(3, 70, "检查密钥记录");
    log.info("步骤 4/4：检查全局密钥记录");
    setCurrentVerthysPath(verthysPath);
    const existing = await findGlobalKeyRecord();
    keyState.hasGlobalKeyRecord.value = existing !== null;

    // ★ 企业级根治：同步后端 key_lifecycle 状态（与 initUnlock 一致）
    //
    // verthys_create 通过 raw worker IPC 完成 create→lock→unlock，
    // 绕过了 verthys_unlock Tauri 命令的 key_lifecycle 状态管理代码。
    // 新建 verthys 无全局密钥记录，后端状态应为 NoKey。
    // 若不显式重置，可能残留上次会话的 Locked/Unlocked 状态 → derive/verify 失败。
    try {
      await verthysReconcileKeyPresence(keyState.hasGlobalKeyRecord.value);
      log.info(`initCreate: 后端 key_lifecycle 已同步（hasGlobalKeyRecord=${keyState.hasGlobalKeyRecord.value}）`);
    } catch (e) {
      log.warn("initCreate: 后端 key_lifecycle 同步失败（非致命，可能影响派生/验证）", e);
    }

    // ★ 企业级根治修复：始终调用 ensureSummaryScan + loadModuleKeyStatus
    //
    // 原缺陷：仅在 existing（有全局密钥记录）时才调用 loadModuleKeyStatus。
    // 新建 verthys 无全局密钥记录 → loadModuleKeyStatus 不被调用 →
    // moduleKeyEnabled/hasModuleKeyRecord 保持初始默认值。
    // 虽然新 verthys 通常无模块密钥，但确保状态一致性仍需调用。
    //
    // 修复：始终填充摘要缓存 + 加载模块状态（即使为空也写入默认值）。
    emit(4, 80, "加载摘要");
    try {
      await ensureSummaryScan();
    } catch (e) {
      log.warn("initCreate: 摘要扫描失败（非致命）", e);
    }
    emit(5, 90, "加载密钥配置");
    try {
      await loadModuleKeyStatus();
    } catch (e) {
      log.warn("initCreate: 加载模块密钥状态失败（非致命）", e);
    }

    emit(6, 100, "创建完成");
    keyState.verthysReady.value = true;
    startBackgroundTasks().catch(() => { /* 后台任务失败不影响创建 */ });
    log.info("创建成功");
    return ok(undefined);
  } catch (e) {
    log.error("initCreate 未捕获异常", e);
    await resetKeyManagerState();
    return errFromUnknown(e, VerthysErrorCode.E_INIT_FAILED);
  }
}

/**
 * 解锁已有加密库（非首次使用）
 *
 * ★ 返回 VerthysResult<void>
 * ★ 新增 onProgress 可选回调，流式接收解锁进度供前端展示
 *
 * @param verthysPath .verthys 文件路径（已有文件）
 * @param preflightResult 调用方已执行的路径预检结果（可选）
 * @param onProgress 解锁进度回调（在解锁各阶段触发，可选）
 * @returns VerthysResult<void>
 */
export async function initUnlock(
  verthysPath: string,
  preflightResult?: PreflightResult,
  onProgress?: (progress: UnlockProgress) => void,
): Promise<VerthysResult<void>> {
  // ★ 修复6：全流程进度反馈 — 前端各阶段直接调用 onProgress 推送进度
  // 不依赖 Tauri Channel（Channel 仅在 verthysUnlock 阶段由后端推送），
  // 前端阶段（ensureWorkerReady / findGlobalKeyRecord）通过直接调用 onProgress 实现
  const t0 = Date.now();
  // ★ 企业级根治：进度条单调递增，防止从 100% 回退到 90%
  //
  // 原缺陷：
  //   后端 C DLL 解锁阶段通过 Tauri Channel emit 100%（MERKLE_DONE）作为最终进度。
  //   verthysUnlock 返回后，前端 emit(7, 90, "正在加载密钥配置…") 会将进度条
  //   从 100% 回退到 90%，造成视觉上的"倒退"。
  //
  // 修复：
  //   记录已推送的最大百分比，后续 emit 的百分比不得低于已推送值。
  //   消息内容正常更新（用户能看到阶段切换），但百分比只增不减。
  let lastEmittedPercent = 0;
  const emit = (stage: number, percent: number, message: string) => {
    const clamped = Math.max(percent, lastEmittedPercent);
    lastEmittedPercent = clamped;
    if (onProgress) {
      onProgress({
        stage,
        percent: clamped,
        elapsed_ms: Date.now() - t0,
        message,
      });
    }
  };

  try {
    // ★ 企业级根治D：确保解锁前 worker 处于干净状态
    //
    // 根治"回退重选 verthys 卡死"根因：
    //   用户回退 → goBackToUnlock → lockAll（异步，40s 超时）→
    //   doLockAll 同步置 verthysReady=false → UI 立即显示解锁视图 →
    //   用户重选 verthys → doUnlock → initUnlock → ensureWorkerReady
    //   复用旧 workerReadyPromise → verthys_unlock IPC 发往正在被 lockAll
    //   销毁的 worker → 永久卡死在"正在解锁加密库…"。
    //
    // 双重防护：
    //   1. awaitLockAllIfInProgress：等待正在进行的 lockAll 完成（最多 45s）
    //      确保 worker 销毁、缓存清空、状态重置全部落地
    //   2. ensureCleanWorkerState：兜底清理 — 即使 lockAll 超时未完成，
    //      若 workerHasBeenUsed=true 且预启动缓存残留，强制销毁旧 worker
    await awaitLockAllIfInProgress();
    await ensureCleanWorkerState();

    // 1. 路径预检
    emit(1, 2, "校验路径");
    let preflight: PreflightResult;
    if (preflightResult) {
      preflight = preflightResult;
    } else {
      try {
        preflight = await withTimeout(verthysPreflight(verthysPath), 5000, "路径预检");
      } catch (e) {
        await resetKeyManagerState();
        return errFromUnknown(e, VerthysErrorCode.E_PATH_INVALID);
      }
    }
    if (!preflight.ok) {
      await resetKeyManagerState();
      return err(VerthysErrorCode.E_PATH_INVALID, "路径不可用，请检查权限或磁盘空间");
    }
    if (!preflight.file_exists) {
      await resetKeyManagerState();
      return err(VerthysErrorCode.E_PATH_NOT_EXISTS, "文件不存在，请使用创建而非打开");
    }

    // 2. ensureWorkerReady
    emit(1, 5, "启动安全核心");
    let ok1: boolean;
    try {
      ok1 = await withTimeout(ensureWorkerReady(), INIT_TIMEOUT_MS, "worker_init");
    } catch (e) {
      await resetKeyManagerState();
      return errFromUnknown(e, VerthysErrorCode.E_WORKER_INIT_FAILED);
    }
    if (!ok1) {
      await resetKeyManagerState();
      return err(VerthysErrorCode.E_WORKER_INIT_FAILED, "安全核心启动失败");
    }

    // 2.5 暴力熔断门禁预检（纯查询，不计数）
    //
    // 服务端在 unlock 入口已强制熔断（fail-closed）；此处仅提前拦截，
    // 避免锁定态进入 Argon2id 长运算流程浪费用户等待。查询失败时
    // 放行，由服务端闸门兜底强制。
    const unlockGate = await checkBruteForceGate();
    if (!unlockGate.allowed) {
      await resetKeyManagerState();
      return unlockGate.reason === "locked"
        ? err(VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED, `尝试次数过多，已锁定 ${Math.ceil(unlockGate.remainingSecs ?? 0)} 秒，请稍后再试`)
        : err(VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED, "失败次数已达上限，需完成安全清理与完整性校验后重试");
    }

    // 3. verthys_unlock — ★ 企业级根治：返回完整 VerthysResponse
    //
    // ★ 后端各阶段进度通过 Channel 流式推送，经 emit 闸门单调递增转发前端
    // 后端会推送 10%~100% 的进度（v1 和 v2 路径均已覆盖），映射到 8%~85% 子区间
    // ★ 分级超时熔断（软 15s 提示 / 硬 35s 降级 / 连续 3 次熔断锁定）
    //   - 软超时 15s：Argon2id 派生耗时过长，前端提示「密钥计算较慢，请耐心等待」继续执行
    //   - 硬超时 35s：整体解锁未完成，触发降级校验，仅保障核心数据可读
    //   - 连续 3 次硬超时自动锁定容器 30 分钟（withGradedTimeout 内部处理）
    //
    // ★ 企业级根治：worker 在 Verthys_Unlock 成功后进程内一次性完成
    //   Verthys_FindFirstLidByType(0x10) + Verthys_GetRecord(lid)，
    //   结果内联到响应 has_global_key/global_key_id/global_key_record 三字段。
    //   前端直接消费，零解锁后 IPC 往返，消除 probe 链竞态与 v1 假阴性死锁。
    emit(2, 8, "解锁加密库");
    let unlockResp;
    try {
      unlockResp = await withGradedTimeout(
        // ★ 企业级根治：后端 Channel 进度统一经 emit 单调递增闸门
        //
        // 原缺陷（Issue 1：进度条 100%→90% 回退）：
        //   此前直接透传 onProgress 给 verthysUnlock。后端 C DLL 在 MERKLE_DONE 阶段
        //   通过 Tauri Channel emit 100% 作为解锁最终进度，该 100% 直达 UI，
        //   完全绕过 emit 的 lastEmittedPercent 单调闸门（闸门只在 emit 调用时更新）。
        //   verthysUnlock 返回后 emit(7,90,"正在加载密钥配置…") 因 lastEmittedPercent
        //   仍为 0 → 推送 90% → 进度条从 100% 回退到 90%，用户看到"进度倒退"。
        //
        // 修复（双重）：
        //   1. 后端进度统一经 emit 闸门：lastEmittedPercent 据后端进度实时抬升，
        //      后续 emit(7,90) 被 Math.max(90, lastEmittedPercent) 钳制，永不回退
        //   2. 后端 0~100 映射到 8%~85% 区间，预留 86%~100% 给前端后处理阶段
        //      （摘要扫描 90% / 解锁完成 100%）。既消除回退，又避免后端提前触达
        //      100% 后前端长时间"卡在 100% 假完成"的错觉
        //
        // ★ 提示词精准映射：C DLL emit 的 p.message 不可控（可能英文/冗长），
        //   基于后端原始 p.percent 精准映射为精简高级文案（单一数据源）
        //   后端 C 层 percent 节点（core/src/api/verthys_v2_lifecycle.c）：
        //     5%  - 读取超级块
        //     10% - Argon2 派生开始（含心跳至 45%）
        //     50% - Argon2 完成 / 索引映射
        //     60% - B+树解密开始
        //     85% - B+树完成
        //     95% - 摘要完成
        //     100% - Merkle 校验完成
        //
        // 安全边界：verthys.ts 的 completed 标志已在 Promise resolve 后阻断 Channel
        //   残留消息，本包装仅负责进度数值的单调化与区间映射，不影响后端逻辑。
        verthysUnlock(verthysPath, VERTHYS_DEFAULT_PASSWORD, (p) => {
          const mapped = Math.min(85, 8 + Math.floor(p.percent * 0.77));
          emit(p.stage, mapped, pickUnlockChannelText(p.percent));
        }),
        UNLOCK_SOFT_TIMEOUT_MS,
        UNLOCK_HARD_TIMEOUT_MS,
        "verthys_unlock",
        () => {
          /* 软超时回调：Argon2id 派生耗时较长，提示用户耐心等待，不中断解锁 */
          emit(2, 30, "密钥运算中");
          log.warn("verthys_unlock 软超时（15s）：Argon2id 派生耗时较长，已提示用户耐心等待");
        },
      );
    } catch (e) {
      await resetKeyManagerState();
      return errFromUnknown(e, VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED);
    }
    if (!unlockResp.ok) {
      await resetKeyManagerState();
      return err(VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED, "打开加密库失败");
    }

    // 4. 消费进程内探测结果 — ★ 企业级根治
    //
    // worker 解锁成功后已进程内完成 has_record + find_lid + get_record，
    // 结果内联到 unlockResp 三字段。前端零 IPC 往返直接决策 UI 路径：
    //   has_global_key=true  + global_key_record → 显示"身份验证"，缓存 recordB64
    //   has_global_key=true  + 无 record        → 显示"身份验证"，verifyGlobalKey 按 id 自取
    //   has_global_key=false                   → 显示"初始化密钥"
    //   has_global_key=undefined（探测异常）    → 回退 findGlobalKeyRecord（单函数，非 IPC 链）
    setCurrentVerthysPath(verthysPath);

    if (unlockResp.has_global_key === true) {
      // 命中全局密钥记录
      keyState.hasGlobalKeyRecord.value = true;
      keyState.globalKeyRecordId.value = unlockResp.global_key_id ?? 0;
      if (unlockResp.global_key_record) {
        // record 读取成功 → 缓存 recordB64，verifyGlobalKey 直接读取（0ms）
        keyState.globalKeyRecordB64.value = unlockResp.global_key_record;
        log.info(`initUnlock: 进程内探测命中全局密钥记录 lid=${unlockResp.global_key_id}（record 已内联）`);
      } else {
        // 命中 lid 但 record 读取失败 → 清空缓存，verifyGlobalKey 按 id 自取
        keyState.globalKeyRecordB64.value = "";
        log.warn(`initUnlock: 进程内探测命中 lid=${unlockResp.global_key_id} 但 record 读取失败，verifyGlobalKey 将按 id 自取`);
      }
    } else if (unlockResp.has_global_key === false) {
      // 确认无全局密钥记录（v1/v2 全遍历确认）
      keyState.hasGlobalKeyRecord.value = false;
      log.info("initUnlock: 进程内探测确认无全局密钥记录");
    } else {
      // 探测异常（worker 未导出 Verthys_FindFirstLidByType 或意外错误）
      // 回退到 findGlobalKeyRecord（单函数调用，非多步 IPC 链，不会触发 loading 死锁）
      log.warn("initUnlock: 进程内探测异常（has_global_key undefined），回退 findGlobalKeyRecord");
      const existing = await findGlobalKeyRecord();
      keyState.hasGlobalKeyRecord.value = existing !== null;
      if (existing) {
        keyState.globalKeyRecordB64.value = existing.recordB64;
        keyState.globalKeyRecordId.value = existing.id;
      }
    }

    // globalKeyRecordLoading 永不设置为 true（进程内探测即时完成，无异步确认阶段）
    keyState.globalKeyRecordLoading.value = false;

    // ★ 解锁后关键路径 — 仅填充摘要缓存（模块密钥状态移至后台）
    //
    // 原缺陷（致命回归 + 卡慢）：
    //   1. 早期版本解锁后不调用 loadModuleKeyStatus → moduleKeyEnabled 保持默认值
    //      → "全部模块被自动开启密钥" / "原有密钥记录被遗忘"
    //   2. 后续修复将 loadModuleKeyStatus 放入关键路径同步 await（10s 超时兜底）
    //      → 阻塞 verthysReady=true → "正在加载密钥配置…时间太久"
    //
    // 当前处理：
    //   步骤 A（关键路径）：await ensureSummaryScan() — 填充摘要缓存
    //     为模块组件列表渲染提供 O(1) 索引，必须在 verthysReady=true 之前完成
    //   步骤 B（后台非阻塞）：loadModuleKeyStatus() — verthysReady=true 后后台执行
    //     - moduleKeyStatusLoading 标志供模块组件守卫
    //     - 乐观并发控制防止与用户开关操作竞态
    //     - 安全权衡：加载窗口内 moduleKeyEnabled 为安全默认 false，模块列表可见但
    //       加密项仍需独立密钥解密；用户刚通过全局密钥认证，风险可接受
    //
    // 时序保证：ensureSummaryScan 在 verthysReady=true 之前完成（列表渲染依赖）；
    //           loadModuleKeyStatus 在后台异步完成，状态响应式更新。
    emit(7, 90, "加载密钥配置");
    try {
      // ★ 企业级根治：摘要扫描超时兜底（10s），防止 IPC 挂起导致卡死
      await withTimeout(ensureSummaryScan(), 10000, "摘要扫描");
    } catch (e) {
      log.warn("initUnlock: 摘要扫描失败/超时（v1 格式或异常），模块加载将回退到全量扫描", e);
    }

    // ★★★ 企业级根治：TYPE 常量冲突数据迁移 ★★★
    //
    // 原缺陷（致命根因）：
    //   TYPE_GLOBAL_KEY (0x10) 与 TYPE_ACCOUNT (0x10) 值相同，已存储的 verthys
    //   文件中全局密钥记录与账户记录共享同一类型值，导致：
    //   - AccountVerthys 扫描 TYPE_ACCOUNT=0x10 误拾全局密钥记录 → "设置遗忘"
    //   - findGlobalKeyRecord 扫描 TYPE_GLOBAL_KEY=0x10 误拾账户记录 → "密钥验证无效"
    //   - 删除"垃圾账户"实际删除全局密钥 → "增删改异常/删除后复活"
    //   同理 TYPE_PHOTO_CHUNK (0x05) 与旧 TYPE_META (FileVerthys 0x05) 冲突。
    //
    // 修复（必须在 loadModuleKeyStatus 之前完成）：
    //   migrateRecordTypes 通过内容嗅探区分冲突类型的记录，将旧账户记录
    //   (0x10) 重写为 TYPE_ACCOUNT (0x02)，旧 FileVerthys 元数据 (0x05) 重写为
    //   TYPE_FILEVERTHYS_META (0x08)。全局密钥记录和照片块保持原类型不变。
    //
    // 幂等性：已迁移记录的新类型不会被再次扫描到，安全重复调用。
    // 性能：首次迁移 N 条 × 3 IPC；后续调用 O(1) 索引查询 <1ms。
    let migrationMigrated = 0;
    try {
      // ★ 企业级根治：整体超时兜底（15s），防止单条记录 IPC 挂起导致
      //   initUnlock 永远停在"正在加载密钥配置…"阶段。
      //   超时后继续加载（迁移幂等，下次解锁重试）
      const migrationResult = await withTimeout(
        migrateRecordTypes(),
        15000,
        "类型迁移",
      );
      migrationMigrated = migrationResult.migrated;
      if (migrationResult.migrated > 0) {
        log.info(`initUnlock: 类型迁移完成 — 迁移 ${migrationResult.migrated} 条，跳过 ${migrationResult.skipped} 条，错误 ${migrationResult.errors} 条`);
      }
    } catch (e) {
      log.error("initUnlock: 类型迁移异常/超时（非致命，继续加载，下次解锁重试）", e);
    }

    // ★★★ 企业级根治：迁移后重新校验缓存的全局密钥记录（消除 probe 竞态） ★★★
    //
    // 原缺陷（竞态根因）：
    //   worker 内联 probe 在 Verthys_Unlock 成功后立即调用
    //   Verthys_FindFirstLidByType(0x10) 搜索全局密钥记录（同 worker runtime.rs
    //   probe_global_key_inproc）。但类型迁移（migrateRecordTypes）在此之后
    //   才执行——如果 verthys 中存在旧账户记录（type=0x10，与 TYPE_GLOBAL_KEY
    //   冲突），probe 可能命中账户记录而非真正的全局密钥记录，将账户 JSON
    //   数据作为 global_key_record 缓存到 keyState.globalKeyRecordB64。
    //   后果：verifyGlobalKey 使用错误的缓存数据 → "原先的密钥验证完全无效"。
    //
    // 修复（迁移后重新校验，两个触发条件满足任一即重新探测）：
    //   条件 1：migrationMigrated > 0 — 有记录被迁移，旧 0x10 记录已重写为
    //           0x02，缓存的 lid 可能指向已删除的旧记录 → 缓存必然过期
    //   条件 2：isAccountRecordB64(cachedRecordB64) — 缓存值本身是账户记录
    //           （JSON 含 platform/username），说明 probe 命中了错误记录
    //           （兜底：即使迁移异常未执行，也能通过内容嗅探捕获错误缓存）
    //
    //   两种结果均需正确处理：
    //     - 找到真正的全局密钥 → 更新缓存（recordB64/Id），hasGlobalKeyRecord=true
    //     - 未找到（verthys 无全局密钥，probe 命中的是纯账户记录，迁移后已无 0x10）
    //       → hasGlobalKeyRecord=false（UI 应显示"初始化密钥"而非"身份验证"）
    const cachedRecordB64 = keyState.globalKeyRecordB64.value;
    const needRevalidate = migrationMigrated > 0 ||
      (cachedRecordB64.length > 0 && isAccountRecordB64(cachedRecordB64));
    if (needRevalidate) {
      log.info("initUnlock: 迁移后重新校验全局密钥记录（消除 probe 竞态）");
      // ★ 企业级根治：超时兜底（5s），防止 findGlobalKeyRecord 的 IPC 挂起
      let revalidated: { id: number; recordB64: string } | null = null;
      try {
        revalidated = await withTimeout(
          findGlobalKeyRecord(),
          5000,
          "全局密钥重新校验",
        );
      } catch (e) {
        log.warn("initUnlock: 全局密钥重新校验超时/异常（保留 unlock 响应缓存值）", e);
      }
      if (revalidated) {
        keyState.globalKeyRecordB64.value = revalidated.recordB64;
        keyState.globalKeyRecordId.value = revalidated.id;
        keyState.hasGlobalKeyRecord.value = true;
        log.info(`initUnlock: 重新校验命中全局密钥记录 lid=${revalidated.id}`);
      } else {
        // probe 命中的是旧账户记录，迁移后已无 0x10 记录 → 无全局密钥
        keyState.hasGlobalKeyRecord.value = false;
        keyState.globalKeyRecordB64.value = "";
        keyState.globalKeyRecordId.value = 0;
        log.info("initUnlock: 重新校验确认无全局密钥记录（probe 此前误拾账户记录）");
      }
    }

    // ★★★ 企业级根治：同步后端 key_lifecycle 状态（消除前后端状态不同步） ★★★
    //
    // 原缺陷（致命根因）：
    //   verthys_unlock 时 worker 进程内 probe 通过 find_first_lid_by_type(0x10)
    //   搜索全局密钥记录，后端 key_lifecycle 据 probe 结果设为 Locked 或 NoKey。
    //   但 TYPE_GLOBAL_KEY(0x10) 与旧 TYPE_ACCOUNT(0x10) 冲突，probe 可能误判。
    //
    //   前端 migrateRecordTypes + 重新校验得到正确结果后，仅更新了前端
    //   keyState.hasGlobalKeyRecord，未同步后端 key_lifecycle → 状态不同步：
    //     - 前端 false + 后端 Locked → UI 显示"初始化密钥"但 derive 要求 NoKey → 失败
    //     - 前端 true  + 后端 NoKey   → UI 显示"身份验证"但 verify 要求 Locked → 失败
    //
    // 根治：
    //   将前端重新校验的最终结果同步到后端 key_lifecycle 状态机。
    //   verthys_reconcile_key_presence 在 NoKey↔Locked 之间安全转换（幂等）。
    //
    // 安全边界：
    //   - 不涉及密钥材料，不接触 worker，仅修正状态机
    //   - verthysReady=true 之前调用，此时 UI 未渲染，无用户交互竞态
    //   - 幂等：状态已匹配时后端无操作
    try {
      await verthysReconcileKeyPresence(keyState.hasGlobalKeyRecord.value);
      log.info(`initUnlock: 后端 key_lifecycle 已同步（hasGlobalKeyRecord=${keyState.hasGlobalKeyRecord.value}）`);
    } catch (e) {
      log.warn("initUnlock: 后端 key_lifecycle 同步失败（非致命，可能影响派生/验证）", e);
    }

    // ★★★ 安全守卫修复：loadModuleKeyStatus 必须在 verthysReady=true 之前完成 ★★★
    //
    // 原缺陷（致命安全漏洞）：
    //   此前将 loadModuleKeyStatus 放到 verthysReady=true 之后的「后台非阻塞」执行。
    //   由于 keyState.moduleKeyEnabled 默认 false，后台加载未完成期间，
    //   useModuleNavigation.switchModule 守卫读 isModuleKeyEnabled → 返回 false →
    //   误判「保护已关闭」→ 直接放行进入模块并加载内容，绕过模块独立密钥验证。
    //   待后台加载完成（或用户切走再切回）才弹密钥框——与用户反馈完全吻合。
    //
    // 根治：
    //   loadModuleKeyStatus 移回关键路径，在 verthysReady=true 之前同步完成。
    //   此时 ensureSummaryScan 已就绪（558 行），loadModuleKeyStatus 内部用
    //   getSummaryIdsByType O(1) 查询 + ≤8 次 verthysGetRecord（模块密钥/config 记录），
    //   正常 <100ms，2s 超时兜底（非致命，失败用安全默认 false + switchModule 防御守卫兜底）。
    //   与 moduleKeyStatusVersion 乐观并发安全：关键路径 verthysReady=false，UI 不渲染，
    //   用户无法触发 setModuleKeyEnabled/setModuleKey，startVersion===current 必然成立。
    //
    // 模块内容即时预加载（修复5保留）：verthysReady=true 后立即后台启动 ensureRecordScan，
    //   静默填充全量记录扫描缓存（含 dataB64，最多 64KB/条），用户进入模块时零 IPC 读取。
    keyState.moduleKeyStatusLoading.value = true;
    // ★ 安全守卫根治：loadModuleKeyStatus 在 verthysReady=true 之前同步完成
    //
    // 原缺陷：withTimeout 2s 超时后 catch 块重置 moduleKeyStatusLoading=false，
    // 但 loadModuleKeyStatus 的 Promise 仍在后台继续执行（v1 全量扫描 25s）。
    // 守卫检查 moduleKeyStatusLoading=false → 跳过等待 → isModuleKeyEnabled 返回默认
    // false → 直接放行，绕过模块独立密钥验证。
    //
    // 根治：
    //   1. loadModuleKeyStatusFallback 已改用 verthysEnumerateRecords（v1 内存路径 1-3s），
    //      整体 loadModuleKeyStatus <3s，8s 超时兜底足够覆盖
    //   2. 超时后不重置 moduleKeyStatusLoading——让 loadModuleKeyStatus 内部完成时
    //      自己设 false（module-auth.ts 第378/370/389行三处完成点均会重置）。
    //      超时窗口内 moduleKeyStatusLoaded 保持 false，switchModule 守卫据此拦截
    //   3. 被抛弃的 Promise 用 .catch 吞掉 unhandled rejection
    const lmkPromise = loadModuleKeyStatus();
    try {
      await withTimeout(lmkPromise, 8000, "模块密钥状态加载");
    } catch (e) {
      // ★ 不重置 moduleKeyStatusLoading：让 lmkPromise 内部完成时自己设 false
      //   超时窗口内 moduleKeyStatusLoaded=false，switchModule 守卫拦截业务模块（安全兜底）
      log.warn("initUnlock: 模块密钥状态加载超时/失败（moduleKeyStatusLoading 保持 true 由内部重置；moduleKeyStatusLoaded=false 守卫拦截）", e);
      // 吞掉被抛弃 Promise 的 unhandled rejection（lmkPromise 内部已有 try/catch，此为防御性兜底）
      lmkPromise.catch(() => { /* loadModuleKeyStatus 内部已处理 moduleKeyStatusLoading/moduleKeyStatusLoaded */ });
    }

    emit(8, 100, "解锁完成");
    keyState.verthysReady.value = true;

    // ★ 性能根治：移除 verthysReady 后立即 ensureRecordScan（消除 worker 队头阻塞）
    //
    // 原缺陷：
    //   verthysReady=true 后立即启动 ensureRecordScan()（非阻塞）+ startBackgroundTasks()
    //   （2.5s 延迟后启动 Merkle 重建 / ensureRecordScan / prefetchFullRecords / integrityPatrol）。
    //   后台任务的 IPC 请求与前端模块加载请求共用同一 worker 通道，
    //   后台任务独占 worker 时前端请求排队等待 → 30s 卡顿。
    //
    // 修复：
    //   1. loadModuleKeyStatus（关键路径已调用）通过 ensureRecordScan 填充 recordScanCache
    //   2. 模块组件挂载时调用 ensureRecordScanSafe() 复用已填充的缓存（scanInProgress 去重，零 IPC）
    //   3. startBackgroundTasks 延迟 12s 启动 + yieldIfFrontendBusy 让出 worker 通道
    //   4. 移除此处的 ensureRecordScan 调用，避免 verthysReady 后立即发起全量扫描 IPC

    // 启动后台任务（Merkle 重建 / 完整性巡检 / 可见区域预加载）
    startBackgroundTasks().catch(() => { /* 后台任务失败不影响解锁 */ });
    log.info("解锁成功");
    return ok(undefined);
  } catch (e) {
    log.error("initUnlock 未捕获异常", e);
    await resetKeyManagerState();
    return errFromUnknown(e, VerthysErrorCode.E_INIT_FAILED);
  }
}

/**
 * 智能初始化：自动判断创建或解锁
 * 基于路径预检的 file_exists 字段决定调用 initCreate 或 initUnlock
 *
 * ★ 返回 VerthysResult<void>
 */
export async function initAndUnlock(verthysPath: string): Promise<VerthysResult<void>> {
  try {
    const preflight = await withTimeout(verthysPreflight(verthysPath), 5000, "路径预检");
    if (!preflight.ok) {
      await resetKeyManagerState();
      return err(VerthysErrorCode.E_PATH_INVALID, "路径不可用，请检查权限或磁盘空间");
    }
    if (preflight.file_exists) {
      return initUnlock(verthysPath, preflight);
    } else {
      return initCreate(verthysPath, preflight);
    }
  } catch (e) {
    log.error("initAndUnlock 路径预检异常", e);
    await resetKeyManagerState();
    return errFromUnknown(e, VerthysErrorCode.E_INIT_FAILED);
  }
}

/* ------------------------------------------------------------------ *
 * 全局根密钥 CRUD                                                     *
 * ------------------------------------------------------------------ */

/**
 * 初始化全局安全密钥（首次设置）
 * GMK 派生在 worker 子进程内完成，前端仅传递参数并持久化 record
 *
 * ★ 返回 VerthysResult<void>
 * ★ 移除自动 setDeviceBinding，由调用方显式调用 bindDevice()
 * ★ 使用 flushVerthysAsync(false) 不阻塞 UI
 *
 * @param globalPassword 全局访问密钥
 * @param binBytes .bin 密钥文件原始字节
 * @param binPassword .bin 文件密码
 * @returns VerthysResult<void>
 */
export async function initGlobalKey(
  globalPassword: string,
  binBytes: Uint8Array,
  binPassword: string
): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_VERTHYS_NOT_READY, "verthys 未解锁");
  }

  // 1. 调用 worker 派生 GMK
  const binDataB64 = bytesToBase64(binBytes);
  let recordB64: string | null;
  try {
    recordB64 = await withTimeout(
      verthysDeriveGlobalKey(globalPassword, binDataB64, binPassword),
      INIT_TIMEOUT_MS,
      "derive_global_key"
    );
  } catch (e) {
    return errFromUnknown(e, VerthysErrorCode.E_GLOBAL_KEY_DERIVE_FAILED);
  }
  if (!recordB64) {
    return err(VerthysErrorCode.E_GLOBAL_KEY_DERIVE_FAILED, "worker 派生全局密钥失败");
  }

  // 2. 持久化 record 到 verthys
  const id = await verthysAddRecord(TYPE_GLOBAL_KEY, "global-key", recordB64);
  if (id === null) {
    return err(VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED, "写入 verthys 失败");
  }

  // ★ 企业级根治修复：await persistVerthys 替代 flushVerthysAsync(false)（根治全局密钥丢失）
  //
  // 原缺陷：flushVerthysAsync(false) 内部为 void persistVerthys() 火并忘，
  // 全局密钥记录写入 worker 内存后不等待落盘。
  // 若用户快速退出或应用崩溃，flush 未完成 → 磁盘无全局密钥记录 →
  // 下次解锁进程内探测 has_global_key=false → 显示"初始化密钥"而非"身份验证"。
  // 用户反馈"原先的密钥验证完全无效"。
  //
  // 修复：await persistVerthys() 确保全局密钥记录落盘完成后再返回成功。
  // 全局密钥是核心安全数据，必须保证持久化，await 的延迟（通常 <2s）可接受。
  const flushOk = await persistVerthys();
  if (!flushOk) {
    log.error("initGlobalKey: 全局密钥记录落盘失败");
    return err(VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED, "全局密钥落盘失败，请重试");
  }

  // 3. 内存状态更新（数据已确认落盘）
  keyState.globalKeyReady.value = true;
  keyState.hasGlobalKeyRecord.value = true;
  // ★ 缓存 recordB64 和 id，供后续 verifyGlobalKey 直接读取（跳过 findGlobalKeyRecord 扫描）
  keyState.globalKeyRecordB64.value = recordB64;
  keyState.globalKeyRecordId.value = id;
  resetSessionTimer();

  // ★ 移除自动 setDeviceBinding
  // 设备绑定由调用方（SecurityCenter.vue）在初始化成功后显式调用 bindDevice()

  log.info("全局密钥初始化成功");
  return ok(undefined);
}

/**
 * 修改全局密钥（需先验证旧密钥）
 *
 * 写入顺序：先派生新 GMK + 写入新记录，成功后再删除旧记录（先添后删）。
 *
 * ★ 返回 VerthysResult<void>
 * ★ 使用 flushVerthysNow() 强制同步落盘（全局密钥是核心数据）
 *
 * @returns VerthysResult<void>
 */
export async function changeGlobalKey(
  oldPassword: string,
  oldBinBytes: Uint8Array,
  oldBinPassword: string,
  newPassword: string,
  newBinBytes: Uint8Array,
  newBinPassword: string
): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_VERTHYS_NOT_READY, "verthys 未解锁");
  }

  // 1. 先验证旧密钥
  const verifyResult = await verifyGlobalKey(oldPassword, oldBinBytes, oldBinPassword);
  if (!verifyResult.ok) {
    return err(VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED, "旧全局密钥验证失败");
  }

  // 2. 查找旧记录
  const oldRecord = await findGlobalKeyRecord();

  // 3. 派生新 GMK
  const newBinDataB64 = bytesToBase64(newBinBytes);
  let newRecordB64: string | null;
  try {
    newRecordB64 = await withTimeout(
      verthysDeriveGlobalKey(newPassword, newBinDataB64, newBinPassword),
      INIT_TIMEOUT_MS,
      "derive_global_key_change"
    );
  } catch (e) {
    return errFromUnknown(e, VerthysErrorCode.E_GLOBAL_KEY_DERIVE_FAILED);
  }
  if (!newRecordB64) {
    return err(VerthysErrorCode.E_GLOBAL_KEY_DERIVE_FAILED, "worker 派生新全局密钥失败");
  }

  // 4. 写入新记录
  const newId = await verthysAddRecord(TYPE_GLOBAL_KEY, "global-key", newRecordB64);
  if (newId === null) {
    return err(VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED, "写入新全局密钥记录失败");
  }

  // 5. 删除旧记录（先添后删）
  if (oldRecord) {
    await verthysDeleteRecord(oldRecord.id);
  }

  // ★ flushVerthysNow 强制同步落盘（关键路径）
  // 全局密钥是核心数据，必须确保落盘成功
  const flushResult = await flushVerthysNow();
  if (!flushResult.ok) {
    log.error("全局密钥落盘失败", flushResult.message);
    return err(VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED, "全局密钥落盘失败，请重试");
  }

  // 7. 状态更新
  keyState.globalKeyReady.value = true;
  keyState.hasGlobalKeyRecord.value = true;
  resetSessionTimer();
  log.info("全局密钥修改成功");
  return ok(undefined);
}

/**
 * 验证全局密钥（后续进入时）
 * GMK 验证在 worker 子进程内完成，前端仅传递参数和 record
 *
 * ★ 返回 VerthysResult<void>
 *
 * @returns VerthysResult<void>
 *   - ok：验证成功
 *   - err(E_VERTHYS_NOT_READY)：verthys 未解锁
 *   - err(E_GLOBAL_KEY_RECORD_NOT_FOUND)：未找到全局密钥记录
 *   - err(E_GLOBAL_KEY_VERIFY_FAILED)：密钥/文件/密码错误
 */
export async function verifyGlobalKey(
  globalPassword: string,
  binBytes: Uint8Array,
  binPassword: string,
  onProgress?: (progress: UnlockProgress) => void,
): Promise<VerthysResult<void>> {
  // ★ 修复4：GMK 验证全流程进度反馈，消除用户面对空白动画 40s 的体验
  const t0 = Date.now();
  const emit = (stage: number, percent: number, message: string) => {
    if (onProgress) {
      onProgress({
        stage,
        percent,
        elapsed_ms: Date.now() - t0,
        message,
      });
    }
  };

  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_VERTHYS_NOT_READY, "verthys 未解锁");
  }

  // ★ 修复2：优先读取 initUnlock 阶段缓存的 recordB64，跳过重复扫描
  //   缓存未命中时回退到 findGlobalKeyRecord（带 10s 超时保护）
  emit(1, 10, "定位密钥记录");
  let recordB64: string;
  if (keyState.globalKeyRecordB64.value) {
    // 缓存命中：0ms 直接读取（initUnlock 已扫描过）
    recordB64 = keyState.globalKeyRecordB64.value;
    log.info("verifyGlobalKey: 缓存命中，跳过 findGlobalKeyRecord 扫描");
  } else {
    // 缓存未命中：回退到扫描（带超时保护）
    emit(2, 15, "扫描密钥记录");
    let found: { id: number; recordB64: string } | null = null;
    try {
      found = await withTimeout(findGlobalKeyRecord(), 10000, "findGlobalKeyRecord");
    } catch (e) {
      log.warn("findGlobalKeyRecord 超时或失败", e);
      found = null;
    }
    if (!found) {
      return err(VerthysErrorCode.E_GLOBAL_KEY_RECORD_NOT_FOUND, "未找到全局密钥记录");
    }
    recordB64 = found.recordB64;
    // 回填缓存，下次验证可直接命中
    keyState.globalKeyRecordB64.value = found.recordB64;
    keyState.globalKeyRecordId.value = found.id;
  }

  // ★ 修复4：验证阶段进度反馈
  emit(3, 40, "验证量子签名");
  const binDataB64 = bytesToBase64(binBytes);
  let verifyOk: boolean;
  try {
    verifyOk = await withTimeout(
      verthysVerifyGlobalKey(globalPassword, binDataB64, binPassword, recordB64),
      INIT_TIMEOUT_MS,
      "verify_global_key"
    );
  } catch (e) {
    return errFromUnknown(e, VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED);
  }
  if (!verifyOk) {
    return err(VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED, "全局密钥验证失败");
  }

  emit(4, 80, "激活安全会话");

  // 内存状态更新
  keyState.globalKeyReady.value = true;
  // ★ 企业级根治：移除冗余 loadModuleKeyStatus 调用（根治"正在初始化安全会话"卡慢）
  //
  // 原缺陷：verifyGlobalKey 中 await loadModuleKeyStatus() 是冗余调用——
  //   initUnlock 已在解锁关键路径（verthysReady=true 之前）调用过 loadModuleKeyStatus，
  //   模块密钥状态已加载完毕。此处重复调用会再次触发 ensureSummaryScan +
  //   verthysGetRecord 链路，在摘要缓存未命中时回退全量扫描 → 20-30s 卡顿。
  //   用户反馈"正在初始化安全会话…时间太久"。
  //
  // 修复：移除此冗余调用。initUnlock 已确保状态就绪，此处无需重载。
  //   若用户在解锁后修改了模块密钥（setModuleKeyEnabled），状态已由该函数
  //   原子更新（await persistVerthys → 更新 keyState.moduleKeyEnabled），无需重载。
  resetSessionTimer();
  // 启动会话守卫（★ 加超时兜底 5s，防止 IPC 挂起卡死）
  try {
    await withTimeout(securitySessionStart(), 5000, "securitySessionStart");
  } catch (e) {
    log.warn("启动会话守卫失败/超时（非致命）", e);
  }
  // 应用当前安全预设（★ 加超时兜底 5s）
  try {
    await withTimeout(applySecurityPreset(keyState.securityPreset.value), 5000, "applySecurityPreset");
  } catch (e) {
    log.warn("应用安全预设失败/超时（非致命）", e);
  }
  emit(8, 100, "验证完成");
  return ok(undefined);
}

/**
 * 带暴力拦截门禁的全局密钥验证
 *
 * ★ 计数职责已上移服务端：verify_global_key 命令在服务端入口强制
 *   熔断闸门并权威计数（仅认证域错误计失败、成功即重置）。本函数
 *   不再调用计数接口，仅在验证前预检与验证后查询锁定态映射给 UI，
 *   避免同一失败被前后端各计一次。
 *
 * ★ 保留现有 VerifyGlobalKeyResult 判别联合返回类型（已有 reason 机制）
 *   内部调用 verifyGlobalKey（VerthysResult 版本）
 *
 * @returns VerifyGlobalKeyResult
 */
export async function verifyGlobalKeyWithBruteForce(
  globalPassword: string,
  binBytes: Uint8Array,
  binPassword: string,
  onProgress?: (progress: UnlockProgress) => void,
): Promise<VerifyGlobalKeyResult> {
  // 1. 暴力拦截门禁预检（纯查询，不计数）：提前拦截以避免无效的
  //    验证运算与 UI 等待；强制力由服务端入口闸门保证
  const gate = await checkBruteForceGate();
  if (!gate.allowed) {
    if (gate.reason === "locked") {
      return { ok: false, reason: "gate_locked", remainingSecs: gate.remainingSecs };
    }
    return { ok: false, reason: "gate_purge_required" };
  }

  // 2. 实际验证（★ 修复4：透传 onProgress 进度回调）
  const result = await verifyGlobalKey(globalPassword, binBytes, binPassword, onProgress);
  if (result.ok) {
    return { ok: true };
  }

  // 3. 失败后查询服务端计数结果（纯查询，不计数）：将锁定/清空态
  //    映射给 UI 展示；查询失败不影响既有错误语义
  try {
    const r: BruteForceCheckResponse = await securityBruteCheck();
    if (r.kind === "Locked") {
      return { ok: false, reason: "locked", remainingSecs: r.remaining_secs };
    }
    if (r.kind === "PurgeRequired") {
      return { ok: false, reason: "purge_required" };
    }
  } catch { /* 查询失败按普通失败处理 */ }
  return { ok: false, reason: "wrong_key" };
}

/* ------------------------------------------------------------------ *
 * 设备机器码绑定与校验                                                 *
 * ------------------------------------------------------------------ */

/**
 * ★ 绑定当前设备机器码（独立可控）
 *
 * 从 initGlobalKey 中移除，由调用方决定是否绑定。
 * 绑定失败返回明确错误码，UI 层可展示提示并允许用户重试。
 *
 * @param force 是否强制重新绑定（已绑定时也覆盖）
 * @returns VerthysResult<void>
 *   - ok：绑定成功
 *   - err(E_VERTHYS_NOT_READY)：verthys 未解锁
 *   - err(E_DEVICE_BIND_FAILED)：绑定失败，UI 可提示用户重试
 */
export async function bindDevice(force: boolean = false): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_VERTHYS_NOT_READY, "verthys 未解锁");
  }
  try {
    // force=true 时 setDeviceBinding 内部覆盖旧绑定
    // force=false 时若已绑定则覆盖（setDeviceBinding 始终写入最新机器码）
    await setDeviceBinding();
    log.info(force ? "设备已强制重新绑定" : "设备绑定成功");
    return ok(undefined);
  } catch (e) {
    const ve = wrapAsVerthysError(e);
    log.error("设备绑定失败", e);
    return err(VerthysErrorCode.E_DEVICE_BIND_FAILED, `设备绑定失败: ${ve.message}`, ve);
  }
}

/**
 * 校验当前设备是否与已绑定机器码匹配
 *
 * ★ 返回 VerthysResult<"match"|"mismatch"|"unbound">
 *
 * ★ 企业级根治修复：后端 check_device_binding 返回 DeviceBindingResult 结构体
 *   （{status, detail, error_code?, match_score?}），原实现直接把对象当字符串
 *   包装进 ok() 返回，导致 deviceCheckResult 被赋值为对象 →
 *   useViewMode 的 === 'mismatch' 字符串比较永远为 false →
 *   device_mismatch 拦截视图永久失效（安全功能失守）。
 *
 *   现基于后端结构化 status 字段显式映射为前端联合类型：
 *     - "match"         → ok("match")     完全匹配
 *     - "partial_match" → ok("match")     部分匹配（权重 ≥80%，允许有限恢复）
 *     - "mismatch"      → ok("mismatch")  不匹配（触发拦截视图）
 *     - "unbound"       → ok("unbound")   未绑定（首次运行）
 *     - "error"         → err(E_DEVICE_BINDING) 校验出错（不阻断主流程）
 *
 * @returns VerthysResult
 *   - ok("match")：设备匹配（含部分匹配有限恢复）
 *   - ok("mismatch")：设备不匹配
 *   - ok("unbound")：未绑定
 *   - err(E_DEVICE_BINDING)：校验异常
 */
export async function verifyDeviceBinding(): Promise<VerthysResult<"match" | "mismatch" | "unbound">> {
  try {
    const result = await checkDeviceBinding();
    switch (result.status) {
      case "match":
        return ok("match");
      case "partial_match":
        // 后端权重匹配 ≥80%（MATCH_THRESHOLD_PERCENT）判定为部分匹配：
        // 允许有限恢复进入管理界面，记录审计日志便于追溯硬件变更
        log.warn(
          `设备部分匹配（${result.match_score ?? "?"}%），允许有限恢复：${result.detail}`,
        );
        return ok("match");
      case "mismatch":
        return ok("mismatch");
      case "unbound":
        return ok("unbound");
      case "error":
        log.error("设备校验出错:", result.detail, result.error_code ?? "");
        return err(
          VerthysErrorCode.E_DEVICE_BINDING,
          result.detail || "设备校验出错",
        );
      default: {
        // 防御性兜底：后端新增枚举值时按校验异常处理（fail-safe，不误放行）
        const exhaustive: never = result.status;
        log.error("未知设备绑定状态:", exhaustive);
        return err(VerthysErrorCode.E_DEVICE_BINDING, "未知设备绑定状态");
      }
    }
  } catch (e) {
    log.error("设备校验失败", e);
    return err(VerthysErrorCode.E_DEVICE_BINDING, `设备校验失败: ${wrapAsVerthysError(e).message}`, e);
  }
}

/** 获取当前设备机器码（SHA-256 hex 前 16 位，用于 UI 显示） */
export async function getDeviceFingerprintShort(): Promise<string> {
  try {
    const fp = await getDeviceFingerprint();
    return fp.substring(0, 16).toUpperCase();
  } catch {
    return "未知";
  }
}

/* ------------------------------------------------------------------ *
 * .bin 文件读取                                                       *
 * ------------------------------------------------------------------ */

/**
 * 读取 .bin 文件字节（通过 Tauri 后端读取本地文件，二进制 IPC 直传）
 */
export async function readBinFile(path: string): Promise<Uint8Array | null> {
  try {
    return await readUserFile(path);
  } catch {
    return null;
  }
}
