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
  verthysDeriveGlobalKey, verthysDeriveAndStoreGlobalKey,
  verthysVerifyGlobalKey, verthysClearGlobalKey,
  verthysResetGlobalKeyState, verthysReconcileKeyPresence,
  verthysGetRecord, verthysEnumerateRecords,
  verthysScanSummaryOpen, verthysScanSummaryNext, verthysScanSummaryClose,
  bytesToBase64, readUserFile,
  setDeviceBinding, checkDeviceBinding, getDeviceFingerprint,
  securityBruteCheck, getWorkerInitFailure,
  securitySessionStart, securitySessionStop,
  type PreflightResult, type InitStatusResult,
  type BruteForceCheckResponse,
  type UnlockProgress,
} from "../lib/verthys";

// 再导出 Worker 预启动接口，供 SecurityCenter 等上层组件使用
export { preloadWorker, invalidateWorkerPreload } from "../lib/verthys";
import { keyState, setCurrentVerthysPath, resetAllState } from "../state/key_state";
import { TYPE_GLOBAL_KEY, INIT_TIMEOUT_MS, CREATE_TIMEOUT_MS, UNLOCK_SOFT_TIMEOUT_MS, UNLOCK_HARD_TIMEOUT_MS } from "../constants/key_manager_const";
import { withTimeout, withGradedTimeout } from "../utils/promise_utils";
import { isTauriEnvironment } from "../utils/tauri_env";
import {
  persistVerthys, clearModuleKeyCache, clearRecordScanCache, resetFlushChain,
  clearSummaryCache, clearFullRecordCache,
  findLidByTypeEarlyStop,
  flushVerthysNow,
  ensureSummaryScan,
} from "../cache/composition/verthys-cache";
// 后台任务 API 直连 core 层（单向化：不再转发 start/stop）
import { startBackgroundTasks, stopBackgroundTasks } from "../core/background-tasks";
import {
  ok, err, errFromUnknown,
  VerthysErrorCode, type VerthysResult,
  wrapAsVerthysError, gateErrorResult,
} from "../lib/verthys_error";
import { resetSessionTimer, clearSessionTimer, checkBruteForceGate, awaitLockAllIfInProgress, securityHardeningFailedRef } from "../session/security-session";
import type { VerifyGlobalKeyResult } from "../types/key_manager";
import { loadModuleKeyStatus } from "./module-auth";
import { migrateRecordTypes, isAccountRecordB64 } from "./type-migration";
import { createLogger } from "../utils/logger";

const log = createLogger("global-verthys");

/**
 * 启动系统会话守卫（锁屏/挂起/显示器关闭锁定）。
 *
 * 任何成功建立会话（新建或解锁）都必须调用；不能只在全局密钥验证
 * 路径调用，否则无全局密钥的库在解锁后不会接线下发挂起守卫位，
 * 防御面板会如实显示「挂起绕过 · 降级（挂起看门狗未启用）」。
 * 守卫启动失败时置位 hardening 降级标志并继续，不阻断解锁。
 */
async function startSessionGuard(): Promise<void> {
  try {
    await withTimeout(securitySessionStart(), 5000, "securitySessionStart");
    securityHardeningFailedRef.value = false;
  } catch (e) {
    securityHardeningFailedRef.value = true;
    log.warn("启动会话守卫失败/超时（非致命）", e);
  }
}

/* ------------------------------------------------------------------ *
 * 内部工具                                                            *
 * ------------------------------------------------------------------ */

/** 在 verthys 中查找全局密钥记录
 *  返回 { id, recordB64 } — 不解析内部结构，由 worker 验证
 *
 *  两级查找，关键路径不做全量解密：
 *    1. findLidByTypeEarlyStop 按类型索引直达目标记录（O(1)）；
 *    2. 索引异常或无结果时回退 verthysEnumerateRecords（单次 IPC）。
 *
 *  全量扫描（ensureRecordScan）由 startBackgroundTasks 后台执行，不阻塞关键路径。
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

  // 路径 2：v1 回退路径 — verthysEnumerateRecords（单次 IPC）
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
 * 解锁响应内联全局密钥探测结果                                        *
 *                                                                    *
 * worker 在 Verthys_V4Unlock 成功分支进程内一次性完成                 *
 *   has_record(Verthys_FindFirstLidByType) + get_record(Verthys_GetRecord)，*
 * 结果内联到 unlock 响应的 has_global_key / global_key_id /           *
 * global_key_record 三字段。initUnlock 直接消费，零 IPC 往返。         *
 *                                                                    *
 * globalKeyRecordLoading 恒为 false（探测即时完成，无异步确认阶段）。 *
 * findGlobalKeyRecord 保留，仅供 initCreate / changeGlobalKey /       *
 * verifyGlobalKey 缓存未命中回退使用（单函数调用，非多步 IPC 链路）。 *
 * ------------------------------------------------------------------ */

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
async function resetKeyManagerState(): Promise<void> {
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
 * 首次创建加密库（严格遵循「先落地、后状态」原则）
 *
 * 返回 VerthysResult<void>，携带结构化错误码
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
 * @returns VerthysResult<string>：成功值为一次性恢复码，调用方展示确认后必须丢弃
 */
export async function initCreate(
  verthysPath: string,
  preflightResult?: PreflightResult,
  onProgress?: (progress: UnlockProgress) => void,
  keyfilePath?: string,
): Promise<VerthysResult<string>> {
  // 进度反馈：与 initUnlock 一致的 emit 单调递增闸门，在各阶段推送进度。
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
    // 创建前必须确保 worker 处于干净状态，否则 ensureWorkerReady 会复用
    // 旧 workerReadyPromise，IPC 发往正在被 lockAll 销毁的 worker 而永久卡死。
    //
    // 双重防护：
    //   1. awaitLockAllIfInProgress：等待正在进行的 lockAll 真正完成
    //      （不设提前返回，各破坏性步骤自带超时）
    //      确保 worker 销毁、缓存清空、状态重置全部落地
    //   2. ensureCleanWorkerState：兜底清理 — 即使 lockAll 超时未完成，
    //      若 workerHasBeenUsed=true 且预启动缓存残留，强制销毁旧 worker
    /* 用户态只呈现 4 个核心节点：准备 → 创建 → 索引/密钥 → 守卫；
     * 其余内部步骤仍以 log.info 完整留痕，节点之间由进度感知层连续推进 */
    emit(0, 1, "准备安全环境");
    await awaitLockAllIfInProgress();
    await ensureCleanWorkerState();

    // 1. 路径预检
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
      /* 安全状态目录预检失败给出专用码与修复指引；其余启动失败保持原语义。 */
      const failure = getWorkerInitFailure();
      if (failure?.code === VerthysErrorCode.E_SECURITY_STATE) {
        return err(
          VerthysErrorCode.E_SECURITY_STATE,
          failure.message || "无法加固安全状态目录：请将用户数据放在本地 NTFS 目录，或联系管理员完成目录预检",
        );
      }
      return err(VerthysErrorCode.E_WORKER_INIT_FAILED, "安全核心启动失败");
    }

    // 3. verthys_create（容器 + 一次性恢复码）
    emit(1, 10, "创建加密库");
    log.info("步骤 3/4：创建加密库并写盘");
    let recoveryCode: string;
    try {
      const createResp = await withTimeout(
        verthysCreate(verthysPath, undefined, keyfilePath),
        CREATE_TIMEOUT_MS,
        "verthys_create",
      );
      if (!createResp.ok) {
        await resetKeyManagerState();
        return err(
          VerthysErrorCode.E_VERTHYS_CREATE_FAILED,
          createResp.error ?? "创建加密库失败",
        );
      }
      /* 恢复码只在本响应内存在；缺失即 fail-closed，禁止创建出无法恢复的库。 */
      if (!createResp.recovery_code) {
        await resetKeyManagerState();
        return err(
          VerthysErrorCode.E_VERTHYS_CREATE_FAILED,
          "创建响应缺少一次性恢复码",
        );
      }
      recoveryCode = createResp.recovery_code;
    } catch (e) {
      await resetKeyManagerState();
      return errFromUnknown(e, VerthysErrorCode.E_VERTHYS_CREATE_FAILED);
    }

    // 4. 检查全局密钥记录 + 更新状态
    emit(2, 70, "建立索引与加载密钥");
    log.info("步骤 4/4：检查全局密钥记录");
    setCurrentVerthysPath(verthysPath);
    const existing = await findGlobalKeyRecord();
    keyState.hasGlobalKeyRecord.value = existing !== null;

    // 同步后端 key_lifecycle 状态（与 initUnlock 一致）
    //
    // verthys_create 通过 raw worker IPC 完成 create→lock→unlock，
    // 绕过了 verthys_unlock Tauri 命令的 key_lifecycle 状态管理代码。
    // 新建 verthys 无全局密钥记录，后端状态必须显式收敛为 NoKey；
    // 否则残留上次会话的 Locked/Unlocked 状态会导致 derive/verify 失败。
    try {
      await verthysReconcileKeyPresence(keyState.hasGlobalKeyRecord.value);
      log.info(`initCreate: 后端 key_lifecycle 已同步（hasGlobalKeyRecord=${keyState.hasGlobalKeyRecord.value}）`);
    } catch (e) {
      log.warn("initCreate: 后端 key_lifecycle 同步失败（非致命，可能影响派生/验证）", e);
    }

    // 与 initUnlock 一致：始终填充摘要缓存并加载模块密钥状态（即使为空也写入默认值）。
    //
    // 若仅在存在全局密钥记录时才调用 loadModuleKeyStatus，
    // 新建库的 moduleKeyEnabled/hasModuleKeyRecord 会停留在初始默认值。
    try {
      await ensureSummaryScan();
    } catch (e) {
      log.warn("initCreate: 摘要扫描失败（非致命）", e);
    }
    try {
      await loadModuleKeyStatus();
    } catch (e) {
      log.warn("initCreate: 加载模块密钥状态失败（非致命）", e);
    }

    emit(3, 99, "启动会话守卫");
    keyState.verthysReady.value = true;
    await startSessionGuard();
    emit(4, 100, "创建完成");
    startBackgroundTasks().catch(() => { /* 后台任务失败不影响创建 */ });
    log.info("创建成功");
    return ok(recoveryCode);
  } catch (e) {
    log.error("initCreate 未捕获异常", e);
    await resetKeyManagerState();
    return errFromUnknown(e, VerthysErrorCode.E_INIT_FAILED);
  }
}

/**
 * 解锁已有加密库（非首次使用）
 *
 * 返回 VerthysResult<void>
 * 新增 onProgress 可选回调，流式接收解锁进度供前端展示
 *
 * @param verthysPath .verthys 文件路径（已有文件）
 * @param preflightResult 调用方已执行的路径预检结果（可选）
 * @param onProgress 解锁进度回调（在解锁各阶段触发，可选）
 * @param usbRebindConfirmed 介质标识变化确认（可选）：置 true 时放行
 *   克隆嫌疑阻断，重绑定在凭据验证通过后由后端落实
 * @returns VerthysResult<void>
 */
export async function initUnlock(
  verthysPath: string,
  preflightResult?: PreflightResult,
  onProgress?: (progress: UnlockProgress) => void,
  usbRebindConfirmed?: boolean,
  recoveryCode?: string,
  keyfilePath?: string,
): Promise<VerthysResult<void>> {
  // 全流程进度反馈：前端各阶段直接调用 onProgress 推送进度。
  // verthys_unlock 为单次 IPC（内部无子阶段回调），阶段之间的连续推进
  // 由前端感知层负责平滑；本层只保证阶段节点与文案真实准确。
  const t0 = Date.now();
  // 进度条单调递增，防止阶段进度回退：
  //   记录已推送的最大百分比，后续 emit 的百分比不得低于已推送值；
  //   消息内容正常更新（用户能看到阶段切换）。
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
    // 解锁前必须确保 worker 处于干净状态，否则 ensureWorkerReady 会复用
    // 旧 workerReadyPromise，IPC 发往正在被 lockAll 销毁的 worker 而永久卡死。
    //
    // 双重防护：
    //   1. awaitLockAllIfInProgress：等待正在进行的 lockAll 真正完成
    //      （不设提前返回，各破坏性步骤自带超时）
    //      确保 worker 销毁、缓存清空、状态重置全部落地
    //   2. ensureCleanWorkerState：兜底清理 — 即使 lockAll 超时未完成，
    //      若 workerHasBeenUsed=true 且预启动缓存残留，强制销毁旧 worker
    /* 用户态只呈现 4 个核心节点：准备 → 解锁 → 索引/同步 → 密钥/守卫；
     * 其余内部步骤仍以 log.info 完整留痕，节点之间由进度感知层连续推进 */
    emit(0, 1, "准备安全环境");
    await awaitLockAllIfInProgress();
    await ensureCleanWorkerState();

    // 1. 路径预检
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
    let ok1: boolean;
    try {
      ok1 = await withTimeout(ensureWorkerReady(), INIT_TIMEOUT_MS, "worker_init");
    } catch (e) {
      await resetKeyManagerState();
      return errFromUnknown(e, VerthysErrorCode.E_WORKER_INIT_FAILED);
    }
    if (!ok1) {
      await resetKeyManagerState();
      /* 安全状态目录预检失败给出专用码与修复指引；其余启动失败保持原语义。 */
      const failure = getWorkerInitFailure();
      if (failure?.code === VerthysErrorCode.E_SECURITY_STATE) {
        return err(
          VerthysErrorCode.E_SECURITY_STATE,
          failure.message || "无法加固安全状态目录：请将用户数据放在本地 NTFS 目录，或联系管理员完成目录预检",
        );
      }
      return err(VerthysErrorCode.E_WORKER_INIT_FAILED, "安全核心启动失败");
    }

    // 2.5 暴力熔断门禁预检（纯查询，不计数）
    //
    // 服务端在 unlock 入口已强制熔断（fail-closed）；此处仅提前拦截，
    // 避免锁定态进入 Argon2id 长运算流程浪费用户等待。Tauri 环境下查询
    // 失败按 fail-closed 拒绝（无法确认门禁状态不得进入认证流程）。
    const unlockGate = await checkBruteForceGate();
    if (!unlockGate.allowed) {
      await resetKeyManagerState();
      if (unlockGate.reason === "locked") {
        const secs = Math.max(1, Math.ceil(unlockGate.remainingSecs ?? 0));
        return err(
          VerthysErrorCode.E_RATE_LIMITED,
          `尝试次数过多，已锁定 ${secs} 秒，请稍后再试`,
          undefined,
          secs,
        );
      }
      return err(VerthysErrorCode.E_CNG_UNAVAILABLE, "无法确认安全门禁状态，请稍后重试");
    }

    // 3. verthys_unlock — 返回完整 VerthysResponse
    //
    // 解锁进度由本层 emit 闸门直接推送（单调递增）
    // 分级超时熔断（软 15s 提示 / 硬 35s 降级 / 连续 3 次熔断锁定）
    //   - 软超时 15s：Argon2id 派生耗时过长，前端提示「密钥计算较慢，请耐心等待」继续执行
    //   - 硬超时 35s：整体解锁未完成，触发降级校验，仅保障核心数据可读
    //   - 连续 3 次硬超时自动锁定容器 30 分钟（withGradedTimeout 内部处理）
    //
    // worker 在 Verthys_V4Unlock 成功后进程内一次性完成
    //   Verthys_FindFirstLidByType(0x10) + Verthys_GetRecord(lid)，
    //   结果内联到响应 has_global_key/global_key_id/global_key_record 三字段。
    //   前端直接消费，零解锁后 IPC 往返，消除 probe 链竞态与 v1 假阴性死锁。
    emit(1, 8, "解锁加密库");
    let unlockResp;
    try {
      unlockResp = await withGradedTimeout(
        verthysUnlock(verthysPath, usbRebindConfirmed, recoveryCode, keyfilePath),
        UNLOCK_SOFT_TIMEOUT_MS,
        UNLOCK_HARD_TIMEOUT_MS,
        "verthys_unlock",
        () => {
          /* 软超时回调：Argon2id 派生耗时较长，提示用户耐心等待，不中断解锁 */
          emit(1, 30, "派生密钥并解锁");
          log.warn("verthys_unlock 软超时（15s）：Argon2id 派生耗时较长，已提示用户耐心等待");
        },
      );
    } catch (e) {
      await resetKeyManagerState();
      // 介质克隆嫌疑：保留可识别错误码，供上层触发"确认更换介质"流程
      //（后端以 E_USB_CLONE_SUSPECTED 前缀返回，通用包装层不识别该域错误码）
      const rawMsg = e instanceof Error ? e.message : String(e);
      if (rawMsg.includes(VerthysErrorCode.E_USB_CLONE_SUSPECTED)) {
        return err(
          VerthysErrorCode.E_USB_CLONE_SUSPECTED,
          "介质标识与登记记录不一致，已阻止解锁",
        );
      }
      return errFromUnknown(e, VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED);
    }
    if (!unlockResp.ok) {
      /* 锁定/限流/门禁错误：展示后端动态信息（已锁定 X 秒），不得折叠为
       * 固定“打开加密库失败”。 */
      const gateResult = gateErrorResult(
        unlockResp.error_code ?? unlockResp.error,
        unlockResp.retry_after_secs,
        unlockResp.error,
      );
      if (gateResult) return gateResult;
      /* 本机密钥材料缺失：普通解锁永久不可用，不得折叠为通用“打开加密库失败”。
       * 该错误不计入口令失败次数（后端未调用 record_auth_failure）。 */
      if (unlockResp.error_code === VerthysErrorCode.E_KEY_MATERIAL_MISSING) {
        return err(
          VerthysErrorCode.E_KEY_MATERIAL_MISSING,
          "本机密钥材料已丢失，无法用普通方式打开该库；请使用恢复码解锁，并在恢复会话中重绑本机设备槽",
        );
      }
      const raw = unlockResp.error ?? "";
      /* keyfile 缺失/无效不属于认证失败：保留 worker 进程与会话状态，
       * 直接引导用户重选 keyfile 后重试（不得折叠为 AUTH）。 */
      if (raw.includes("0000001A")) {
        return err(
          VerthysErrorCode.E_KEYFILE_REQUIRED,
          "该加密库已启用 keyfile，请选择 keyfile 文件后重试",
        );
      }
      if (raw.includes("0000001B")) {
        return err(
          VerthysErrorCode.E_KEYFILE_INVALID,
          "keyfile 文件无效，请选择创建时保存的 keyfile",
        );
      }
      await resetKeyManagerState();
      if (raw.includes("00000018")) {
        return err(VerthysErrorCode.E_TPM, "设备环境已变化，请使用恢复码解锁并重密封");
      }
      if (raw.includes("00000019")) {
        return err(VerthysErrorCode.E_ROLLBACK, "检测到文件回退，已拒绝打开");
      }
      return err(VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED, "打开加密库失败");
    }

    // 4. 消费进程内探测结果
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

    // 解锁后关键路径 — 填充摘要缓存 + 加载模块密钥状态
    //
    //   步骤 A（关键路径）：await ensureSummaryScan() — 填充摘要缓存
    //     为模块组件列表渲染提供 O(1) 索引，必须在 verthysReady=true 之前完成
    //   步骤 B（关键路径）：await loadModuleKeyStatus()（8s 超时兜底）——
    //     必须在 verthysReady=true 之前完成，否则守卫读到默认 false 会放行模块
    //     - moduleKeyStatusLoading 标志供模块组件守卫
    //     - 乐观并发控制防止与用户开关操作竞态
    //     - 安全权衡：加载窗口内 moduleKeyEnabled 为安全默认 false，模块列表可见但
    //       加密项仍需独立密钥解密；用户刚通过全局密钥认证，风险可接受
    //
    // 时序保证：ensureSummaryScan 与 loadModuleKeyStatus 均在 verthysReady=true
    //           之前完成（列表渲染与模块守卫依赖）。
    emit(2, 88, "建立索引与同步状态");
    try {
      // 摘要扫描超时兜底（10s），防止 IPC 挂起导致卡死
      await withTimeout(ensureSummaryScan(), 10000, "摘要扫描");
    } catch (e) {
      log.warn("initUnlock: 摘要扫描失败/超时（v1 格式或异常），模块加载将回退到全量扫描", e);
    }

    // TYPE 常量冲突数据迁移
    //
    // TYPE_GLOBAL_KEY (0x10) 与 TYPE_ACCOUNT (0x10) 值相同，已存储的 verthys
    // 文件中全局密钥记录与账户记录可能共享同一类型值，导致：
    //   - AccountVerthys 扫描 TYPE_ACCOUNT=0x10 误拾全局密钥记录 → "设置遗忘"
    //   - findGlobalKeyRecord 扫描 TYPE_GLOBAL_KEY=0x10 误拾账户记录 → "密钥验证无效"
    //   - 删除"垃圾账户"实际删除全局密钥 → "增删改异常/删除后复活"
    //   同理 TYPE_PHOTO_CHUNK (0x05) 与旧 TYPE_META (FileVerthys 0x05) 冲突。
    //
    // 迁移必须在 loadModuleKeyStatus 之前完成：
    //   migrateRecordTypes 通过内容嗅探区分冲突类型的记录，将旧账户记录
    //   (0x10) 重写为 TYPE_ACCOUNT (0x02)，旧 FileVerthys 元数据 (0x05) 重写为
    //   TYPE_FILEVERTHYS_META (0x08)。全局密钥记录和照片块保持原类型不变。
    //
    // 幂等性：已迁移记录的新类型不会被再次扫描到，安全重复调用。
    // 性能：首次迁移 N 条 × 3 IPC；后续调用 O(1) 索引查询 <1ms。
    let migrationMigrated = 0;
    try {
      // 整体超时兜底（15s），防止单条记录 IPC 挂起导致
      //   initUnlock 永远停在"建立摘要索引"阶段。
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

    // 迁移后必须重新校验缓存的全局密钥记录
    //
    // 冲突来源：worker 内联 probe 在 Verthys_V4Unlock 成功后立即调用
    //   Verthys_FindFirstLidByType(0x10) 搜索全局密钥记录（同 worker runtime.rs
    //   probe_global_key_inproc），而类型迁移（migrateRecordTypes）在此之后
    //   才执行。若 verthys 中存在旧账户记录（type=0x10，与 TYPE_GLOBAL_KEY
    //   冲突），probe 可能命中账户记录而非真正的全局密钥记录，将账户 JSON
    //   数据作为 global_key_record 缓存到 keyState.globalKeyRecordB64。
    //   后果：verifyGlobalKey 使用错误的缓存数据导致验证失效。
    //
    // 两个触发条件满足任一即重新探测：
    //   条件 1：migrationMigrated > 0 — 有记录被迁移，旧 0x10 记录已重写为
    //           0x02，缓存的 lid 可能指向已重写的旧记录 → 缓存必然过期
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
      // 超时兜底（5s），防止 findGlobalKeyRecord 的 IPC 挂起
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

    // 同步后端 key_lifecycle 状态
    //
    // 冲突来源：
    //   verthys_unlock 时 worker 进程内 probe 通过 find_first_lid_by_type(0x10)
    //   搜索全局密钥记录，后端 key_lifecycle 据 probe 结果设为 Locked 或 NoKey。
    //   TYPE_GLOBAL_KEY(0x10) 与旧 TYPE_ACCOUNT(0x10) 冲突，probe 可能误判。
    //
    //   前端 migrateRecordTypes + 重新校验得到正确结果后，必须同步后端
    //   状态，否则状态不同步：
    //     - 前端 false + 后端 Locked → UI 显示"初始化密钥"但 derive 要求 NoKey → 失败
    //     - 前端 true  + 后端 NoKey   → UI 显示"身份验证"但 verify 要求 Locked → 失败
    //
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

    // 安全约束：loadModuleKeyStatus 必须在 verthysReady=true 之前完成
    //
    //   keyState.moduleKeyEnabled 默认 false。若模块状态尚未加载就置
    //   verthysReady=true，useModuleNavigation.switchModule 守卫读
    //   isModuleKeyEnabled → 返回 false → 误判「保护已关闭」→ 直接放行
    //   进入模块并加载内容，绕过模块独立密钥验证。
    //
    //   loadModuleKeyStatus 内部为三次 v4_module_status 查询（C 层 M1 状态，
    //   无记录读取/解密），正常 <100ms，2s 超时兜底（非致命，失败 fail-closed
    //   + switchModule 守卫兜底）。
    //   与 moduleKeyStatusVersion 乐观并发安全：关键路径 verthysReady=false，
    //   UI 不渲染，用户无法触发 setModuleKey/disableModuleProtection，
    //   startVersion===current 必然成立。
    //
    // 模块内容预加载：verthysReady=true 后由后台任务 ensureRecordScan 静默填充
    //   全量记录扫描缓存（含 dataB64，最多 64KB/条），用户进入模块时零 IPC 读取。
    emit(3, 95, "加载密钥并启动守卫");
    keyState.moduleKeyStatusLoading.value = true;
    // 超时处理：withTimeout 超时后不重置 moduleKeyStatusLoading——
    // 由 loadModuleKeyStatus 内部完成时置 false；超时窗口内
    // moduleKeyStatusLoaded=false，switchModule 守卫据此拦截业务模块。
    // 被抛弃的 Promise 用 .catch 吞掉 unhandled rejection。
    const lmkPromise = loadModuleKeyStatus();
    try {
      await withTimeout(lmkPromise, 8000, "模块密钥状态加载");
    } catch (e) {
      // 不重置 moduleKeyStatusLoading：让 lmkPromise 内部完成时自己设 false
      //   超时窗口内 moduleKeyStatusLoaded=false，switchModule 守卫拦截业务模块（安全兜底）
      log.warn("initUnlock: 模块密钥状态加载超时/失败（moduleKeyStatusLoading 保持 true 由内部重置；moduleKeyStatusLoaded=false 守卫拦截）", e);
      // 吞掉被抛弃 Promise 的 unhandled rejection（lmkPromise 内部已有 try/catch，此为防御性兜底）
      lmkPromise.catch(() => { /* loadModuleKeyStatus 内部已处理 moduleKeyStatusLoading/moduleKeyStatusLoaded */ });
    }

    keyState.verthysReady.value = true;
    await startSessionGuard();
    emit(4, 100, "解锁完成");

    // 不在 verthysReady=true 后立即发起 ensureRecordScan：
    //   后台任务的 IPC 请求与前端模块加载请求共用同一 worker 通道，
    //   后台任务独占 worker 时前端请求排队等待 → 30s 卡顿。
    //
    //   1. loadModuleKeyStatus（关键路径已调用）通过 ensureRecordScan 填充 recordScanCache
    //   2. 模块组件挂载时调用 ensureRecordScanSafe() 复用已填充的缓存（scanInProgress 去重，零 IPC）
    //   3. startBackgroundTasks 延迟启动 + yieldIfFrontendBusy 让出 worker 通道

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
 * 返回 VerthysResult<string | void>：新建时为一次性恢复码，解锁时为 void
 */
export async function initAndUnlock(verthysPath: string): Promise<VerthysResult<string | void>> {
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

/** 密钥操作互斥（initGlobalKey / changeGlobalKey 共享）：
 *  派生成功到记录落盘确认之间后端状态仍是 NoKey，重复 derive 在此窗口
 *  是合法的——互斥锁保证同一时刻仅一条密钥编排在飞，杜绝并发派生时
 *  GMK 被后写覆盖而磁盘出现多条的错位。 */
let keyOpInFlight = false;

/** IPC 补偿动作重试（2 次）：补偿链自身不可再引入新的不可达状态 */
async function ipcRetry(fn: () => Promise<boolean>): Promise<boolean> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      if (await fn()) return true;
    } catch {
      /* 重试一次 */
    }
  }
  return false;
}

/**
 * 初始化全局安全密钥（首次设置）
 * GMK 派生在 worker 子进程内完成，前端仅传递参数并持久化 record
 *
 * 时序契约（状态机与磁盘事实强一致）：
 *   派生成功仅驻留 worker 内存，后端状态保持 NoKey；本函数完成
 *   "写记录 + 读回验证"后才经 reconcile(true) 推进 NoKey → Locked。
 *   任一环节失败即清理现场（删半成品记录 + 清 GMK + reconcile(false)），
 *   用户可立即重试，杜绝"派生成功但记录丢失"的中间态死锁。
 *
 * 落盘确认采用内容级读回验证（GetRecord 读回 == 写入值）：
 *   AddRecord 单调用即时落盘（一次提交收口），读回命中即记录已持久；
 *   不依赖 flush 后的 mtime 等
 *   间接判据（该启发式对 no-op flush 恒可误报）。
 *
 * @param globalPassword 全局访问密钥
 * @param binBytes .bin 密钥文件原始字节
 * @param binPassword .bin 文件密码
 * @param onProgress 阶段进度回调（复用解锁/验证进度呈现链，可为空）
 * @returns VerthysResult<void>
 */
export async function initGlobalKey(
  globalPassword: string,
  binBytes: Uint8Array,
  binPassword: string,
  onProgress?: (progress: UnlockProgress) => void,
): Promise<VerthysResult<void>> {
  if (keyOpInFlight) {
    return err(VerthysErrorCode.E_VERTHYS_NOT_READY, "有进行中的密钥操作，请稍候再试");
  }
  keyOpInFlight = true;
  try {
    return await initGlobalKeyInner(globalPassword, binBytes, binPassword, onProgress);
  } finally {
    keyOpInFlight = false;
  }
}

/** initGlobalKey 编排主体（互斥锁内执行）；复用锁成功后进入 */
async function initGlobalKeyInner(
  globalPassword: string,
  binBytes: Uint8Array,
  binPassword: string,
  onProgress?: (progress: UnlockProgress) => void,
): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_VERTHYS_NOT_READY, "verthys 未解锁");
  }

  const t0 = Date.now();
  const emit = (stage: number, percent: number, message: string) => {
    if (onProgress) {
      onProgress({ stage, percent, elapsed_ms: Date.now() - t0, message });
    }
  };
  emit(1, 8, "准备派生安全密钥");

  // 任一后续步骤失败：清理现场后复位（幂等补偿，磁盘回到"无记录/
  // 待收敛"态；补偿动作自身失败时经强制复位命令兜底）。
  // worker 已在派生持久化失败路径自清 GMK 与半成品记录，此处复核一道。
  const abortReinit = async (): Promise<void> => {
    const cleared = await ipcRetry(() => verthysClearGlobalKey().catch(() => false));
    const reconciled = await ipcRetry(() => verthysReconcileKeyPresence(false));
    if (!cleared || !reconciled) {
      await verthysResetGlobalKeyState().catch(() => {});
    }
  };

  // 1. 派生 + 持久化 + 内容级读回验证：worker 进程内原子完成
  //    （收敛残留记录 → 写入 → GetRecord 逐字节比对），派生与
  //    落盘确认同一调用，无跨 IPC 中间态。
  emit(2, 20, "派生安全密钥");
  const binDataB64 = bytesToBase64(binBytes);
  let persisted: { id: number; recordB64: string };
  try {
    persisted = await withTimeout(
      verthysDeriveAndStoreGlobalKey(globalPassword, binDataB64, binPassword),
      INIT_TIMEOUT_MS,
      "derive_and_store_global_key"
    );
  } catch (e) {
    await abortReinit();
    return errFromUnknown(e, VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED);
  }
  emit(3, 70, "确认密钥落盘");

  // 2. 兜底 flush（LSM 归并；记录已由 worker 读回验证确认落盘，
  //    flush 失败仅降级提示，非阻断）
  const flushOk = await persistVerthys();
  if (!flushOk) {
    log.warn("initGlobalKey: 兜底 flush 未确认（记录已由读回验证确认落盘，非阻断）");
  }

  // 3. 状态推进：记录已在磁盘 → reconcile(true) 推进 NoKey → Locked
  emit(4, 88, "推进密钥状态");
  const advanced = await verthysReconcileKeyPresence(true);
  if (!advanced) {
    // 记录已确认落盘：复位 NoKey 后用户重试时 worker 收敛会先清
    // 残留再写入，恒收敛为单条，无需前端删除。
    await abortReinit();
    return err(VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED,
      "全局密钥状态确认失败，请重试（或重启应用）");
  }

  // 4. 前端状态（数据已由 worker 读回验证确认落盘）
  keyState.globalKeyReady.value = true;
  keyState.hasGlobalKeyRecord.value = true;
  // 缓存 recordB64 和 id，供后续 verifyGlobalKey 直接读取（跳过 findGlobalKeyRecord 扫描）
  keyState.globalKeyRecordB64.value = persisted.recordB64;
  keyState.globalKeyRecordId.value = persisted.id;
  resetSessionTimer();

  log.info("全局密钥初始化成功");
  return ok(undefined);
}

/**
 * 修改全局密钥（需先验证旧密钥）
 *
 * 编排契约（磁盘恒收敛为单条全局密钥记录）：
 *   1. 记录收敛：清除任一残留的 global-key 记录（历史中断产物），
 *      仅保留验证命中的目标记录；
 *   2. 先派生并写入新记录（读回验证内容一致）；
 *   3. 再删除旧记录（读回验证删除生效）；
 *   4. 任一步骤失败：回收新记录 + 清 GMK（后端回 Locked），磁盘回到
 *      "仅旧记录"，用户以旧密钥重新验证即可重试——杜绝两条并存、杜绝
 *      状态机中间态死锁。
 *
 * 落盘确认采用内容级读回验证（同 initGlobalKey：单调用即时落盘，
 * 读回命中即持久；flush 仅作归并兜底，失败不阻断）。
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
  if (keyOpInFlight) {
    return err(VerthysErrorCode.E_VERTHYS_NOT_READY, "有进行中的密钥操作，请稍候再试");
  }
  keyOpInFlight = true;
  try {
    return await changeGlobalKeyInner(
      oldPassword, oldBinBytes, oldBinPassword,
      newPassword, newBinBytes, newBinPassword,
    );
  } finally {
    keyOpInFlight = false;
  }
}

/** changeGlobalKey 编排主体（互斥锁内执行）；复用锁成功后进入 */
async function changeGlobalKeyInner(
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

  // 1. 验证旧密钥（成功后 GMK=旧值、后端 Unlocked）
  const verifyResult = await verifyGlobalKey(oldPassword, oldBinBytes, oldBinPassword);
  if (!verifyResult.ok) {
    return err(VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED, "旧全局密钥验证失败");
  }

  // 失败统一补偿：回收新记录 + 清 GMK（Unlocked→Locked），补偿动作
  // 连续失败时经强制复位命令兜底。磁盘收敛回"仅旧记录"，用户以旧密钥
  // 重新验证即可重试。
  const abortChange = async (writtenNewId: number | null): Promise<void> => {
    if (writtenNewId !== null) {
      const removed = await ipcRetry(() => verthysDeleteRecord(writtenNewId));
      if (removed) {
        await flushVerthysNow();
      }
    }
    const cleared = await ipcRetry(() => verthysClearGlobalKey().catch(() => false));
    if (!cleared) {
      await verthysResetGlobalKeyState().catch(() => {});
    }
  };
  let newId: number | null = null;

  try {
    // 2. 查找旧记录 + 记录收敛：清除任何残留 global-key 记录（历史中断
    //    产生的中间态），全局密钥记录恒为单条。摘要游标仅取索引元数据，
    //    不解密业务数据块，收敛不扩大敏感数据读取面。
    const oldRecord = await findGlobalKeyRecord();
    const staleIds: number[] = [];
    if (oldRecord) {
      try {
        let batch = await verthysScanSummaryOpen(0, 512);
        const collect = (ids: { id: number; type: number; name: string }[]) => {
          for (const r of ids) {
            if (r.type === TYPE_GLOBAL_KEY && r.name === "global-key" && r.id !== oldRecord.id) {
              staleIds.push(r.id);
            }
          }
        };
        collect(batch.records);
        while (!batch.exhausted) {
          batch = await verthysScanSummaryNext(512);
          collect(batch.records);
        }
      } catch (e) {
        log.warn("changeGlobalKey: 摘要收敛扫描异常（跳过收敛）", e);
      } finally {
        await verthysScanSummaryClose().catch(() => {});
      }
    }
    for (const sid of staleIds) {
      log.warn(`changeGlobalKey: 收敛残留全局密钥记录 lid=${sid}`);
      await verthysDeleteRecord(sid);
    }
    if (staleIds.length > 0) {
      await flushVerthysNow();
    }

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
      await abortChange(null);
      return errFromUnknown(e, VerthysErrorCode.E_GLOBAL_KEY_DERIVE_FAILED);
    }
    if (!newRecordB64) {
      await abortChange(null);
      return err(VerthysErrorCode.E_GLOBAL_KEY_DERIVE_FAILED, "worker 派生新全局密钥失败");
    }

    // 4. 写入新记录 + 内容级读回验证
    newId = await verthysAddRecord(TYPE_GLOBAL_KEY, "global-key", newRecordB64);
    if (newId === null) {
      await abortChange(null);
      return err(VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED, "写入新全局密钥记录失败");
    }
    let newReadBack: { type: number; name: string; dataB64: string } | null = null;
    try {
      newReadBack = await withTimeout(verthysGetRecord(newId), INIT_TIMEOUT_MS, "readback_new_global_key");
    } catch (e) {
      log.warn("changeGlobalKey: 新记录读回验证异常", e);
    }
    if (!newReadBack || newReadBack.dataB64 !== newRecordB64) {
      await abortChange(newId);
      return err(VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED,
        "新全局密钥记录落盘确认失败（已回滚，请以旧密钥重新验证后重试）");
    }

    // 5. 删除旧记录 + 读回验证删除生效
    if (oldRecord) {
      const delOk = await verthysDeleteRecord(oldRecord.id);
      if (!delOk) {
        await abortChange(newId);
        return err(VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED,
          "旧全局密钥记录删除失败（已回滚，请以旧密钥重新验证后重试）");
      }
      const ghost = await verthysGetRecord(oldRecord.id).catch(() => null);
      if (ghost !== null) {
        await abortChange(newId);
        return err(VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED,
          "旧全局密钥记录删除确认失败（已回滚，请以旧密钥重新验证后重试）");
      }
    }

    // 6. 兜底 flush（LSM 归并；新记录已读回确认落盘，失败不阻断）
    const flushResult = await flushVerthysNow();
    if (!flushResult.ok) {
      log.warn("changeGlobalKey: 兜底 flush 未确认（新记录已读回确认落盘，非阻断）");
    }

    // 7. 状态更新（后端已 Unlocked，GMK=新值）
    keyState.globalKeyReady.value = true;
    keyState.hasGlobalKeyRecord.value = true;
    keyState.globalKeyRecordB64.value = newRecordB64;
    keyState.globalKeyRecordId.value = newId;
    resetSessionTimer();
    log.info("全局密钥修改成功");
    return ok(undefined);
  } catch (e) {
    // 任一未预期异常：补偿回收后按持久化失败上报
    try {
      await abortChange(newId);
    } catch (compErr) {
      await verthysResetGlobalKeyState().catch(() => {});
      log.error("changeGlobalKey: 失败补偿异常", compErr);
    }
    return errFromUnknown(e, VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED);
  }
}

/**
 * 验证全局密钥（后续进入时）
 * GMK 验证在 worker 子进程内完成，前端仅传递参数和 record
 *
 * 返回 VerthysResult<void>
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
  // GMK 验证全流程进度反馈：各阶段推送进度，避免长时间无反馈。
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

  // 优先读取 initUnlock 阶段缓存的 recordB64，跳过重复扫描
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

  // 验证阶段进度反馈
  emit(3, 40, "验证全局密钥");
  const binDataB64 = bytesToBase64(binBytes);
  let verifyOk: boolean;
  try {
    verifyOk = await withTimeout(
      verthysVerifyGlobalKey(globalPassword, binDataB64, binPassword, recordB64),
      INIT_TIMEOUT_MS,
      "verify_global_key"
    );
  } catch (e) {
    const gateResult = gateErrorResult(
      (e as { errorCode?: string } | null)?.errorCode,
      (e as { retryAfterSecs?: number } | null)?.retryAfterSecs,
      e instanceof Error ? e.message : null,
    );
    if (gateResult) return gateResult;
    return errFromUnknown(e, VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED);
  }
  if (!verifyOk) {
    return err(VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED, "全局密钥验证失败");
  }

  emit(4, 80, "激活安全会话");

  // 内存状态更新
  keyState.globalKeyReady.value = true;
  // 此处不调用 loadModuleKeyStatus：
  //   initUnlock 已在解锁关键路径（verthysReady=true 之前）完成模块密钥状态加载。
  //   重复调用会再次触发 ensureSummaryScan + verthysGetRecord 链路，
  //   摘要缓存未命中时回退全量扫描 → 20-30s 卡顿。
  //   若用户在解锁后修改了模块保护（setModuleKey/disableModuleProtection），状态已由该函数
  //   原子更新（C 层事务成功后更新 keyState.moduleKeyEnabled），无需重载。
  resetSessionTimer();
  // 会话守卫已在 initCreate / initUnlock 启动；此处为幂等重试（首次启动
  // 失败时在此路径重试一次）。
  await startSessionGuard();
  // 运行档位不在解锁收尾应用：恢复链以受信配置为唯一权威（读取→应用），
  // 本地缓存值禁止回写权威文件，此处的缓存 apply 会与恢复链竞态并覆盖受信副本。
  emit(5, 100, "验证完成");
  return ok(undefined);
}

/**
 * 带暴力拦截门禁的全局密钥验证
 *
 * 计数职责已上移服务端：verify_global_key 命令在服务端入口强制
 *   熔断闸门并权威计数（仅认证域错误计失败、成功即重置）。本函数
 *   不再调用计数接口，仅在验证前预检与验证后查询锁定态映射给 UI，
 *   避免同一失败被前后端各计一次。
 *
 * 保留现有 VerifyGlobalKeyResult 判别联合返回类型（已有 reason 机制）
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
    return { ok: false, reason: "gate_unavailable" };
  }

  // 2. 实际验证（透传 onProgress 进度回调）
  const result = await verifyGlobalKey(globalPassword, binBytes, binPassword, onProgress);
  if (result.ok) {
    return { ok: true };
  }

  /* 服务端闸门已给出结构化锁定/门禁码：直接映射，不再二次查询把信息折叠。 */
  if (result.code === VerthysErrorCode.E_RATE_LIMITED) {
    return { ok: false, reason: "locked", remainingSecs: Math.max(1, result.retryAfterSecs ?? 1) };
  }
  if (result.code === VerthysErrorCode.E_CNG_UNAVAILABLE) {
    return { ok: false, reason: "gate_unavailable" };
  }

  // 3. 失败后查询服务端计数结果（纯查询，不计数）：将锁定态映射给 UI 展示；
  //    查询失败不影响既有错误语义
  try {
    const r: BruteForceCheckResponse = await securityBruteCheck();
    if (r.kind === "Locked") {
      return { ok: false, reason: "locked", remainingSecs: r.remaining_secs };
    }
  } catch { /* 查询失败按普通失败处理 */ }
  return { ok: false, reason: "wrong_key" };
}

/* ------------------------------------------------------------------ *
 * 设备机器码绑定与校验                                                 *
 * ------------------------------------------------------------------ */

/**
 * 绑定当前设备机器码（独立可控）
 *
 * 由调用方决定是否绑定。
 * 绑定失败返回明确错误码，UI 层可展示提示并允许用户重试。
 *
 * 无 force 参数：setDeviceBinding 始终写入当前机器码（覆盖语义是唯一行为）。
 * @returns VerthysResult<void>
 *   - ok：绑定成功
 *   - err(E_VERTHYS_NOT_READY)：verthys 未解锁
 *   - err(E_DEVICE_BIND_FAILED)：绑定失败，UI 可提示用户重试
 */
export async function bindDevice(): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_VERTHYS_NOT_READY, "verthys 未解锁");
  }
  try {
    await setDeviceBinding();
    log.info("设备绑定成功");
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
 * 返回 VerthysResult<"match"|"mismatch"|"unbound">
 *
 * 后端 check_device_binding 返回 DeviceBindingResult 结构体
 *   （{status, detail, error_code?, match_score?}），必须按 status 显式映射
 *   为前端联合类型：直接透传对象会使 useViewMode 的 === 'mismatch'
 *   字符串比较恒为 false，导致 device_mismatch 拦截视图失效。
 *
 *   映射规则：
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
