/*
 * key/global/create.ts — 加密库创建与初始化分发
 */
import {
  ensureWorkerReady,
  ensureCleanWorkerState,
  verthysCreate, verthysPreflight,
  verthysReconcileKeyPresence,
  getWorkerInitFailure,
  type PreflightResult, type UnlockProgress,
} from "../../lib/verthys";
import { keyState, setCurrentVerthysPath } from "../../state/key_state";
import { INIT_TIMEOUT_MS, CREATE_TIMEOUT_MS } from "../../constants/key_manager_const";
import { withTimeout } from "../../utils/ipc/promise_utils";
import { ensureSummaryScan } from "../../cache/composition/verthys-cache";
import { startBackgroundTasks } from "../../core/background-tasks";
import {
  ok, err, errFromUnknown,
  VerthysErrorCode, type VerthysResult,
} from "../../lib/util/verthys_error";
import { resetSessionTimer, awaitLockAllIfInProgress } from "../../session/security-session";
import { loadModuleKeyStatus } from "../module-auth";
import {
  log, resetKeyManagerState, startSessionGuard, resolveGlobalKeyRecord,
  type GlobalKeyRecordRef,
} from "./shared";
import { initUnlock } from "./unlock";

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
    let existing: GlobalKeyRecordRef | null = null;
    try {
      existing = (await resolveGlobalKeyRecord()).record;
    } catch (e) {
      log.warn("initCreate: 全局密钥解析失败（按无记录处理）", e);
    }
    keyState.hasGlobalKeyRecord.value = existing !== null;
    keyState.globalKeyRecordB64.value = existing?.recordB64 ?? "";
    keyState.globalKeyRecordId.value = existing?.id ?? 0;

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
    /* 容器解锁即开始统一空闲计时：模块口令只依赖 verthysReady，
     * 不能等到全局密钥验证后才武装，否则该会话没有任何自动锁定。 */
    resetSessionTimer();
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
