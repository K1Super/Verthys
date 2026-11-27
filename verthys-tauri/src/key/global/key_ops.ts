/*
 * key/global/key_ops.ts — 全局根密钥初始化与修改
 */
import {
  verthysDeriveAndStoreGlobalKey, verthysChangeGlobalKey,
  verthysClearGlobalKey, verthysResetGlobalKeyState, verthysReconcileKeyPresence,
  bytesToBase64,
  type UnlockProgress,
} from "../../lib/verthys";
import { keyState } from "../../state/key_state";
import { INIT_TIMEOUT_MS } from "../../constants/key_manager_const";
import { withTimeout } from "../../utils/ipc/promise_utils";
import {
  persistVerthys,
  invalidateSummaryRecord, invalidateScannedRecord,
} from "../../cache/composition/verthys-cache";
import {
  ok, err, errFromUnknown,
  VerthysErrorCode, type VerthysResult,
} from "../../lib/util/verthys_error";
import { resetSessionTimer } from "../../session/security-session";
import { log } from "./shared";

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
 * 修改全局密钥（后端单命令）
 *
 * 前端只负责参数传递与状态同步；核验旧钥、派生新钥、写新记录、删旧记录、
 * GMK 换槽全部由 worker 单次调用完成。任何失败都不会让前端与后端状态
 * 分叉：失败时 GMK 槽保持原值，旧记录仍是权威。
 *
 * 错误码：
 *   - E_GLOBAL_KEY_VERIFY_FAILED：旧钥三要素错误
 *   - E_GLOBAL_KEY_RECORD_NOT_FOUND：无有效记录
 *   - E_GLOBAL_KEY_PERSIST_FAILED：新记录写入/读回失败（旧钥仍有效）
 *   - E_GLOBAL_KEY_CHANGE_UNCONFIRMED：通信超时，结果未确认
 *   - E_RATE_LIMITED / E_CNG_UNAVAILABLE：熔断/门禁
 *
 * @returns VerthysResult<{ cleanupPending: boolean }>
 */
export async function changeGlobalKey(
  oldPassword: string,
  oldBinBytes: Uint8Array,
  oldBinPassword: string,
  newPassword: string,
  newBinBytes: Uint8Array,
  newBinPassword: string
): Promise<VerthysResult<{ cleanupPending: boolean }>> {
  if (keyOpInFlight) {
    return err(VerthysErrorCode.E_VERTHYS_NOT_READY, "有进行中的密钥操作，请稍候再试");
  }
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_VERTHYS_NOT_READY, "verthys 未解锁");
  }
  keyOpInFlight = true;
  const oldId = keyState.globalKeyRecordId.value;
  try {
    const result = await verthysChangeGlobalKey(
      oldPassword,
      bytesToBase64(oldBinBytes),
      oldBinPassword,
      newPassword,
      bytesToBase64(newBinBytes),
      newBinPassword,
    );

    // 后端已完成换槽与记录写入：同步前端权威状态
    keyState.globalKeyReady.value = true;
    keyState.hasGlobalKeyRecord.value = true;
    keyState.globalKeyRecordB64.value = result.recordB64;
    keyState.globalKeyRecordId.value = result.id;
    // 旧记录与后端确认删除的残留一并失效，避免通用缓存命中已删除 id
    const affected = new Set<number>([oldId, ...result.deletedIds]);
    for (const id of affected) {
      if (id > 0) {
        invalidateSummaryRecord(id);
        invalidateScannedRecord(id);
      }
    }
    resetSessionTimer();
    log.info(
      `全局密钥修改成功（lid=${result.id}，cleanup_pending=${result.cleanupPending}）`,
    );
    return ok({ cleanupPending: result.cleanupPending });
  } catch (e) {
    const code = (e as { errorCode?: string } | null)?.errorCode;
    const retryAfterSecs = (e as { retryAfterSecs?: number } | null)?.retryAfterSecs;
    switch (code) {
      case "E_GLOBAL_KEY_VERIFY_FAILED":
        return err(VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED, "旧密钥验证失败，请检查");
      case "E_GLOBAL_KEY_RECORD_NOT_FOUND":
        return err(VerthysErrorCode.E_GLOBAL_KEY_RECORD_NOT_FOUND, "未找到全局密钥记录");
      case "E_GLOBAL_KEY_PERSIST_FAILED":
        return err(VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED, "新密钥写入失败，旧密钥仍有效");
      case "E_GLOBAL_KEY_CHANGE_UNCONFIRMED":
        return err(
          VerthysErrorCode.E_GLOBAL_KEY_CHANGE_UNCONFIRMED,
          "修改结果未确认：请重启应用后以新密钥验证",
        );
      case "E_RATE_LIMITED":
        return err(
          VerthysErrorCode.E_RATE_LIMITED,
          "尝试次数过多，请稍后再试",
          undefined,
          retryAfterSecs,
        );
      case "E_CNG_UNAVAILABLE":
        return err(
          VerthysErrorCode.E_CNG_UNAVAILABLE,
          "安全门禁暂时不可用，请重启应用后重试",
        );
      default:
        return errFromUnknown(e, VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED);
    }
  } finally {
    keyOpInFlight = false;
  }
}
