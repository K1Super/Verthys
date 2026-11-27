/*
 * key/global/verify.ts — 全局根密钥验证（含暴力门禁）
 */
import {
  verthysVerifyGlobalKey, bytesToBase64,
  securityBruteCheck,
  type BruteForceCheckResponse, type UnlockProgress,
} from "../../lib/verthys";
import { keyState } from "../../state/key_state";
import { INIT_TIMEOUT_MS } from "../../constants/key_manager_const";
import { withTimeout } from "../../utils/ipc/promise_utils";
import {
  ok, err, errFromUnknown, gateErrorResult,
  VerthysErrorCode, type VerthysResult,
} from "../../lib/util/verthys_error";
import { resetSessionTimer, checkBruteForceGate } from "../../session/security-session";
import type { VerifyGlobalKeyResult } from "../../types/key_manager";
import { log, startSessionGuard, resolveGlobalKeyRecord, type GlobalKeyRecordRef } from "./shared";

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

  // 优先读取 initUnlock 阶段缓存的 recordB64；未命中走权威解析器
  emit(1, 10, "定位密钥记录");
  let recordB64: string;
  if (keyState.globalKeyRecordB64.value) {
    // 缓存命中：0ms 直接读取（initUnlock 已解析过）
    recordB64 = keyState.globalKeyRecordB64.value;
    log.info("verifyGlobalKey: 缓存命中，跳过记录解析");
  } else {
    // 缓存未命中：权威解析（最新有效记录）
    emit(2, 15, "解析密钥记录");
    let found: GlobalKeyRecordRef | null = null;
    try {
      found = await withTimeout(
        resolveGlobalKeyRecord().then((r) => r.record),
        10000,
        "resolveGlobalKeyRecord",
      );
    } catch (e) {
      log.warn("resolveGlobalKeyRecord 超时或失败", e);
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
