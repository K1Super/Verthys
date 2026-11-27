/*
 * ipc/global_key.ts — 系统指标快照与 GMK（全局密钥）IPC 封装
 */

import { ipc } from "./internal";
import type { VerthysResponse } from "../../types/verthys";

/** 系统运行指标快照（CPU 占用率真实差分采样；无基线时 cpu_usage=null） */
export interface SystemSnapshot {
  cpu_usage: number | null;
}

/** 查询系统运行指标（安全防护面板「CPU 占用」的真实数据源） */
export async function verthysGetSystemSnapshot(): Promise<SystemSnapshot> {
  return await ipc<SystemSnapshot>("verthys_system_snapshot");
}

/* ------------------------------------------------------------------ *
 * GMK IPC 封装（敏感操作下沉）                                        *
 *                                                                    *
 * 主进程仅转发，GMK 派生/验证/改钥全部在 worker 子进程内完成           *
 * 前端不持有 GMK，模块独立密钥由前端 AES-GCM 直接加密验证器           *
 * ------------------------------------------------------------------ */

/** 修改全局密钥结果（后端单命令已完成核验、落盘、清理与 GMK 换槽） */
export interface ChangeGlobalKeyResult {
  /** 新权威记录 id */
  id: number;
  /** 新权威记录 base64 */
  recordB64: string;
  /** 已确认删除的旧记录 id */
  deletedIds: number[];
  /** 新记录已落盘但旧记录未清理干净（下次解锁自动收敛） */
  cleanupPending: boolean;
}

/** 修改全局密钥（单命令：旧钥核验 → 新钥派生 → 写新/删旧 → 换槽）
 *
 * 失败时抛出 Error（含 errorCode / retryAfterSecs），由调用方按码映射提示；
 * 不在此函数内折叠错误，避免把"旧钥错误"与"落盘失败"混为一谈。
 */
export async function verthysChangeGlobalKey(
  oldPassword: string,
  oldBinDataB64: string,
  oldBinPassword: string,
  newPassword: string,
  newBinDataB64: string,
  newBinPassword: string
): Promise<ChangeGlobalKeyResult> {
  const r = await ipc<VerthysResponse>("verthys_change_global_key", {
    oldPassword,
    oldBinDataB64,
    oldBinPassword,
    newPassword,
    newBinDataB64,
    newBinPassword,
  });
  if (!r.ok || r.id == null || !r.data) {
    const e = new Error(r.error || "修改全局密钥失败") as Error & {
      errorCode?: string;
      retryAfterSecs?: number;
    };
    e.errorCode = r.error_code ?? r.error ?? undefined;
    e.retryAfterSecs = r.retry_after_secs ?? undefined;
    throw e;
  }
  return {
    id: r.id,
    recordB64: r.data,
    deletedIds: r.ids ?? [],
    cleanupPending: r.cleanup_pending ?? false,
  };
}

/** 派生并持久化全局密钥（首次初始化专用，敏感操作下沉）
 *
 * worker 进程内原子完成「派生 → 收敛残留记录 → 写入 → 读回逐字节
 * 验证」，响应内联返回记录 lid 与 recordB64。存储不经 add_record
 * 命令——派生、落盘与读回验证在同一 worker 调用内原子完成，不产生
 * 派生存放跨两次 IPC 的中间态窗口。
 *
 * 失败（派生失败/写失败/读回不一致）由 worker 内部统一补偿：
 * 清 GMK + 回收半成品记录，前端仅需按错误引导用户重试。
 *
 * @returns { id, recordB64 } — recordB64 已确认落盘且读回一致
 * @throws Error 后端返回 ok=false 时抛出，message 为后端错误描述
 */
export async function verthysDeriveAndStoreGlobalKey(
  password: string,
  binDataB64: string,
  binPassword: string
): Promise<{ id: number; recordB64: string }> {
  const r = await ipc<VerthysResponse>("verthys_derive_and_store_global_key", {
    password,
    binDataB64,
    binPassword,
  });
  if (!r.ok || r.id == null || !r.data) {
    throw new Error(r.error || "派生并持久化全局密钥失败");
  }
  return { id: r.id, recordB64: r.data };
}

/** 验证全局密钥（后续进入时）
 *
 * 失败时抛出 Error（含后端错误消息），而非返回 false：
 * 调用方 verifyGlobalKey 需要区分状态不匹配 / 冷却中 / 密码长度不足 /
 * bin 数据校验失败等具体原因；errFromUnknown 捕获后把后端原始消息保留
 * 在 VerthysResult.message / cause 中，便于诊断。
 *
 * @param recordB64 verthys 中存储的全局密钥记录（base64）
 * @returns true 验证成功，worker 内存持有 GMK
 * @throws Error 后端返回 ok=false 时抛出，message 为后端错误描述
 */
export async function verthysVerifyGlobalKey(
  password: string,
  binDataB64: string,
  binPassword: string,
  recordB64: string
): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_verify_global_key", {
    password,
    binDataB64,
    binPassword,
    recordB64,
  });
  if (!r.ok) {
    /* 保留结构化错误码与锁定秒数：调用方据此展示“已锁定 X 秒”或门禁
     * 不可用提示，而非仅得到一个布尔值。 */
    const e = new Error(r.error || "验证全局密钥失败") as Error & {
      errorCode?: string;
      retryAfterSecs?: number;
    };
    e.errorCode = r.error_code ?? r.error ?? undefined;
    e.retryAfterSecs = r.retry_after_secs ?? undefined;
    throw e;
  }
  return true;
}

/** 清零 worker 内存中的 GMK（lockAll 时调用） */
export async function verthysClearGlobalKey(): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_clear_global_key");
  return r.ok;
}

/** 幂等强制复位全局密钥状态（失败补偿链最终兜底）
 *
 * 后端强制：GMK 清零（best-effort）+ 状态机任何状态回 NoKey。
 * 供前端补偿动作（clear/reconcile）连续失败后调用，保证不残留
 * 中间态死锁；任何状态下调用均幂等成功。
 */
export async function verthysResetGlobalKeyState(): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_reset_global_key_state");
  return r.ok;
}

/** 协调全局密钥存在状态（修正 probe 冲突导致的前后端状态不同步）
 *
 * 场景：
 *   verthys_unlock 时 worker 进程内 probe 通过 find_first_lid_by_type(0x10)
 *   搜索全局密钥记录。但 TYPE_GLOBAL_KEY(0x10) 与旧 TYPE_ACCOUNT(0x10) 冲突，
 *   probe 可能命中账户记录 → has_global_key 误判 → 后端 key_lifecycle 状态错误。
 *
 *   前端 migrateRecordTypes 将旧账户记录重写为 0x02 后重新校验（findGlobalKeyRecord），
 *   得到正确结果。本函数将正确结果同步到后端，修正 key_lifecycle 状态机。
 *
 * 调用时机：initUnlock 关键路径中，migrateRecordTypes + 重新校验完成之后。
 *
 * @param hasGlobalKey 前端重新校验的全局密钥存在状态
 * @returns true 表示后端状态已修正（或已匹配无需修正）
 */
export async function verthysReconcileKeyPresence(hasGlobalKey: boolean): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_reconcile_key_presence", { hasGlobalKey });
  return r.ok;
}
