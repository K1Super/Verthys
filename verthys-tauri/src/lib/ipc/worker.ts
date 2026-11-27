/*
 * ipc/worker.ts — 账号字段编解码 + worker 子进程生命周期与预检
 */

import { serializeToJsonB64, deserializeFromJsonB64 } from "../../utils/codec/json_codec";
import { withTimeout } from "../../utils/ipc/promise_utils";
import { ipc } from "./internal";
import type {
  VerthysResponse,
  AccountFields,
  PreflightResult,
  InitStatusResult,
} from "../../types/verthys";

/* ------------------------------------------------------------------ *
 * 账号字段序列化（JSON ↔ base64）                                     *
 *                                                                    *
 * 使用通用 json_codec 工具，消除重复的 JSON.stringify + TextEncoder   *
 * ------------------------------------------------------------------ */
export function serializeAccount(acc: AccountFields): string {
  return serializeToJsonB64(acc);
}

/** 将 base64 反序列化为账号字段 */
export function deserializeAccount(b64: string): AccountFields {
  return deserializeFromJsonB64<AccountFields>(b64);
}

/* ------------------------------------------------------------------ *
 * Tauri 指令封装（最小白名单）                                        *
 * ------------------------------------------------------------------ */

/** 初始化 worker 子进程（加载 DLL，创建上下文）
 *  dllPath 参数不生效：后端强制自动解析 DLL 绝对路径，前端传空即可
 *
 *  注意：调用方应优先使用 ensureWorkerReady() / preloadWorker() 以复用预启动会话，
 *  避免重复 spawn 子进程。直接调用本函数会绕过 memoization 缓存。
 */
/** 最近一次 worker_init 失败的结构化信息（供上层给出专用文案） */
let workerInitFailure: { code?: string; message: string } | null = null;

/** 读取最近一次 worker_init 失败信息（成功时为 null） */
export function getWorkerInitFailure(): { code?: string; message: string } | null {
  return workerInitFailure;
}

export async function workerInit(dllPath: string = ""): Promise<boolean> {
  const r = await ipc<VerthysResponse>("worker_init", { dllPath });
  if (r.ok) {
    workerInitFailure = null;
    return true;
  }
  workerInitFailure = {
    code: r.error_code ?? undefined,
    message: r.error ?? "",
  };
  return false;
}

/** 销毁 worker 子进程（杀死进程，销毁所有句柄与密钥） */
export async function workerDestroy(): Promise<boolean> {
  try {
    const r = await ipc<VerthysResponse>("worker_destroy");
    return r.ok;
  } finally {
    // 无论 worker_destroy 成功/失败/超时，都作废预启动缓存：
    //   若 IPC 超时/异常后跳过作废，workerReadyPromise 会残留指向已销毁 worker，
    //   下次 ensureWorkerReady 复用死 worker。
    invalidateWorkerPreload();
  }
}

/* ------------------------------------------------------------------ *
 * Worker 预启动（memoized）                                           *
 *                                                                    *
 * worker_init 的全部工作（路径探测、运行库检查、DLL 完整性校验、       *
 * 沙箱子进程创建、6 层动态防护）不依赖具体 .verthys 文件内容，            *
 * 仅与安全环境准备有关。因此可在用户选定文件后立即后台预启动，          *
 * 与用户浏览路径、点击「确认」按钮的时间完全重叠。                      *
 *                                                                    *
 * memoization 保证：                                                  *
 *   - 多次调用 preloadWorker / ensureWorkerReady 共享同一 worker_init  *
 *   - 预启动失败时清除缓存，允许后续重试                               *
 *   - worker 销毁后（workerDestroy / verthysLock）自动作废缓存           *
 * ------------------------------------------------------------------ */

/** 当前 worker_init 的 memoized Promise（null 表示无预启动进行中/已完成） */
let workerReadyPromise: Promise<boolean> | null = null;

/** 预启动 Worker 子进程（幂等，可安全多次调用）
 *  不阻塞：返回 Promise，调用方可选 await 或 fire-and-forget
 *  场景：用户选定 .verthys 文件后立即调用，与用户阅读路径、点击确认的时间重叠
 */
export function preloadWorker(): Promise<boolean> {
  if (!workerReadyPromise) {
    // 启动 worker_init 并 memoize；失败时清除缓存以允许重试
    workerReadyPromise = workerInit("").catch((e) => {
      workerReadyPromise = null;
      throw e;
    });
  }
  return workerReadyPromise;
}

/** 确保 Worker 就绪：预启动已完成则立即返回，否则启动并等待
 *  场景：doUnlock / initUnlock / initCreate 内部复用预启动会话
 */
export async function ensureWorkerReady(): Promise<boolean> {
  return preloadWorker();
}

/** 作废预启动缓存（worker 已销毁或用户取消时调用） */
export function invalidateWorkerPreload(): void {
  workerReadyPromise = null;
  workerInitFailure = null;
}

/* ------------------------------------------------------------------ *
 * 确保解锁前 worker 处于干净状态                                       *
 *                                                                    *
 * 背景：lockAll 的 verthysLock 仅销毁 VerthysSessionGuard，不销毁 worker *
 * 子进程，worker 状态仍为 Ready；且 lockAll 会在 finally 调用           *
 * invalidateWorkerPreload() 清空预启动缓存。若此时直接 ensureWorkerReady，*
 * 会 spawn 新 worker 而旧 worker 仍存活，worker_init 因状态不匹配失败，  *
 * 或 IPC 发往正在被销毁的 worker 而卡死。                              *
 *                                                                    *
 * 本函数在 initUnlock/initCreate 起始处调用，确保：                     *
 *   1. 无条件调用 worker_destroy（后端对不存在的 worker 为空操作）      *
 *      彻底销毁可能存活的 worker 子进程 + 重置状态机为 Uninitialized    *
 *   2. 作废预启动缓存 → ensureWorkerReady 启动全新 worker              *
 *                                                                    *
 * 安全性：worker_destroy 后端对不存在的 worker 为空操作（WorkerState=    *
 *   None 时跳过），不会误报错误。无条件调用确保任何路径下 worker 都      *
 *   被彻底清理，消除"状态仍为 Ready"导致的 worker_init 失败。          *
 * ------------------------------------------------------------------ */
export async function ensureCleanWorkerState(): Promise<void> {
  // 无条件销毁 worker（5s 超时兜底）：lockAll 超时/失败/部分完成、
  // 预启动缓存已被清空等路径都必须清理 worker，不能以缓存状态作为判断条件。
  try {
    await withTimeout(ipc<VerthysResponse>("worker_destroy"), 5000, "worker_destroy");
  } catch {
    // worker 可能已销毁（lockAll 已完成），忽略
  }
  invalidateWorkerPreload();
}

/** 路径预检：校验目录存在性、可写性、系统保护目录、磁盘空间 */
export async function verthysPreflight(verthysPath: string): Promise<PreflightResult> {
  return await ipc<PreflightResult>("verthys_preflight", { verthysPath });
}

/** 查询初始化状态（读取 .verthys_state 文件）
 *  none   → 全新用户，首次使用
 *  ready  → 老用户，已有合法 .verthys
 *  broken → 上次初始化失败或文件缺失，已自动清理
 */
export async function verthysInitStatus(): Promise<InitStatusResult> {
  return await ipc<InitStatusResult>("verthys_init_status");
}
