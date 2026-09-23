/*
 * verthys.ts — 前端唯一与后端通信的接口层（最小指令白名单）
 *
 * 设计原则（codebase-design 深模块）：
 *   - 前端仅能调用预定义的受限 Tauri 指令，无法自定义调用 DLL 底层接口
 *   - 文件二进制数据经 Tauri v2 raw IPC（ArrayBuffer 请求体 +
 *     tauri::ipc::Response 响应）直传，零 base64 编解码；账号序列化等
 *     小体量数据仍走 base64 in JSON 协议
 *   - 前端不含任何加密、密钥、文件读写逻辑，完全无安全权重
 *
 * 分层架构：
 *   types/verthys.ts            ← 类型定义
 *   constants/verthys_const.ts  ← 常量定义
 *   utils/binary_codec.ts     ← base64/hex/ArrayBuffer 编解码
 *   utils/json_codec.ts       ← 通用 JSON↔base64 序列化
 *   utils/invoke_wrapper.ts   ← 统一带超时 invoke 包装
 *   lib/verthys_error.ts        ← 标准化 IPC 通信错误
 *   lib/crypto.ts             ← encryptPasswordField/decryptPasswordField
 *   lib/verthys.ts              ← 纯 IPC 调用（本文件）
 *
 * 重构后 verthys.ts 仅保留纯 IPC 调用，不再包含任何加密实现。
 * 所有 Tauri 调用逻辑、前后端字段映射、批量游标逻辑 100% 不变。
 */

import { invokeWithTimeout } from "../utils/invoke_wrapper";
import { wrapAsVerthysError, ipcFailed } from "./verthys_error";
import { serializeToJsonB64, deserializeFromJsonB64 } from "../utils/json_codec";
import { withTimeout } from "../utils/promise_utils";
import { Channel } from "@tauri-apps/api/core";
// 前端 IPC 优先级门控：关键 IPC 调用标记前端活跃，后台任务据此让出 worker 通道
import { markFrontendIpcActive } from "../core/frontend-ipc-priority";

import type {
  VerthysResponse,
  VerthysRecordEntry,
  VerthysSummaryEntry,
  EnumerateBatch,
  AccountFields,
  RecordEntry,
  PreflightResult,
  InitStatusResult,
  VerthysPreset,
  BruteForceCheckResponse,
  BruteForceStatus,
  UnknownModuleInfo,
  ShadowSleepStatus,
  SecurityPresetCode,
  PresetConfig,
  PresetFeatures,
  SecurityStatusReport,
  UnlockProgress,
  ClipboardResult,
  PrivacyModeResult,
  BatchRecordInput,
  ImportBatchProgress,
  ImportBeginResult,
  AddRecordsBatchResult,
  WalRecoverResult,
  DeviceBindingResult,
} from "../types/verthys";

import {
  VERTHYS_PRESET_BALANCED,
} from "../constants/verthys_const";

/* ------------------------------------------------------------------ *
 * 再导出（保持对外 API 完全不变）                                      *
 *                                                                    *
 * 上层组件和 keyManager 分层通过 `from "../../lib/verthys"` 导入       *
 * 类型、常量、加密函数，此处再导出确保页面零改动。                     *
 * ------------------------------------------------------------------ */

// 类型再导出
export type {
  VerthysResponse,
  VerthysRecordEntry,
  VerthysSummaryEntry,
  EnumerateBatch,
  AccountFields,
  RecordEntry,
  PreflightResult,
  InitStatusResult,
  VerthysPreset,
  BruteForceCheckResponse,
  BruteForceStatus,
  UnknownModuleInfo,
  ShadowSleepStatus,
  SecurityPresetCode,
  PresetConfig,
  SecurityStatusReport,
  UnlockProgress,
  ClipboardResult,
  PrivacyModeResult,
  BatchRecordInput,
  ImportBatchProgress,
  ImportBeginResult,
  AddRecordsBatchResult,
  WalRecoverResult,
  DeviceBindingResult,
} from "../types/verthys";
export type { PresetFeatures } from "../types/verthys";

// 常量再导出
export {
  VERTHYS_PRESET_BALANCED,
  VERTHYS_PRESET_SECURE,
  SECURITY_PRESET_BALANCED,
  SECURITY_PRESET_SECURE,
  SECURITY_PRESET_PERFORMANCE,
  SECURITY_PRESET_CUSTOM,
} from "../constants/verthys_const";

// 加密函数再导出（从 crypto.ts 迁移，verthys.ts 不再包含加密实现）
export { encryptPasswordField, decryptPasswordField } from "./crypto";

/* ------------------------------------------------------------------ *
 * 私有 IPC 包装 — 统一错误标准化                                       *
 *                                                                    *
 * 所有 Tauri invoke 调用经由 ipc() 包装：                             *
 *   - invoke 抛出的原生错误自动包装为 VerthysError                      *
 *   - VerthysError extends Error，与全局 error-handler 兼容              *
 *   - 调用逻辑、参数、返回值处理 100% 不变                             *
 * ------------------------------------------------------------------ */

async function ipc<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return await invokeWithTimeout<T>(cmd, args);
  } catch (e) {
    throw wrapAsVerthysError(e);
  }
}

/* ------------------------------------------------------------------ *
 * 账号字段序列化（JSON ↔ base64）                                     *
 *                                                                    *
 * 使用通用 json_codec 工具，消除重复的 JSON.stringify + TextEncoder   *
 * ------------------------------------------------------------------ */

/** 将账号字段序列化为 base64（JSON → UTF-8 → base64） */
export function serializeAccount(acc: AccountFields): string {
  return serializeToJsonB64(acc);
}

/** 将 base64 反序列化为账号字段 */
export function deserializeAccount(b64: string): AccountFields {
  return deserializeFromJsonB64<AccountFields>(b64);
}

/* ------------------------------------------------------------------ *
 * base64 编解码（从 utils/binary_codec 再导出，保持 API 不变）        *
 * ------------------------------------------------------------------ */

export { bytesToBase64, base64ToBytes } from "../utils/binary_codec";

/* ------------------------------------------------------------------ *
 * Tauri 指令封装（最小白名单）                                        *
 * ------------------------------------------------------------------ */

/** 初始化 worker 子进程（加载 DLL，创建上下文）
 *  dllPath 参数已废弃：后端强制自动解析 DLL 绝对路径，前端传空即可
 *
 *  注意：调用方应优先使用 ensureWorkerReady() / preloadWorker() 以复用预启动会话，
 *  避免重复 spawn 子进程。直接调用本函数会绕过 memoization 缓存。
 */
export async function workerInit(dllPath: string = ""): Promise<boolean> {
  const r = await ipc<VerthysResponse>("worker_init", { dllPath });
  return r.ok;
}

/** 销毁 worker 子进程（杀死进程，销毁所有句柄与密钥） */
export async function workerDestroy(): Promise<boolean> {
  try {
    const r = await ipc<VerthysResponse>("worker_destroy");
    return r.ok;
  } finally {
    // 修复：无论 worker_destroy 成功/失败/超时，都作废预启动缓存
    //   原缺陷：invalidateWorkerPreload 在 await 之后，若 IPC 超时/异常则永不执行
    //   → workerReadyPromise 残留指向已销毁 worker → 下次 ensureWorkerReady 复用死 worker
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

/** 修复：worker 是否已被使用（unlock/create 成功过）
 *
 * 用于 ensureCleanWorkerState 区分两种 workerReadyPromise !== null 场景：
 *   - workerHasBeenUsed=false：worker 仅预启动，尚未解锁 → 预启动有效，复用
 *   - workerHasBeenUsed=true：worker 曾解锁过，可能因 lockAll 未完成而残留 → 强制销毁重建
 *
 * verthysUnlock/verthysCreate 成功后置 true；
 * verthysLock/workerDestroy/invalidateWorkerPreload 置 false。 */
let workerHasBeenUsed = false;

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
  workerHasBeenUsed = false;
}

/* ------------------------------------------------------------------ *
 * 修复：确保解锁前 worker 处于干净状态                         *
 *                                                                    *
 * 根治"回退重选 verthys 卡死"和"安全核心启动失败"根因：                   *
 *   用户回退 → goBackToUnlock → lockAll → doLockAll 同步置            *
 *   verthysReady=false → UI 立即显示解锁视图 → 用户重选 verthys →          *
 *   doUnlock → initUnlock → ensureWorkerReady 复用旧 workerReadyPromise *
 *   → verthysUnlock IPC 发往正在被 lockAll 销毁的 worker → 永久卡死。    *
 *                                                                    *
 *   以及：lockAll 的 verthysLock 仅销毁 VerthysSessionGuard，不销毁 worker  *
 *   子进程，worker 状态仍为 Ready。下次 worker_init 因状态不匹配失败。  *
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
  // 修复：无条件销毁 worker，消除"状态仍为 Ready"导致的 worker_init 失败
  //
  // 原实现仅在 workerReadyPromise !== null && workerHasBeenUsed 时销毁，
  // 但 lockAll 的 verthysLock()/workerDestroy() 会在 finally 中调用
  // invalidateWorkerPreload() 清空 workerReadyPromise 和 workerHasBeenUsed，
  // 导致此处的条件不满足，无法兜底销毁后端 worker。
  //
  // 新实现无条件调用 worker_destroy（5s 超时兜底），后端对不存在的 worker 为空操作。
  // 这确保任何路径下（包括 lockAll 超时/失败/部分完成）worker 都被彻底清理。
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

/** 创建新加密库（首次初始化专用，与 unlock 分离）
 *  流程：create_with_preset（创建新 verthys + 写入预设）→ lock（写盘）→ unlock（重开）
 *  失败自动回滚：删除不完整 .verthys 文件 + 销毁 worker
 *
 *  preset: v2 安全预设
 *    - VERTHYS_PRESET_BALANCED (0)：日常推荐（默认）
 *    - VERTHYS_PRESET_SECURE (1)：涉密/合规
 */
export async function verthysCreate(
  verthysPath: string,
  password: string,
  preset: VerthysPreset = VERTHYS_PRESET_BALANCED
): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_create", { verthysPath, password, preset });
  if (r.ok) {
    // 修复B：标记 worker 已被使用（create 内部会 unlock 重开）
    // ensureCleanWorkerState 据此判断：下次解锁前若 workerHasBeenUsed=true
    // 且预启动缓存残留 → 强制销毁旧 worker，防止复用被 lockAll 销毁中的死 worker
    workerHasBeenUsed = true;
  }
  return r.ok;
}

/** 第一层：选择即预热 — 用户选择 .verthys 文件后立即后台预读索引区到 OS 页缓存
 *  fire-and-forget：返回 true 表示预热已启动（不等待完成）
 *  安全边界：纯文件 I/O，不加载 DLL、不接触密钥、不解密任何数据
 *
 *  实现细节：
 *  - v2 格式：从超级块明文头部（前 128 字节）读取 index_region_off/size，
 *    顺序预读索引区到页缓存
 *  - v1 格式：顺序预读整个文件
 *  - 使用 Windows FILE_FLAG_SEQUENTIAL_SCAN 提示 OS 预读
 *  - 性能收益：磁盘 I/O 耗时从 3~5 秒移出关键路径，与密码输入时间重叠
 */
export async function verthysPreheat(verthysPath: string): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_preheat", { verthysPath });
  return r.ok;
}

/** 解锁已有加密库（worker 内调用 Verthys_Unlock）
 *
 * 新增 onProgress 可选回调，流式接收解锁进度
 * - worker 在解锁期间推送多条 unlock_progress 进度行
 * - 每条进度行通过 Tauri Channel 转发到前端 onProgress 回调
 * - 后端进度感知超时（60s 无进度才判定挂起），无需前端 Promise.race 兜底
 *
 * @param verthysPath 加密库文件路径
 * @param password 解锁密码
 * @param onProgress 进度回调（在解锁各阶段触发，可选）
 * @returns 解锁响应（含 has_global_key/global_key_id/global_key_record 进程内探测结果）
 */
export async function verthysUnlock(
  verthysPath: string,
  password: string,
  onProgress?: (progress: UnlockProgress) => void,
): Promise<VerthysResponse> {
  // 创建 Tauri Channel 用于流式接收进度
  const channel = new Channel<UnlockProgress>();

  /* 修复修复：阻止 Promise resolve 后的 Channel 残留进度消息
   *
   * 根因：Tauri Channel 的 onmessage 是异步处理的。当 verthys_unlock 命令返回
   * （Promise resolve）时，Channel 队列中可能仍有未消费的进度消息（如 Argon2id
   * 心跳"密钥计算较慢"）。这些残留消息会在 Promise resolve 后继续被 onmessage
   * 处理，覆盖 initUnlock 中 emit(8,100,"解锁完成…") 设置的 UI 状态，
   * 导致 UI 从"解锁完成"变回"密钥计算较慢"，用户误以为解锁卡住。
   *
   * 修复：使用 completed 标志，Promise resolve/reject 后阻止 onProgress 回调。
   *   - resolve 前：正常转发进度消息
   *   - resolve 后：静默丢弃残留消息（initUnlock 的 emit 已负责最终 UI 状态）
   *
   * 安全边界：仅影响前端进度 UI 展示，不影响后端解锁逻辑。
   *           后端 send_json_with_unlock_progress 同步返回最终结果。 */
  let completed = false;
  if (onProgress) {
    channel.onmessage = (p: UnlockProgress) => {
      if (!completed) {
        onProgress(p);
      }
    };
  }

  try {
    /* 修复：返回完整 VerthysResponse，含 worker 进程内探测的
     * has_global_key/global_key_id/global_key_record 三字段。
     * 调用方 initUnlock 直接消费，消除解锁后 probe IPC 链。 */
    const resp = await ipc<VerthysResponse>("verthys_unlock", {
      verthysPath,
      password,
      onProgress: channel,
    });
    if (resp.ok) {
      // 修复B：标记 worker 已被使用（unlock 成功）
      // ensureCleanWorkerState 据此判断：下次解锁前若 workerHasBeenUsed=true
      // 且预启动缓存残留 → 强制销毁旧 worker，防止复用被 lockAll 销毁中的死 worker
      workerHasBeenUsed = true;
    }
    return resp;
  } finally {
    /* 关键：Promise resolve/reject 后立即置位，阻止后续 Channel 残留消息
     * 覆盖 UI 状态。finally 块在 return/throw 前执行，确保标志及时生效。 */
    completed = true;
  }
}

/** 持久化落盘（发送 lock 指令并等待响应，不销毁 worker）— 7步流程步骤4+5 */
export async function verthysLockPersist(): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_lock_persist");
  return r.ok;
}

/** 销毁 worker 并清理资源（剪贴板+文件锁）— 7步流程步骤7
 *  注意：verthys_lock 会销毁 worker 子进程，因此同步作废预启动缓存
 *  修复：invalidateWorkerPreload 移至 finally 块，
 *    确保 IPC 超时/异常时也作废缓存（根治 workerReadyPromise 残留指向死 worker） */
export async function verthysLock(): Promise<boolean> {
  try {
    const r = await ipc<VerthysResponse>("verthys_lock");
    return r.ok;
  } finally {
    // 无论 verthys_lock 成功/失败/超时，都作废预启动缓存
    invalidateWorkerPreload();
  }
}

/** 刷新加密库（lock 写盘 → unlock 重新打开，worker 保持存活） */
export async function verthysFlush(verthysPath: string, password: string): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_flush", { verthysPath, password });
  return r.ok;
}

/** 磁盘级持久化验证（只读，绕过 worker 内存，直接校验磁盘文件）
 *
 *  消除"内存可见、磁盘丢失"的假成功：persistVerthys 成功后回读 worker 内存
 *  无法检测磁盘是否真正写入（v1 AddRecord 仅写内存）。本命令绕过 worker，
 *  直接读取磁盘文件，校验 flush 确实将数据写入了磁盘文件。
 *
 *  验证项（全部只读，不解密、不接触密钥、不修改文件、不改变 worker 状态）：
 *    1. 文件存在且非空
 *    2. magic "VERT" 合法
 *    3. mtime 时效性：文件修改时间在 15s 内（核心检测项）
 *    4. v2 超级块明文字段一致性 / v1 头部字段一致性
 *    5. expectedRecordCount 弱大小合理性检查
 *
 *  @param verthysPath 加密库文件路径
 *  @param expectedRecordCount 期望记录数（可选，用于弱大小校验）
 *  @returns true=磁盘文件已落盘且结构完整，false=验证失败
 */
export async function verthysVerifyDiskPersist(
  verthysPath: string,
  expectedRecordCount?: number
): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_verify_disk_persist", {
    verthysPath,
    expectedRecordCount: expectedRecordCount ?? null,
  });
  return r.ok;
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
 * Comprehensive_optimization：照片导入异步批处理流水线 IPC 封装      *
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
 * 创建导入会话：初始化 WAL + 从既有快照恢复 committed_hashes（续传去重）。
 *
 * 流程：
 *   1. 防重入：后端检查是否已存在活跃会话，存在则拒绝
 *   2. 创建 ImportSession：加载遗留 WAL 快照 → 恢复 committed_hashes → 截断 WAL 写 begin
 *   3. 返回 import_id + committed_hashes（供生产者去重）
 *
 * @param verthysPath 可选 verthys 路径（不传则从当前会话守卫读取）
 * @returns { ok, import_id, hashes, total_count }
 */
export async function verthysImportBegin(
  verthysPath?: string,
): Promise<ImportBeginResult> {
  const r = await ipc<VerthysResponse>("verthys_import_begin", {
    verthysPath: verthysPath ?? null,
  });
  return {
    ok: r.ok,
    import_id: r.import_id ?? "",
    hashes: r.hashes ?? [],
    total_count: r.total_count ?? 0,
    error: r.error,
  };
}

/**
 * 批量写入 N 条已加密记录（WAL pending → worker add_record 串行 → WAL committed → 检查点）。
 *
 * 「N 次加密，1 次 IPC 传输」：前端 Worker 池并行加密 N 条记录后，单次 IPC 写入。
 * 后端串行调用 worker add_record，每条伴随 WAL pending/committed，每批次结束写检查点。
 * 通过 onProgress Channel 流式推送进度，前端在 requestAnimationFrame 内绘制进度条。
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
 * 关闭导入会话：success=true 触发 WAL 压缩，failure 保留 WAL 供续传。
 *
 * @param success 是否成功完成（true 压缩 WAL，false 保留供续传）
 * @returns { ok, total_count, import_id }
 */
export async function verthysImportEnd(
  success: boolean,
): Promise<{ ok: boolean; total_count: number; import_id: string; error?: string }> {
  const r = await ipc<VerthysResponse>("verthys_import_end", { success });
  return {
    ok: r.ok,
    total_count: r.total_count ?? 0,
    import_id: r.import_id ?? "",
    error: r.error,
  };
}

/**
 * 查询当前导入会话的检查点状态（累计 committed 计数 + 去重哈希集）。
 *
 * 用于前端在导入过程中查询实时进度，或断点续传前确认当前状态。纯只读。
 *
 * @returns { ok, import_id, hashes, total_count, batch_id }
 */
export async function verthysImportCheckpoint(): Promise<{
  ok: boolean;
  import_id: string;
  hashes: string[];
  total_count: number;
  batch_id: number;
  error?: string;
}> {
  const r = await ipc<VerthysResponse>("verthys_import_checkpoint");
  return {
    ok: r.ok,
    import_id: r.import_id ?? "",
    hashes: r.hashes ?? [],
    total_count: r.total_count ?? 0,
    batch_id: r.batch_id ?? 0,
    error: r.error,
  };
}

/**
 * 扫描遗留 WAL，返回 committed 哈希集（续传去重，不创建新会话）。
 *
 * 应用启动时或导入前调用，检查是否存在遗留 WAL（上次崩溃/关闭未完成）：
 *   - WAL 不存在 → 返回空哈希集（无需续传）
 *   - WAL 存在且未 end → 返回 committed 哈希集（续传去重依据）
 *
 * @param verthysPath 可选 verthys 路径（不传则从当前会话守卫读取）
 * @returns { ok, hashes, total_count, import_id?, batch_id?, processed_count? }
 */
export async function verthysWalRecover(
  verthysPath?: string,
): Promise<WalRecoverResult> {
  const r = await ipc<VerthysResponse>("verthys_wal_recover", {
    verthysPath: verthysPath ?? null,
  });
  return {
    ok: r.ok,
    hashes: r.hashes ?? [],
    total_count: r.total_count ?? 0,
    import_id: r.import_id,
    batch_id: r.batch_id,
    processed_count: r.processed_count,
    error: r.error,
  };
}

/** 读取记录（返回 base64 数据） */
export async function verthysGetRecord(
  id: number
): Promise<{ type: number; name: string; dataB64: string } | null> {
  const r = await ipc<VerthysResponse>("verthys_get_record", { id });
  if (!r.ok) return null;
  return {
    type: r.rtype ?? 0,
    name: r.name ?? "",
    dataB64: r.data ?? "",
  };
}

/**
 * 批量枚举记录（一次 IPC 调用获取所有记录）
 * 替代前端逐条探测的 enumerateRecords，消除 N 次 IPC 往返开销
 * @param startId 增量扫描起始 ID（从该 ID 开始顺序读取）
 * @returns 记录数组（id/type/name/dataB64）
 */
export async function verthysEnumerateRecords(
  startId: number = 1
): Promise<{ id: number; type: number; name: string; dataB64: string }[]> {
  // 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
  markFrontendIpcActive();
  const r = await ipc<VerthysResponse>("verthys_enumerate_records", { startId });
  if (!r.ok || !r.records) return [];
  return r.records.map(e => ({
    id: e.id,
    type: e.rtype,
    name: e.name,
    dataB64: e.data,
  }));
}

/**
 * 项5：流式枚举记录（Tauri Channel 分页推送）
 *
 * 替代一次性 verthysEnumerateRecords（数千条记录 JSON.parse 阻塞主线程 100ms+）。
 * 后端循环调用 worker enumerate_records（每批 batchSize 条），
 * 每批通过 onBatch Channel 推送到前端，前端收到一批即渲染一批。
 *
 * 用户感知：渐进式加载（首批 200 条 100ms 内到达），而非"瞬间冻结后爆发"。
 * 单批 JSON 体积小，JSON.parse 耗时 < 5ms，主线程不阻塞。
 *
 * @param startId 起始记录 ID（首屏传 1，后续批 = 上一批 last_id + 1）
 * @param batchSize 每批最多返回条数（默认 200，上限 500）
 * @param onBatch 每批到达回调（参数含 records/last_id/count/exhausted/total_pushed）
 * @returns 累计推送总数（exhausted=true 时表示已遍历完毕）
 */
export async function verthysEnumerateRecordsStream(
  startId: number,
  batchSize: number,
  onBatch: (batch: EnumerateBatch) => void,
): Promise<number> {
  // 创建 Tauri Channel 用于流式接收批次（与 verthysUnlock 模式一致）
  const channel = new Channel<EnumerateBatch>();
  channel.onmessage = onBatch;

  const r = await ipc<VerthysResponse>("verthys_enumerate_records_stream", {
    startId,
    batchSize,
    onBatch: channel,
  });
  // 返回累计推送总数（后端 record_count 字段）
  return r.record_count ?? 0;
}

/* ------------------------------------------------------------------ *
 * 游标批量扫描（双缓冲流水线预取，替代逐条 enumerate_records）        *
 *                                                                    *
 * 架构：                                                             *
 *   - verthysScanOpen  → 打开游标，返回首批记录 + exhausted 标记       *
 *   - verthysScanNext  → 返回下一批记录（后台预取已就绪）+ exhausted    *
 *   - verthysScanClose → 关闭游标，释放所有资源                        *
 *                                                                    *
 * 前端用法：                                                         *
 *   const first = await verthysScanOpen(0, 1000);                      *
 *   process(first.records);                                          *
 *   while (!first.exhausted) {                                       *
 *     const next = await verthysScanNext(1000);                        *
 *     process(next.records);                                         *
 *     if (next.exhausted) break;                                     *
 *   }                                                                *
 *   await verthysScanClose();                                          *
 * ------------------------------------------------------------------ */

/** 打开扫描游标，返回首批记录
 * @param startId 起始记录 ID（0 表示从头扫描）
 * @param batchSize 单批拉取条数（<1KB 记录建议 1000~2000，>1KB 建议 200~500）
 * @returns 首批记录列表 + 是否遍历结束
 * @throws 当后端 scan_open 失败时抛异常（v1 格式不支持游标扫描等）
 *
 * 失败时不静默返回空记录，而是抛异常让调用方决定回退策略。
 * 原因：scan_open 返回 ok=false 可能是"v1 格式不支持"或"熔断"等错误，
 * 静默返回空会导致 ensureRecordScan 误认为"verthys 为空"，模块内容不显示。
 */
export async function verthysScanOpen(
  startId: number = 0,
  batchSize: number = 1000
): Promise<{ records: { id: number; type: number; name: string; dataB64: string }[]; exhausted: boolean }> {
  // 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
  markFrontendIpcActive();
  const r = await ipc<VerthysResponse>("verthys_scan_open", { startId, batchSize });
  if (!r.ok) {
    throw ipcFailed(`scan_open failed: ${r.error ?? "unknown error"}`);
  }
  const records = (r.records || []).map(e => ({
    id: e.id,
    type: e.rtype,
    name: e.name,
    dataB64: e.data,
  }));
  return { records, exhausted: r.exhausted ?? false };
}

/** 拉取下一批记录（双缓冲流水线切换）
 * @param batchSize 单批拉取条数（与 open 时一致）
 * @returns 下一批记录列表 + 是否遍历结束
 */
export async function verthysScanNext(
  batchSize: number = 1000
): Promise<{ records: { id: number; type: number; name: string; dataB64: string }[]; exhausted: boolean }> {
  const r = await ipc<VerthysResponse>("verthys_scan_next", { batchSize });
  if (!r.ok) return { records: [], exhausted: true };
  const records = (r.records || []).map(e => ({
    id: e.id,
    type: e.rtype,
    name: e.name,
    dataB64: e.data,
  }));
  return { records, exhausted: r.exhausted ?? false };
}

/** 关闭扫描游标，释放所有资源（共享内存、C 游标、预取任务） */
export async function verthysScanClose(): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_scan_close", {});
  return r.ok;
}

/* ------------------------------------------------------------------ *
 * 摘要扫描（轻量元数据，不读数据块）                        *
 *                                                                    *
 * 与全量扫描的区别：                                                  *
 *   - 仅返回 lid/type/name/data_size/physical_offset/merkle_leaf     *
 *   - 不解密数据块，解锁后 1-2 秒内加载全部摘要索引                   *
 *   - 用于列表渲染 + 搜索 + 删除（用户体感零延迟）                    *
 *   - 完整数据按需加载（verthysGetRecord / 全量扫描）                   *
 *                                                                    *
 * 前端用法：                                                          *
 *   const first = await verthysScanSummaryOpen(0, 1000);               *
 *   summaryCache.populate(first.records);                            *
 *   while (!first.exhausted) {                                       *
 *     const next = await verthysScanSummaryNext(1000);                 *
 *     summaryCache.populate(next.records);                           *
 *     if (next.exhausted) break;                                     *
 *   }                                                                *
 *   await verthysScanSummaryClose();                                   *
 * ------------------------------------------------------------------ */

/** 摘要记录（前端简化类型，供 verthys-cache.ts 两层缓存使用）
 * 新增 createdTime（创建时间戳，列表展示用）
 */
export interface SummaryRecord {
  id: number;
  type: number;
  name: string;
  dataSize: number;
  physicalOffset: number;
  merkleLeaf: string;
  createdTime: number;
}

/** 打开摘要扫描游标，返回首批摘要记录
 * @param startId 起始记录 ID（0 表示从头扫描）
 * @param batchSize 单批拉取条数（元数据极小，建议 1000~2000）
 * @returns 首批摘要记录列表 + 是否遍历结束
 * @throws 当后端 scan_summary_open 失败时抛异常（v1 格式不支持 / 熔断等）
 */
export async function verthysScanSummaryOpen(
  startId: number = 0,
  batchSize: number = 1000
): Promise<{ records: SummaryRecord[]; exhausted: boolean }> {
  // 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
  markFrontendIpcActive();
  const r = await ipc<VerthysResponse>("verthys_scan_summary_open", { startId, batchSize });
  if (!r.ok) {
    throw ipcFailed(`scan_summary_open failed: ${r.error ?? "unknown error"}`);
  }
  const records = (r.summary_records || []).map(e => ({
    id: e.id,
    type: e.rtype,
    name: e.name,
    dataSize: e.data_size,
    physicalOffset: e.physical_offset,
    merkleLeaf: e.merkle_leaf,
    createdTime: e.created_time ?? 0,
  }));
  return { records, exhausted: r.exhausted ?? false };
}

/** 拉取下一批摘要记录（双缓冲流水线切换）
 * @param batchSize 单批拉取条数（与 open 时一致）
 * @returns 下一批摘要记录列表 + 是否遍历结束
 */
export async function verthysScanSummaryNext(
  batchSize: number = 1000
): Promise<{ records: SummaryRecord[]; exhausted: boolean }> {
  const r = await ipc<VerthysResponse>("verthys_scan_summary_next", { batchSize });
  if (!r.ok) return { records: [], exhausted: true };
  const records = (r.summary_records || []).map(e => ({
    id: e.id,
    type: e.rtype,
    name: e.name,
    dataSize: e.data_size,
    physicalOffset: e.physical_offset,
    merkleLeaf: e.merkle_leaf,
    createdTime: e.created_time ?? 0,
  }));
  return { records, exhausted: r.exhausted ?? false };
}

/** 关闭摘要扫描游标，释放所有资源（摘要共享内存、C 游标、预取任务） */
export async function verthysScanSummaryClose(): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_scan_summary_close", {});
  return r.ok;
}

/** 删除记录 */
export async function verthysDeleteRecord(id: number): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_delete_record", { id });
  return r.ok;
}

/** 批量删除记录（单次事务，合并为单次 flush）
 *  将整个 ID 列表传给 Rust 层，单次 verthys_flush 一次性移除所有条目，
 *  只做一次重加密和一次全局 HMAC 更新 */
export async function verthysDeleteRecords(ids: number[]): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_delete_records", { ids });
  return r.ok;
}

/** 获取已加载的轻量摘要记录数
 *  返回解锁时从 summary_index_off 加载的摘要记录数。
 *  >0 表示摘要索引可用，前端可直接渲染列表无需 B+ 树扫描。
 *
 *  修复：worker 返回 ok=false 时抛出异常而非返回 0
 *    原 bug：worker 失败时返回 0，调用方误判"verthys 为空"→ UI 显示"初始化密钥"
 *    修复：worker 失败时抛异常，调用方 catch 后走"计数未知"路径，继续第一批扫描
 */
export async function verthysGetSummaryCount(): Promise<number> {
  const r = await ipc<VerthysResponse & { record_count?: number }>(
    "verthys_get_summary_count",
    {}
  );
  if (!r.ok) {
    throw new Error(`verthysGetSummaryCount worker 失败: ${r.error ?? "未知错误"}`);
  }
  return r.record_count ?? 0;
}

/** ：轻量级记录类型存在性检查（只扫摘要索引，不读数据块）
 *
 *  C 层 Verthys_HasRecordByType 直接遍历 B+ 树叶子节点检查 type 字段，
 *  不分配 name 堆内存，不访问数据区块，典型耗时 < 100ms。
 *
 *  用于启动阶段快速判断是否有全局密钥记录，消除"猜超时"设计缺陷。
 *
 *  @param rtype 目标记录类型（如 TYPE_GLOBAL_KEY = 0x10）
 *  @returns true=存在匹配类型的记录，false=不存在
 *  @throws worker 失败时抛异常（v1 容器不支持、worker 未初始化等）
 */
export async function verthysHasRecordByType(rtype: number): Promise<boolean> {
  const r = await ipc<VerthysResponse & { record_count?: number }>(
    "verthys_has_record_by_type",
    { rtype }
  );
  if (!r.ok) {
    throw new Error(`verthysHasRecordByType worker 失败: ${r.error ?? "未知错误"}`);
  }
  return (r.record_count ?? 0) > 0;
}

/** 导出为独立 .verthys 文件 */
export async function verthysExport(
  exportPath: string,
  password: string
): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_export", { exportPath, password });
  return r.ok;
}

/** 导入 .verthys 文件 */
export async function verthysImport(
  importPath: string,
  password: string
): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_import", { importPath, password });
  return r.ok;
}

/** 修改主密码 */
export async function verthysChangePassword(
  oldPw: string,
  newPw: string
): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_change_password", {
    oldPassword: oldPw,
    newPassword: newPw,
  });
  return r.ok;
}

/* ------------------------------------------------------------------ *
 * 动态防护状态查询                                                  *
 *                                                                    *
 * verthysGetSecurityStatus 透传 worker 的 security_status op，          *
 * 返回 7 条攻击路径的阻断/降级/失败状态。                              *
 * 防御状态为进程级事实，锁定态亦可查询。                               *
 * ------------------------------------------------------------------ */

/**
 * 查询动态防护实时状态
 *
 * 调用链：前端 → verthys_security_status → worker security_status
 *   → FFI Verthys_GetSecurityStatus → SecurityStatusReport
 *
 * 7 条攻击路径（path_state 下标）：
 *   0=挂起绕过 1=内存转储 2=休眠取证 3=IAT Hook
 *   4=DLL 劫持 5=进程读取 6=跨设备
 *
 * @returns 防御状态报告（worker 失败时抛异常）
 * @throws Error worker 未初始化或防御状态查询失败
 */
export async function verthysGetSecurityStatus(): Promise<SecurityStatusReport> {
  const r = await ipc<VerthysResponse & { security_status?: SecurityStatusReport }>(
    "verthys_security_status",
    {}
  );
  if (!r.ok || !r.security_status) {
    throw new Error(`verthys_security_status 失败: ${r.error ?? "未知错误"}`);
  }
  return r.security_status;
}

/** 系统运行指标快照（CPU 占用率真实差分采样；无基线时 cpu_usage=null） */
export interface SystemSnapshot {
  cpu_usage: number | null;
}

/** 查询系统运行指标（安全防护面板「CPU / IO 开销」的真实数据源） */
export async function verthysGetSystemSnapshot(): Promise<SystemSnapshot> {
  return await ipc<SystemSnapshot>("verthys_system_snapshot");
}

/* ------------------------------------------------------------------ *
 * GMK 派生 IPC 封装（#2 敏感操作下沉）                                *
 *                                                                    *
 * 主进程仅转发，GMK 派生/验证全部在 worker 子进程内完成               *
 * 前端不持有 GMK，模块独立密钥由前端 AES-GCM 直接加密验证器           *
 * ------------------------------------------------------------------ */

/** 派生全局主密钥 GMK（首次设置）
 *
 * 修复：失败时抛出 Error（含后端错误消息），而非返回 null。
 *
 * 原缺陷：返回 null 丢失后端 VerthysResponse.error 中的具体错误信息
 * （状态不匹配 / 密码长度不足 / bin 数据校验失败等）。调用方
 * initGlobalKey 仅能返回泛化的 E_GLOBAL_KEY_DERIVE_FAILED，用户看到
 * "全局密钥派生失败"却不知具体原因，且 catch 分支无法区分超时与业务失败。
 *
 * 修复：r.ok=false 时抛出 Error(r.error)，errFromUnknown 捕获后保留
 * 后端原始消息于 VerthysResult.message / cause 中，便于 console 诊断。
 * 调用方 initGlobalKey 的 try-catch 已正确处理此抛出路径。
 *
 * @returns record(base64) — 前端写入 verthys 持久化，worker 内存持有 GMK
 * @throws Error 后端返回 ok=false 时抛出，message 为后端错误描述
 */
export async function verthysDeriveGlobalKey(
  password: string,
  binDataB64: string,
  binPassword: string
): Promise<string> {
  const r = await ipc<VerthysResponse>("verthys_derive_global_key", {
    password,
    binDataB64,
    binPassword,
  });
  if (!r.ok || !r.data) {
    throw new Error(r.error || "派生全局密钥失败");
  }
  return r.data;
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
 * 修复：失败时抛出 Error（含后端错误消息），而非返回 false。
 *
 * 原缺陷：返回 false 丢失后端 VerthysResponse.error 中的具体错误信息
 * （状态不匹配 / 冷却中 / 密码长度不足 / bin 数据校验失败等）。
 * 调用方 verifyGlobalKey 仅能返回泛化的 E_GLOBAL_KEY_VERIFY_FAILED。
 *
 * 修复：r.ok=false 时抛出 Error(r.error)，errFromUnknown 捕获后保留
 * 后端原始消息于 VerthysResult.message / cause 中，便于 console 诊断。
 * 调用方 verifyGlobalKey 的 try-catch 已正确处理此抛出路径。
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
    throw new Error(r.error || "验证全局密钥失败");
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

/** 修复：协调全局密钥存在状态（修正 probe 竞态导致的前后端状态不同步）
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

/**
 * 设置隐私模式（防截屏 + 剪贴板保护联动）
 *
 * 关闭隐私模式（enabled=false）要求 auth_token 授权。
 * auth_token 为用户主密码，由前端在用户确认关闭后传入。
 * 未提供 auth_token 时后端返回 PERMISSION_DENIED 错误码。
 *
 * 返回 PrivacyModeResult 结构化结果：
 *   - ok=true, partial_protection=false：隐私模式已按预期切换
 *   - ok=true, partial_protection=true：防截屏已启用但剪贴板监听失败（部分保护）
 *   - ok=false：频率超限 / 未授权 / 全部窗口失败
 *
 * 向后兼容：返回值同时包含 ok 字段，旧代码 r.ok 仍可用。
 */
export async function setPrivacyMode(
  enabled: boolean,
  authToken?: string,
): Promise<PrivacyModeResult> {
  return await ipc<PrivacyModeResult>("set_privacy_mode", {
    enabled,
    authToken: authToken ?? null,
  });
}

/**
 * 事务式安全清空剪贴板（多次覆写 + 重试）
 *
 * 完整事务序列：OpenClipboard → EmptyClipboard → 3 轮随机覆写 → 最终清空。
 * 剪贴板被占用时自动重试（50ms × 3）。
 *
 * 返回 ClipboardResult 结构化结果：
 *   - ok=true：剪贴板已安全擦除
 *   - ok=false, error_code=CLIPBOARD_LOCKED：剪贴板被占用，重试后仍失败
 *   - ok=false, error_code=RATE_LIMITED：频率超限（>10次/分钟）
 *
 * 向后兼容：返回值包含 ok 字段，旧代码 r.ok 仍可用。
 */
export async function clearClipboard(): Promise<ClipboardResult> {
  return await ipc<ClipboardResult>("clear_clipboard");
}

/**
 * 启动时恢复持久化的隐私模式状态
 *
 * 从 DPAPI 加密的状态文件加载隐私模式状态，自动恢复防截屏 + 剪贴板监听。
 * 应在应用启动后（setup 阶段）调用。
 *
 * 返回 PrivacyModeResult：
 *   - ok=true, enabled=true：隐私模式已恢复
 *   - ok=true, enabled=true, partial_protection=true：部分保护已恢复
 *   - ok=true, enabled=false：无持久化状态或上次为关闭
 */
export async function restorePrivacyMode(): Promise<PrivacyModeResult> {
  return await ipc<PrivacyModeResult>("restore_privacy_mode");
}

/** 读取文件字节（二进制 IPC：返回原始 Uint8Array，去 base64 化）
 *
 *  后端返回 tauri::ipc::Response → invoke 直接收到 ArrayBuffer，
 *  内存峰值 ×1（原 base64 路径 ×2.66：Rust b64 串 + JSON 串 + 前端解码）。
 *
 *  ⚠ 白名单限制：仅允许 app_data / app_config / Documents / Pictures /
 *    Downloads / home_dir / desktop_dir 内的文件。非用户主目录路径
 *    （如 D:\、E:\、网络位置）会被沙箱拒绝。
 *
 *  适用场景：读取应用内部文件、已知白名单路径文件。
 *  不适用：用户通过文件对话框 open() 选择的任意路径文件 → 用 readUserFile。 */
export async function readFileBytes(path: string): Promise<Uint8Array> {
  const buf = await ipc<ArrayBuffer>("read_file_bytes", { path });
  return new Uint8Array(buf);
}

/** 写入原始字节到文件（二进制 IPC：raw body 直传，去 base64 化）
 *
 *  字节经请求体直传（Tauri v2 raw IPC），目标路径经 x-path 请求头传递。
 *  路径经 encodeURIComponent 百分号编码 — HTTP 头仅允许可见 ASCII，
 *  中文用户名路径（如 C:\Users\张三\）必须编码传输，Rust 端严格解码。
 *
 *  ⚠ 白名单限制：同 readFileBytes，仅允许白名单路径。
 *  用户通过对话框 save() 选择的任意路径 → 用 writeUserFile。 */
export async function writeFileBytes(path: string, data: Uint8Array): Promise<void> {
  try {
    await invokeWithTimeout<void>("write_file_bytes", data, undefined, {
      headers: { "x-path": encodeURIComponent(path) },
    });
  } catch (e) {
    throw wrapAsVerthysError(e);
  }
}

/** 读取用户通过对话框显式选择的文件字节（二进制 IPC）
 *
 *  返回原始 Uint8Array（后端 tauri::ipc::Response 二进制通道）。
 *
 *  与 readFileBytes 的区别：跳过沙箱白名单校验（用户已通过 Tauri dialog
 *  open() 显式授权），允许读取任意磁盘/网络位置的文件。
 *
 *  安全保障（后端 read_user_file 命令）：
 *  - validate_path_input 字符级校验（防路径注入、目录遍历、保留设备名）
 *  - canonicalize 解析符号链接（确保路径真实）
 *  - 系统关键目录拒绝（C:\Windows、C:\Program Files 等）
 *  - 文件大小限制（2GB）
 *  - 超时控制（10s）+ 审计日志
 *
 *  适用场景：拾光解析功能导入 .venc 文件、导入照片、读取 .bin 密钥文件等
 *  用户通过文件对话框显式选择的文件。
 *
 *  根治缺陷：原 chooseParseFile 使用 readFileBytes，用户选择的 .venc 文件
 *  若位于 D:\ 等非 home_dir 路径，沙箱返回 PermissionDenied，
 *  前端 catch 块仅显示"读取文件失败"。 */
export async function readUserFile(path: string): Promise<Uint8Array> {
  const buf = await ipc<ArrayBuffer>("read_user_file", { path });
  return new Uint8Array(buf);
}

/** 写入原始字节到用户通过对话框选择的位置（二进制 IPC）
 *
 *  字节经请求体直传（Tauri v2 raw IPC），目标路径经 x-path 请求头传递，
 *  消除 base64 编码 1.33× 内存放大与编解码 CPU 开销。
 *  路径经 encodeURIComponent 百分号编码 — HTTP 头仅允许可见 ASCII，
 *  中文用户名路径（如 C:\Users\张三\）必须编码传输，Rust 端严格解码。
 *
 *  与 writeFileBytes 的区别：跳过沙箱白名单校验（用户已通过 Tauri dialog
 *  save() 显式授权保存位置），允许写入任意磁盘/网络位置。
 *
 *  安全保障：同 readUserFile（系统关键目录拒绝 + 其他安全检查）。
 *
 *  适用场景：导出加密照片到用户选择的保存位置等。 */
export async function writeUserFile(path: string, data: Uint8Array): Promise<void> {
  try {
    await invokeWithTimeout<void>("write_user_file", data, undefined, {
      headers: { "x-path": encodeURIComponent(path) },
    });
  } catch (e) {
    throw wrapAsVerthysError(e);
  }
}

/* ------------------------------------------------------------------ *
 * 设备机器码                                                          *
 * ------------------------------------------------------------------ */

/** 获取当前设备机器码（SHA-256 hex） */
export async function getDeviceFingerprint(): Promise<string> {
  return await ipc<string>("get_device_fingerprint");
}

/** 绑定当前设备机器码到状态文件（首次初始化全局密钥时调用） */
export async function setDeviceBinding(): Promise<void> {
  await ipc<void>("set_device_binding");
}

/**
 * 校验当前设备机器码是否匹配（返回结构化结果）
 *
 * 修复修复：原实现错误声明返回纯字符串 "match"|"mismatch"|"unbound"，
 *   但后端 #[tauri::command] check_device_binding 返回的是 DeviceBindingResult
 *   结构体（JSON 对象：{status, detail, error_code?, match_score?}），导致前端
 *   拿到对象后与字符串比较永远不等 → device_mismatch 拦截视图永久失效 +
 *   deviceCheckResult 状态机紊乱。
 *
 *   现返回 types/verthys.ts 的 DeviceBindingResult 规范类型（单一数据源，
 *   与后端 controller/types.rs serde 序列化严格一致）。 */
export async function checkDeviceBinding(): Promise<DeviceBindingResult> {
  return await ipc<DeviceBindingResult>("check_device_binding");
}

/* ====================================================================== *
 * 安全防护模块（security_commands.rs 对应封装）                          *
 *                                                                        *
 * 七组共 23 个 Tauri 命令的前端封装：
 *   1. 暴力拦截（brute_force）
 *   2. 会话守卫（session_guard）
 *   3. 模块巡检（module_whitelist）
 *   4. 痕迹清理（cleanup）
 *   5. 文件锁与 ACL（file_lock）
 *   6. USB 安全（usb_guard）
 *   7. 三档预设查询（preset）
 * ====================================================================== */

/* -------------------- 1. 暴力拦截 -------------------- */

/** 检查当前是否允许尝试解锁 */
export async function securityBruteCheck(): Promise<BruteForceCheckResponse> {
  return await ipc<BruteForceCheckResponse>("security_brute_check");
}

// 失败计数与成功重置的记录接口已上移服务端口令类命令入口（unlock /
// verify_global_key）权威执行，前端不再提供记录封装，防止同一失败
// 被前后端各计一次。此处仅保留查询与清除类纯读操作。

/** 清除熔断状态（PurgeRequired 处理完成后调用） */
export async function securityBruteClearPurge(): Promise<void> {
  await ipc<void>("security_brute_clear_purge");
}

/** 获取暴力拦截状态快照 */
export async function securityBruteStatus(): Promise<BruteForceStatus> {
  return await ipc<BruteForceStatus>("security_brute_status");
}

/* -------------------- 2. 会话守卫 -------------------- */

/** 启动会话守卫（监听系统锁屏/解锁事件） */
export async function securitySessionStart(): Promise<void> {
  await ipc<void>("security_session_start");
}

/** 停止会话守卫 */
export async function securitySessionStop(): Promise<void> {
  await ipc<void>("security_session_stop");
}

/** 设置高安全模式（启用电源挂起监听 + 更激进的锁屏策略）
 *  后端以 SecurityResult 包装返回：授权拒绝（会话未解锁）时 ok=false，
 *  此处不抛错，将 ok 透传给调用方以便可见地报告失败。 */
export async function securitySessionSetHighSecurity(enabled: boolean): Promise<boolean> {
  const r = await ipc<{ ok: boolean }>("security_session_set_high_security", { enabled });
  return r.ok === true;
}

/* -------------------- 3. 模块巡检 -------------------- */

/** 巡检当前进程已加载模块，返回未知/可疑模块列表
 *  install_dir 为应用安装目录（主 EXE 所在目录） */
export async function securityModulePatrol(installDir: string): Promise<UnknownModuleInfo[]> {
  return await ipc<UnknownModuleInfo[]>("security_module_patrol", { installDir });
}

/** 添加受信任路径到白名单 */
export async function securityAddTrustedPath(path: string): Promise<void> {
  await ipc<void>("security_add_trusted_path", { path });
}

/** 清空受信任路径白名单 */
export async function securityClearTrustedPaths(): Promise<void> {
  await ipc<void>("security_clear_trusted_paths");
}

/* -------------------- 4. 痕迹清理 -------------------- */

/** 清空系统最近使用记录（Recent + 跳转列表 + 通知 Shell） */
export async function securityCleanupRecent(): Promise<void> {
  await ipc<void>("security_cleanup_recent");
}

/** 安全删除文件（Gutmann 35-pass 或 Simple 3-pass 覆写后删除）
 *  mode: "gutmann"=35-pass, "simple"=3-pass */
export async function securitySecureDelete(path: string, mode: "gutmann" | "simple"): Promise<void> {
  await ipc<void>("security_secure_delete", { path, mode });
}

/** 清理崩溃残留临时文件，返回清理文件数 */
export async function securityCleanupCrashResidue(tempDir: string): Promise<number> {
  return await ipc<number>("security_cleanup_crash_residue", { tempDir });
}

/* -------------------- 5. 文件锁与 ACL -------------------- */

/** 加固私有目录 ACL（当前用户完全控制，其他用户拒绝访问） */
export async function securityHardenPrivateDir(dir: string): Promise<void> {
  await ipc<void>("security_harden_private_dir", { dir });
}

/* -------------------- 6. USB 安全 -------------------- */

/** 读取 USB 设备序列号哈希（drive_letter 如 "E"） */
export async function securityUsbReadSerial(driveLetter: string): Promise<string> {
  return await ipc<string>("security_usb_read_serial", { driveLetter });
}

/** 注册已知 USB 设备（卷标 + 序列号哈希） */
export async function securityUsbRegisterDevice(
  volumeLabel: string,
  serialHash: string
): Promise<void> {
  await ipc<void>("security_usb_register_device", { volumeLabel, serialHash });
}

/** 检测克隆外设（true=克隆，false=合法或首次见到） */
export async function securityUsbCheckClone(
  volumeLabel: string,
  serialHash: string
): Promise<boolean> {
  return await ipc<boolean>("security_usb_check_clone", { volumeLabel, serialHash });
}

/** 进入影子休眠（外设拔出后加密索引驻留内存）
 *  timeoutMin: 休眠超时（分钟），超时自动 purge */
export async function securityUsbShadowSleep(
  encryptedIndexB64: string,
  txid: number,
  timeoutMin: number
): Promise<void> {
  await ipc<void>("security_usb_shadow_sleep", {
    encryptedIndexB64,
    txid,
    timeoutMin,
  });
}

/** 尝试从影子休眠恢复加密索引，返回 base64 或 null */
export async function securityUsbTryRecover(txid: number): Promise<string | null> {
  return await ipc<string | null>("security_usb_try_recover", { txid });
}

/** 清除影子休眠中的加密索引（3-round 覆写后清零） */
export async function securityUsbPurge(): Promise<void> {
  await ipc<void>("security_usb_purge");
}

/** 查询影子休眠状态 */
export async function securityUsbShadowStatus(): Promise<ShadowSleepStatus> {
  return await ipc<ShadowSleepStatus>("security_usb_shadow_status");
}

/* -------------------- 7. 预设查询 -------------------- */

/** 获取三档安全预设的配置详情
 *  preset: 0=BALANCED, 1=SECURE, 2=PERFORMANCE */
export async function securityGetPresetConfig(preset: SecurityPresetCode): Promise<PresetConfig> {
  return await ipc<PresetConfig>("security_get_preset_config", { preset });
}

/** 运行时切换安全预设：后端会话授权 → 原子落盘受信文件 → worker →
 *  C 层双缓冲切档（0/1/2 档），成功后返回新档真实配置；失败抛错（明确错误码）。
 *  CUSTOM(3) 无 C 层档位：仅落盘自定义特性并返回其配置，会话层开关由调用方组合。 */
export async function securityApplyPreset(
  code: 0 | 1 | 2 | 3,
  features?: PresetFeatures,
): Promise<PresetConfig> {
  return await ipc<PresetConfig>("security_apply_preset", { code, features });
}

/** 受信持久化的预设状态（后端权威副本）
 *  code: 0=BALANCED, 1=SECURE, 2=PERFORMANCE, 3=CUSTOM
 *  customFeatures: 仅 code=3 时存在 */
export interface PresetPersistState {
  code: number;
  customFeatures?: PresetFeatures | null;
}

/** 读取受信持久化的预设状态；无配置（全新用户/未落盘）返回 null */
export async function securityLoadPresetState(): Promise<PresetPersistState | null> {
  return await ipc<PresetPersistState | null>("security_load_preset_state");
}
