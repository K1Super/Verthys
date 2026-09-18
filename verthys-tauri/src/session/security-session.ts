/*
 * session/security-session.ts — 会话安全层
 *
 * 职责：
 *   1. 会话空闲计时（touchSession / resetSessionTimer / clearSessionTimer）
 *   2. 三档安全预设适配（applySecurityPreset / setSessionTimeout / getSessionTimeout）
 *   3. 暴力拦截门禁（checkBruteForceGate / getBruteForceStatus / clearBruteForcePurge）
 *   4. lockAll 锁定全部（清零缓存 + worker GMK + 重置状态）
 */
import {
  securityBruteCheck, securityBruteRecordFailure, securityBruteRecordSuccess,
  securityBruteClearPurge, securityBruteStatus,
  securitySessionStart, securitySessionStop, securitySessionSetHighSecurity,
  securityGetPresetConfig,
  verthysClearGlobalKey, verthysLock, verthysLockPersist, workerDestroy,
  type SecurityPresetCode, type BruteForceCheckResponse,
} from "../lib/verthys";
import { keyState, setCurrentVerthysPath, loadCustomFeatures, saveSecurityPreset, resetAllState } from "../state/key_state";
import { PRESET_SESSION_TIMEOUT_MS } from "../constants/key_manager_const";
import type { BruteForceGateResult } from "../types/key_manager";
import { clearModuleKeyCache, clearModuleCache, clearRecordScanCache, cancelDebouncedFlush, resetFlushChain, waitForFlush, clearAllCacheTimers, setCacheDirty, clearSummaryCache, clearFullRecordCache } from "../cache/composition/verthys-cache";
// ★ 后台任务 API 直连 core 层（verthys-cache 组合根 §二.2 单向化：不再转发 start/stop）
import { startBackgroundTasks, stopBackgroundTasks } from "../core/background-tasks";

// 导出 securityPresetRef 供 keyManager.ts 再导出
export const securityPresetRef = keyState.securityPreset;

/* ------------------------------------------------------------------ *
 * 会话计时                                                            *
 * ------------------------------------------------------------------ */

/** 会话空闲超时（毫秒），默认 30 分钟 */
let sessionTimeoutMs = 30 * 60 * 1000;

let sessionTimer: number | null = null;

function clearSessionTimer(): void {
  if (sessionTimer !== null) {
    window.clearTimeout(sessionTimer);
    sessionTimer = null;
  }
}

function resetSessionTimer(): void {
  clearSessionTimer();
  sessionTimer = window.setTimeout(() => {
    lockAll();
  }, sessionTimeoutMs);
}

/** 触碰会话（任何用户操作都应调用，重置空闲计时） */
export function touchSession(): void {
  if (keyState.globalKeyReady.value) {
    resetSessionTimer();
  }
}

// 供 global-verthys.ts 调用
export { clearSessionTimer, resetSessionTimer };

/* ------------------------------------------------------------------ *
 * 会话超时设置                                                        *
 * ------------------------------------------------------------------ */

/** 设置会话空闲超时（毫秒），立即生效并重置计时 */
export function setSessionTimeout(ms: number): void {
  const clamped = Math.max(60 * 1000, Math.min(ms, 24 * 60 * 60 * 1000)); // 1 分钟 ~ 24 小时
  sessionTimeoutMs = clamped;
  // 若会话已激活，立即按新时长重置计时
  if (keyState.globalKeyReady.value) {
    resetSessionTimer();
  }
}

/** 获取当前会话空闲超时（毫秒） */
export function getSessionTimeout(): number {
  return sessionTimeoutMs;
}

/* ------------------------------------------------------------------ *
 * 三档安全预设适配                                                    *
 *                                                                    *
 * applySecurityPreset 在初始化成功与用户切换预设时调用：              *
 *   - 更新 securityPresetRef                                          *
 *   - 设置会话空闲超时（按预设档位）                                  *
 *   - 启用/禁用会话守卫的高安全模式（SECURE → 高安全）                *
 * ------------------------------------------------------------------ */

/**
 * 应用三档安全预设
 *  在初始化成功后与用户切换预设时调用
 *  @param preset 0=BALANCED, 1=SECURE, 2=PERFORMANCE, 3=CUSTOM
 *  @returns 该预设的配置详情（含各特性开关）
 */
export async function applySecurityPreset(preset: SecurityPresetCode) {
  keyState.securityPreset.value = preset;
  // 0. 持久化当前预设代号，使应用重启后保持上次选择而非回退默认
  saveSecurityPreset(preset);
  // 1. 按预设调整会话空闲超时
  sessionTimeoutMs = PRESET_SESSION_TIMEOUT_MS[preset];
  if (keyState.globalKeyReady.value) {
    resetSessionTimer();
  }

  // 2. CUSTOM 预设：从 localStorage 读取自定义特性，按需启用高安全模式
  if (preset === 3) {
    const custom = loadCustomFeatures();
    // 高安全模式 = session_lock_on_idle + clip_clear_on_lock
    const highSec = custom.session_lock_on_idle && custom.clip_clear_on_lock;
    try {
      await securitySessionSetHighSecurity(highSec);
    } catch (e) {
      console.warn("[applySecurityPreset] CUSTOM 设置高安全模式失败（非致命）", e);
    }
    // 返回自定义特性配置（包装为 PresetConfig 格式）
    return {
      name: "CUSTOM",
      code: 3,
      features: custom,
    };
  }

  // 3. 标准预设 0/1/2：SECURE 启用高安全模式
  try {
    await securitySessionSetHighSecurity(preset === 1);
  } catch (e) {
    console.warn("[applySecurityPreset] 设置高安全模式失败（非致命）", e);
  }
  // 4. 返回预设配置详情
  try {
    return await securityGetPresetConfig(preset);
  } catch (e) {
    console.warn("[applySecurityPreset] 查询预设配置失败", e);
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * 暴力拦截门禁                                                        *
 *                                                                    *
 * verifyGlobalKeyWithBruteForce 在 verifyGlobalKey 基础上加入：       *
 *   1. 调用前检查暴力拦截状态（Locked/PurgeRequired 直接拒绝）        *
 *   2. 验证成功 → securityBruteRecordSuccess                         *
 *   3. 验证失败 → securityBruteRecordFailure（可能触发锁定/熔断）     *
 *   4. PurgeRequired → 抛出特定错误，SecurityCenter 处理熔断流程      *
 * ------------------------------------------------------------------ */

/** 检查当前是否允许尝试解锁（暴力拦截门禁） */
export async function checkBruteForceGate(): Promise<BruteForceGateResult> {
  try {
    const r: BruteForceCheckResponse = await securityBruteCheck();
    if (r.kind === "Allow") return { allowed: true };
    if (r.kind === "Locked") {
      return { allowed: false, reason: "locked", remainingSecs: r.remaining_secs };
    }
    return { allowed: false, reason: "purge_required" };
  } catch (e) {
    // Tauri 不可用时放行（浏览器模式/开发期）
    console.warn("[checkBruteForceGate] 查询失败，放行", e);
    return { allowed: true };
  }
}

/** 获取暴力拦截状态快照（供 UI 显示失败次数/锁定剩余时间） */
export async function getBruteForceStatus() {
  try {
    return await securityBruteStatus();
  } catch (e) {
    console.warn("[getBruteForceStatus] 查询失败", e);
    return null;
  }
}

/** 清除熔断状态（PurgeRequired 处理完成后调用） */
export async function clearBruteForcePurge(): Promise<void> {
  try {
    await securityBruteClearPurge();
  } catch (e) {
    console.warn("[clearBruteForcePurge] 清除失败", e);
  }
}

/* ------------------------------------------------------------------ *
 * lockAll 锁定全部                                                    *
 *                                                                    *
 * ★ 四层根治方案·第四层（全局应用生命周期兜底）— 7 步流程：           *
 *                                                                    *
 *   步骤 1：取消防抖定时器（在 waitForFlush 内部完成）                *
 *   步骤 2：阻塞等待全部删除、落盘队列执行完成（waitForFlush 12s）    *
 *   步骤 3：清空所有内存缓存（模块数据+会话密钥+记录扫描缓存）        *
 *   步骤 3.5：清除 worker 内存中的 GMK（verthysClearGlobalKey）          *
 *   步骤 4+5：通知 Rust 层执行安全原子落盘 + 等待持久化回执            *
 *            （verthysLockPersist 发送 lock + 8s 等待响应）             *
 *   步骤 6：发送线程停止标记，等待 C 消息线程退出（securitySessionStop）*
 *   步骤 7：销毁 Verthys 工作线程、释放全局锁内存（verthysLock）           *
 *                                                                    *
 * 顺序不可颠倒：                                                      *
 *   - waitForFlush 必须在清空缓存之前：pending delete 的 ID 复用校验   *
 *     需要读取扫描缓存，清空后校验失效                                *
 *   - verthysLockPersist 必须在 securitySessionStop 之前：lock 指令      *
 *     需要 worker 存活                                                *
 *   - securitySessionStop 必须在 verthysLock 之前：防止 C 线程在         *
 *     worker 销毁后触发重入 lockAll                                   *
 * ------------------------------------------------------------------ */

/** 重入保护标志：防止 session_guard on_lock 回调与用户操作并发触发 lockAll */
let lockAllInProgress = false;

/** ★ 企业级根治C：当前 lockAll 的 Promise（null 表示无 lockAll 进行中）
 *
 * 用于 awaitLockAllIfInProgress：外部代码（doUnlock/initUnlock/goBackToUnlock）
 * 可在执行解锁/创建前等待正在进行的 lockAll 完成，避免：
 *   - worker 被 lockAll 销毁期间发起 verthys_unlock → IPC 发往死 worker → 永久卡死
 *   - lockAll 清空缓存期间发起 initUnlock → 状态机不一致
 *
 * 必须与 lockAllInProgress 同步生命周期：
 *   - lockAll() 入口置 lockAllPromise = doLockAll 的 Promise
 *   - lockAll() finally 块置 lockAllPromise = null
 */
let lockAllPromise: Promise<void> | null = null;

/** lockAll 总体超时（40s 安全网，覆盖 waitForFlush 22s + 各步骤超时） */
const LOCK_ALL_TOTAL_TIMEOUT_MS = 40000;

/** 单步超时包装：防止单个 IPC 调用卡死 */
function withStepTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T | undefined> {
  return Promise.race([
    promise,
    new Promise<undefined>((resolve) => {
      setTimeout(() => {
        console.warn(`[lockAll] ${label} 超时 ${ms}ms，继续执行后续步骤`);
        resolve(undefined);
      }, ms);
    }),
  ]);
}

/**
 * 锁定全部：按 7 步流程串行执行，确保删除数据落盘后再销毁 worker。
 *
 * 重入保护：lockAllInProgress 标志防止 session_guard on_lock 回调与
 * 用户操作（关闭按钮/手动锁定）并发触发，避免竞态。
 *
 * 总体超时：40s 安全网，防止单步卡死导致 lockAll 无限阻塞。
 *
 * ★ 企业级根治C：lockAllPromise 暴露给 awaitLockAllIfInProgress，
 *   使 doUnlock/initUnlock 能等待正在进行的 lockAll 完成后再发起新解锁。
 */
export async function lockAll(onProgress?: (percent: number, message: string) => void): Promise<void> {
  // ★ 重入保护：已在进行中则忽略（session_guard 可能并发触发）
  if (lockAllInProgress) {
    console.warn("[lockAll] 已在进行中，忽略重入调用");
    return;
  }
  lockAllInProgress = true;

  // ★ 企业级根治C：构建本次 lockAll 的 Promise（含总体超时安全网）
  //   暴露给 awaitLockAllIfInProgress，使并发解锁请求能等待其完成
  const thisPromise = Promise.race([
    doLockAll(onProgress),
    new Promise<void>((resolve) => {
      setTimeout(() => {
        console.error(`[lockAll] 总体超时 ${LOCK_ALL_TOTAL_TIMEOUT_MS}ms，强制完成`);
        // ★ 方案 6.2.4：40s 超时标记缓存脏数据
        //    部分数据可能未落盘，下次导航/解锁时弹窗提示用户
        setCacheDirty(true);
        resolve();
      }, LOCK_ALL_TOTAL_TIMEOUT_MS);
    }),
  ]);
  lockAllPromise = thisPromise;

  try {
    await thisPromise;
  } finally {
    lockAllInProgress = false;
    lockAllPromise = null;
  }
}

/** ★ 企业级根治C：等待正在进行的 lockAll 完成
 *
 * 若有 lockAll 正在进行，阻塞等待其完成（最多 40s + 5s 余量）；
 * 若无 lockAll 进行中，立即返回。
 *
 * 使用场景：
 *   - doUnlock/initUnlock/initCreate 起始处：确保旧的 lockAll 完成后再解锁
 *   - goBackToUnlock 调用 lockAll 后：确保锁定完成后再允许用户操作
 *
 * 安全超时：45s 兜底（覆盖 lockAll 40s 总体超时 + 5s 余量），
 *   防止 lockAllPromise 因异常未清空导致永久等待。
 *
 * 注意：本函数不触发新的 lockAll，仅等待已存在的 lockAll。
 */
export async function awaitLockAllIfInProgress(): Promise<void> {
  const ongoing = lockAllPromise;
  if (ongoing === null) return;

  // ★ 安全超时兜底：45s（覆盖 lockAll 40s + 5s 余量）
  //   防止 lockAllPromise 因未捕获异常未清空导致永久等待
  await Promise.race([
    ongoing,
    new Promise<void>((resolve) => {
      setTimeout(() => {
        console.warn("[awaitLockAllIfInProgress] 等待 lockAll 超时 45s，强制返回");
        resolve();
      }, 45000);
    }),
  ]);
}

/** 7 步流程实际实现
 *
 * ★ 企业级根治：接受 onProgress 回调，每步推送进度
 *
 * 原缺陷：goBackToUnlock 调用 lockAll() 后进度条停在 0% 无响应，
 *   因为 lockAll 是单个 await，40s 阻塞期间无进度更新。
 *
 * 修复：doLockAll 每步调用 onProgress 推送百分比和消息，
 *   goBackToUnlock 传入回调直接更新 UI 进度条。
 */
async function doLockAll(onProgress?: (percent: number, message: string) => void): Promise<void> {
  clearSessionTimer();

  // 同步重置前端状态（避免中间态闪烁）
  keyState.verthysReady.value = false;
  keyState.globalKeyReady.value = false;
  keyState.moduleKeyReady.value = { photo: false, accounts: false, certs: false, fileverthys: false };

  // ★ 步骤 1+2：取消防抖定时器 + 阻塞等待全部删除、落盘队列执行完成
  onProgress?.(5, "等待数据落盘");
  try { await waitForFlush(); } catch { /* */ }

  // ★ 方案 6.3：waitForFlush 完成后立即清空所有缓存定时器
  clearAllCacheTimers();

  // ★ 步骤 3：停止后台任务 + 清空所有内存缓存
  // ★ 企业级根治：stopBackgroundTasks 内部已有 3s 超时，外层 withStepTimeout 5s 兜底
  //    原缺陷：withStepTimeout 10s 超时过长，用户感知"停止后台任务时间过长"
  //    修复：缩短至 5s（stopBackgroundTasks 3s + 余量），超时后继续后续步骤
  onProgress?.(20, "停止后台任务");
  try { await withStepTimeout(stopBackgroundTasks(), 5000, "stopBackgroundTasks"); } catch { /* */ }
  clearModuleKeyCache();
  clearModuleCache();
  clearRecordScanCache();
  clearSummaryCache();
  clearFullRecordCache();

  // 步骤 3.5：清除 worker 内存中的 GMK
  onProgress?.(35, "清除内存密钥");
  try { await withStepTimeout(verthysClearGlobalKey(), 8000, "verthysClearGlobalKey"); } catch { /* */ }

  // ★ 步骤 4+5：安全原子落盘 + 等待持久化回执
  onProgress?.(50, "安全落盘");
  try { await withStepTimeout(verthysLockPersist(), 12000, "verthysLockPersist"); } catch { /* */ }

  // ★ 步骤 6：停止 C 消息线程
  onProgress?.(70, "停止安全会话");
  try { await withStepTimeout(securitySessionStop(), 5000, "securitySessionStop"); } catch { /* */ }

  // ★ 步骤 7：销毁 worker（企业级根治：verthysLock + workerDestroy 双重销毁）
  //
  // 原缺陷（"安全核心启动失败"根因）：
  //   doLockAll 步骤 7 仅调用 verthysLock()，后端 verthys_lock 只销毁 VerthysSessionGuard
  //   （释放文件锁），不销毁 worker 子进程，worker 状态仍为 Ready。
  //   前端 verthysLock() 的 finally 调用 invalidateWorkerPreload() 仅清空前端缓存，
  //   后端 worker 子进程仍存活且状态为 Ready。
  //   下次 doUnlock → initUnlock → ensureWorkerReady → workerInit("") →
  //   后端 worker_init → transition_to_initializing() →
  //   状态为 Ready → 返回 Err("worker 已就绪") → worker_init 返回 err →
  //   initUnlock 返回 E_WORKER_INIT_FAILED → 用户看到"安全核心启动失败"。
  //
  //   用户"回到主界面再拉取窗口"之所以能成功：SecurityCenter 组件卸载/重新挂载
  //   的时间差让 worker 状态发生变化（或触发了其他清理路径），非确定性修复。
  //
  // 修复：
  //   1. verthysLock()：持久化 + 释放文件锁 + 重置 key_lifecycle（后端 verthys_lock 已做）
  //   2. workerDestroy()：销毁 worker 子进程 + transition_to_uninitialized()
  //      （后端 worker_destroy 已做）→ 下次 worker_init 可从 Uninitialized 成功转移
  //
  // 安全性：worker_destroy 后端对不存在的 worker 为空操作（WorkerState=None 时跳过），
  //   不会误报错误。workerDestroy 前端 finally 调用 invalidateWorkerPreload()，
  //   双重保险清空前端缓存。
  onProgress?.(85, "销毁安全核心");
  try { await withStepTimeout(verthysLock(), 8000, "verthysLock"); } catch { /* */ }
  try { await withStepTimeout(workerDestroy(), 5000, "workerDestroy"); } catch { /* */ }

  onProgress?.(100, "清理完成");

  // ★ 企业级根治修复：步骤 7.5 — 补全状态重置
  //
  // 原缺陷：doLockAll 仅重置 verthysReady/globalKeyReady/moduleKeyReady 三个状态，
  // 遗漏 hasModuleKeyRecord/moduleKeyEnabled/hasGlobalKeyRecord/globalKeyRecordB64/
  // globalKeyRecordId/storedVerthysPath 等关键状态。
  // 锁定后这些状态残留，下次解锁时若 loadModuleKeyStatus 未及时完成，
  // UI 会显示上一会话的旧状态（如"全部模块已开启密钥"）。
  //
  // 修复：调用 resetAllState() 统一重置全部 keyState 为安全默认值。
  // 必须在 verthysLock 之后（worker 已销毁）、setCurrentVerthysPath("") 之前调用，
  // 因为 resetAllState 内部会清空 _currentVerthysPath，与后续 setCurrentVerthysPath("") 一致。
  // 注意：clearModuleKeyCache/clearModuleCache/clearRecordScanCache 等已在步骤 3 执行，
  // resetAllState 仅重置 keyState refs，不重复清理缓存。
  resetAllState();

  // 步骤 8：清空路径并重置 flush 链
  //    必须在 verthysLock 之后：路径为空时 doFlush 会短路，pending flush 无法执行
  setCurrentVerthysPath("");
  resetFlushChain();
}
