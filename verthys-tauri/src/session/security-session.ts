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
  securityBruteCheck,
  securityBruteClearPurge, securityBruteStatus,
  securitySessionStart, securitySessionStop, securitySessionSetHardening,
  securityApplyPreset, securityLoadPresetState,
  verthysClearGlobalKey, verthysLock, verthysLockPersist, workerDestroy,
  type SecurityPresetCode, type BruteForceCheckResponse, type PresetFeatures,
} from "../lib/verthys";
import { ref, readonly } from "vue";
import { isTauriEnvironment } from "../utils/tauri_env";
import { keyState, setCurrentVerthysPath, loadCustomFeatures, saveSecurityPreset, saveCustomFeatures, saveCustomSessionMinutes, normalizeCustomSessionMinutes, loadSecurityPreset, resetAllState } from "../state/key_state";
import { PRESET_SESSION_TIMEOUT_MS, SECURITY_PRESET_KEY, CUSTOM_FEATURES_KEY } from "../constants/key_manager_const";
import { withTimeout } from "../utils/promise_utils";
import type { BruteForceGateResult } from "../types/key_manager";
import { clearModuleKeyCache, clearModuleCache, clearRecordScanCache, cancelDebouncedFlush, resetFlushChain, waitForFlush, clearAllCacheTimers, setCacheDirty, isCacheDirty, clearSummaryCache, clearFullRecordCache } from "../cache/composition/verthys-cache";
// 后台任务 API 直连 core 层（单向化：不再转发 start/stop）
import { startBackgroundTasks, stopBackgroundTasks } from "../core/background-tasks";

// 导出 securityPresetRef 供 keyManager.ts 再导出
export const securityPresetRef = keyState.securityPreset;

// 导出 sessionLockEnabledRef 供 keyManager.ts 再导出（UI 据此展示空闲锁定状态）
export const sessionLockEnabledRef = keyState.sessionLockEnabled;

// 导出 customSessionMinutesRef 供 keyManager.ts 再导出（自定义档空闲锁定时长，分钟）
export const customSessionMinutesRef = keyState.customSessionMinutes;

/** 会话硬化 / 会话守卫是否处于降级状态
 *
 * 安全档位宣称的「挂起锁定 / 剪贴板监听 / 系统锁屏会话守卫」若启停失败，
 * 旧实现仅 console.warn —— 界面仍显示已启用，属不可见的安全降级。
 * 本 ref 供管理面板如实标注「部分安全硬化未生效」。 */
export const securityHardeningFailedRef = ref(false);

/* ------------------------------------------------------------------ *
 * 会话计时                                                            *
 * ------------------------------------------------------------------ */

/** 会话空闲超时（毫秒），默认 30 分钟 */
let sessionTimeoutMs = 30 * 60 * 1000;

/** 在途定时器句柄（null = 未武装） */
let sessionTimer: number | null = null;

/** 会话空闲截止时间（Date.now() 基准时间戳）；0 = 计时器未武装
 *
 * 单一事实源：真实锁定裁决与 UI 倒计时同源读取本值，
 * 消除「真实计时器」与「UI 倒计时」两套时钟各自漂移的问题。 */
const sessionDeadline = ref(0);

/** 会话空闲截止时间（只读）：UI 倒计时据此同步，0 表示未武装 */
export const sessionIdleDeadlineRef = readonly(sessionDeadline);

/** 用户输入活动事件（passive 监听，零阻断）
 *
 * 会话空闲语义 = 无任何真实输入；焦点变化（focus）不算活动，
 * 否则用户离开后仅切回窗口即可永久续期。 */
const SESSION_ACTIVITY_EVENTS: (keyof WindowEventMap)[] = [
  "pointerdown",
  "pointermove",
  "wheel",
  "keydown",
  "touchstart",
];

/** 活动重置节流窗口（毫秒）：高频指针事件每秒最多刷新一次截止时间 */
const ACTIVITY_TOUCH_THROTTLE_MS = 1000;

let activityWatchInstalled = false;
let lastActivityTouchAt = 0;

/** 全局输入活动 → 刷新空闲截止时间 */
function onUserActivity(): void {
  const now = Date.now();
  if (now - lastActivityTouchAt < ACTIVITY_TOUCH_THROTTLE_MS) return;
  lastActivityTouchAt = now;
  touchSession();
}

/** 惰性装配全局活动监听（首次武装时装配，单例生命周期） */
function installActivityWatch(): void {
  if (activityWatchInstalled || typeof window === "undefined") return;
  activityWatchInstalled = true;
  for (const event of SESSION_ACTIVITY_EVENTS) {
    window.addEventListener(event, onUserActivity, { passive: true });
  }
}

/** 清除在途定时器句柄（不改变截止时间） */
function clearTimerHandle(): void {
  if (sessionTimer !== null) {
    window.clearTimeout(sessionTimer);
    sessionTimer = null;
  }
}

/** 按当前截止时间武装定时器；到点复核真实空闲时长后再执行锁定
 *
 * 复核的意义：
 *   - 计时期间发生过输入 → 截止时间已前移 → 按新截止时间续排
 *   - 系统休眠/后台节流导致回调延迟 → 真实空闲已达标 → 立即锁定
 *   - 时钟回拨导致提前触发 → 剩余时间 > 0 → 续排，绝不误锁
 */
function armSessionDeadline(): void {
  clearTimerHandle();
  const armedDeadline = sessionDeadline.value;
  if (armedDeadline === 0) return;
  sessionTimer = window.setTimeout(() => {
    sessionTimer = null;
    if (sessionDeadline.value === 0) return; // 等待期间已解除武装
    if (sessionDeadline.value - Date.now() > 0) {
      armSessionDeadline();
      return;
    }
    void lockAll().catch((e) => {
      console.error("[session] 空闲锁定执行失败", e);
    });
  }, Math.max(0, armedDeadline - Date.now()));
}

function clearSessionTimer(): void {
  clearTimerHandle();
  if (sessionDeadline.value !== 0) sessionDeadline.value = 0;
}

function resetSessionTimer(): void {
  if (typeof window === "undefined") return;
  // 空闲锁定关闭（自定义档显式关闭）或会话未激活时不武装计时器
  if (!keyState.sessionLockEnabled.value || !keyState.globalKeyReady.value) {
    clearTimerHandle();
    if (sessionDeadline.value !== 0) sessionDeadline.value = 0;
    return;
  }
  installActivityWatch();
  sessionDeadline.value = Date.now() + sessionTimeoutMs;
  armSessionDeadline();
}

/** 触碰会话（任何真实用户输入都应调用，空闲截止时间从当前时刻重新计算） */
export function touchSession(): void {
  resetSessionTimer();
}

/** 查询会话空闲剩余时间（毫秒）；未武装时返回完整超时 */
export function getSessionRemainingMs(): number {
  if (sessionDeadline.value === 0) return sessionTimeoutMs;
  return Math.max(0, sessionDeadline.value - Date.now());
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

/**
 * 设置会话空闲锁定开关
 *  关闭时立即清除在途计时器（不再自动锁定）；开启时按当前超时重新武装
 * @param enabled true = 启用空闲锁定；false = 不自动锁定
 */
export function setSessionLockEnabled(enabled: boolean): void {
  keyState.sessionLockEnabled.value = enabled;
  if (!enabled) {
    clearSessionTimer();
    return;
  }
  if (keyState.globalKeyReady.value) {
    resetSessionTimer();
  }
}

/** 查询会话空闲锁定开关（UI 据此展示"已关闭"状态） */
export function isSessionLockEnabled(): boolean {
  return keyState.sessionLockEnabled.value;
}

/* ------------------------------------------------------------------ *
 * 三档安全预设适配                                                    *
 *                                                                    *
 * applySecurityPreset 在初始化成功与用户切换预设时调用：              *
 *   - 标准档 0/1/2：先调后端真实切档（security_apply_preset →        *
 *     worker → C 层双缓冲原子切换），成功后才更新前端状态；           *
 *     失败抛错（明确错误码），前端状态保持原值                        *
 *   - CUSTOM 档：组合会话层硬化开关，无 C 层档位                     *
 * ------------------------------------------------------------------ */

/**
 * 应用三档安全预设
 *  在初始化成功后与用户切换预设时调用
 *  @param preset 0=BALANCED, 1=SECURE, 2=PERFORMANCE, 3=CUSTOM
 *  @param issuedEpoch 恢复链发起时的竞态版本号（可选）；
 *         应用前若已被用户显式切换超越，则放弃本次应用并返回 null
 *  @param customOverride CUSTOM 档的显式特性集（可选）；缺省时读取本地
 *         缓存。显式传入使"应用自定义模板"链路避免先写缓存再读回的
 *         双写 —— 本地缓存只在后端应用成功后落一次（单一落盘点）。
 *  @param customMinutesOverride CUSTOM 档空闲锁定时长（分钟，可选）；
 *         缺省时取本地缓存值。恢复链传入后端受信值，保证与磁盘一致。
 *  @returns 该预设的配置详情（含各特性开关）；被超越时返回 null
 *  @throws 后端切档/落盘失败或超时时抛错（调用方以 withTimeout 兜底并提示）
 */
export async function applySecurityPreset(
  preset: SecurityPresetCode,
  issuedEpoch?: number,
  customOverride?: PresetFeatures,
  customMinutesOverride?: number,
) {
  // 竞态仲裁：恢复链携带发起时版本号，应用前校验未被用户显式切换超越
  if (issuedEpoch !== undefined && issuedEpoch !== presetEpoch) {
    console.warn("[applySecurityPreset] 恢复结果已被用户切换超越，放弃应用");
    return null;
  }
  // CUSTOM 档：后端落盘自定义特性与空闲锁定时长（无 C 层档位），
  // 会话层开关组合实现
  if (preset === 3) {
    const custom = customOverride ?? loadCustomFeatures();
    const customMinutes = normalizeCustomSessionMinutes(
      customMinutesOverride ?? keyState.customSessionMinutes.value,
    );
    // 先后端落盘 + 返回权威配置；失败抛错，前端状态不变
    const config = await securityApplyPreset(3, custom, customMinutes);

    // 会话层硬化：剪贴板监听由专用开关独立控制（不再与空闲锁定合并为
    // 单一布尔——两能力互不牵连）；挂起锁定不向自定义档暴露。
    try {
      // 3s 超时兜底：后端会话守卫命令阻塞时不得卡死预设应用流程
      const ok = await withTimeout(
        securitySessionSetHardening(false, custom.clip_clear_on_lock),
        3000,
        "设置会话硬化开关",
      );
      securityHardeningFailedRef.value = !ok;
      if (!ok) {
        // 后端返回 ok=false（会话未解锁被拒绝/监听启动失败）：可见报告而非静默吞掉
        console.warn("[applySecurityPreset] CUSTOM 会话硬化开关被后端拒绝或监听启动失败");
      }
    } catch (e) {
      securityHardeningFailedRef.value = true;
      console.warn("[applySecurityPreset] CUSTOM 设置会话硬化开关失败（非致命）", e);
    }

    // 后端成功后更新前端状态 + localStorage 缓存（后端为权威）
    keyState.securityPreset.value = preset;
    saveSecurityPreset(preset);
    saveCustomFeatures(custom);
    keyState.customSessionMinutes.value = customMinutes;
    saveCustomSessionMinutes(customMinutes);
    // 自定义档：超时取用户设置值，空闲锁定由特性开关决定
    sessionTimeoutMs = customMinutes * 60 * 1000;
    setSessionLockEnabled(custom.session_lock_on_idle);
    return config;
  }

  // 标准档 0/1/2：先调后端真实切档（含原子落盘），成功后更新前端状态
  const config = await securityApplyPreset(preset as 0 | 1 | 2);

  // 后端切档成功后同步前端状态与缓存（保持顺序：失败时状态不变）
  keyState.securityPreset.value = preset;
  saveSecurityPreset(preset);
  sessionTimeoutMs = PRESET_SESSION_TIMEOUT_MS[preset];
  // 标准档恒启用空闲锁定（覆盖自定义档可能关闭的状态），并按新超时重新武装
  setSessionLockEnabled(true);

  // 会话层硬化（与 C 层档位分离）：SECURE 启用挂起锁定与剪贴板监听；
  // 其余标准档关闭两项（剪贴板锁定清空为恒定底线，不受该开关影响）。
  // 失败独立可见报告，不回滚已成功的 C 层切档。
  try {
    const suspendLock = preset === 1;
    const clipboardMonitor = preset === 1;
    const ok = await withTimeout(
      securitySessionSetHardening(suspendLock, clipboardMonitor),
      3000,
      "设置会话硬化开关",
    );
    securityHardeningFailedRef.value = !ok;
    if (!ok) {
      console.warn("[applySecurityPreset] 会话硬化开关被后端拒绝或监听启动失败");
    }
  } catch (e) {
    securityHardeningFailedRef.value = true;
    console.warn("[applySecurityPreset] 设置会话硬化开关失败（非致命）", e);
  }

  return config;
}

/* ------------------------------------------------------------------ *
 * 启动恢复链：受信配置为权威，localStorage 仅作迁移来源与只读缓存     *
 *                                                                    *
 *   1. 后端有值 → 真实应用后端档位，同步前端缓存                      *
 *   2. 后端无值、localStorage 有值 → 迁移：应用并落盘后端；           *
 *      localStorage 保留为只读缓存（清键会造成下次启动初值退化）      *
 *   3. 两端均无 → 应用默认 BALANCED（落盘后端建立权威副本）           *
 *                                                                    *
 * 竞态仲裁：用户显式切换递增 presetEpoch；恢复链在读取后与应用入口   *
 * 双重校验 epoch，变化即丢弃恢复结果（用户的最新选择为最终状态）。   *
 * ------------------------------------------------------------------ */

/** 预设竞态版本号（单调递增）：用户显式切换时递增 */
let presetEpoch = 0;

/** 用户显式切换预设入口调用：递增竞态版本，使在途恢复链自弃 */
export function bumpPresetEpoch(): void {
  presetEpoch += 1;
}

/** 恢复完成报告 */
export interface PresetRestoreReport {
  /** 持久化不一致标记：本次恢复前后端处于回滚失败状态（已按受信文件重新收敛） */
  persistDirty: boolean;
}

/**
 * 恢复安全预设（全局密钥就绪后调用）
 *
 * 后端受信文件为单一事实源；localStorage 仅作只读缓存与首次迁移来源。
 * 失败抛错由调用方提示，不静默回退。
 * @returns 恢复报告（含持久化不一致标记，供调用方可见报告）
 */
export async function restoreSecurityPreset(): Promise<PresetRestoreReport> {
  const epochAtStart = presetEpoch;
  const { state: backend, persistDirty } = await securityLoadPresetState();

  // 竞态仲裁：读取后端期间用户已显式切换 → 丢弃恢复结果
  if (presetEpoch !== epochAtStart) {
    return { persistDirty };
  }

  if (backend && backend.code >= 0 && backend.code <= 3) {
    // 后端有值：同步 CUSTOM 特性与空闲锁定时长后真实应用
    // （apply 入口按 epoch 做最终裁决）
    if (backend.code === 3 && backend.customFeatures) {
      saveCustomFeatures(backend.customFeatures);
    }
    await applySecurityPreset(
      backend.code as SecurityPresetCode,
      epochAtStart,
      undefined,
      backend.code === 3
        ? backend.customSessionTimeoutMinutes ?? undefined
        : undefined,
    );
    return { persistDirty };
  }

  // 后端无值：迁移 localStorage 旧值（若存在）
  const hadPreset = localStorage.getItem(SECURITY_PRESET_KEY) != null;
  const hadCustom = localStorage.getItem(CUSTOM_FEATURES_KEY) != null;
  if (hadPreset || hadCustom) {
    const localCode = loadSecurityPreset();
    await applySecurityPreset(localCode, epochAtStart);
    // 竞态仲裁：应用迁移期间用户已显式切换 → 保留其新缓存，不清理
    if (presetEpoch !== epochAtStart) {
      return { persistDirty };
    }
    // 迁移完成：localStorage 保留为只读缓存（后端已持有权威副本）。
    // 不删键——缓存空洞会使下次启动的前端初值退化，进而存在以默认档
    // 覆盖受信副本的路径（解锁收尾不再回写权威，此路径必须一并封死）。
    return { persistDirty };
  }

  // 两端均无：应用默认档并落盘后端，建立权威副本
  saveSecurityPreset(0);
  await applySecurityPreset(0, epochAtStart);
  return { persistDirty };
}

/* ------------------------------------------------------------------ *
 * 暴力拦截门禁                                                        *
 *                                                                    *
 * 计数与强制由服务端口令类命令入口执行（fail-closed 闸门 + 权威计数），*
 * 前端仅做纯查询：                                                    *
 *   1. checkBruteForceGate — 调用前预检，避免锁定态进入长运算流程      *
 *   2. getBruteForceStatus — UI 展示失败次数/锁定剩余时间             *
 *   3. clearBruteForcePurge — PurgeRequired 处理完成后清除           *
 * ------------------------------------------------------------------ */

/** 检查当前是否允许尝试解锁（暴力拦截门禁）
 *
 * 失败语义：Tauri 环境下查询失败一律 fail-closed（无法确认门禁状态时
 * 不得进入长运算解锁流程）；仅浏览器模式（无安全后端）允许放行。 */
export async function checkBruteForceGate(): Promise<BruteForceGateResult> {
  try {
    const r: BruteForceCheckResponse = await securityBruteCheck();
    if (r.kind === "Allow") return { allowed: true };
    if (r.kind === "Locked") {
      return { allowed: false, reason: "locked", remainingSecs: r.remaining_secs };
    }
    return { allowed: false, reason: "purge_required" };
  } catch (e) {
    console.warn("[checkBruteForceGate] 查询失败", e);
    if (isTauriEnvironment()) {
      // 后端不可用 / 查询失败：拒绝进入认证流程（服务端闸门仍会兜底）
      return { allowed: false, reason: "gate_unavailable" };
    }
    // 浏览器模式（开发期）：无安全后端，允许继续
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
 * 四层根治设计·第四层（全局应用生命周期兜底）— 7 步流程：           *
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

/** 锁库结果：安装闸门只接受 clean=true，且 clean 由 flushed / dirty / errors 共同决定。 */
export interface LockOutcome {
  clean: boolean;
  flushed: boolean;
  dirty: boolean;
  errors: string[];
  durationMs: number;
}

/** 重入保护标志：防止 session_guard on_lock 回调与用户操作并发触发 lockAll */
let lockAllInProgress = false;

/** 当前 lockAll 的"真实工作"Promise（null 表示无 lockAll 进行中）
 *
 * 与等待上限分离（关键治理）：
 *   旧实现以 40s `Promise.race` 结束等待并释放闸门，但 doLockAll 仍在后台
 *   继续执行；40s 后用户可立即解锁，残留的「清 GMK / 锁库 / 销毁 worker」
 *   会打在**新会话**上（新 worker 被销毁、新状态被 resetAllState 抹掉），
 *   窗口期内还可并发启动第二个 lockAll。
 *
 * 现语义：
 *   - 闸门（lockAllInProgress）只在 doLockAll 真正结束后释放；
 *   - 等待方 await 的是真实工作（各步均有超时包裹，总时长有界）；
 *   - 破坏性步骤执行前校验代际，任何强制换代都会让旧步骤立即自弃。
 */
let lockWorkPromise: Promise<LockOutcome> | null = null;

/** 锁定代际（单调递增）：每次 lockAll 启动递增；步骤执行前校验 */
let lockGeneration = 0;

/** 单步超时包装：防止单个 IPC 调用卡死 */
function withStepTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T | undefined> {
  return Promise.race([
    promise,
    new Promise<undefined>((resolve) => {
      setTimeout(() => {
        console.warn(`[lockAll] ${label} 超时 ${ms}ms，继续执行后续步骤`);
        // 任一步超时都意味着落盘/清理可能不完整：如实标记缓存脏数据
        setCacheDirty(true);
        resolve(undefined);
      }, ms);
    }),
  ]);
}

/**
 * 锁定全部：按 7 步流程串行执行，确保删除数据落盘后再销毁 worker。
 *
 * 重入保护：lockAllInProgress 闸门防止 session_guard on_lock 回调与
 * 用户操作（关闭按钮/手动锁定）并发触发；已在执行时本调用只等待真实
 * 工作完成，绝不并行启动第二套销毁步骤。
 *
 * 时长治理：不再使用「40s 总超时后释放闸门」的竞速收口 —— 各步骤均有
 * 独立超时包裹，真实工作总时长有界；闸门只在真实工作结束后释放。
 */
export async function lockAll(onProgress?: (percent: number, message: string) => void): Promise<LockOutcome> {
  // 重入：等待在途真实工作完成（不重复启动销毁链）
  if (lockAllInProgress && lockWorkPromise) {
    console.warn("[lockAll] 已在进行中，等待当前锁定序列完成");
    return await lockWorkPromise;
  }
  lockAllInProgress = true;
  const generation = ++lockGeneration;
  const work = doLockAll(generation, onProgress);
  lockWorkPromise = work;

  try {
    return await work;
  } finally {
    // 仅当前代次可释放闸门；强制换代时由新代次接管
    if (generation === lockGeneration) {
      lockAllInProgress = false;
      lockWorkPromise = null;
    }
  }
}

/** 等待正在进行的 lockAll 完成
 *
 * 若有 lockAll 正在进行，阻塞等待其**真实工作**结束；
 * 若无 lockAll 进行中，立即返回。
 *
 * 使用场景：
 *   - doUnlock/initUnlock/initCreate 起始处：确保旧的 lockAll 完成后再解锁
 *   - goBackToUnlock 调用 lockAll 后：确保锁定完成后再允许用户操作
 *
 * 为何不再设 45s 提前返回：提前返回会让解锁与残留销毁步骤并行，
 * 新会话会被旧 lockAll 的清 GMK / 锁库 / 销毁 worker 命中。各步均有
 * 超时包裹，真实工作不会无限阻塞。
 *
 * 注意：本函数不触发新的 lockAll，仅等待已存在的 lockAll。
 */
export async function awaitLockAllIfInProgress(): Promise<void> {
  const ongoing = lockWorkPromise;
  if (ongoing === null) return;
  await ongoing;
}

/** 7 步流程实际实现
 *
 * 修复：接受 onProgress 回调，每步推送进度
 *
 * 代际仲裁：每个破坏性步骤执行前校验 generation —— 若在等待期间被
 *   强制换代（新锁定序列接管），旧序列立即自弃，绝不污染新会话。
 */
async function doLockAll(
  generation: number,
  onProgress?: (percent: number, message: string) => void,
): Promise<LockOutcome> {
  /** 当前序列是否仍为权威（否则立即停止后续破坏性步骤） */
  const current = (): boolean => generation === lockGeneration;
  const startedAt = Date.now();
  let flushed = true;
  const errors: string[] = [];
  const snapshot = (): LockOutcome => {
    const dirty = isCacheDirty();
    return {
      clean: flushed && !dirty && errors.length === 0,
      flushed,
      dirty,
      errors: [...errors],
      durationMs: Date.now() - startedAt,
    };
  };

  clearSessionTimer();

  // 同步重置前端状态（避免中间态闪烁）
  keyState.verthysReady.value = false;
  keyState.globalKeyReady.value = false;
  keyState.moduleKeyReady.value = { photo: false, accounts: false, fileverthys: false };

  // 步骤 1+2：取消防抖定时器 + 阻塞等待全部删除、落盘队列执行完成
  onProgress?.(5, "等待数据落盘");
  try { await waitForFlush(); } catch (error) {
    flushed = false;
    errors.push(`waitForFlush: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!current()) return snapshot();

  // waitForFlush 完成后立即清空所有缓存定时器
  clearAllCacheTimers();

  // 步骤 3：停止后台任务 + 清空所有内存缓存
  // 修复：stopBackgroundTasks 内部已有 3s 超时，外层 withStepTimeout 5s 兜底
  //    原缺陷：withStepTimeout 10s 超时过长，用户感知"停止后台任务时间过长"
  //    修复：缩短至 5s（stopBackgroundTasks 3s + 余量），超时后继续后续步骤
  onProgress?.(20, "停止后台任务");
  try { await withStepTimeout(stopBackgroundTasks(), 5000, "stopBackgroundTasks"); } catch (error) {
    errors.push(`stopBackgroundTasks: ${String(error)}`);
  }
  if (!current()) return snapshot();
  clearModuleKeyCache();
  clearModuleCache();
  clearRecordScanCache();
  clearSummaryCache();
  clearFullRecordCache();

  // 步骤 3.5：清除 worker 内存中的 GMK
  onProgress?.(35, "清除内存密钥");
  try { await withStepTimeout(verthysClearGlobalKey(), 8000, "verthysClearGlobalKey"); } catch (error) {
    errors.push(`verthysClearGlobalKey: ${String(error)}`);
  }
  if (!current()) return snapshot();

  // 步骤 4+5：安全原子落盘 + 等待持久化回执
  onProgress?.(50, "安全落盘");
  try { await withStepTimeout(verthysLockPersist(), 12000, "verthysLockPersist"); } catch (error) {
    errors.push(`verthysLockPersist: ${String(error)}`);
  }
  if (!current()) return snapshot();

  // 步骤 6：停止 C 消息线程
  onProgress?.(70, "停止安全会话");
  try { await withStepTimeout(securitySessionStop(), 5000, "securitySessionStop"); } catch (error) {
    errors.push(`securitySessionStop: ${String(error)}`);
  }
  if (!current()) return snapshot();

  // 步骤 7：销毁 worker（根治：verthysLock + workerDestroy 双重销毁）
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
  try { await withStepTimeout(verthysLock(), 8000, "verthysLock"); } catch (error) {
    errors.push(`verthysLock: ${String(error)}`);
  }
  if (!current()) return snapshot();
  try { await withStepTimeout(workerDestroy(), 5000, "workerDestroy"); } catch (error) {
    errors.push(`workerDestroy: ${String(error)}`);
  }
  if (!current()) return snapshot();

  onProgress?.(100, "清理完成");

  // 修复修复：步骤 7.5 — 补全状态重置
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

  return snapshot();
}
