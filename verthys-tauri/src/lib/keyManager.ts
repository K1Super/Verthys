/*
 * keyManager.ts — 密钥管理中枢聚合导出入口（无业务实现）
 *
 * 分层架构：
 *   Layer 0: types/key_manager.ts + constants/key_manager_const.ts + lib/key_error.ts
 *   Layer 1: utils/verthys_traversal.ts + utils/promise_utils.ts + state/key_state.ts
 *   Layer 2: cache/composition/verthys-cache.ts（模块缓存 + 扫描缓存 + flush 队列）
 *   Layer 3a: session/security-session.ts（会话计时 + 预设 + 暴力拦截 + lockAll）
 *   Layer 3b: key/global-verthys.ts（加密库 init + GMK CRUD + 设备绑定）
 *   Layer 3c: key/module-auth.ts（模块密钥 CRUD + 登录登出）
 *   Layer 4: lib/keyManager.ts（本文件，纯聚合导出）
 */

/* ===== 常量再导出 ===== */
export {
  TYPE_GLOBAL_KEY,
  MODULE_IDS,
  MODULE_LABELS,
  SESSION_PRESET_MINUTES,
} from "../constants/key_manager_const";

/* 全部记录类型常量统一从 record_types.ts 再导出，
 *   避免各模块本地定义 TYPE_* 的冲突
 */
export {
  TYPE_PHOTO_META,
  TYPE_PHOTO_CHUNK,
  TYPE_ACCOUNT,
  TYPE_ACCOUNT_LIST,
  TYPE_ACCOUNT_LEGACY,
  TYPE_FILEVERTHYS_META,
  TYPE_FILEVERTHYS_CHUNK,
  TYPE_PRIORITY,
} from "../constants/record_types";

/* ===== 类型再导出 ===== */
export type {
  ModuleId,
  BruteForceGateResult,
  VerifyGlobalKeyResult,
} from "../types/key_manager";

/* ===== 响应式状态再导出（独立 ref 命名） ===== */
import { keyState } from "../state/key_state";

export const verthysReadyRef = keyState.verthysReady;
export const globalKeyReadyRef = keyState.globalKeyReady;
export const hasGlobalKeyRecordRef = keyState.hasGlobalKeyRecord;
/* 全局密钥记录 id：修改密钥成功后更新；超时回查据此确认后端真实结果 */
export const globalKeyRecordIdRef = keyState.globalKeyRecordId;
export const moduleKeyReadyRef = keyState.moduleKeyReady;
export const hasModuleKeyRecordRef = keyState.hasModuleKeyRecord;
export const moduleKeyEnabledRef = keyState.moduleKeyEnabled;
export const moduleHasRecoveryRef = keyState.moduleHasRecovery;
/* 导出 moduleKeyStatusLoadingRef，供 useModuleNavigation.switchModule
 *   防御性守卫消费——解锁关键路径若仍在加载模块密钥状态，切换模块前需等待完成，
 *   否则 moduleKeyEnabled 默认为 false，守卫会误判保护已关闭而直接放行 */
export const moduleKeyStatusLoadingRef = keyState.moduleKeyStatusLoading;
/* 导出 moduleKeyStatusLoadedRef，供 useModuleNavigation.switchModule
 *   判断模块密钥状态是否已加载完成。仅 loadModuleKeyStatus 真正完成时为 true，
 *   未加载完前守卫拦截业务模块进入。 */
export const moduleKeyStatusLoadedRef = keyState.moduleKeyStatusLoaded;
/* 模块密钥状态加载失败标志：守卫据此立即 fail-closed */
export const moduleKeyStatusFailedRef = keyState.moduleKeyStatusFailed;
export const initStatusRef = keyState.initStatus;
export const initDetailRef = keyState.initDetail;

/* ===== 自定义特性持久化 ===== */
export {
  loadCustomFeatures,
  saveCustomFeatures,
  isLockedFeature,
  loadSecurityPreset,
  saveSecurityPreset,
} from "../state/key_state";

/* ===== 缓存层 API ===== */
export {
  getModuleCache,
  setModuleCache,
  clearModuleCache,
  ensureRecordScan,
  cancelRecordScan,
  cancelSummaryScan,
  getRecordIdsByType,
  getRecordFromScan,
  invalidateScannedRecord,
  addRecordToScan,
  clearRecordScanCache,
  persistVerthys,
  persistVerthysDetailed,
  deleteAndPersist,
  deleteAndPersistBatch,
  waitForFlush,
  isFlushing,
} from "../cache/composition/verthys-cache";

/* ===== 两层缓存 API（摘要常驻 + 全量按需 LRU-50） ===== */
export {
  ensureSummaryScan,
  getSummaryIdsByType,
  getSummaryRecord,
  getAllSummaryIds,
  getSummaryCacheSize,
  addSummaryRecord,
  invalidateSummaryRecord,
  clearSummaryCache,
  getFullRecord,
  prefetchFullRecords,
  invalidateFullRecord,
  addFullRecord,
  clearFullRecordCache,
  getFullRecordCacheSize,
  /* 批量获取多条记录 dataB64（扫描缓存优先 + 并行 IPC 回退）。
   *   供 4 个业务模块列表加载使用，避免逐条 getFullRecord 串行 IPC
   *   与后台 ensureRecordScan 争用同一常驻 worker。 */
  getRecordsDataB64Batch,
  clearAllVerthysCaches,
  ensureTypeIds,
  clearTypeIdCache,
  resolveTypeIds,
} from "../cache/composition/verthys-cache";
/* 后台任务 API 直连 core 层再导出（单向化，下游导入路径保持不变） */
export { startBackgroundTasks, stopBackgroundTasks } from "../core/background-tasks";
export type { SummaryRecord } from "../lib/verthys";

/* ===== 安全扫描包装（永不抛出，Vue 组件专用） ===== */
export { ensureRecordScanSafe, ensureSummaryScanSafe } from "../utils/verthys_scan_safe";
/* 扫描进度快照类型（信号层消费；仅类型，无运行时代码） */
export type { ScanProgress } from "../cache/composition/verthys-cache";

/* ===== 会话安全层 API ===== */
export {
  touchSession,
  setSessionTimeout,
  getSessionTimeout,
  getSessionRemainingMs,
  sessionIdleDeadlineRef,
  setSessionLockEnabled,
  isSessionLockEnabled,
  applySecurityPreset,
  restoreSecurityPreset,
  bumpPresetEpoch,
  checkBruteForceGate,
  getBruteForceStatus,
  lockAll,
  awaitLockAllIfInProgress,
  securityPresetRef,
  sessionLockEnabledRef,
  customSessionMinutesRef,
  securityHardeningFailedRef,
} from "../session/security-session";

/* ===== 全局加密库层 API ===== */
export {
  checkInitStatus,
  initCreate,
  initUnlock,
  initAndUnlock,
  initGlobalKey,
  changeGlobalKey,
  verifyGlobalKey,
  verifyGlobalKeyWithBruteForce,
  verifyDeviceBinding,
  getDeviceFingerprintShort,
  readBinFile,
} from "../key/global-verthys";

/* ===== 模块密钥认证层 API ===== */
export {
  generateModuleKey,
  setModuleKey,
  verifyModuleKey,
  hasModuleKey,
  isModuleReady,
  logoutModule,
  disableModuleProtection,
  isModuleKeyEnabled,
  loadModuleKeyStatus,
} from "../key/module-auth";

/* ================================================================== *
 * 基础库 API 再导出                                                   *
 *                                                                    *
 * 通过 keyManager 门面统一再导出，供 Vue 组件与上层模块使用，          *
 * 保持单一导入入口。                                                  *
 * ================================================================== */

/* ===== VerthysResult 结构化错误契约 API =====
 *
 * 所有公共函数返回 Promise<VerthysResult<T>>。
 * Vue 组件通过 result.ok / result.code 处理错误，提供精确 UI 提示。
 */
export {
  VerthysErrorCode,
  ok,
  err,
  errFromVerthysError,
  errFromUnknown,
  isVerthysError,
  isOk,
  isErr,
  defaultCodeFromKind,
  wrapAsVerthysError,
} from "../lib/verthys_error";
export type { VerthysResult, VerthysErrorResult } from "../lib/verthys_error";
export { VerthysError, VerthysErrorKind } from "../lib/verthys_error";
export type { DeviceBindingResult } from "../types/key_manager";

/* ===== CacheCoordinator 缓存协调器（单例）=====
 *
 * 业务代码通过 cacheCoordinator.addRecord /
 * removeRecord / updateRecord 同步三层缓存（摘要/扫描/全量），
 * 消除手动调用 5 个分散缓存函数的遗漏风险。
 */
export { CacheCoordinator, cacheCoordinator } from "../cache/coordination/cache-coordinator";
export type { RecordUpdate } from "../cache/coordination/cache-coordinator";

/* ===== 统一日志工具（环境感知）=====
 *
 * 所有业务模块使用 createLogger(moduleName)
 * 替换原生 console，开发环境输出 debug/info/warn/error，
 * 生产环境仅输出 error，避免污染控制台与影响性能。
 */
export { createLogger, log, isDevelopment } from "../utils/logger";
export type { Logger } from "../utils/logger";

/* ===== 统一冲刷队列服务（延迟持久化）=====
 *
 * global-verthys.ts 与 module-auth.ts 共享此服务，
 * enqueueFlush 入队后立即返回（不阻塞 UI），flushVerthysNow 强制同步
 * 落盘（关键路径专用，含超时保护）。
 */
export {
  enqueueFlush,
  flushVerthysNow,
  flushQueueStatus,
  resetFlushChain,
  scheduleBackgroundFlush,
  cancelDebouncedFlush,
} from "../cache/composition/verthys-flush";

/* ===== 全局后台任务管理（async 停止）=====
 *
 * startBackgroundTasks 启动后台巡检任务，
 * stopBackgroundTasks 为 async，等待所有任务实际终止后再返回，
 * 防止 resetKeyManagerState 后旧任务访问已释放缓存。
 *
 * 注意：startBackgroundTasks / stopBackgroundTasks 直连
 *   "../core/background-tasks" 再导出，此处补导 isBackgroundTasksRunning。
 */
export { isBackgroundTasksRunning } from "../core/background-tasks";

/* ===== 设备绑定独立 API =====
 *
 * 由调用方显式控制。
 * SecurityCenter.vue 在 initGlobalKey 成功后调用 bindDevice()，
 * 失败仅 Toast 提示不阻塞主流程（始终写入当前机器码）。
 */
export { bindDevice } from "../key/global-verthys";

/* ===== 错误码 i18n 翻译工具 =====
 *
 * 将 VerthysResult 错误码翻译为用户可读中文消息，
 * 供所有 Vue 组件复用，避免在每个组件中重复 switch/case。
 */
export { translateVerthysError } from "../utils/verthys-error-i18n";
