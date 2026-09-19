/*
 * cache/composition/verthys-cache.ts — Verthys 缓存层（对外 API 绑定层 / 组合根）
 *
 * ★ 组合根增强设计落地：在并发重构基础上实施五项改进：
 *   1. 延迟初始化：domain 的创建与依赖装配收拢进 initVerthysCache()，
 *      由应用启动流程（app/bootstrap.ts）显式调用，模块加载零副作用，
 *      杜绝"模块求值期依赖未就绪"的初始化时序隐患
 *   2. 打破循环依赖：不再 re-export background-tasks 的 start/stop，
 *      消费方直接从 core/background-tasks 导入；本文件仅保留对
 *      stopBackgroundTasks 的钩子注入（domain → core 依赖单向化）
 *   3. 类型安全绑定：全部对外 API 改为显式包装函数（含返回类型标注），
 *      彻底消除 .bind 的类型推断丢失（尤其泛型与重载签名）
 *   4. 接口隔离：领域层依赖 KeyStateForCache 最小接口，
 *      不再接收完整 keyState（含全部 Vue 响应式状态）
 *   5. 封装性增强：快照提供者注册经 domain.registerSnapshotProvider()
 *      内部封装，组合根不直接触碰领域内部方法
 *
 * 五大缓存职责说明（与旧版一致，职责划分同 verthys-cache-domain.ts 头注）：
 *   1. 模块数据缓存（跨路由/模块切换持久化，消除"先空后有"闪烁）
 *   2. 模块独立密钥会话缓存（明文，lockAll 时清零，Uint8Array 可零填充）
 *   3. 共享记录扫描缓存（LRU-5000 + 64KB 大体积管控，消除多模块重复扫描）
 *   4. 摘要缓存 summaryCache（第一层：常驻内存，永久存在）
 *   5. 全量记录缓存 fullRecordCache（第二层：LRU-50，按需加载，永不截断）
 *
 * ★ 组合根装配关系（initVerthysCache 内完成，仅此一处）：
 *   - 注入 VerthysCacheApi 适配器（lib/verthys 真实 IPC → 领域接口，依赖倒置）
 *   - 注入 KeyStateForCache 适配（keyState.moduleKeyReady 最小接口）
 *   - 注入与 verthys-flush-service 共享的 pendingDeletionIds / committedDeletionIds
 *     同一 Set 实例 → 冲刷队列与缓存扫描的删除过滤保持单一权威源
 *   - 注入 shouldAbortBackgroundWork（isCacheTimersCancelled）与
 *     stopBackgroundTasks 钩子（domain 不导入 core 层，依赖单向）
 *   - 经 domain.registerSnapshotProvider() 注册快照提供者：flush 删除
 *     校验经 LRU peek 读取扫描缓存快照
 *
 * ★ 模块依赖关系（单向化后）：
 *   verthys-cache.ts → verthys-flush.ts（共享删除集合 + re-export flush API，单向）
 *   verthys-cache.ts → verthys-cache-domain.ts（组合根装配领域类，单向）
 *   verthys-cache.ts → core/background-tasks.ts（仅导入 stopBackgroundTasks 钩子）
 *   background-tasks.ts → verthys-cache.ts（ensureRecordScan/prefetchFullRecords
 *     等访问器，仅运行时调用）
 *   ★ 残余双向边（verthys-cache ↔ background-tasks）安全性：双方均仅在
 *     运行时（函数调用时）访问对方导出，无模块求值期访问；ES Module
 *     live binding + 本文件"加载零副作用 + 调用前已初始化"保证安全。
 *     公共 API 面已消除循环：start/stop 由 background-tasks 自行导出，
 *     消费方直接导入，不再经本文件转发。
 *
 * ★ 初始化契约：
 *   - initVerthysCache() 幂等，由 MainView.onBeforeMount 调用（v3 懒加载
 *     架构修复：bootstrap 静态导入会将业务层拖入 index 主包 — 已迁出；
 *     父先于子挂载时序保证先于全部子组件消费方）；
 *   - 全部对外 API 经 ensureDomain() 守卫：未初始化时 fail-fast 抛出
 *     （可诊断的初始化顺序缺陷优于静默 undefined）。
 */
import {
  verthysScanOpen, verthysScanNext, verthysScanClose,
  verthysEnumerateRecords, verthysEnumerateRecordsStream,
  verthysScanSummaryOpen, verthysScanSummaryNext, verthysScanSummaryClose,
  verthysGetRecord,
} from "../../lib/verthys";
import type { SummaryRecord } from "../../lib/verthys";
import { getCurrentVerthysPath, keyState } from "../../state/key_state";
import type { ModuleId, ScannedRecord } from "../../types/key_manager";
import {
  VerthysCacheDomain,
  type VerthysCacheApi,
  type KeyStateForCache,
} from "../domain/verthys-cache-domain";
import {
  isCacheTimersCancelled,
  pendingDeletionIds,
  committedDeletionIds,
} from "./verthys-flush";
// ★ 仅注入停止钩子（clearAllVerthysCaches 前置等待后台任务终止）；
//   startBackgroundTasks 不再由本文件导入或转发
import { stopBackgroundTasks } from "../../core/background-tasks";
import { createLogger } from "../../utils/logger";

const log = createLogger("verthys-cache");

// ★ re-export flush 队列 API（统一冲刷队列服务）
export {
  persistVerthys,
  deleteAndPersist,
  deleteAndPersistBatch,
  waitForFlush,
  isFlushing,
  cancelDebouncedFlush,
  resetFlushChain,
  clearAllCacheTimers,
  scheduleBackgroundFlush,
  isPendingDeletion,
  isCacheDirty,
  clearPendingDeletionIds,
  setCacheDirty,
  pendingFlushWorkRef,
  enqueueFlush,
  flushVerthysNow,
  flushQueueStatus,
} from "./verthys-flush";

/* ------------------------------------------------------------------ *
 * 组合根：延迟初始化（模块加载零副作用）                               *
 * ------------------------------------------------------------------ */

/** 领域实例持有者（initVerthysCache 装配，全局唯一） */
let domain: VerthysCacheDomain | null = null;

/**
 * 初始化缓存层（应用启动流程显式调用一次；幂等）。
 *
 * 装配内容：VerthysCacheApi 适配器 + KeyStateForCache 最小接口 +
 * 共享删除集合 + 中止/停止钩子 + 快照提供者注册。
 * 构造函数仅存储引用、不读取任何运行时状态（verthys 路径 / keyState
 * 均延迟到实际调用时访问），因此调用时机无外部前置条件。
 */
export function initVerthysCache(): void {
  if (domain) return;

  /** VerthysCacheApi 适配器：lib/verthys 真实 IPC → 领域接口（流式批次就地归一化） */
  const verthysApi: VerthysCacheApi = {
    scanOpen: verthysScanOpen,
    scanNext: verthysScanNext,
    scanClose: verthysScanClose,
    enumerateRecords: verthysEnumerateRecords,
    enumerateRecordsStream: (startId, batchSize, onBatch) =>
      verthysEnumerateRecordsStream(startId, batchSize, (batch) => {
        // EnumerateBatch 原始字段（rtype/data）→ 领域模型（type/dataB64）
        onBatch({
          records: batch.records.map(e => ({
            id: e.id,
            type: e.rtype,
            name: e.name,
            dataB64: e.data,
          })),
        });
      }),
    scanSummaryOpen: verthysScanSummaryOpen,
    scanSummaryNext: verthysScanSummaryNext,
    scanSummaryClose: verthysScanSummaryClose,
    getRecord: verthysGetRecord,
  };

  // ★ 接口隔离：领域层仅依赖 moduleKeyReady 读写，
  //   以最小接口适配，不暴露完整 KeyState（Vue 响应式状态与实现解耦）
  const keyStateForCache: KeyStateForCache = {
    moduleKeyReady: keyState.moduleKeyReady,
  };

  domain = new VerthysCacheDomain(verthysApi, keyStateForCache, getCurrentVerthysPath, {
    // ★ 共享删除过滤集合（与 VerthysFlushService 同一实例，单一权威源）
    pendingDeletionIds,
    committedDeletionIds,
    // 后台预加载中止钩子（lockAll / resetFlushChain 触发）
    shouldAbortBackgroundWork: isCacheTimersCancelled,
    // clearAllVerthysCaches 前置钩子（await 后台任务完全终止后再清缓存）
    stopBackgroundTasks,
  });

  // ★ 注册快照提供者（领域内部封装），
  //    供 verthys-flush 的 deleteAndPersist 进行 ID 复用校验。
  //    经 LRU peek 只读访问 recordScanCache（不扰动 recency），
  //    避免 verthys-flush ↔ verthys-cache 循环导入。
  domain.registerSnapshotProvider();

  log.info("VerthysCache 组合根初始化完成（领域实例装配 + 快照提供者注册）");
}

/** 确保领域实例已初始化（fail-fast 守卫） */
function ensureDomain(): VerthysCacheDomain {
  if (!domain) {
    throw new Error("VerthysCache 尚未初始化，请先调用 initVerthysCache()（MainView.onBeforeMount 挂载流程已接入）");
  }
  return domain;
}

/* ------------------------------------------------------------------ *
 * 对外 API 绑定（签名与旧版逐一对应）                                  *
 *                                                                    *
 * ★ 全部导出改为显式包装函数并标注返回类型，                       *
 *   彻底避免 .bind 绑定造成的泛型擦除与重载签名类型推断丢失；         *
 *   每次调用经 ensureDomain() 守卫，未初始化 fail-fast。              *
 * ------------------------------------------------------------------ */

/* === 1. 模块数据缓存 === */

/** 读取模块缓存数据 */
export function getModuleCache<T>(key: string): { data: T | null; recordId: number | null } {
  return ensureDomain().getModuleCache<T>(key);
}

/** 写入模块缓存数据 */
export function setModuleCache<T>(key: string, data: T, recordId: number | null = null): void {
  ensureDomain().setModuleCache(key, data, recordId);
}

/** 清空指定模块缓存（不传 key 则清空全部） */
export function clearModuleCache(key?: string): void {
  ensureDomain().clearModuleCache(key);
}

/* === 2. 模块独立密钥会话缓存 === */

/** 缓存模块独立密钥到会话（验证成功后调用；Uint8Array 存储 + 闲置 15min 自动销毁） */
export function cacheModuleKey(moduleId: ModuleId, key: string): void {
  ensureDomain().cacheModuleKey(moduleId, key);
}

/** 获取会话中缓存的模块密钥（未登录返回 null） */
export function fetchModuleKey(moduleId: ModuleId): string | null {
  return ensureDomain().fetchModuleKey(moduleId);
}

/** 移除指定模块的会话密钥缓存（登出模块/闲置超时时调用） */
export function removeModuleKey(moduleId: ModuleId): void {
  ensureDomain().removeModuleKey(moduleId);
}

/** 清零全部模块密钥缓存（lockAll 时调用，安全零填充） */
export function clearModuleKeyCache(): void {
  ensureDomain().clearModuleKeyCache();
}

/* === 3. 共享记录扫描缓存 === */

/** 确保记录扫描缓存覆盖最新记录（游标批量扫描 + v1 回退；并发复用同一 Promise） */
export function ensureRecordScan(): Promise<void> {
  return ensureDomain().ensureRecordScan();
}

/** 从扫描缓存中按类型获取记录 ID 列表（O(1) 索引查询，已排序） */
export function getRecordIdsByType(type: number): number[] {
  return ensureDomain().getRecordIdsByType(type);
}

/** 从扫描缓存中获取单条记录数据（无 IPC 调用） */
export function getRecordFromScan(id: number): ScannedRecord | null {
  return ensureDomain().getRecordFromScan(id);
}

/** 使扫描缓存中的单条记录失效（删除记录后调用，杜绝"删除复活"） */
export function invalidateScannedRecord(id: number): void {
  ensureDomain().invalidateScannedRecord(id);
}

/** 将新增记录同步到扫描缓存（添加记录后调用） */
export function addRecordToScan(id: number, type: number, name: string, dataB64: string): void {
  ensureDomain().addRecordToScan(id, type, name, dataB64);
}

/** 清空整个扫描缓存（lockAll / verthysFlush 后调用；非阻塞令牌失效） */
export function clearRecordScanCache(): void {
  ensureDomain().clearRecordScanCache();
}

/** 批量获取多条记录的 dataB64（扫描缓存优先 + 并行 IPC 回退） */
export function getRecordsDataB64Batch(ids: number[]): Promise<Map<number, string>> {
  return ensureDomain().getRecordsDataB64Batch(ids);
}

/* === 4. 摘要缓存（第一层：常驻，无淘汰） === */

/** 确保摘要缓存覆盖全部记录（解锁后 1-2 秒内完成） */
export function ensureSummaryScan(): Promise<void> {
  return ensureDomain().ensureSummaryScan();
}

/** 从摘要缓存中按类型获取记录 ID 列表（O(1) 索引查询，已排序） */
export function getSummaryIdsByType(type: number): number[] {
  return ensureDomain().getSummaryIdsByType(type);
}

/** 按类型查找首条记录 LID（早停扫描，关键路径专用；与全量摘要扫描互斥） */
export function findLidByTypeEarlyStop(type: number): Promise<number | null> {
  return ensureDomain().findLidByTypeEarlyStop(type);
}

/** 从摘要缓存获取单条记录（无 IPC 调用，仅元数据） */
export function getSummaryRecord(id: number): SummaryRecord | null {
  return ensureDomain().getSummaryRecord(id);
}

/** 获取摘要缓存中所有记录 ID（用于完整性巡检、全量遍历，已排序） */
export function getAllSummaryIds(): number[] {
  return ensureDomain().getAllSummaryIds();
}

/** 获取摘要缓存当前条目数（调试/监控用） */
export function getSummaryCacheSize(): number {
  return ensureDomain().getSummaryCacheSize();
}

/** 将新增/编辑记录的摘要同步到缓存（add/edit 后立即调用） */
export function addSummaryRecord(rec: SummaryRecord): void {
  ensureDomain().addSummaryRecord(rec);
}

/** 使摘要缓存中的单条记录失效（删除记录后调用，杜绝"删除复活"） */
export function invalidateSummaryRecord(id: number): void {
  ensureDomain().invalidateSummaryRecord(id);
}

/** 清空整个摘要缓存（lockAll / verthysFlush 后调用） */
export function clearSummaryCache(): void {
  ensureDomain().clearSummaryCache();
}

/* === 5. 全量记录缓存（第二层：LRU-50，按需加载） === */

/** 获取单条记录的完整数据（按需加载，不受 64KB 管控限制） */
export function getFullRecord(id: number): Promise<ScannedRecord | null> {
  return ensureDomain().getFullRecord(id);
}

/** 检查全量记录缓存中是否已存在指定 ID 的记录（不触发加载） */
export function hasFullRecord(id: number): boolean {
  return ensureDomain().hasFullRecord(id);
}

/** 预加载多条记录（后台任务二：被动补齐机制，低优先级可中止） */
export function prefetchFullRecords(ids: number[]): Promise<void> {
  return ensureDomain().prefetchFullRecords(ids);
}

/** 使全量记录缓存中的单条记录失效（编辑/删除后调用；安全覆写） */
export function invalidateFullRecord(id: number): void {
  ensureDomain().invalidateFullRecord(id);
}

/** 直接将完整记录写入全量缓存（导入/新增后调用，同步更新摘要缓存） */
export function addFullRecord(id: number, type: number, name: string, dataB64: string, dataSize?: number): void {
  ensureDomain().addFullRecord(id, type, name, dataB64, dataSize);
}

/** 清空全量记录缓存（lockAll / verthysFlush 后调用，安全覆写） */
export function clearFullRecordCache(): void {
  ensureDomain().clearFullRecordCache();
}

/** 获取全量记录缓存当前条目数（调试/监控用） */
export function getFullRecordCacheSize(): number {
  return ensureDomain().getFullRecordCacheSize();
}

/* === 统一清空 === */

/** 统一清空所有 Verthys 缓存（lockAll 一次性调用；先 await 后台任务终止） */
export function clearAllVerthysCaches(): Promise<void> {
  return ensureDomain().clearAllVerthysCaches();
}