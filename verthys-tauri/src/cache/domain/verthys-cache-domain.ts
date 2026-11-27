/*
 * cache/domain/verthys-cache-domain.ts — Verthys 缓存领域门面（VerthysCacheDomain）
 *
 * 门面只做装配与跨域编排，五类缓存各由独立单元承载：
 *   - ModuleCache        模块数据缓存 + 模块登录状态（module-cache.ts）
 *   - RecordScanCache    记录扫描缓存（LRU-5000 + 64KB 大体积管控）
 *   - SummaryCache       摘要缓存（常驻，无淘汰）+ 早停扫描
 *   - TypeIdCache        权威类型 ID 缓存（类型盲索引）
 *   - FullRecordCache    全量记录缓存（LRU-50）+ 删除标记
 *
 * 跨域编排仅保留在本文件：
 *   1. module 登出 / 全量清空时按固定顺序清空各域缓存
 *   2. 批量取 dataB64：扫描缓存优先，未命中或大体积置空时回退全量缓存
 *   3. addFullRecord：全量缓存写入 + 摘要同步 + 类型 ID 失效
 *   4. 扫描清除事件转发（scan-cleared / summary-cleared）
 *
 * 并发与一致性约束（各单元内部实现，门面保证装配原子性）：
 *   1. 清除与扫描竞态：代际令牌（Generation Token）使旧扫描自动失效
 *   2. 数据一致性：全量记录写缓存前在 deletionMutex 内完成
 *      "检查-写入"原子操作
 *   3. 游标资源竞争：早停扫描与全量摘要扫描经同一 mutex 互斥
 *   4. 路径切换：批次合并前校验令牌 + 路径，不一致立即终止扫描
 *
 * 集成说明：
 *   - pendingDeletionIds / committedDeletionIds 与 verthys-flush-service 共享
 *     同一 Set 实例（由 verthys-cache.ts 绑定层注入），保持"冲刷队列 ↔ 缓存
 *     扫描过滤"单一权威源，杜绝两套集合漂移导致删除复活
 *   - 底层 verthys IPC 经 VerthysCacheApi 接口注入（可测试），停止钩子
 *     stopBackgroundTasks 由绑定层注入（domain 不导入 core 层，依赖单向）
 *   - UI 状态经 KeyStateForCache 最小接口注入（接口隔离原则）：领域层仅
 *     依赖 moduleKeyReady 的读写能力，不感知完整 KeyState 与 Vue 实现
 *   - 快照提供者注册经 registerSnapshotProvider() 内部封装：绑定层只触发
 *     注册，不直接触碰 getScanSnapshot 内部方法（封装性）
 */
import type { ModuleId, ScannedRecord } from "../../types/key_manager";
import type { SummaryRecord } from "../../lib/verthys";
import { TypedEventEmitter } from "../concurrency/typed-event-emitter";
import { estimateBase64Size } from "../shared/base64-size";
// MODULE_CACHE_KEY：权威模块表（constants 层零依赖）
import { MODULE_CACHE_KEY } from "../../constants/key_manager_const";
// 快照注册通道：经 verthys-flush 绑定层的 setSnapshotProvider 单向注入
//   （verthys-flush → verthys-flush-service，无任何指向本文件的回边，无循环依赖）
import { setSnapshotProvider } from "../composition/verthys-flush";
import type {
  KeyStateForCache,
  ScanProgress,
  VerthysCacheApi,
  VerthysCacheDomainDeps,
  VerthysCacheEventMap,
} from "./cache-contracts";
import { ModuleCache } from "./module-cache";
import { RecordScanCache } from "./record-scan-cache";
import { SummaryCache } from "./summary-cache";
import { TypeIdCache } from "./type-id-cache";
import { FullRecordCache } from "./full-record-cache";

export type {
  KeyStateForCache,
  ScanProgress,
  VerthysCacheApi,
  VerthysCacheDomainDeps,
  VerthysCacheEventMap,
} from "./cache-contracts";

export class VerthysCacheDomain extends TypedEventEmitter<VerthysCacheEventMap> {
  private readonly modules: ModuleCache;
  private readonly recordScan: RecordScanCache;
  private readonly summary: SummaryCache;
  private readonly typeIds: TypeIdCache;
  private readonly fullRecords: FullRecordCache;
  private readonly stopBackgroundTasksHook: () => Promise<void>;

  constructor(
    verthysApi: VerthysCacheApi,
    keyState: KeyStateForCache,
    getCurrentVerthysPath: () => string | null,
    deps: VerthysCacheDomainDeps,
  ) {
    super();
    this.modules = new ModuleCache(keyState);
    this.typeIds = new TypeIdCache(verthysApi, getCurrentVerthysPath, deps.pendingDeletionIds);
    this.recordScan = new RecordScanCache(
      verthysApi,
      getCurrentVerthysPath,
      deps.pendingDeletionIds,
      () => this.emit("scan-cleared"),
      (type) => this.typeIds.clear(type),
    );
    this.summary = new SummaryCache(
      verthysApi,
      getCurrentVerthysPath,
      deps.pendingDeletionIds,
      () => this.emit("summary-cleared"),
      (type) => this.typeIds.clear(type),
    );
    this.fullRecords = new FullRecordCache(
      verthysApi,
      deps.pendingDeletionIds,
      deps.committedDeletionIds,
      deps.shouldAbortBackgroundWork,
    );
    this.stopBackgroundTasksHook = deps.stopBackgroundTasks;
  }

  /* ==================== 快照提供（ID 复用防护） ==================== */

  /**
   * 注册快照提供者（封装性：绑定层只触发注册，不直接触碰内部方法）。
   *
   * 组合根 verthys-cache.ts 在 initVerthysCache() 中调用本方法一次；内部经
   * verthys-flush 的 setSnapshotProvider 将 getScanSnapshot 登记为删除校验
   * 的快照来源。快照读取走 LRU peek（只读不触碰 recency），删除入队时
   * 不扰动正常访问的 LRU 顺序。
   */
  registerSnapshotProvider(): void {
    setSnapshotProvider((id) => this.getScanSnapshot(id));
  }

  /** 返回记录快照子集，供冲刷队列的 ID 复用校验使用 */
  getScanSnapshot(id: number): { name: string; type: number; dataB64: string } | null {
    return this.recordScan.snapshot(id);
  }

  /* ==================== 1. 模块数据缓存 ==================== */

  /** 读取模块缓存数据 */
  getModuleCache<T>(key: string): { data: T | null; recordId: number | null } {
    return this.modules.get<T>(key);
  }

  /** 写入模块缓存数据 */
  setModuleCache<T>(key: string, data: T, recordId: number | null = null): void {
    this.modules.set(key, data, recordId);
  }

  /** 清空指定模块缓存（不传 key 则清空全部） */
  clearModuleCache(key?: string): void {
    this.modules.clear(key);
  }

  /* ==================== 2. 模块独立密钥会话状态 ==================== */

  /** 标记模块已登录（口令已交付 worker；渲染层不保存原始密钥） */
  markModuleReady(moduleId: ModuleId): void {
    this.modules.markReady(moduleId);
  }

  /** 登出模块（清除登录状态与该模块的全部明文缓存） */
  removeModuleKey(moduleId: ModuleId): void {
    this.modules.clearReady(moduleId);
    /* 模块锁定后其记录不再可解，渲染层不能继续持有任何明文副本：
     * 列表缓存、扫描/摘要/全量记录缓存都可能包含该模块条目。扫描游标
     * 一并重置，解锁后从零重扫，避免锁定窗口内的失败区段被增量跳过。
     * 清理范围覆盖其他模块的同构缓存，属安全优先的过度清理，代价是
     * 下次进入模块重新扫描一次。 */
    this.modules.clear(MODULE_CACHE_KEY[moduleId]);
    this.recordScan.clear();
    this.summary.clear();
    this.fullRecords.clear();
  }

  /** 清空全部模块登录状态（lockAll 时调用） */
  clearModuleKeyCache(): void {
    this.modules.clearAllReady();
  }

  /* ==================== 3. 记录扫描缓存 ==================== */

  /** 确保记录扫描缓存覆盖最新记录（游标批量扫描 + 进度回调） */
  ensureRecordScan(onProgress?: (progress: ScanProgress) => void): Promise<void> {
    return this.recordScan.ensure(onProgress);
  }

  /** 请求取消进行中的记录扫描（批次边界生效） */
  cancelRecordScan(): void {
    this.recordScan.cancel();
  }

  /** 读取扫描期发现的损坏条目 ID（升序；供完整性巡检与诊断使用） */
  getScanFailedIds(): number[] {
    return this.recordScan.getFailedIds();
  }

  /** 从扫描缓存中按类型获取记录 ID 列表（O(1) 索引查询，已排序） */
  getRecordIdsByType(type: number): number[] {
    return this.recordScan.idsByType(type);
  }

  /** 从扫描缓存中获取单条记录数据（无 IPC 调用；LRU 访问触碰） */
  getRecordFromScan(id: number): ScannedRecord | null {
    return this.recordScan.get(id);
  }

  /** 使扫描缓存中的单条记录失效（删除记录后调用） */
  invalidateScannedRecord(id: number): void {
    this.recordScan.invalidate(id);
  }

  /** 将新增记录同步到扫描缓存（添加记录后调用） */
  addRecordToScan(id: number, type: number, name: string, dataB64: string): void {
    this.recordScan.add(id, type, name, dataB64);
  }

  /** 非阻塞清除扫描缓存（立即失效在途扫描并允许新扫描启动） */
  clearRecordScanCache(): void {
    this.recordScan.clear();
  }

  /**
   * 批量获取多条记录的 dataB64（扫描缓存优先 + 并行 IPC 回退）。
   *
   * 流程：
   *   1. 逐条取扫描缓存 —— 命中且带数据则零 IPC
   *   2. miss 或 dataB64 为空（超过管控阈值的大体积记录被置空）→ 收集 fallbackIds
   *   3. Promise.all 并行回退。注意：worker 侧为单消费者串行执行，
   *      并行只重叠前端的往返与 JSON 解析等待，不提高后端吞吐；
   *      真正省下主线程的是解密下沉（AEAD 与密钥派生在 worker 池执行）。
   *
   * 返回 Map<id, dataB64>（仅含成功获取且 dataB64 非空的记录）。
   * 调用方应先 await ensureRecordScan() 确保扫描缓存就绪。
   */
  async getRecordsDataB64Batch(ids: number[]): Promise<Map<number, string>> {
    const result = new Map<number, string>();
    const fallbackIds: number[] = [];
    for (const id of ids) {
      // 待删除 ID 不返回（磁盘存在也不返回，杜绝删除复活）
      if (this.fullRecords.pendingDeletionIds.has(id)) continue;
      const r = this.recordScan.get(id);
      if (r && r.dataB64) {
        result.set(id, r.dataB64);
      } else {
        fallbackIds.push(id); // 缓存未命中或大体积管控置空 → IPC 回退
      }
    }
    if (fallbackIds.length > 0) {
      const frs = await Promise.all(fallbackIds.map((id) => this.fullRecords.get(id)));
      for (let i = 0; i < fallbackIds.length; i++) {
        const fr = frs[i];
        if (fr && fr.dataB64) result.set(fallbackIds[i], fr.dataB64);
      }
    }
    return result;
  }

  /* ==================== 4. 摘要缓存 ==================== */

  /** 确保摘要缓存覆盖全部记录（仅元数据，不解密数据块） */
  ensureSummaryScan(): Promise<void> {
    return this.summary.ensure();
  }

  /** 请求取消进行中的摘要扫描（语义同记录扫描） */
  cancelSummaryScan(): void {
    this.summary.cancel();
  }

  /** 从摘要缓存中按类型获取记录 ID 列表（历史迁移/诊断专用） */
  getSummaryIdsByType(type: number): number[] {
    return this.summary.idsByType(type);
  }

  /** 按类型查找首条记录 LID（早停扫描，关键路径专用） */
  findLidByTypeEarlyStop(type: number): Promise<number | null> {
    return this.summary.findLidByTypeEarlyStop(type);
  }

  /** 从摘要缓存获取单条记录（无 IPC 调用；仅返回元数据） */
  getSummaryRecord(id: number): SummaryRecord | null {
    return this.summary.get(id);
  }

  /** 获取摘要缓存中所有记录 ID（用于完整性巡检、全量遍历，已排序） */
  getAllSummaryIds(): number[] {
    return this.summary.allIds();
  }

  /** 获取摘要缓存当前条目数（调试/监控用） */
  getSummaryCacheSize(): number {
    return this.summary.size();
  }

  /** 将新增/编辑记录的摘要同步到缓存（add/edit 后立即调用） */
  addSummaryRecord(rec: SummaryRecord): void {
    this.summary.add(rec);
  }

  /** 使摘要缓存中的单条记录失效（删除记录后调用） */
  invalidateSummaryRecord(id: number): void {
    this.summary.invalidate(id);
  }

  /** 清空整个摘要缓存（lockAll / flush 后调用；立即失效进行中扫描） */
  clearSummaryCache(): void {
    this.summary.clear();
  }

  /* ==================== 5. 权威类型 ID（类型盲索引） ==================== */

  /** 枚举并缓存指定业务类型的完整记录 ID 列表 */
  ensureTypeIds(type: number): Promise<number[]> {
    return this.typeIds.ensure(type);
  }

  /** 清空类型 ID 缓存；传 type 只失效该类型 */
  clearTypeIdCache(type?: number): void {
    this.typeIds.clear(type);
  }

  /* ==================== 6. 全量记录缓存（第二层：LRU-50） ==================== */

  /** 获取单条记录的完整数据（按需加载，含 LRU 缓存） */
  getFullRecord(id: number): Promise<ScannedRecord | null> {
    return this.fullRecords.get(id);
  }

  /** 检查全量记录缓存中是否已存在指定 ID 的记录（不触发加载） */
  hasFullRecord(id: number): boolean {
    return this.fullRecords.has(id);
  }

  /** 预加载多条记录（被动补齐机制；会话结束立即停止） */
  prefetchFullRecords(ids: number[]): Promise<void> {
    return this.fullRecords.prefetch(ids);
  }

  /** 使全量记录缓存中的单条记录失效（编辑/删除后调用；安全覆写） */
  invalidateFullRecord(id: number): void {
    this.fullRecords.invalidate(id);
  }

  /**
   * 直接将完整记录写入全量缓存（导入/新增后调用）。
   *
   * 场景：前端已持有完整 dataB64（刚加密入库），直接写入避免下次查看
   * 再次 IPC 获取。同时更新摘要缓存，确保列表立即显示新记录。
   */
  addFullRecord(
    id: number,
    type: number,
    name: string,
    dataB64: string,
    dataSize?: number,
  ): void {
    // 1. 写入全量记录缓存（含 LRU 淘汰）
    this.fullRecords.set({ id, type, name, dataB64 });

    // 2. 同步更新摘要缓存（physicalOffset/merkleLeaf 为占位值，
    //    下次 ensureSummaryScan 会从后端读取真实值覆盖）；
    //    摘要写入同时失效该类型的旧枚举结果。
    //    dataSize 回退估算使用 estimateBase64Size
    //    （cache/shared/base64-size.ts 单一权威源，处理填充字符）
    const summary: SummaryRecord = {
      id,
      type,
      name,
      dataSize: dataSize ?? estimateBase64Size(dataB64),
      physicalOffset: 0,
      merkleLeaf: "",
      createdTime: Math.floor(Date.now() / 1000), /* 创建时间戳 */
    };
    this.summary.add(summary);
  }

  /** 清空全量记录缓存（clear 逐条安全覆写） */
  clearFullRecordCache(): void {
    this.fullRecords.clear();
  }

  /** 获取全量记录缓存当前条目数（调试/监控用） */
  getFullRecordCacheSize(): number {
    return this.fullRecords.size();
  }

  /* ==================== 删除标记管理（共享集合，mutex 保护） ==================== */

  /** 标记记录进入待删除状态（立即移除已缓存的全量记录） */
  markForDeletion(id: number): Promise<void> {
    return this.fullRecords.markForDeletion(id);
  }

  /** 解除待删除标记（回滚场景） */
  unmarkForDeletion(id: number): Promise<void> {
    return this.fullRecords.unmarkForDeletion(id);
  }

  /** 清空待删除标记集合（新会话初始化） */
  clearPendingDeletionIds(): Promise<void> {
    return this.fullRecords.clearPendingDeletionIds();
  }

  /* ==================== 全量清空 ==================== */

  /**
   * 统一清空所有 Verthys 缓存（lockAll 一次性调用）。
   *
   * 先 await stopBackgroundTasks（注入钩子）确保后台任务
   * 完全终止，再清空缓存，杜绝「旧后台任务访问已释放缓存」的竞态。
   */
  async clearAllVerthysCaches(): Promise<void> {
    // 先 await 后台任务完全终止（注入钩子），再清空缓存
    await this.stopBackgroundTasksHook();
    // 首先清空模块登录状态，lockAll 统一清空入口的安全闭环
    this.modules.clearAllReady();
    this.summary.clear();
    this.typeIds.clear();
    this.fullRecords.clear();
    this.recordScan.clear();
    this.modules.clear();
  }
}
