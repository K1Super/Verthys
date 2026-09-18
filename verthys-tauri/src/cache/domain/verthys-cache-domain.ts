/*
 * cache/domain/verthys-cache-domain.ts — Verthys 缓存领域（VerthysCacheDomain）
 *
 * ★ verthys-cache 并发重构方案（verthys-cache-refactor-concurrency-fix.md §三 +
 *   修正附录）核心实现：将缓存逻辑封装为可注入、可测试的领域类，
 *   对外 API 由 cache/composition/verthys-cache.ts 绑定导出（签名与旧版逐一对应）。
 *
 * 五大缓存
 *   1. 模块数据缓存 moduleDataCache（跨路由/模块切换持久化）
 *   2. 模块独立密钥会话缓存 moduleKeyCache（明文，Uint8Array 可零填充，
 *      闲置 15 分钟自动销毁，lockAll 时清零）
 *   3. 共享记录扫描缓存 recordScanCache（LRU-5000 + 64KB 大体积管控）
 *   4. 摘要缓存 summaryCache（第一层：常驻内存，永久存在，无淘汰）
 *   5. 全量记录缓存 fullRecordCache（第二层：LRU-50，按需加载，永不截断）
 *
 * ★ 方案根治的六项缺陷（方案 §一 逐条对应）：
 *   1. 并发竞态：clearRecordScanCache 与进行中扫描的竞态 → 代际令牌
 *      （Generation Token）使旧扫描自动失效，非阻塞清除立即生效
 *   2. 数据一致性：getFullRecord 写缓存前未复查待删集合 → 写入前获取
 *      deletionMutex 做"检查-写入"原子操作
 *   3. 游标资源竞争：findLidByTypeEarlyStop 与 ensureSummaryScan 同时开
 *      多游标 → 早停扫描与全量摘要扫描经 summaryScanMutex 互斥，且
 *      早停扫描先等待进行中的全量扫描完成并复查缓存
 *   4. 扫描状态清理缺失：scanInProgress 未置 null → finally 无条件清空，
 *      保证扫描结束后可重新触发
 *   5. 路径切换未检测：旧扫描结果合并到新路径缓存 → 批次合并前校验
 *      令牌 + 路径，不一致立即 invalidateActiveScanToken 终止扫描
 *   6. AsyncMutex 使用错误：acquire() 返回释放函数，调用方在 finally 中释放
 *
 * ★ 修正附录（§一）落实：maxScannedId 仅由 mergeScanEntry 维护，
 *   runRecordScan 的 finally 不再用缓存键重算覆盖（LRU 淘汰会使重算值
 *   偏小 → 增量扫描从错误 ID 开始 → 大量重复扫描甚至循环）。
 *   computeMaxScannedId 方法按附录要求删除。invalidateScannedRecord 在
 *   删除当前最大 ID 时仍需重算（现网 ID 复用缺陷修复，语义不同，保留）。
 *
 * ★ 集成说明（关联项目顶级适配）：
 *   - pendingDeletionIds / committedDeletionIds 与 verthys-flush-service 共享
 *     同一 Set 实例（由 verthys-cache.ts 绑定层注入），保持"冲刷队列 ↔ 缓存
 *     扫描过滤"单一权威源，杜绝两套集合漂移导致删除复活
 *   - Node 'events' 的 EventEmitter 在浏览器 bundle 不可解析，以零依赖
 *     TypedEventEmitter 等价替代（API 对齐，事件表静态类型化）
 *   - 底层 verthys IPC 经 VerthysCacheApi 接口注入（可测试），停止钩子
 *     stopBackgroundTasks 由绑定层注入（domain 不导入 core 层，依赖单向）
 *   - UI 状态经 KeyStateForCache 最小接口注入（接口隔离原则）：领域层仅
 *     依赖 moduleKeyReady 的读写能力，不感知完整 KeyState 与 Vue 实现，
 *     测试可用普通对象 { value: {...} } 替代响应式 Ref
 *   - 快照提供者注册经 registerSnapshotProvider() 内部封装：绑定层只触发
 *     注册，不直接触碰 getScanSnapshot 内部方法（封装性）
 *
 * ★ 评审修复（verthys-cache-domain 评审 §一/§二）：
 *   1. clearAllVerthysCaches 补充 clearModuleKeyCache（明文密钥零填充，
 *      lockAll 统一清空入口安全闭环，置于各缓存清空之首）
 *   2. addFullRecord 的 dataSize 回退估算改用 estimateBase64Size
 *      （cache/shared/base64-size.ts 单一权威源，处理填充字符，与批量协调器一致）
 *   3+5. 扫描令牌自检失效改为属主保护（invalidateScanIfCurrent）：
 *      finally 以 activeScanToken === token 的属主关系决定 scanClose 与
 *      状态清理——自检失效仍持有游标时必关（堵资源泄漏）并清理引用
 *      （无陈旧残留）；被后继扫描顶替时不关不清（防误杀后继游标，
 *      此时状态引用属于后继扫描而非陈旧值；Rust scan_controller.rs
 *      verthys_scan_open 已验证会先关闭并 abort 旧游标，残留资源由
 *      后继 scan_open 自动顶替或 worker 销毁兜底释放）
 *   4. clearModuleKeyCache 改用 MODULE_IDS 权威表驱动重置（新增模块
 *      自动覆盖，杜绝硬编码列表遗漏；逐键置 false 保持响应式更新）
 */
import type { ModuleId, ScannedRecord } from "../../types/key_manager";
import type { SummaryRecord } from "../../lib/verthys";
import { AsyncMutex } from "../concurrency/async-mutex";
import { LRUCache } from "../concurrency/lru-cache";
import { TypedEventEmitter } from "../concurrency/typed-event-emitter";
import { estimateBase64Size } from "../shared/base64-size";
// ★ MODULE_IDS：权威模块表（constants 层零依赖，新增模块自动纳入密钥重置）
import { MODULE_IDS } from "../../constants/key_manager_const";
// ★ 快照注册通道：经 verthys-flush 绑定层的 setSnapshotProvider 单向注入
//   （verthys-flush → verthys-flush-service，无任何指向本文件的回边，无循环依赖）
import { setSnapshotProvider } from "../composition/verthys-flush";
// ★ 前端 IPC 优先级门控：关键 IPC 调用标记前端活跃，后台任务据此让出 worker 通道
//   （该模块零导入，不引入循环依赖）
import { markFrontendIpcActive } from "../../core/frontend-ipc-priority";
import { createLogger } from "../../utils/logger";

const log = createLogger("verthys-cache-domain");

/* ------------------------------------------------------------------ *
 * 注入接口定义                                                        *
 * ------------------------------------------------------------------ */

/**
 * 底层 verthys IPC 访问接口（依赖倒置：领域类不直接依赖 lib/verthys 实现，
 * 由绑定层注入真实 IPC 适配器，测试可注入 mock）。
 */
export interface VerthysCacheApi {
  /** 打开记录扫描游标，返回首批记录（v2 格式；v1 抛异常触发回退） */
  scanOpen(startId: number, batchSize: number): Promise<{ records: ScannedRecord[]; exhausted: boolean }>;
  /** 拉取下一批记录（双缓冲流水线切换） */
  scanNext(batchSize: number): Promise<{ records: ScannedRecord[]; exhausted: boolean }>;
  /** 关闭记录扫描游标（释放共享内存 + C 游标 + 预取任务） */
  scanClose(): Promise<boolean>;
  /** 批量枚举记录（单次 IPC，v1 内存路径回退用） */
  enumerateRecords(startId: number): Promise<ScannedRecord[]>;
  /** 流式枚举记录（最后兜底，逐批 Channel 推送） */
  enumerateRecordsStream(
    startId: number,
    batchSize: number,
    onBatch: (batch: { records: ScannedRecord[] }) => void,
  ): Promise<number>;
  /** 打开摘要扫描游标，返回首批摘要（轻量元数据，不解密数据块） */
  scanSummaryOpen(startId: number, batchSize: number): Promise<{ records: SummaryRecord[]; exhausted: boolean }>;
  /** 拉取下一批摘要记录 */
  scanSummaryNext(batchSize: number): Promise<{ records: SummaryRecord[]; exhausted: boolean }>;
  /** 关闭摘要扫描游标 */
  scanSummaryClose(): Promise<boolean>;
  /** 读取单条完整记录（返回 base64 数据） */
  getRecord(id: number): Promise<{ type: number; name: string; dataB64: string } | null>;
}

/**
 * ★ KeyState 最小接口（接口隔离原则，方案 §二.4）。
 *
 * 领域层对 UI 状态的唯一依赖：moduleKeyReady 的读写（缓存密钥时置 true、
 * 移除/清零时置 false）。以结构化类型表达 `{ value: Record<ModuleId, boolean> }`，
 * Vue 的 `Ref<Record<ModuleId, boolean>>` 天然满足该契约（Ref.value 可读写），
 * 测试场景可用普通对象替代响应式实现，领域类不感知 Vue 与完整 KeyState。
 */
export interface KeyStateForCache {
  /** 各模块密钥已验证状态（响应式读写；领域层仅通过 .value 访问） */
  moduleKeyReady: { value: Record<ModuleId, boolean> };
}

/** VerthysCacheDomain 必需注入依赖（组合根 verthys-cache.ts 装配） */
export interface VerthysCacheDomainDeps {
  /**
   * ★ 共享待删除 ID 集合（与 VerthysFlushService 同一实例，单一权威源）。
   * 冲刷队列与缓存扫描的删除过滤据此保持完全一致。
   */
  pendingDeletionIds: Set<number>;
  /** ★ 共享已提交删除 ID 集合（同上） */
  committedDeletionIds: Set<number>;
  /**
   * 后台预加载中止钩子：返回 true 表示会话已结束（lockAll 触发
   * clearAllCacheTimers），prefetchFullRecords 应立即停止。
   * 绑定层注入 verthys-flush 的 isCacheTimersCancelled。
   */
  shouldAbortBackgroundWork: () => boolean;
  /**
   * clearAllVerthysCaches 前置钩子：await 后台任务完全终止后再清空缓存
   * （白皮书 2.2.2，杜绝"旧后台任务访问已释放缓存"竞态）。
   * 绑定层注入 core/background-tasks 的 stopBackgroundTasks
   * （经钩子注入保持 domain → core 依赖单向，不引入循环导入）。
   */
  stopBackgroundTasks: () => Promise<void>;
}

/** 领域事件表（TypedEventEmitter 静态约束；type 别名以满足 Record 索引签名约束） */
export type VerthysCacheEventMap = {
  /** 记录扫描缓存已被清空（lockAll / flush 后 / 路径切换） */
  "scan-cleared": [];
  /** 摘要缓存已被清空 */
  "summary-cleared": [];
}

/** 扫描令牌：代际 + 取消标志（方案 §二 核心机制） */
interface ScanToken {
  generation: number;
  cancelled: boolean;
}

/* ------------------------------------------------------------------ *
 * 常量（与旧版一致）                                                  *
 * ------------------------------------------------------------------ */

/** 记录扫描缓存 LRU 容量（方案 7.3：超限移除最久未使用记录，防内存溢出） */
const RECORD_CACHE_LRU_THRESHOLD = 5000;
/** 大体积 dataB64 管控阈值：超出仅缓存 id/type/name，dataB64 置空 */
const DATAB64_CACHE_MAX_BYTES = 64 * 1024;
/** 全量记录缓存 LRU 容量（improve.md "改造二" 规定：50 条） */
const FULL_RECORD_CACHE_CAPACITY = 50;
/** 扫描批大小（upgrade.md "以每批 200 条为单位逐步填充缓存"，渐进式渲染） */
const SCAN_BATCH_SIZE = 200;
/** 摘要早停扫描迭代上限：100 批 × 200 条 = 20,000 条，防后端异常导致无限循环 */
const EARLY_STOP_MAX_BATCHES = 100;
/** 模块密钥闲置超时：15 分钟（方案 7.2，不依赖手动锁屏清空） */
const MODULE_KEY_IDLE_TIMEOUT_MS = 15 * 60 * 1000;

export class VerthysCacheDomain extends TypedEventEmitter<VerthysCacheEventMap> {
  // === 缓存存储 ===
  /** 模块数据缓存（跨路由/模块切换持久化，消除"先空后有"闪烁） */
  private moduleDataCache = new Map<string, { data: unknown; recordId: number | null }>();
  /** 模块独立密钥会话缓存（方案 7.1：Uint8Array 存储，可安全零填充） */
  private moduleKeyCache = new Map<ModuleId, Uint8Array>();
  /** 方案 7.2：每模块独立的闲置超时计时器 */
  private moduleKeyTimers = new Map<ModuleId, ReturnType<typeof setTimeout>>();
  /** 记录扫描缓存（LRU-5000，淘汰时同步移除类型索引） */
  private recordScanCache: LRUCache<number, ScannedRecord>;
  /** 摘要缓存（第一层：常驻内存，永久存在，无 LRU 淘汰） */
  private summaryCache = new Map<number, SummaryRecord>();
  /** 全量记录缓存（第二层：LRU-50，永不截断 dataB64） */
  private fullRecordCache: LRUCache<number, ScannedRecord>;

  // === 记录扫描状态 ===
  private scanInProgress: Promise<void> | null = null;
  private scanGeneration = 0;
  private activeScanToken: ScanToken | null = null;
  private scanVerthysPath: string | null = null;
  private maxScannedId = 0;

  // === 摘要扫描状态 ===
  private summaryScanInProgress: Promise<void> | null = null;
  private summaryScanGeneration = 0;
  private activeSummaryScanToken: ScanToken | null = null;
  private summaryScanVerthysPath: string | null = null;
  private maxSummaryId = 0;

  // === 并发控制（方案 §二：AsyncMutex） ===
  private scanMutex = new AsyncMutex();
  private summaryScanMutex = new AsyncMutex();
  /** 保护 pendingDeletionIds 相关的"检查-写入"原子段 */
  private deletionMutex = new AsyncMutex();

  // === 删除标记（与 VerthysFlushService 共享同一实例） ===
  private pendingDeletionIds: Set<number>;
  private committedDeletionIds: Set<number>;

  // === 索引（消除 getRecordIdsByType / getSummaryIdsByType 全量遍历 + 排序开销） ===
  private recordIndexByType = new Map<number, Set<number>>();
  private summaryIndexByType = new Map<number, Set<number>>();

  // === 加载器（防并发重复 IPC：同 ID 多次请求复用同一 Promise） ===
  private fullRecordLoaders = new Map<number, Promise<ScannedRecord | null>>();

  // === 注入依赖（构造函数装配，全部必需） ===
  private readonly verthysApi: VerthysCacheApi;
  /** UI 状态最小接口（KeyStateForCache：仅 moduleKeyReady 读写） */
  private readonly keyState: KeyStateForCache;
  private readonly getCurrentVerthysPath: () => string | null;
  private readonly shouldAbortBackgroundWork: () => boolean;
  private readonly stopBackgroundTasksHook: () => Promise<void>;

  /** TextEncoder/TextDecoder 单例（模块密钥转换用，避免重复创建） */
  private keyTextEncoder = new TextEncoder();
  private keyTextDecoder = new TextDecoder();

  constructor(
    verthysApi: VerthysCacheApi,
    keyState: KeyStateForCache,
    getCurrentVerthysPath: () => string | null,
    deps: VerthysCacheDomainDeps,
  ) {
    super();
    this.verthysApi = verthysApi;
    this.keyState = keyState;
    this.getCurrentVerthysPath = getCurrentVerthysPath;
    // recordScanCache 容量 5000，淘汰时同步移除类型索引
    this.recordScanCache = new LRUCache(RECORD_CACHE_LRU_THRESHOLD, (id, rec) => this.onScanEvict(id, rec));
    // fullRecordCache 容量 50，淘汰时安全覆写 dataB64（缩短明文暴露窗口）
    this.fullRecordCache = new LRUCache(FULL_RECORD_CACHE_CAPACITY, (id, rec) => this.onFullRecordEvict(id, rec));
    // ★ 共享删除集合：注入与 VerthysFlushService 相同实例，保持过滤单一权威源
    this.pendingDeletionIds = deps.pendingDeletionIds;
    this.committedDeletionIds = deps.committedDeletionIds;
    this.shouldAbortBackgroundWork = deps.shouldAbortBackgroundWork;
    this.stopBackgroundTasksHook = deps.stopBackgroundTasks;
  }

  /* ==================== 快照提供（verthys-flush ID 复用防护） ==================== */

  /**
   * ★ 注册快照提供者（封装性：绑定层只触发注册，不直接触碰内部方法）。
   *
   * 组合根 verthys-cache.ts 在 initVerthysCache() 中调用本方法一次；内部经
   * verthys-flush 的 setSnapshotProvider 将 getScanSnapshot 登记为删除校验
   * 的快照来源。快照读取走 LRU peek（只读不触碰 recency），删除入队时
   * 不扰动正常访问的 LRU 顺序。
   */
  registerSnapshotProvider(): void {
    setSnapshotProvider((id) => this.getScanSnapshot(id));
  }

  /**
   * 返回记录快照子集（name/type/dataB64），供 VerthysFlushService 的
   * deleteAndPersist 进行 ID 复用校验（经 registerSnapshotProvider 登记）。
   *
   * ★ 使用 LRU peek（只读不触碰 recency）：删除入队时的快照读取
   *   不应扰动正常访问的 LRU 顺序。
   */
  getScanSnapshot(id: number): { name: string; type: number; dataB64: string } | null {
    const rec = this.recordScanCache.peek(id);
    if (!rec) return null;
    return { name: rec.name, type: rec.type, dataB64: rec.dataB64 };
  }

  /* ==================== 1. 模块数据缓存 ==================== */

  /** 读取模块缓存数据 */
  getModuleCache<T>(key: string): { data: T | null; recordId: number | null } {
    const entry = this.moduleDataCache.get(key);
    return { data: (entry?.data as T) || null, recordId: entry?.recordId ?? null };
  }

  /** 写入模块缓存数据 */
  setModuleCache<T>(key: string, data: T, recordId: number | null = null): void {
    this.moduleDataCache.set(key, { data, recordId });
  }

  /** 清空指定模块缓存（不传 key 则清空全部） */
  clearModuleCache(key?: string): void {
    if (key) this.moduleDataCache.delete(key);
    else this.moduleDataCache.clear();
  }

  /* ==================== 2. 模块独立密钥会话缓存 ==================== */
  /* 方案 7.1：密钥以 Uint8Array 存储，清空时零填充覆写内存，            *
 *   杜绝 V8 字符串 intern 导致明文残留堆内存。                           *
   * 方案 7.2：闲置 15 分钟自动销毁，每次访问重置计时器。                  */

  /** 方案 7.2：重置指定模块的闲置计时器（每次访问调用） */
  private resetModuleKeyTimer(moduleId: ModuleId): void {
    const existing = this.moduleKeyTimers.get(moduleId);
    if (existing) clearTimeout(existing);
    const timer = setTimeout(() => {
      log.info(`模块 ${moduleId} 密钥闲置 15min，自动销毁`);
      this.removeModuleKey(moduleId);
    }, MODULE_KEY_IDLE_TIMEOUT_MS);
    this.moduleKeyTimers.set(moduleId, timer);
  }

  /** 方案 7.1：安全零填充 Uint8Array（覆写内存：0 → 0xFF → 0） */
  private secureZeroBytes(bytes: Uint8Array): void {
    bytes.fill(0);
    bytes.fill(0xFF);
    bytes.fill(0);
  }

  /** 缓存模块独立密钥到会话（验证成功后调用） */
  cacheModuleKey(moduleId: ModuleId, key: string): void {
    // 方案 7.1：将字符串密钥转换为 Uint8Array 存储
    const keyBytes = this.keyTextEncoder.encode(key);
    this.moduleKeyCache.set(moduleId, keyBytes);
    // 原子地设置 moduleKeyReady=true（原缺陷修复：遗漏会导致重复验证弹窗）
    this.keyState.moduleKeyReady.value[moduleId] = true;
    // 方案 7.2：启动/重置闲置计时器
    this.resetModuleKeyTimer(moduleId);
  }

  /** 获取会话中缓存的模块密钥（未登录返回 null） */
  fetchModuleKey(moduleId: ModuleId): string | null {
    const keyBytes = this.moduleKeyCache.get(moduleId);
    if (!keyBytes) return null;
    // 方案 7.2：访问时重置闲置计时器
    this.resetModuleKeyTimer(moduleId);
    // 方案 7.1：Uint8Array → 字符串（瞬时转换，用后即弃）
    return this.keyTextDecoder.decode(keyBytes);
  }

  /** 移除指定模块的会话密钥缓存（登出模块/闲置超时时调用） */
  removeModuleKey(moduleId: ModuleId): void {
    // 方案 7.1：安全零填充后删除
    const keyBytes = this.moduleKeyCache.get(moduleId);
    if (keyBytes) {
      this.secureZeroBytes(keyBytes);
    }
    this.moduleKeyCache.delete(moduleId);
    // 原子地设置 moduleKeyReady=false（超时后状态与缓存同步清除）
    this.keyState.moduleKeyReady.value[moduleId] = false;
    // 方案 7.2：清除闲置计时器
    const timer = this.moduleKeyTimers.get(moduleId);
    if (timer) {
      clearTimeout(timer);
      this.moduleKeyTimers.delete(moduleId);
    }
  }

  /** 清零全部模块密钥缓存（lockAll 时调用） */
  clearModuleKeyCache(): void {
    // 方案 7.1：逐个安全零填充所有密钥字节
    for (const keyBytes of this.moduleKeyCache.values()) {
      this.secureZeroBytes(keyBytes);
    }
    this.moduleKeyCache.clear();
    // ★ 评审 #4 落实：以 MODULE_IDS 权威模块表驱动重置——新增模块自动
    //   纳入覆盖，杜绝硬编码列表遗漏；逐键置 false 保持响应式精确更新
    for (const moduleId of MODULE_IDS) {
      this.keyState.moduleKeyReady.value[moduleId] = false;
    }
    // 方案 7.2：清除所有闲置计时器
    for (const timer of this.moduleKeyTimers.values()) {
      clearTimeout(timer);
    }
    this.moduleKeyTimers.clear();
  }

  /* ==================== 3. 记录扫描缓存（游标批量扫描） ==================== */

  /** 扫描令牌有效性：令牌仍是当前活动令牌且未被取消 */
  private isScanTokenValid(token: ScanToken | null): boolean {
    return token !== null && token === this.activeScanToken && !token.cancelled;
  }

  /** 摘要扫描令牌有效性（同上，摘要域独立） */
  private isSummaryScanTokenValid(token: ScanToken | null): boolean {
    return token !== null && token === this.activeSummaryScanToken && !token.cancelled;
  }

  /** 路径是否已变化（切换 verthys / lockAll 时触发） */
  private isPathChanged(expectedPath: string | null): boolean {
    return expectedPath !== this.getCurrentVerthysPath();
  }

  private createScanToken(): ScanToken {
    this.scanGeneration++;
    return { generation: this.scanGeneration, cancelled: false };
  }

  private createSummaryScanToken(): ScanToken {
    this.summaryScanGeneration++;
    return { generation: this.summaryScanGeneration, cancelled: false };
  }

  /** 立即终止当前活动扫描（仅限 clearRecordScanCache 全量清除场景调用） */
  private invalidateActiveScanToken(): void {
    if (this.activeScanToken) {
      this.activeScanToken.cancelled = true;
    }
  }

  /** 立即终止当前活动摘要扫描（仅限 clearSummaryCache 全量清除场景调用） */
  private invalidateActiveSummaryScanToken(): void {
    if (this.activeSummaryScanToken) {
      this.activeSummaryScanToken.cancelled = true;
    }
  }

  /**
   * ★ 评审 #3/#5：属主保护的扫描自检失效（路径变化 / 批次校验失败时调用）。
   *
   * 仅当 token 仍是当前活动令牌（游标所有权在本扫描）时设置 cancelled 标志：
   *   - 若 clearRecordScanCache 之后后继扫描已注册为 activeScanToken，
   *     无条件取消"当前活动令牌"会误杀后继扫描 → 本方法对非属主 no-op
   *   - 仅设标志、不清空 activeScanToken/scanVerthysPath 引用——状态引用
   *     统一由 runRecordScan 的 finally 按属主关系收尾，全路径无陈旧残留
   */
  private invalidateScanIfCurrent(token: ScanToken): void {
    if (this.activeScanToken === token) {
      token.cancelled = true;
    }
  }

  /** 属主保护的摘要扫描自检失效（语义同 invalidateScanIfCurrent） */
  private invalidateSummaryScanIfCurrent(token: ScanToken): void {
    if (this.activeSummaryScanToken === token) {
      token.cancelled = true;
    }
  }

  /**
   * 确保记录扫描缓存覆盖最新记录。
   * 使用游标批量扫描（双缓冲流水线预取 + 共享内存零拷贝）。
   *
   * 并发安全：scanMutex 保证检查-登记原子性；多个模块同时调用时只执行一次扫描
   * （复用同一 Promise）。进行中的扫描经 scanInProgress 暴露给并发调用方。
   *
   * 回退策略：scan_open 依赖 v2 B+ 树游标。.verthys 为 v1 格式时
   *   Verthys_ScanOpen 返回 VERTHYS_ERR_INVALID，回退 verthysEnumerateRecords
   *   （单次 IPC，v1 内存路径），再失败回退 verthysEnumerateRecordsStream。
   */
  async ensureRecordScan(): Promise<void> {
    // ★ 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
    markFrontendIpcActive();
    const release = await this.scanMutex.acquire();
    let wrapped: Promise<void>;
    try {
      // 已有扫描在进行中 → 复用同一 Promise（避免并发重复扫描）
      if (this.scanInProgress) return this.scanInProgress;

      const scanPromise = this.runRecordScan();
      // ★ 修复（方案 §四.3）：finally 无条件清空，保证扫描结束后能重新触发
      wrapped = scanPromise.finally(() => {
        this.scanInProgress = null;
      });
      this.scanInProgress = wrapped;
    } finally {
      release();
    }
    return wrapped;
  }

  /** 实际执行记录扫描（令牌校验 + 路径校验 + 逐批合并） */
  private async runRecordScan(): Promise<void> {
    const token = this.createScanToken();
    this.activeScanToken = token;
    this.scanVerthysPath = this.getCurrentVerthysPath();
    if (!this.scanVerthysPath) return;

    const startId = this.maxScannedId > 0 ? this.maxScannedId + 1 : 0;

    try {
      // 优先使用游标批量扫描（v2 格式，双缓冲流水线预取 + 共享内存零拷贝）
      const first = await this.verthysApi.scanOpen(startId, SCAN_BATCH_SIZE);
      this.mergeScanBatch(first.records, token);

      // 后续批次（双缓冲流水线：A 区消费时 B 区已预取就绪）
      let exhausted = first.exhausted;
      while (!exhausted) {
        if (!this.isScanTokenValid(token) || this.isPathChanged(this.scanVerthysPath)) {
          this.invalidateScanIfCurrent(token);
          return;
        }
        const next = await this.verthysApi.scanNext(SCAN_BATCH_SIZE);
        this.mergeScanBatch(next.records, token);
        exhausted = next.exhausted;
      }
    } catch {
      // 回退：v1 格式不支持游标扫描（Verthys_ScanOpen 返回 VERTHYS_ERR_INVALID）
      await this.runRecordScanFallback(token, startId);
    } finally {
      // ★ 评审 #3/#5 落实（属主保护收尾）：
      //   - activeScanToken === token：游标所有权仍在本扫描（正常完成，或
      //     因路径变化自检失效但无人顶替）→ 必须 scanClose 释放共享内存/
      //     C 游标/预取任务（无人顶替时不关即泄漏），并清理状态引用，
      //     杜绝陈旧残留。
      //   - activeScanToken !== token：游标已被后继扫描的 scan_open 顶替
      //     （Rust scan_controller.rs verthys_scan_open 先关闭并 abort 旧游标，
      //     已验证）或被 clearRecordScanCache 清理 → 不可关闭（会误杀后继
      //     游标），也不可清状态引用（此时引用属于后继扫描，并非陈旧值）；
      //     残留资源由后继 scan_open 的自动顶替或 worker 销毁兜底释放。
      if (this.activeScanToken === token) {
        await this.verthysApi.scanClose().catch(() => {});
        // ★ 修正附录（§一）：maxScannedId 由 mergeScanEntry 维护，
        //   此处不基于缓存键重算覆盖（LRU 淘汰会使重算值偏小）。
        this.scanVerthysPath = null;
        this.activeScanToken = null;
      } else {
        log.debug("记录扫描令牌已失效（游标由后继 scan_open 顶替或缓存清除），scanClose 移交后继/后端兜底");
      }
    }
  }

  /**
   * 回退路径：游标扫描失败时使用 verthysEnumerateRecords（单次 IPC，
   * v1 内存路径），再失败回退 verthysEnumerateRecordsStream（逐批 Channel）。
   * 同样全程校验令牌与路径。
   */
  private async runRecordScanFallback(token: ScanToken, startId: number): Promise<void> {
    if (!this.isScanTokenValid(token) || this.isPathChanged(this.scanVerthysPath)) {
      this.invalidateScanIfCurrent(token);
      return;
    }
    const fallbackStart = startId > 0 ? startId : 1;
    try {
      // 单次 IPC，v1 格式下从 unlock 时已解密内存读取（v1 路径 1-3s）
      const allRecords = await this.verthysApi.enumerateRecords(fallbackStart);
      this.mergeScanBatch(allRecords, token);
    } catch {
      // verthysEnumerateRecords 也失败（worker 异常）→ 最后兜底：流式枚举
      if (!this.isScanTokenValid(token) || this.isPathChanged(this.scanVerthysPath)) {
        this.invalidateScanIfCurrent(token);
        return;
      }
      await this.verthysApi.enumerateRecordsStream(fallbackStart, SCAN_BATCH_SIZE, (batch) => {
        // Channel 回调中再次检查（扫描期间若 verthys 已切换或锁定 → 丢弃结果）
        this.mergeScanBatch(batch.records, token);
      });
    }
  }

  /** 合并一批扫描记录（逐条校验令牌与路径 + 过滤待删 ID + 内存优先合并） */
  private mergeScanBatch(records: ScannedRecord[], token: ScanToken): void {
    for (const r of records) {
      if (!this.isScanTokenValid(token) || this.isPathChanged(this.scanVerthysPath)) {
        // ★ 评审 #3：属主保护失效（非属主 no-op，防误杀后继扫描）
        this.invalidateScanIfCurrent(token);
        return;
      }
      // 方案 3.4：过滤待删除 ID（磁盘存在也不写入前端缓存，根治回填复活）
      if (this.pendingDeletionIds.has(r.id)) continue;
      // 方案三.2：内存优先合并（不覆盖已有缓存，仅补充缺失项）
      this.mergeScanEntry(r.id, r.type, r.name, r.dataB64);
    }
  }

  /**
   * 方案三.2：内存优先合并 — 磁盘扫描不覆盖已有缓存条目。
   *
   * 内存缓存是权威数据源，磁盘仅为持久化备份。仅补充缓存中缺失的记录；
   * 已有条目仅同步索引（防止类型变更后索引不一致），不覆盖数据。
   */
  private mergeScanEntry(id: number, type: number, name: string, dataB64: string): void {
    if (this.recordScanCache.has(id)) {
      const old = this.recordScanCache.peek(id);
      if (old && old.type !== type) {
        this.removeFromIndex(id, old.type);
        this.addToIndex(id, type);
      }
      return;
    }
    this.setScanCacheEntry(id, type, name, dataB64);
  }

  /**
   * 方案 7.3：将记录写入缓存（无条件覆盖；用户主动 add/edit 后同步用）。
   * 含大体积 dataB64 管控 + LRU 淘汰（淘汰回调同步移除类型索引）。
   */
  private setScanCacheEntry(id: number, type: number, name: string, dataB64: string): void {
    // 大体积 dataB64 不缓存（置空），调用方通过 IPC 获取
    const safeDataB64 = dataB64.length > DATAB64_CACHE_MAX_BYTES ? "" : dataB64;
    // 若已有同 ID 旧记录且类型不同，先从旧类型索引中移除
    const old = this.recordScanCache.peek(id);
    if (old && old.type !== type) {
      this.removeFromIndex(id, old.type);
    }
    this.recordScanCache.set(id, { id, type, name, dataB64: safeDataB64 });
    this.addToIndex(id, type);
    // ★ maxScannedId 唯一维护点（修正附录 §一）：仅单调递增，
    //   不做基于缓存键的重算覆盖（invalidateScannedRecord 的定向重算除外）
    if (id > this.maxScannedId) this.maxScannedId = id;
  }

  /** 从扫描缓存中按类型获取记录 ID 列表（O(1) 索引查询，已排序） */
  getRecordIdsByType(type: number): number[] {
    const set = this.recordIndexByType.get(type);
    if (!set) return [];
    return [...set].sort((a, b) => a - b);
  }

  /** 从扫描缓存中获取单条记录数据（无 IPC 调用；LRU 访问触碰） */
  getRecordFromScan(id: number): ScannedRecord | null {
    // 方案 3.4：待删除 ID 不返回（磁盘存在也不写入前端缓存）
    if (this.pendingDeletionIds.has(id)) return null;
    // LRU get：命中即移到末尾（标记为最近使用）
    return this.recordScanCache.get(id) ?? null;
  }

  /**
   * 使扫描缓存中的单条记录失效（删除记录后调用）。
   * 删除后该 ID 不会出现在 getRecordIdsByType 的结果中，杜绝"删除复活"。
   *
   * ★ ID 复用缺陷修复：若被删除的记录 ID 等于当前 maxScannedId，
   * 必须重新遍历缓存计算新的 maxScannedId。否则 verthys 后端复用该 ID
   * 分配新记录时，ensureRecordScan 的增量扫描会从旧 maxScannedId+1 开始，
   * 永远扫描不到复用 ID 的新记录 → 缓存永久缺失数据。
   */
  invalidateScannedRecord(id: number): void {
    const rec = this.recordScanCache.peek(id);
    if (rec) {
      this.removeFromIndex(id, rec.type);
      this.recordScanCache.delete(id);
      // ID 复用修复：删除的是当前最大 ID → 重新计算 maxScannedId
      // （定向重算，与修正附录禁止的"扫描结束全量重算覆盖"语义不同）
      if (id === this.maxScannedId) {
        this.recomputeMaxScannedId();
      }
    }
  }

  /**
   * 重新计算 maxScannedId（仅删除最大 ID 记录时调用）。
   * 遍历缓存中所有 ID 取最大值。O(n)，频率极低。
   * 注意：LRU 淘汰可能已移除真实最大 ID，重算值偏小时只会导致下次
   * 扫描从更小的 ID 开始（幂等重复合并，mergeScanEntry 内存优先，无副作用）。
   */
  private recomputeMaxScannedId(): void {
    let newMax = 0;
    for (const id of this.recordScanCache.keys()) {
      if (id > newMax) newMax = id;
    }
    this.maxScannedId = newMax;
  }

  /**
   * 将新增记录同步到扫描缓存（添加记录后调用）。
   * 避免新记录 ID <= maxScannedId 时 ensureRecordScan 增量扫描遗漏。
   * 方案 7.3：统一经 setScanCacheEntry 写入（LRU + 大体积管控）。
   */
  addRecordToScan(id: number, type: number, name: string, dataB64: string): void {
    this.setScanCacheEntry(id, type, name, dataB64);
  }

  /**
   * 非阻塞清除扫描缓存（方案 §四.4）。
   *
   * 立即使当前扫描失效（代际令牌），清空缓存与索引并允许新扫描立即启动，
   * 不等待旧扫描结束。旧扫描在每个批次合并前校验令牌与路径，
   * 失效后不再写入任何数据；旧游标资源由后继 scan_open 的自动顶替
   * （Rust verthys_scan_open 先关闭并 abort 旧游标，已验证）或 worker
   * 销毁兜底释放。
   */
  clearRecordScanCache(): void {
    // 1. 立即使当前扫描失效
    this.invalidateActiveScanToken();
    this.activeScanToken = null;
    this.scanInProgress = null;   // 允许新扫描立即启动
    this.scanVerthysPath = null;

    // 2. 清空缓存和索引（LRU clear 逐条触发 onEvict 同步移除索引，幂等）
    this.recordScanCache.clear();
    this.recordIndexByType.clear();
    this.maxScannedId = 0;

    this.emit("scan-cleared");
  }

  /**
   * 批量获取多条记录的 dataB64（扫描缓存优先 + 并行 IPC 回退）。
   *
   * 流程：
   *   1. 逐条 getRecordFromScan(id) —— 命中 recordScanCache 零 IPC
   *   2. miss 或 dataB64 为空（>64KB 大体积记录被管控置空）→ 收集 fallbackIds
   *   3. Promise.all 并行 IPC 回退（JS 端 round-trip 重叠，比串行快 3-5 倍）
   *
   * 返回 Map<id, dataB64>（仅含成功获取且 dataB64 非空的记录）。
   * 调用方应先 await ensureRecordScan() 确保扫描缓存就绪。
   */
  async getRecordsDataB64Batch(ids: number[]): Promise<Map<number, string>> {
    const result = new Map<number, string>();
    const fallbackIds: number[] = [];
    for (const id of ids) {
      // 待删除 ID 不返回（磁盘存在也不返回，杜绝删除复活）
      if (this.pendingDeletionIds.has(id)) continue;
      const r = this.getRecordFromScan(id);
      if (r && r.dataB64) {
        result.set(id, r.dataB64);
      } else {
        fallbackIds.push(id); // 缓存未命中或大体积管控置空 → IPC 回退
      }
    }
    if (fallbackIds.length > 0) {
      const frs = await Promise.all(fallbackIds.map(id => this.getFullRecord(id)));
      for (let i = 0; i < fallbackIds.length; i++) {
        const fr = frs[i];
        if (fr && fr.dataB64) result.set(fallbackIds[i], fr.dataB64);
      }
    }
    return result;
  }

  /* ==================== 4. 摘要缓存（第一层：常驻，无淘汰） ==================== */

  /** 将摘要记录 ID 添加到类型索引 */
  private addSummaryToIndex(id: number, type: number): void {
    let set = this.summaryIndexByType.get(type);
    if (!set) {
      set = new Set();
      this.summaryIndexByType.set(type, set);
    }
    set.add(id);
  }

  /** 将摘要记录 ID 从类型索引移除 */
  private removeSummaryFromIndex(id: number, type: number): void {
    this.summaryIndexByType.get(type)?.delete(id);
  }

  /** 将摘要记录写入缓存（无条件覆盖，用于 add/edit 后同步） */
  private setSummaryCacheEntry(rec: SummaryRecord): void {
    // 若已有同 ID 旧记录且类型不同，先从旧类型索引中移除
    const old = this.summaryCache.get(rec.id);
    if (old && old.type !== rec.type) {
      this.removeSummaryFromIndex(rec.id, old.type);
    }
    this.summaryCache.set(rec.id, rec);
    this.addSummaryToIndex(rec.id, rec.type);
    // ★ maxSummaryId 唯一维护点（与 maxScannedId 同源策略，单调递增）
    if (rec.id > this.maxSummaryId) this.maxSummaryId = rec.id;
  }

  /**
   * 内存优先合并 — 磁盘摘要扫描不覆盖已有缓存条目（增量加载用）。
   * 已有条目仅同步索引，不覆盖数据。
   */
  private mergeSummaryEntry(rec: SummaryRecord): void {
    if (this.summaryCache.has(rec.id)) {
      const old = this.summaryCache.get(rec.id);
      if (old && old.type !== rec.type) {
        this.removeSummaryFromIndex(rec.id, old.type);
        this.addSummaryToIndex(rec.id, rec.type);
      }
      return;
    }
    this.setSummaryCacheEntry(rec);
  }

  /**
   * 确保摘要缓存覆盖全部记录（Phase 2E：解锁后 1-2 秒内完成）。
   *
   * 仅扫描元数据（lid/type/name/data_size/physical_offset/merkle_leaf/
   * created_time），不解密数据块，列表渲染 + 搜索 + 删除完全基于它。
   *
   * 并发安全：summaryScanMutex 保证检查-登记原子性；多模块复用同一 Promise。
   * 竞态保护：代际令牌 + 路径校验，clearSummaryCache 立即使进行中扫描失效。
   *
   * 回退策略：摘要扫描失败（v1 格式 / 熔断）时静默返回——summaryCache
   * 保持空，调用方 getSummaryIdsByType 返回空数组，findGlobalKeyRecord
   * 检测到摘要为空时自行回退 verthysEnumerateRecords（v1 内存路径）。
   * ★ 不回退全量扫描：避免 v1 容器关键路径全量解密（20-30s 延迟）。
   */
  async ensureSummaryScan(): Promise<void> {
    // ★ 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
    markFrontendIpcActive();
    const release = await this.summaryScanMutex.acquire();
    let wrapped: Promise<void>;
    try {
      // 已有扫描在进行中 → 复用同一 Promise（避免并发重复扫描）
      if (this.summaryScanInProgress) return this.summaryScanInProgress;

      const scanPromise = this.runSummaryScan();
      // ★ 修复（方案 §四.3）：finally 无条件清空，保证扫描结束后能重新触发
      wrapped = scanPromise.finally(() => {
        this.summaryScanInProgress = null;
      });
      this.summaryScanInProgress = wrapped;
    } finally {
      release();
    }
    return wrapped;
  }

  /** 实际执行摘要扫描（令牌校验 + 路径校验 + 逐批合并） */
  private async runSummaryScan(): Promise<void> {
    const token = this.createSummaryScanToken();
    this.activeSummaryScanToken = token;
    this.summaryScanVerthysPath = this.getCurrentVerthysPath();
    if (!this.summaryScanVerthysPath) return;

    const startId = this.maxSummaryId > 0 ? this.maxSummaryId + 1 : 0;

    try {
      // 摘要游标批量扫描（v2 格式，双缓冲流水线 + 共享内存零拷贝）
      const first = await this.verthysApi.scanSummaryOpen(startId, SCAN_BATCH_SIZE);
      this.mergeSummaryBatch(first.records, token);

      let exhausted = first.exhausted;
      while (!exhausted) {
        if (!this.isSummaryScanTokenValid(token) || this.isPathChanged(this.summaryScanVerthysPath)) {
          this.invalidateSummaryScanIfCurrent(token);
          return;
        }
        const next = await this.verthysApi.scanSummaryNext(SCAN_BATCH_SIZE);
        this.mergeSummaryBatch(next.records, token);
        exhausted = next.exhausted;
      }
    } catch {
      // 摘要扫描失败（v1 格式 / 熔断）→ 静默返回，不触发任何全量扫描
      // （回退策略详见 ensureSummaryScan 头注释）
    } finally {
      // ★ 评审 #3/#5 落实（属主保护收尾，语义同 runRecordScan 的 finally）：
      //   activeSummaryScanToken === token（游标所有权在本扫描）→ 关闭摘要
      //   游标并清理状态引用；已被后继 scan_summary_open 顶替或被
      //   clearSummaryCache 清理 → 不关不清（防误杀后继游标，资源由
      //   后继自动顶替或 worker 销毁兜底）。
      if (this.activeSummaryScanToken === token) {
        await this.verthysApi.scanSummaryClose().catch(() => {});
        // maxSummaryId 同修正附录策略，不重算
        this.summaryScanVerthysPath = null;
        this.activeSummaryScanToken = null;
      } else {
        log.debug("摘要扫描令牌已失效（游标由后继 scan_summary_open 顶替或缓存清除），scanSummaryClose 移交后继/后端兜底");
      }
    }
  }

  /** 合并一批摘要记录（校验令牌与路径 + 过滤待删 ID + 内存优先合并） */
  private mergeSummaryBatch(records: SummaryRecord[], token: ScanToken): void {
    for (const r of records) {
      if (!this.isSummaryScanTokenValid(token) || this.isPathChanged(this.summaryScanVerthysPath)) {
        // ★ 评审 #3：属主保护失效（非属主 no-op，防误杀后继扫描）
        this.invalidateSummaryScanIfCurrent(token);
        return;
      }
      // 过滤待删除 ID（磁盘存在也不写入前端缓存，根治回填复活）
      if (this.pendingDeletionIds.has(r.id)) continue;
      this.mergeSummaryEntry(r);
    }
  }

  /**
   * 从摘要缓存中按类型获取记录 ID 列表（O(1) 索引查询，已排序）。
   *
   * 列表渲染专用：基于常驻 summaryCache，1-2 秒内渲染完整列表，
   * 不解密任何数据块，不受 64KB 截断影响。
   */
  getSummaryIdsByType(type: number): number[] {
    const set = this.summaryIndexByType.get(type);
    if (!set) return [];
    return [...set].sort((a, b) => a - b);
  }

  /**
   * 按类型查找首条记录 LID（早停扫描，关键路径专用）。
   *
   * 与 ensureSummaryScan 的区别：找到首条匹配即返回（典型 <0.3s），
   * 全量摘要扫描需 2-3s。使用场景：findGlobalKeyRecord 仅需找到
   * TYPE_GLOBAL_KEY 的 LID，无需等待列表渲染就绪。
   *
   * ★ 方案 §一.3 根治（游标资源竞争）：底层 worker 每类游标仅支持单个
   *   ScanState，本方法与 ensureSummaryScan 经 summaryScanMutex 互斥，
   *   且在打开游标前先等待进行中的全量摘要扫描完成并复查缓存，
   *   杜绝同时打开多个摘要游标。
   *
   * 流程：
   *   1. 先查常驻缓存 → O(1)
   *   2. 有全量摘要扫描进行中 → 等待完成后复查缓存
   *   3. 仍未命中 → 持 summaryScanMutex 打开摘要游标逐批扫描（早停）
   *   4. 全部批次无匹配 → 返回 null（调用方回退 verthysEnumerateRecords）
   */
  async findLidByTypeEarlyStop(type: number): Promise<number | null> {
    const fromCache = (): number | null => {
      const ids = this.getSummaryIdsByType(type);
      return ids.length > 0 ? ids[0] : null;
    };

    // 1. 先查常驻缓存（O(1)，若已被 ensureSummaryScan 填充则直接命中）
    const cached = fromCache();
    if (cached !== null) return cached;

    for (;;) {
      // 2. 已有全量摘要扫描进行中 → 等待完成后复查缓存（不持锁等待，避免阻塞）
      if (this.summaryScanInProgress) {
        await this.summaryScanInProgress.catch(() => {});
        const hit = fromCache();
        if (hit !== null) return hit;
        continue; // 重新评估（扫描可能已被 clear，进入互斥分支）
      }

      // 3. 持互斥锁执行早停游标扫描（与 ensureSummaryScan 的登记段互斥，
      //    保证同一时刻最多一个摘要游标打开）
      const release = await this.summaryScanMutex.acquire();
      try {
        // double-check：等待互斥锁期间状态可能已变化
        if (this.summaryScanInProgress) continue; // finally 释放锁，回循环等待
        const hit = fromCache();
        if (hit !== null) return hit;
        return await this.earlyStopSummaryCursor(type);
      } finally {
        release();
      }
    }
  }

  /** 早停游标扫描主体（调用方须已持 summaryScanMutex） */
  private async earlyStopSummaryCursor(type: number): Promise<number | null> {
    const pathAtStart = this.getCurrentVerthysPath();
    if (!pathAtStart) return null;

    try {
      const first = await this.verthysApi.scanSummaryOpen(0, SCAN_BATCH_SIZE);
      for (const r of first.records) {
        if (this.pendingDeletionIds.has(r.id)) continue;
        if (r.type === type) return r.id;
      }
      let exhausted = first.exhausted;
      let batchCount = 1;
      while (!exhausted) {
        // 迭代上限保护：超过上限仍未找到，终止扫描
        // （防后端异常返回 exhausted=false 但 records 为空导致无限循环）
        if (batchCount >= EARLY_STOP_MAX_BATCHES) {
          log.warn(`早停扫描达到迭代上限 ${EARLY_STOP_MAX_BATCHES} 批（${EARLY_STOP_MAX_BATCHES * SCAN_BATCH_SIZE} 条），终止扫描`);
          return null;
        }
        // 扫描期间若 verthys 已切换或锁定 → 丢弃结果
        if (pathAtStart !== this.getCurrentVerthysPath()) return null;
        const next = await this.verthysApi.scanSummaryNext(SCAN_BATCH_SIZE);
        batchCount++;
        for (const r of next.records) {
          if (this.pendingDeletionIds.has(r.id)) continue;
          if (r.type === type) return r.id;
        }
        exhausted = next.exhausted;
      }
    } catch {
      // 摘要扫描失败（v1 格式 / 熔断）→ 返回 null，调用方回退到 verthysEnumerateRecords
      return null;
    } finally {
      // 确保游标关闭（早停命中 / 上限终止 / 路径切换 / 异常 / 正常结束全路径覆盖）
      await this.verthysApi.scanSummaryClose().catch(() => {});
    }
    return null;
  }

  /** 从摘要缓存获取单条记录（无 IPC 调用；仅返回元数据，用于列表项渲染） */
  getSummaryRecord(id: number): SummaryRecord | null {
    // 待删除 ID 不返回（磁盘存在也不返回，杜绝删除复活）
    if (this.pendingDeletionIds.has(id)) return null;
    return this.summaryCache.get(id) ?? null;
  }

  /** 获取摘要缓存中所有记录 ID（用于完整性巡检、全量遍历，已排序） */
  getAllSummaryIds(): number[] {
    return [...this.summaryCache.keys()].sort((a, b) => a - b);
  }

  /** 获取摘要缓存当前条目数（调试/监控用） */
  getSummaryCacheSize(): number {
    return this.summaryCache.size;
  }

  /**
   * 将新增/编辑记录的摘要同步到缓存（add/edit 后立即调用）。
   * 确保 ensureSummaryScan 增量扫描不遗漏新记录。
   */
  addSummaryRecord(rec: SummaryRecord): void {
    this.setSummaryCacheEntry(rec);
  }

  /**
   * 使摘要缓存中的单条记录失效（删除记录后调用）。
   * 删除后该 ID 不会出现在 getSummaryIdsByType 的结果中，杜绝"删除复活"。
   *
   * ★ ID 复用缺陷修复：同 invalidateScannedRecord（删除最大 ID 时重算）。
   */
  invalidateSummaryRecord(id: number): void {
    const rec = this.summaryCache.get(id);
    if (rec) {
      this.removeSummaryFromIndex(id, rec.type);
      this.summaryCache.delete(id);
      if (id === this.maxSummaryId) {
        this.recomputeMaxSummaryId();
      }
    }
  }

  /** 重新计算 maxSummaryId（仅删除最大 ID 记录时调用） */
  private recomputeMaxSummaryId(): void {
    let newMax = 0;
    for (const id of this.summaryCache.keys()) {
      if (id > newMax) newMax = id;
    }
    this.maxSummaryId = newMax;
  }

  /** 清空整个摘要缓存（lockAll / verthysFlush 后调用；立即失效进行中扫描） */
  clearSummaryCache(): void {
    this.invalidateActiveSummaryScanToken();
    this.activeSummaryScanToken = null;
    this.summaryScanInProgress = null;
    this.summaryScanVerthysPath = null;
    this.summaryCache.clear();
    this.summaryIndexByType.clear();
    this.maxSummaryId = 0;
    this.emit("summary-cleared");
  }

  /* ==================== 5. 全量记录缓存（第二层：LRU-50，按需加载） ==================== */

  /**
   * 获取单条记录的完整数据（按需加载，含 LRU 缓存）。
   *
   * 与 getRecordFromScan 的区别：不受 64KB 管控限制，永远返回完整 dataB64；
   * LRU-50 容量；解密失败的记录不缓存；同 ID 并发请求复用同一 IPC Promise。
   *
   * ★ 方案 §四.1 锁粒度优化：仅在"写入缓存前"获取 deletionMutex 做
   *   检查-写入原子段，避免长时间持锁阻塞删除标记操作。
   */
  async getFullRecord(id: number): Promise<ScannedRecord | null> {
    // 快速路径：初步检查不持锁（最终一致性由写入时锁保证）
    if (this.pendingDeletionIds.has(id)) return null;

    // 1. 命中缓存：LRU 移到末尾（标记为最近使用）
    const cached = this.fullRecordCache.get(id);
    if (cached) return cached;

    // 2. 防并发：同 ID 已有加载任务 → 复用同一 Promise
    const existing = this.fullRecordLoaders.get(id);
    if (existing) return existing;

    // 3. 未命中：发起 IPC 加载完整数据
    const loader = (async (): Promise<ScannedRecord | null> => {
      try {
        const r = await this.verthysApi.getRecord(id);
        if (!r) return null;
        // ★ 写入前获取 deletionMutex 原子检查，避免将已删除记录写入缓存
        const release = await this.deletionMutex.acquire();
        try {
          if (this.pendingDeletionIds.has(id)) return null;
          const rec: ScannedRecord = { id, type: r.type, name: r.name, dataB64: r.dataB64 };
          this.fullRecordCache.set(id, rec);
          return rec;
        } finally {
          release();
        }
      } catch {
        // 加载失败不缓存（避免缓存错误数据），但也不向上抛（与旧版语义一致）
        return null;
      } finally {
        this.fullRecordLoaders.delete(id);
      }
    })();

    this.fullRecordLoaders.set(id, loader);
    return loader;
  }

  /**
   * 检查全量记录缓存中是否已存在指定 ID 的记录（不触发加载）。
   * 供 integrityPatrol 使用：已在缓存中的记录无需重复读取，直接跳过。
   */
  hasFullRecord(id: number): boolean {
    return this.fullRecordCache.has(id);
  }

  /**
   * 预加载多条记录（Phase 2E 后台任务二：被动补齐机制）。
   *
   * 低优先级：串行加载，每条之间让出主线程；会话结束（lockAll 触发
   * shouldAbortBackgroundWork）立即停止；单条失败不影响后续。
   */
  async prefetchFullRecords(ids: number[]): Promise<void> {
    for (const id of ids) {
      // 已缓存 / 待删除 → 跳过
      if (this.fullRecordCache.has(id) || this.pendingDeletionIds.has(id)) continue;
      // 让出主线程，避免阻塞 UI（低优先级后台任务）
      await new Promise<void>(resolve => setTimeout(resolve, 0));
      // 会话已结束（lockAll 触发 cacheTimersCancelled）→ 停止预加载
      if (this.shouldAbortBackgroundWork()) return;
      try {
        await this.getFullRecord(id);
      } catch {
        // 单条失败不影响后续
      }
    }
  }

  /** 使全量记录缓存中的单条记录失效（编辑/删除后调用；安全覆写） */
  invalidateFullRecord(id: number): void {
    const rec = this.fullRecordCache.peek(id);
    if (rec) {
      rec.dataB64 = ""; // 安全覆写
      this.fullRecordCache.delete(id);
    }
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
    const rec: ScannedRecord = { id, type, name, dataB64 };
    this.fullRecordCache.set(id, rec);

    // 2. 同步更新摘要缓存（physicalOffset/merkleLeaf 为占位值，
    //    下次 ensureSummaryScan 会从后端读取真实值覆盖）
    // ★ 评审 #2 落实：dataSize 回退估算改用 estimateBase64Size
    //   （cache/shared/base64-size.ts 单一权威源，处理填充字符，
    //   与 batch-cache-coordinator / cache-coordinator 保持一致）
    const summary: SummaryRecord = {
      id,
      type,
      name,
      dataSize: dataSize ?? estimateBase64Size(dataB64),
      physicalOffset: 0,
      merkleLeaf: "",
      createdTime: Math.floor(Date.now() / 1000),  /* Phase 2G：创建时间戳 */
    };
    this.setSummaryCacheEntry(summary);
  }

  /** 清空全量记录缓存（lockAll / verthysFlush 后调用；clear 逐条安全覆写） */
  clearFullRecordCache(): void {
    this.fullRecordCache.clear(); // LRU clear 逐条触发 onFullRecordEvict 安全覆写
    this.fullRecordLoaders.clear();
  }

  /** 获取全量记录缓存当前条目数（调试/监控用） */
  getFullRecordCacheSize(): number {
    return this.fullRecordCache.size;
  }

  /* ==================== 删除标记管理（共享集合，mutex 保护） ==================== */

  /**
   * 标记记录进入待删除状态：加入共享过滤集合并立即移除可能已缓存的全量
   * 记录（防止 getFullRecord 的在途加载在标记完成后写入已删记录）。
   * ★ 注意：主删除路径由 VerthysFlushService.deleteAndPersist 直接入集合；
   * 本方法供独立使用领域 API 的调用方/测试使用。
   */
  async markForDeletion(id: number): Promise<void> {
    const release = await this.deletionMutex.acquire();
    try {
      this.pendingDeletionIds.add(id);
      // 立即移除可能已缓存的全量记录
      const cached = this.fullRecordCache.peek(id);
      if (cached) {
        cached.dataB64 = "";
        this.fullRecordCache.delete(id);
      }
    } finally {
      release();
    }
  }

  /** 解除待删除标记（回滚场景） */
  async unmarkForDeletion(id: number): Promise<void> {
    const release = await this.deletionMutex.acquire();
    try {
      this.pendingDeletionIds.delete(id);
      this.committedDeletionIds.delete(id);
    } finally {
      release();
    }
  }

  /** 清空待删除标记集合（新会话初始化；主路径经 VerthysFlushService 同步清空） */
  async clearPendingDeletionIds(): Promise<void> {
    const release = await this.deletionMutex.acquire();
    try {
      this.pendingDeletionIds.clear();
      this.committedDeletionIds.clear();
    } finally {
      release();
    }
  }

  /* ==================== 索引维护（LRU 淘汰回调） ==================== */

  /** recordScanCache 淘汰回调：同步移除类型索引，杜绝索引悬挂 ID */
  private onScanEvict(id: number, rec: ScannedRecord): void {
    this.removeFromIndex(id, rec.type);
  }

  /** fullRecordCache 淘汰回调：安全覆写 dataB64（缩短明文暴露窗口） */
  private onFullRecordEvict(id: number, rec: ScannedRecord): void {
    rec.dataB64 = "";
  }

  /** 将记录 ID 添加到类型索引 */
  private addToIndex(id: number, type: number): void {
    let set = this.recordIndexByType.get(type);
    if (!set) {
      set = new Set();
      this.recordIndexByType.set(type, set);
    }
    set.add(id);
  }

  /** 将记录 ID 从类型索引中移除 */
  private removeFromIndex(id: number, type: number): void {
    this.recordIndexByType.get(type)?.delete(id);
  }

  /* ==================== 全量清空 ==================== */

  /**
   * 统一清空所有 Verthys 缓存（lockAll 一次性调用）。
   *
   * 先 await stopBackgroundTasks（注入钩子）确保后台任务
   * 完全终止，再清空缓存，杜绝「旧后台任务访问已释放缓存」的竞态。
   */
  async clearAllVerthysCaches(): Promise<void> {
    // 先 await 后台任务完全终止（注入钩子），再清空缓存，
    // 杜绝「旧后台任务访问已释放缓存」的竞态
    await this.stopBackgroundTasksHook();
    // ★ 评审 #1 落实：首先清零明文密钥（Uint8Array 安全零填充），
    //   lockAll 统一清空入口的安全闭环（方案 7.1：明文密钥不残留内存）
    this.clearModuleKeyCache();
    this.clearSummaryCache();
    this.clearFullRecordCache();
    this.clearRecordScanCache();
    this.clearModuleCache();
  }
}