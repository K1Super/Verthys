/*
 * cache/domain/cache-contracts.ts — 缓存领域共享契约
 *
 * 领域接口（IPC 访问面 / UI 状态最小接口 / 注入依赖 / 事件表 / 进度快照）、
 * 跨缓存单元共享常量与扫描令牌登记器集中于此，避免各缓存单元与门面互相
 * 导入形成环。
 *
 * 注入接口保持接口隔离：领域层只声明实际使用的能力，测试可注入普通对象。
 */
import type { ModuleId, ScannedRecord } from "../../types/key_manager";
import type { ScanProjectOptions, SummaryRecord } from "../../lib/verthys";

/**
 * 底层 verthys IPC 访问接口（依赖倒置：领域类不直接依赖 lib/verthys 实现，
 * 由绑定层注入真实 IPC 适配器，测试可注入 mock）。
 */
export interface VerthysCacheApi {
  /** 打开记录扫描游标，返回首批记录（v2 格式；v1 抛异常触发回退）
   *
   * options 为投影选项：记录扫描只需索引与小体积数据，传 INDEX 投影 +
   * 缓存管控阈值即可让后端跳过 MB 级记录的解密与搬运（含大记录的数据集
   * 不再因单批超容而整批失败）。 */
  scanOpen(startId: number, batchSize: number, options?: ScanProjectOptions): Promise<{ records: ScannedRecord[]; exhausted: boolean; failedIds: number[] }>;
  /** 拉取下一批记录（双缓冲流水线切换） */
  scanNext(batchSize: number): Promise<{ records: ScannedRecord[]; exhausted: boolean; failedIds: number[] }>;
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
  /** 按类型分页枚举记录 ID（类型盲索引，不读记录密文） */
  listIdsByType(type: number, afterId: number, maxCount: number): Promise<{ ids: number[]; exhausted: boolean }>;
  /** 读取单条完整记录（返回 base64 数据） */
  getRecord(id: number): Promise<{ type: number; name: string; dataB64: string } | null>;
}

/**
 * KeyState 最小接口（接口隔离原则）。
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

/** 领域必需注入依赖（组合根 verthys-cache.ts 装配） */
export interface VerthysCacheDomainDeps {
  /**
   * 共享待删除 ID 集合（与 VerthysFlushService 同一实例，单一权威源）。
   * 冲刷队列与缓存扫描的删除过滤据此保持完全一致。
   */
  pendingDeletionIds: Set<number>;
  /** 共享已提交删除 ID 集合（同上） */
  committedDeletionIds: Set<number>;
  /**
   * 后台预加载中止钩子：返回 true 表示会话已结束（lockAll 触发
   * clearAllCacheTimers），prefetchFullRecords 应立即停止。
   * 绑定层注入 verthys-flush 的 isCacheTimersCancelled。
   */
  shouldAbortBackgroundWork: () => boolean;
  /**
   * clearAllVerthysCaches 前置钩子：await 后台任务完全终止后再清空缓存
   * （杜绝"旧后台任务访问已释放缓存"竞态）。
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
};

/**
 * 记录扫描进度快照（批次粒度上报，供上层把扫描推进接到进度呈现）。
 *
 * 数值全部为可验证的真实计数：cached 为缓存当前条数（含本次合并结果），
 * scanned 为本次扫描已读取条数（含损坏条目），failed 为本次扫描发现的
 * 不可读条目数。上层以"全库条数"为分母即可得到真实完成度。
 */
export interface ScanProgress {
  /** 缓存中当前记录条数（本次扫描合并后） */
  cached: number;
  /** 本次扫描已读取条数（含损坏条目） */
  scanned: number;
  /** 本次扫描发现的不可读条目数 */
  failed: number;
}

/** 扫描令牌：代际 + 取消标志（并发扫描失效核心机制） */
export interface ScanToken {
  generation: number;
  cancelled: boolean;
}

/* ------------------------------------------------------------------ *
 * 共享常量                                                           *
 * ------------------------------------------------------------------ */

/** 记录扫描缓存 LRU 容量（超限移除最久未使用记录，防内存溢出） */
export const RECORD_CACHE_LRU_THRESHOLD = 5000;
/** 全量记录缓存 LRU 容量（50 条） */
export const FULL_RECORD_CACHE_CAPACITY = 50;
/** 扫描批大小（每批 200 条，渐进式渲染） */
export const SCAN_BATCH_SIZE = 200;
/** 摘要早停扫描迭代上限：100 批 × 200 条 = 20,000 条，防后端异常导致无限循环 */
export const EARLY_STOP_MAX_BATCHES = 100;
/** 类型 ID 分页大小：类型盲索引单页 1000 条，平衡 IPC 次数与单包体积 */
export const TYPE_ID_BATCH_SIZE = 1000;

/* ------------------------------------------------------------------ *
 * 扫描令牌登记器                                                     *
 * ------------------------------------------------------------------ */

/**
 * 扫描令牌登记器（记录 / 摘要两域各持一个实例）。
 *
 * 语义与领域类内的代际令牌完全一致：
 *   - create() 递增代际并登记为当前活动令牌；
 *   - isValid() 要求令牌仍是活动令牌且未被取消；
 *   - invalidateIfCurrent() 仅对属主令牌置取消标志（非属主 no-op，
 *     防误杀后继扫描）；
 *   - clearActive() 解除登记但不关闭游标（资源移交后继或后端兜底）。
 */
export class ScanTokenRegistry {
  private generation = 0;
  private active: ScanToken | null = null;

  /** 创建并登记为当前活动令牌 */
  create(): ScanToken {
    this.generation += 1;
    this.active = { generation: this.generation, cancelled: false };
    return this.active;
  }

  /** 令牌有效性：仍是当前活动令牌且未被取消 */
  isValid(token: ScanToken | null): boolean {
    return token !== null && token === this.active && !token.cancelled;
  }

  /** 立即终止当前活动令牌（仅限全量清除场景调用） */
  invalidateActive(): void {
    if (this.active) this.active.cancelled = true;
  }

  /** 属主保护的失效：非属主 no-op，防误杀后继扫描 */
  invalidateIfCurrent(token: ScanToken | null): void {
    // token 为 null 表示当前无活动扫描（空槽场景）：显式排除，
    // 否则 active 同为 null 时会误入分支并对 null 解引用。
    if (token !== null && this.active === token) {
      token.cancelled = true;
    }
  }

  /** 扫描是否仍持有游标（属性判定，不检查取消标志） */
  isOwner(token: ScanToken | null): boolean {
    return this.active === token;
  }

  /** 解除登记（不清除取消标志之外的状态；调用方须先自行判定属主） */
  clearActive(): void {
    this.active = null;
  }
}
