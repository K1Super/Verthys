/*
 * cache/coordination/cache-coordinator.ts — 缓存协调器（事件驱动单例）
 *
 * ★ cache-coordinator 重构设计落地：
 *   采用观察者模式 + 依赖注入重构，通过领域事件（record:add/record:remove/
 *   record:update）解耦缓存更新逻辑，缓存层实现可注入、可替换、可测试。
 *
 * ★ 根治的五项缺陷（逐条对应）：
 *   1. updateRecord 覆盖 createdTime → 更新前自动从摘要缓存读取旧
 *      createdTime 保留（调用方未显式传入时）
 *   2. RecordUpdate 缺少元数据字段 → 扩展 createdTime?/physicalOffset?/
 *      merkleLeaf?，调用方可传入完整摘要信息，消除占位值失真
 *   3. removeRecord 未同步清理 pendingDeletionIds → 提供 configure() 注入
 *      onRecordDeleted 回调（默认不注入，安全警示示于下方）
 *   4. dataSize 估算不精确 → estimateBase64Size 处理填充字符
 *      （共享实现位于 cache/shared/base64-size.ts）
 *   5. 单例缺少可测试性 → 提供 configure()/resetInstance()
 *
 * ★ onRecordDeleted 安全警示：
 *   正常删除路径【禁止】将 onRecordDeleted 接线为"从 pendingDeletionIds
 *   移除 ID"。pendingDeletionIds 是防复活保护：deleteAndPersist
 *   入队即过滤该 ID，直到 flush 磁盘验证成功才由 VerthysFlushService 移除。
 *   若在缓存同步阶段提前移除，磁盘旧数据会被扫描回填 → 删除复活。
 *   该回调仅用于特殊场景（如独立于冲刷队列的显式确认删除）。
 *
 * ★ 构建约束与设计对齐（与 verthys-cache-domain 重构同源决策）：
 *   - Node 'events' 的 EventEmitter 在本 Vite 浏览器 bundle 不可解析
 *     （无 events 包、无 polyfill），以零依赖 TypedEventEmitter 等价替代，
 *     事件名与监听器参数由事件表静态类型化（比 Node 版更安全）
 *   - 单例身份稳定性：原 configure() 以新实例替换 CacheCoordinator.instance，
 *     而模块底部导出的 cacheCoordinator 常量在模块求值时绑定，替换后
 *     消费方持有旧实例（ES live binding 指向导出时的对象）。本实现将
 *     configure()/resetInstance() 改为对既有单例的就地重配置/出厂重置，
 *     保持导出绑定与 getInstance() 返回值永远同一实例（原 API 与用途
 *     完整保留，身份漂移缺陷根治）
 *   - 默认处理器保留现网逐层 try/catch 失败包容（原头注声称
 *     "单层缓存失败不影响其他层"，逐层隔离是该承诺的落实）
 *
 * 使用示例：
 *   import { cacheCoordinator } from "../cache/coordination/cache-coordinator";
 *   cacheCoordinator.addRecord({ id, type, name, dataB64 });
 *   cacheCoordinator.removeRecord(id);
 *   cacheCoordinator.updateRecord({ id, type, name, dataB64, createdTime });
 */
import { TypedEventEmitter } from "../concurrency/typed-event-emitter";
import { estimateBase64Size } from "../shared/base64-size";
import {
  addRecordToScan,
  addFullRecord,
  addSummaryRecord,
  invalidateScannedRecord,
  invalidateSummaryRecord,
  invalidateFullRecord,
  getSummaryRecord,
} from "../composition/verthys-cache";
import type { SummaryRecord } from "../../lib/verthys";
import { createLogger } from "../../utils/logger";

const log = createLogger("cache-coordinator");

/* ==================== 类型定义 ==================== */

/** 记录更新数据（CacheCoordinator.addRecord/updateRecord 的入参） */
export interface RecordUpdate {
  /** 记录 ID */
  id: number;
  /** 记录类型（TYPE_GLOBAL_KEY / TYPE_MODULE_KEY / TYPE_MODULE_KEY_CONFIG / 业务类型） */
  type: number;
  /** 记录名称 */
  name: string;
  /** 记录数据（Base64 编码） */
  dataB64: string;
  /** 原始数据大小（字节，用于摘要显示）；不传则从 dataB64 精确估算 */
  dataSize?: number;
  /** 创建时间（Unix 秒）；不传则 addRecord 使用当前时间、updateRecord 自动保留旧值 */
  createdTime?: number;
  /** 物理偏移量；不传为 0 占位，下次 ensureSummaryScan 覆盖 */
  physicalOffset?: number;
  /** Merkle 叶子哈希；不传为空串占位，下次 ensureSummaryScan 覆盖 */
  merkleLeaf?: string;
}

/** 缓存更新处理器（依赖注入点，可整体或按需替换） */
export interface CacheHandlers {
  onAdd?: (rec: RecordUpdate) => void;
  onRemove?: (id: number) => void;
  onUpdate?: (rec: RecordUpdate) => void;
}

/** 领域事件表（TypedEventEmitter 静态约束） */
export type CacheCoordinatorEventMap = {
  "record:add": [RecordUpdate];
  "record:remove": [number];
  "record:update": [RecordUpdate];
};

/* ==================== 默认处理器工厂 ==================== */

/**
 * 默认缓存更新处理器：同步三层缓存（摘要/扫描/全量）。
 *
 * 失败包容：每层缓存独立 try/catch，单层失败不影响其他层
 * （例如 fullRecordCache LRU 淘汰异常时不阻断摘要/扫描层写入）。
 */
function createDefaultHandlers(): Required<CacheHandlers> {
  /** 由 RecordUpdate 构造摘要记录（未传字段落占位值） */
  const toSummary = (rec: RecordUpdate): SummaryRecord => ({
    id: rec.id,
    type: rec.type,
    name: rec.name,
    dataSize: rec.dataSize ?? estimateBase64Size(rec.dataB64),
    physicalOffset: rec.physicalOffset ?? 0,
    merkleLeaf: rec.merkleLeaf ?? "",
    createdTime: rec.createdTime ?? Math.floor(Date.now() / 1000),
  });

  return {
    onAdd: (rec) => {
      // 第一层：摘要缓存（列表渲染数据源，最高优先级）
      try {
        addSummaryRecord(toSummary(rec));
      } catch (e) {
        log.warn("onAdd: 摘要缓存更新失败", e);
      }
      // 第二层：扫描缓存（兼容路径，含 LRU + 大体积管控）
      try {
        addRecordToScan(rec.id, rec.type, rec.name, rec.dataB64);
      } catch (e) {
        log.warn("onAdd: 扫描缓存更新失败", e);
      }
      // 第三层：全量记录缓存（按需 LRU-50）
      try {
        addFullRecord(rec.id, rec.type, rec.name, rec.dataB64, rec.dataSize);
      } catch (e) {
        log.warn("onAdd: 全量缓存更新失败", e);
      }
    },
    onRemove: (id) => {
      // 删除操作幂等（记录不存在时无副作用），逐层独立容错
      try {
        invalidateScannedRecord(id);
      } catch (e) {
        log.warn("onRemove: 扫描缓存失效失败", e);
      }
      try {
        invalidateSummaryRecord(id);
      } catch (e) {
        log.warn("onRemove: 摘要缓存失效失败", e);
      }
      try {
        invalidateFullRecord(id);
      } catch (e) {
        log.warn("onRemove: 全量缓存失效失败", e);
      }
    },
    onUpdate: (rec) => {
      // ★ 评审修复：旧缓存失效逐层独立容错（与 onRemove 一致）——
      //   原实现三层失效合并在单个 try/catch 内，若 invalidateScannedRecord
      //   抛出异常，摘要/全量两层失效将被跳过，旧记录残留缓存产生数据
      //   不一致；逐层隔离后单层失败不影响其他层的失效
      try {
        invalidateScannedRecord(rec.id);
      } catch (e) {
        log.warn("onUpdate: 扫描缓存失效失败", e);
      }
      try {
        invalidateSummaryRecord(rec.id);
      } catch (e) {
        log.warn("onUpdate: 摘要缓存失效失败", e);
      }
      try {
        invalidateFullRecord(rec.id);
      } catch (e) {
        log.warn("onUpdate: 全量缓存失效失败", e);
      }

      // 重新写入（各层独立容错；toSummary 已携带 updateRecord 保留的 createdTime）
      try {
        addSummaryRecord(toSummary(rec));
      } catch (e) {
        log.warn("onUpdate: 摘要缓存更新失败", e);
      }
      try {
        addRecordToScan(rec.id, rec.type, rec.name, rec.dataB64);
      } catch (e) {
        log.warn("onUpdate: 扫描缓存更新失败", e);
      }
      try {
        addFullRecord(rec.id, rec.type, rec.name, rec.dataB64, rec.dataSize);
      } catch (e) {
        log.warn("onUpdate: 全量缓存更新失败", e);
      }
    },
  };
}

/**
 * 缓存协调器（事件驱动单例）
 *
 * ★ 封装统一的记录增删改接口，
 *   内部自动同步所有缓存层，消除业务代码手动调用分散缓存函数的遗漏风险。
 *
 * 特点：
 * - 通过 TypedEventEmitter 发布领域事件，缓存更新逻辑经 CacheHandlers 解耦
 * - 依赖注入缓存更新函数和删除标记回调（configure），便于测试
 * - 自动保留记录元数据（updateRecord 保留 createdTime 等）
 * - 错误隔离：单层缓存失败不影响其他层 + 事件处理失败不阻断发布方
 *
 * 通过 CacheCoordinator.getInstance() 获取单例，
 * 或直接使用导出的 cacheCoordinator 便捷单例。
 */
export class CacheCoordinator extends TypedEventEmitter<CacheCoordinatorEventMap> {
  private static instance: CacheCoordinator | null = null;

  private cacheHandlers: CacheHandlers;
  private onRecordDeleted?: (id: number) => void;

  /** 私有构造函数（单例模式）：装配默认事件订阅 */
  private constructor(
    handlers?: CacheHandlers,
    onRecordDeleted?: (id: number) => void,
  ) {
    super();
    this.cacheHandlers = handlers ?? createDefaultHandlers();
    this.onRecordDeleted = onRecordDeleted;
    this.setupDefaultSubscriptions();
  }

  /**
   * 获取单例实例（首次调用时装配默认实现）
   */
  static getInstance(): CacheCoordinator {
    if (!CacheCoordinator.instance) {
      CacheCoordinator.instance = new CacheCoordinator();
    }
    return CacheCoordinator.instance;
  }

  /**
   * 配置依赖（测试或自定义场景使用）。
   *
   * ★ 就地重配置：保持单例身份不变（模块导出的 cacheCoordinator 常量与
   *   getInstance() 返回值始终同一实例），handlers 整体替换、
   *   onRecordDeleted 未传时清除。
   *
   * @param handlers 缓存更新处理器（整体替换）
   * @param onRecordDeleted 删除记录时的额外回调（例如独立的删除确认逻辑；
   *   类头注安全警示——禁止接线为清除 pendingDeletionIds）
   */
  static configure(handlers: CacheHandlers, onRecordDeleted?: (id: number) => void): void {
    CacheCoordinator.getInstance().applyConfiguration(handlers, onRecordDeleted);
  }

  /**
   * 重置单例（测试用）：恢复默认处理器、清除注入回调、
   * 移除全部自定义监听器并重建默认订阅（出厂状态）。
   *
   * ★ 同样保持单例身份不变（原实现将 instance 置 null 会导致
   *   已导出的 cacheCoordinator 常量与后续 getInstance() 脱钩）。
   */
  static resetInstance(): void {
    CacheCoordinator.getInstance().applyFactoryReset();
  }

  /** 就地应用新配置（configure 的实例侧实现） */
  private applyConfiguration(handlers: CacheHandlers, onRecordDeleted?: (id: number) => void): void {
    this.cacheHandlers = handlers;
    this.onRecordDeleted = onRecordDeleted;
  }

  /** 出厂重置（resetInstance 的实例侧实现） */
  private applyFactoryReset(): void {
    this.removeAllListeners();
    this.cacheHandlers = createDefaultHandlers();
    this.onRecordDeleted = undefined;
    this.setupDefaultSubscriptions();
  }

  /** 注册领域事件订阅（构造/出厂重置时调用；处理器引用在触发时读取，支持就地换装） */
  private setupDefaultSubscriptions(): void {
    this.on("record:add", (rec) => {
      try {
        this.cacheHandlers.onAdd?.(rec);
      } catch (e) {
        log.warn("缓存添加事件处理失败", e);
      }
    });

    this.on("record:remove", (id) => {
      try {
        this.cacheHandlers.onRemove?.(id);
        // 调用外部注入的删除标记回调（如果有）
        this.onRecordDeleted?.(id);
      } catch (e) {
        log.warn("缓存删除事件处理失败", e);
      }
    });

    this.on("record:update", (rec) => {
      try {
        this.cacheHandlers.onUpdate?.(rec);
      } catch (e) {
        log.warn("缓存更新事件处理失败", e);
      }
    });
  }

  /**
   * 新增记录：发布 record:add 事件，默认处理器同步写入三层缓存。
   * createdTime 未传时补当前时间（Unix 秒）。
   */
  addRecord(rec: RecordUpdate): void {
    if (rec.createdTime === undefined) {
      rec = { ...rec, createdTime: Math.floor(Date.now() / 1000) };
    }
    this.emit("record:add", rec);
  }

  /**
   * 删除记录：发布 record:remove 事件，默认处理器同步失效三层缓存。
   *
   * ★ pendingDeletionIds 不在此清理（防复活保护由
   *   VerthysFlushService 在磁盘验证成功后管理）。
   */
  removeRecord(id: number): void {
    this.emit("record:remove", id);
  }

  /**
   * 更新记录（保留原 createdTime）。
   *
   * createdTime 未传时自动从摘要缓存读取旧值保留；读取失败或无旧值时
   * 回退默认处理器的时间兜底。先失效旧三层缓存，再写入新记录。
   */
  updateRecord(rec: RecordUpdate): void {
    if (rec.createdTime === undefined) {
      try {
        const oldSummary = getSummaryRecord(rec.id);
        if (oldSummary?.createdTime) {
          rec = { ...rec, createdTime: oldSummary.createdTime };
        }
      } catch {
        // 忽略读取失败，交由默认处理器的时间兜底
      }
    }
    this.emit("record:update", rec);
  }
}

/** 导出单例便捷实例（业务代码直接使用，无需 getInstance()；身份恒定，同文件头注） */
export const cacheCoordinator = CacheCoordinator.getInstance();
