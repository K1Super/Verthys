/*
 * cache/domain/verthys-flush-service.ts — Verthys 统一冲刷队列服务（领域类）
 *
 * ★ 重构核心实现。
 *   原 verthys-flush.ts 的模块级散落状态全部收拢为本类私有字段，
 *   对外 API 由 cache/composition/verthys-flush.ts 绑定导出（签名与旧版逐一对应）。
 *
 * ★ 本实现根治的九项缺陷（逐条对应）：
 *   1. globalOpVersion 声明未参与校验、纯 flush 也递增 → 整体移除
 *      （时序隔离由「快照校验 + 队列代际」承担，杜绝误弃合法删除）
 *   2. cacheTimersCancelled 布尔标志竞态窗口 → trackedSetTimeout 捕获
 *      注册时的代际 token，回调执行时校验代际而非共享布尔
 *   3. emergencyFlush 错误清空删除集合、未检查返回值 → 仅在 verthysFlush
 *      返回 true 时移除已提交删除 ID，未提交部分保留过滤保护
 *   4. deleteAndPersistBatch 缺乏快照校验 → 入队时逐 ID 捕获快照，
 *      执行时逐 ID 校验，被复用 ID 跳过删除
 *   5. flushVerthysNow 超时后队列永久卡死 → handleFlushTimeout 递增队列
 *      代际使卡住任务全部失效，重置链后新操作立即可入队
 *   6. resetFlushChain 未使用队列代际 → 旧任务完成时因代际不匹配不再
 *      递减计数器（负数缺陷根治）
 *   7. clearAllCacheTimers 未更新 pendingFlushWorkRef → 统一调用
 *      updatePendingFlushWork()，UI「保存中」指示器不再失真
 *   8. scheduleBackgroundFlush 缺乏节流 → 已有 flush 待执行时直接返回
 *   9. 状态变量散落 → 全部收拢为本类私有状态，可注入、可测试
 *
 * ★ 评审修复：
 *   删除失败时 pendingDeletionIds 未清理（严重缺陷）→ deleteAndPersist /
 *   deleteAndPersistBatch 的删除执行统一容错：返回 false 或抛出异常
 *   （verthysDeleteRecords/verthysDeleteRecord 会抛 VERTHYS_WRITE_BLOCKED 等）
 *   即为"删除未发生"，立即解除对应 ID 的过滤屏蔽，杜绝"记录仍在磁盘却被
 *   永久屏蔽 → 界面隐形丢失"；异常路径解除屏蔽后重新抛出，保持调用方
 *   现有异常契约（UI catch 提示用户）。成功路径不变：ID 进入
 *   committedDeletionIds，由 doFlush 磁盘验证成功后批量移除。
 *
 * 核心保证（与旧版一致）：
 *   1. 串行执行：flushChain Promise 链保证所有 flush 操作顺序执行
 *   2. 防抖合并：连续 delete 在 300ms 窗口内合并为单次 flush
 *   3. 超时保护：单次 doFlush 18s 超时 + 重试 2 次；waitForFlush 22s 超时
 *   4. ID 复用防护：delete 入队时记录 name+type+dataB64 快照，执行时校验
 *   5. 定时器统一管理：trackedSetTimeout 注册 trackedTimerIds + 代际 token
 *
 * 依赖关系（避免循环导入）：
 *   - verthys-flush-service.ts → lib/verthys.ts（verthysFlush/verthysDeleteRecords/verthysVerifyDiskPersist）
 *   - verthys-flush-service.ts → constants/key_manager_const.ts（VERTHYS_DEFAULT_PASSWORD）
 *   - verthys-flush-service.ts → lib/verthys_error.ts（VerthysResult，用于 flushVerthysNow）
 *   - currentVerthysPathGetter 由 verthys-flush.ts 构造时注入（state/key_state.ts）
 *   - snapshotProvider 由 verthys-cache.ts 注册（提供 recordScanCache 快照访问，
 *     避免 verthys-flush ↔ verthys-cache 循环导入）
 */
import { verthysFlush, verthysDeleteRecords, verthysVerifyDiskPersist } from "../../lib/verthys";
import { VERTHYS_DEFAULT_PASSWORD } from "../../constants/key_manager_const";
import { createLogger } from "../../utils/logger";
import { ok, err, VerthysErrorCode, type VerthysResult } from "../../lib/verthys_error";
import { ref, type Ref } from "vue";

const log = createLogger("verthys-flush");

/* ------------------------------------------------------------------ *
 * 快照提供者类型（避免与 verthys-cache.ts 循环导入）                     *
 *                                                                    *
 * deleteAndPersist 需要 recordScanCache.get(id) 获取删除快照用于      *
 * ID 复用防护。通过 setSnapshotProvider 注入访问函数，由 verthys-cache  *
 * 在模块初始化时注册。                                                *
 * ------------------------------------------------------------------ */

/** 记录快照类型（ScannedRecord 的子集） */
export interface RecordSnapshot {
  name: string;
  type: number;
  dataB64: string;
}

/** 快照提供者函数类型：返回指定 ID 记录的快照，不存在返回 null */
export type SnapshotProvider = (id: number) => RecordSnapshot | null;

/** 防抖窗口：300ms 内的连续 delete 共享一次 flush（与旧版一致） */
const FLUSH_DEBOUNCE_MS = 300;
/** doFlush 单次 IPC 超时（Rust verthys_flush 使用 send_batch_with_timeout 8s/操作，
 *  lock+unlock 两次最坏 16s，前端 18s 兜底覆盖 Rust 最坏情况 + 2s IPC 开销） */
const FLUSH_SINGLE_TIMEOUT_MS = 18000;
/** doFlush 最大重试次数（每次 18s，2 次 = 36s 最坏；waitForFlush 22s 超时后 doFlush 后台继续） */
const FLUSH_MAX_RETRIES = 2;
/** waitForFlush 总超时（覆盖单次 flush 18s + 4s 开销；超时后 lockAll 继续，doFlush 后台运行） */
const WAIT_FLUSH_TIMEOUT_MS = 22000;
/** doFlush 重试线性退避间隔 */
const FLUSH_RETRY_BACKOFF_MS = 100;

export class VerthysFlushService {
  // === 私有状态（原模块级散落变量收拢） ===
  private flushChain: Promise<void> = Promise.resolve();
  private pendingDeleteCount = 0;   // flushChain 中待执行的 delete 操作数
  private pendingFlushCount = 0;    // flushChain 中待执行的 flush 操作数
  private debounceFlushPending = false; // 防抖定时器是否待触发 flush（确保防抖窗口内 isFlushing=true）
  private flushDebounceTimer: ReturnType<typeof setTimeout> | null = null;
  private cacheDirty = false;       // 缓存脏数据标记（导航守卫弹窗提示）
  private lastFlushError: string | null = null;
  private generation = 0;           // 定时器代际：clearAllCacheTimers 递增，旧定时器回调失效
  private queueGeneration = 0;      // 队列代际：使旧任务失效（超时兜底 / 会话重置）
  private timersCancelled = false;  // 定时器取消标志（新会话合法操作时重置）

  private snapshotProvider: SnapshotProvider | null = null;
  private _committedDeletionIds = new Set<number>();
  private _pendingDeletionIds = new Set<number>();
  private trackedTimerIds = new Set<ReturnType<typeof setTimeout>>();

  private currentVerthysPathGetter: () => string | null;

  // === 响应式状态（UI「保存中」指示器绑定） ===
  public pendingFlushWorkRef: Ref<boolean> = ref(false);

  constructor(currentVerthysPathGetter: () => string | null) {
    this.currentVerthysPathGetter = currentVerthysPathGetter;
  }

  /* ==================== 兼容导出访问器 ==================== */

  /**
   * 待删除 ID 过滤集合（根治磁盘回填复活）。
   *
   * ★ 共享单一权威源：verthys-flush.ts 绑定层将本集合注入 VerthysCacheDomain，
   *   扫描/读取路径据此过滤，磁盘存在也不写入前端缓存，直到 flush 成功后清除。
   * 生命周期：
   *   - flush 成功后仅移除已提交删除的 ID（committedDeletionIds）
   *   - 删除失败/异常时立即解除对应 ID 屏蔽（删除未发生不应屏蔽，
   *     防止"记录仍在磁盘却被永久过滤 → 界面隐形丢失"）
   *   - 22s 超时后保留（防止磁盘回填旧数据，直到新会话初始化）
   *   - resetFlushChain 清空（新会话初始化）
   */
  get pendingDeletionIds(): Set<number> {
    return this._pendingDeletionIds;
  }

  /**
   * 已提交删除 ID 追踪集合（flush 成功后批量删除对应 ID，而非清空全部）。
   *
   * 当 deleteFn 返回 true（删除 IPC 已执行），对应 ID 加入此集合。
   * doFlush 成功后，仅将此集合中的 ID 从 pendingDeletionIds 批量移除，而非 clear()。
   * 修复竞态：旧实现 doFlush 成功即 pendingDeletionIds.clear()，会误清
   *   flush 进行期间新入队但尚未执行 deleteFn 的 ID，导致其过滤保护提前失效。
   */
  get committedDeletionIds(): Set<number> {
    return this._committedDeletionIds;
  }

  /** 注册快照提供者（由 verthys-cache.ts 在模块初始化时调用） */
  setSnapshotProvider(fn: SnapshotProvider): void {
    this.snapshotProvider = fn;
  }

  private getSnapshot(id: number): RecordSnapshot | null {
    return this.snapshotProvider ? this.snapshotProvider(id) : null;
  }

  /* ==================== 定时器管理（代际化） ==================== */

  /**
   * 受追踪的 setTimeout。
   *
   * ★ 回调执行时校验「注册时的定时器代际」而非共享布尔。
   *   旧实现的竞态窗口：clearAllCacheTimers 置 cancelled=true 后，新合法操作
   *   立即重置为 false，此时已在任务队列中尚未执行的旧回调会意外执行。
   *   代际 token 在注册瞬间捕获，回调触发时 token !== this.generation 即丢弃，
   *   无论取消标志是否被新操作重置。
   */
  private trackedSetTimeout(cb: () => void, ms: number): ReturnType<typeof setTimeout> {
    const token = this.generation;
    const id = setTimeout(() => {
      this.trackedTimerIds.delete(id);
      if (token !== this.generation) return;
      cb();
    }, ms);
    this.trackedTimerIds.add(id);
    return id;
  }

  /** 受追踪的 clearTimeout：从 trackedTimerIds 移除并清除 */
  private trackedClearTimeout(id: ReturnType<typeof setTimeout>): void {
    clearTimeout(id);
    this.trackedTimerIds.delete(id);
  }

  /**
   * 统一清空所有缓存定时器。
   *
   * 调用时机：lockAll 末尾、resetFlushChain、窗口卸载。
   * 递增代际使所有已注册回调失效；清空全部 pending 定时器，
   * 杜绝后台残留任务篡改缓存（如超时回调在 worker 销毁后仍触发 IPC）。
   *
   * ★ 同步更新 pendingFlushWorkRef，
   *   清空防抖后 UI「保存中」指示器不再显示错误状态。
   */
  clearAllCacheTimers(): void {
    this.generation++;
    this.timersCancelled = true;
    for (const id of this.trackedTimerIds) clearTimeout(id);
    this.trackedTimerIds.clear();
    this.flushDebounceTimer = null;
    this.debounceFlushPending = false;
    this.updatePendingFlushWork();
  }

  /**
   * 查询定时器是否已被取消（供 verthys-cache.ts 的 prefetchFullRecords 检查）。
   *
   * prefetchFullRecords 在每条记录加载前检查此标志，
   * 若已取消（lockAll / resetFlushChain 触发）则立即停止预加载，
   * 防止对已销毁 worker 的 IPC 调用。
   */
  isCacheTimersCancelled(): boolean {
    return this.timersCancelled;
  }

  /** 重置定时器取消标志（新会话合法操作启动时调用） */
  private resetTimersCancelledFlag(): void {
    this.timersCancelled = false;
  }

  /* ==================== 查询接口 ==================== */

  /** 是否有 pending 操作（delete 或 flush 未完成，或防抖 flush 待触发） */
  isFlushing(): boolean {
    return this.pendingDeleteCount > 0 || this.pendingFlushCount > 0 || this.debounceFlushPending;
  }

  /** 检查缓存是否处于脏数据状态（22s 超时后置 true，需弹窗提示用户） */
  isCacheDirty(): boolean {
    return this.cacheDirty;
  }

  /** 检查指定 ID 是否在待删除集合中（路由守卫、扫描过滤使用） */
  isPendingDeletion(id: number): boolean {
    return this._pendingDeletionIds.has(id);
  }

  /** 查询队列状态 */
  flushQueueStatus(): { pendingCount: number; lastError: string | null; isFlushing: boolean } {
    return {
      pendingCount: this.pendingDeleteCount + this.pendingFlushCount,
      lastError: this.lastFlushError,
      isFlushing: this.isFlushing(),
    };
  }

  /** 更新 pendingFlushWorkRef（在所有计数变化点调用） */
  private updatePendingFlushWork(): void {
    this.pendingFlushWorkRef.value = this.isFlushing();
  }

  /* ==================== 核心操作 ==================== */

  /**
   * 持久化 verthys 到磁盘（新增/编辑后调用，写透模式）。
   * 立即入队 flush，取消防抖（此立即 flush 已覆盖 pending delete）。
   */
  async persistVerthys(): Promise<boolean> {
    const currentVerthysPath = this.currentVerthysPathGetter();
    if (!currentVerthysPath) {
      log.error("persistVerthys: currentVerthysPath 为空");
      return false;
    }
    this.resetTimersCancelledFlag();
    const gen = this.queueGeneration;

    this.cancelDebouncedFlush();
    this.pendingFlushCount++;
    this.updatePendingFlushWork();

    const result = this.flushChain.then(() => {
      if (gen !== this.queueGeneration) return;
      return this.doFlush();
    });

    // 更新链尾（吞掉错误，避免一次失败中断后续所有 flush）
    this.flushChain = result.then(
      () => {
        if (gen !== this.queueGeneration) return;
        this.pendingFlushCount--;
        this.updatePendingFlushWork();
      },
      () => {
        if (gen !== this.queueGeneration) return;
        this.pendingFlushCount--;
        this.updatePendingFlushWork();
      },
    );
    return result.then(() => true, () => false);
  }

  /**
   * 删除记录并持久化（防抖合并 flush）。
   *
   * ★ ID 复用防护：可选传入 recordId，入队时记录该 ID 的
   *   name+type+dataB64 快照。执行 delete 前校验缓存中该 ID 的记录是否与
   *   快照一致，若不一致（verthys 后端复用 ID 分配给新记录），丢弃旧删除，
   *   防止"旧删除覆盖后续新增/修改的同 ID 记录"。
   *
   * ★ 校验语义（与现网删除调用链时序严格对齐）：
   *   UI 删除流程（AccountVerthys.vue 等）在调用 deleteAndPersist 之前已执行
   *   invalidateScannedRecord(rid)，故入队时快照可能为 null（无校验依据，
   *   直接执行）；队列执行时 current 为 null 同样可能（该删除流程自身移除了
   *   缓存条目）。仅当「入队时有快照 && 执行时缓存中存在同 ID 记录 &&
   *   元数据不一致」三条件同时成立才判定 ID 复用、丢弃旧删除。
   *   若把 current=null 也判为不一致，已走 UI 流程的删除会在执行段被
   *   全部丢弃 → 记录不落盘删除 → 「删除复活」回归。
   *
   * @param deleteFn 执行删除 IPC 的函数（返回 true/false）
   * @param recordId 待删除记录的 ID（可选，用于 ID 复用校验）
   * @returns delete 结果（flush 由防抖调度，不阻塞调用方）
   */
  async deleteAndPersist(
    deleteFn: () => Promise<boolean>,
    recordId?: number,
  ): Promise<boolean> {
    const currentVerthysPath = this.currentVerthysPathGetter();
    if (!currentVerthysPath) return false;
    this.resetTimersCancelledFlag();

    const gen = this.queueGeneration;

    // 将待删除 ID 加入过滤集合（立即生效，杜绝磁盘回填复活）
    if (recordId !== undefined) {
      this._pendingDeletionIds.add(recordId);
    }

    // 记录删除时的完整元数据快照（type/name/dataB64）
    const snapshot = recordId !== undefined ? this.getSnapshot(recordId) : null;
    const snapshotName = snapshot?.name;
    const snapshotType = snapshot?.type;
    const snapshotDataB64 = snapshot?.dataB64;

    this.pendingDeleteCount++;
    this.updatePendingFlushWork();

    const result = this.flushChain.then(async () => {
      if (gen !== this.queueGeneration) return true;
      if (recordId !== undefined) {
        const current = this.getSnapshot(recordId);
        // ★ ID 复用校验：仅当执行时缓存中同 ID 记录存在且元数据与快照不一致
        //   才判定为复用（语义与方法头注释一致）
        if (current !== null && snapshotName !== undefined) {
          if (
            current.name !== snapshotName ||
            current.type !== snapshotType ||
            current.dataB64 !== snapshotDataB64
          ) {
            log.warn(`ID=${recordId} 已被复用或修改，丢弃旧删除`);
            this._pendingDeletionIds.delete(recordId);
            return true;
          }
        }
      }
      // ★ 评审修复：删除执行统一容错——返回 false 或抛出异常均视为
      //   "删除未发生"，立即解除该 ID 的过滤屏蔽（避免记录仍在磁盘却被
      //   pendingDeletionIds 永久屏蔽 → 界面隐形丢失）；异常路径解除后
      //   重新抛出，保持调用方现有异常契约（UI catch 提示用户）
      let delOk: boolean;
      try {
        delOk = await deleteFn();
      } catch (e) {
        log.error("delete 执行异常，已解除该 ID 的过滤屏蔽", e);
        if (recordId !== undefined) {
          this._pendingDeletionIds.delete(recordId);
        }
        throw e;
      }
      if (!delOk) {
        log.warn("delete 返回 false，已解除该 ID 的过滤屏蔽");
        if (recordId !== undefined) {
          this._pendingDeletionIds.delete(recordId);
        }
      }
      // deleteFn 成功 → 标记为已提交，doFlush 成功后批量移除（非 clear）
      if (delOk && recordId !== undefined) {
        this._committedDeletionIds.add(recordId);
      }
      return delOk;
    });

    // 更新链尾（吞掉错误，避免一次失败中断后续所有操作）
    this.flushChain = result.then(
      () => {
        if (gen !== this.queueGeneration) return;
        this.pendingDeleteCount--;
        this.updatePendingFlushWork();
      },
      () => {
        if (gen !== this.queueGeneration) return;
        this.pendingDeleteCount--;
        this.updatePendingFlushWork();
      },
    );

    // 防抖调度 flush（300ms 内的连续 delete 共享一次 flush）
    this.scheduleDebouncedFlush();
    return result;
  }

  /**
   * 批量删除并持久化（批量删除必须合并为单次 flush）。
   *
   * 将整个 ID 列表一次性传递给 Rust 层（verthysDeleteRecords），worker 在单次
   * verthys 事务内一次性从索引区移除所有对应条目，只做一次重加密和一次全局
   * HMAC 更新。无论删除多少张照片，磁盘写入量恒定，仅与索引区大小相关。
   *
   * ★ 入队时逐 ID 捕获快照，执行时逐 ID 校验——
   *   「入队时有快照 && 执行时缓存中存在同 ID 记录 && 元数据不一致」的 ID
   *   判定为已被复用，从删除列表中剔除（并移出待删过滤集合），仅对
   *   未被复用的 ID 执行单次批量删除 IPC。校验语义与 deleteAndPersist 一致。
   *
   * @param recordIds 待删除记录 ID 列表
   * @returns 批量删除结果（true=全部成功或全部被判定复用）
   */
  async deleteAndPersistBatch(recordIds: number[]): Promise<boolean> {
    const currentVerthysPath = this.currentVerthysPathGetter();
    if (!currentVerthysPath || recordIds.length === 0) return false;
    this.resetTimersCancelledFlag();

    const gen = this.queueGeneration;
    const snapshots = new Map<number, RecordSnapshot | null>();

    // 全部 ID 加入过滤集合（立即生效，杜绝磁盘回填复活）+ 逐 ID 捕获快照
    for (const id of recordIds) {
      this._pendingDeletionIds.add(id);
      snapshots.set(id, this.getSnapshot(id));
    }

    this.pendingDeleteCount++;
    this.updatePendingFlushWork();
    const idsCopy = recordIds.slice(); // 防御性拷贝，避免调用方后续修改数组

    const result = this.flushChain.then(async () => {
      if (gen !== this.queueGeneration) return true;
      const validIds: number[] = [];
      for (const id of idsCopy) {
        const oldSnap = snapshots.get(id);
        const current = this.getSnapshot(id);
        // ★ 逐 ID 快照校验（语义同 deleteAndPersist：仅 current 存在且
        //   入队快照存在时不一致才判定复用）
        if (oldSnap && current) {
          if (
            oldSnap.name !== current.name ||
            oldSnap.type !== current.type ||
            oldSnap.dataB64 !== current.dataB64
          ) {
            log.warn(`批量删除中 ID=${id} 已被复用或修改，跳过`);
            this._pendingDeletionIds.delete(id);
            continue;
          }
        }
        validIds.push(id);
      }
      if (validIds.length === 0) return true;
      // ★ 评审修复：批量删除执行统一容错——返回 false 或抛出异常均视为
      //   "删除未发生"，立即解除全部 attempted IDs（validIds，已剔除复用
      //   跳过项，其标记已单独移除）的过滤屏蔽；异常路径解除后重新抛出，
      //   保持调用方现有异常契约
      let delOk: boolean;
      try {
        delOk = await verthysDeleteRecords(validIds);
      } catch (e) {
        log.error("verthysDeleteRecords 执行异常，已解除全部 attempted IDs 的过滤屏蔽", e);
        for (const id of validIds) {
          this._pendingDeletionIds.delete(id);
        }
        throw e;
      }
      if (!delOk) {
        log.warn(`verthysDeleteRecords 返回 false (count=${validIds.length})，已解除过滤屏蔽`);
        for (const id of validIds) {
          this._pendingDeletionIds.delete(id);
        }
      }
      // 全部成功 → 标记为已提交，doFlush 成功后批量移除
      if (delOk) {
        for (const id of validIds) {
          this._committedDeletionIds.add(id);
        }
      }
      return delOk;
    });

    this.flushChain = result.then(
      () => {
        if (gen !== this.queueGeneration) return;
        this.pendingDeleteCount--;
        this.updatePendingFlushWork();
      },
      () => {
        if (gen !== this.queueGeneration) return;
        this.pendingDeleteCount--;
        this.updatePendingFlushWork();
      },
    );

    // 防抖调度单次 flush（300ms 内的连续批量删除共享一次 flush）
    this.scheduleDebouncedFlush();
    return result;
  }

  /* ==================== 防抖调度 ==================== */

  /** 防抖调度 flush：300ms 内的连续 delete 共享一次 flush */
  private scheduleDebouncedFlush(): void {
    // 已有防抖定时器 → 复用（不重复计数，多次 delete 共享一次 flush）
    if (this.flushDebounceTimer) return;
    // 预占 flush 待触发标志，确保防抖窗口内 isFlushing()=true
    // （修复竞态：delete 完成后计数归零但防抖 flush 还没入队，
    //  isFlushing()=false → 关闭应用跳过 waitForFlush → lockAll 抢先写旧状态）
    this.debounceFlushPending = true;
    this.updatePendingFlushWork();
    this.flushDebounceTimer = this.trackedSetTimeout(() => {
      this.flushDebounceTimer = null;
      this.debounceFlushPending = false;
      this.updatePendingFlushWork();
      this.enqueueFlushInternal();
    }, FLUSH_DEBOUNCE_MS);
  }

  /** 取消防抖定时器（lockAll / persistVerthys / waitForFlush 调用） */
  cancelDebouncedFlush(): void {
    if (this.flushDebounceTimer) {
      this.trackedClearTimeout(this.flushDebounceTimer);
      this.flushDebounceTimer = null;
      this.debounceFlushPending = false;
      this.updatePendingFlushWork();
    }
  }

  /** 入队一次 flush（在 flushChain 尾部追加 doFlush）— 内部使用 */
  private enqueueFlushInternal(): void {
    const gen = this.queueGeneration;
    this.pendingFlushCount++;
    this.updatePendingFlushWork();

    const flushResult = this.flushChain.then(() => {
      if (gen !== this.queueGeneration) return;
      return this.doFlush();
    });

    this.flushChain = flushResult.then(
      () => {
        if (gen !== this.queueGeneration) return;
        this.pendingFlushCount--;
        this.updatePendingFlushWork();
      },
      () => {
        if (gen !== this.queueGeneration) return;
        this.pendingFlushCount--;
        this.updatePendingFlushWork();
      },
    );
  }

  /**
   * 将操作加入冲刷队列（不阻塞调用方）。
   *
   * 用于非关键路径的延迟持久化：initGlobalKey/setModuleKey/setModuleKeyEnabled
   * 调用此方法，不等待落盘完成，立即返回。落盘失败通过 Toast 提醒但不影响内存状态。
   *
   * @param operation 待执行的异步操作（通常为 () => persistVerthys()）
   * @returns Promise，resolve 时表示操作已入队（非执行完成）
   */
  async enqueueFlush(operation: () => Promise<void>): Promise<void> {
    this.resetTimersCancelledFlag();
    const gen = this.queueGeneration;
    this.pendingFlushCount++;
    this.updatePendingFlushWork();

    const flushResult = this.flushChain.then(async () => {
      if (gen !== this.queueGeneration) return;
      try {
        await operation();
      } catch (e) {
        log.error("enqueueFlush: 操作执行失败", e);
        this.lastFlushError = e instanceof Error ? e.message : String(e);
      }
    });

    this.flushChain = flushResult.then(
      () => {
        if (gen !== this.queueGeneration) return;
        this.pendingFlushCount--;
        this.updatePendingFlushWork();
      },
      () => {
        if (gen !== this.queueGeneration) return;
        this.pendingFlushCount--;
        this.updatePendingFlushWork();
      },
    );
    return flushResult;
  }

  /**
   * 立即冲刷并等待完成（关键路径专用）。
   *
   * 用于应用退出、lockAll、密码变更等必须同步落盘的场景。
   *
   * ★ 超时后调用 handleFlushTimeout 重置队列——
   *   旧实现超时后 flushChain 可能仍卡住，后续操作追加到未完成的队列上
   *   导致永久阻塞；重置后新操作立即可入队，持久化能力恢复。
   *
   * @param timeoutMs 超时毫秒数（默认 22000ms）
   * @returns VerthysResult，成功为 ok(void)，超时为 err(E_FLUSH_TIMEOUT)
   */
  async flushVerthysNow(timeoutMs: number = WAIT_FLUSH_TIMEOUT_MS): Promise<VerthysResult<void>> {
    try {
      this.resetTimersCancelledFlag();
      this.cancelDebouncedFlush();
      this.enqueueFlushInternal();

      let timedOut = false;
      await Promise.race([
        this.flushChain,
        new Promise<void>((resolve) => {
          this.trackedSetTimeout(() => {
            log.error(`flushVerthysNow 超时 ${timeoutMs}ms`);
            timedOut = true;
            this.handleFlushTimeout();
            resolve();
          }, timeoutMs);
        }),
      ]);

      if (timedOut) {
        return err(VerthysErrorCode.E_FLUSH_TIMEOUT, `冲刷超时 ${timeoutMs}ms，数据可能未完全落盘`);
      }
      return ok(undefined);
    } catch (e) {
      log.error("flushVerthysNow 异常", e);
      return err(VerthysErrorCode.E_PERSIST_FAILED, `冲刷失败: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  /**
   * 等待所有 pending 操作完成（应用退出前调用，保证数据落盘）。
   * 取消防抖定时器并立即入队 flush，确保待删除记录全部落盘后再 lockAll。
   *
   * ★ 22s 超时兜底流程：
   *   1. handleFlushTimeout 重置队列 + 执行一次无重试紧急原子 flush
   *   2. 标记缓存脏数据（cacheDirty=true），导航守卫弹窗提示用户
   *   3. 保留未提交的 pendingDeletionIds（防止磁盘回填旧数据，直到新会话初始化）
   *   4. 放行导航/锁屏流程，避免 UI 永久卡死
   */
  async waitForFlush(): Promise<void> {
    this.resetTimersCancelledFlag();
    this.cancelDebouncedFlush();
    this.enqueueFlushInternal();

    let timedOut = false;
    await Promise.race([
      this.flushChain,
      new Promise<void>((resolve) => {
        this.trackedSetTimeout(() => {
          log.error(`waitForFlush 超时 ${WAIT_FLUSH_TIMEOUT_MS}ms，执行紧急兜底`);
          timedOut = true;
          this.handleFlushTimeout();
          resolve();
        }, WAIT_FLUSH_TIMEOUT_MS);
      }),
    ]);

    if (timedOut) {
      log.warn("waitForFlush 超时，队列已重置，保留删除标记");
    }
  }

  /**
   * 超时兜底：使卡住的队列失效并重置，允许新操作入队。
   *
   * 保留 pendingDeletionIds 和 committedDeletionIds（emergencyFlush 仅清除
   * 已成功落盘部分），防止磁盘回填旧数据。
   */
  private handleFlushTimeout(): void {
    log.error("检测到 flush 队列超时，重置队列以恢复持久化能力");
    this.queueGeneration++;                  // 使所有旧任务失效
    this.flushChain = Promise.resolve();     // 重置队列，丢弃卡住任务
    this.pendingDeleteCount = 0;
    this.pendingFlushCount = 0;
    this.debounceFlushPending = false;
    this.cacheDirty = true;
    this.updatePendingFlushWork();

    // 尝试一次紧急冲刷（不依赖原队列）
    this.emergencyFlush();
  }

  /**
   * 紧急无重试原子 flush（超时兜底）。
   * 不走 doFlush 重试逻辑，单次 verthysFlush 尽可能写入磁盘。
   *
   * ★ 仅在 verthysFlush 返回 true（磁盘已实际写入）时
   *   才从 pendingDeletionIds 移除已提交删除的 ID；返回 false 或抛异常时
   *   保留全部删除标记，杜绝「队列中仍有未执行删除却提前解除过滤保护 →
   *   磁盘旧数据回填复活」。
   */
  private async emergencyFlush(): Promise<void> {
    const path = this.currentVerthysPathGetter();
    if (!path) return;
    try {
      const success = await verthysFlush(path, VERTHYS_DEFAULT_PASSWORD);
      if (success) {
        // 仅移除已提交删除的 ID，保留未提交部分
        for (const id of this._committedDeletionIds) {
          this._pendingDeletionIds.delete(id);
        }
        this._committedDeletionIds.clear();
        this.cacheDirty = false;
        this.lastFlushError = null;
      } else {
        log.error("紧急 flush 返回 false，保留删除标记");
        this.lastFlushError = "紧急 flush 失败";
      }
    } catch (e) {
      log.error("紧急 flush 异常", e);
      this.lastFlushError = `紧急 flush 异常: ${e instanceof Error ? e.message : String(e)}`;
    }
  }

  /**
   * 重置 flush 串行队列。
   *
   * lockAll 销毁 worker 后调用：将 flushChain 重置为新的 resolved Promise，
   * 切断前一会话残留的 pending doFlush 链，避免在新会话中触发对已销毁
   * worker 的 IPC 调用。
   *
   * ★ queueGeneration++ 使旧任务全部失效——旧任务完成时
   *   因代际不匹配不再递减计数器（负数缺陷根治）；旧任务遗留的
   *   pendingDeletionIds 一并清空（旧任务已全部失效，"删除屏蔽"随之解除）。
   *
   * 调用时机：lockAll 末尾，在 verthysLock() 与 setCurrentVerthysPath("") 之后。
   */
  resetFlushChain(): void {
    this.queueGeneration++;
    this.flushChain = Promise.resolve();
    this.pendingDeleteCount = 0;
    this.pendingFlushCount = 0;
    this.debounceFlushPending = false;
    this.cacheDirty = false;
    this.lastFlushError = null;
    // 重置会话时清空删除集合（旧任务已全部失效）
    this._pendingDeletionIds.clear();
    this._committedDeletionIds.clear();
    this.clearAllCacheTimers();
    this.updatePendingFlushWork();
  }

  /**
   * 非阻塞后台冲刷（导航切换时调用）。
   *
   * 立即入队 flush，但不等待完成；flush 在后台异步执行，导航切换立即返回。
   *
   * ★ 节流保护——已有 flush 待执行（pendingFlushCount>0
   *   或防抖窗口待触发）时直接返回，杜绝频繁调用导致 flush 任务重复入队堆积。
   */
  scheduleBackgroundFlush(): void {
    const path = this.currentVerthysPathGetter();
    if (!path) return;
    this.resetTimersCancelledFlag();
    if (this.pendingFlushCount > 0 || this.debounceFlushPending) {
      return; // 已有待执行 flush，避免堆积
    }
    this.cancelDebouncedFlush();
    this.enqueueFlushInternal();
  }

  /* ==================== 实际 flush 执行 ==================== */

  /**
   * 实际执行 flush 操作（含重试逻辑与磁盘级持久化验证）。
   *
   * 新 flush 模式（Verthys_Flush）不改变 worker 状态（始终保持 UNLOCKED），
   * flush 失败后无需 verthysUnlock 恢复。短暂延迟后重试（线性退避 100ms）。
   */
  private async doFlush(): Promise<boolean> {
    const path = this.currentVerthysPathGetter();
    // 空路径保护：lockAll 已清空路径后，残留的 pending flush 不得触发 IPC
    if (!path) {
      log.warn("doFlush: currentVerthysPath 为空，跳过 flush（worker 可能已销毁）");
      return false;
    }

    for (let attempt = 1; attempt <= FLUSH_MAX_RETRIES; attempt++) {
      const okResult = await Promise.race([
        verthysFlush(path, VERTHYS_DEFAULT_PASSWORD),
        new Promise<boolean>((resolve) => {
          this.trackedSetTimeout(() => {
            log.error(`verthysFlush 超时 ${FLUSH_SINGLE_TIMEOUT_MS}ms`);
            resolve(false);
          }, FLUSH_SINGLE_TIMEOUT_MS);
        }),
      ]);
      if (!okResult) {
        log.error(`verthysFlush 第 ${attempt}/${FLUSH_MAX_RETRIES} 次失败`);
        this.lastFlushError = `verthysFlush 第 ${attempt} 次失败`;
      } else {
        // 磁盘级持久化验证：flush 成功后绕过 worker 内存直接校验磁盘文件，
        // 消除"内存可见、磁盘丢失"假成功。验证失败按 flush 失败处理，触发重试。
        const diskOk = await verthysVerifyDiskPersist(path);
        if (diskOk) {
          // flush 成功后立即从 Set 中批量移除已提交删除的对应 ID（而非 clear 全部）
          for (const id of this._committedDeletionIds) {
            this._pendingDeletionIds.delete(id);
          }
          this._committedDeletionIds.clear();
          // 重置脏数据标记（数据已成功落盘）
          this.cacheDirty = false;
          this.lastFlushError = null;
          return true;
        }
        log.error(`磁盘验证失败第 ${attempt}/${FLUSH_MAX_RETRIES} 次`);
        this.lastFlushError = "disk verification failed";
      }
      if (attempt < FLUSH_MAX_RETRIES) {
        // 短暂延迟后重试（线性退避：100ms）
        await new Promise<void>(resolve => this.trackedSetTimeout(resolve, FLUSH_RETRY_BACKOFF_MS));
      }
    }
    return false;
  }

  /* ==================== 删除集合管理 ==================== */

  /** 清空待删除 ID 集合（仅在新会话完整初始化、verthys 重新解锁成功后调用） */
  clearPendingDeletionIds(): void {
    this._pendingDeletionIds.clear();
    this._committedDeletionIds.clear();
  }

  /** 标记缓存脏数据状态（手动设置/清除） */
  setCacheDirty(dirty: boolean): void {
    this.cacheDirty = dirty;
  }
}
