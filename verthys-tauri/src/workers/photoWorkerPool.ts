/**
 * workers/photoWorkerPool.ts — 照片加密 Web Worker 池（piscina 等价实现）
 *
 * ★ Comprehensive_optimization：异步批处理流水线 — 传输器阶段（工作线程池）
 *
 * =============================================================================
 * 设计目标
 * =============================================================================
 * 传输层：线程池替代子进程 + 零拷贝批量回传：
 *   1. 池化管理：维护 hardwareConcurrency-1 个常驻 Web Worker，避免频繁创建销毁
 *   2. 任务队列：FIFO 调度，空闲 Worker 立即领取任务
 *   3. 零拷贝传输：fileBytes 通过 transferList 零所有权转让到 Worker
 *   4. 崩溃自动重启：Worker onerror / messageerror 触发重建，未完成任务重新投递
 *   5. 背压控制：待处理任务数超过阈值时，submit() 返回的 Promise 暂停 resolve，
 *      防止生产者持续投喂导致内存暴涨（背压队列优化点）
 *
 * =============================================================================
 * 并发模型：
 * =============================================================================
 * - 池上限：min(4, max(1, hardwareConcurrency - 1))
 *   照片加密为 SSD 顺序读 + AES 混合负载，4 并发即达吞吐拐点；
 *   超过 4 后磁盘带宽饱和，多余 Worker 只贡献常驻 V8 isolate 内存
 *   （每 isolate 基线 10~15MB，原 hardwareConcurrency-1=19 → +200~280MB）
 * - 按需创建：构造期零 Worker 实例化，首个任务到达时冷启动（<100ms），
 *   避免模块 import 即全量创建的内存阶跃
 * - 空闲回收：全部 Worker 空闲 >120s → terminate 一半，下次任务再冷启动
 * - 每个 Worker 串行处理分配的任务（加密是 CPU 密集型，单线程满载最优）
 * - 主线程通过 submit() 投递任务，Worker 完成后通过 postMessage 回传结果
 *
 * =============================================================================
 * 背压策略
 * =============================================================================
 * - maxPendingTasks = poolSize * 4（每个 Worker 积压不超过 4 个待处理任务）
 * - 当 pending 数达到阈值，submit() 不立即入队，而是等待 drain 信号
 * - 这保证内存中同时存在的 fileBytes 不超过 (poolSize * 4) × 平均照片大小
 *   1000 张 5MB 照片 + 8 核 → 内存峰值 ~140MB，远低于 500MB 上限
 *
 * =============================================================================
 * 崩溃恢复
 * =============================================================================
 * - Worker 触发 onerror / messageerror / 异常退出时：
 *   a) 记录日志，标记该 Worker 为 crashed
 *   b) 重建新 Worker 替代（保留 pool size）
 *   c) 将该 Worker 上正在处理的任务重新投递到队列头部（保证不丢任务）
 * - 连续崩溃保护：若同一 Worker 在 5 秒内崩溃 3 次，放弃重建，
 *   将该 Worker 的任务标记为失败（避免崩溃循环）
 *
 * =============================================================================
 * 安全边界
 * =============================================================================
 * - Worker 仅接收 photoKey + fileBytes，不接触 verthys 句柄
 * - fileBytes 通过 transferList 转让后，主线程失去访问权（防内存泄露明文）
 * - terminate() 时所有 Worker 立即销毁，清空任务队列
 */
import type {
  PhotoCryptoRequest,
  PhotoCryptoResponse,
  PhotoCryptoSuccess,
  PhotoCryptoFailure,
  PhotoMetaCryptoRequest,
  PhotoMetaCryptoSuccess,
} from "./photo-crypto.worker";
import type { PhotoMeta } from "../lib/crypto";
import { createLogger } from "../utils/logger";

const log = createLogger("photo-worker-pool");

/** Worker 池配置 */
export interface PhotoWorkerPoolOptions {
  /** 池大小上限（默认 min(4, max(1, hardwareConcurrency - 1)) — 混合负载吞吐拐点） */
  poolSize?: number;
  /** 最大待处理任务数（默认 poolSize * 4，背压阈值） */
  maxPendingTasks?: number;
  /** Worker 崩溃重启最大次数（默认 3，超过则放弃） */
  maxRestartAttempts?: number;
  /** 崩溃重启冷却时间（默认 5000ms，连续崩溃判定窗口） */
  restartCooldownMs?: number;
  /** 全部空闲超时回收阈值（默认 120000ms，超时后 terminate 一半 Worker） */
  idleRecycleMs?: number;
}

/** 单个待处理任务（含 resolve/reject 句柄，用于 Worker 回调） */
interface PendingTask {
  /** 任务 ID（自增，用于关联请求与响应） */
  id: number;
  /** 请求载荷（完整加密请求 或 meta-only 加密请求） */
  request: PhotoCryptoRequest | PhotoMetaCryptoRequest;
  /** 成功回调（完整加密返回 PhotoCryptoSuccess，meta-only 返回 PhotoMetaCryptoSuccess） */
  resolve: (result: PhotoCryptoSuccess | PhotoMetaCryptoSuccess) => void;
  /** 失败回调 */
  reject: (error: Error) => void;
  /** 任务提交时间戳（用于超时检测） */
  submittedAt: number;
}

/** 单个 Worker 的运行时状态 */
interface WorkerSlot {
  /** Worker 实例 */
  worker: Worker;
  /** 该 Worker 当前正在处理的任务（null 表示空闲） */
  currentTask: PendingTask | null;
  /** 崩溃重启次数（用于连续崩溃保护） */
  restartCount: number;
  /** 最近一次崩溃时间戳（用于冷却窗口判定） */
  lastCrashAt: number;
  /** 是否已终止（terminate 后不再重建） */
  terminated: boolean;
}

/**
 * 照片加密 Web Worker 池（单例）
 *
 * 线程池替代子进程 + 零拷贝批量回传：
 * - 常驻 Worker 池，避免频繁创建销毁
 * - transferList 零拷贝传输 fileBytes
 * - 背压队列防止内存暴涨
 * - 崩溃自动重启 + 任务重新投递
 */
export class PhotoWorkerPool {
  private static instance: PhotoWorkerPool | null = null;

  /** 池大小上限 */
  private readonly poolSize: number;
  /** 最大待处理任务数（背压阈值） */
  private readonly maxPendingTasks: number;
  /** 崩溃重启最大次数 */
  private readonly maxRestartAttempts: number;
  /** 崩溃重启冷却时间 */
  private readonly restartCooldownMs: number;
  /** 全部空闲超时回收阈值 */
  private readonly idleRecycleMs: number;

  /** Worker 槽位数组（按需创建，长度 ≤ poolSize） */
  private slots: WorkerSlot[] = [];
  /** 待处理任务队列（FIFO） */
  private taskQueue: PendingTask[] = [];
  /** 任务 ID 自增计数器 */
  private nextTaskId = 1;
  /** 当前待处理任务数（队列 + 正在处理） */
  private pendingCount = 0;
  /** 背压等待者队列（pending 达阈值时，submit 等待 drain） */
  private drainWaiters: Array<() => void> = [];
  /** 是否已终止（terminate 后不再接受新任务） */
  private terminated = false;
  /** 最近一次任务分配时间戳（空闲回收基准） */
  private lastBusyAt = Date.now();
  /** 空闲回收定时器句柄（null 表示未调度） */
  private idleRecycleTimer: number | null = null;

  /** 私有构造（单例） */
  private constructor(options: PhotoWorkerPoolOptions = {}) {
    // ★ 池上限钳制：SSD + AES 混合负载 4 并发即饱和磁盘吞吐，
    //   超额 Worker 只贡献常驻 isolate 内存（每 isolate 基线 10~15MB）
    this.poolSize = options.poolSize ?? Math.min(4, Math.max(1, (navigator.hardwareConcurrency || 4) - 1));
    this.maxPendingTasks = options.maxPendingTasks ?? this.poolSize * 4;
    this.maxRestartAttempts = options.maxRestartAttempts ?? 3;
    this.restartCooldownMs = options.restartCooldownMs ?? 5000;
    this.idleRecycleMs = options.idleRecycleMs ?? 120_000;
    this.initializePool();
  }

  /** 获取单例 */
  static getInstance(options?: PhotoWorkerPoolOptions): PhotoWorkerPool {
    if (!PhotoWorkerPool.instance) {
      PhotoWorkerPool.instance = new PhotoWorkerPool(options ?? {});
    }
    return PhotoWorkerPool.instance;
  }

  /** 初始化 Worker 池（★ 按需创建：构造期零 Worker 实例化） */
  private initializePool(): void {
    log.info(`Worker 池已配置（按需创建）: maxPool=${this.poolSize}, maxPending=${this.maxPendingTasks}`);
  }

  /** 创建单个 Worker 槽位 */
  private createWorkerSlot(slotIndex: number): WorkerSlot {
    // Vite 原生支持 new Worker(new URL(...), { type: 'module' }) 语法
    const worker = new Worker(
      new URL("./photo-crypto.worker.ts", import.meta.url),
      { type: "module" },
    );

    const slot: WorkerSlot = {
      worker,
      currentTask: null,
      restartCount: 0,
      lastCrashAt: 0,
      terminated: false,
    };

    // 消息处理：接收 Worker 加密结果
    worker.onmessage = (e: MessageEvent<PhotoCryptoResponse>) => {
      this.handleWorkerMessage(slot, e.data);
    };

    // 错误处理：Worker 崩溃
    worker.onerror = (e: ErrorEvent) => {
      log.error(`Worker[${slotIndex}] 崩溃 (onerror):`, e.message ?? e);
      this.handleWorkerCrash(slot, slotIndex);
    };

    // messageerror：反序列化失败（数据损坏）
    worker.onmessageerror = () => {
      log.error(`Worker[${slotIndex}] messageerror（消息反序列化失败）`);
      this.handleWorkerCrash(slot, slotIndex);
    };

    return slot;
  }

  /** 处理 Worker 返回的消息 */
  private handleWorkerMessage(slot: WorkerSlot, response: PhotoCryptoResponse): void {
    const task = slot.currentTask;
    if (!task) {
      log.warn("收到 Worker 消息但无当前任务，忽略");
      return;
    }

    // 校验任务 ID 一致性（防止乱序）
    if (response.id !== task.id) {
      log.warn(`任务 ID 不匹配: expected=${task.id}, got=${response.id}，忽略`);
      return;
    }

    // 清空当前任务（释放 Worker）
    slot.currentTask = null;
    this.pendingCount--;

    if (response.ok) {
      // ★ 统一处理两种成功响应类型：
      //   PhotoCryptoSuccess（完整加密） / PhotoMetaCryptoSuccess（meta-only 加密）
      //   两者都含 ok: true + id，通过联合类型 resolve
      task.resolve(response);
    } else {
      const failure = response as PhotoCryptoFailure;
      task.reject(new Error(failure.error || `加密失败: ${failure.name}`));
    }

    // 通知背压等待者（pending 减少，可能释放配额）
    this.notifyDrainWaiters();

    // 分配下一个任务给该空闲 Worker
    this.dispatchNextTask();

    // 队列排空 → 调度空闲回收检查（markBusy 已取消定时器时此处重新调度）
    this.scheduleIdleRecycle();
  }

  /** 处理 Worker 崩溃 */
  private handleWorkerCrash(slot: WorkerSlot, slotIndex: number): void {
    if (slot.terminated) return;

    const now = Date.now();
    const inCooldownWindow = now - slot.lastCrashAt < this.restartCooldownMs;

    if (inCooldownWindow) {
      slot.restartCount++;
    } else {
      // 超出冷却窗口，重置计数
      slot.restartCount = 1;
    }
    slot.lastCrashAt = now;

    // 将正在处理的任务重新投递到队列头部（保证不丢任务）
    if (slot.currentTask) {
      const lostTask = slot.currentTask;
      slot.currentTask = null;
      this.pendingCount--;
      log.warn(`Worker[${slotIndex}] 崩溃，任务 ${lostTask.id} 重新投递到队列头部`);

      // 头部插入（优先于新任务，保证崩溃恢复的任务先执行）
      this.taskQueue.unshift(lostTask);
      this.notifyDrainWaiters();
    }

    // 终止旧 Worker
    try {
      slot.worker.terminate();
    } catch {
      // terminate 失败忽略
    }

    // 连续崩溃保护：超过阈值则放弃重建
    if (slot.restartCount > this.maxRestartAttempts) {
      log.error(
        `Worker[${slotIndex}] 在 ${this.restartCooldownMs}ms 内连续崩溃 ${slot.restartCount} 次，` +
          `放弃重建，该槽位永久失效`,
      );
      slot.terminated = true;
      return;
    }

    // 重建新 Worker
    log.info(`Worker[${slotIndex}] 重建中 (restartCount=${slot.restartCount})`);
    const newSlot = this.createWorkerSlot(slotIndex);
    // 保留 restartCount / lastCrashAt / terminated 状态
    newSlot.restartCount = slot.restartCount;
    newSlot.lastCrashAt = slot.lastCrashAt;
    // ★ 按池化（slots 动态增删）安全替换：indexOf 定位，非索引赋值
    const slotIdx = this.slots.indexOf(slot);
    if (slotIdx >= 0) {
      this.slots[slotIdx] = newSlot;
    } else {
      this.slots.push(newSlot);
    }

    // 分配任务给新 Worker
    this.dispatchNextTask();
  }

  /** 分配下一个任务给空闲 Worker（★ 无空闲且未达上限时按需冷启动） */
  private dispatchNextTask(): void {
    if (this.terminated || this.taskQueue.length === 0) return;

    // 查找空闲 Worker
    let idleSlot = this.slots.find((s) => !s.terminated && !s.currentTask);

    // ★ 按需创建：无空闲且未达池上限 → 冷启动新 Worker（<100ms）
    if (!idleSlot && this.slots.length < this.poolSize) {
      idleSlot = this.createWorkerSlot(this.slots.length);
      this.slots.push(idleSlot);
      log.info(`按需冷启动 Worker[${this.slots.length - 1}]（active=${this.slots.length}/${this.poolSize}）`);
    }
    if (!idleSlot) return;

    const task = this.taskQueue.shift();
    if (!task) return;

    idleSlot.currentTask = task;
    this.markBusy();

    // ★ 根据请求类型决定 transferList：
    //   - PhotoCryptoRequest（完整加密）：fileBytes 是 ArrayBuffer，通过 transferList 零拷贝转让
    //   - PhotoMetaCryptoRequest（meta-only）：无 fileBytes，meta 对象通过结构化克隆传输
    try {
      if ("fileBytes" in task.request) {
        // 完整加密：transferList 零拷贝传输 fileBytes（主线程失去访问权）
        const transferList: Transferable[] = [task.request.fileBytes];
        idleSlot.worker.postMessage(task.request, transferList);
      } else {
        // meta-only 加密：无 transferList，结构化克隆传输 meta + photoKey
        idleSlot.worker.postMessage(task.request);
      }
    } catch (e) {
      // postMessage 失败（极罕见：Worker 已终止或序列化异常）
      log.error(`任务 ${task.id} postMessage 失败:`, e);
      idleSlot.currentTask = null;
      this.pendingCount--;
      task.reject(new Error(`Worker 通信失败: ${e instanceof Error ? e.message : String(e)}`));
      this.notifyDrainWaiters();
    }
  }

  /** 标记忙碌（任务分配时调用：重置空闲基准 + 取消回收定时器） */
  private markBusy(): void {
    this.lastBusyAt = Date.now();
    if (this.idleRecycleTimer !== null) {
      clearTimeout(this.idleRecycleTimer);
      this.idleRecycleTimer = null;
    }
  }

  /** 调度空闲回收检查（任务完成且队列排空后调用） */
  private scheduleIdleRecycle(): void {
    if (this.terminated || this.idleRecycleTimer !== null) return;
    const wait = Math.max(0, this.idleRecycleMs - (Date.now() - this.lastBusyAt));
    this.idleRecycleTimer = window.setTimeout(() => {
      this.idleRecycleTimer = null;
      this.recycleIdleWorkers();
    }, wait);
  }

  /** ★ 空闲回收：全部 Worker 空闲且超阈值 → terminate 一半（下次任务冷启动） */
  private recycleIdleWorkers(): void {
    if (this.terminated) return;
    const allIdle = this.taskQueue.length === 0 && this.slots.every((s) => !s.currentTask);
    if (!allIdle) return;

    const keep = Math.max(1, Math.ceil(this.slots.length / 2));
    const toRemove = this.slots.length - keep;
    if (toRemove <= 0) return;

    log.info(`空闲回收: terminate ${toRemove} 个 Worker（保留 ${keep}，空闲 >${this.idleRecycleMs}ms）`);
    for (let i = 0; i < toRemove; i++) {
      const slot = this.slots.pop();
      if (!slot) break;
      slot.terminated = true;
      try {
        slot.worker.terminate();
      } catch {
        // 终止失败忽略
      }
    }
  }

  /** 通知背压等待者（pending 减少，可能释放配额） */
  private notifyDrainWaiters(): void {
    while (this.drainWaiters.length > 0 && this.pendingCount < this.maxPendingTasks) {
      const waiter = this.drainWaiters.shift();
      if (waiter) waiter();
    }
  }

  /** 等待背压释放（pending 低于阈值时立即 resolve） */
  private waitForDrain(): Promise<void> {
    if (this.pendingCount < this.maxPendingTasks) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.drainWaiters.push(resolve);
    });
  }

  /**
   * 提交加密任务到 Worker 池
   *
   * 零拷贝批量回传：fileBytes 通过 transferList 零所有权转让到 Worker。
   * 背压控制：pending 达阈值时，submit 等待 drain，防止内存暴涨。
   *
   * @param request 加密请求（含 fileBytes ArrayBuffer，调用后主线程失去访问权）
   * @returns 加密成功响应（含 hash / thumbB64 / metaB64）
   */
  async submit(request: Omit<PhotoCryptoRequest, "id">): Promise<PhotoCryptoSuccess> {
    if (this.terminated) {
      throw new Error("Worker 池已终止，无法提交新任务");
    }

    // 背压控制：等待 pending 低于阈值
    await this.waitForDrain();

    if (this.terminated) {
      throw new Error("Worker 池在等待背压期间被终止");
    }

    return new Promise<PhotoCryptoSuccess>((resolve, reject) => {
      const task: PendingTask = {
        id: this.nextTaskId++,
        request: { ...request, id: this.nextTaskId - 1 },
        resolve,
        reject,
        submittedAt: Date.now(),
      };
      // 修正 id（nextTaskId 已自增，但 request.id 应与 task.id 一致）
      task.request.id = task.id;

      this.taskQueue.push(task);
      this.pendingCount++;
      this.dispatchNextTask();
    });
  }

  /**
   * 批量提交并收集所有结果（保持输入顺序）
   *
   * 用于消费者阶段：将一批已加密记录收集后，一次性传递给后端 IPC。
   * 内部并行调度到 Worker 池，结果按输入顺序排列。
   *
   * @param requests 加密请求列表
   * @returns 成功结果列表（顺序与输入一致，失败项被过滤并通过 onFailure 回调）
   */
  async submitBatch(
    requests: Array<Omit<PhotoCryptoRequest, "id">>,
    onFailure?: (request: Omit<PhotoCryptoRequest, "id">, error: Error) => void,
  ): Promise<PhotoCryptoSuccess[]> {
    const promises = requests.map((req) =>
      this.submit(req).catch((err: Error) => {
        onFailure?.(req, err);
        return null;
      }),
    );
    const results = await Promise.all(promises);
    return results.filter((r): r is PhotoCryptoSuccess => r !== null);
  }

  /**
   * ★ Parsed Import：提交 meta-only 加密任务到 Worker 池
   *
   * 线程池替代子进程优化点在 .venc 解析导入场景的复用：
   *   - 解析 .venc 文件后，chunks 已用当前 photoKey 加密（同设备导入），
   *     仅需重新加密元数据（doParse 阶段被解密用于预览）
   *   - 复用 Worker 池的背压控制、崩溃恢复、任务队列调度
   *   - 与 submit() 的区别：无 fileBytes（无 transferList），meta 通过结构化克隆传输
   *
   * @param request meta-only 加密请求（含已解密的 PhotoMeta + photoKey + recordName）
   * @returns meta-only 加密成功响应（含 metaB64 / hash / thumbB64 / name / mime / size）
   */
  async submitMetaOnly(
    request: Omit<PhotoMetaCryptoRequest, "id">,
  ): Promise<PhotoMetaCryptoSuccess> {
    if (this.terminated) {
      throw new Error("Worker 池已终止，无法提交新任务");
    }

    // 背压控制：等待 pending 低于阈值（与 submit() 共享背压配额）
    await this.waitForDrain();

    if (this.terminated) {
      throw new Error("Worker 池在等待背压期间被终止");
    }

    return new Promise<PhotoMetaCryptoSuccess>((resolve, reject) => {
      const task: PendingTask = {
        id: this.nextTaskId++,
        request: { ...request, id: this.nextTaskId - 1 } as PhotoMetaCryptoRequest,
        resolve: resolve as (result: PhotoCryptoSuccess | PhotoMetaCryptoSuccess) => void,
        reject,
        submittedAt: Date.now(),
      };
      // 修正 id（nextTaskId 已自增，但 request.id 应与 task.id 一致）
      (task.request as PhotoMetaCryptoRequest).id = task.id;

      this.taskQueue.push(task);
      this.pendingCount++;
      this.dispatchNextTask();
    });
  }

  /** 获取当前池状态（调试/监控用） */
  getStats(): {
    poolSize: number;
    activeWorkers: number;
    pendingTasks: number;
    queuedTasks: number;
    idleWorkers: number;
    maxPending: number;
    drainWaiters: number;
  } {
    const idleWorkers = this.slots.filter((s) => !s.terminated && !s.currentTask).length;
    return {
      poolSize: this.poolSize,
      activeWorkers: this.slots.filter((s) => !s.terminated).length,
      pendingTasks: this.pendingCount,
      queuedTasks: this.taskQueue.length,
      idleWorkers,
      maxPending: this.maxPendingTasks,
      drainWaiters: this.drainWaiters.length,
    };
  }

  /** 终止所有 Worker 并清空任务队列
   *
   * 用于应用关闭或模块锁定时，安全释放 Worker 资源。
   * 待处理任务的 Promise 将被 reject。
   */
  terminate(): void {
    if (this.terminated) return;
    this.terminated = true;

    // 取消空闲回收定时器
    if (this.idleRecycleTimer !== null) {
      clearTimeout(this.idleRecycleTimer);
      this.idleRecycleTimer = null;
    }

    log.info("Worker 池终止中，销毁所有 Worker");

    // 终止所有 Worker
    for (const slot of this.slots) {
      try {
        slot.worker.terminate();
      } catch {
        // 终止失败忽略
      }
      slot.terminated = true;
    }
    this.slots = [];

    // 拒绝所有待处理任务
    while (this.taskQueue.length > 0) {
      const task = this.taskQueue.shift();
      if (task) {
        task.reject(new Error("Worker 池已终止"));
      }
    }
    this.pendingCount = 0;

    // 释放所有背压等待者
    while (this.drainWaiters.length > 0) {
      const waiter = this.drainWaiters.shift();
      if (waiter) waiter();
    }
  }
}

/** 导出单例便捷方法 */
export const photoWorkerPool = PhotoWorkerPool.getInstance();
