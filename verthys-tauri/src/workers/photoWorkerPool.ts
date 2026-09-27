/**
 * workers/photoWorkerPool.ts — 照片加密 Web Worker 池
 *
 * 职责：作为三阶段导入流水线的传输器阶段，管理 Web Worker 池的生命周期、
 * 任务调度、背压、崩溃恢复与超时控制；同时承载读取链路的解密任务
 * （列表按需解密 / 查看原图），使派生与 AEAD 解密不占用渲染主线程。
 *
 * =============================================================================
 * 设计目标
 * =============================================================================
 * 1. 池化管理：维护 min(4, max(1, hardwareConcurrency-1)) 个常驻 Worker，
 *    按需冷启动（构造期零实例化），全部空闲超时后逐步回收。
 * 2. 任务恒可重放：提交任务时主线程保留源字节权威副本（source），每次投递
 *    生成一个新的可转移副本（source.slice()）交给 Worker。崩溃/超时后任务
 *    可无损重投，直至达到最大尝试次数才判定为毒丸失败。
 * 3. 有限时间 settle：每个在途任务挂看门狗预算（按历史耗时 EWMA 估算），
 *    超时终止 Worker 并重投；池级兜底保证 submit 返回的 Promise 绝不悬挂。
 * 4. 背压：待处理任务数达阈值时 submit 等待 drain，防止内存暴涨。
 * 5. 失败可分类：Worker 明确拒绝（数据损坏等确定性失败）以 TaskRejectedError
 *    区分于池基础设施失败（崩溃/超时/毒丸/终止），调用方据此决定是否回退重算。
 *
 * =============================================================================
 * 内存峰值
 * =============================================================================
 * 完整加密任务在途期间同时持有 source 副本与 Worker 侧转移副本，
 * 峰值约 maxPendingTasks × 2 × 平均文件大小，受背压阈值约束。
 * 解密任务载荷为密文 base64 字符串（结构化克隆，无转移副本），
 * 明文经 transferList 直接回到调用方，不在池内驻留。
 *
 * =============================================================================
 * 安全边界
 * =============================================================================
 * - Worker 仅接收 photoKey + 文件字节（或密文串），不接触 verthys 句柄、不发起 IPC。
 * - 转移副本（transferList）的所有权在投递时移交给 Worker，Worker 内部
 *   使用后清零；主线程 source 副本在任务 settle 后随引用释放由 GC 回收。
 */
import type {
  PhotoCryptoRequest,
  PhotoCryptoResponse,
  PhotoCryptoSuccess,
  PhotoCryptoFailure,
  PhotoMetaCryptoRequest,
  PhotoMetaCryptoSuccess,
  PhotoSlimThumbRequest,
  PhotoSlimThumbSuccess,
  PhotoSlimSetRequest,
  PhotoSlimSetSuccess,
  PhotoSlimRepackRequest,
  PhotoDecryptMetaRequest,
  PhotoDecryptMetaSuccess,
  PhotoDecryptThumbRequest,
  PhotoDecryptThumbSuccess,
  PhotoDecryptSlimSetRequest,
  PhotoDecryptSlimSetSuccess,
  PhotoDecryptChunksRequest,
  PhotoDecryptChunksSuccess,
} from "./photo-crypto.worker";
import { createLogger } from "../utils/logger";
import {
  MAX_TASK_ATTEMPTS,
  MAX_CONSECUTIVE_SLOT_CRASHES,
} from "../constants/crypto_const";

const log = createLogger("photo-worker-pool");

/* ------------------------------------------------------------------ *
 * 错误类型                                                            *
 * ------------------------------------------------------------------ */

/** Worker 池错误基类：以 name 字段区分错误族，供调用方精确匹配 */
export class WorkerPoolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkerPoolError";
  }
}

/** 池已终止：terminate() 后提交或终止期间在途任务被拒绝 */
export class PoolTerminatedError extends WorkerPoolError {
  constructor() {
    super("Worker 池已终止");
    this.name = "PoolTerminatedError";
  }
}

/** 毒丸任务：同一任务达到最大尝试次数仍未完成 */
export class PoisonPillError extends WorkerPoolError {
  /** 任务 ID */
  readonly taskId: number;
  /** 最后一次失败原因 */
  readonly reason: string;

  constructor(taskId: number, reason: string) {
    super(`任务 ${taskId} 重试达到上限，判定为不可完成（原因: ${reason}）`);
    this.name = "PoisonPillError";
    this.taskId = taskId;
    this.reason = reason;
  }
}

/** 任务超时：在单次投递的预算时间内未返回结果 */
export class TaskTimeoutError extends WorkerPoolError {
  /** 任务 ID */
  readonly taskId: number;
  /** 本次投递的超时预算（毫秒） */
  readonly budgetMs: number;

  constructor(taskId: number, budgetMs: number) {
    super(`任务 ${taskId} 超时（预算 ${budgetMs}ms 内未响应）`);
    this.name = "TaskTimeoutError";
    this.taskId = taskId;
    this.budgetMs = budgetMs;
  }
}

/**
 * Worker 已执行并明确拒绝任务：确定性失败。
 *
 * 与池基础设施失败（崩溃/超时/毒丸/终止/通信失败）区分：这类失败由输入数据
 * 决定（标签校验不过、密文损坏、块序号与 AD 不符），重投或在主线程重算必然
 * 得到同样结果，调用方应直接呈现失败而不回退。
 */
export class TaskRejectedError extends WorkerPoolError {
  /** 任务 ID */
  readonly taskId: number;
  /** Worker 返回的失败原因 */
  readonly reason: string;

  constructor(taskId: number, reason: string) {
    super(`任务 ${taskId} 被 Worker 拒绝（原因: ${reason}）`);
    this.name = "TaskRejectedError";
    this.taskId = taskId;
    this.reason = reason;
  }
}

/**
 * 结构化克隆失败判定：postMessage 对含 Proxy / 函数 / Symbol 等
 * 不可克隆值的载荷抛 DataCloneError（DOMException，name 为固定值）。
 */
function isDataCloneError(e: unknown): boolean {
  return (
    typeof e === "object" &&
    e !== null &&
    (e as { name?: unknown }).name === "DataCloneError"
  );
}

/* ------------------------------------------------------------------ *
 * 配置与常量                                                          *
 * ------------------------------------------------------------------ */

/** Worker 池配置 */
export interface PhotoWorkerPoolOptions {
  /** 池大小上限（默认 min(4, max(1, hardwareConcurrency - 1))） */
  poolSize?: number;
  /** 最大待处理任务数（默认 poolSize * 4，背压阈值） */
  maxPendingTasks?: number;
  /** 全部空闲超时回收阈值（默认 120000ms） */
  idleRecycleMs?: number;
  /** Worker 工厂（测试注入点；默认真实 Worker 构造） */
  workerFactory?: () => Worker;
}

/** 看门狗扫描周期（毫秒） */
const WATCHDOG_SWEEP_MS = 2_000;
/** 超时预算下限（毫秒）：防止慢机任务被过早判死 */
const BUDGET_MIN_MS = 30_000;
/** 超时预算上限（毫秒）：保证有限时间 settle 的上界 */
const BUDGET_MAX_MS = 300_000;
/** 超时预算倍率：预算 = 历史耗时估计 × 倍率 */
const BUDGET_FACTOR = 6;
/** 无样本时的初始耗时估计（毫秒）：对应初始预算 60s，随样本快速收敛 */
const INITIAL_EWMA_MS = 10_000;

/* ------------------------------------------------------------------ *
 * 超时预算估算器                                                      *
 * ------------------------------------------------------------------ */

/**
 * 基于历史任务实际耗时的 EWMA 估算器：
 * 每次任务成功完成记录实际耗时，维护耗时近似的 EWMA；超时预算为
 * 该估计值乘以固定倍率后钳制在安全区间。相比固定阈值，慢机不会被
 * 过早判超时，快机也不会等待过久的无意义上限。
 */
class TimeoutBudgetEstimator {
  /** 耗时 EWMA（毫秒），null 表示尚无样本 */
  private ewmaMs: number | null = null;
  /** 最近样本环形窗口（用于稳定估算，容量有界） */
  private readonly samples: number[] = [];
  /** 样本窗口容量 */
  private static readonly SAMPLE_CAP = 200;

  /** 记录一次成功完成的任务耗时 */
  record(elapsedMs: number): void {
    this.samples.push(elapsedMs);
    if (this.samples.length > TimeoutBudgetEstimator.SAMPLE_CAP) {
      this.samples.shift();
    }
    const p95 = this.percentile95();
    this.ewmaMs = this.ewmaMs === null
      ? p95
      : this.ewmaMs * 0.8 + p95 * 0.2;
  }

  /** 计算当前任务超时预算（毫秒） */
  budget(): number {
    const estimate = this.ewmaMs ?? INITIAL_EWMA_MS;
    return Math.min(BUDGET_MAX_MS, Math.max(BUDGET_MIN_MS, Math.round(estimate * BUDGET_FACTOR)));
  }

  /** 样本 95 分位（排序法，样本量有界） */
  private percentile95(): number {
    if (this.samples.length === 0) return INITIAL_EWMA_MS;
    const sorted = [...this.samples].sort((a, b) => a - b);
    const idx = Math.min(
      sorted.length - 1,
      Math.floor(sorted.length * 0.95),
    );
    return sorted[idx];
  }
}

/* ------------------------------------------------------------------ *
 * 任务与槽位结构                                                      *
 * ------------------------------------------------------------------ */

/** 完整加密请求体（不含 id 与 fileBytes：后者由池按次生成可转移副本） */
type PhotoCryptoRequestBody = Omit<PhotoCryptoRequest, "id" | "fileBytes">;
/** meta-only 加密请求体（不含 id） */
type PhotoMetaCryptoRequestBody = Omit<PhotoMetaCryptoRequest, "id">;
/** 缩略图记录加密请求体（不含 id：op 由提交入口补齐） */
type PhotoSlimThumbRequestBody = Omit<PhotoSlimThumbRequest, "id">;
/** 块集记录加密请求体（不含 id：op 由提交入口补齐） */
type PhotoSlimSetRequestBody = Omit<PhotoSlimSetRequest, "id">;
/** 块集记录解密请求体（不含 id：op 由提交入口补齐） */
type PhotoDecryptSlimSetRequestBody = Omit<PhotoDecryptSlimSetRequest, "id">;
/** 重打包加密请求体（不含 id 与 fileBytes：后者由池按次生成可转移副本） */
type PhotoSlimRepackRequestBody = Omit<PhotoSlimRepackRequest, "id" | "fileBytes">;
/** 元数据解密请求体（不含 id：op 由提交入口补齐，Worker 据此分发） */
type PhotoDecryptMetaRequestBody = Omit<PhotoDecryptMetaRequest, "id">;
/** 缩略图记录解密请求体（不含 id：op 由提交入口补齐） */
type PhotoDecryptThumbRequestBody = Omit<PhotoDecryptThumbRequest, "id">;
/** 数据块解密请求体（不含 id：op 由提交入口补齐，Worker 据此分发） */
type PhotoDecryptChunksRequestBody = Omit<PhotoDecryptChunksRequest, "id">;

/** 任意任务的成功响应（池按任务类别收窄后返回给调用方） */
type PhotoTaskSuccess =
  | PhotoCryptoSuccess
  | PhotoMetaCryptoSuccess
  | PhotoSlimThumbSuccess
  | PhotoSlimSetSuccess
  | PhotoDecryptMetaSuccess
  | PhotoDecryptThumbSuccess
  | PhotoDecryptSlimSetSuccess
  | PhotoDecryptChunksSuccess;

/**
 * 任务类别：决定 Worker 明确拒绝时的错误类别。
 * 加密任务沿用既有错误语义（普通 Error，导入链路按文案入账）；
 * 解密任务的明确拒绝是确定性失败，以 TaskRejectedError 区分于池故障。
 */
type TaskKind = "encrypt" | "decrypt";

/** 任务载荷：source 为源字节权威副本（任务 settle 前不得释放） */
interface TaskPayload {
  /** 源字节副本（无文件字节的任务为 null：结构化克隆天然可重放） */
  source: Uint8Array | null;
  /** 已投递次数（每次 dispatch +1，达到上限判毒丸） */
  attempts: number;
}

/** 单个待处理任务（含 resolve/reject 句柄，用于 Worker 回调） */
interface PendingTask {
  /** 任务 ID（自增，用于关联请求与响应） */
  id: number;
  /** 请求载荷（fileBytes 由投递时按次生成） */
  request:
    | PhotoCryptoRequestBody
    | PhotoSlimRepackRequestBody
    | PhotoMetaCryptoRequestBody
    | PhotoSlimThumbRequestBody
    | PhotoSlimSetRequestBody
    | PhotoDecryptMetaRequestBody
    | PhotoDecryptThumbRequestBody
    | PhotoDecryptSlimSetRequestBody
    | PhotoDecryptChunksRequestBody;
  /** 载荷（source 权威副本 + 尝试计数） */
  payload: TaskPayload;
  /** 成功回调 */
  resolve: (result: PhotoTaskSuccess) => void;
  /** 失败回调 */
  reject: (error: Error) => void;
  /** 本次投递时间戳（看门狗判定基准） */
  submittedAt: number;
  /** 本次投递的超时预算（毫秒） */
  timeoutBudgetMs: number;
  /** 任务类别（决定 Worker 明确拒绝时的错误类别） */
  kind: TaskKind;
}

/** 单个 Worker 的运行时状态 */
interface WorkerSlot {
  /** 槽位序号（日志与指标标识） */
  index: number;
  /** Worker 实例 */
  worker: Worker;
  /** 该 Worker 当前正在处理的任务（null 表示空闲） */
  currentTask: PendingTask | null;
  /** 连续失败计数（崩溃/超时；成功完成一个任务后清零） */
  consecutiveCrashes: number;
  /** 累计崩溃次数（仅观测指标，不参与判定） */
  totalCrashes: number;
  /** 是否已永久失效（连续失败超限，不再重建） */
  terminated: boolean;
  /**
   * 模块密钥失效后需在该 Worker 的下一次任务入口清空派生缓存。
   * 新建 Worker 默认 true（启动即干净，首次任务带标记无副作用）。
   */
  keyCacheClearPending: boolean;
}

/**
 * 提交完整加密任务的输入：fileBytes 与请求体分离，
 * 池在内部保留 fileBytes 的权威副本以保证任务可重放。
 */
export interface SubmitInput {
  /** 文件原始字节（提交后主线程仍可继续使用原引用） */
  fileBytes: Uint8Array;
  /** 加密请求体（不含 id/fileBytes） */
  request: PhotoCryptoRequestBody;
}

/* ------------------------------------------------------------------ *
 * 超时看门狗                                                          *
 * ------------------------------------------------------------------ */

/**
 * 周期扫描全部槽位在途任务的看门狗：在途任务超过本次投递预算即触发超时
 * 处理（终止挂起 Worker 并重投或判失败）。周期扫描比每任务独立定时器
 * 更轻量（零任务时为无操作的空转）。
 */
class TimeoutWatchdog {
  /** 周期扫描定时器句柄（null 表示未运行） */
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly sweepFn: () => void,
    private readonly sweepMs: number,
  ) {}

  /** 启动周期扫描（幂等：已在运行则忽略） */
  start(): void {
    if (this.timer !== null) return;
    this.timer = setInterval(() => this.sweepFn(), this.sweepMs);
  }

  /** 停止周期扫描（幂等） */
  stop(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}

/* ------------------------------------------------------------------ *
 * Worker 池主体                                                       *
 * ------------------------------------------------------------------ */

/**
 * 照片加密 Web Worker 池（单例）
 *
 * 并发模型：
 * - 池大小钳制为 min(4, max(1, hardwareConcurrency-1))：加密负载下
 *   超出该并发只贡献常驻内存而不提升吞吐
 * - 任务 FIFO 调度；每个 Worker 串行处理分配到的任务
 * - 崩溃/超时触发槽位重建；连续失败超限后槽位永久失效；
 *   全部槽位失效时池级兜底拒绝所有未完成任务（杜绝悬挂）
 */
export class PhotoWorkerPool {
  private static instance: PhotoWorkerPool | null = null;

  /** 池大小上限 */
  private readonly poolSize: number;
  /** 最大待处理任务数（背压阈值） */
  private readonly maxPendingTasks: number;
  /** 全部空闲超时回收阈值 */
  private readonly idleRecycleMs: number;
  /** Worker 工厂（测试注入点） */
  private readonly workerFactory: () => Worker;

  /** Worker 槽位数组（按需创建，长度 ≤ poolSize） */
  private readonly slots: WorkerSlot[] = [];
  /** 待处理任务队列（FIFO） */
  private readonly taskQueue: PendingTask[] = [];
  /** 任务 ID 自增计数器 */
  private nextTaskId = 1;
  /** 当前待处理任务数（队列 + 在途） */
  private pendingCount = 0;
  /** 背压等待者队列（pending 达阈值时，submit 等待 drain） */
  private readonly drainWaiters: Array<() => void> = [];
  /** 是否已终止（terminate 后不再接受新任务） */
  private terminated = false;
  /** 最近一次任务分配时间戳（空闲回收基准） */
  private lastBusyAt = Date.now();
  /** 空闲回收定时器句柄（null 表示未调度） */
  private idleRecycleTimer: ReturnType<typeof setTimeout> | null = null;
  /** 超时预算估算器（历史耗时驱动） */
  private readonly timeoutEstimator = new TimeoutBudgetEstimator();
  /** 超时看门狗（扫描回调闭包引用池内部状态） */
  private readonly watchdog = new TimeoutWatchdog(
    () => this.sweepTimeouts(),
    WATCHDOG_SWEEP_MS,
  );
  /** 毒丸任务计数（观测） */
  private poisonPills = 0;
  /** 超时次数（观测） */
  private timeouts = 0;
  /** 永久失效槽位数（观测） */
  private slotExhausted = 0;
  /** 池自愈重建次数（观测：全部槽位失效后冷启动新 Worker 的次数） */
  private poolRevivals = 0;

  /** 私有构造（单例） */
  private constructor(options: PhotoWorkerPoolOptions = {}) {
    // node 测试环境无 navigator：以 4 核为回退基准
    const cores = typeof navigator !== "undefined" ? (navigator.hardwareConcurrency || 4) : 4;
    this.poolSize = options.poolSize ?? Math.min(4, Math.max(1, cores - 1));
    this.maxPendingTasks = options.maxPendingTasks ?? this.poolSize * 4;
    this.idleRecycleMs = options.idleRecycleMs ?? 120_000;
    this.workerFactory = options.workerFactory ?? (() => new Worker(
      new URL("./photo-crypto.worker.ts", import.meta.url),
      { type: "module" },
    ));
  }

  /** 获取单例（首次创建时应用配置） */
  static getInstance(options?: PhotoWorkerPoolOptions): PhotoWorkerPool {
    if (!PhotoWorkerPool.instance) {
      PhotoWorkerPool.instance = PhotoWorkerPool.create(options ?? {});
    }
    return PhotoWorkerPool.instance;
  }

  /** 创建独立实例（测试与多池场景使用；单例路径也经此构造） */
  static create(options: PhotoWorkerPoolOptions = {}): PhotoWorkerPool {
    return new PhotoWorkerPool(options);
  }

  /** 创建单个 Worker 槽位 */
  private createWorkerSlot(slotIndex: number): WorkerSlot {
    const worker = this.workerFactory();

    const slot: WorkerSlot = {
      index: slotIndex,
      worker,
      currentTask: null,
      consecutiveCrashes: 0,
      totalCrashes: 0,
      terminated: false,
      keyCacheClearPending: true,
    };

    // 消息处理：接收 Worker 加密结果
    worker.onmessage = (e: MessageEvent<PhotoCryptoResponse>) => {
      this.handleWorkerMessage(slot, e.data);
    };

    // 错误处理：Worker 崩溃
    worker.onerror = (e: ErrorEvent) => {
      log.error(`Worker[${slotIndex}] 崩溃 (onerror):`, e.message ?? e);
      this.handleWorkerCrash(slot, e.message ?? "onerror");
    };

    // messageerror：反序列化失败（数据损坏）
    worker.onmessageerror = () => {
      log.error(`Worker[${slotIndex}] messageerror（消息反序列化失败）`);
      this.handleWorkerCrash(slot, "messageerror");
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
      // 协议级异常：Worker 回显的 ID 与在途任务不符，该槽位后续响应同样
      // 无法关联到任务。按崩溃路径收敛（终止并重建槽位 + 任务重投或判毒丸）：
      // 若仅忽略本条消息，任务会悬挂至看门狗超时（预算下限 30s），期间槽位
      // 被幽灵任务占用，导入进行中界面无法关闭。
      const reason = `任务 ID 不匹配: expected=${task.id}, got=${response.id}`;
      log.error(`${reason}，按崩溃路径收敛`);
      this.handleWorkerCrash(slot, reason);
      return;
    }

    // 记录本次投递实际耗时，驱动超时预算估算
    this.timeoutEstimator.record(performance.now() - task.submittedAt);

    // 清空当前任务（释放 Worker）
    slot.currentTask = null;
    this.pendingCount--;

    if (response.ok) {
      // 成功完成：连续失败计数清零（槽位健康状况恢复）
      slot.consecutiveCrashes = 0;
      task.resolve(response);
    } else {
      const failure = response as PhotoCryptoFailure;
      // 解密任务的明确拒绝是确定性失败（数据损坏/标签校验不过），与池故障
      // （崩溃/超时/终止）区分：调用方据此决定是否回退主线程重算，避免对
      // 确定性失败重复付出派生成本；加密任务保持既有错误语义不变。
      task.reject(
        task.kind === "decrypt"
          ? new TaskRejectedError(task.id, failure.error || `解密失败: ${failure.name}`)
          : new Error(failure.error || `加密失败: ${failure.name}`),
      );
    }

    // 通知背压等待者（pending 减少，可能释放配额）
    this.notifyDrainWaiters();

    // 分配下一个任务给该空闲 Worker
    this.dispatchNextTask();

    // 队列排空 → 调度空闲回收检查
    this.scheduleIdleRecycle();
  }

  /** 处理 Worker 崩溃：在途任务重投或判毒丸，槽位重建 */
  private handleWorkerCrash(slot: WorkerSlot, reason: string): void {
    if (slot.terminated) return;

    const task = slot.currentTask;
    slot.currentTask = null;

    if (task) {
      if (task.payload.attempts >= MAX_TASK_ATTEMPTS) {
        // 达到最大尝试次数：该任务判定毒丸，拒绝并释放
        this.poisonPills++;
        log.error(`任务 ${task.id} 判定毒丸（原因: ${reason}），拒绝`);
        task.reject(new PoisonPillError(task.id, reason));
        this.pendingCount--;
        this.notifyDrainWaiters();
      } else {
        // 任务可重放：回到队头优先重投（源副本未被动过）
        this.taskQueue.unshift(task);
      }
    }

    this.restartSlot(slot);
  }

  /** 看门狗扫描：将超预算的在途任务转超时处理 */
  private sweepTimeouts(): void {
    const now = performance.now();
    for (const slot of this.slots) {
      const task = slot.currentTask;
      if (task && now - task.submittedAt > task.timeoutBudgetMs) {
        this.onTaskTimeout(slot, task);
      }
    }
  }

  /** 处理任务超时：终止挂起 Worker，重投或判失败，槽位重建 */
  onTaskTimeout(slot: WorkerSlot, task: PendingTask): void {
    this.timeouts++;
    log.warn(
      `Worker[${slot.index}] 任务 ${task.id} 超时（预算 ${task.timeoutBudgetMs}ms），终止挂起 Worker`,
    );

    // 挂起 Worker 无法继续产出：终止（terminate 不触发 onerror 级联崩溃计数）
    try {
      slot.worker.terminate();
    } catch {
      // 终止失败忽略：重建时旧引用随 GC 释放
    }
    slot.currentTask = null;

    if (task.payload.attempts < MAX_TASK_ATTEMPTS) {
      this.taskQueue.unshift(task);
    } else {
      task.reject(new TaskTimeoutError(task.id, task.timeoutBudgetMs));
      this.pendingCount--;
      this.notifyDrainWaiters();
    }

    this.restartSlot(slot);
  }

  /** 槽位重建：连续失败计数推进，超限则槽位永久失效 */
  private restartSlot(slot: WorkerSlot): void {
    if (slot.terminated) return;

    slot.consecutiveCrashes++;
    slot.totalCrashes++;
    log.warn(
      `Worker[${slot.index}] 连续失败 ${slot.consecutiveCrashes}/${MAX_CONSECUTIVE_SLOT_CRASHES} ` +
        `(累计 ${slot.totalCrashes})`,
    );

    if (slot.consecutiveCrashes > MAX_CONSECUTIVE_SLOT_CRASHES) {
      log.error(`Worker[${slot.index}] 连续失败超限，槽位永久失效`);
      slot.terminated = true;
      this.slotExhausted++;
      try {
        slot.worker.terminate();
      } catch {
        // 终止失败忽略
      }
      this.onSlotPermanentlyFailed(slot);
      return;
    }

    // 重建前回收旧 Worker：崩溃/超时/协议错配后旧实例状态不可信，且槽位
    // 对象会被新实例替换出 slots 数组——若不显式终止，旧 Worker 线程随引用
    // 丢失而泄漏（每次故障泄漏一个常驻线程）。terminate 幂等，超时路径已
    // 先行终止时重复调用无害。
    try {
      slot.worker.terminate();
    } catch {
      // 终止失败忽略：旧实例随引用释放由 GC 回收
    }

    // 重建新 Worker（保留连续失败计数与观测计数）
    const newSlot = this.createWorkerSlot(slot.index);
    newSlot.consecutiveCrashes = slot.consecutiveCrashes;
    newSlot.totalCrashes = slot.totalCrashes;
    const slotIdx = this.slots.indexOf(slot);
    if (slotIdx >= 0) {
      this.slots[slotIdx] = newSlot;
    } else {
      this.slots.push(newSlot);
    }

    // 新 Worker 就绪后继续投递（可能重投刚回队的任务）
    this.dispatchNextTask();
  }

  /** 槽位永久失效后的池级自愈：全部槽位失效即重建并以新 Worker 继续服务在队任务 */
  private onSlotPermanentlyFailed(_slot: WorkerSlot): void {
    if (this.slots.length > 0 && this.slots.every((s) => s.terminated)) {
      // 全部槽位永久失效：在位任务已由崩溃路径逐任务收敛（重投或判毒丸）。
      // 此处必须立即自愈并继续调度——在队任务若无人触发调度将永久悬挂；
      // 历史实现改为 drainAll 拒绝全部任务并把池钉死为永久失效，使一次
      // 崩溃风暴后「导入照片」在本次会话内彻底不可用（须重启应用）。
      log.warn("全部槽位永久失效，触发池自愈重建");
      this.reviveExhaustedPool();
      this.dispatchNextTask();
    }
  }

  /** 池是否已耗尽（存在槽位且全部永久失效） */
  private isPoolExhausted(): boolean {
    return this.slots.length > 0 && this.slots.every((s) => s.terminated);
  }

  /**
   * 池自愈：废弃全部永久失效槽位（下次调度按需冷启动全新 Worker）。
   *
   * 仅在「全部槽位永久失效」时生效；新 Worker 为全新实例（无残留上下文），
   * 任务级尝试上限（MAX_TASK_ATTEMPTS）与毒丸判定仍然生效，故自愈不会
   * 引入无限重试：单任务最多尝试固定次数后必被拒绝。
   *
   * @returns 是否执行了自愈重建
   */
  private reviveExhaustedPool(): boolean {
    if (!this.isPoolExhausted()) return false;
    for (const slot of this.slots) {
      try {
        slot.worker.terminate();
      } catch {
        // 终止失败忽略：实例随引用释放回收
      }
    }
    this.slots.length = 0;
    this.poolRevivals++;
    log.warn(
      `池自愈重建：废弃 ${this.slotExhausted} 个失效槽位，冷启动新 Worker 继续服务`,
    );
    return true;
  }

  /** 分配下一个任务给空闲 Worker（无空闲且未达上限时按需冷启动） */
  private dispatchNextTask(): void {
    if (this.terminated) return;
    if (this.taskQueue.length > 0) {
      // 自愈优先于兜底：全部槽位永久失效时废弃旧槽位并冷启动新 Worker，
      // 在队任务继续被服务（杜绝「一次崩溃风暴后导入功能永久不可用」）
      this.reviveExhaustedPool();
    }
    if (this.taskQueue.length === 0) return;

    // 查找空闲 Worker
    let idleSlot = this.slots.find((s) => !s.terminated && !s.currentTask);

    // 按需创建：无空闲且未达池上限 → 冷启动新 Worker
    if (!idleSlot && this.slots.length < this.poolSize) {
      idleSlot = this.createWorkerSlot(this.slots.length);
      this.slots.push(idleSlot);
      log.info(`按需冷启动 Worker[${this.slots.length - 1}]（active=${this.slots.length}/${this.poolSize}）`);
    }
    if (!idleSlot) return;

    const task = this.taskQueue.shift();
    if (!task) return;

    // 本次投递计时与预算（重投时刷新）
    task.submittedAt = performance.now();
    task.timeoutBudgetMs = this.timeoutEstimator.budget();
    this.watchdog.start();
    idleSlot.currentTask = task;
    this.markBusy();

    // 无文件字节分支的最终请求体：DataCloneError 自愈重投时复用
    // （attachClear 已消费的 clearCache 语义与任务 id 都保留其中）
    let plainRetryBody: object | null = null;

    try {
      // 派生缓存清理标记：模块密钥失效后，为每个 Worker 的首次投递附加
      // "先清空按盐派生缓存"指令（避免失效密钥的派生结果继续驻留工作线程）
      const attachClear = <T extends object>(body: T): T => {
        if (!idleSlot.keyCacheClearPending) return body;
        idleSlot.keyCacheClearPending = false;
        return { ...body, clearCache: true };
      };

      if (task.payload.source) {
        // 完整加密：从源副本生成全新可转移副本（每次投递零共享）
        const transfer = task.payload.source.slice().buffer;
        const req: PhotoCryptoRequest = {
          ...attachClear(task.request as PhotoCryptoRequestBody),
          id: task.id,
          fileBytes: transfer,
        };
        idleSlot.worker.postMessage(req, [transfer]);
      } else {
        // 无文件字节的任务（meta-only 加密 / 解密）：结构化克隆
        // （不转移所有权，天然可重放）
        const req = {
          ...attachClear(task.request as
            | PhotoMetaCryptoRequestBody
            | PhotoDecryptMetaRequestBody
            | PhotoDecryptChunksRequestBody),
          id: task.id,
        };
        plainRetryBody = req;
        idleSlot.worker.postMessage(req);
      }
      task.payload.attempts++;
    } catch (e) {
      // 结构化克隆失败自愈（纵深防御，零正常路径成本）：
      //   载荷含不可克隆值（典型：Vue 响应式 Proxy 经未净化链路穿透进
      //   meta 字段）时 postMessage 抛 DataCloneError。这是任务级确定性
      //   缺陷而非 Worker 故障：原地净化为纯数据（JSON 往返）后重投一次，
      //   不消耗槽位崩溃计数（槽位健康无涉）与毒丸预算（属同一次投递的
      //   修复而非重试，attempts 不自增）；净化后仍失败才按既有路径 settle。
      if (plainRetryBody && isDataCloneError(e)) {
        try {
          idleSlot.worker.postMessage(
            JSON.parse(JSON.stringify(plainRetryBody)) as object,
          );
          log.warn(`任务 ${task.id} 载荷含不可克隆值，已脱代理净化并重投`);
          return;
        } catch (retryErr) {
          log.error(`任务 ${task.id} 净化重投仍失败:`, retryErr);
        }
      }
      // postMessage 同步失败（Worker 已终止或序列化异常）：
      // 不自动重试（终止竞态下重试大概率再失败），按失败 settle
      log.error(`任务 ${task.id} postMessage 失败:`, e);
      idleSlot.currentTask = null;
      this.pendingCount--;
      task.reject(new Error(`Worker 通信失败: ${e instanceof Error ? e.message : String(e)}`));
      this.notifyDrainWaiters();
      // 继续投递队列中的下一个任务
      this.dispatchNextTask();
    }
  }

  /** 拒绝全部在队与在途任务（池耗尽/终止的最终收敛路径） */
  drainAll(reason: Error): void {
    this.watchdog.stop();
    for (const task of this.taskQueue) {
      task.reject(reason);
    }
    this.taskQueue.length = 0;
    for (const slot of this.slots) {
      if (slot.currentTask) {
        slot.currentTask.reject(reason);
        slot.currentTask = null;
      }
    }
    this.pendingCount = 0;
    // 唤醒背压等待者：submit 在 waitForDrain 后会检查 terminated 状态并拒绝
    this.notifyDrainWaiters();
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
    this.idleRecycleTimer = setTimeout(() => {
      this.idleRecycleTimer = null;
      this.recycleIdleWorkers();
    }, wait);
  }

  /** 空闲回收：全部 Worker 空闲且超阈值 → 回收一半（下次任务冷启动） */
  private recycleIdleWorkers(): void {
    if (this.terminated) return;
    const allIdle = this.taskQueue.length === 0 && this.slots.every((s) => !s.currentTask);
    if (!allIdle) return;

    const keep = Math.max(1, Math.ceil(this.slots.length / 2));
    const toRemove = this.slots.length - keep;
    if (toRemove <= 0) return;

    log.info(`空闲回收: terminate ${toRemove} 个 Worker（保留 ${keep}）`);
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

  /**
   * 等待背压释放（读取闸门）。
   *
   * 在途任务数低于阈值时立即 resolve；否则等待既有任务 settle 后唤醒。
   * 调用方（导入生产者）据此在读取下一个文件前等待配额，避免把全部源
   * 文件字节一次性读入内存（读取后即被在途任务引用，直到 settle 才释放）。
   *
   * 保证：pending 每次减少都会唤醒等待者；池终止或耗尽时 drainAll 亦唤醒
   * （调用方在唤醒后经 submit 重新检查终止/耗尽状态并得到明确错误）。
   */
  async waitForCapacity(): Promise<void> {
    if (this.pendingCount < this.maxPendingTasks) {
      return;
    }
    return new Promise<void>((resolve) => {
      this.drainWaiters.push(resolve);
    });
  }

  /**
   * 提交前置流程（全部提交入口共用）：终止检查 → 池自愈 → 背压等待 → 二次终止检查。
   *
   * 池自愈：全部槽位永久失效时废弃旧槽位（下次调度冷启动新 Worker）。历史实现
   * 在提交时直接抛 PoolExhaustedError，使一次崩溃风暴后导入功能在本次会话内
   * 永久不可用；自愈后新 Worker 为全新实例，任务级尝试上限仍然生效，不引入
   * 无限重试。二次终止检查收敛"等待背压期间池被终止"的竞态。
   */
  private async awaitAdmission(): Promise<void> {
    if (this.terminated) {
      throw new PoolTerminatedError();
    }
    this.reviveExhaustedPool();
    await this.waitForCapacity();
    if (this.terminated) {
      throw new PoolTerminatedError();
    }
  }

  /**
   * 任务入队（全部提交入口共用）：装配任务对象并交由调度。
   *
   * @param request 请求体（不含 id，由池分配；op 已由提交入口按操作类型补齐）
   * @param source 源字节权威副本（无文件字节的任务传 null，走结构化克隆）
   * @param kind 任务类别（决定 Worker 明确拒绝时的错误类别）
   * @param priority true 时插入队首：读取链路的解密任务载荷小、耗时短，若按
   *   FIFO 排在已排队的导入任务之后，用户交互（滚动、点击查看）要等整批
   *   导入完成才被服务
   */
  private enqueueTask(
    request: PendingTask["request"],
    source: Uint8Array | null,
    kind: TaskKind,
    priority: boolean,
  ): Promise<PhotoTaskSuccess> {
    return new Promise<PhotoTaskSuccess>((resolve, reject) => {
      const task: PendingTask = {
        id: this.nextTaskId++,
        request,
        payload: { source, attempts: 0 },
        resolve,
        reject,
        submittedAt: 0,
        timeoutBudgetMs: this.timeoutEstimator.budget(),
        kind,
      };

      if (priority) {
        this.taskQueue.unshift(task);
      } else {
        this.taskQueue.push(task);
      }
      this.pendingCount++;
      this.dispatchNextTask();
    });
  }

  /**
   * 提交完整加密任务到 Worker 池
   *
   * 提交时拷贝文件字节为源权威副本，任务因此恒可重放：Worker 崩溃或
   * 超时后由池自动重投，调用方无需感知。背压：pending 达阈值时等待
   * drain。任务以毒丸失败、池耗尽或池终止时以明确错误拒绝，绝不悬挂。
   *
   * @param input 提交输入（fileBytes 与请求体分离）
   * @returns 加密成功响应（含 hash / thumbB64 / metaB64）
   */
  async submit(input: SubmitInput): Promise<PhotoCryptoSuccess> {
    await this.awaitAdmission();

    // 源权威副本：任务 settle 前由 task.payload 持有
    const source = input.fileBytes.slice();

    return (await this.enqueueTask(
      input.request,
      source,
      "encrypt",
      false,
    )) as PhotoCryptoSuccess;
  }

  /**
   * 批量提交并收集所有结果（保持输入顺序）
   *
   * 内部并行调度到 Worker 池，结果按输入顺序排列，失败项被过滤并通过
   * onFailure 回调通知。
   */
  async submitBatch(
    inputs: SubmitInput[],
    onFailure?: (input: SubmitInput, error: Error) => void,
  ): Promise<PhotoCryptoSuccess[]> {
    const promises = inputs.map((input) =>
      this.submit(input).catch((err: Error) => {
        onFailure?.(input, err);
        return null;
      }),
    );
    const results = await Promise.all(promises);
    return results.filter((r): r is PhotoCryptoSuccess => r !== null);
  }

  /**
   * 提交 meta-only 加密任务到 Worker 池（解析导入路径）
   *
   * 与 submit() 共享队列、背压、崩溃恢复与看门狗。请求经结构化克隆
   * 传输（无 fileBytes、无转移所有权），天然可重放。
   *
   * @param request meta-only 加密请求体（不含 id）
   * @returns meta-only 加密成功响应
   */
  async submitMetaOnly(
    request: PhotoMetaCryptoRequestBody,
  ): Promise<PhotoMetaCryptoSuccess> {
    await this.awaitAdmission();
    return (await this.enqueueTask(
      request,
      null,
      "encrypt",
      false,
    )) as PhotoMetaCryptoSuccess;
  }

  /**
   * 提交索引瘦身布局的缩略图记录加密任务（导入链路）
   *
   * 与 meta-only 加密同一语义：结构化克隆（密文/明文均为字符串，天然可重放），
   * 与索引加密任务共用同一文件盐——池按任务轮转时派生缓存按"口令指纹 + 盐"
   * 命中，故缩略图加密不额外产生 PBKDF2。
   *
   * @param request 请求体（thumbB64 / fileSaltB64 / fileHashHex / photoKey / label）
   * @returns 缩略图密文与其 BLAKE3 hex
   */
  async submitEncryptSlimThumb(
    request: Omit<PhotoSlimThumbRequest, "id" | "op">,
  ): Promise<PhotoSlimThumbSuccess> {
    await this.awaitAdmission();
    const full: PhotoSlimThumbRequestBody = { ...request, op: "encrypt_slim_thumb" };
    return (await this.enqueueTask(
      full,
      null,
      "encrypt",
      false,
    )) as PhotoSlimThumbSuccess;
  }

  /**
   * 提交重打包加密任务（既有布局 → 索引瘦身布局）
   *
   * 与 submit() 共享队列、背压、崩溃重投与看门狗：源字节由池保留权威副本，
   * 任务恒可重放；产物形状与常规导入一致，主线程复用同一写入链路。
   *
   * @param input 提交输入（fileBytes 与请求体分离）
   * @returns 加密成功响应（含 external 外置块与元数据模板）
   */
  async submitSlimRepack(input: {
    fileBytes: Uint8Array;
    request: Omit<PhotoSlimRepackRequest, "id" | "op" | "fileBytes">;
  }): Promise<PhotoCryptoSuccess> {
    await this.awaitAdmission();
    const source = input.fileBytes.slice();
    return (await this.enqueueTask(
      { ...input.request, op: "encrypt_slim_photo" },
      source,
      "encrypt",
      false,
    )) as PhotoCryptoSuccess;
  }

  /**
   * 提交索引瘦身布局的块集记录加密任务（导入 / 重打包链路）
   *
   * 与索引加密任务共用同一文件盐，派生缓存按盐命中时不额外产生 PBKDF2。
   *
   * @param request 请求体（set / fileSaltB64 / fileHashHex / photoKey / label）
   * @returns 块集密文与其 BLAKE3 hex
   */
  async submitEncryptSlimSet(
    request: Omit<PhotoSlimSetRequest, "id" | "op">,
  ): Promise<PhotoSlimSetSuccess> {
    await this.awaitAdmission();
    const full: PhotoSlimSetRequestBody = { ...request, op: "encrypt_slim_set" };
    return (await this.enqueueTask(
      full,
      null,
      "encrypt",
      false,
    )) as PhotoSlimSetSuccess;
  }

  /**
   * 提交索引瘦身布局的块集记录解密任务（查看原图 / 导出 / 删除级联补取）
   *
   * @param request 请求体（setCipherB64 / wrappedFileKey / fileHashHex / photoKey / label）
   * @returns 解密后的块集内容（逐块 ID 与哈希，按序一一对应）
   */
  async submitDecryptSlimSet(
    request: Omit<PhotoDecryptSlimSetRequest, "id" | "op">,
  ): Promise<PhotoDecryptSlimSetSuccess> {
    await this.awaitAdmission();
    const full: PhotoDecryptSlimSetRequestBody = { ...request, op: "decrypt_slim_set" };
    return (await this.enqueueTask(
      full,
      null,
      "decrypt",
      true,
    )) as PhotoDecryptSlimSetSuccess;
  }

  /**
   * 标记全部 Worker 清空按盐派生缓存（模块密钥失效/登出时调用）。
   *
   * 语义：各 Worker 在收到下一个任务时先清空缓存再执行（避免失效密钥的
   * 派生结果继续驻留工作线程内存）。新建 Worker 默认带标记，启动即干净。
   */
  invalidateDerivedKeys(): void {
    for (const slot of this.slots) {
      slot.keyCacheClearPending = true;
    }
  }

  /**
   * 提交元数据解密任务到 Worker 池（读取链路：列表按需解密、查看原图回填）
   *
   * 与加密任务共享队列、背压、崩溃恢复与看门狗；请求体为密文 base64 字符串
   * （结构化克隆，无转移所有权），任务恒可重放。任务插入队首优先服务用户
   * 交互。Worker 明确拒绝以 TaskRejectedError 抛出：属确定性失败（数据损坏 /
   * 标签校验不过），调用方不应回退主线程重算。
   *
   * @param request 解密请求体（metaB64 / photoKey / label，不含 id 与 op）
   * @returns 解密成功响应（meta 为解密后的元数据）
   */
  async submitDecryptMeta(
    request: Omit<PhotoDecryptMetaRequest, "id" | "op">,
  ): Promise<PhotoDecryptMetaSuccess> {
    await this.awaitAdmission();
    const full: PhotoDecryptMetaRequestBody = { ...request, op: "decrypt_meta" };
    return (await this.enqueueTask(
      full,
      null,
      "decrypt",
      true,
    )) as PhotoDecryptMetaSuccess;
  }

  /**
   * 提交索引瘦身布局的缩略图记录解密任务（列表路径的补取）。
   *
   * 语义同 submitDecryptMeta：缩略图明文由 Worker 侧 transferList 零拷贝回传；
   * 与元数据共用同一文件盐，若由同一 Worker 服务则派生缓存命中（零 PBKDF2）。
   *
   * @param request 请求体（thumbCipherB64 / wrappedFileKey / fileHashHex / photoKey / label）
   * @returns 缩略图原始字节
   */
  async submitDecryptThumb(
    request: Omit<PhotoDecryptThumbRequest, "id" | "op">,
  ): Promise<PhotoDecryptThumbSuccess> {
    await this.awaitAdmission();
    const full: PhotoDecryptThumbRequestBody = { ...request, op: "decrypt_thumb" };
    return (await this.enqueueTask(
      full,
      null,
      "decrypt",
      true,
    )) as PhotoDecryptThumbSuccess;
  }

  /**
   * 提交数据块解密任务到 Worker 池（查看原图）
   *
   * 语义同 submitDecryptMeta：明文由 Worker 侧 transferList 零拷贝回传，
   * 池内不驻留明文；任一块解密失败即整体失败（拒绝产出残缺序列）。
   *
   * @param request 解密请求体（chunksB64 / photoKey / fileHashHex / label，不含 id 与 op）
   * @returns 解密成功响应（plaintexts 与输入块顺序一致）
   */
  async submitDecryptChunks(
    request: Omit<PhotoDecryptChunksRequest, "id" | "op">,
  ): Promise<PhotoDecryptChunksSuccess> {
    await this.awaitAdmission();
    const full: PhotoDecryptChunksRequestBody = { ...request, op: "decrypt_chunks" };
    return (await this.enqueueTask(
      full,
      null,
      "decrypt",
      true,
    )) as PhotoDecryptChunksSuccess;
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
    totalCrashes: number;
    poisonPills: number;
    timeouts: number;
    slotExhausted: number;
    poolRevivals: number;
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
      totalCrashes: this.slots.reduce((sum, s) => sum + s.totalCrashes, 0),
      poisonPills: this.poisonPills,
      timeouts: this.timeouts,
      slotExhausted: this.slotExhausted,
      poolRevivals: this.poolRevivals,
    };
  }

  /**
   * 终止池：拒绝所有在队/在途任务并销毁全部 Worker。
   *
   * 终止为不可逆操作（单例语义）：终止后再提交一律拒绝。
   * 在途 submit 的 Promise 以 PoolTerminatedError 有限时间 settle。
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

    // 拒绝在队与在途任务、唤醒背压等待者、停止看门狗
    this.drainAll(new PoolTerminatedError());

    // 销毁所有 Worker
    for (const slot of this.slots) {
      slot.terminated = true;
      try {
        slot.worker.terminate();
      } catch {
        // 终止失败忽略
      }
    }
    this.slots.length = 0;
  }
}

/** 导出单例便捷方法 */
export const photoWorkerPool = PhotoWorkerPool.getInstance();