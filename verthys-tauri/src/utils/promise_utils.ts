/*
 * utils/promise_utils.ts — Promise 工具函数
 *
 * 分级超时熔断（软 15s 提示 / 硬 35s 降级 / 连续 3 次熔断锁定）
 *
 *   withGradedTimeout 替代原固定 35s 单一超时阈值：
 *     - 软超时（softMs）：触发 onSoftTimeout 回调（前端提示用户耐心等待），
 *       但 Promise 继续等待，不拒绝。区分「Argon2id 计算缓慢（可容忍）」与
 *       「磁盘 IO 卡死（需熔断）」。
 *     - 硬超时（hardMs）：Promise 拒绝，触发降级校验路径。
 *     - 熔断保护：连续 3 次硬超时自动锁定容器 30 分钟，引导用户使用备份密钥恢复。
 *       熔断状态持久化于 localStorage，跨进程重启仍生效。
 *
 * Comprehensive_optimization：yieldToMain — 主线程让出（浏览器等价 setImmediate）
 *
 *   在数据处理循环中，每处理完一批数据后调用 yieldToMain()，让出主线程，
 *   保证 requestAnimationFrame 回调能得到执行机会，避免 UI 冻结。
 *   使用 MessageChannel（浏览器中最快的宏任务调度，比 setTimeout(0) 快 ~4ms）。
 */
import {
  CIRCUIT_BREAKER_THRESHOLD,
  CIRCUIT_BREAKER_LOCK_MS,
  CIRCUIT_BREAKER_STORAGE_KEY,
} from "../constants/key_manager_const";

/* ------------------------------------------------------------------ *
 * Comprehensive_optimization：yieldToMain — 主线程让出              *
 * ------------------------------------------------------------------ *
 *
 * 浏览器中等价 Node.js 的 setImmediate：将控制权交还给事件循环，
 * 让 requestAnimationFrame / UI 渲染 / 用户输入等宏任务得以执行。
 *
 * 实现选型：
 *   - MessageChannel：浏览器中最快的宏任务调度（无 4ms 最小钳制），
 *     Vue 3 的 nextTick 在不支持 Promise 时也使用此做法。
 *   - setTimeout(0)：备选，但嵌套调用后有 ~4ms 最小钳制（HTML5 规范）。
 *   - queueMicrotask：不适用——微任务在下一个宏任务前全部执行完，
 *     不会让出给 rAF / UI 渲染。
 *
 * 使用场景：
 *   - 照片导入流水线：每批文件处理完后 yield，保证进度条 rAF 回调执行
 *   - .venc 解析：每张照片解密完后 yield，保证解析进度条实时刷新
 *   - 任何长循环中需要让出主线程的场景
 * ------------------------------------------------------------------ */

/** 复用的 MessageChannel（避免每次创建新实例的开销） */
let _yieldChannel: MessageChannel | null = null;
/** 当前等待中的 resolve 函数（同一时刻仅允许一个 yieldToMain 等待） */
let _yieldResolve: (() => void) | null = null;

/** 初始化复用的 MessageChannel（惰性创建） */
function getYieldChannel(): MessageChannel {
  if (!_yieldChannel) {
    _yieldChannel = new MessageChannel();
    _yieldChannel.port1.onmessage = () => {
      const resolve = _yieldResolve;
      _yieldResolve = null;
      if (resolve) resolve();
    };
  }
  return _yieldChannel;
}

/**
 * 让出主线程：将控制权交还给事件循环，保证 rAF / UI 渲染得以执行。
 *
 * 浏览器等价 Node.js 的 setImmediate，使用 MessageChannel 实现
 * （比 setTimeout(0) 快，无 4ms 最小钳制）。
 *
 * 在数据处理循环中每批处理后调用，避免长任务卡顿。
 *
 * @returns Promise，在下一个宏任务周期 resolve
 */
export function yieldToMain(): Promise<void> {
  // 如果已有 yield 在等待，使用 setTimeout(0) 避免冲突
  if (_yieldResolve !== null) {
    return new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  return new Promise<void>((resolve) => {
    _yieldResolve = resolve;
    const channel = getYieldChannel();
    channel.port2.postMessage(null);
  });
}

/**
 * 带超时的 Promise 包装
 * 超时后抛出固定错误，前端可捕获并回滚
 */
export function withTimeout<T>(promise: Promise<T>, ms: number, label = "操作"): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${label} 超时（${ms / 1000}s）`));
    }, ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

/* ------------------------------------------------------------------ *
 * 熔断器状态管理                                                      *
 *                                                                    *
 * 状态结构（JSON 持久化于 localStorage）：                            *
 *   {                                                                 *
 *     consecutiveHardTimeouts: number,  // 连续硬超时次数             *
 *     lockedUntil: number | null       // 熔断锁定到期时间戳（ms）    *
 *   }                                                                 *
 *                                                                    *
 * 熔断逻辑：                                                          *
 *   - 每次 hardMs 超时：consecutiveHardTimeouts++                     *
 *   - 达到 CIRCUIT_BREAKER_THRESHOLD：设置 lockedUntil = now + LOCK_MS *
 *   - 解锁成功：consecutiveHardTimeouts 重置为 0                      *
 *   - 调用前检查 lockedUntil：未到期则直接拒绝（熔断打开）             *
 * ------------------------------------------------------------------ */

interface CircuitBreakerState {
  consecutiveHardTimeouts: number;
  lockedUntil: number | null;
}

function loadCircuitBreakerState(): CircuitBreakerState {
  try {
    const raw = localStorage.getItem(CIRCUIT_BREAKER_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as CircuitBreakerState;
      if (typeof parsed.consecutiveHardTimeouts === "number") {
        return {
          consecutiveHardTimeouts: parsed.consecutiveHardTimeouts,
          lockedUntil: typeof parsed.lockedUntil === "number" ? parsed.lockedUntil : null,
        };
      }
    }
  } catch {
    /* localStorage 不可用或数据损坏：视为无熔断状态 */
  }
  return { consecutiveHardTimeouts: 0, lockedUntil: null };
}

function saveCircuitBreakerState(state: CircuitBreakerState): void {
  try {
    localStorage.setItem(CIRCUIT_BREAKER_STORAGE_KEY, JSON.stringify(state));
  } catch {
    /* localStorage 不可用：熔断状态仅内存生效（降级，不阻断主流程） */
  }
}

/**
 * 检查熔断器是否处于打开状态（锁定期内拒绝所有解锁请求）
 *
 * @returns 若处于熔断锁定状态，返回剩余锁定毫秒数；否则返回 0
 */
export function checkCircuitBreaker(): number {
  const state = loadCircuitBreakerState();
  if (state.lockedUntil !== null) {
    const now = Date.now();
    if (now < state.lockedUntil) {
      return state.lockedUntil - now;
    }
    /* 锁定期已过：自动清除熔断状态，允许重试 */
    if (state.consecutiveHardTimeouts >= CIRCUIT_BREAKER_THRESHOLD) {
      saveCircuitBreakerState({ consecutiveHardTimeouts: 0, lockedUntil: null });
    }
  }
  return 0;
}

/**
 * 解锁成功时重置熔断器（清除连续硬超时计数）
 *
 * 必须在 verthysUnlock 成功返回后调用，确保正常解锁后熔断状态清零。
 */
export function resetCircuitBreaker(): void {
  saveCircuitBreakerState({ consecutiveHardTimeouts: 0, lockedUntil: null });
}

/**
 * 分级超时 Promise 包装（软/硬双级超时 + 熔断核心）
 *
 * @param promise       被包装的 Promise（如 verthysUnlock）
 * @param softMs        软超时阈值（ms），触发 onSoftTimeout 但不拒绝
 * @param hardMs        硬超时阈值（ms），超过则拒绝 Promise
 * @param label         操作标签（用于错误信息）
 * @param onSoftTimeout 软超时回调（前端展示「密钥计算较慢，请耐心等待」提示）
 *
 * 硬超时触发熔断计数：连续 CIRCUIT_BREAKER_THRESHOLD 次后自动锁定容器。
 *
 * @throws Error 硬超时或熔断打开时抛出
 */
export function withGradedTimeout<T>(
  promise: Promise<T>,
  softMs: number,
  hardMs: number,
  label: string,
  onSoftTimeout?: () => void,
): Promise<T> {
  /* 熔断前置检查：若处于熔断锁定状态，直接拒绝，不启动 Promise */
  const remainingLock = checkCircuitBreaker();
  if (remainingLock > 0) {
    const minutes = Math.ceil(remainingLock / 60000);
    return Promise.reject(
      new Error(`连续解锁超时已触发熔断保护，容器已临时锁定 ${minutes} 分钟。请稍后重试或使用备份密钥恢复。`),
    );
  }

  return new Promise<T>((resolve, reject) => {
    let softTimerFired = false;

    /* 软超时定时器：触发 onSoftTimeout 回调，但 Promise 继续等待 */
    const softTimer = setTimeout(() => {
      softTimerFired = true;
      if (onSoftTimeout) {
        try {
          onSoftTimeout();
        } catch {
          /* 回调异常不影响主流程 */
        }
      }
    }, softMs);

    /* 硬超时定时器：拒绝 Promise，递增熔断计数 */
    const hardTimer = setTimeout(() => {
      clearTimeout(softTimer);
      /* 熔断计数：连续硬超时达到阈值则锁定容器 */
      const state = loadCircuitBreakerState();
      state.consecutiveHardTimeouts += 1;
      if (state.consecutiveHardTimeouts >= CIRCUIT_BREAKER_THRESHOLD) {
        state.lockedUntil = Date.now() + CIRCUIT_BREAKER_LOCK_MS;
        saveCircuitBreakerState(state);
        reject(
          new Error(
            `${label} 硬超时（${hardMs / 1000}s），连续 ${state.consecutiveHardTimeouts} 次超时已触发熔断保护，` +
            `容器已临时锁定 ${CIRCUIT_BREAKER_LOCK_MS / 60000} 分钟。请使用备份密钥恢复或稍后重试。`,
          ),
        );
      } else {
        saveCircuitBreakerState(state);
        reject(new Error(`${label} 硬超时（${hardMs / 1000}s），已触发降级校验。连续超时 ${state.consecutiveHardTimeouts}/${CIRCUIT_BREAKER_THRESHOLD} 次后将熔断锁定。`));
      }
    }, hardMs);

    promise.then(
      (v) => {
        clearTimeout(softTimer);
        clearTimeout(hardTimer);
        /* 解锁成功：重置熔断计数（softTimerFired 不影响重置） */
        resetCircuitBreaker();
        resolve(v);
      },
      (e) => {
        clearTimeout(softTimer);
        clearTimeout(hardTimer);
        /* Promise 被拒绝（非超时原因，如密码错误）：不递增熔断计数，
         * 但也不重置（保留历史超时计数，仅成功才清零） */
        reject(e);
      },
    );
  });
}
