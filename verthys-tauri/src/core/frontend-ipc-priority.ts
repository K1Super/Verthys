/*
 * core/frontend-ipc-priority.ts — 前端 IPC 优先级门控
 *
 * 模块加载性能根治设计：消除 worker 单线程串行 FIFO 队头阻塞
 *
 * 问题根因：
 *   worker 是单例常驻进程，Actor 单消费者 + mpsc FIFO 队列（容量 32），无优先级、无抢占。
 *   后台任务（ensureRecordScan / prefetchFullRecords / integrityPatrol）
 *   的 IPC 请求与前端模块加载请求（getRecordsDataB64Batch → verthysGetRecord）
 *   共用同一 worker 通道。后台任务独占 worker 时前端请求排队等待 → 30s 卡顿。
 *
 * 处理方式：
 *   1. markFrontendIpcActive()：前端关键 IPC 调用入口处标记「前端活跃」时间戳
 *   2. isFrontendIpcBusy()：检查距上次前端活跃是否在防抖窗口内（800ms）
 *   3. yieldIfFrontendBusy()：后台任务在每个 IPC 调用前调用，
 *      若前端活跃则 await setTimeout(200ms) 让出 worker 通道，
 *      直到前端空闲（防抖窗口外）才继续执行
 *
 * 时序保证：
 *   - 前端模块加载（getRecordsDataB64Batch / getFullRecord / ensureRecordScan /
 *     ensureSummaryScan）入口处调用 markFrontendIpcActive()
 *   - 后台任务（integrityPatrol / ensureRecordScan /
 *     prefetchFullRecords）在每个 IPC 调用前调用 yieldIfFrontendBusy()
 *   - 前端活跃时后台任务持续让出，前端请求获得 worker 通道优先权
 *   - 前端空闲后（800ms 无活动）后台任务自动恢复执行
 *
 * 安全边界：
 *   - 仅影响后台任务调度，不影响前端 IPC 逻辑
 *   - yieldIfFrontendBusy 最坏情况后台任务长时间等待，但前端空闲后自动恢复
 *   - integrityPatrol 仅巡检不阻塞业务
 */

/** 前端最后一次活跃的时间戳（ms） */
let lastFrontendActiveTime = 0;

/**
 * 前端活跃防抖窗口（ms）。
 *
 * 800ms 窗口覆盖：
 *   - 单次 verthysGetRecord IPC round-trip（通常 <100ms）
 *   - getRecordsDataB64Batch 并行 IPC（通常 <300ms）
 *   - ensureRecordScan 首批 IPC（通常 <500ms）
 *
 * 窗口过短（<500ms）：前端连续 IPC 间隙后台任务可能插入，仍造成队头阻塞。
 * 窗口过长（>2000ms）：后台任务延迟过大，巡检长时间不执行。
 * 800ms 平衡：覆盖前端连续请求 + 后台任务不过度延迟。
 */
const FRONTEND_BUSY_WINDOW_MS = 800;

/**
 * 后台任务让出时的轮询间隔（ms）。
 *
 * 200ms 轮询：
 *   - 足够细粒度：前端空闲后 200ms 内后台任务即可恢复
 *   - 不过度频繁：避免空转浪费 CPU（5 次/秒检查可接受）
 */
const YIELD_POLL_INTERVAL_MS = 200;

/**
 * 标记前端 IPC 活跃。
 *
 * 在前端关键 IPC 函数入口处调用：
 *   - verthys.ts: verthysGetRecord / verthysEnumerateRecords / verthysScanOpen / verthysScanSummaryOpen
 *   - verthys-cache.ts: getRecordsDataB64Batch / getFullRecord / ensureRecordScan / ensureSummaryScan
 *
 * 调用后，后续 800ms 内 isFrontendIpcBusy() 返回 true，
 * 后台任务调用 yieldIfFrontendBusy() 时会持续让出 worker 通道。
 */
export function markFrontendIpcActive(): void {
  lastFrontendActiveTime = Date.now();
}

/**
 * 检查前端 IPC 是否处于活跃状态（防抖窗口内）。
 *
 * @returns true 表示前端在 800ms 内有 IPC 活动，后台任务应让出
 */
export function isFrontendIpcBusy(): boolean {
  return Date.now() - lastFrontendActiveTime < FRONTEND_BUSY_WINDOW_MS;
}

/**
 * 后台任务让出 worker 通道（若前端活跃）。
 *
 * 在后台任务的每个 IPC 调用前调用：
 *   - integrityPatrol: 每个 verthysGetRecord 调用前
 *   - 任务一（ensureRecordScan）和任务二（prefetchFullRecords）启动前
 *
 * 行为：
 *   - 前端活跃 → 循环 await setTimeout(200ms) 让出，直到前端空闲
 *   - 前端空闲 → 立即返回（零开销）
 *
 * 修复：限制最大让出次数，防止 lockAll 期间无限让出
 *
 * 原缺陷：
 *   lockAll 期间前端持续 IPC（waitForFlush / verthysClearGlobalKey / verthysLockPersist 等），
 *   isFrontendIpcBusy() 持续返回 true，yieldIfFrontendBusy 无限循环让出。
 *   stopBackgroundTasks 的 3s 超时等不到任务退出，用户感知"停止后台任务时间过长"。
 *
 * 修复：
 *   限制最大让出次数（MAX_YIELD_ROUNDS=10，即最多让出 2s），
 *   超过限制后强制返回，调用方在 yield 后检查 cancelled 会立即退出。
 *
 * 注意：本函数不检查取消标志，调用方需自行在 yield 后检查 controller.cancelled。
 */
const MAX_YIELD_ROUNDS = 10;

export async function yieldIfFrontendBusy(): Promise<void> {
  let rounds = 0;
  while (isFrontendIpcBusy() && rounds < MAX_YIELD_ROUNDS) {
    rounds++;
    await new Promise<void>((resolve) => {
      setTimeout(resolve, YIELD_POLL_INTERVAL_MS);
    });
  }
}
