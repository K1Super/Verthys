/*
 * core/background-tasks.ts — 全局后台任务管理
 *
 * ★ 将 backgroundTasks 的启动/停止抽象到独立模块，
 *   供 global-verthys.ts 与 module-auth.ts 及未来组件共享使用。
 *
 * 核心改进（相对 verthys-cache.ts 旧实现）：
 *   1. stopBackgroundTasks 改为 async，await 所有任务实际终止后才返回，
 *      杜绝「重置后立即创建新会话，旧后台任务仍在运行访问已释放缓存」的竞态。
 *   2. 任务 Promise 追踪：startBackgroundTasks 记录全部任务 Promise 到
 *      taskPromises 数组，stopBackgroundTasks 通过 Promise.all 等待全部完成。
 *   3. 取消传播：controller.cancelled 在每个任务的关键检查点校验，
 *      确保取消信号能及时生效（无需等待单条 IPC 超时）。
 *
 * 三条后台任务（解锁后启动，低优先级，不打扰前台）：
 *   任务一：解析完整数据索引（复用 ensureRecordScan）
 *   任务二：预加载可见区域记录（prefetchFullRecords）
 *   任务三：完整性巡检（integrityPatrol，基于 merkle_leaf）
 *
 * 依赖关系（避免循环导入）：
 *   - background-tasks.ts → cache/composition/verthys-cache.ts（ensureRecordScan / prefetchFullRecords /
 *     getAllSummaryIds / getSummaryIdsByType / hasFullRecord）
 *   - background-tasks.ts → lib/verthys.ts（verthysGetRecord）
 *   - background-tasks.ts → utils/logger.ts（日志）
 *   - cache/composition/verthys-cache.ts（组合根）→ 本模块：仅注入 stopBackgroundTasks 钩子
 *     （单向化：start/stop 不再经 verthys-cache 转发，消费方直接从本模块导入）
 *
 * ★ ES Module 循环依赖安全性：
 *   残余双向边（verthys-cache ↔ background-tasks）：本模块仅运行时（函数调用时）
 *   访问 verthys-cache 导出的缓存访问器，verthys-cache 仅在 initVerthysCache() 装配时
 *   引用本模块的 stopBackgroundTasks（函数引用注入，非模块求值期调用）；
 *   ES Module live binding + 组合根"加载零副作用 + 调用前已初始化"保证安全。
 */
import {
  verthysGetRecord,
} from "../lib/verthys";
import {
  ensureRecordScan,
  prefetchFullRecords,
  getAllSummaryIds,
  getSummaryIdsByType,
  hasFullRecord,
} from "../cache/composition/verthys-cache";
import { TYPE_PRIORITY } from "../constants/record_types";
import { createLogger } from "../utils/logger";
// ★ 前端 IPC 优先级门控：后台任务在前端活跃时让出 worker 通道
import { yieldIfFrontendBusy } from "./frontend-ipc-priority";

const log = createLogger("background-tasks");

/* ------------------------------------------------------------------ *
 * ★ 项8：后台任务降级常量                                            *
 *                                                                    *
 *  BACKGROUND_START_DELAY_MS：                                       *
 *    解锁成功后等待 UI 完成首屏渲染 + 模块内容加载的延迟时间。        *
 *    ★ 性能根治：从 2500ms 提升到 12000ms                           *
 *                                                                    *
 *    原缺陷（2500ms）：                                              *
 *      解锁后 2.5s 即启动后台任务，但此时前端模块内容仍在加载中       *
 *      （verthysGetRecord / getRecordsDataB64Batch 等 IPC），           *
 *      后台任务与前端模块加载共用 worker 通道，                       *
 *      后台任务独占 worker 时前端请求排队等待 → 30s 卡顿。            *
 *                                                                    *
 *    修复（12000ms）：                                               *
 *      延迟 12s 启动后台任务，确保前端首屏 + 模块列表 + 模块内容      *
 *      全部加载完成后再启动全量扫描 / 巡检任务。                      *
 *      12s 覆盖：首屏渲染 1-2s + 摘要扫描 1-2s + 模块内容加载 2-3s    *
 *      + 用户浏览/切换模块的初始交互窗口 5-6s。                       *
 *      配合 yieldIfFrontendBusy 门控，前端活跃时后台任务主动让出。    *
 * ------------------------------------------------------------------ */
const BACKGROUND_START_DELAY_MS = 12000;

/* ------------------------------------------------------------------ *
 * 后台任务状态与取消控制器                                              *
 *                                                                    *
 * ★ stopBackgroundTasks 改为 async，等待所有任务完全终止           *
 *   旧实现 stopBackgroundTasks 为同步函数，仅设置取消标志不等待任务实际 *
 *   终止。重置后立即创建新会话，旧后台任务可能仍在运行，访问已释放的    *
 *   缓存或监听器，引发竞态。                                          *
 *                                                                    *
 * 新实现：                                                            *
 *   - taskPromises 追踪所有已启动任务的 Promise                       *
 *   - stopBackgroundTasks 设置取消标志后 await Promise.all(taskPromises)*
 *   - 确保所有任务检查 cancelled 标志后退出才返回                     *
 * ------------------------------------------------------------------ */

/** 后台任务运行状态（防止重复启动） */
let backgroundTasksRunning = false;

/** 后台任务取消控制器（lockAll 时通过 stopBackgroundTasks 取消） */
let backgroundTaskController: { cancelled: boolean } = { cancelled: false };

/** 所有活跃后台任务的 Promise 列表（用于 stopBackgroundTasks 等待） */
let taskPromises: Promise<void>[] = [];

/** 后台任务总体完成 Promise（stopBackgroundTasks await 此对象） */
let allTasksCompletion: Promise<void> = Promise.resolve();

/* 记录类型优先级已移至 constants/record_types.ts 统一管理
 * ★ 企业级根治：原硬编码 [0x01,0x02,0x04,0x03] 使用 C 层规范值，
 *   与前端实际存储类型不匹配，导致预加载永远查不到账户/证书/文件记录。
 *   现从 record_types.ts 导入 TYPE_PRIORITY（引用实际常量值）。
 */

/* ------------------------------------------------------------------ *
 * 公共 API                                                            *
 * ------------------------------------------------------------------ */

/**
 * ★ 解锁后启动三条低优先级后台任务。
 *
 * 目标：解锁完成的同时，系统启动三条低优先级后台任务。
 *   第一条悄悄解析完整数据索引，为后续可能的全量搜索和导出建立高速缓存。
 *   第二条预加载当前屏幕可见区域内的几条记录对应的完整数据块，
 *    让用户很可能点开的就是已缓存好的内容。
 *    第三条基于轻量索引的校验码进行全盘完整性巡检，完全不打扰前台操作。
 *
 * 任务一：解析完整数据索引
 *   - 复用 ensureRecordScan（旧 recordScanCache）
 *   - 为后续可能的全量搜索/导出建立高速缓存
 *   - 失败不影响 UI（summaryCache 已支撑列表渲染）
 *
 * 任务二：预加载可见区域记录
 *   - 从 summaryCache 取首批 ID（按类型分组，前 N 条）
 *   - 通过 prefetchFullRecords 后台解密填入 fullRecordCache
 *   - 用户点击时大概率命中缓存
 *
 * 任务三：完整性巡检
 *   - 基于 summaryCache 中的 merkle_leaf 字段
 *   - 对比磁盘实际数据的可读性
 *   - 不打扰前台操作，发现损坏仅记录不阻塞
 *
 * ★ 异步安全保证：
 *   所有任务 Promise 被追踪到 taskPromises 数组，
 *   stopBackgroundTasks 可通过 Promise.all 等待全部完成。
 *
 * @returns Promise<void>，resolve 时表示所有任务已入队（非全部完成）
 */
export async function startBackgroundTasks(): Promise<void> {
  // 已在运行 → 不重复启动
  if (backgroundTasksRunning) return;
  backgroundTasksRunning = true;
  backgroundTaskController = { cancelled: false };
  const controller = backgroundTaskController;

  // 重置任务追踪列表
  taskPromises = [];

  /**
   * ★ 项8：延迟启动策略
   *
   * 解锁成功后立即启动后台任务会与 UI 首屏渲染争抢 CPU，
   * 导致解锁后前 10 秒的间歇性卡顿（列表渲染 / 视差动画 / 交互反馈）。
   *
   * 延迟 2.5s 启动让首屏列表渲染 / 视差动画 / 交互反馈先完成，
   * 用户感知为「解锁后立即流畅，后台默默工作」。
   *
   * 延迟期间若被取消（lockAll 触发），不再启动任何任务。
   *
   * ★ 企业级根治：startGate 必须响应 cancelled 标志
   *   原实现：纯 setTimeout，lockAll 时任务卡在 startGate 上 12s，
   *   stopBackgroundTasks 的 3s 超时等不到任务退出
   *   修复：用轮询检查 cancelled，检测到立即 resolve，startGate 立即放行
   */
  const startGate = new Promise<void>((resolve) => {
    const elapsed = { value: 0 };
    const POLL_INTERVAL_MS = 100;
    const timer = setInterval(() => {
      elapsed.value += POLL_INTERVAL_MS;
      if (controller.cancelled || elapsed.value >= BACKGROUND_START_DELAY_MS) {
        clearInterval(timer);
        resolve();
      }
    }, POLL_INTERVAL_MS);
  });

  /**
   * 任务一：解析完整数据索引（旧 recordScanCache 作为长期加速兜底）
   * 不阻塞：失败静默，summaryCache 已支撑 UI。
   * ★ 项8：延迟 12s 启动，避免与首屏渲染 + 模块内容加载争抢 worker 通道。
   * ★ 性能根治：启动前 yieldIfFrontendBusy，前端活跃时让出 worker 通道。
   */
  if (!controller.cancelled) {
    const scanTask = startGate
      .then(async () => {
        if (controller.cancelled) return;
        // ★ 前端 IPC 优先级门控：前端活跃时让出 worker 通道
        await yieldIfFrontendBusy();
        return ensureRecordScan();
      })
      .then(() => {})
      .catch(() => { /* 静默：summaryCache 已兜底 */ });
    taskPromises.push(scanTask);
  }

  /**
   * 任务二：预加载可见区域记录（首批各类型前 20 条）
   * 从 summaryCache 取首批 ID，通过 prefetchFullRecords 后台解密填入 fullRecordCache。
   * ★ 项8：延迟 12s 启动，避免与首屏渲染 + 模块内容加载争抢 worker 通道。
   * ★ 性能根治：启动前 yieldIfFrontendBusy，前端活跃时让出 worker 通道。
   */
  if (!controller.cancelled) {
    const visibleIds = collectVisibleRecordIds(20);
    if (visibleIds.length > 0) {
      const prefetchTask = startGate
        .then(async () => {
          if (controller.cancelled) return;
          // ★ 前端 IPC 优先级门控：前端活跃时让出 worker 通道
          await yieldIfFrontendBusy();
          return prefetchFullRecords(visibleIds);
        })
        .then(() => {})
        .catch(() => { /* 静默 */ });
      taskPromises.push(prefetchTask);
    }
  }

  /**
   * 任务三：完整性巡检（基于 merkle_leaf）
   * 遍历 summaryCache 中所有记录，校验可读性。
   * 发现损坏仅记录警告，不阻塞 UI（单条损坏不影响整体）。
   * ★ 项8：延迟 12s 启动，避免与首屏渲染 + 模块内容加载争抢 worker 通道。
   * ★ 性能根治：integrityPatrol 内部每条 verthysGetRecord 前 yieldIfFrontendBusy。
   */
  if (!controller.cancelled) {
    const patrolTask = startGate
      .then(() => {
        if (controller.cancelled) return;
        return integrityPatrol(controller);
      })
      .then(() => {})
      .catch(() => { /* 静默 */ });
    taskPromises.push(patrolTask);
  }

  // ★ 追踪全部任务完成时机（stopBackgroundTasks await 此对象）
  allTasksCompletion = Promise.all(taskPromises)
    .then(() => {
      backgroundTasksRunning = false;
    })
    .catch(() => {
      backgroundTasksRunning = false;
    });

  // 不 await allTasksCompletion：startBackgroundTasks 入队后立即返回，
  // 任务在后台异步执行，不阻塞解锁关键路径。
  // stopBackgroundTasks 负责 await 全部任务终止。
}

/**
 * ★ 停止后台任务并等待所有任务完全终止。
 *
 * 旧实现为同步函数，仅设置取消标志不等待任务实际终止。
 * 重置后立即创建新会话，旧后台任务可能仍在运行，访问已释放的缓存或监听器，引发竞态。
 *
 * 新实现：
 *   1. 设置 controller.cancelled = true（通知所有任务在下一个检查点退出）
 *   2. await allTasksCompletion（等待所有任务 Promise 完成）
 *   3. 确保 taskPromises 已清空，杜绝残留
 *
 * ★ 企业级根治：限制最大等待时间，防止"正在停止后台任务"卡死
 *
 * 原缺陷：
 *   stopBackgroundTasks 无超时上限地 await allTasksCompletion。
 *   后台任务可能卡在以下位置，导致 stopBackgroundTasks 长时间不返回：
 *     a) startGate setTimeout(12000)：解锁后 12s 内 lockAll，任务卡在延迟启动门
 *     b) yieldIfFrontendBusy：前端活跃时无限让出
 *     c) verthysGetRecord IPC：在途 IPC 无法中断
 *     d) setTimeout 片间让出（巡检 50ms）
 *   security-session.ts 的 withStepTimeout(stopBackgroundTasks(), 10000) 超时后
 *   Promise.race 仅 resolve 当前调用，后台任务 Promise 仍在运行，继续占用 worker
 *   通道，与后续 lockAll 步骤争抢资源，用户感知"停止后台任务时间过长"。
 *
 * 修复：
 *   1. 设置取消标志后，最多等待 3000ms 让任务在检查点退出
 *   2. 超时后强制清理状态（taskPromises/allTasksCompletion），不再等待
 *   3. 残留任务 Promise 在后台继续运行，但 cancelled=true 确保它们在下个检查点退出
 *   4. worker 销毁（verthysLock）会强制终止所有在途 IPC，彻底清理残留任务
 *
 * @returns Promise<void>，resolve 时表示已尽力停止后台任务（不保证全部实际终止）
 */
export async function stopBackgroundTasks(): Promise<void> {
  // 设置取消标志（所有任务在下个检查点退出）
  backgroundTaskController.cancelled = true;

  // ★ 企业级根治：限制最大等待时间 3000ms
  //    足以让任务在检查点退出（cancelled 检查在每次循环开始），
  //    超时后强制清理，由 verthysLock 销毁 worker 彻底终止残留 IPC
  const STOP_TIMEOUT_MS = 3000;
  try {
    await Promise.race([
      allTasksCompletion,
      new Promise<void>((resolve) => {
        setTimeout(() => {
          log.warn(`stopBackgroundTasks 超时 ${STOP_TIMEOUT_MS}ms，强制清理（残留任务由 verthysLock 终止）`);
          resolve();
        }, STOP_TIMEOUT_MS);
      }),
    ]);
  } catch {
    /* 静默：任务异常不应阻塞 stopBackgroundTasks */
  }

  // 清理状态（无论任务是否实际终止，状态必须重置）
  backgroundTasksRunning = false;
  taskPromises = [];
  allTasksCompletion = Promise.resolve();
}

/**
 * 检查后台任务是否正在运行。
 * @returns true 表示有活跃的后台任务
 */
export function isBackgroundTasksRunning(): boolean {
  return backgroundTasksRunning;
}

/* ------------------------------------------------------------------ *
 * 内部任务实现                                                        *
 * ------------------------------------------------------------------ */

/**
 * 收集各类型前 N 条记录 ID（用于预加载可见区域）。
 * 优先返回照片类型（最可能被点击查看）。
 *
 * @param perType 每种类型取前 N 条
 * @returns 按 TYPE_PRIORITY 排序的 ID 列表
 */
function collectVisibleRecordIds(perType: number): number[] {
  const ids: number[] = [];
  for (const type of TYPE_PRIORITY) {
    const typeIds = getSummaryIdsByType(type);
    if (typeIds.length === 0) continue;
    // 取前 perType 条（已按 ID 升序排序）
    const subset = typeIds.slice(0, perType);
    ids.push(...subset);
  }
  return ids;
}

/**
 * ★ 任务三：完整性巡检（基于 merkle_leaf）。
 *
 *   "基于轻量索引的校验码进行全盘完整性巡检，完全不打扰前台操作"。
 *
 * 实现：
 *   - 遍历 summaryCache 中所有记录
 *   - 通过 verthysGetRecord 拉取完整数据，校验可读性
 *   - 发现损坏仅记录警告，不阻塞 UI（单条损坏不影响整体）
 *   - 低优先级：每条之间让出主线程 50ms
 *
 * 注意：当前阶段仅做"在场性 + 可读性"巡检（验证记录可被读取）。
 * 完整 merkle 哈希校验需要后端提供 merkle 计算接口，
 * 留待后续扩展（B+ 树序列化版本化后）。
 *
 * @param controller 取消控制器，cancelled=true 时立即退出
 */
async function integrityPatrol(controller: { cancelled: boolean }): Promise<void> {
  const allIds = getAllSummaryIds();
  let checked = 0;
  let failed = 0;

  for (const id of allIds) {
    // ★ 取消检查：lockAll 触发后立即退出
    if (controller.cancelled) return;

    // 已在全量缓存中 → 跳过（无需重复读取，已验证可读）
    if (hasFullRecord(id)) {
      checked++;
      continue;
    }

    // 让出主线程 50ms（低优先级，不打扰前台）
    await new Promise<void>(resolve => setTimeout(resolve, 50));

    // ★ 二次取消检查（50ms 等待期间可能已被取消）
    if (controller.cancelled) return;

    // ★ 前端 IPC 优先级门控：前端活跃时让出 worker 通道，避免队头阻塞
    await yieldIfFrontendBusy();
    // yield 后再次检查取消标志（让出期间可能已被 lockAll 取消）
    if (controller.cancelled) return;

    try {
      const r = await verthysGetRecord(id);
      if (!r || !r.dataB64) {
        failed++;
        log.warn(`记录 ID=${id} 读取失败或数据为空`);
      } else {
        checked++;
      }
    } catch {
      failed++;
      log.warn(`记录 ID=${id} IPC 异常`);
    }
  }

  if (failed > 0) {
    log.warn(`巡检完成：${checked} 条正常，${failed} 条异常`);
  } else if (checked > 0) {
    log.debug(`巡检完成：${checked} 条记录全部正常`);
  }
}
