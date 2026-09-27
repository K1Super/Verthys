/**
 * photo-album/utils/timer.ts — 单次定时器工具
 *
 * 职责：以句柄纳管方式管理一次性清理定时器。同一实例任意时刻至多存在一个
 * 挂起回调：新调度自动作废旧调度，显式 cancel/dispose 供流程切换与组件卸载
 * 时清理，防止迟到的旧回调污染新一轮状态。
 *
 * 设计要点：
 * - schedule 重复调用时清除旧句柄（调度互斥），回调触发前自动置空句柄
 * - cancel 仅作废挂起回调；dispose 语义与 cancel 相同，但以命名宣示实例
 *   生命周期终结，供 onScopeDispose 配对调用
 * - 回调异常被记录后隔离，不向上传播为未捕获异常（定时回调无调用方）
 */

/** 单次定时器控制句柄 */
export interface SingleTimer {
  /** 调度一次性回调（替换任何未触发的旧回调） */
  schedule(fn: () => void, ms: number): void;
  /** 作废当前挂起回调（无挂起时为空操作） */
  cancel(): void;
  /** 终结实例（与 cancel 等价，宣示不可复用） */
  dispose(): void;
}

/**
 * 创建单次定时器
 *
 * @param label 实例标识，仅用于异常日志定位，不参与业务逻辑
 */
export function useSingleTimer(label: string): SingleTimer {
  let handle: ReturnType<typeof setTimeout> | null = null;

  return {
    schedule(fn: () => void, ms: number) {
      if (handle !== null) clearTimeout(handle);
      handle = setTimeout(() => {
        handle = null;
        try {
          fn();
        } catch (e) {
          console.error(`[timer:${label}] 定时回调异常`, e);
        }
      }, ms);
    },
    cancel() {
      if (handle !== null) {
        clearTimeout(handle);
        handle = null;
      }
    },
    dispose() {
      if (handle !== null) {
        clearTimeout(handle);
        handle = null;
      }
    },
  };
}