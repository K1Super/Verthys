/**
 * useSessionTimer.ts — 会话超时计时器 Composable
 *
 * 来源：SecurityCenter.vue 原 L1045-L1046, L1454-L1463, L1716（零行为变更提取）
 *
 * 职责：
 *   1. 管理会话剩余时间显示（sessionRemaining，毫秒，模板用于「会话空闲 N 分钟后自动锁定」）
 *   2. 提供核心函数：
 *      - startSessionTick：启动 1s 间隔计时器（仅显示，实际超时由 keyManager 管理）
 *      - stopSessionTick：停止计时器（供 onBeforeUnmount 调用）
 *      - resetSession：重置剩余时间（锁定后 / 预设切换后调用）
 *
 * ★ 设计说明：
 *   - 计时器仅用于 UI 显示倒计时，不触发实际锁定（实际超时由 keyManager 守护）
 *   - globalKeyReady 为 true 时倒计时；归零后重置为 getSessionTimeout()（循环显示）
 *   - globalKeyReady 为 false 时不倒计时（未验证，无需显示）
 *
 * 设计：纯 Composable，globalKeyReady 通过 Ref 注入。计时器生命周期由调用方管理。
 */

import { ref, watch, type Ref } from 'vue';
import { getSessionTimeout } from '../../lib/keyManager';
import { useGlobalIdleScheduler } from '../useGlobalIdleScheduler';

/**
 * useSessionTimer 选项
 * 所有外部依赖通过参数注入，保持 Composable 纯净可测试
 */
export interface UseSessionTimerOptions {
  /** 全局密钥是否已就绪（仅就绪时倒计时，归零后重置） */
  globalKeyReady: Ref<boolean>;
}

/**
 * 会话超时计时器 Composable
 *
 * @param options 依赖注入
 * @returns 状态变量 + 核心函数
 *
 * @example
 * ```ts
 * const { sessionRemaining, startSessionTick, stopSessionTick, resetSession } =
 *   useSessionTimer({ globalKeyReady: globalKeyReadyRef });
 * // onMounted(() => startSessionTick());
 * // onBeforeUnmount(() => stopSessionTick());
 * ```
 */
export function useSessionTimer(options: UseSessionTimerOptions) {
  /* ===== 会话剩余时间（仅显示，实际超时由 keyManager 管理） ===== */
  const sessionRemaining = ref(getSessionTimeout());
  let sessionTick: number | null = null;

  /* ===== ★ 空闲治理 R5：订阅全局空闲档位 =====
   * idle / deep-idle 档暂停 UI 倒计时更新（每秒响应式写入归零）；
   * 恢复 active / settling 瞬间按暂停时长补偿并立即刷新，
   * 显示值与真实流逝时间严格一致（方案 7.2）。 */
  const { level: idleLevel } = useGlobalIdleScheduler();
  let pausedAtMs = 0;

  watch(idleLevel, (newLevel, oldLevel) => {
    const idleNow = newLevel === 'idle' || newLevel === 'deep-idle';
    const wasIdle = oldLevel === 'idle' || oldLevel === 'deep-idle';
    if (wasIdle && !idleNow) {
      // 恢复：按暂停时长一次性补偿 + 立即刷新（倒计时进行中且已就绪）
      if (
        pausedAtMs > 0 &&
        options.globalKeyReady.value &&
        sessionRemaining.value > 0
      ) {
        const pausedElapsed = performance.now() - pausedAtMs;
        sessionRemaining.value = Math.max(
          0,
          sessionRemaining.value - pausedElapsed,
        );
      }
      pausedAtMs = 0;
    } else if (!wasIdle && idleNow) {
      pausedAtMs = performance.now();
    }
  });

  /** 启动会话计时器（1s 间隔，仅更新 UI 显示；空闲档跳过更新） */
  const startSessionTick = () => {
    sessionTick = window.setInterval(() => {
      if (idleLevel.value === 'idle' || idleLevel.value === 'deep-idle') {
        return; // 空闲档暂停 UI 更新（恢复时 watch 立即补偿刷新）
      }
      if (options.globalKeyReady.value && sessionRemaining.value > 0) {
        sessionRemaining.value = Math.max(0, sessionRemaining.value - 1000);
      } else if (options.globalKeyReady.value) {
        sessionRemaining.value = getSessionTimeout();
      }
    }, 1000);
  };

  /** 停止会话计时器（供 onBeforeUnmount 调用，防止组件卸载后回调空转） */
  const stopSessionTick = () => {
    if (sessionTick !== null) {
      window.clearInterval(sessionTick);
      sessionTick = null;
    }
  };

  /** 重置会话剩余时间（锁定后 / 预设切换后调用，同步本地显示） */
  const resetSession = () => {
    sessionRemaining.value = getSessionTimeout();
  };

  return {
    // 状态（模板显示倒计时）
    sessionRemaining,
    // 方法
    startSessionTick,
    stopSessionTick,
    resetSession,
  };
}

/** useSessionTimer 返回值类型（便于显式标注） */
export type UseSessionTimerReturn = ReturnType<typeof useSessionTimer>;
