/**
 * useSessionTimer.ts — 会话倒计时显示 Composable
 *
 * 职责：
 *   1. 把会话层的真实空闲截止时间投影为 UI 文本（sessionRemaining）
 *   2. 1s 节拍仅在非低功耗档推进显示；idle/deep-idle 档暂停逐秒重算
 *      （恢复瞬间按截止时间立即校正，显示值与真实空闲时间严格一致）
 *
 * 设计（单一事实源）：
 *   - 实际锁定裁决与显示同源于 security-session 的会话截止时间
 *   - 用户活动刷新截止时间 → sessionIdleDeadlineRef 变化 → 显示即时同步
 *   - 本 Composable 不维护本地倒计时计数、不做暂停补偿：
 *     每次取值都是「截止时间 − 当前时刻」，不存在两套时钟漂移
 *
 * 设计：纯 Composable，globalKeyReady / idleLockEnabled 通过 Ref 注入。
 * 计时器生命周期由调用方管理（onMounted 启动 / onBeforeUnmount 停止）。
 */

import { ref, watch, type Ref } from 'vue';
import {
  getSessionRemainingMs,
  getSessionTimeout,
  sessionIdleDeadlineRef,
} from '../../lib/keyManager';
import { useGlobalIdleScheduler } from '../useGlobalIdleScheduler';

/**
 * useSessionTimer 选项
 * 所有外部依赖通过参数注入，保持 Composable 纯净可测试
 */
export interface UseSessionTimerOptions {
  /** 全局密钥是否已就绪（仅就绪时展示真实倒计时） */
  globalKeyReady: Ref<boolean>;
  /** 会话空闲锁定开关（false = 不自动锁定，显示完整超时） */
  idleLockEnabled: Ref<boolean>;
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
 *   useSessionTimer({ globalKeyReady: globalKeyReadyRef, idleLockEnabled: sessionLockEnabledRef });
 * // onMounted(() => startSessionTick());
 * // onBeforeUnmount(() => stopSessionTick());
 * ```
 */
export function useSessionTimer(options: UseSessionTimerOptions) {
  /* ===== 会话剩余时间（权威截止时间的投影，仅用于显示） ===== */
  const sessionRemaining = ref(getSessionTimeout());
  let sessionTick: number | null = null;

  const { level: idleLevel } = useGlobalIdleScheduler();

  /** 低功耗档：暂停逐秒重算（恢复时由 watch 立即校正） */
  const isLowPowerIdle = () =>
    idleLevel.value === 'idle' || idleLevel.value === 'deep-idle';

  /** 从权威截止时间同步显示值
   *  - 未就绪 / 空闲锁定关闭：显示完整超时（下一会话的默认值）
   *  - 已就绪且已武装：按真实截止时间计算剩余 */
  const syncRemaining = () => {
    if (!options.globalKeyReady.value || !options.idleLockEnabled.value) {
      sessionRemaining.value = getSessionTimeout();
      return;
    }
    sessionRemaining.value = getSessionRemainingMs();
  };

  /* 活动重置 / 武装 / 解除武装 → 截止时间变化 → 显示即时同步 */
  watch(sessionIdleDeadlineRef, syncRemaining);

  /* 会话就绪态或空闲锁定开关变化 → 立即同步 */
  watch([options.globalKeyReady, options.idleLockEnabled], syncRemaining);

  /* 低功耗档恢复 → 立即按截止时间校正（不依赖暂停时长补偿） */
  watch(idleLevel, (level) => {
    if (level !== 'idle' && level !== 'deep-idle') syncRemaining();
  });

  /** 启动会话计时器（1s 间隔，仅更新 UI 显示；低功耗档/锁定关闭时跳过更新）
   *  幂等：重复调用不会叠加第二个 interval（旧实现会叠加，倒计时成倍加速） */
  const startSessionTick = () => {
    if (sessionTick !== null) return;
    sessionTick = window.setInterval(() => {
      if (isLowPowerIdle()) return; // 低功耗档暂停 UI 更新（恢复时 watch 立即校正）
      if (!options.idleLockEnabled.value || !options.globalKeyReady.value) return;
      sessionRemaining.value = getSessionRemainingMs();
    }, 1000);
  };

  /** 停止会话计时器（供 onBeforeUnmount 调用，防止组件卸载后回调空转） */
  const stopSessionTick = () => {
    if (sessionTick !== null) {
      window.clearInterval(sessionTick);
      sessionTick = null;
    }
  };

  /** 立即按权威截止时间校正显示（预设切换 / 锁定后调用） */
  const resetSession = () => {
    syncRemaining();
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
