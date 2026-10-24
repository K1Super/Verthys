/**
 * key-tools/usePasswordStrength.ts — 密码安全评估面板的状态绑定
 *
 * 职责：把桥接层的异步评估接到 Vue 响应式状态上，处理输入防抖、代际丢弃与
 * 卸载清理；不包含任何评估算法与 Worker 细节。
 *
 * 关键约束：
 * - 防抖用于吸收连续输入：一次评估会进入 Worker 做模式分析，逐字符触发会
 *   让旧请求不断被取代（虽然桥接能处理，但纯属浪费）。
 * - 任何时刻只有最新一次输入可以写结果；被取代或已卸载的回调必须静默丢弃。
 */
import { onScopeDispose, ref, type Ref } from "vue";
import {
  EMPTY_ASSESSMENT,
  PasswordStrengthBridge,
  createPasswordStrengthBridge,
  type PasswordAssessment,
} from "./password_strength";

/** 输入防抖窗口（毫秒）：大于键入间隔，避免每个按键都触发一次分析 */
export const STRENGTH_DEBOUNCE_MS = 140;

/** 组合式配置 */
export interface UsePasswordStrengthOptions {
  /** 防抖窗口（毫秒） */
  debounceMs?: number;
  /** 桥接实例（测试注入点；默认为本实例独享的真实桥接） */
  bridge?: PasswordStrengthBridge;
}

/** 评估面板状态 */
export interface PasswordStrengthState {
  /** 当前评估结果（空输入为等级 0） */
  result: Ref<PasswordAssessment>;
  /** 是否有一次评估正在等待调度或执行 */
  pending: Ref<boolean>;
  /** 提交输入（内部防抖） */
  assess: (password: string) => void;
  /** 预热分析引擎 */
  preload: () => void;
}

export function usePasswordStrength(
  options: UsePasswordStrengthOptions = {},
): PasswordStrengthState {
  const bridge = options.bridge ?? createPasswordStrengthBridge();
  const debounceMs = options.debounceMs ?? STRENGTH_DEBOUNCE_MS;

  const result = ref<PasswordAssessment>({ ...EMPTY_ASSESSMENT });
  const pending = ref(false);

  let timer: ReturnType<typeof setTimeout> | null = null;
  /** 代际：只有最新一代的异步结果允许落状态 */
  let generation = 0;

  const clearTimer = (): void => {
    if (timer === null) return;
    clearTimeout(timer);
    timer = null;
  };

  const assess = (password: string): void => {
    clearTimer();
    generation += 1;
    const run = generation;

    if (!password) {
      pending.value = false;
      result.value = { ...EMPTY_ASSESSMENT };
      return;
    }

    timer = setTimeout(() => {
      timer = null;
      if (run !== generation) return;
      pending.value = true;
      void bridge.assess(password).then((next) => {
        // 被更新输入取代（null）或已过期：不得覆盖当前结果
        if (run !== generation || !next) return;
        result.value = next;
        pending.value = false;
      });
    }, debounceMs);
  };

  const preload = (): void => {
    bridge.preload();
  };

  onScopeDispose(() => {
    clearTimer();
    generation += 1;
    bridge.dispose();
  });

  return { result, pending, assess, preload };
}
