/**
 * useErrorToast — 顶部错误提示弹窗（自动消失）
 *
 * 与 clip-toast 同结构，但定位在顶部、红色主题。
 * 用法：
 *   const { errorMsg, showError } = useErrorToast();
 *   showError("密码错误");
 *
 * 模板中配合全局 .error-toast 样式：
 *   <transition name="err-toast">
 *     <div v-if="errorMsg" class="error-toast glass"><span class="toast-dot"></span>{{ errorMsg }}</div>
 *   </transition>
 */

import { ref, onBeforeUnmount } from "vue";

/** 提示显示时长（毫秒） */
const DURATION = 2500;

export function useErrorToast() {
  const errorMsg = ref("");
  let timer: ReturnType<typeof setTimeout> | null = null;

  /** 显示错误提示，自动消失 */
  const showError = (msg: string) => {
    errorMsg.value = msg;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => { errorMsg.value = ""; }, DURATION);
  };

  onBeforeUnmount(() => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  });

  return { errorMsg, showError };
}
