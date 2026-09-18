/**
 * useClipToast — 安全复制 + 倒计时自动清空剪贴板
 *
 * 用法：
 *   const { clipCountdown, copyWithTimeout } = useClipToast();
 *   await copyWithTimeout("敏感文本");
 *
 * 模板中配合全局 .clip-toast 样式：
 *   <transition name="toast">
 *     <div v-if="clipCountdown > 0" class="clip-toast glass">
 *       <span class="toast-dot"></span>
 *       已复制 · {{ clipCountdown }}s 后自动清空
 *     </div>
 *   </transition>
 */

import { ref, onBeforeUnmount } from "vue";
import { clearClipboard } from "../lib/verthys";

/** 倒计时秒数 */
const COUNTDOWN_SECONDS = 15;

export function useClipToast() {
  const clipCountdown = ref(0);
  let clipTimer: ReturnType<typeof setInterval> | null = null;

  /** 复制文本到剪贴板并启动安全倒计时 */
  const copyWithTimeout = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch { /* */ }

    clipCountdown.value = COUNTDOWN_SECONDS;

    if (clipTimer) clearInterval(clipTimer);
    clipTimer = setInterval(() => {
      clipCountdown.value--;
      if (clipCountdown.value <= 0) {
        if (clipTimer) clearInterval(clipTimer);
        clipTimer = null;
        // 覆写剪贴板 + 调用 Tauri 清空
        navigator.clipboard.writeText("\u0000".repeat(32)).catch(() => {});
        try { clearClipboard(); } catch { /* */ }
      }
    }, 1000);
  };

  onBeforeUnmount(() => {
    if (clipTimer) {
      clearInterval(clipTimer);
      clipTimer = null;
    }
  });

  return { clipCountdown, copyWithTimeout };
}
