/**
 * useClipToast — 安全复制 + 倒计时自动清空剪贴板
 *
 * 职责分离：
 *   - 本 composable 承担剪贴板生命周期（写入 → 逐秒倒计时 → 到期覆写清零）；
 *   - 提示渲染统一经全局 Toast 中心倒计时通道（底部 .clip-toast），
 *     由 ToastLayer 在最高层（--z-toast）渲染 —— 模块内不再自行渲染提示 DOM。
 *
 * 用法：
 *   const { copyWithTimeout } = useClipToast("密码已复制");
 *   await copyWithTimeout("敏感文本");
 *   （text 为提示场景文案；倒计时提示形如「密码已复制 · 14s 后自动清空」）
 */

import { onBeforeUnmount } from "vue";
import { clearClipboard } from "../lib/verthys";
import { toastState, useToastCenter, type ToastClip } from "./useToastCenter";

/** 倒计时秒数 */
const COUNTDOWN_SECONDS = 30;

export function useClipToast(text: string) {
  const { setClip } = useToastCenter();
  let clipTimer: ReturnType<typeof setInterval> | null = null;
  /** 本实例最后写入的倒计时状态（对象身份 — 卸载时用于精确判定归属） */
  let lastPushed: ToastClip | null = null;

  /** 写入中心并记录本实例最后写入的身份（每次写入均为新对象） */
  const pushClip = (state: ToastClip | null) => {
    lastPushed = state;
    setClip(state);
  };

  /** 停止倒计时（幂等） */
  const stopTimer = () => {
    if (clipTimer) {
      clearInterval(clipTimer);
      clipTimer = null;
    }
  };

  /** 复制文本到剪贴板并启动安全倒计时（提示经全局 Toast 中心渲染，自动收起） */
  const copyWithTimeout = async (content: string) => {
    try {
      await navigator.clipboard.writeText(content);
    } catch { /* */ }

    let remaining = COUNTDOWN_SECONDS;
    pushClip({ text, seconds: remaining });

    stopTimer();
    clipTimer = setInterval(() => {
      /* 通道单写者自守：若中心当前值已非本实例最后写入（被新实例接管 /
       * 外部收起），本实例立即让出通道并停止计时 —— 模块交叉淡出导致新旧
       * 实例短暂并存时，杜绝双计时器交错回写（提示秒数在 A/B 间翻跳） */
      if (toastState.clip.value !== lastPushed) {
        stopTimer();
        return;
      }
      remaining--;
      if (remaining <= 0) {
        stopTimer();
        pushClip(null);
        // 覆写剪贴板 + 调用 Tauri 清空（清理失败不得以未捕获异常逃逸出计时
        // 回调：浏览器非安全上下文无 clipboard API 时静默跳过）
        try { navigator.clipboard.writeText("\u0000".repeat(32)).catch(() => {}); } catch { /* */ }
        try { clearClipboard(); } catch { /* */ }
        return;
      }
      pushClip({ text, seconds: remaining });
    }, 1000);
  };

  /* 卸载清理：停止倒计时并按归属收起提示 —— 提示状态为全局单例，不再随
   * 模块 DOM 卸载自动消失，须显式收回，否则残留倒计时提示。
   * 归属判定（对象身份）：模块切换为交叉淡出（新旧短暂并存），若新模块已
   * 接管倒计时通道（中心当前值 ≠ 本实例最后写入），不得误清他人状态。 */
  onBeforeUnmount(() => {
    stopTimer();
    if (toastState.clip.value === lastPushed) setClip(null);
  });

  return { copyWithTimeout };
}