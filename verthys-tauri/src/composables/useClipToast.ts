/**
 * useClipToast — 安全复制 + 到期静默清空剪贴板
 *
 * 职责分离：
 *   - 本 composable 承担剪贴板生命周期（写入 → 到期覆写清零 + 通知后端清空）；
 *   - 提示统一经全局 Toast 中心 status 通道渲染（ToastLayer 最高层）。
 *
 * 默认清空时长 1 分钟（60s）。清空时间提示按「设定时长」直陈（不折算已
 *   消耗的提示时长，也不做逐秒倒计时）。清空计时器为模块级单例：任一实例发起新复制
 *   都会取消上一笔的清空计时，保证「最后复制的内容」才拥有清空权；组件卸载
 *   只取消接力提示，不取消清空计时（跨模块切换后剪贴板仍必须按时清空）。
 *
 * 降级写入：WebView 无 Clipboard API（非安全上下文 / 被占用）时，
 *   调用方可注入 write 兜底（如 textarea + execCommand）；不注入即维持
 *   "写不进去就如实返回失败"的原语义。
 */

import { onBeforeUnmount } from "vue";
import { clearClipboard } from "../lib/verthys";
import { useToastCenter } from "./useToastCenter";

const { showStatus } = useToastCenter();

/** 默认自动清空时长（秒） */
const CLEAR_AFTER_SECONDS = 60;
/** 成功提示展示时长（与 Toast 中心 status 默认口径一致） */
const STATUS_DURATION_MS = 2500;
/** 轮番间隔：等成功提示收起后再接力清空时间提示（含过渡间隙） */
const RELAY_GAP_MS = 200;

export interface ClipToastOptions {
  /** 可选降级写入器：Clipboard API 不可用时调用；返回是否真正写入 */
  write?: (content: string) => Promise<boolean>;
  /** 自动清空时长（秒），默认 60 */
  seconds?: number;
}

/* ===== 模块级清空计时（单写者：最后复制的内容拥有清空权） ===== */
let clearTimer: ReturnType<typeof setTimeout> | null = null;
let clearGeneration = 0;

const cancelPendingClear = (): void => {
  if (clearTimer !== null) {
    clearTimeout(clearTimer);
    clearTimer = null;
  }
};

/** 武装到期清空：一代复制只有一个有效计时，旧代次到点直接让出 */
const armClear = (seconds: number): void => {
  cancelPendingClear();
  const generation = ++clearGeneration;
  clearTimer = setTimeout(() => {
    clearTimer = null;
    if (generation !== clearGeneration) return;
    // 覆写 + 调用 Tauri 清空（清理失败不得以未捕获异常逃逸出计时回调）
    try { navigator.clipboard.writeText("\u0000".repeat(32)).catch(() => {}); } catch { /* */ }
    try { clearClipboard(); } catch { /* */ }
  }, seconds * 1000);
};

export function useClipToast(text: string, options: ClipToastOptions = {}) {
  /** 本实例的接力提示计时（卸载即取消，避免离开模块后仍弹提示） */
  let relayTimer: ReturnType<typeof setTimeout> | null = null;
  let disposed = false;

  const stopRelay = (): void => {
    if (relayTimer !== null) {
      clearTimeout(relayTimer);
      relayTimer = null;
    }
  };

  /**
   * 复制文本到剪贴板并武装安全清空。
   *
   * @returns 是否真正写入成功 —— 调用方据此给出准确反馈。
   *   写剪贴板可能被拒（非安全上下文 / 无权限 / 被占用）：此时不提示成功。
   */
  const copyWithTimeout = async (content: string): Promise<boolean> => {
    let written = false;
    try {
      await navigator.clipboard.writeText(content);
      written = true;
    } catch {
      written = false;
    }
    if (!written && options.write) {
      try {
        written = await options.write(content);
      } catch {
        written = false;
      }
    }
    if (!written) return false;

    const seconds = options.seconds ?? CLEAR_AFTER_SECONDS;
    armClear(seconds);

    stopRelay();
    // 第一段：复制结果（短时展示，不常驻）
    showStatus(text, STATUS_DURATION_MS);
    // 第二段：成功提示收起后，再单独给出清空时间（按设定时长直陈，
    // 不折算已消耗的提示时间、不逐秒倒计时）
    relayTimer = setTimeout(() => {
      relayTimer = null;
      if (disposed) return;
      showStatus(`剪贴板将在 ${seconds} 秒后自动清空`, STATUS_DURATION_MS);
    }, STATUS_DURATION_MS + RELAY_GAP_MS);

    return true;
  };

  /* 卸载清理：只收回本实例的接力提示；清空计时（模块级）继续，确保
   * 跨模块切换后剪贴板仍按原定时间清空。 */
  onBeforeUnmount(() => {
    disposed = true;
    stopRelay();
  });

  return { copyWithTimeout };
}
