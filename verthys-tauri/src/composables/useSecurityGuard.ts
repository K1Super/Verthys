/*
 * useSecurityGuard — 前端安全拦截
 *
 * 职责：
 *   - 禁用右键菜单、文本选中、开发者工具快捷键
 *   - dev 环境自动关闭拦截，便于调试
 *
 *   全局前端安全拦截抽离，支持开发/生产环境开关
 */

import { onMounted, onBeforeUnmount } from "vue";

/** 生产环境才启用安全拦截 */
const isProduction = !import.meta.env.DEV;

export function useSecurityGuard(enabled: boolean = isProduction) {
  /* 事件处理器引用：卸载时需精确移除 */
  let contextMenuHandler: ((e: MouseEvent) => void) | null = null;
  let selectStartHandler: ((e: Event) => void) | null = null;
  let keydownHandler: ((e: KeyboardEvent) => void) | null = null;

  onMounted(() => {
    if (!enabled) return;

    /* 禁用右键菜单 */
    contextMenuHandler = (e: MouseEvent) => e.preventDefault();
    /* 禁用文本选中（输入框/文本域除外） */
    selectStartHandler = (e: Event) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag !== "INPUT" && tag !== "TEXTAREA") e.preventDefault();
    };
    /* 禁用 F12 / Ctrl+Shift+I/J/C / Ctrl+U */
    keydownHandler = (e: KeyboardEvent) => {
      if (e.key === "F12") e.preventDefault();
      if (e.ctrlKey && e.shiftKey && (e.key === "I" || e.key === "J" || e.key === "C")) {
        e.preventDefault();
      }
      if (e.ctrlKey && e.key === "u") e.preventDefault();
    };

    document.addEventListener("contextmenu", contextMenuHandler);
    document.addEventListener("selectstart", selectStartHandler);
    document.addEventListener("keydown", keydownHandler);
  });

  onBeforeUnmount(() => {
    if (contextMenuHandler) document.removeEventListener("contextmenu", contextMenuHandler);
    if (selectStartHandler) document.removeEventListener("selectstart", selectStartHandler);
    if (keydownHandler) document.removeEventListener("keydown", keydownHandler);
  });
}
