/*
 * app/error-handler.ts — 全局异常兜底
 *
 * 职责（仅两项）：
 *   1. 捕获所有未处理致命错误，构造结构化错误信息
 *   2. 将错误信息投递至日志管道（前端通过 console + IPC）
 *
 * 不做业务补偿处理（重试、回滚等）。
 */
import { invoke } from "@tauri-apps/api/core";

/** 全局未捕获错误处理器 */
export function installGlobalErrorHandler(): void {
  // Vue 全局错误处理器
  // 在 bootstrap 中通过 app.config.errorHandler 挂载

  // window 级未捕获异常
  window.addEventListener("error", (event: ErrorEvent) => {
    reportFatal("window.error", event.message, event.error?.stack ?? "");
    // 不阻止默认行为，让开发者工具也能看到
  });

  // Promise 未捕获 rejection
  window.addEventListener("unhandledrejection", (event: PromiseRejectionEvent) => {
    const reason = event.reason;
    const message = typeof reason === "string" ? reason : reason?.message ?? String(reason);
    const stack = reason?.stack ?? "";
    reportFatal("unhandledrejection", message, stack);
  });
}

/** Vue 错误处理器（挂载到 app.config.errorHandler） */
export function vueErrorHandler(
  err: unknown,
  _instance: unknown,
  info: string,
): void {
  const message = err instanceof Error ? err.message : String(err);
  const stack = err instanceof Error ? err.stack ?? "" : "";
  reportFatal("vue.error", `${message} (info: ${info})`, stack);
}

/** 构造结构化致命错误并投递至日志管道 */
function reportFatal(source: string, message: string, stack: string): void {
  const entry = {
    timestamp: new Date().toISOString(),
    level: "FATAL",
    source,
    message,
    stack,
  };

  // 投递至日志管道（开发环境 console，生产环境通过 IPC 发送至后端日志管道）
  if (import.meta.env.DEV) {
    console.error("[FATAL]", entry);
  } else {
    // 生产环境：通过 Tauri IPC 投递至后端日志管道
    invoke("log_fatal", { entry: JSON.stringify(entry) }).catch(() => {
      // IPC 不可用时降级为 console（仅致命错误）
      console.error("[FATAL-IPC-FAIL]", entry);
    });
  }
}
