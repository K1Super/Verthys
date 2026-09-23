/*
 * utils/invoke_wrapper.ts — 统一带超时的 Tauri invoke 包装
 *
 * 纯工具函数，不依赖任何业务逻辑或错误类型
 * 供 verthys.ts 所有 IPC 接口复用
 *
 * 二进制 IPC 扩展：
 *   - args 支持 ArrayBuffer / Uint8Array（raw body 直传，Tauri v2 raw IPC）
 *   - 新增 options（InvokeOptions.headers）：raw body 与 JSON args 互斥，
 *     附加参数（如目标路径 x-path）经请求头传递
 */

import { invoke, type InvokeOptions } from "@tauri-apps/api/core";
import { withTimeout } from "./promise_utils";

/**
 * 统一 Tauri invoke 包装函数（带可选超时）
 *
 * @param cmd Tauri 指令名
 * @param args 入参（camelCase 对象由 Tauri 自动转 snake_case；
 *             或 ArrayBuffer/Uint8Array 作为原始二进制请求体直传）
 * @param timeoutMs 可选超时（毫秒），不传则不设超时
 * @param options 可选 invoke 选项（headers 等，用于 raw IPC 的 x-path 传参）
 * @returns Tauri 返回值
 * @throws 原始错误（由调用方决定是否包装为 VerthysError）
 */
export async function invokeWithTimeout<T>(
  cmd: string,
  args?: Record<string, unknown> | ArrayBuffer | Uint8Array,
  timeoutMs?: number,
  options?: InvokeOptions,
): Promise<T> {
  const p = invoke<T>(cmd, args, options);
  if (timeoutMs !== undefined && timeoutMs > 0) {
    return withTimeout(p, timeoutMs, cmd);
  }
  return p;
}
