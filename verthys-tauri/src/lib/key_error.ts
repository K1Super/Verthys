/*
 * lib/key_error.ts — 密钥管理层标准化错误封装
 *
 * 设计原则：
 *   - 细分业务错误类型，替代原生模糊 Error
 *   - 继承 Error，兼容全局异常兜底钩子（app/error-handler.ts）
 *   - 底层仅抛出标准化错误，仅顶层允许 console 警告日志
 *
 * 错误类型映射：
 *   KEY_ERROR           → 密钥错误（验证失败/密钥不匹配）
 *   BRUTE_FORCE_LOCKED  → 暴力拦截锁定
 *   SESSION_TIMEOUT     → 会话超时
 *   VERTHYS_CORRUPTED     → 文件损坏/格式非法
 *   VERTHYS_NOT_READY     → 加密库未解锁
 *   IPC_FAILED          → Tauri IPC 调用失败
 */

export enum KeyErrorKind {
  KEY_ERROR = "KEY_ERROR",
  BRUTE_FORCE_LOCKED = "BRUTE_FORCE_LOCKED",
  SESSION_TIMEOUT = "SESSION_TIMEOUT",
  VERTHYS_CORRUPTED = "VERTHYS_CORRUPTED",
  VERTHYS_NOT_READY = "VERTHYS_NOT_READY",
  IPC_FAILED = "IPC_FAILED",
}

export class KeyError extends Error {
  readonly kind: KeyErrorKind;
  readonly cause?: unknown;

  constructor(kind: KeyErrorKind, message: string, cause?: unknown) {
    super(`[${kind}] ${message}`);
    this.name = "KeyError";
    this.kind = kind;
    this.cause = cause;
  }
}

export function keyError(message: string, cause?: unknown): KeyError {
  return new KeyError(KeyErrorKind.KEY_ERROR, message, cause);
}

export function bruteForceLocked(message: string, cause?: unknown): KeyError {
  return new KeyError(KeyErrorKind.BRUTE_FORCE_LOCKED, message, cause);
}

export function sessionTimeout(message: string, cause?: unknown): KeyError {
  return new KeyError(KeyErrorKind.SESSION_TIMEOUT, message, cause);
}

export function verthysCorrupted(message: string, cause?: unknown): KeyError {
  return new KeyError(KeyErrorKind.VERTHYS_CORRUPTED, message, cause);
}

export function verthysNotReady(message: string, cause?: unknown): KeyError {
  return new KeyError(KeyErrorKind.VERTHYS_NOT_READY, message, cause);
}

export function ipcFailed(message: string, cause?: unknown): KeyError {
  return new KeyError(KeyErrorKind.IPC_FAILED, message, cause);
}

export function wrapAsKeyError(err: unknown, kind: KeyErrorKind, fallbackMessage: string): KeyError {
  if (err instanceof KeyError) return err;
  const detail = err instanceof Error ? err.message : String(err);
  return new KeyError(kind, `${fallbackMessage} (${detail})`, err);
}
