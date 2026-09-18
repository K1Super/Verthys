/*
 * lib/crypto_error.ts — 加密层标准化错误封装
 *
 * 设计原则：
 *   - 细分错误类型，替代原生模糊 Error，便于上层精准捕获与用户提示
 *   - 所有加密/解密入口抛出 CryptoError，而非原生 Error
 *   - 继承 Error，天然兼容全局异常兜底钩子（app/error-handler.ts）
 *   - 底层加密工具禁止任何 console 打印，仅抛出标准化错误
 *
 * 错误类型映射：
 *   INVALID_INPUT           → 空密码、非法 hex、Salt/Nonce 长度不符
 *   KEY_DERIVATION_FAILED   → PBKDF2/HKDF 派生异常
 *   TAG_VERIFICATION_FAILED → Poly1305 标签校验失败（密钥错误或数据被篡改）
 *   FORMAT_CORRUPTED        → .venc 格式损坏（数据截断、结构非法）
 *   HASH_MISMATCH           → BLAKE3 哈希不匹配
 *   UNSUPPORTED_VERSION     → .venc 版本不受支持
 *
 */

/* ------------------------------------------------------------------ *
 * 错误类型枚举                                                        *
 * ------------------------------------------------------------------ */

export enum CryptoErrorKind {
  /** 入参非法（空密码、非法 hex、长度不符） */
  INVALID_INPUT = "INVALID_INPUT",
  /** 密钥派生异常（PBKDF2/HKDF 失败） */
  KEY_DERIVATION_FAILED = "KEY_DERIVATION_FAILED",
  /** 标签校验失败（Poly1305 认证未通过） */
  TAG_VERIFICATION_FAILED = "TAG_VERIFICATION_FAILED",
  /** 格式损坏（.venc 结构非法或数据截断） */
  FORMAT_CORRUPTED = "FORMAT_CORRUPTED",
  /** 哈希不匹配（BLAKE3 完整性校验失败） */
  HASH_MISMATCH = "HASH_MISMATCH",
  /** 不支持的版本（.venc 版本号超出支持范围） */
  UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION",
}

/* ------------------------------------------------------------------ *
 * 标准化错误类                                                        *
 * ------------------------------------------------------------------ */

/**
 * 加密层统一错误类型
 *
 * 继承 Error，天然被 app/error-handler.ts 的全局兜底捕获。
 * 上层可通过 `instanceof CryptoError` 判断错误来源，
 * 通过 `err.kind` 获取具体错误类型进行差异化处理。
 */
export class CryptoError extends Error {
  /** 错误类型枚举 */
  readonly kind: CryptoErrorKind;
  /** 原始异常（用于调试，不暴露给用户） */
  readonly cause?: unknown;

  constructor(kind: CryptoErrorKind, message: string, cause?: unknown) {
    super(`[${kind}] ${message}`);
    this.name = "CryptoError";
    this.kind = kind;
    this.cause = cause;
  }
}

/* ------------------------------------------------------------------ *
 * 错误构造工厂函数（简化调用方代码）                                  *
 * ------------------------------------------------------------------ */

/** 构造入参非法错误 */
export function invalidInput(message: string, cause?: unknown): CryptoError {
  return new CryptoError(CryptoErrorKind.INVALID_INPUT, message, cause);
}

/** 构造密钥派生失败错误 */
export function keyDerivationFailed(message: string, cause?: unknown): CryptoError {
  return new CryptoError(CryptoErrorKind.KEY_DERIVATION_FAILED, message, cause);
}

/** 构造标签校验失败错误 */
export function tagVerificationFailed(message: string, cause?: unknown): CryptoError {
  return new CryptoError(CryptoErrorKind.TAG_VERIFICATION_FAILED, message, cause);
}

/** 构造格式损坏错误 */
export function formatCorrupted(message: string, cause?: unknown): CryptoError {
  return new CryptoError(CryptoErrorKind.FORMAT_CORRUPTED, message, cause);
}

/** 构造哈希不匹配错误 */
export function hashMismatch(message: string, cause?: unknown): CryptoError {
  return new CryptoError(CryptoErrorKind.HASH_MISMATCH, message, cause);
}

/** 构造不支持的版本错误 */
export function unsupportedVersion(message: string, cause?: unknown): CryptoError {
  return new CryptoError(CryptoErrorKind.UNSUPPORTED_VERSION, message, cause);
}

/* ------------------------------------------------------------------ *
 * 错误包装工具                                                        *
 * ------------------------------------------------------------------ */

/**
 * 将原生 Error 包装为 CryptoError
 *
 * 若原错误已是 CryptoError 则原样返回，避免双重包装。
 * 用于捕获 noble-ciphers / Web Crypto API 抛出的模糊 Error。
 *
 * @param err 原始错误
 * @param kind 目标错误类型
 * @param fallbackMessage 包装失败时的兜底消息
 */
export function wrapAsCryptoError(
  err: unknown,
  kind: CryptoErrorKind,
  fallbackMessage: string,
): CryptoError {
  if (err instanceof CryptoError) return err;
  const detail = err instanceof Error ? err.message : String(err);
  return new CryptoError(kind, `${fallbackMessage} (${detail})`, err);
}
