/*
 * utils/binary_codec.ts — 二进制编解码工具
 *
 * 设计原则：
 *   - 纯函数，无副作用，无状态
 *   - 不依赖任何加密常量或错误类型，保持工具层独立性
 *   - 供 crypto.ts / verthys.ts / 其他模块共用，消除重复实现
 *
 */

/* ------------------------------------------------------------------ *
 * Hex 编解码                                                         *
 * ------------------------------------------------------------------ */

/**
 * 将十六进制字符串转换为 Uint8Array
 * @param hex 十六进制字符串（长度必须为偶数）
 * @returns 对应的字节数组
 * @throws Error 如果 hex 非法（空串、奇数长度、非 hex 字符）
 */
export function hexToBytes(hex: string): Uint8Array {
  if (!hex || hex.length === 0) {
    throw new Error("hex 字符串为空");
  }
  if (hex.length % 2 !== 0) {
    throw new Error(`hex 长度非法（奇数）: ${hex.length}`);
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("hex 包含非法字符");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * 将 Uint8Array 转换为十六进制字符串
 * @param bytes 字节数组
 * @returns 小写十六进制字符串
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * 校验字符串是否为合法的十六进制
 * @param hex 待校验字符串
 * @returns true 表示合法
 */
export function isValidHex(hex: string): boolean {
  if (!hex || hex.length === 0 || hex.length % 2 !== 0) return false;
  return /^[0-9a-fA-F]*$/.test(hex);
}

/* ------------------------------------------------------------------ *
 * ArrayBuffer 转换                                                    *
 * ------------------------------------------------------------------ */

/**
 * Uint8Array → ArrayBuffer（类型安全转换）
 *
 * 避免 SharedArrayBuffer 问题：slice 返回独立的 ArrayBuffer 副本，
 * 确保 Web Crypto API 接受输入。
 *
 * @param buf Uint8Array 视图
 * @returns 独立的 ArrayBuffer
 */
export function toArrayBuffer(buf: Uint8Array): ArrayBuffer {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/* ------------------------------------------------------------------ *
 * Base64 编解码（二进制 ↔ 字符串）                                    *
 *                                                                    *
 * 供 crypto.ts / verthys.ts / serialization.ts 等共用，                *
 * 消除各模块重复的 btoa/atob 样板                                     *
 * ------------------------------------------------------------------ */

/**
 * 将 Uint8Array 转换为 base64 字符串
 * @param bytes 字节数组
 * @returns base64 编码字符串
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * 将 base64 字符串转换为 Uint8Array
 * @param b64 base64 编码字符串
 * @returns 字节数组
 */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
