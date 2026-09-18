/*
 * utils/json_codec.ts — 通用 JSON ↔ base64 序列化工具
 *
 * 纯函数，无副作用，供 verthys.ts / serialization.ts 等共用
 * 消除各模块重复的 JSON.stringify + TextEncoder + bytesToBase64 样板
 */

import { bytesToBase64, base64ToBytes } from "./binary_codec";

/**
 * 将任意对象序列化为 base64 字符串
 * 流程：JSON.stringify → UTF-8 编码 → base64
 *
 * @param obj 待序列化对象
 * @returns base64 编码的 JSON 字符串
 */
export function serializeToJsonB64<T>(obj: T): string {
  const json = JSON.stringify(obj);
  const encoder = new TextEncoder();
  return bytesToBase64(encoder.encode(json));
}

/**
 * 将 base64 字符串反序列化为对象
 * 流程：base64 解码 → UTF-8 解码 → JSON.parse
 *
 * @param b64 base64 编码的 JSON 字符串
 * @returns 反序列化后的对象
 */
export function deserializeFromJsonB64<T>(b64: string): T {
  const bytes = base64ToBytes(b64);
  const decoder = new TextDecoder();
  const json = decoder.decode(bytes);
  return JSON.parse(json) as T;
}
