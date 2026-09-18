/*
 * utils/serialization.ts — 密钥记录序列化工具
 *
 * 职责：ModuleKeyRecord / ModuleKeyConfigRecord 的 JSON ↔ base64 序列化
 * 不含任何业务逻辑，纯函数
 */
import { bytesToBase64, base64ToBytes } from "./binary_codec";
import type { ModuleKeyRecord, ModuleKeyConfigRecord } from "../types/key_manager";
import {
  MODULE_KEY_VERIFIER_PREFIX,
  MODULE_KEY_VERIFIER_SUFFIX,
  MODULE_KEY_RECORD_VERSION,
} from "../constants/key_manager_const";
import type { ModuleId } from "../types/key_manager";

/** 序列化模块密钥验证器记录为 base64
 *
 * ★ 白皮书 3.2 方案三：版本化
 *   确保 version 字段存在（旧调用方可能不传），默认写入 MODULE_KEY_RECORD_VERSION。
 */
export function serializeModuleKeyRecord(rec: ModuleKeyRecord): string {
  const enc = new TextEncoder();
  // 确保 version 字段存在（向后兼容旧调用方）
  const full: ModuleKeyRecord = {
    moduleId: rec.moduleId,
    verifierB64: rec.verifierB64,
    version: rec.version ?? MODULE_KEY_RECORD_VERSION,
  };
  return bytesToBase64(enc.encode(JSON.stringify(full)));
}

/** 反序列化模块密钥验证器记录
 *
 * ★ 白皮书 3.2 方案三：版本化向后兼容
 *   旧记录无 version 字段 → 反序列化时视为 v0。
 */
export function deserializeModuleKeyRecord(b64: string): ModuleKeyRecord | null {
  try {
    const dec = new TextDecoder();
    const json = dec.decode(base64ToBytes(b64));
    const rec = JSON.parse(json) as ModuleKeyRecord;
    if (!rec || typeof rec.moduleId !== "string" || typeof rec.verifierB64 !== "string") {
      return null;
    }
    // 向后兼容：旧记录无 version 字段 → 视为 v0
    return {
      moduleId: rec.moduleId,
      verifierB64: rec.verifierB64,
      version: typeof rec.version === "number" ? rec.version : 0,
    };
  } catch {
    return null;
  }
}

/** 序列化模块密钥保护开关记录为 base64 */
export function serializeModuleKeyConfigRecord(rec: ModuleKeyConfigRecord): string {
  const enc = new TextEncoder();
  return bytesToBase64(enc.encode(JSON.stringify(rec)));
}

/** 反序列化模块密钥保护开关记录 */
export function deserializeModuleKeyConfigRecord(b64: string): ModuleKeyConfigRecord | null {
  try {
    const dec = new TextDecoder();
    const json = dec.decode(base64ToBytes(b64));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/** 生成模块密钥验证器明文（固定常量，按模块 ID 区分） */
export function moduleVerifierPlain(moduleId: ModuleId): string {
  return MODULE_KEY_VERIFIER_PREFIX + moduleId + MODULE_KEY_VERIFIER_SUFFIX;
}
