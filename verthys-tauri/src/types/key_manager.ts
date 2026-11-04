/*
 * types/key_manager.ts — 密钥管理层统一类型定义
 *
 */
import type { SecurityPresetCode, BruteForceCheckResponse, PresetFeatures } from "./verthys";

/** 模块 ID 枚举（PasswordTools 故意排除） */
export type ModuleId = "photo" | "accounts" | "fileverthys";

/** 设备绑定操作结果
 *
 * 设备绑定解耦与可控化
 *   bindDevice 返回结构化结果，UI 层可展示提示并允许用户重试。
 */
export type DeviceBindingResult =
  | { ok: true; bound: true }
  | { ok: false; code: string; message: string };

/** 扫描缓存中的记录条目 */
export interface ScannedRecord {
  id: number;
  type: number;
  name: string;
  dataB64: string;
}

/** 暴力拦截门禁检查结果 */
export type BruteForceGateResult =
  | { allowed: true }
  | { allowed: false; reason: "locked"; remainingSecs: number }
  | { allowed: false; reason: "purge_required" }
  | { allowed: false; reason: "gate_unavailable" };

/** verifyGlobalKeyWithBruteForce 返回类型 */
export type VerifyGlobalKeyResult =
  | { ok: true }
  | { ok: false; reason: "wrong_key" | "locked" | "purge_required" | "gate_locked" | "gate_purge_required" | "gate_unavailable"; remainingSecs?: number };

// Re-export verthys types for convenience
export type { SecurityPresetCode, BruteForceCheckResponse, PresetFeatures };
