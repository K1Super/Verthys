/*
 * types/key_manager.ts — 密钥管理层统一类型定义
 *
 */
import type { SecurityPresetCode, BruteForceCheckResponse, PresetFeatures } from "./verthys";

/** 模块 ID 枚举（PasswordTools 故意排除） */
export type ModuleId = "photo" | "accounts" | "certs" | "fileverthys";

/** 模块密钥验证器记录（JSON）
 *
 * 版本化设计：
 *   version 字段用于「先添后删」事务的原子性保证。
 *   每次更新递增 version；findModuleKeyRecord 返回 version 最大者。
 *   旧记录（无 version 字段）反序列化时视为 v0。
 */
export interface ModuleKeyRecord {
  moduleId: string;
  verifierB64: string;
  /** 记录版本号，每次 setModuleKey 递增；旧记录为 0 */
  version?: number;
}

/** 模块会话状态（合并 moduleKeyReady + moduleKeyCache，原子化）
 *
 * 会话状态原子化
 *   合并 moduleKeyReady 与 moduleKeyCache 为单一响应式对象，
 *   verifyModuleKey 成功后原子设置，logoutModule 一次性清空，
 *   消除不一致窗口。
 */
export interface ModuleSession {
  /** 模块密钥已验证（会话中可用） */
  ready: boolean;
  /** 模块独立密钥（明文 Uint8Array，安全零填充可擦除；null 表示未登录） */
  key: Uint8Array | null;
}

/** 设备绑定操作结果
 *
 * 设备绑定解耦与可控化
 *   bindDevice 返回结构化结果，UI 层可展示提示并允许用户重试。
 */
export type DeviceBindingResult =
  | { ok: true; bound: true }
  | { ok: false; code: string; message: string };

/** 模块密钥保护开关记录（JSON） */
export interface ModuleKeyConfigRecord {
  moduleId: string;
  enabled: boolean;
}

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
  | { allowed: false; reason: "purge_required" };

/** verifyGlobalKeyWithBruteForce 返回类型 */
export type VerifyGlobalKeyResult =
  | { ok: true }
  | { ok: false; reason: "wrong_key" | "locked" | "purge_required" | "gate_locked" | "gate_purge_required"; remainingSecs?: number };

// Re-export verthys types for convenience
export type { SecurityPresetCode, BruteForceCheckResponse, PresetFeatures };
