/*
 * 开发夹具配置客户端：只与 dev-only 命令交互，不持久化到 localStorage。
 *
 * 配置由 Rust 侧 DPAPI 加密保存；本模块只负责传输与类型约束。
 */
import { invoke, isTauri } from "@tauri-apps/api/core";

export interface DevFixtureProfile {
  schemaVersion: number;
  containerPath: string;
  containerKeyfilePath: string;
  globalPassword: string;
  binPassword: string;
  binKeyfilePath: string;
  moduleKeys: Record<string, string>;
  recoveryCode: string;
  updatedAt: string;
}

export interface DevFixtureFingerprints {
  global: string;
  bin: string;
  recovery: string;
  modules: Record<string, string>;
}

export interface DevFixtureProfileView {
  profile: DevFixtureProfile | null;
  fingerprints: DevFixtureFingerprints;
}

export interface DevFixtureStatus {
  enabled: boolean;
  reason: string;
  storeDir: string;
  profileExists: boolean;
}

export interface DevFixtureSaveOutcome {
  fingerprints: DevFixtureFingerprints;
  updatedAt: string;
}

function disabledStatus(reason: string): DevFixtureStatus {
  return {
    enabled: false,
    reason,
    storeDir: "",
    profileExists: false,
  };
}

export async function getFixtureStatus(): Promise<DevFixtureStatus> {
  if (!isTauri()) return disabledStatus("非 Tauri 环境");
  return invoke<DevFixtureStatus>("devfixture_status");
}

export async function getFixtureProfile(): Promise<DevFixtureProfileView> {
  if (!isTauri()) {
    return {
      profile: null,
      fingerprints: { global: "—", bin: "—", recovery: "—", modules: {} },
    };
  }
  return invoke<DevFixtureProfileView>("devfixture_profile_get");
}

export async function saveFixtureProfile(
  profile: DevFixtureProfile,
): Promise<DevFixtureSaveOutcome> {
  return invoke<DevFixtureSaveOutcome>("devfixture_profile_save", { profile });
}

export async function clearFixtureProfile(): Promise<boolean> {
  return invoke<boolean>("devfixture_profile_clear");
}
