/**
 * app/launch-presentation-runtime.ts — 启动展示判定运行时
 *
 * 职责：读取系统启动时刻（Rust 只读命令）、对比持久化标记并返回本次
 *   启动应采用的展示形态。
 *
 * 失败策略（全部回退首映，绝不让启动判定阻塞或误跳过）：
 *   - 非 Tauri 环境（浏览器开发）→ 首映
 *   - IPC 失败或超过 300ms → 首映
 *   - 标记读取失败 / 写入失败 → 本次按判定执行，下次回退首映
 *
 * Why 在 bootstrap 挂载前完成判定：避免先渲染引导页再切换为直接进入，
 *   也避免直接进入路径出现一帧引导页闪烁。
 */

import { invoke } from "@tauri-apps/api/core";
import {
  decideLaunchPresentation,
  LAUNCH_BOOT_EPOCH_KEY,
  parseStoredBootEpoch,
  type LaunchPresentation,
} from "./launch-presentation";

/** 启动时刻查询上限：本地只读命令，300ms 已覆盖系统繁忙情形 */
export const BOOT_EPOCH_IPC_TIMEOUT_MS = 300;

/** Rust 启动时刻命令响应 */
interface BootEpochResponse {
  boot_epoch_ms: number;
  uptime_ms: number;
}

/** 为启动路径的 IPC 增加超时上限，避免窗口长时间停在未渲染状态 */
function invokeWithTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("verthys_boot_epoch 超时")), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

/** 读取上次启动时刻；不可用时返回 null（回退首映） */
function readStoredBootEpoch(): number | null {
  try {
    return parseStoredBootEpoch(window.localStorage.getItem(LAUNCH_BOOT_EPOCH_KEY));
  } catch {
    return null;
  }
}

/** 记录本次启动时刻；写入失败不阻断启动 */
function writeBootEpoch(bootEpochMs: number): void {
  try {
    window.localStorage.setItem(LAUNCH_BOOT_EPOCH_KEY, String(bootEpochMs));
  } catch {
    // 下次启动读不到标记时会回退首映，行为安全
  }
}

/** 判定本次启动的展示形态（任何异常均回退首映） */
export async function resolveLaunchPresentation(): Promise<LaunchPresentation> {
  // Tauri 注入的 IPC 桥是 invoke 的前置条件；浏览器开发环境直接回退首映
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) {
    return "ceremony";
  }

  let bootEpochMs: number | null = null;
  try {
    const response = await invokeWithTimeout(
      invoke<BootEpochResponse>("verthys_boot_epoch"),
      BOOT_EPOCH_IPC_TIMEOUT_MS,
    );
    const value = response?.boot_epoch_ms;
    if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) {
      bootEpochMs = value;
    }
  } catch {
    bootEpochMs = null;
  }

  const presentation = decideLaunchPresentation(bootEpochMs, readStoredBootEpoch());
  if (bootEpochMs !== null) writeBootEpoch(bootEpochMs);
  return presentation;
}
