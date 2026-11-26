/*
 * 开发日志面板客户端：只调用 dev-only 日志尾部读取命令。
 *
 * 命令在发布构建中直接拒绝；本模块只由 DevDock 动态加载，不进入产物。
 */
import { invoke, isTauri } from "@tauri-apps/api/core";

export type DevLogSource = "all" | "main_ui" | "worker" | "inspector";

export interface DevLogLine {
  timestamp: string;
  level: string;
  pid: number;
  module: string;
  message: string;
  processName: string;
}

export interface DevLogTail {
  logDir: string;
  lines: DevLogLine[];
}

const EMPTY_TAIL: DevLogTail = { logDir: "", lines: [] };

export async function tailDevLogs(
  process: DevLogSource,
  maxLines = 200,
): Promise<DevLogTail> {
  if (!isTauri()) return EMPTY_TAIL;
  return invoke<DevLogTail>("diagnostics_tail_logs", { process, maxLines });
}
