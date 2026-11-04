/**
 * diagnostic_logs.ts — 应用诊断日志导出
 *
 * 由开发工具选择导出位置，后端把 `logs/` 下的应用日志（含轮转历史）脱敏后
 * 打包为 zip。审计日志是 HMAC 链式文件，不由本入口导出。
 */
import { invoke, isTauri } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";

/** 开发工具选择保存位置并导出脱敏诊断日志；取消返回 null。 */
export async function exportAppLogs(): Promise<string | null> {
  if (!isTauri()) return null;
  const target = await save({
    title: "导出诊断日志",
    defaultPath: "verthys-diagnostics.zip",
    filters: [{ name: "ZIP 压缩包", extensions: ["zip"] }],
  });
  if (!target) return null;
  return await invoke<string>("diagnostics_export_logs", { targetPath: target });
}
