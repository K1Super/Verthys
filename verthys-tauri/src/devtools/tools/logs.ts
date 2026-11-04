/*
 * devtools/tools/logs.ts — 日志导出工具
 *
 * 复用既有导出链路与脱敏逻辑，不在开发工具里重写打包或路径解析；
 * 非 Tauri 环境（仅 vite dev）没有后端命令，直接提示而不静默返回。
 */
import { isTauri } from "@tauri-apps/api/core";
import { useAppUpdater } from "../../composables/useAppUpdater";
import { exportAppLogs } from "../../lib/diagnostic_logs";
import { updaterErrorMessage } from "../../lib/updater_error";
import type { DevTool, DevToolContext } from "../registry";

function ensureTauri(ctx: DevToolContext): boolean {
  if (isTauri()) return true;
  ctx.error("需在 tauri dev 中运行");
  return false;
}

export const logTools: DevTool[] = [
  {
    id: "logs.diagnostics",
    group: "logs",
    kind: "action",
    label: "导出诊断日志",
    hint: "打包应用日志与审计链，路径与长哈希已脱敏",
    run: async (ctx) => {
      if (!ensureTauri(ctx)) return;
      const path = await exportAppLogs();
      if (path) ctx.notify(`诊断日志已导出：${path}`);
    },
  },
  {
    id: "logs.updater",
    group: "logs",
    kind: "action",
    label: "导出更新日志",
    hint: "打包更新事件日志，用于定位检查、校验或安装阶段失败",
    run: async (ctx) => {
      if (!ensureTauri(ctx)) return;

      const updater = useAppUpdater();
      const previousError = updater.lastErrorCode.value;
      const path = await updater.exportLogs();

      if (path) {
        ctx.notify(`更新日志已导出：${path}`);
        return;
      }
      /* 取消保存与失败都返回 null；仅在错误码变化时提示，避免陈旧错误误报 */
      if (updater.lastErrorCode.value && updater.lastErrorCode.value !== previousError) {
        ctx.error(updaterErrorMessage(updater.lastErrorCode.value));
      }
    },
  },
];
