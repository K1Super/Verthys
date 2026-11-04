/*
 * devtools/tools/environment.ts — 环境信息与界面动作
 *
 * 环境读取保持只读；重载属于不可逆的界面状态丢弃，必须先二次确认。
 */
import { isTauri } from "@tauri-apps/api/core";
import type { DevTool } from "../registry";

export const environmentTools: DevTool[] = [
  {
    id: "environment.info",
    group: "environment",
    kind: "info",
    label: "运行环境",
    hint: "构建模式、运行载体、视口与客户端标识",
    read: () => ({
      版本: import.meta.env.VITE_APP_VERSION ?? "unknown",
      构建模式: import.meta.env.MODE,
      运行载体: isTauri() ? "Tauri" : "Browser",
      视口: `${window.innerWidth} × ${window.innerHeight}`,
      像素比: window.devicePixelRatio,
      客户端: navigator.userAgent,
    }),
  },
  {
    id: "actions.reload",
    group: "actions",
    kind: "action",
    label: "重载界面",
    hint: "丢弃未保存的界面状态并重新加载",
    tone: "danger",
    run: () => {
      if (!window.confirm("重载界面？未保存的界面状态会丢失")) return;
      window.location.reload();
    },
  },
];
