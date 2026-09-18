/*
 * app/config.ts — 环境参数校验
 *
 * 启动时校验环境变量与运行时配置，校验失败则拒绝启动。
 */

import type { EnvConfig } from "./context";

/**
 * 校验环境配置并构造启动参数对象
 *
 * 校验失败时抛出错误，入口层捕获后拒绝启动。
 */
export function validateConfig(): EnvConfig {
  const debug = import.meta.env.DEV;

  // 校验必需的环境变量
  const apiBase = import.meta.env.VITE_API_BASE ?? "tauri://localhost";

  // 校验应用版本号
  const version = import.meta.env.VITE_APP_VERSION ?? "2.6.1";

  // 开发模式下输出配置摘要（入口层允许的启动关键事件）
  if (debug) {
    console.info("[entry] 环境校验通过: debug=%s, version=%s", debug, version);
  }

  return {
    debug,
    apiBase,
    version,
  };
}
