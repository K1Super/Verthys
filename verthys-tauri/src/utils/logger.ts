/*
 * utils/logger.ts — 环境感知日志工具
 *
 * 落实白皮书 2.2 方案五、4.3 统一日志工具：
 *   - 根据 import.meta.env.MODE 控制日志级别
 *   - 开发环境（MODE=development）：输出 debug/info/warn/error
 *   - 生产环境（MODE=production）：仅输出 error（避免污染控制台、影响 Tauri 后端性能）
 *   - 所有业务模块使用 createLogger(moduleName) 替换原生 console
 *
 * 性能考量：
 *   - isDev 在模块加载时计算一次，避免每次日志调用重复判断
 *   - debug/info 在生产环境通过空函数实现，V8 内联后零开销
 *   - 字符串拼接延迟到日志函数内部（生产环境直接跳过）
 *
 * 使用示例：
 *   import { createLogger } from "../utils/logger";
 *   const log = createLogger("global-verthys");
 *   log.info("解锁成功");              // 输出：[global-verthys] 解锁成功
 *   log.error("派生失败", e);          // 输出：[global-verthys] 派生失败 Error(...)
 */

type LogLevel = "debug" | "info" | "warn" | "error";

/**
 * 当前环境是否为开发模式（模块加载时计算一次）
 *
 * Tauri + Vite 环境下 import.meta.env.MODE 由 Vite 注入：
 *   - vite dev → MODE = "development"
 *   - vite build → MODE = "production"
 *
 * 兼容性：若 import.meta.env 不存在（极端情况），默认按生产环境处理（仅 error 输出）
 */
const isDev: boolean =
  typeof (import.meta as any).env !== "undefined" &&
  (import.meta as any).env?.MODE === "development";

/** 日志级别权重（用于运行时级别过滤） */
const LEVEL_WEIGHT: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

/** 生产环境最低输出级别 */
const PROD_MIN_LEVEL: LogLevel = "error";

/** 判断某级别是否允许输出 */
function shouldLog(level: LogLevel): boolean {
  if (isDev) return true;
  return LEVEL_WEIGHT[level] >= LEVEL_WEIGHT[PROD_MIN_LEVEL];
}

/** Logger 接口：与 console 同源的 4 个级别 */
export interface Logger {
  debug(...args: unknown[]): void;
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
}

/**
 * 创建带模块前缀的日志器
 *
 * @param moduleName 模块名（如 "global-verthys"、"module-auth"、"cache-coordinator"）
 * @returns Logger 实例，所有输出自动带 `[moduleName]` 前缀
 *
 * 使用示例：
 *   const log = createLogger("global-verthys");
 *   log.info("解锁成功");  // 输出：[global-verthys] 解锁成功
 */
export function createLogger(moduleName: string): Logger {
  const prefix = `[${moduleName}]`;

  return {
    debug(...args: unknown[]): void {
      if (shouldLog("debug")) {
        console.debug(prefix, ...args);
      }
    },
    info(...args: unknown[]): void {
      if (shouldLog("info")) {
        console.info(prefix, ...args);
      }
    },
    warn(...args: unknown[]): void {
      if (shouldLog("warn")) {
        console.warn(prefix, ...args);
      }
    },
    error(...args: unknown[]): void {
      // error 级别始终输出（即使生产环境也需要捕获致命错误）
      if (shouldLog("error")) {
        console.error(prefix, ...args);
      }
    },
  };
}

/**
 * 全局默认日志器（无模块归属的工具函数使用）
 * 模块业务代码应优先使用 createLogger(moduleName) 创建专属日志器
 */
export const log: Logger = createLogger("verthys");

/** 查询当前是否为开发环境（供业务代码条件分支使用） */
export function isDevelopment(): boolean {
  return isDev;
}
