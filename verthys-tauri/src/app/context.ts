/*
 * app/context.ts — 前端进程级上下文容器
 *
 * 持有全局配置与中间件引用，通过参数注入至各分层。
 * 不设计为全局静态变量。
 */

/** 环境配置（启动时校验） */
export interface EnvConfig {
  /** 是否调试模式 */
  readonly debug: boolean;
  /** API 基础路径 */
  readonly apiBase: string;
  /** 应用版本号 */
  readonly version: string;
}

/** 前端上下文容器 */
export class AppContext {
  private readonly _config: EnvConfig;

  constructor(config: EnvConfig) {
    this._config = config;
  }

  get config(): EnvConfig {
    return this._config;
  }
}
