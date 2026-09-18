/*
 * app/bootstrap.ts — 应用启动控制器
 *
 * 职责：
 *   - 创建 Vue 应用实例
 *   - 挂载全局中间件（错误处理器、插件等）
 *   - 注册全局组件
 *   - 挂载至 DOM
 *
 * 此文件为"控制器层"，由入口 main.ts 调用，不含环境初始化逻辑。
 */

import { createApp, type App as VueApp } from "vue";
import App from "../App.vue";
import { vueErrorHandler } from "./error-handler";
import type { AppContext } from "./context";
import { vTip } from "../directives/vTip";

/**
 * 启动 Vue 应用
 *
 * 接收上下文参数（注入式传递），创建应用实例并挂载中间件。
 * 入口层调用此函数后，控制权完全移交至此处。
 *
 * ★ 缓存层组合根初始化（initVerthysCache）由 MainView.onBeforeMount 承担
 *   （v3 懒加载架构修复）：本文件属静态入口图（index chunk），静态导入
 *   verthys-cache 会将 keyManager→verthys→crypto 整个业务层（~77KB）拖入
 *   主包，破坏「引导页轻首屏 + MainView 业务层异步分包」架构。
 *   MainView 为异步 chunk（已含 verthys-cache 全依赖树），其 onBeforeMount
 *   先于全部子组件执行（父先于子挂载时序）——首个业务消费方运行前
 *   domain 必已装配，initVerthysCache 契约（幂等 + ensureDomain fail-fast）
 *   保持不变。
 */
export function bootstrap(ctx: AppContext): VueApp {

  const app = createApp(App);

  // ===== 挂载全局中间件 =====

  // 1. 全局错误处理器
  app.config.errorHandler = vueErrorHandler;

  // 2. 全局属性注入上下文（供组件通过 inject 访问）
  app.provide("appContext", ctx);

  // 3. 全局自定义指令：量子悬浮提示
  app.directive("tip", vTip);

  // 4. 性能优化：关闭生产环境性能追踪
  if (!ctx.config.debug) {
    app.config.performance = false;
  }

  // ===== 挂载至 DOM =====
  app.mount("#app");

  return app;
}
