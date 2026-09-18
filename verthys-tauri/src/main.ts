/*
 * main.ts — 前端入口文件
 *
 * 入口文件仅允许的 6 项职责：
 *   1. 全局执行环境初始化
 *   2. 解析并校验命令行参数与配置文件
 *   3. 创建进程级别的上下文容器
 *   4. 创建本进程私有的核心资源句柄
 *   5. 调用对应的控制器入口方法
 *   6. 注册全局异常兜底钩子
 *
 * 严格禁止：
 *   - 直接执行 createApp / mount 等视图初始化逻辑
 *   - 直接调用底层工具库而不通过控制器
 *   - 使用 console.log 等输出（调试除外，上线前移除）
 *   - 捕获异常并做业务补偿处理
 */

// ===== 步骤 1: 全局执行环境初始化 =====
// 全局CSS统一引入（设计令牌 → 复用组件 → 动画关键帧 → 空闲治理）
import "./styles/tokens.css";
import "./styles/components.css";
import "./styles/animations.css";
// ★ 空闲 CSS 动画治理（idle-*/glass-calm/reduce-motion 根类规则，置于最后覆盖）
import "./styles/idle-governance.css";

import { validateConfig } from "./app/config";
import { AppContext } from "./app/context";
import { installGlobalErrorHandler } from "./app/error-handler";
import { bootstrap } from "./app/bootstrap";
import { installGcHelper } from "./utils/gc";

/**
 * 前端进程入口
 *
 * 仅执行 6 项合法职责，不包含任何视图渲染/业务逻辑。
 */
function main(): void {
  // ===== 步骤 1: 全局执行环境初始化 =====
  // 全局CSS已在文件顶部引入（tokens → components → animations）
  // Vue 运行时由 Vite 自动初始化，无需手动设置

  // ===== 项12：V8 GC 辅助工具安装 =====
  // 桥接 --expose-gc 暴露的原生 gc() 到 window.gc，
  // 供模块卸载/切换时主动触发 Major GC，减少 Stop-The-World 暂停。
  // 必须在 Vue 应用创建之前调用，确保后续 onUnmounted/watch 可用。
  installGcHelper();

  // ===== 步骤 2: 解析并校验环境参数 =====
  const config = validateConfig();

  // ===== 步骤 3: 创建进程级上下文容器 =====
  const ctx = new AppContext(config);

  // ===== 步骤 6: 注册全局异常兜底钩子 =====
  installGlobalErrorHandler();

  // ===== 步骤 4: 创建本进程私有核心资源 =====
  // （前端无数据库连接池/CNG句柄等资源，上下文即为唯一资源）

  // ===== 步骤 5: 调用控制器入口方法，移交控制权 =====
  bootstrap(ctx);
}

main();
