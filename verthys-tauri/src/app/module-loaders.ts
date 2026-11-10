/**
 * module-loaders — 模块分包加载器注册表
 *
 * 职责：
 *   1. 集中声明各导航模块的动态导入说明符（唯一权威源）
 *   2. 缓存加载 Promise，使预热、意图预取与导航提交共享同一次加载
 *   3. 加载失败时清除缓存，允许后续点击重试
 *
 * Why：模块舞台的异步组件、空闲期预热与点击前就绪等待若各自持有导入
 *   说明符，会形成多次独立加载与解析；点击时仍要等待“加载 → 解析 → 执行”
 *   全部落在交互帧内，表现为进入模块前的停顿。三者共享同一份 Promise
 *   后，预热完成即代表组件可立即解析，点击不再承担分包成本。
 *
 * 约束：本模块只允许动态导入组件，禁止静态导入任何业务模块，否则会把
 *   懒加载分包并回主包并破坏首屏体积。
 */

import type { AsyncComponentLoader, Component } from "vue";

/** 导航模块标识（与导航模块列表的 id 一一对应） */
export type ModuleNavId = "accounts" | "photos" | "verthys" | "tools" | "security";

/** 各模块分包的动态导入说明符 */
export const MODULE_LOADERS: Record<ModuleNavId, AsyncComponentLoader> = {
  accounts: () => import("../components/modules/AccountVerthys.vue"),
  photos: () => import("../components/modules/PhotoAlbum.vue"),
  verthys: () => import("../components/modules/FileVerthys.vue"),
  tools: () => import("../components/modules/PasswordTools.vue"),
  security: () => import("../components/modules/SecurityCenter.vue"),
};

/** 预热顺序：按进入概率排序，中枢为最高频入口 */
export const MODULE_WARM_ORDER: readonly ModuleNavId[] = [
  "security",
  "accounts",
  "photos",
  "verthys",
  "tools",
];

type LoadedModule = Component | { default: Component };

/** 已发起（含进行中）的加载过程；失败即删除，避免命中已拒绝的 Promise */
const pendingLoads = new Map<ModuleNavId, Promise<LoadedModule>>();

/** 启动或复用指定模块分包的加载 */
export function loadModule(id: ModuleNavId): Promise<LoadedModule> {
  const cached = pendingLoads.get(id);
  if (cached) return cached;
  const load = MODULE_LOADERS[id]().catch((error) => {
    pendingLoads.delete(id);
    throw error;
  });
  pendingLoads.set(id, load);
  return load;
}

/** 等待指定模块分包就绪；失败不抛出，由异步组件在渲染时自行重试 */
export async function ensureModuleLoaded(id: ModuleNavId): Promise<void> {
  try {
    await loadModule(id);
  } catch {
    // 预热/守候失败不阻断导航：异步组件渲染时会再度尝试并呈现其错误路径
  }
}

/** 判定字符串是否为已知导航模块标识 */
export function isModuleNavId(id: string): id is ModuleNavId {
  return Object.prototype.hasOwnProperty.call(MODULE_LOADERS, id);
}
