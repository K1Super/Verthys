/*
 * cache/domain/module-cache.ts — 模块数据缓存与登录状态
 *
 * 只保存"本会话是否已通过模块口令"的状态位与跨路由的模块数据，
 * 不保存任何密钥；过期与锁定统一由全局会话空闲锁定触发，
 * 模块层不维护独立计时器。
 */
import type { ModuleId } from "../../types/key_manager";
// MODULE_IDS：权威模块表（constants 层零依赖，新增模块自动纳入密钥重置）
import { MODULE_IDS } from "../../constants/key_manager_const";
import type { KeyStateForCache } from "./cache-contracts";

export class ModuleCache {
  /** 模块数据缓存（跨路由/模块切换持久化，消除"先空后有"闪烁） */
  private readonly data = new Map<string, { data: unknown; recordId: number | null }>();

  constructor(private readonly keyState: KeyStateForCache) {}

  /** 读取模块缓存数据 */
  get<T>(key: string): { data: T | null; recordId: number | null } {
    const entry = this.data.get(key);
    return { data: (entry?.data as T) || null, recordId: entry?.recordId ?? null };
  }

  /** 写入模块缓存数据 */
  set<T>(key: string, value: T, recordId: number | null = null): void {
    this.data.set(key, { data: value, recordId });
  }

  /** 清空指定模块缓存（不传 key 则清空全部） */
  clear(key?: string): void {
    if (key) this.data.delete(key);
    else this.data.clear();
  }

  /** 标记模块已登录（口令已交付 worker；渲染层不保存原始密钥） */
  markReady(moduleId: ModuleId): void {
    this.keyState.moduleKeyReady.value[moduleId] = true;
  }

  /** 清除单个模块登录状态 */
  clearReady(moduleId: ModuleId): void {
    this.keyState.moduleKeyReady.value[moduleId] = false;
  }

  /** 清空全部模块登录状态（lockAll 时调用） */
  clearAllReady(): void {
    for (const moduleId of MODULE_IDS) {
      this.keyState.moduleKeyReady.value[moduleId] = false;
    }
  }
}
