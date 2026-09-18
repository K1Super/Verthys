/*
 * utils/tauri_env.ts — Tauri 环境判断工具
 *
 */

/** 判断当前是否运行在 Tauri 环境中（非浏览器模式） */
export function isTauriEnvironment(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
