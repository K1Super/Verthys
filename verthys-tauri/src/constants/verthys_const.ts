/*
 * constants/verthys_const.ts — Verthys IPC 层统一常量
 *
 * 与后端 Rust 枚举严格对齐，禁止单独修改
 */

import type { VerthysPreset, SecurityPresetCode } from "../types/verthys";

/* ------------------------------------------------------------------ *
 * 加密库 v2 安全预设                                                   *
 * ------------------------------------------------------------------ */

/** 平衡模式（日常推荐）：启用温启动缓存/文件监听/影子休眠 */
export const VERTHYS_PRESET_BALANCED: VerthysPreset = 0;
/** 高安全模式（涉密/合规）：禁用温启动缓存，锁定即内存绝对清零 */
export const VERTHYS_PRESET_SECURE: VerthysPreset = 1;

/* ------------------------------------------------------------------ *
 * 三档安全预设代号                                                     *
 *                                                                    *
 * BALANCED(0)：默认，启用温启动缓存/影子休眠/全部防护                *
 * SECURE(1)：高安全，禁用温启动缓存，锁定即内存绝对清零              *
 * PERFORMANCE(2)：仅保留核心防护，禁用高开销特性                     *
 * CUSTOM(3)：自定义模板，前端 localStorage 持久化                    *
 * ------------------------------------------------------------------ */

/** BALANCED（平衡模式，默认） */
export const SECURITY_PRESET_BALANCED: SecurityPresetCode = 0;
/** SECURE（高安全模式） */
export const SECURITY_PRESET_SECURE: SecurityPresetCode = 1;
/** PERFORMANCE（性能模式） */
export const SECURITY_PRESET_PERFORMANCE: SecurityPresetCode = 2;
/** CUSTOM（自定义模板，前端 localStorage 持久化） */
export const SECURITY_PRESET_CUSTOM: SecurityPresetCode = 3;
