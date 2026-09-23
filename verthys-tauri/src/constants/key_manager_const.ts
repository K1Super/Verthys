/*
 * constants/key_manager_const.ts — 密钥管理层统一常量
 *
 */
import type { SecurityPresetCode, PresetFeatures } from "../types/verthys";
import type { ModuleId } from "../types/key_manager";

/* Verthys 记录类型
 *
 * 修复：TYPE 常量统一到 constants/record_types.ts（单一真相源）
 *
 * 原缺陷：TYPE_GLOBAL_KEY=0x10 与 AccountVerthys.vue 局部定义的 TYPE_ACCOUNT=0x10
 * 值相同，导致全局密钥记录与账户记录互相误识，引发设置遗忘/密钥验证无效/
 * 增删改异常/删除后复活等一系列致命故障。
 *
 * 修复：全部记录类型常量集中到 record_types.ts 统一分配，确保全局唯一。
 * 此处改为 re-export，保持现有 import 路径向后兼容（module-auth.ts /
 * global-verthys.ts / keyManager.ts 等无需修改 import 语句）。
 */
export {
  TYPE_GLOBAL_KEY,
  TYPE_MODULE_KEY,
  TYPE_MODULE_KEY_CONFIG,
} from "./record_types";

/* 模块密钥记录版本化常量 */

/** 模块密钥记录当前版本号（每次 setModuleKey 写入此值）
 *
 * 旧记录（无 version 字段）反序列化时视为 v0。
 * 新记录写入 MODULE_KEY_RECORD_VERSION，每次更新递增。
 */
export const MODULE_KEY_RECORD_VERSION = 1;

/** 自愈清理任务的单次最大清理记录数（防止极端情况下批量清理阻塞）
 *
 * findModuleKeyRecord 发现多条同 moduleId 记录时，
 * 异步触发清理旧版本记录，单次最多清理此数量。
 */
export const MODULE_KEY_SELF_HEAL_BATCH = 10;

/* 模块枚举 */
export const MODULE_IDS: ModuleId[] = ["photo", "accounts", "certs", "fileverthys"];

export const MODULE_LABELS: Record<ModuleId, string> = {
  photo: "拾光",
  accounts: "存签",
  certs: "枢钥",
  fileverthys: "清藏",
};

/* 会话超时 */
export const SESSION_PRESET_MINUTES = [5, 10, 15, 30, 60] as const;

/** 各预设对应的会话空闲超时（毫秒） */
export const PRESET_SESSION_TIMEOUT_MS: Record<SecurityPresetCode, number> = {
  0: 30 * 60 * 1000, // BALANCED: 30 分钟
  1: 10 * 60 * 1000, // SECURE: 10 分钟
  2: 60 * 60 * 1000, // PERFORMANCE: 60 分钟
  3: 20 * 60 * 1000, // CUSTOM: 20 分钟
};

/* 模块密钥验证器明文 */
export const MODULE_KEY_VERIFIER_PREFIX = "VERTHYS_MODULE_KEY_";
export const MODULE_KEY_VERIFIER_SUFFIX = "_v1";

/* Verthys 默认密码 */
export const VERTHYS_DEFAULT_PASSWORD = "VERTHYS_DEFAULT_PASSWORD_v1";

/* 超时 */
export const INIT_TIMEOUT_MS = 30 * 1000;
export const CREATE_TIMEOUT_MS = 120 * 1000;

/* 分级超时熔断常量（前端调度层）
 *
 * 替代原固定 35s 单一超时阈值，区分可容忍的计算缓慢与不可容忍的 IO 卡死：
 *   - 软超时 15s：Argon2id 派生耗时过长，前端提示「密钥计算较慢，请耐心等待」继续执行
 *   - 硬超时 120s：整体解锁未完成，触发降级校验，仅保障核心数据可读
 *   - 熔断阈值 3：连续 3 次硬超时自动锁定容器，引导用户使用备份密钥恢复
 *
 * 修复修复（硬超时 35s → 120s）：
 *   原硬超时 35s 对 SECURE 预设（Argon2id 64MiB/3/1）在大 verthys 或低端 CPU 上
 *   不足以完成解锁（Argon2id 6~15s + B+树解密 + 摘要加载可能 20~40s），
 *   导致正常解锁被误判为超时失败。
 *
 *   真正的安全网是 worker 进程的进度感知空闲超时（60s 无进度 = 挂起）。
 *   C 层已添加 Argon2id 心跳进度（每 2s 推送）+ B+树中间进度回调，
 *   确保进度通道持续活跃，worker 空闲超时不会误触发。
 *   前端 120s 硬超时仅作为最终兜底（进程真正卡死时触发降级）。
 *
 * 熔断状态持久化于 localStorage，跨进程重启仍生效，避免攻击者通过重启绕过熔断。 */
export const UNLOCK_SOFT_TIMEOUT_MS = 15 * 1000;   // 软超时：15s 提示用户耐心等待
export const UNLOCK_HARD_TIMEOUT_MS = 120 * 1000;  // 硬超时：120s 降级校验（进度感知 worker 60s 空闲超时为真正安全网）
export const CIRCUIT_BREAKER_THRESHOLD = 3;        // 连续硬超时熔断阈值
export const CIRCUIT_BREAKER_LOCK_MS = 30 * 60 * 1000; // 熔断锁定时长：30 分钟
export const CIRCUIT_BREAKER_STORAGE_KEY = "verthys_unlock_circuit_breaker";

/* 自定义特性 localStorage key */
export const CUSTOM_FEATURES_KEY = "verthys_custom_security_features";

/* 当前安全预设代号 localStorage key（持久化用户选择的安全模式） */
export const SECURITY_PRESET_KEY = "verthys_security_preset";

/** C 层核心防护特性（固定 ON，不可关闭） */
export const LOCKED_FEATURES: ReadonlySet<string> = new Set([
  "anti_debug",
  "anti_inject",
  "integrity_check",
  "memory_guard",
  "key_separation",
  "emergency_response",
]);

/** 默认自定义特性 */
export const DEFAULT_CUSTOM_FEATURES: PresetFeatures = {
  anti_debug: true,
  anti_inject: true,
  integrity_check: true,
  memory_guard: true,
  key_separation: true,
  emergency_response: true,
  session_lock_on_idle: true,
  shadow_sleep: true,
  module_patrol: true,
  clip_clear_on_lock: true,
  usb_clone_detect: true,
  trace_cleanup: true,
};
