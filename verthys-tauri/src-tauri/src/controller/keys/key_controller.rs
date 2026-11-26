/*
 * @file controller/key_controller.rs
 * @brief GMK 派生与验证控制器
 *
 * 本模块提供全局主密钥（GMK）的派生、验证、子密钥派生及内存清零能力。
 * 所有敏感操作（密码处理、PBKDF2 计算）均在 worker 子进程中执行，
 * 主进程仅负责指令转发与状态管理，绝不接触密钥明文。
 *
 * =============================================================================
 * 安全设计
 * =============================================================================
 * - 密码零化：密码以 `Zeroizing<String>` 接收，序列化后立即擦除，确保
 *   密码明文不在主进程内存中驻留。
 * - 状态机约束：密钥生命周期严格遵循 NoKey → Locked → Unlocked 状态转移，
 *   非法状态转换返回 KEY_STATE_MISMATCH。
 * - 防暴力破解：连续验证失败 5 次触发指数冷却（2s → 60s 上限），
 *   冷却期内拒绝验证请求，返回 RATE_LIMITED。
 * - 输入硬校验：密码 ≤512 字节，Base64 数据 ≤4KB，module_id 限 [a-zA-Z0-9_-]{1,64}，
 *   防止 DoS 与注入。
 * - 操作超时：派生/验证 15 秒（PBKDF2 密集计算），清零 2 秒（轻量），
 *   超时后丢弃响应并告警。
 * - 审计日志：每次密钥操作（派生/验证/清零/子密钥）记录操作类型、结果及
 *   上下文（不含密钥），用于异常追溯。
 * - 密码复杂度：派生时校验密码长度与字符种类，不符合返回
 *   PASSWORD_COMPLEXITY_INSUFFICIENT。
 *
 * =============================================================================
 * 子模块边界
 * =============================================================================
 *   op_lock    密钥操作互斥守卫与忙提示文案
 *   validation 口令/Base64 输入校验与密钥审计写入
 *   requests   借用式请求体与派生类命令公共前置检查
 *   derive     派生并持久化 GMK 命令
 *   verify     验证 GMK 命令
 *   clear      清零、存在状态协调与强制复位命令
 *   tests      输入校验、超时常量、状态机与互斥行为单元测试
 *
 * =============================================================================
 * 依赖方向
 * =============================================================================
 * controller → state / controller::types / controller::api_error /
 *             infrastructure::audit / util::audit_log / util::crypto / util::base64 / constants
 */

mod clear;
mod derive;
mod op_lock;
mod requests;
mod validation;
mod verify;

#[cfg(test)]
mod tests;

use crate::constants::timeout::DEFAULT as TIMEOUT_CONFIG;
use std::time::Duration;

// ===== 超时常量 =====

/// 派生/验证超时（15 秒），适配 PBKDF2 密集计算。
const DERIVE_VERIFY_TIMEOUT: Duration = TIMEOUT_CONFIG.derive_verify;

/// 清零超时（2 秒），轻量内存擦除操作。
const CLEAR_TIMEOUT: Duration = TIMEOUT_CONFIG.clipboard_op;

// ===== 对外命令与共享入口 =====

pub use clear::{
    verthys_clear_global_key, verthys_reconcile_key_presence, verthys_reset_global_key_state,
};
pub use derive::verthys_derive_and_store_global_key;
pub use verify::verthys_verify_global_key;

pub(crate) use validation::{
    decode_and_validate_b64, validate_password_complexity, validate_password_length,
    write_key_audit,
};
