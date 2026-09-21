/*
 * util/mod.rs — 工具层模块入口
 *
 * 分层架构（codebase-design 强制约束）：
 *   工具层是最底层，无日志权限，不引用上层模块。
 *   仅通过 pub 接口对外暴露纯函数与错误枚举。
 *
 * 禁止行为（CI 红线）：
 *   - use crate::controller::...
 *   - use crate::service::...
 *   - use crate::middleware::...  （例外：VerthysError 可被上层引用）
 *   - 任何 println! / eprintln! / log::* 调用
 *
 * 模块清单：
 *   - base64:    Base64 编解码（改用标准 base64 crate）
 *   - disk:      磁盘空间查询
 *   - error:     项目统一错误枚举 VerthysError / VerthysResult
 *   - ffi:       C FFI 调用辅助
 *   - path:      路径处理（输入硬校验 + canonicalize 全解析）
 *   - random:    随机字节生成（改用 getrandom crate，系统 CSPRNG）
 *   - crypto:    密码学工具（PBKDF2/DPAPI/HMAC/ct_eq）
 *   - audit_log: 审计日志（HMAC 链式防篡改）
 *   - sandbox:   路径沙箱（白名单基目录 + resolve_and_validate）
 */
pub mod base64;
pub mod disk;
pub mod error;
pub mod ffi;
pub mod path;
pub mod random;
/// 密码学工具（PBKDF2/DPAPI/HMAC/ct_eq）
pub mod crypto;
/// HMAC 链式防篡改审计日志
pub mod audit_log;
/// 路径沙箱白名单 + resolve_and_validate
pub mod sandbox;
/// 零化擦除的安全字符串包装（Zeroizing<String> + 透明 serde）
pub mod secured_string;
/// 日志敏感负载脱敏（白名单字段保留，其余值只留类型与规模）
pub mod log_sanitizer;
