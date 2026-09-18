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
 *   - base64:    Base64 编解码（第 13.6 项，改用标准 base64 crate）
 *   - disk:      磁盘空间查询
 *   - error:     项目统一错误枚举 VerthysError / VerthysResult
 *   - ffi:       C FFI 调用辅助
 *   - path:      路径处理（第 3.8 项，输入硬校验 + canonicalize 全解析）
 *   - random:    随机字节生成（改用 getrandom crate，系统 CSPRNG）
 *   - crypto:    密码学工具（第 4.3/5.6/9.1/13.2 项，PBKDF2/DPAPI/HMAC/ct_eq）
 *   - audit_log: 审计日志（第 5.8/6.6/7.6/9.8/13.7/16.5 项，HMAC 链式防篡改）
 *   - sandbox:   路径沙箱（第 3.1/6.1 项，白名单基目录 + resolve_and_validate）
 */
pub mod base64;
pub mod disk;
pub mod error;
pub mod ffi;
pub mod path;
pub mod random;
/// 第 4.3/5.6/9.1/13.2 项：密码学工具（PBKDF2/DPAPI/HMAC/ct_eq）
pub mod crypto;
/// 第 5.8/6.6/7.6/9.8/13.7/16.5 项：HMAC 链式防篡改审计日志
pub mod audit_log;
/// 第 3.1/6.1 项：路径沙箱白名单 + resolve_and_validate
pub mod sandbox;
/// 第 11.1 项：零化擦除的安全字符串包装（Zeroizing<String> + 透明 serde）
pub mod secured_string;
