/*
 * security_commands/mod.rs — 安全防护模块的 Tauri 命令层（第 13 章全量重写版）
 *
 *    "优化.md" 第十三章 — 企业级解决方案（13.1-13.8）
 *
 * 重写要点：
 *   13.2.1 — 命令层操作许可与路径白名单：文件系统命令不再接收前端路径，
 *            改为逻辑标识符（"verthys_dir"/"temp_dir"/"data_dir"），由后端
 *            从受信上下文解析。install_dir 从 current_exe 获取。
 *   13.2.2 — 暴力拦截 DPAPI 加密持久化：BruteForceGuard 状态写入 DPAPI
 *            加密文件，应用启动时加载，防止重启绕过。
 *   13.2.3 — 异步任务 + 信令分离：耗时操作（磁盘清理/ACL 加固/设备查询）
 *            使用 spawn_blocking，Mutex 仅保护快速状态读写。
 *   13.2.4 — 锁中毒自愈：获取锁时检测中毒，into_inner() 取出后废弃，
 *            重置为新实例并记录严重告警。
 *   13.2.5 — 命令权限分级与抗重放：敏感操作（record_success/clear_purge/
 *            set_high_security）要求携带一次性 auth_token，且检查 KeyLifecycle。
 *   13.2.6 — 使用 base64 crate 替换自编 Base64 实现。
 *   13.2.7 — 统一结构化审计日志：每个安全命令执行时记录审计事件。
 *   13.2.8 — 修复会话守卫与影子休眠：session_start 要求真实 HWND，
 *            shadow_status 返回真实 txid，影子休眠 DPAPI 绑定会话。
 *
 * 模块结构：
 *   - state：安全全局状态 + 锁中毒自愈（13.2.2 / 13.2.4 / 13.2.5）
 *   - responses：响应类型定义（含 #[derive(serde::Serialize, TS)]）
 *   - persistence：DPAPI 加密状态持久化层（13.2.2 / SECURITY.md 1/3/5）
 *   - auth：一次性权限令牌（13.2.5）
 *   - audit：结构化审计日志（13.2.7）
 *   - path_resolver：路径白名单解析（13.2.1）
 *   - commands：Tauri 命令分组
 *       1. brute_force：check / record_failure / record_success / clear_purge / status
 *       2. session：start / stop / set_high_security
 *       3. module_whitelist：patrol / add_trusted_path / clear_trusted_paths
 *       4. cleanup：clear_recent / secure_delete / cleanup_crash_residue
 *       5. file_lock：harden_private_dir
 *       6. usb：read_serial / register_device / check_clone /
 *          shadow_sleep / try_recover / purge / shadow_status
 *       7. preset：get_preset_config
 *       8. auth：generate_auth_token
 */

pub mod state;
pub mod persistence;
pub mod responses;
pub mod path_resolver;
pub mod audit;
pub mod auth;
pub mod commands;

pub use commands::brute_force::*;
pub use commands::session::*;
pub use commands::module_whitelist::*;
pub use commands::cleanup::*;
pub use commands::file_lock::*;
pub use commands::usb::*;
pub use commands::preset::*;

pub use state::SecurityState;

#[cfg(test)]
mod tests;
