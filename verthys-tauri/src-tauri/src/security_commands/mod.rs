/*
 * security_commands/mod.rs — 安全防护模块的 Tauri 命令层
 *
 *
 * 重写要点：
 *   1. 命令层操作许可与路径白名单：文件系统命令不再接收前端路径，
 *            改为逻辑标识符（"verthys_dir"/"temp_dir"/"data_dir"），由后端
 *            从受信上下文解析。install_dir 从 current_exe 获取。
 *   2. 暴力拦截 DPAPI 加密持久化：BruteForceGuard 状态写入 DPAPI
 *            加密文件，应用启动时加载，防止重启绕过。
 *   3. 异步任务 + 信令分离：耗时操作（磁盘清理/ACL 加固/设备查询）
 *            使用 spawn_blocking，Mutex 仅保护快速状态读写。
 *   4. 锁中毒自愈：获取锁时检测中毒，into_inner() 取出后废弃，
 *            重置为新实例并记录严重告警。
 *   5. 命令权限分级：敏感操作（record_success/clear_purge/
 *            set_high_security / 白名单变更 / USB 注册）要求已解锁会话，
 *            由 auth::require_session_authorized 按密钥生命周期统一裁决。
 *   6. 使用 base64 crate 替换自编 Base64 实现。
 *   7. 统一结构化审计日志：每个安全命令执行时记录审计事件。
 *   8. 修复会话守卫与影子休眠：session_start 要求真实 HWND，
 *            shadow_status 返回真实 txid，影子休眠 DPAPI 绑定会话。
 *
 * 模块结构：
 *   - state：安全全局状态 + 锁中毒自愈
 *   - responses：响应类型定义（含 #[derive(serde::Serialize, TS)]）
 *   - persistence：DPAPI 加密状态持久化层
 *   - auth：会话授权裁决
 *   - preset_persistence：安全预设受信持久化（单一事实源）
 *   - audit：结构化审计日志
 *   - path_resolver：路径白名单解析
 *   - commands：Tauri 命令分组
 *       1. brute_force：check / record_failure / record_success / clear_purge / status
 *       2. session：start / stop / set_high_security
 *       3. module_whitelist：patrol / add_trusted_path / clear_trusted_paths
 *       4. cleanup：clear_recent / secure_delete / cleanup_crash_residue
 *       5. file_lock：harden_private_dir
 *       6. usb：read_serial / register_device / check_clone /
 *          shadow_sleep / try_recover / purge / shadow_status
 *       7. preset：get_preset_config / apply_preset / load_preset_state
 *       8. auth：require_session_authorized
 */

pub mod state;
pub mod persistence;
pub mod responses;
pub mod path_resolver;
pub mod audit;
pub mod auth;
/// 安全预设受信持久化（单一事实源，与状态文件同域）
pub mod preset_persistence;
pub mod commands;
/// 解锁命令的服务端暴力熔断桥接（gate 检查 / 失败计数 / 成功重置）
pub mod brute_force_bridge;

pub use commands::brute_force::*;
pub use commands::session::*;
pub use commands::module_whitelist::*;
pub use commands::cleanup::*;
pub use commands::file_lock::*;
pub use commands::usb::*;
pub use commands::preset::*;
pub use commands::system_metrics::*;

pub use state::SecurityState;

#[cfg(test)]
mod tests;
