/*
 * commands/mod.rs — 安全命令子模块入口
 *
 *
 *
 * 命令分组：
 *   1. 暴力拦截（brute_force）：check / record_failure / record_success / clear_purge / status
 *   2. 会话守卫（session_guard）：start / stop / set_high_security
 *   3. 模块巡检（module_whitelist）：patrol / add_trusted_path / clear_trusted_paths
 *   4. 痕迹清理（cleanup）：clear_recent / secure_delete / cleanup_crash_residue
 *   5. 文件锁与 ACL（file_lock）：harden_private_dir
 *   6. USB 安全（usb_guard）：read_serial / register_device / check_clone /
 *      shadow_sleep / try_recover / purge / shadow_status
 *   7. 三档预设查询（preset）：get_preset_config
 *   8. 会话授权（auth）：require_session_authorized
 */

pub mod brute_force;
pub mod session;
pub mod module_whitelist;
pub mod cleanup;
pub mod file_lock;
pub mod usb;
pub mod preset;
pub mod system_metrics;
