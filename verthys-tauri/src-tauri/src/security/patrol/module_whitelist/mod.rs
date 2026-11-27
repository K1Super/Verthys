/*
 * module_whitelist.rs — 模块白名单实时巡检
 *
 *
 * 安全策略：
 *   - Windows 文件系统大小写不敏感，路径比较统一转小写
 *   - 路径真实化：先调用 GetLongPathNameW 解析短名/符号链接，再统一规范化
 *   - 受信任路径白名单用 std::sync::Mutex<Vec<String>> 保护
 *   - wintrust.dll 通过 extern "system" + #[link(name="wintrust")] 直接 FFI 链接
 *   - 非 Windows 平台空实现（返回空 Vec / false），保证跨平台编译通过
 */

mod baseline;
mod patrol;
mod trusted;
mod types;

#[cfg(target_os = "windows")]
mod win_impl;

#[cfg(all(test, target_os = "windows"))]
mod tests;

pub use baseline::{
    build_system_baseline, check_module_against_baseline, compute_file_hash, HashBaseline,
};
pub use patrol::{
    module_signature_status, patrol_modules, patrol_modules_paths_only,
    trusted_signable_module_paths, verify_signature,
};
pub use trusted::{
    add_trusted_path, clear_trusted_paths, export_trusted_paths, import_trusted_paths,
};
pub use types::{BaselineCheck, SignatureStatus, UnknownModule};
