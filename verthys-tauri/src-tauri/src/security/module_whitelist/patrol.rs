/* ====================================================================== *
 *  公共接口 — 平台分发                                                    *
 * ====================================================================== */

use super::types::{SignatureStatus, UnknownModule};

/// 遍历当前进程已加载模块，返回未知/可疑模块列表
///
/// Windows 实现：CreateToolhelp32Snapshot + Module32FirstW/NextW 枚举
/// 非 Windows：空实现，返回空 Vec
#[cfg(target_os = "windows")]
pub fn patrol_modules(install_dir: &str) -> Vec<UnknownModule> {
    super::win_impl::patrol_modules(install_dir)
}

/// 轻量巡检：仅路径白名单匹配，跳过 WinVerifyTrust 签名验证（降低 CPU 开销）
///
/// 供后台巡检线程（background_patrol）每 30s 高频调用：
///   - 仅检测"未知路径"的第三方 DLL（不在安装目录/System32/SysWOW64/WinSxS/
///     Microsoft 运行时目录/受信任白名单下）
///   - 受信任位置的非系统模块按路径信任，不调用 WinVerifyTrust
///   - 非 Windows：空实现，返回空 Vec
#[cfg(target_os = "windows")]
pub fn patrol_modules_paths_only(install_dir: &str) -> Vec<UnknownModule> {
    super::win_impl::patrol_modules_paths_only(install_dir)
}

/// 验证模块的 Authenticode 数字签名
///
/// Windows 实现：WinVerifyTrust + WINTRUST_ACTION_GENERIC_VERIFY_V2
/// 非 Windows：空实现，返回 false
#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub fn verify_signature(module_path: &str) -> bool {
    super::win_impl::verify_signature(module_path)
}

/// 查询模块签名核验结论（后台巡检威胁分级用）
///
/// 与 `verify_signature` 共用同一缓存；额外区分“签名有效但吊销状态
/// 不可达”，使离线环境下的合法第三方模块不被误判为未签名。
/// 非 Windows：恒为 `Invalid`（平台无 Authenticode 语义）。
pub fn module_signature_status(module_path: &str) -> SignatureStatus {
    #[cfg(target_os = "windows")]
    {
        super::win_impl::signature_status(module_path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = module_path;
        SignatureStatus::Invalid
    }
}

/// 枚举当前进程已加载模块中"位于受信位置且签名核验被轻量巡检跳过"的模块
///
/// 返回 (模块名, 完整路径) 列表，路径为原始形态（未规范化），供调用方
/// 随机抽样后逐个执行签名复核。筛选口径与 scan_modules 的签名验证集合
/// 一致：安装目录 / Microsoft 运行时目录 / 用户受信白名单下的模块，
/// 排除系统目录（System32/SysWOW64/WinSxS，catalog 签名，由哈希基线负责）。
///
/// 供后台巡检线程做完整校验抽样。
/// 非 Windows 平台返回空列表。
pub fn trusted_signable_module_paths(install_dir: &str) -> Vec<(String, String)> {
    #[cfg(target_os = "windows")]
    {
        super::win_impl::trusted_signable_module_paths(install_dir)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = install_dir;
        Vec::new()
    }
}

/* ====================================================================== *
 *  非 Windows 平台空实现                                                 *
 * ====================================================================== */

#[cfg(not(target_os = "windows"))]
pub fn patrol_modules(_install_dir: &str) -> Vec<UnknownModule> {
    Vec::new()
}

#[cfg(not(target_os = "windows"))]
pub fn patrol_modules_paths_only(_install_dir: &str) -> Vec<UnknownModule> {
    Vec::new()
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn verify_signature(_module_path: &str) -> bool {
    false
}
