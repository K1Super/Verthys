/*
 * @file infrastructure/path_resolver/dll_verify.rs
 * @brief DLL 完整性哈希校验与运行库依赖检查
 *
 * 完整性校验为失败关闭门禁：Release 构建缺少嵌入哈希或哈希不匹配即拒绝加载；
 * 开发构建允许未构建 C 核心时跳过，仅记录警告。
 */

use crate::dll_hash;
use crate::util::path::sanitize_path;

/// 校验 verthys.dll 的 SHA-256 是否与编译时嵌入值一致。
///
/// 该函数在 worker 启动预检中调用，用于检测 DLL 是否被替换。
/// Release 构建必须存在嵌入哈希：缺失即视为构建契约失效并拒绝启动；
/// 开发构建允许未构建 C 核心时跳过，仅记录警告。
///
/// Debug 宿主加载 `build_dev` / `build/core/Debug` 的 dev DLL 时跳过生产
/// 基线：该基线来自生产 Release 产物，Debug 产物必然不同；此豁免仅限
/// Debug 构建与明确的 dev 路径，Release 宿主仍强制校验生产 DLL。
///
/// # 参数
/// - `dll_path`：DLL 文件绝对路径
///
/// # 返回
/// - `Ok(())`：摘要一致，或 Debug 构建的 dev DLL
/// - `Err(String)`：读取失败、Release 缺少基线或摘要不一致
pub fn verify_dll_integrity(dll_path: &str) -> Result<(), String> {
    use sha2::{Digest, Sha256};

    #[cfg(debug_assertions)]
    {
        let normalized = dll_path.replace('/', "\\").to_ascii_lowercase();
        if normalized.contains("\\build_dev\\") || normalized.contains("\\build\\core\\debug\\") {
            log::warn!(
                "[DLL 校验] Debug 宿主加载 dev DLL，跳过生产哈希基线: {}",
                sanitize_path(dll_path)
            );
            return Ok(());
        }
    }

    let embedded_hash = dll_hash::DLL_HASH;
    let Some(expected) = embedded_hash else {
        if cfg!(debug_assertions) {
            log::warn!("[DLL 校验] 编译时未嵌入 DLL 哈希，开发构建跳过校验");
            return Ok(());
        }
        log::error!("[DLL 校验] Release 构建缺少 DLL 哈希基线，拒绝启动 worker");
        return Err("DLL 完整性基线缺失，无法校验加密核心".into());
    };

    let data =
        std::fs::read(dll_path).map_err(|e| format!("读取 DLL 失败，无法完成完整性校验: {}", e))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let actual = format!("{:x}", hasher.finalize());

    if actual != expected {
        // 失败关闭：哈希漂移可能来自替换、损坏或产物不同步，
        // 三者都无法保证 FFI 布局与协议一致，禁止继续加载。
        log::error!(
            "[DLL 校验] DLL 哈希不匹配 expected={} actual={}，拒绝加载",
            expected,
            actual
        );
        return Err("DLL 完整性校验失败：加密核心与编译时基线不一致".into());
    }

    log::info!("[DLL 校验] DLL 哈希校验通过: {}", expected);
    Ok(())
}

/// 获取编译时嵌入的 DLL SHA-256 哈希前缀（前 16 字符）
///
/// 该哈希前缀用于诊断信息（如 DiagInfo），便于区分不同版本，
/// 同时不泄露完整哈希值，降低哈希碰撞攻击风险。
/// 若编译时未嵌入哈希，返回空字符串。
pub fn get_dll_hash_prefix() -> String {
    dll_hash::DLL_HASH
        .map(|h| h.chars().take(16).collect())
        .unwrap_or_default()
}

/// 检查 VC++ 运行库依赖是否存在（仅 Windows）
///
/// 在 Windows 平台检查 System32 目录下是否存在 vcruntime140.dll 等
/// 常见 VC++ 运行库文件，用于提前预判子进程能否正常启动。
/// 缺失时返回包含具体缺失文件的错误信息，引导用户安装 Redistributable。
/// 非 Windows 平台静默跳过。
pub fn check_dll_dependencies(_dll_path: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let system32 = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let system32_dir = std::path::Path::new(&system32).join("System32");

        let required_runtimes = ["vcruntime140.dll", "msvcp140.dll", "vcruntime140_1.dll"];

        let mut missing = Vec::new();
        for dll in &required_runtimes {
            let full_path = system32_dir.join(dll);
            if !full_path.exists() {
                missing.push(dll.to_string());
            }
        }

        if !missing.is_empty() {
            return Err(format!(
                "缺少 VC++ 运行库依赖: {} — 请安装 Microsoft Visual C++ Redistributable",
                missing.join(", ")
            ));
        }

        log::info!("[DLL 依赖] VC++ 运行库依赖检查通过");
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = dll_path;
    }

    Ok(())
}
