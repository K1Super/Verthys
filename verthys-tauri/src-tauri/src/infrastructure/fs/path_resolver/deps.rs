/*
 * @file infrastructure/path_resolver/deps.rs
 * @brief 依赖预检：加载器搜索路径与二进制导入依赖校验
 *
 * 在 spawn 子进程之前解析 worker exe 与 verthys.dll 的导入表，
 * 按 Windows 加载器搜索顺序确认每个被导入 DLL 可访问；
 * 加载器级失败（exit code 0 + 零 stderr）无法通过就绪超时诊断，
 * 必须在此主动拦截。
 */

use super::dll_verify::check_dll_dependencies;
use super::pe::parse_pe_imports;

/// Windows 加载器搜索顺序中查找指定 DLL
///
/// 搜索顺序（简化版 SafeDllSearchMode，与 Windows 加载器一致）：
///   1. exe 同级目录（应用级 DLL，如 verthys.dll）
///   2. System32（64-bit 进程系统 DLL 目录）
///   3. Windows 目录（SystemRoot 根）
///   4. PATH 环境变量中的目录
///
/// 返回首个命中目录的字符串（用于日志），未命中返回 None。
pub(super) fn find_dll_in_search_paths(
    dll_name: &str,
    exe_dir: &std::path::Path,
) -> Option<String> {
    // 1. exe 同级目录
    if exe_dir.join(dll_name).exists() {
        return Some("exe_dir".to_string());
    }

    // 2. System32 / 3. Windows 目录
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let system32 = std::path::Path::new(&system_root).join("System32");
    if system32.join(dll_name).exists() {
        return Some("System32".to_string());
    }
    if std::path::Path::new(&system_root).join(dll_name).exists() {
        return Some("Windows".to_string());
    }

    // 4. PATH 环境变量
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(';') {
            if dir.is_empty() {
                continue;
            }
            if std::path::Path::new(dir).join(dll_name).exists() {
                return Some("PATH".to_string());
            }
        }
    }

    None
}

/// 校验 worker exe 与 verthys.dll 的全部导入依赖可访问（预检）
///
/// 在 spawn 子进程之前，解析两个 PE 文件的导入表，对每个被导入的
/// DLL 按 Windows 加载器搜索顺序确认可访问。缺失任一依赖将导致
/// 加载器级失败（exit code 0 + 零 stderr），无法通过就绪超时诊断，
/// 必须在此主动拦截。
///
/// 此函数在 `check_dll_dependencies`（VC++ 运行库基础检查）之上扩展：
///   - VC++ 运行库：vcruntime140 / msvcp140 / vcruntime140_1 / ucrtbase
///   - 应用级 DLL：verthys.dll（worker 导入它）等
///   - 系统 DLL：kernel32 / user32 / advapi32 等（缺失视为系统损坏）
///
/// # 参数
/// - `worker_exe`：verthys-worker.exe 绝对路径
/// - `dll_path`：verthys.dll 绝对路径
///
/// # 返回
/// - `Ok(())`：全部导入依赖可访问
/// - `Err(String)`：缺失依赖列表（错误信息已脱敏，仅含 DLL 名称）
pub fn check_binary_dependencies(worker_exe: &str, dll_path: &str) -> Result<(), String> {
    // 1. 基础检查：VC++ 运行库（保持与 check_dll_dependencies 一致的行为）
    check_dll_dependencies(dll_path)?;

    // 2. 确定 exe 同级目录（应用级 DLL 搜索基准）
    let exe_dir = std::path::Path::new(worker_exe)
        .parent()
        .ok_or_else(|| "无法解析 worker exe 所在目录".to_string())?;

    // 3. 解析 worker exe 与 verthys.dll 的导入表
    let worker_imports =
        parse_pe_imports(worker_exe).map_err(|e| format!("worker exe 导入表解析失败: {}", e))?;
    let dll_imports =
        parse_pe_imports(dll_path).map_err(|e| format!("verthys.dll 导入表解析失败: {}", e))?;

    log::debug!(
        "[dep_check] worker 导入 {} 项, dll 导入 {} 项",
        worker_imports.len(),
        dll_imports.len()
    );

    // 4. 合并去重，逐一校验可访问性
    let mut all_imports = std::collections::HashSet::new();
    for imp in worker_imports.iter().chain(dll_imports.iter()) {
        all_imports.insert(imp.clone());
    }

    let mut missing: Vec<String> = Vec::new();
    for imp in &all_imports {
        if find_dll_in_search_paths(imp, exe_dir).is_none() {
            missing.push(imp.clone());
        }
    }

    if !missing.is_empty() {
        // 已脱敏：仅含 DLL 文件名，不含路径
        return Err(format!(
            "缺失导入依赖: {} — 请确认依赖 DLL 已随包发布或系统运行库已安装",
            missing.join(", ")
        ));
    }

    log::info!(
        "[dep_check] 导入依赖校验通过（共 {} 项）",
        all_imports.len()
    );
    Ok(())
}

/// Debug 专用：宿主同级文件优先。
///
/// 签名开发运行时把 `Verthys.exe`、`verthys-worker.exe` 与 `verthys.dll`
/// 放在同一目录，服务预 ARM 只接受同目录 worker。Debug 宿主必须优先选择
/// 该布局；Release 不编译此分支，安装目录解析顺序保持不变。
#[cfg(debug_assertions)]
pub(super) fn debug_sibling_file(
    exe_dir: &std::path::Path,
    name: &str,
) -> Option<std::path::PathBuf> {
    let candidate = exe_dir.join(name);
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}
