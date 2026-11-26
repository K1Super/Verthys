/* ====================================================================== *
 *  系统目录模块哈希基线库                                                 *
 *                                                                        *
 *  对 System32、SysWOW64、WinSxS 等系统目录下的模块，预计算所有合法微软   *
 *  DLL 的 SHA-256 哈希集合，在巡检时对哈希进行匹配。任何不在基线库中的    *
 *  模块（包括被替换或新增的 DLL）一律视为威胁。                           *
 *                                                                        *
 *  基线库在应用启动时构建一次（惰性初始化），后续巡检直接使用缓存结果。    *
 * ====================================================================== */

#[cfg(target_os = "windows")]
use super::trusted::realize_path;
use super::types::BaselineCheck;

/// 系统目录模块哈希基线（路径 → SHA-256 hex）
///
/// 杜绝位置信任。
/// 预计算系统目录下所有合法微软 DLL 的 SHA-256 哈希，
/// 巡检时对系统目录模块的哈希进行匹配，被替换的 DLL 即便在系统目录下也被检出。
pub type HashBaseline = std::collections::HashMap<String, String>;

/// 计算文件的 SHA-256 哈希（hex 编码）
///
/// 读取文件内容并计算 SHA-256，返回 64 字符 hex 字符串。
/// 文件不存在 / 读取失败 / 过大（> 256MB，防 DoS）时返回 None。
#[cfg(target_os = "windows")]
pub fn compute_file_hash(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};

    // 文件大小上限 256MB，防止超大文件导致内存耗尽
    const MAX_HASH_FILE_SIZE: u64 = 256 * 1024 * 1024;

    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > MAX_HASH_FILE_SIZE {
        log::warn!(
            "[module_whitelist] 文件过大（{} 字节 > {} 上限），跳过哈希计算: {}",
            metadata.len(),
            MAX_HASH_FILE_SIZE,
            sanitize_path_for_hash(path)
        );
        return None;
    }

    let data = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    Some(hash.iter().map(|b| format!("{:02x}", b)).collect())
}

/// 非 Windows 平台：计算文件哈希（空实现）
#[cfg(not(target_os = "windows"))]
pub fn compute_file_hash(_path: &str) -> Option<String> {
    None
}

/// 构建系统目录模块哈希基线
///
/// 枚举 System32、SysWOW64 目录下的所有 .dll/.sys 文件，计算 SHA-256 哈希，
/// 返回"规范化路径 → SHA-256 hex"映射表。
///
/// WinSxS 目录因体积庞大（数十万文件）且模块均通过 catalog 签名验证，
/// 不纳入哈希基线（仅在 patrol_modules 完整巡检中通过签名验证）。
///
/// 此函数在后台线程中调用（启动时惰性构建），不阻塞主线程。
/// 构建失败时返回空 HashMap（降级为仅路径信任）。
#[cfg(target_os = "windows")]
pub fn build_system_baseline() -> HashBaseline {
    let mut baseline = HashBaseline::new();

    // System32 目录
    let system32 = super::win_impl::get_system32_dir_normalized();
    if !system32.is_empty() {
        collect_dir_hashes(&system32, &mut baseline);
    }

    // SysWOW64 目录
    let syswow64 = super::win_impl::get_syswow64_dir_normalized();
    if !syswow64.is_empty() {
        collect_dir_hashes(&syswow64, &mut baseline);
    }

    log::info!(
        "[module_whitelist] 系统目录哈希基线已构建：{} 个模块",
        baseline.len()
    );

    baseline
}

/// 非 Windows 平台：构建系统目录哈希基线（空实现）
#[cfg(not(target_os = "windows"))]
pub fn build_system_baseline() -> HashBaseline {
    HashBaseline::new()
}

/// 核验模块哈希与基线的匹配结论
///
/// 把“哈希不匹配（可能被替换，也可能是
/// 系统更新换文件）”和“无法读取文件计算哈希（文件已删除/权限不足）”
/// 分开返回，供调用方按签名结论分级，避免把系统更新误判为注入。
///
/// 注意：此函数仅对系统目录模块有意义。非系统目录模块应通过签名验证判断。
#[cfg(target_os = "windows")]
pub fn check_module_against_baseline(module_path: &str, baseline: &HashBaseline) -> BaselineCheck {
    let normalized = realize_path(module_path);
    if normalized.is_empty() {
        return BaselineCheck::NotInBaseline;
    }

    let expected_hash = match baseline.get(&normalized) {
        Some(h) => h,
        None => return BaselineCheck::NotInBaseline,
    };

    match compute_file_hash(module_path) {
        Some(actual_hash) => {
            if &actual_hash == expected_hash {
                BaselineCheck::Match
            } else {
                BaselineCheck::Mismatch
            }
        }
        None => {
            log::warn!(
                "[module_whitelist] 无法计算模块哈希（文件可能已删除）: {}",
                sanitize_path_for_hash(module_path)
            );
            BaselineCheck::Unreadable
        }
    }
}

/// 非 Windows 平台：无系统目录哈希基线
#[cfg(not(target_os = "windows"))]
pub fn check_module_against_baseline(
    _module_path: &str,
    _baseline: &HashBaseline,
) -> BaselineCheck {
    BaselineCheck::NotInBaseline
}

/// 枚举目录下所有 .dll/.sys 文件并计算哈希
///
/// 递归遍历目录（深度 1，仅直接子文件），对每个 .dll/.sys 文件
/// 计算 SHA-256 并加入基线。
///
/// 跳过无法读取的文件（权限不足等），不中断基线构建。
#[cfg(target_os = "windows")]
fn collect_dir_hashes(dir: &str, baseline: &mut HashBaseline) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            log::warn!(
                "[module_whitelist] 读取目录失败，跳过哈希基线收集: {} ({})",
                sanitize_path_for_hash(dir),
                e
            );
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // 仅处理 .dll 和 .sys 文件
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !ext.eq_ignore_ascii_case("dll") && !ext.eq_ignore_ascii_case("sys") {
            continue;
        }

        let path_str = path.to_string_lossy().to_string();
        let normalized = realize_path(&path_str);
        if normalized.is_empty() {
            continue;
        }

        if let Some(hash) = compute_file_hash(&path_str) {
            baseline.insert(normalized, hash);
        }
    }
}

/// 路径脱敏（用于日志输出，隐藏用户名）
#[cfg(target_os = "windows")]
fn sanitize_path_for_hash(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    if let Ok(home) = std::env::var("USERPROFILE") {
        let h = home.replace('\\', "/");
        if normalized.contains(&h) {
            return normalized.replace(&h, "<USER_HOME>");
        }
    }
    normalized
}
