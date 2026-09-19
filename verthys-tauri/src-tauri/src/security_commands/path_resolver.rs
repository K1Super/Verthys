/*
 * path_resolver.rs — 路径白名单解析
 *
 *
 * 职责：
 *   文件系统命令不再接收前端传入的路径，改为逻辑标识符：
 *     "verthys_dir"  → app_config_dir（.verthys 文件所在目录）
 *     "temp_dir"   → app_config_dir/tmp（临时文件目录）
 *     "data_dir"   → app_config_dir（应用数据根目录）
 *   install_dir 从 current_exe().parent() 获取，不信任前端输入。
 *
 *   - resolve_logical_path：将逻辑标识符解析为规范化实际路径，含白名单校验
 *   - get_install_dir：从 current_exe 推导安装目录（不信任前端）
 */

use tauri::Manager;

/* ====================================================================== *
 *  路径白名单解析                                           *
 *                                                                        *
 *  文件系统命令不再接收前端传入的路径，改为逻辑标识符：                    *
 *    "verthys_dir"  → app_config_dir（.verthys 文件所在目录）                 *
 *    "temp_dir"   → app_config_dir/tmp（临时文件目录）                    *
 *    "data_dir"   → app_config_dir（应用数据根目录）                      *
 *  install_dir 从 current_exe().parent() 获取，不信任前端输入。            *
 * ====================================================================== */

/// 逻辑路径标识符
pub(super) const LOGICAL_VERTHYS_DIR: &str = "verthys_dir";
pub(super) const LOGICAL_TEMP_DIR: &str = "temp_dir";
pub(super) const LOGICAL_DATA_DIR: &str = "data_dir";

/// 将逻辑标识符解析为实际路径
///
/// 返回 Ok(canonical_path) 表示路径合法且在白名单内。
/// 返回 Err(msg) 表示标识符无效或路径不在白名单内。
pub(super) fn resolve_logical_path(
    app: &tauri::AppHandle,
    logical_id: &str,
) -> Result<std::path::PathBuf, String> {
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("获取配置目录失败: {}", e))?;

    let target = match logical_id {
        LOGICAL_VERTHYS_DIR | LOGICAL_DATA_DIR => config_dir.clone(),
        LOGICAL_TEMP_DIR => config_dir.join("tmp"),
        _ => {
            return Err(format!(
                "未知路径标识符: '{}'（有效值: verthys_dir / temp_dir / data_dir）",
                logical_id
            ));
        }
    };

    // 确保目录存在
    if !target.exists() {
        std::fs::create_dir_all(&target)
            .map_err(|e| format!("创建目录失败 [{}]: {}", target.display(), e))?;
    }

    // 规范化路径（解析符号链接）
    let canonical = std::fs::canonicalize(&target)
        .map_err(|e| format!("路径解析失败 [{}]: {}", target.display(), e))?;

    // 白名单校验：规范化后的路径必须在 config_dir 下
    let config_canonical = std::fs::canonicalize(&config_dir)
        .map_err(|e| format!("配置目录解析失败: {}", e))?;

    if !canonical.starts_with(&config_canonical) {
        return Err("路径不在白名单基目录内（安全拒绝）".to_string());
    }

    Ok(canonical)
}

/// 获取应用安装目录（从 current_exe 推导，不信任前端）
pub(super) fn get_install_dir() -> Result<String, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("获取当前可执行文件路径失败: {}", e))?;
    let install_dir = exe
        .parent()
        .ok_or_else(|| "无法获取可执行文件父目录".to_string())?;
    Ok(install_dir.to_string_lossy().to_string())
}
