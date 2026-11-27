/*
 * @file infrastructure/path_resolver/resolve.rs
 * @brief verthys-worker.exe 与 verthys.dll 的运行时路径解析
 *
 * 路径解析策略优先使用开发环境最新构建产物，生产环境回退至 Tauri 资源目录。
 * 所有命中路径经 sanitize_path 脱敏后记录日志。
 */

#[cfg(debug_assertions)]
use super::deps::debug_sibling_file;
use crate::util::path::sanitize_path;
use tauri::Manager;

/// 解析 verthys-worker.exe 的绝对路径
///
/// 路径搜索顺序：
/// 0. Debug 构建：宿主同级 `verthys-worker.exe` 优先（签名开发运行时）。
/// 1. 开发环境：当前 exe 位于 `target/{debug,release}` 下时，
///    优先查找 `../../../verthys-worker/target/{release,debug}/verthys-worker.exe`
///    保证使用最新构建产物。
/// 2. 生产环境：依次尝试 Tauri 资源目录（`binaries/`、根目录）、
///    可执行文件同级目录（包括 `binaries/`、`resources/binaries/` 等）。
/// 3. 兜底：当前工作目录下的相对路径。
///
/// 所有搜索到的路径均会经 `sanitize_path` 脱敏后记录日志。
/// 若所有策略均失败，返回包含已尝试范围的错误信息。
pub fn resolve_worker_path(app: &tauri::AppHandle) -> Result<String, String> {
    let exe_name = if cfg!(target_os = "windows") {
        "verthys-worker.exe"
    } else {
        "verthys-worker"
    };

    // 0. Debug 构建优先宿主同级：签名开发运行时的 worker 与宿主同目录，
    // 预 ARM 只在该布局下生效。
    #[cfg(debug_assertions)]
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            if let Some(sibling) = debug_sibling_file(exe_dir, exe_name) {
                let abs = sibling.canonicalize().map_err(|e| e.to_string())?;
                log::info!(
                    "[resolve_worker] 开发运行时同级命中: {}",
                    sanitize_path(&abs.display().to_string())
                );
                return Ok(abs.display().to_string());
            }
        }
    }

    // 1. 开发环境优先
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let exe_dir_str = exe_dir.display().to_string().replace('/', "\\");
            let is_dev = exe_dir_str.ends_with("\\target\\debug")
                || exe_dir_str.ends_with("\\target\\release");

            if is_dev {
                // Debug 宿主优先 Debug worker：Debug worker 跳过 DLL 哈希基线，
                // 与 build_dev 的 dev DLL 匹配；Release 宿主仍优先 Release worker。
                let profiles: &[&str] = if cfg!(debug_assertions) {
                    &["debug", "release"]
                } else {
                    &["release", "debug"]
                };
                for profile in profiles {
                    let p = exe_dir.join(format!(
                        "../../../verthys-worker/target/{}/{}",
                        profile, exe_name
                    ));
                    if p.exists() {
                        let abs = p.canonicalize().map_err(|e| e.to_string())?;
                        log::info!(
                            "[resolve_worker] 开发环境命中: {}",
                            sanitize_path(&abs.display().to_string())
                        );
                        return Ok(abs.display().to_string());
                    }
                }
            }
        }
    }

    // 2. Tauri 资源目录
    let resource_candidates = [
        "binaries/verthys-worker".to_string(),
        "verthys-worker".to_string(),
    ];
    for rel in &resource_candidates {
        if let Ok(path) = app
            .path()
            .resolve(rel, tauri::path::BaseDirectory::Resource)
        {
            let exe = if cfg!(target_os = "windows") {
                format!("{}.exe", path.display())
            } else {
                path.display().to_string()
            };
            if std::path::Path::new(&exe).exists() {
                log::info!("[resolve_worker] 资源路径命中: {}", sanitize_path(&exe));
                return Ok(exe);
            }
        }
    }

    // 3. 可执行文件同级目录
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let exe_based = [
                exe_dir.join(format!("binaries/{}", exe_name)),
                exe_dir.join(exe_name),
                exe_dir.join(format!("resources/binaries/{}", exe_name)),
                exe_dir.join(format!("resources/{}", exe_name)),
            ];
            for p in &exe_based {
                if p.exists() {
                    let abs = p.canonicalize().map_err(|e| e.to_string())?;
                    log::info!(
                        "[resolve_worker] exe 同级命中: {}",
                        sanitize_path(&abs.display().to_string())
                    );
                    return Ok(abs.display().to_string());
                }
            }
        }
    }

    // 4. 当前工作目录相对路径（兜底）
    let dev_candidates = [
        "../verthys-worker/target/release/verthys-worker.exe",
        "../verthys-worker/target/debug/verthys-worker.exe",
        "../../verthys-worker/target/release/verthys-worker.exe",
        "../../verthys-worker/target/debug/verthys-worker.exe",
    ];
    for c in &dev_candidates {
        if std::path::Path::new(c).exists() {
            let abs = std::fs::canonicalize(c).map_err(|e| e.to_string())?;
            log::info!(
                "[resolve_worker] CWD 相对命中: {}",
                sanitize_path(&abs.display().to_string())
            );
            return Ok(abs.display().to_string());
        }
    }

    Err(format!(
        "verthys-worker ({}) 未找到。已尝试：开发目录、资源目录(binaries/|根)、exe同级、CWD相对",
        exe_name
    ))
}

/// 解析 verthys.dll 的绝对路径
///
/// 搜索策略与 `resolve_worker_path` 类似，但针对 DLL 文件：
/// 0. Debug 构建：宿主同级 `verthys.dll` 优先（签名开发运行时）。
/// 1. 开发环境：当前 exe 在 `target/{debug,release}` 下时，
///    查找 `../../../../build/core/Release/verthys.dll`。
/// 2. 生产环境：Tauri 资源目录、可执行文件同级（含 `resources/`、`_up_/` 嵌套路径）。
/// 3. 兜底：当前工作目录及向上递归查找 `build/core/Release/`。
///
/// 路径匹配成功后将通过 `sanitize_path` 脱敏后记录日志。
///
/// 上溯深度约束：
///   开发环境 exe 位于 `verthys-tauri/src-tauri/target/{debug,release}`，
///   `build/` 位于仓库根 `Verthys/build/`，故需上溯 4 级；
///   `resolve_worker_path` 上溯 3 级即可命中，因为 `verthys-worker/` 挂在
///   `verthys-tauri/` 下。
///
///   深度不足会回退到 Tauri 资源目录，命中 `src-tauri/target/debug/verthys.dll`
///   或 `src-tauri/verthys.dll` 等旧拷贝。旧 DLL 早于 C 端 VerthysSummaryRecord
///   的 slot_state 字段，Rust worker 按 88 字节读取旧 DLL 写入的 80 字节记录
///   会读到错位的 name 指针，解引用空指针导致 worker 0xC0000005 崩溃，
///   上游表现为"worker 子进程已退出"。
pub fn resolve_dll_path(app: &tauri::AppHandle) -> Result<String, String> {
    // 0. Debug 构建优先宿主同级：与签名宿主配套的 DLL 是开发运行时的
    // 权威产物，避免回退到旧的 target 拷贝。
    #[cfg(debug_assertions)]
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            if let Some(sibling) = debug_sibling_file(exe_dir, "verthys.dll") {
                let abs = sibling.canonicalize().map_err(|e| e.to_string())?;
                log::info!(
                    "[resolve_dll] 开发运行时同级命中: {}",
                    sanitize_path(&abs.display().to_string())
                );
                return Ok(abs.display().to_string());
            }
        }
    }

    // 1. 开发环境优先
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let exe_dir_str = exe_dir.display().to_string().replace('/', "\\");
            let is_dev = exe_dir_str.ends_with("\\target\\debug")
                || exe_dir_str.ends_with("\\target\\release");

            if is_dev {
                // Debug 宿主（dev 应用）优先使用 build_dev 的 Debug DLL：
                // 该构建 caller-auth OFF、test-hooks OFF，未签名 dev worker 可正常
                // 加载；Release 宿主或 build_dev 缺失时才回退到生产 Release DLL。
                if cfg!(debug_assertions) {
                    let debug_candidates = [
                        exe_dir.join("../../../../build_dev/core/Debug/verthys.dll"),
                        exe_dir.join("../../../../build/core/Debug/verthys.dll"),
                    ];
                    for p in &debug_candidates {
                        if p.exists() {
                            let abs = p.canonicalize().map_err(|e| e.to_string())?;
                            log::info!(
                                "[resolve_dll] 开发环境 Debug 命中: {}",
                                sanitize_path(&abs.display().to_string())
                            );
                            return Ok(abs.display().to_string());
                        }
                    }
                }
                // 4 级上溯抵达仓库根 Verthys/build/core/Release/
                //   exe_dir = Verthys/verthys-tauri/src-tauri/target/{debug,release}
                //   ../../../../ → Verthys/  → build/core/Release/verthys.dll ✓
                //   深度不足仅到 verthys-tauri/，build/ 不在此层 → 回退到旧 DLL
                let p = exe_dir.join("../../../../build/core/Release/verthys.dll");
                if p.exists() {
                    let abs = p.canonicalize().map_err(|e| e.to_string())?;
                    log::info!(
                        "[resolve_dll] 开发环境命中: {}",
                        sanitize_path(&abs.display().to_string())
                    );
                    return Ok(abs.display().to_string());
                }
            }
        }
    }

    // 2. Tauri 资源目录
    if let Ok(path) = app
        .path()
        .resolve("verthys.dll", tauri::path::BaseDirectory::Resource)
    {
        if path.exists() {
            log::info!(
                "[resolve_dll] 资源路径命中: {}",
                sanitize_path(&path.display().to_string())
            );
            return Ok(path.display().to_string());
        }
    }

    // 3. 可执行文件同级目录（含 resources/、_up_/ 等嵌套）
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let exe_based = [
                exe_dir.join("verthys.dll"),
                exe_dir.join("resources/verthys.dll"),
                exe_dir.join("_up_/_up_/build/core/Release/verthys.dll"),
                exe_dir.join("_up_/build/core/Release/verthys.dll"),
            ];
            for p in &exe_based {
                if p.exists() {
                    let abs = p.canonicalize().map_err(|e| e.to_string())?;
                    log::info!(
                        "[resolve_dll] exe 同级命中: {}",
                        sanitize_path(&abs.display().to_string())
                    );
                    return Ok(abs.display().to_string());
                }
            }
        }
    }

    // 4. 当前工作目录相对路径
    let candidates = [
        "../../build/core/Release/verthys.dll",
        "../../../build/core/Release/verthys.dll",
        "../build/core/Release/verthys.dll",
        "build/core/Release/verthys.dll",
    ];

    for c in &candidates {
        if std::path::Path::new(c).exists() {
            let abs = std::fs::canonicalize(c).map_err(|e| e.to_string())?;
            log::info!(
                "[resolve_dll] CWD 相对命中: {}",
                sanitize_path(&abs.display().to_string())
            );
            return Ok(abs.display().to_string());
        }
    }

    // 5. 向上递归查找
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            for depth in 1..=5 {
                let p = exe_dir
                    .join("../".repeat(depth))
                    .join("build/core/Release/verthys.dll");
                if p.exists() {
                    return Ok(p
                        .canonicalize()
                        .map_err(|e| e.to_string())?
                        .display()
                        .to_string());
                }
            }
        }
    }

    // 6. 当前工作目录根
    if std::path::Path::new("verthys.dll").exists() {
        return Ok(std::fs::canonicalize("verthys.dll")
            .map_err(|e| e.to_string())?
            .display()
            .to_string());
    }

    Err("verthys.dll 未找到。已尝试：资源目录、exe同级、开发目录".into())
}
