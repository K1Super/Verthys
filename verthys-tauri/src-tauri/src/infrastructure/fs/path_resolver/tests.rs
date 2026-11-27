/*
 * @file infrastructure/path_resolver/tests.rs
 * @brief path_resolver 单元测试
 */

#[cfg(debug_assertions)]
use super::deps::debug_sibling_file;
use super::deps::find_dll_in_search_paths;
use super::*;

/// 解析当前测试二进制自身的 PE 头，验证架构检测返回已知值。
/// 测试二进制由 cargo 编译生成，必为合法 PE 镜像。
#[test]
fn test_detect_pe_architecture_on_self() {
    let exe = std::env::current_exe().expect("current_exe");
    let arch = detect_pe_architecture(&exe.display().to_string());
    assert!(arch.is_ok(), "detect_pe_architecture 应成功: {:?}", arch);
    let arch = arch.unwrap();
    // 测试二进制架构应为主机架构之一（Windows 上通常为 X64）
    assert!(
        arch == PeArch::X64 || arch == PeArch::X86 || arch == PeArch::Arm64,
        "意外架构: {:?}",
        arch
    );
}

/// Debug 构建必须豁免 dev DLL 的生产哈希基线（Release 仍严格校验）。
#[cfg(debug_assertions)]
#[test]
fn dev_dll_path_skips_production_hash_baseline_in_debug() {
    let dll = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("build_dev")
        .join("core")
        .join("Debug")
        .join("verthys.dll");
    if !dll.exists() {
        return;
    }
    assert!(verify_dll_integrity(&dll.display().to_string()).is_ok());
}

/// Debug 宿主同级文件必须优先于外部 target 路径。
#[cfg(debug_assertions)]
#[test]
fn debug_sibling_file_prefers_existing_sibling() {
    let dir = std::env::temp_dir().join(format!("verthys_dev_sibling_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    assert!(debug_sibling_file(&dir, "verthys-worker.exe").is_none());

    let file = dir.join("verthys-worker.exe");
    std::fs::write(&file, b"stub").expect("write sibling");
    let found = debug_sibling_file(&dir, "verthys-worker.exe");
    assert_eq!(found.as_deref(), Some(file.as_path()));

    let _ = std::fs::remove_dir_all(&dir);
}

/// 非 PE 文件应返回错误，绝不 panic
#[test]
fn test_detect_pe_architecture_non_pe() {
    // 创建临时文件，内容非 MZ
    let tmp = std::env::temp_dir().join("verthys_pe_test_nonpe.bin");
    std::fs::write(&tmp, b"NOT_A_PE_FILE_CONTENT").expect("write temp");
    let r = detect_pe_architecture(tmp.to_str().unwrap());
    assert!(r.is_err(), "非 PE 文件应返回错误");
    let _ = std::fs::remove_file(&tmp);
}

/// 不存在的文件应返回错误
#[test]
fn test_detect_pe_architecture_missing_file() {
    let r = detect_pe_architecture("Z:\\nonexistent\\file.exe");
    assert!(r.is_err());
}

/// 解析当前测试二进制的导入表，验证：
///   - 返回非空列表（任何 PE 都至少导入一个 DLL）
///   - kernel32.dll 必在其中（Windows 必备依赖）
#[test]
fn test_parse_pe_imports_on_self() {
    let exe = std::env::current_exe().expect("current_exe");
    let imports = parse_pe_imports(&exe.display().to_string());
    assert!(imports.is_ok(), "parse_pe_imports 应成功: {:?}", imports);
    let imports = imports.unwrap();
    assert!(!imports.is_empty(), "测试二进制应至少导入一个 DLL");

    // 全部应为小写
    for imp in &imports {
        assert_eq!(imp.to_lowercase(), *imp, "导入名应已小写化: {}", imp);
    }

    // Windows 测试二进制必然导入 kernel32.dll
    #[cfg(target_os = "windows")]
    {
        assert!(
            imports.iter().any(|s| s == "kernel32.dll"),
            "kernel32.dll 应在导入表中: {:?}",
            imports
        );
    }
}

/// 非 PE 文件解析导入表应返回错误
#[test]
fn test_parse_pe_imports_non_pe() {
    let tmp = std::env::temp_dir().join("verthys_pe_imports_nonpe.bin");
    std::fs::write(&tmp, b"RANDOM_BYTES_NOT_PE").expect("write temp");
    let r = parse_pe_imports(tmp.to_str().unwrap());
    assert!(r.is_err());
    let _ = std::fs::remove_file(&tmp);
}

/// 不存在的文件解析导入表应返回错误
#[test]
fn test_parse_pe_imports_missing_file() {
    let r = parse_pe_imports("Z:\\nonexistent\\missing.dll");
    assert!(r.is_err());
}

/// find_dll_in_search_paths 对系统核心 DLL 应命中 System32
#[test]
#[cfg(target_os = "windows")]
fn test_find_dll_system32() {
    let exe_dir = std::env::temp_dir();
    let hit = find_dll_in_search_paths("kernel32.dll", &exe_dir);
    assert!(hit.is_some(), "kernel32.dll 应在搜索路径中找到");
}

/// find_dll_in_search_paths 对虚构 DLL 应返回 None
#[test]
fn test_find_dll_missing() {
    let exe_dir = std::env::temp_dir();
    let hit = find_dll_in_search_paths("zzz_nonexistent_dll_12345.dll", &exe_dir);
    assert!(hit.is_none(), "虚构 DLL 不应在搜索路径中");
}

/// check_dll_dependencies 在 Windows 上应通过（测试机必装 VC++ 运行库）
#[test]
#[cfg(target_os = "windows")]
fn test_check_dll_dependencies_passes() {
    // 传入一个占位路径，函数实际只检查 System32
    let r = check_dll_dependencies("dummy.dll");
    assert!(r.is_ok(), "VC++ 运行库检查应通过: {:?}", r);
}

/// check_binary_dependencies 对当前 exe 应通过
/// （当前测试二进制的所有导入依赖在测试环境中均可达）
#[test]
fn test_check_binary_dependencies_on_self() {
    let exe = std::env::current_exe().expect("current_exe");
    let exe_str = exe.display().to_string();
    // 用自身同时作为 worker 与 dll（仅验证导入表解析 + 搜索路径逻辑，
    // 不验证架构一致性，因为此处不关心 dll 架构）
    let r = check_binary_dependencies(&exe_str, &exe_str);
    assert!(r.is_ok(), "当前二进制依赖检查应通过: {:?}", r);
}
