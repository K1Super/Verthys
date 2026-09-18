use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    tauri_build::build();

    let out_dir = std::env::var("OUT_DIR").unwrap();

    // ===== 1. 前端资源哈希校验 =====
    // 计算 dist 目录中所有文件的 SHA-256，生成 resource_hashes.rs
    let dist_dir = PathBuf::from("../dist");

    // ★ 企业级根治修复：release 模式下强制校验 dist/ 存在且包含 index.html
    //
    // 根因：用户用 `cargo build --release` 直接构建（跳过 `tauri build` 的
    // beforeBuildCommand），若 dist/ 缺失或为空，tauri::generate_context!()
    // 嵌入空资源 → EXE 运行时 WebView2 白屏/浏览器错误页。
    //
    // 修复：release 模式下 dist/ 缺失或缺 index.html 时编译失败，
    // 引导用户先执行 `npm run build` 或使用 `tauri build`。
    if !dist_dir.exists() {
        if !cfg!(debug_assertions) {
            panic!(
                "❌ 前端 dist 目录不存在！\n\
                 请先执行 `npm run build`（或 `yarn build`）构建前端资源，\n\
                 或直接使用 `tauri build`（会自动执行 beforeBuildCommand）。\n\
                 详见 tauri.conf.json → build.beforeBuildCommand"
            );
        }
        println!("cargo:warning=前端 dist 目录不存在，跳过哈希生成（dev模式）");
        generate_empty_hashes(&out_dir);
    } else if !dist_dir.join("index.html").exists() {
        if !cfg!(debug_assertions) {
            panic!(
                "❌ 前端 dist 目录缺少 index.html！dist 目录可能不完整。\n\
                 请重新执行 `npm run build`（或 `yarn build`）构建前端资源。"
            );
        }
        println!("cargo:warning=前端 dist 目录缺少 index.html（dev模式跳过）");
        generate_empty_hashes(&out_dir);
    } else {
        let mut entries: Vec<(String, String)> = Vec::new();
        collect_hashes(&dist_dir, &dist_dir, &mut entries);
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut code = String::new();
        code.push_str("/// 自动生成：前端资源 SHA-256 哈希清单\n");
        code.push_str("/// 由 build.rs 在编译时计算，用于运行时完整性校验\n");
        code.push_str("pub static RESOURCE_HASHES: &[(&str, &str)] = &[\n");
        for (path, hash) in &entries {
            code.push_str(&format!(
                "    (\"{}\", \"{}\"),\n",
                path.replace('\\', "/"),
                hash
            ));
        }
        code.push_str("];\n");

        let dest = PathBuf::from(&out_dir).join("resource_hashes.rs");
        fs::write(&dest, code).expect("写入 resource_hashes.rs 失败");
        println!("cargo:rerun-if-changed=../dist");
    }

    // ===== 2. DLL 哈希校验（防恶意 DLL 劫持） =====
    // 编译时计算 verthys.dll 的 SHA-256，生成 dll_hash.rs
    // 运行时 worker_init 启动子进程前校验 DLL 完整性
    let dll_candidates = [
        "../../build/core/Release/verthys.dll",
        "../../../build/core/Release/verthys.dll",
        "../build/core/Release/verthys.dll",
    ];
    let mut dll_hash_code = String::new();
    let mut dll_found = false;
    for candidate in &dll_candidates {
        let p = Path::new(candidate);
        if p.exists() {
            if let Ok(data) = fs::read(p) {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let hash = hasher.finalize();
                let hash_hex = format!("{:x}", hash);
                dll_hash_code.push_str(&format!(
                    "/// 自动生成：verthys.dll SHA-256 哈希（编译时计算）\n\
                     /// 用于运行时 DLL 完整性校验，防止恶意 DLL 替换劫持\n\
                     pub static DLL_HASH: Option<&str> = Some(\"{}\");\n",
                    hash_hex
                ));
                dll_found = true;
                println!("cargo:rerun-if-changed={}", candidate);
                break;
            }
        }
    }
    if !dll_found {
        println!("cargo:warning=verthys.dll 未找到，跳过 DLL 哈希生成（开发模式可忽略）");
        dll_hash_code.push_str(
            "/// verthys.dll 未在编译时找到（开发模式常见）\n\
             pub static DLL_HASH: Option<&str> = None;\n",
        );
    }
    let dll_dest = PathBuf::from(&out_dir).join("dll_hash.rs");
    fs::write(&dll_dest, dll_hash_code).expect("写入 dll_hash.rs 失败");

    // ===== 3. 打包素材门禁（企业级：阻断过期素材进入生产包） =====
    //
    // 根治"生产包安全核心启动失败"根因：
    //   打包素材（src-tauri/verthys.dll、src-tauri/binaries/verthys-worker-*.exe）
    //   是手工同步的快照。若与最新构建产物脱节（旧 worker + 新 DLL + 新主程序），
    //   FFI 布局 / 协议不匹配 → worker 子进程启动即崩溃 → 就绪握手失败 →
    //   用户看到"安全核心启动失败"，且生产环境无日志可查，极难定位。
    //
    // 门禁规则（release 构建硬阻断，dev 仅警告）：
    //   1. src-tauri/verthys.dll 必须与 <repo>/build/core/Release/verthys.dll 哈希一致
    //   2. src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe 必须与
    //      verthys-tauri/verthys-worker/target/release/verthys-worker.exe 哈希一致
    //   3. worker 源码（src/**/*.rs、Cargo.toml）不得晚于 worker release 产物
    //      （源码更新后必须重新 cargo build --release 并同步素材）
    verify_bundle_assets();
}

/// 计算文件 SHA-256（十六进制小写）。文件不可读时返回空串（由调用方处理）。
fn sha256_file(path: &Path) -> String {
    match fs::read(path) {
        Ok(data) => {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            format!("{:x}", hasher.finalize())
        }
        Err(_) => String::new(),
    }
}

/// 递归收集目录下所有文件的最新修改时间（用于源码新鲜度校验）。
///
/// 返回 None 表示目录不存在；Some(instant) 为其中最新的 mtime。
fn newest_mtime(dir: &Path) -> Option<std::time::SystemTime> {
    let mut newest: Option<std::time::SystemTime> = None;
    let stack = &mut vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        if let Ok(readdir) = fs::read_dir(&current) {
            for entry in readdir.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(meta) = entry.metadata() {
                    if let Ok(mtime) = meta.modified() {
                        if newest.map_or(true, |n| mtime > n) {
                            newest = Some(mtime);
                        }
                    }
                }
            }
        }
    }
    newest
}

/// 打包素材门禁：校验 src-tauri 下的打包素材与最新构建产物严格一致。
///
/// release 构建（tauri build / cargo build --release）时任一规则不满足即 panic 阻断，
/// 错误信息包含明确的修复命令；dev 构建仅输出 cargo:warning 不阻断。
fn verify_bundle_assets() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let verthys_tauri_dir = manifest_dir
        .parent()
        .expect("无法定位 verthys-tauri 目录")
        .to_path_buf();
    let repo_root = verthys_tauri_dir
        .parent()
        .expect("无法定位仓库根目录")
        .to_path_buf();

    let is_release = !cfg!(debug_assertions);

    // ---- 规则 1：DLL 素材同步校验 ----
    let latest_dll = repo_root.join("build/core/Release/verthys.dll");
    let staged_dll = manifest_dir.join("verthys.dll");
    if latest_dll.exists() {
        println!("cargo:rerun-if-changed={}", latest_dll.display());
        println!("cargo:rerun-if-changed={}", staged_dll.display());
        if !staged_dll.exists() {
            let msg = "❌ 打包素材缺失：src-tauri/verthys.dll 不存在！\n\
                       最新构建产物位于 build/core/Release/verthys.dll。\n\
                       修复：Copy-Item build/core/Release/verthys.dll verthys-tauri/src-tauri/verthys.dll";
            if is_release {
                panic!("{}", msg);
            }
            println!("cargo:warning={}", msg);
        } else {
            let h_latest = sha256_file(&latest_dll);
            let h_staged = sha256_file(&staged_dll);
            if h_latest != h_staged {
                let msg = format!(
                    "❌ 打包素材过期：src-tauri/verthys.dll（{}…）与最新构建产物（{}…）哈希不一致！\n\
                     修复：Copy-Item build/core/Release/verthys.dll verthys-tauri/src-tauri/verthys.dll",
                    &h_staged.chars().take(16).collect::<String>(),
                    &h_latest.chars().take(16).collect::<String>()
                );
                if is_release {
                    panic!("{}", msg);
                }
                println!("cargo:warning={}", msg);
            }
        }
    }

    // ---- 规则 2 + 3：worker 素材同步 + 源码新鲜度校验 ----
    let worker_dir = verthys_tauri_dir.join("verthys-worker");
    let worker_release_exe = worker_dir.join("target/release/verthys-worker.exe");
    let staged_worker = manifest_dir.join("binaries/verthys-worker-x86_64-pc-windows-msvc.exe");
    let worker_src_dir = worker_dir.join("src");

    if worker_src_dir.exists() {
        println!("cargo:rerun-if-changed={}", staged_worker.display());

        // 规则 3：worker 源码不得晚于 release 产物（源码更新未重编译）
        if let Some(src_newest) = newest_mtime(&worker_src_dir) {
            let cargo_toml = worker_dir.join("Cargo.toml");
            let src_newest = match cargo_toml.metadata().and_then(|m| m.modified()) {
                Ok(t) if t > src_newest => t,
                _ => src_newest,
            };
            if let Ok(exe_meta) = worker_release_exe.metadata() {
                if let Ok(exe_mtime) = exe_meta.modified() {
                    if src_newest > exe_mtime {
                        let msg = "❌ worker 源码已更新但未重新编译！\n\
                                   修复：cd verthys-tauri/verthys-worker && cargo build --release，\n\
                                   然后 Copy-Item verthys-worker/target/release/verthys-worker.exe \n\
                                   src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe";
                        if is_release {
                            panic!("{}", msg);
                        }
                        println!("cargo:warning={}", msg);
                    }
                }
            }
        }

        // 规则 2：worker 素材哈希必须与 release 产物一致
        if !worker_release_exe.exists() {
            let msg = "❌ verthys-worker release 构建产物不存在！\n\
                       修复：cd verthys-tauri/verthys-worker && cargo build --release，\n\
                       然后 Copy-Item verthys-worker/target/release/verthys-worker.exe \n\
                       src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe";
            if is_release {
                panic!("{}", msg);
            }
            println!("cargo:warning={}", msg);
        } else if !staged_worker.exists() {
            let msg = "❌ 打包素材缺失：src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe 不存在！\n\
                       修复：Copy-Item verthys-tauri/verthys-worker/target/release/verthys-worker.exe \n\
                       verthys-tauri/src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe";
            if is_release {
                panic!("{}", msg);
            }
            println!("cargo:warning={}", msg);
        } else {
            let h_release = sha256_file(&worker_release_exe);
            let h_staged = sha256_file(&staged_worker);
            if h_release != h_staged {
                let msg = format!(
                    "❌ 打包素材过期：src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe（{}…）\n\
                     与 verthys-worker/target/release/verthys-worker.exe（{}…）哈希不一致！\n\
                     修复：Copy-Item verthys-tauri/verthys-worker/target/release/verthys-worker.exe \n\
                     verthys-tauri/src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe",
                    &h_staged.chars().take(16).collect::<String>(),
                    &h_release.chars().take(16).collect::<String>()
                );
                if is_release {
                    panic!("{}", msg);
                }
                println!("cargo:warning={}", msg);
            }
        }
    }
}

fn collect_hashes(base: &Path, dir: &Path, entries: &mut Vec<(String, String)>) {
    if let Ok(readdir) = fs::read_dir(dir) {
        for entry in readdir.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_hashes(base, &path, entries);
            } else if path.is_file() {
                let rel = path.strip_prefix(base).unwrap();
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                if let Ok(data) = fs::read(&path) {
                    let mut hasher = Sha256::new();
                    hasher.update(&data);
                    let hash = hasher.finalize();
                    let hash_hex = format!("{:x}", hash);
                    entries.push((rel_str, hash_hex));
                }
            }
        }
    }
}

fn generate_empty_hashes(out_dir: &str) {
    let dest = PathBuf::from(out_dir).join("resource_hashes.rs");
    fs::write(
        &dest,
        "pub static RESOURCE_HASHES: &[(&str, &str)] = &[];\n",
    )
    .expect("写入 resource_hashes.rs 失败");
}
