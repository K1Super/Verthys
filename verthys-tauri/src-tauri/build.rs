use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    tauri_build::build();

    let out_dir = std::env::var("OUT_DIR").unwrap();

    // ===== 1. 前端资源哈希校验 =====
    // 计算 dist 目录中所有文件的 SHA-256，生成 resource_hashes.rs
    let dist_dir = PathBuf::from("../dist");

    // 修复修复：release 模式下强制校验 dist/ 存在且包含 index.html
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
    // 编译时从构建产物契约（CMake 构建 C 核心后生成）读取 DLL 路径与
    // SHA-256，生成 dll_hash.rs。不再按生成器类型猜测 DLL 子目录——历史
    // 候选路径（Release 子目录）在 Ninja 单配置构建下全部落空，哈希退化为
    // None，运行时完整性校验静默失效。
    // 契约缺失/失效时：release 构建直接编译失败（阻断无校验产物进入生产），
    // dev 构建仅警告并生成 None（dev 允许未构建 C 核心时进行编译检查）。
    let repo_root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .expect("无法定位 verthys-tauri 目录")
        .parent()
        .expect("无法定位仓库根目录")
        .to_path_buf();
    let is_release = !cfg!(debug_assertions);

    let mut dll_hash_code = String::new();
    let dll_contract = match load_dll_contract(&repo_root) {
        Some(c) if !c.dll_path.exists() => {
            gate_contract_failure(
                is_release,
                &format!(
                    "❌ 构建产物契约指向的 DLL 不存在：{}\n\
                     修复：先运行 build_production.ps1 构建 C 核心（契约由 CMake 构建完成后自动生成）",
                    c.dll_path.display()
                ),
            );
            None
        }
        Some(c) => {
            let actual_hash = sha256_file(&c.dll_path);
            if actual_hash != c.sha256 {
                gate_contract_failure(
                    is_release,
                    &format!(
                        "❌ 构建产物契约已过期：DLL 实际哈希（{}…）与契约记录（{}…）不一致\n\
                         修复：重新构建 C 核心以刷新契约（build_production.ps1 或 cmake --build build）",
                        &actual_hash[..16.min(actual_hash.len())],
                        &c.sha256[..16.min(c.sha256.len())]
                    ),
                );
                None
            } else {
                println!("cargo:rerun-if-changed={}", c.dll_path.display());
                Some(c)
            }
        }
        None => {
            gate_contract_failure(
                is_release,
                "❌ 构建产物契约缺失或无效：build/core/verthys.artifacts.json\n\
                 修复：先运行 build_production.ps1 构建 C 核心（契约由 CMake 构建完成后自动生成）",
            );
            None
        }
    };

    match &dll_contract {
        Some(c) => {
            dll_hash_code.push_str(&format!(
                "/// 自动生成：verthys.dll SHA-256 哈希（来自构建产物契约）\n\
                 /// 用于运行时 DLL 完整性校验，防止恶意 DLL 替换劫持\n\
                 pub static DLL_HASH: Option<&str> = Some(\"{}\");\n",
                c.sha256
            ));
        }
        None => {
            dll_hash_code.push_str(
                "/// verthys.dll 未在编译时定位（开发模式：未构建 C 核心或契约失效）\n\
                 pub static DLL_HASH: Option<&str> = None;\n",
            );
        }
    }
    let dll_dest = PathBuf::from(&out_dir).join("dll_hash.rs");
    fs::write(&dll_dest, dll_hash_code).expect("写入 dll_hash.rs 失败");

    // ===== 3. 打包素材门禁（：阻断过期素材进入生产包） =====
    //
    // 根治"生产包安全核心启动失败"根因：
    //   打包素材（src-tauri/verthys.dll、src-tauri/binaries/verthys-worker-*.exe）
    //   是手工同步的快照。若与最新构建产物脱节（旧 worker + 新 DLL + 新主程序），
    //   FFI 布局 / 协议不匹配 → worker 子进程启动即崩溃 → 就绪握手失败 →
    //   用户看到"安全核心启动失败"，且生产环境无日志可查，极难定位。
    //
    // 门禁规则（release 构建硬阻断，dev 仅警告）：
    //   1. src-tauri/verthys.dll 必须与构建产物契约记录的 DLL 哈希一致
    //      （契约在 C 核心构建完成后由 CMake 自动生成）
    //   2. src-tauri/binaries/verthys-worker-x86_64-pc-windows-msvc.exe 必须与
    //      verthys-tauri/verthys-worker/target/release/verthys-worker.exe 哈希一致
    //   3. worker 源码（src/**/*.rs、Cargo.toml）不得晚于 worker release 产物
    //      （源码更新后必须重新 cargo build --release 并同步素材）
    verify_bundle_assets(dll_contract.as_ref());
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

/// 契约结构差异识别的阈值：当前产物契约仅接受 schema 1。
const CONTRACT_SCHEMA: u32 = 1;
/// 容器格式版本：与 C 核心构建侧写入契约的格式版本常量一致，不匹配即契约失效。
const CONTRACT_FMT_VERSION: u32 = 3;

/// C 核心构建产物契约（由 CMake 在 DLL 链接完成后生成）。
#[derive(serde::Deserialize)]
struct ArtifactContract {
    schema: u32,
    #[allow(dead_code)]
    generator: String,
    #[allow(dead_code)]
    config: String,
    dll: String,
    sha256: String,
    #[allow(dead_code)]
    version: String,
    fmt_version: u32,
    #[allow(dead_code)]
    built_at: String,
}

/// 契约校验通过后的可消费结果：DLL 绝对路径与期望 SHA-256。
struct DllContract {
    dll_path: PathBuf,
    sha256: String,
}

/// 读取并校验构建产物契约。
///
/// 契约文件按外部输入对待：schema 与 fmt_version 必须等于已知常量；
/// `dll` 字段必须是纯相对路径（拒绝绝对路径与 `..` 组件，防止解引用
/// 逃逸出仓库根目录）；`sha256` 必须是 64 位小写十六进制字面量。
/// 任何校验失败返回 None，由调用方按构建模式决定警告或阻断。
fn load_dll_contract(repo_root: &Path) -> Option<DllContract> {
    let manifest_path = repo_root.join("build/core/verthys.artifacts.json");
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    let text = fs::read_to_string(&manifest_path).ok()?;
    let m: ArtifactContract = serde_json::from_str(&text).ok()?;
    if m.schema != CONTRACT_SCHEMA || m.fmt_version != CONTRACT_FMT_VERSION {
        println!("cargo:warning=构建产物契约 schema/fmt_version 不匹配，忽略该契约");
        return None;
    }
    let rel = Path::new(&m.dll);
    let has_up_dir = rel
        .components()
        .any(|c| !matches!(c, std::path::Component::Normal(_)));
    if rel.is_absolute() || rel.as_os_str().is_empty() || has_up_dir {
        println!("cargo:warning=构建产物契约 dll 路径非法（绝对路径或含越界组件），忽略该契约");
        return None;
    }
    if m.sha256.len() != 64 || !m.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        println!("cargo:warning=构建产物契约 sha256 字段格式非法，忽略该契约");
        return None;
    }
    Some(DllContract {
        dll_path: repo_root.join(rel),
        sha256: m.sha256,
    })
}

/// 契约失败门禁：release 构建硬阻断（panic 携带修复指引），dev 构建仅警告。
fn gate_contract_failure(is_release: bool, msg: &str) {
    if is_release {
        panic!("{}", msg);
    }
    println!("cargo:warning={}", msg.replace('\n', " "));
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
                        if newest.is_none_or(|n| mtime > n) {
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
/// DLL 规则的最新产物路径取自构建产物契约；契约缺失时跳过 DLL 规则
/// （仅 dev 可能发生，生成 DLL 哈希处已先行警告）。worker 规则独立于 DLL
/// 规则执行，一方失效不抑制另一方。
/// release 构建（tauri build / cargo build --release）时任一规则不满足即 panic 阻断，
/// 错误信息包含明确的修复命令；dev 构建仅输出 cargo:warning 不阻断。
fn verify_bundle_assets(dll_contract: Option<&DllContract>) {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let verthys_tauri_dir = manifest_dir
        .parent()
        .expect("无法定位 verthys-tauri 目录")
        .to_path_buf();

    let is_release = !cfg!(debug_assertions);

    // ---- 规则 1：DLL 素材同步校验 ----
    if let Some(contract) = dll_contract {
        let latest_dll = &contract.dll_path;
        let staged_dll = manifest_dir.join("verthys.dll");
        println!("cargo:rerun-if-changed={}", latest_dll.display());
        println!("cargo:rerun-if-changed={}", staged_dll.display());
        if !staged_dll.exists() {
            let msg = format!(
                "❌ 打包素材缺失：src-tauri/verthys.dll 不存在！\n\
                 最新构建产物位于 {}。\n\
                 修复：Copy-Item {} verthys-tauri/src-tauri/verthys.dll",
                latest_dll.display(),
                latest_dll.display()
            );
            if is_release {
                panic!("{}", msg);
            }
            println!("cargo:warning={}", msg);
        } else {
            let h_latest = sha256_file(latest_dll);
            let h_staged = sha256_file(&staged_dll);
            if h_latest != h_staged {
                let msg = format!(
                    "❌ 打包素材过期：src-tauri/verthys.dll（{}…）与最新构建产物（{}…）哈希不一致！\n\
                     修复：Copy-Item {} verthys-tauri/src-tauri/verthys.dll",
                    h_staged.chars().take(16).collect::<String>(),
                    h_latest.chars().take(16).collect::<String>(),
                    latest_dll.display()
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
                    h_staged.chars().take(16).collect::<String>(),
                    h_release.chars().take(16).collect::<String>()
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
