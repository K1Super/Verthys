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

    // ===== 2. 打包素材清单校验（通道 + 契约 + 配对） =====
    // 打包路径（src-tauri/verthys.dll、src-tauri/binaries/verthys-worker-*.exe）
    // 由两条通道写入：build_dev.ps1（开发签名 DLL + 开发 worker）与
    // build_production.ps1（生产签名 DLL + release worker）。路径相同、字节不同，
    // 因此不能用"与某一通道的最新产物比较"判断新鲜度——那会把另一条通道的
    // 合法产物误报为过期。清单（bundle-assets.json）记录通道、契约与哈希，
    // 门禁按清单校验：通道与构建语义匹配、文件哈希与清单一致、DLL 与契约一致、
    // worker 与 DLL 配对（worker 在编译期固化 DLL 全文件摘要）。
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .parent()
        .expect("无法定位 verthys-tauri 目录")
        .parent()
        .expect("无法定位仓库根目录")
        .to_path_buf();
    let is_release = !cfg!(debug_assertions);

    // Debug 专用开发 DLL 覆盖：开发运行时加载 build_dev 的签名 DLL，其哈希与
    // 生产契约不同。Release 明确禁止该变量，避免开发 DLL 进入生产包。
    println!("cargo:rerun-if-env-changed=VERTHYS_DEV_DLL_PATH");
    let dev_dll_path = std::env::var("VERTHYS_DEV_DLL_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty());
    if is_release && dev_dll_path.is_some() {
        panic!("VERTHYS_DEV_DLL_PATH 仅用于开发构建；Release 构建必须清除该变量");
    }
    let dev_dll_hash = match &dev_dll_path {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_file() {
                panic!(
                    "VERTHYS_DEV_DLL_PATH 指向的 DLL 不存在：{}",
                    path.display()
                );
            }
            println!("cargo:rerun-if-changed={}", path.display());
            let hash = sha256_file(&path);
            if hash.len() != 64 {
                panic!(
                    "VERTHYS_DEV_DLL_PATH 指向的 DLL 不可读取：{}",
                    path.display()
                );
            }
            Some(hash)
        }
        None => None,
    };

    let bundle = load_bundle_manifest(&manifest_dir);

    // 先校验清单与素材本体，再决定是否需要生产契约：
    // 通道/清单错误必须在读取任何构建产物之前给出最准确的失败原因。
    verify_bundle_assets(
        &manifest_dir,
        &repo_root,
        dev_dll_hash.as_deref(),
        is_release,
        bundle.as_ref(),
    );

    // 生产契约只在清单声明 production 通道时才是必需输入；
    // dev 通道不需要生产契约，避免"从未构建生产核心"的工作区产生噪音。
    let need_prod_contract = bundle.as_ref().is_none_or(|b| b.channel == "production");
    let dll_contract = if need_prod_contract {
        match load_dll_contract(&repo_root) {
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
        }
    } else {
        None
    };

    // 运行时 DLL 完整性哈希必须与磁盘上实际会被加载的 DLL 一致：
    // 开发覆盖优先（build_dev.ps1 显式指定），其次打包素材清单（已绑定契约），
    // 最后才是生产契约（清单缺失时的过渡状态）。
    let runtime_dll_hash = dev_dll_hash
        .clone()
        .or_else(|| bundle.as_ref().map(|b| b.dll.sha256.clone()))
        .or_else(|| dll_contract.as_ref().map(|c| c.sha256.clone()));
    let dll_hash_code = match &runtime_dll_hash {
        Some(hash) => format!(
            "/// 自动生成：verthys.dll SHA-256（开发覆盖或打包素材清单）\n\
             /// 用于运行时 DLL 完整性校验，防止恶意 DLL 替换劫持\n\
             pub static DLL_HASH: Option<&str> = Some(\"{}\");\n",
            hash
        ),
        None => "/// verthys.dll 未在编译时定位（开发模式：尚未生成打包素材清单）\n\
                 pub static DLL_HASH: Option<&str> = None;\n"
            .to_string(),
    };
    let dll_dest = PathBuf::from(&out_dir).join("dll_hash.rs");
    fs::write(&dll_dest, dll_hash_code).expect("写入 dll_hash.rs 失败");

    // ===== 3. 核心版本常量（清单兼容门的事实来源） =====
    // 兼容判定若与真实核心版本脱节，会表现为“不兼容也能安装”或“兼容却被拒绝”。
    // 版本常量在编译期直接来自 C 核心头文件；头文件缺失或格式变化时构建失败，
    // 不允许回退到任何手写数值。
    let (core_api_version, core_container_version) = load_core_versions(&repo_root);
    let core_versions_code = format!(
        "/// 编译期从核心 API 头文件解析出的当前接口集版本。\n\
         pub const CORE_API_VERSION: u32 = 0x{:04X};\n\
         /// 编译期从容器头文件解析出的当前容器格式版本。\n\
         pub const CORE_CONTAINER_VERSION: u32 = {};\n",
        core_api_version, core_container_version
    );
    fs::write(
        PathBuf::from(&out_dir).join("core_versions.rs"),
        core_versions_code,
    )
    .expect("写入 core_versions.rs 失败");
}

/// 读取核心头文件中的版本宏；任一缺失即阻断构建，避免兼容门使用过期数值。
fn load_core_versions(repo_root: &Path) -> (u32, u32) {
    // 版本语义唯一事实源：API 版本与容器格式版本同处 verthys_version.h。
    let version_header = repo_root.join("core/include/verthys_version.h");
    println!("cargo:rerun-if-changed={}", version_header.display());

    let text = fs::read_to_string(&version_header).unwrap_or_else(|error| {
        panic!(
            "无法读取核心版本头文件 {}: {error}",
            version_header.display()
        )
    });

    let api = parse_define_u32(&text, "VERTHYS_API_VERSION")
        .unwrap_or_else(|| panic!("核心 API 版本宏缺失或格式非法: {}", version_header.display()));
    let container = parse_define_u32(&text, "VERTHYS_CONTAINER_FORMAT_VERSION")
        .unwrap_or_else(|| panic!("容器格式版本宏缺失或格式非法: {}", version_header.display()));
    (api, container)
}

/// 解析形如 `#define NAME 0x000E` 或 `#define NAME 3u` 的整型宏。
fn parse_define_u32(text: &str, symbol: &str) -> Option<u32> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("#define") || parts.next() != Some(symbol) {
            continue;
        }
        let raw = parts.next()?.trim_end_matches(&['u', 'U'][..]);
        return if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            raw.parse::<u32>().ok()
        };
    }
    None
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
const CONTRACT_FMT_VERSION: u32 = 4;

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
    let m: ArtifactContract = serde_json::from_str(strip_utf8_bom(&text)).ok()?;
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

/// 打包素材清单 schema：字段语义变化时递增，旧清单直接拒绝。
const BUNDLE_SCHEMA: u32 = 1;
/// 打包素材清单文件名（位于 src-tauri/）。
const BUNDLE_MANIFEST_FILE: &str = "bundle-assets.json";
/// 打包路径是 Tauri 配置的固定入口，清单只能描述这两个文件。
const CANONICAL_DLL: &str = "verthys.dll";
const CANONICAL_WORKER: &str = "binaries/verthys-worker-x86_64-pc-windows-msvc.exe";
const PROD_CONTRACT_REL: &str = "build/core/verthys.artifacts.json";
const DEV_CONTRACT_REL: &str = "build_dev/core/verthys.artifacts.json";

/// 打包素材清单：由 staging 脚本按实际字节生成，记录通道、契约与配对关系。
#[derive(serde::Deserialize)]
struct BundleManifest {
    schema: u32,
    channel: String,
    version: String,
    fmt_version: u32,
    producer: String,
    dll: BundleDll,
    worker: BundleWorker,
    contract: BundleContract,
}

#[derive(serde::Deserialize)]
struct BundleDll {
    path: String,
    #[allow(dead_code)]
    source: String,
    sha256: String,
    #[allow(dead_code)]
    built_at: String,
}

#[derive(serde::Deserialize)]
struct BundleWorker {
    path: String,
    #[allow(dead_code)]
    source: String,
    sha256: String,
    #[allow(dead_code)]
    built_at: String,
    dll_sha256: String,
}

#[derive(serde::Deserialize)]
struct BundleContract {
    path: String,
    sha256: String,
}

/// 构建脚本产出的 JSON 可能被 Windows PowerShell 以带 BOM 的 UTF-8 写回；
/// serde_json 不接受 BOM，读取侧统一剥离，避免清单写入者差异阻断构建。
fn strip_utf8_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 读取打包素材清单。缺失返回 None，由门禁按构建模式决定警告或阻断；
/// 存在但格式/字段非法一律 panic：清单只允许构建脚本生成，手工改坏没有合法场景。
fn load_bundle_manifest(manifest_dir: &Path) -> Option<BundleManifest> {
    let path = manifest_dir.join(BUNDLE_MANIFEST_FILE);
    println!("cargo:rerun-if-changed={}", path.display());
    let text = fs::read_to_string(&path).ok()?;
    let manifest: BundleManifest = serde_json::from_str(strip_utf8_bom(&text)).unwrap_or_else(|error| {
        panic!(
            "❌ 打包素材清单格式非法：{}\n{error}\n\
             修复：重新运行 build_production.ps1 或 build_dev.ps1 生成清单",
            path.display()
        )
    });
    if manifest.schema != BUNDLE_SCHEMA {
        panic!(
            "❌ 打包素材清单 schema 不支持：{}（期望 {}）\n\
             修复：重新运行 build_production.ps1 或 build_dev.ps1",
            manifest.schema, BUNDLE_SCHEMA
        );
    }
    if manifest.channel != "dev" && manifest.channel != "production" {
        panic!(
            "❌ 打包素材清单通道非法：{}\n修复：重新运行 build_production.ps1 或 build_dev.ps1",
            manifest.channel
        );
    }
    if manifest.dll.path != CANONICAL_DLL {
        panic!(
            "❌ 打包素材清单 DLL 路径非法：{}（期望 {}）",
            manifest.dll.path, CANONICAL_DLL
        );
    }
    if manifest.worker.path != CANONICAL_WORKER {
        panic!(
            "❌ 打包素材清单 worker 路径非法：{}（期望 {}）",
            manifest.worker.path, CANONICAL_WORKER
        );
    }
    let expected_contract = if manifest.channel == "production" {
        PROD_CONTRACT_REL
    } else {
        DEV_CONTRACT_REL
    };
    if manifest.contract.path != expected_contract {
        panic!(
            "❌ 打包素材清单契约路径与通道不符：{}（channel={}，期望 {}）",
            manifest.contract.path, manifest.channel, expected_contract
        );
    }
    for (label, value) in [
        ("dll.sha256", &manifest.dll.sha256),
        ("worker.sha256", &manifest.worker.sha256),
        ("worker.dll_sha256", &manifest.worker.dll_sha256),
        ("contract.sha256", &manifest.contract.sha256),
    ] {
        if !is_sha256_hex(value) {
            panic!("❌ 打包素材清单 {label} 不是 64 位十六进制哈希：{value}");
        }
    }
    Some(manifest)
}

/// 打包素材门禁：按清单校验打包路径上的字节，而不是与某一条通道的最新产物比较。
///
/// 校验链（任一失配即阻断）：
///   1. 通道与构建语义匹配：release 只能是 production；设置开发 DLL 覆盖时只能是 dev
///   2. DLL / worker 实际哈希与清单一致
///   3. worker 绑定哈希与 DLL 哈希一致（编译期固化的配对不变量）
///   4. DLL 与契约记录的交付字节一致，契约文件本身未被刷新替换
///   5. production 通道额外校验 worker 源码新鲜度
///
/// 清单缺失时：release 阻断；dev 仅警告（尚未部署打包素材的首次编译）。
fn verify_bundle_assets(
    manifest_dir: &Path,
    repo_root: &Path,
    dev_dll_hash: Option<&str>,
    is_release: bool,
    bundle: Option<&BundleManifest>,
) {
    let staged_dll = manifest_dir.join(CANONICAL_DLL);
    let staged_worker = manifest_dir.join(CANONICAL_WORKER);
    println!("cargo:rerun-if-changed={}", staged_dll.display());
    println!("cargo:rerun-if-changed={}", staged_worker.display());

    let Some(bundle) = bundle else {
        if is_release {
            panic!(
                "❌ 打包素材清单缺失：src-tauri/{BUNDLE_MANIFEST_FILE}\n\
                 修复：生产打包先运行 build_production.ps1；开发环境运行 build_dev.ps1"
            );
        }
        println!(
            "cargo:warning=打包素材清单缺失（src-tauri/{BUNDLE_MANIFEST_FILE}），\
             跳过素材一致性校验；运行 build_dev.ps1 或 build_production.ps1 生成"
        );
        return;
    };

    if is_release && bundle.channel != "production" {
        panic!(
            "❌ 打包素材通道错误：release 构建要求 channel=production，实际 channel={}（producer={}）\n\
             修复：运行 build_production.ps1 重新部署打包素材",
            bundle.channel, bundle.producer
        );
    }
    if dev_dll_hash.is_some() && bundle.channel != "dev" {
        panic!(
            "❌ VERTHYS_DEV_DLL_PATH 已设置，但打包素材通道为 {}（producer={}）\n\
             修复：运行 build_dev.ps1 重新部署开发素材",
            bundle.channel, bundle.producer
        );
    }
    if let Some(expected) = dev_dll_hash {
        if expected != bundle.dll.sha256 {
            panic!(
                "❌ 开发 DLL 覆盖与打包素材不一致：VERTHYS_DEV_DLL_PATH={}…，清单={}…\n\
                 修复：运行 build_dev.ps1 重新部署开发素材",
                &expected[..16.min(expected.len())],
                &bundle.dll.sha256[..16.min(bundle.dll.sha256.len())]
            );
        }
    }

    for (label, path, expected) in [
        ("verthys.dll", &staged_dll, &bundle.dll.sha256),
        ("verthys-worker", &staged_worker, &bundle.worker.sha256),
    ] {
        if !path.is_file() {
            panic!(
                "❌ 打包素材缺失：{}\n修复：运行 build_production.ps1 或 build_dev.ps1 重新部署",
                path.display()
            );
        }
        let actual = sha256_file(path);
        if &actual != expected {
            panic!(
                "❌ 打包素材与清单不一致：{}（清单={}… 实际={}…）\n\
                 修复：重新运行 build_production.ps1 或 build_dev.ps1 生成素材与清单",
                label,
                &expected[..16.min(expected.len())],
                &actual[..16.min(actual.len())]
            );
        }
    }

    if bundle.worker.dll_sha256 != bundle.dll.sha256 {
        panic!(
            "❌ 打包素材未配对：worker 绑定 DLL={}…，打包 DLL={}…\n\
             修复：重新构建 worker 与 DLL（build_production.ps1 或 build_dev.ps1）",
            &bundle.worker.dll_sha256[..16.min(bundle.worker.dll_sha256.len())],
            &bundle.dll.sha256[..16.min(bundle.dll.sha256.len())]
        );
    }

    let contract_path = repo_root.join(&bundle.contract.path);
    println!("cargo:rerun-if-changed={}", contract_path.display());
    if !contract_path.is_file() {
        panic!(
            "❌ 打包素材契约缺失：{}\n修复：重新构建 C 核心后重新部署打包素材",
            contract_path.display()
        );
    }
    let contract_file_hash = sha256_file(&contract_path);
    if contract_file_hash != bundle.contract.sha256 {
        panic!(
            "❌ 打包素材契约已被刷新：{}（清单={}… 当前={}…）\n\
             修复：重新运行 build_production.ps1 或 build_dev.ps1 让素材与契约同步",
            contract_path.display(),
            &bundle.contract.sha256[..16.min(bundle.contract.sha256.len())],
            &contract_file_hash[..16.min(contract_file_hash.len())]
        );
    }
    let contract_text = fs::read_to_string(&contract_path).unwrap_or_else(|error| {
        panic!(
            "❌ 无法读取打包素材契约 {}：{error}",
            contract_path.display()
        )
    });
    let contract: ArtifactContract = serde_json::from_str(strip_utf8_bom(&contract_text)).unwrap_or_else(|error| {
        panic!(
            "❌ 打包素材契约格式非法 {}：{error}",
            contract_path.display()
        )
    });
    if contract.sha256 != bundle.dll.sha256 {
        panic!(
            "❌ 打包 DLL 与契约记录不一致（契约={}… 清单={}…）\n\
             修复：重新运行 build_production.ps1 或 build_dev.ps1",
            &contract.sha256[..16.min(contract.sha256.len())],
            &bundle.dll.sha256[..16.min(bundle.dll.sha256.len())]
        );
    }
    if contract.version != bundle.version || contract.fmt_version != bundle.fmt_version {
        panic!(
            "❌ 打包素材版本与契约不一致（契约={}/{}，清单={}/{}）",
            contract.version, contract.fmt_version, bundle.version, bundle.fmt_version
        );
    }

    // worker 源码新鲜度只在生产通道校验：dev worker 由独立 target 目录构建，
    // 与 verthys-worker/target/release 无关。
    if bundle.channel == "production" {
        let worker_dir = manifest_dir
            .parent()
            .expect("无法定位 verthys-tauri 目录")
            .join("verthys-worker");
        let worker_release_exe = worker_dir.join("target/release/verthys-worker.exe");
        let worker_src_dir = worker_dir.join("src");
        println!("cargo:rerun-if-changed={}", worker_src_dir.display());
        println!(
            "cargo:rerun-if-changed={}",
            worker_dir.join("Cargo.toml").display()
        );
        if worker_src_dir.exists() {
            if let Some(src_newest) = newest_mtime(&worker_src_dir) {
                let cargo_toml = worker_dir.join("Cargo.toml");
                let src_newest = match cargo_toml.metadata().and_then(|m| m.modified()) {
                    Ok(t) if t > src_newest => t,
                    _ => src_newest,
                };
                if let Ok(exe_meta) = worker_release_exe.metadata() {
                    if let Ok(exe_mtime) = exe_meta.modified() {
                        if src_newest > exe_mtime {
                            panic!(
                                "❌ worker 源码已更新但未重新编译！\n\
                                 修复：运行 build_production.ps1（不要使用 -SkipWorker）"
                            );
                        }
                    }
                }
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
