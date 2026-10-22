/*
 * build.rs — 为 worker 生成 verthys.dll 的全文件 SHA-256 基线。
 *
 * 职责边界：只读取构建产物并生成常量，不修改 DLL。
 * 关键约束：Release 构建找不到 DLL 或无法计算基线时必须构建失败，
 * 禁止产出无哈希基线的 worker；哈希必须在 DLL 签名完成后计算。
 */

use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=VERTHYS_DLL_PATH");

    let manifest = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR 缺失"),
    );
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("VERTHYS_DLL_PATH") {
        candidates.push(PathBuf::from(path));
    }
    // 契约输出优先：C 核心刚构建完成的 DLL 是权威产物，打包拷贝可能滞后。
    candidates.push(manifest.join("../../build/core/Release/verthys.dll"));
    candidates.push(manifest.join("../src-tauri/verthys.dll"));

    // 候选 DLL 任一变化都必须重跑本脚本，否则 Release 会沿用旧哈希基线，
    // 导致新构建的 DLL 在运行时被摘要校验拒绝。
    for candidate in &candidates {
        println!("cargo:rerun-if-changed={}", candidate.display());
    }

    let dll = candidates.into_iter().find(|path| path.is_file());
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR 缺失"));
    let target = out_dir.join("expected_dll_hash.rs");

    // Debug 构建的 DLL 来自仓库构建目录，与打包拷贝可能不同步；
    // 仅在 Release 固化基线，避免开发期因路径选择差异误拒绝加载。
    if profile != "release" {
        std::fs::write(
            &target,
            "pub(crate) const EXPECTED_DLL_SHA256: [u8; 32] = [0u8; 32];\n\
             pub(crate) const HAS_EXPECTED_DLL_HASH: bool = false;\n",
        )
        .expect("写入 DLL 哈希占位失败");
        println!("cargo:warning=Debug 构建跳过 verthys.dll 哈希基线");
        return;
    }

    match dll {
        Some(path) => {
            let bytes = std::fs::read(&path).expect("读取 verthys.dll 失败");
            let digest = Sha256::digest(&bytes);
            let mut literal = String::new();
            for (index, byte) in digest.iter().enumerate() {
                if index > 0 {
                    literal.push_str(", ");
                }
                literal.push_str(&format!("0x{:02X}", byte));
            }
            std::fs::write(
                &target,
                format!(
                    "pub(crate) const EXPECTED_DLL_SHA256: [u8; 32] = [{}];\n\
                     pub(crate) const HAS_EXPECTED_DLL_HASH: bool = true;\n",
                    literal
                ),
            )
            .expect("写入 DLL 哈希基线失败");
            println!(
                "cargo:warning=worker DLL hash baseline: {}",
                path.display()
            );
        }
        None => {
            panic!("Release 构建缺少 verthys.dll，无法生成完整性基线");
        }
    }
}
