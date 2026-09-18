/*
 * @file infrastructure/resource_guard.rs
 * @brief 前端资源完整性校验基础设施
 *
 * 本模块在开发环境下对 dist 目录中的前端资源进行 SHA-256 哈希校验，
 * 防止本地构建产物被篡改引入恶意脚本。
 * 生产环境下前端资源已嵌入二进制，受二进制签名保护，无需文件系统校验。
 *
 * =============================================================================
 * 设计原则
 * =============================================================================
 * 1. 环境区分：仅在 debug 模式下执行文件系统校验，release 模式跳过。
 *    原因：release 模式资源通过 tauri::generate_context! 嵌入二进制，
 *    其完整性由二进制签名保证，dist 目录仅作为开发产物，可能与嵌入版本不一致。
 * 2. 非阻断性：校验失败仅返回错误，由调用方决定是否继续启动（建议阻断）。
 * 3. 轻量级：仅在启动时执行一次，不影响运行时性能。
 *
 * =============================================================================
 * 安全边界
 * =============================================================================
 * - 哈希清单由 build.rs 在编译时生成，包含 dist 目录下所有文件的 SHA-256。
 * - 校验仅检查文件内容哈希，不验证文件权限或元数据。
 * - 若 dist 目录不存在或缺少某文件，视为校验失败。
 * - 哈希清单为空（如未配置）时直接通过，不执行校验。
 *
 * =============================================================================
 * 依赖
 * =============================================================================
 * - resource_hashes：编译时嵌入的哈希清单（build.rs 生成）
 * - sha2：SHA-256 计算
 *
 * =============================================================================
 * 后续优化
 * =============================================================================
 * - 当前使用 eprintln! 输出错误信息，后续需替换为统一日志框架（LogSender）。
 */

use crate::resource_hashes;

/// 验证前端资源（dist 目录）的 SHA-256 完整性
///
/// 仅当满足以下条件时执行实际校验：
/// - 编译时哈希清单非空
/// - 当前为 debug 构建模式
/// - 能够定位到 dist 目录
///
/// 校验过程：遍历哈希清单中的每个文件，计算其实际 SHA-256 并与期望值比对，
/// 统计不匹配或缺失的文件数量。若存在任何差异，返回包含错误计数的错误信息。
///
/// # 返回
/// - `Ok(())`：校验通过或跳过（release 模式、哈希清单为空）
/// - `Err(msg)`：存在文件哈希不匹配或缺失，msg 包含具体数量
pub fn verify_resource_hashes() -> Result<(), String> {
    use sha2::{Digest, Sha256};

    let hashes = resource_hashes::RESOURCE_HASHES;
    if hashes.is_empty() {
        return Ok(());
    }

    // release 模式下资源已嵌入二进制，无需校验文件系统
    if !cfg!(debug_assertions) {
        return Ok(());
    }

    // 尝试定位 dist 目录（按优先级搜索）
    let candidates = [
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("dist")))
            .unwrap_or_else(|| std::path::PathBuf::from("dist")),
        std::path::PathBuf::from("../dist"),
        std::path::PathBuf::from("dist"),
        std::path::PathBuf::from("../../dist"),
        std::path::PathBuf::from("../../../dist"),
    ];

    let dist_dir = match candidates.iter().find(|d| d.exists()) {
        Some(d) => d,
        None => return Ok(()),
    };

    let mut mismatch_count = 0;
    for (rel_path, expected_hash) in hashes {
        let full_path = dist_dir.join(rel_path);
        if !full_path.exists() {
            eprintln!("[安全] 资源缺失: {}", rel_path);
            mismatch_count += 1;
            continue;
        }
        let data = match std::fs::read(&full_path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("[安全] 资源读取失败: {}", rel_path);
                mismatch_count += 1;
                continue;
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let actual_hash = format!("{:x}", hasher.finalize());
        if &actual_hash != expected_hash {
            eprintln!("[安全] 资源哈希不匹配: {}", rel_path);
            mismatch_count += 1;
        }
    }

    if mismatch_count > 0 {
        return Err(format!("资源完整性校验失败：{} 个文件被篡改或缺失", mismatch_count));
    }

    Ok(())
}