/*
 * @file infrastructure/log_export.rs
 * @brief 应用诊断日志导出（脱敏 zip）
 *
 * 职责：把 `logs/` 下的应用日志（当前文件与轮转历史）打包为 zip，导出前
 * 统一执行路径与长哈希脱敏。审计日志 `audit.log` 位于 app_config_dir 且
 * 是 HMAC 链式文件，按完整行原样打包、不做字段脱敏，也不做轮转。
 *
 * 安全约束：
 * - 只读取应用日志目录内的普通 `.log` 文件，拒绝符号链接；
 * - 导出目标必须是绝对路径且以 `.zip` 结尾；
 * - 先写临时文件再原子替换，失败不留半成品；
 * - 单文件与总导出量设上限，避免异常日志撑爆导出进程。
 */
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::util::redaction::redact_json_line;

/// 单个日志文件导出上限（异常超大文件跳过）
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// 一次导出总字节上限
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// 导出应用日志到用户指定 zip；返回最终路径
///
/// `audit_log` 若存在则按完整行原样打包（不脱敏），保留 HMAC 链可验证性；
/// 应用日志则逐行脱敏。
pub(crate) fn export(
    log_dir: &Path,
    audit_log: Option<&Path>,
    target: &str,
) -> Result<String, String> {
    let target_path = PathBuf::from(target.trim());
    if !target_path.is_absolute()
        || target_path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.eq_ignore_ascii_case("zip"))
            != Some(true)
    {
        return Err("导出路径必须是绝对路径且以 .zip 结尾".to_string());
    }
    write_archive(log_dir, audit_log, &target_path)?;
    Ok(target_path.to_string_lossy().to_string())
}

/// 将日志目录打包为脱敏 zip；供命令与测试共用
fn write_archive(source: &Path, audit_log: Option<&Path>, target: &Path) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| "导出路径缺少父目录".to_string())?;
    std::fs::create_dir_all(parent).map_err(|error| format!("无法创建导出目录: {error}"))?;

    let temp = parent.join(format!(".diagnostics-export-{}.zip", Uuid::new_v4()));
    let file = std::fs::File::create(&temp)
        .map_err(|error| format!("无法创建导出文件: {error}"))?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut files = Vec::new();
    let mut total_bytes = 0u64;

    if let Ok(entries) = std::fs::read_dir(source) {
        let mut candidates: Vec<PathBuf> = entries
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("log") {
                    return None;
                }
                // 只接受普通文件，符号链接一律跳过
                if entry.file_type().map(|kind| kind.is_file()).unwrap_or(false) {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();
        candidates.sort();

        for path in candidates {
            let size = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
            if size > MAX_FILE_BYTES || total_bytes.saturating_add(size) > MAX_TOTAL_BYTES {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let Ok(payload) = std::fs::read_to_string(&path) else {
                continue;
            };
            let redacted = payload
                .lines()
                .map(redact_json_line)
                .collect::<Vec<_>>()
                .join("\n");
            zip.start_file(name, options).map_err(zip_error)?;
            zip.write_all(redacted.as_bytes()).map_err(|error| {
                format!("无法写入导出日志: {error}")
            })?;
            total_bytes = total_bytes.saturating_add(size);
            files.push(name.to_string());
        }
    }

    // 审计日志按完整行原样打包：HMAC 链依赖逐字节内容，脱敏会破坏可验证性。
    // 只取到最后一个换行，避免并发追加中的半行进入导出包。
    let mut audit_included = false;
    if let Some(audit_path) = audit_log {
        let size = std::fs::metadata(audit_path).map(|meta| meta.len()).unwrap_or(0);
        if size > 0
            && size <= MAX_FILE_BYTES
            && total_bytes.saturating_add(size) <= MAX_TOTAL_BYTES
            && std::fs::symlink_metadata(audit_path)
                .map(|meta| !meta.file_type().is_symlink())
                .unwrap_or(false)
        {
            if let Ok(payload) = std::fs::read_to_string(audit_path) {
                let complete_len = payload.rfind('\n').map(|index| index + 1).unwrap_or(0);
                if complete_len > 0 {
                    zip.start_file("audit.log", options).map_err(zip_error)?;
                    zip.write_all(&payload.as_bytes()[..complete_len])
                        .map_err(|error| format!("无法写入审计日志: {error}"))?;
                    total_bytes = total_bytes.saturating_add(complete_len as u64);
                    files.push("audit.log".to_string());
                    audit_included = true;
                }
            }
        }
    }

    let manifest = json!({
        "schemaVersion": 1,
        "source": "app-logs",
        "generatedAt": Utc::now().to_rfc3339(),
        "redaction": "paths+sha256",
        "auditLogIncluded": audit_included,
        "auditRedaction": "none",
        "files": files,
        "totalBytes": total_bytes,
    });
    zip.start_file("manifest.json", options)
        .map_err(zip_error)?;
    zip.write_all(
        serde_json::to_vec_pretty(&manifest)
            .unwrap_or_default()
            .as_slice(),
    )
    .map_err(|error| format!("无法写入导出清单: {error}"))?;
    let file = zip.finish().map_err(zip_error)?;
    file.sync_all()
        .map_err(|error| format!("无法同步导出文件: {error}"))?;
    drop(file);

    let _ = std::fs::remove_file(target);
    std::fs::rename(&temp, target).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        format!("无法完成导出文件替换: {error}")
    })?;
    Ok(())
}

fn zip_error(error: zip::result::ZipError) -> String {
    format!("日志打包失败: {error}")
}

#[cfg(test)]
mod tests {
    use super::write_archive;
    use std::io::Read;

    #[test]
    fn exported_logs_are_redacted_and_have_manifest() {
        let dir = std::env::temp_dir().join(format!(
            "verthys-app-log-export-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let line = serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "level": "INFO",
            "module": "entry",
            "message": r"open C:\Users\alice\Verthys\vault.verthys",
            "hash": "a".repeat(64),
        })
        .to_string();
        std::fs::write(dir.join("main_ui.log"), format!("{line}\n")).unwrap();
        std::fs::write(dir.join("main_ui.1.log"), format!("{line}\n")).unwrap();
        let target = dir.join("export.zip");
        write_archive(&dir, None, &target).unwrap();

        let file = std::fs::File::open(&target).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        for name in ["main_ui.log", "main_ui.1.log"] {
            let mut entry = archive.by_name(name).unwrap();
            let mut text = String::new();
            entry.read_to_string(&mut text).unwrap();
            assert!(!text.contains("C:\\Users"), "导出不得包含绝对路径: {text}");
            assert!(!text.contains(&"a".repeat(64)), "导出不得包含完整哈希");
            assert!(text.contains("<path>"));
            assert!(text.contains("aaaaaaaaaaaa…"));
        }
        let manifest = {
            let mut entry = archive.by_name("manifest.json").unwrap();
            let mut text = String::new();
            entry.read_to_string(&mut text).unwrap();
            text
        };
        let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(manifest["source"], "app-logs");
        assert_eq!(manifest["redaction"], "paths+sha256");
        assert_eq!(manifest["files"].as_array().unwrap().len(), 2);
        drop(archive);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn non_log_files_are_not_exported() {
        let dir = std::env::temp_dir().join(format!(
            "verthys-app-log-filter-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main_ui.log"), "{\"level\":\"INFO\"}\n").unwrap();
        std::fs::write(dir.join("secret.txt"), "must-not-export").unwrap();
        let target = dir.join("export.zip");
        write_archive(&dir, None, &target).unwrap();

        let file = std::fs::File::open(&target).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        assert!(archive.by_name("main_ui.log").is_ok());
        assert!(archive.by_name("secret.txt").is_err());
        drop(archive);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn audit_log_is_exported_verbatim_without_partial_tail() {
        let dir = std::env::temp_dir().join(format!(
            "verthys-app-log-audit-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // 生产环境 audit.log 位于 app_config_dir，不在 logs/ 下；测试同样放到子目录，
        // 避免它被应用日志遍历重复收集。
        let audit_dir = dir.join("config");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let audit_path = audit_dir.join("audit.log");
        let complete = "{\"event\":{\"event_type\":\"KeyDerive\"},\"prev_hmac\":\"00\",\"hmac\":\"aa\"}\n";
        // 模拟并发追加中的半行：只导出到最后一个换行
        std::fs::write(&audit_path, format!("{complete}{{\"partial\":")).unwrap();
        std::fs::write(dir.join("main_ui.log"), "{\"level\":\"INFO\"}\n").unwrap();
        let target = dir.join("export.zip");
        write_archive(&dir, Some(&audit_path), &target).unwrap();

        let file = std::fs::File::open(&target).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let audit = {
            let mut entry = archive.by_name("audit.log").unwrap();
            let mut text = String::new();
            entry.read_to_string(&mut text).unwrap();
            text
        };
        assert_eq!(audit, complete, "审计日志必须逐字节保留完整行");
        assert!(!audit.contains("partial"));
        let manifest = {
            let mut entry = archive.by_name("manifest.json").unwrap();
            let mut text = String::new();
            entry.read_to_string(&mut text).unwrap();
            text
        };
        let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(manifest["auditLogIncluded"], true);
        assert_eq!(manifest["auditRedaction"], "none");
        drop(archive);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
