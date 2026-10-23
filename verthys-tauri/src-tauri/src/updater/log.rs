/*
 * updater/log.rs — 更新事件日志与导出
 *
 * 日志是更新链路唯一的本机审计面：事件名、基础字段与脱敏规则必须在写入前
 * 固化，导出时再执行一次同样规则，避免用户把技术路径或完整哈希带走。
 */

use super::marker;
use super::UpdaterError;
use chrono::Utc;
use regex::Regex;
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Once, OnceLock};
use std::time::{Duration, SystemTime};
use tauri::{AppHandle, Manager};
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

static CLEANUP_ONCE: Once = Once::new();
static MIGRATE_ONCE: Once = Once::new();
static SESSION_ID: OnceLock<String> = OnceLock::new();
static INSTALL_ID: OnceLock<String> = OnceLock::new();

/// 合法事件清单。新增事件必须先登记，源码扫描测试会拒绝未登记事件。
#[cfg(test)]
pub const EVENTS: &[&str] = &[
    "config_invalid",
    "check_sent",
    "check_hit",
    "check_miss",
    "check_failed",
    "manifest_invalid",
    "manifest_sig_invalid",
    "precheck_blocked",
    "download_start",
    "download_success",
    "download_failed",
    "size_mismatch",
    "hash_mismatch",
    "pe_version_mismatch",
    "sig_invalid",
    "sig_ok",
    "pubkey_mismatch",
    "authenticode_ok",
    "authenticode_skipped",
    "authenticode_invalid",
    "release_recheck_ok",
    "release_recheck_failed",
    "release_withdrawn",
    "hash_ok",
    "lock_failed",
    "lock_ok",
    "install_handoff",
    "install_failed",
    "health_ok",
    "health_fail",
    "rolled_back",
    "marker_invalid",
    "repair_started",
    "repair_failed",
    "repair_confirmed",
    "cancelled",
    "e2e_failed",
    "e2e_prepared",
];

fn log_root(app: &AppHandle) -> Result<PathBuf, UpdaterError> {
    let base = app.path().app_data_dir().map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法解析应用数据目录: {error}"),
            true,
        )
    })?;
    Ok(base.join("logs").join("updater"))
}

fn log_dir(app: &AppHandle) -> Result<PathBuf, UpdaterError> {
    let dir = log_root(app)?;
    MIGRATE_ONCE.call_once(|| {
        if dir.exists() {
            return;
        }
        let Ok(base) = app.path().app_data_dir() else {
            return;
        };
        let legacy = base.join("updater").join("logs");
        if legacy.exists() {
            if let Some(parent) = dir.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::rename(&legacy, &dir);
        }
    });
    std::fs::create_dir_all(&dir).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法创建日志目录: {error}"),
            true,
        )
    })?;
    CLEANUP_ONCE.call_once(|| cleanup_old_logs(&dir));
    Ok(dir)
}

fn cleanup_old_logs(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(7 * 24 * 60 * 60))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
            continue;
        }
        if let Ok(metadata) = entry.metadata() {
            if metadata
                .modified()
                .map(|time| time < cutoff)
                .unwrap_or(false)
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn log_path(app: &AppHandle) -> Result<PathBuf, UpdaterError> {
    let stamp = Utc::now().format("%Y%m%d");
    Ok(log_dir(app)?.join(format!("updater-{stamp}.jsonl")))
}

fn session_id() -> &'static str {
    SESSION_ID.get_or_init(|| Uuid::new_v4().to_string())
}

fn install_id(app: &AppHandle) -> &'static str {
    INSTALL_ID.get_or_init(|| marker::install_id(app).unwrap_or_default())
}

/// 追加一条事件；失败只影响可观测性，不影响更新主流程。
pub fn append(
    app: &AppHandle,
    event: &str,
    phase: &str,
    code: Option<&str>,
    severity: &str,
    detail: Value,
) {
    let Ok(path) = log_path(app) else {
        return;
    };
    if let Ok(metadata) = std::fs::metadata(&path) {
        if metadata.len() > 5 * 1024 * 1024 {
            let rolled = path.with_extension("1.jsonl");
            let _ = std::fs::rename(&path, &rolled);
        }
    }

    let mut detail = detail;
    redact_value(&mut detail);
    let line = build_record(
        event,
        phase,
        code,
        severity,
        detail,
        session_id(),
        install_id(app),
    );
    let Ok(mut text) = serde_json::to_string(&line) else {
        return;
    };
    text.push('\n');
    if let Err(error) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
    {
        eprintln!("[updater] 日志写入失败: {error}");
    }
}

/// 生成固定基础字段；供写入与测试共用。
fn build_record(
    event: &str,
    phase: &str,
    code: Option<&str>,
    severity: &str,
    detail: Value,
    session_id: &str,
    install_id: &str,
) -> Value {
    json!({
        "ts": Utc::now().to_rfc3339(),
        "eventId": Uuid::new_v4().to_string(),
        "sessionId": session_id,
        "installId": install_id,
        "event": event,
        "phase": phase,
        "code": code,
        "severity": severity,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "detail": detail,
    })
}

/// 导出脱敏日志为 zip；返回用户选择的文件路径。
pub fn export(app: &AppHandle, target: &str) -> Result<String, UpdaterError> {
    let target_path = PathBuf::from(target.trim());
    if !target_path.is_absolute()
        || target_path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.eq_ignore_ascii_case("zip"))
            != Some(true)
    {
        return Err(UpdaterError::new(
            "E_UPDATER_INTERNAL",
            "导出路径必须是绝对路径且以 .zip 结尾",
            false,
        ));
    }
    let dir = log_dir(app)?;
    write_archive(&dir, &target_path)?;
    Ok(target_path.to_string_lossy().to_string())
}

/// 将目录下的 jsonl 日志脱敏后打包；供命令与测试共用。
fn write_archive(source: &Path, target: &Path) -> Result<(), UpdaterError> {
    let parent = target
        .parent()
        .ok_or_else(|| UpdaterError::new("E_UPDATER_INTERNAL", "导出路径缺少父目录", false))?;
    std::fs::create_dir_all(parent).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法创建导出目录: {error}"),
            true,
        )
    })?;

    let temp = parent.join(format!(".updater-export-{}.zip", Uuid::new_v4()));
    let file = std::fs::File::create(&temp).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法创建导出文件: {error}"),
            true,
        )
    })?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut files = Vec::new();

    if let Ok(entries) = std::fs::read_dir(source) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
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
                .map(redact_line)
                .collect::<Vec<_>>()
                .join("\n");
            zip.start_file(name, options).map_err(zip_error)?;
            zip.write_all(redacted.as_bytes()).map_err(|error| {
                UpdaterError::new(
                    "E_UPDATER_INTERNAL",
                    format!("无法写入导出日志: {error}"),
                    true,
                )
            })?;
            files.push(name.to_string());
        }
    }

    let manifest = json!({
        "schemaVersion": 1,
        "generatedAt": Utc::now().to_rfc3339(),
        "redaction": "paths+sha256",
        "files": files,
    });
    zip.start_file("manifest.json", options)
        .map_err(zip_error)?;
    zip.write_all(
        serde_json::to_vec_pretty(&manifest)
            .unwrap_or_default()
            .as_slice(),
    )
    .map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法写入导出清单: {error}"),
            true,
        )
    })?;
    let file = zip.finish().map_err(zip_error)?;
    file.sync_all().map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法同步导出文件: {error}"),
            true,
        )
    })?;
    drop(file);
    let _ = std::fs::remove_file(target);
    std::fs::rename(&temp, target).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        UpdaterError::new(
            "E_UPDATER_INTERNAL",
            format!("无法完成导出文件替换: {error}"),
            true,
        )
    })?;
    Ok(())
}

fn zip_error(error: zip::result::ZipError) -> UpdaterError {
    UpdaterError::new("E_UPDATER_INTERNAL", format!("日志打包失败: {error}"), true)
}

fn redact_line(line: &str) -> String {
    match serde_json::from_str::<Value>(line) {
        Ok(mut value) => {
            redact_value(&mut value);
            serde_json::to_string(&value).unwrap_or_else(|_| redact_text(line))
        }
        Err(_) => redact_text(line),
    }
}

fn redact_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = redact_text(text),
        Value::Array(items) => {
            for item in items {
                redact_value(item);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                redact_value(item);
            }
        }
        _ => {}
    }
}

fn redact_text(text: &str) -> String {
    static PATH_RE: OnceLock<Regex> = OnceLock::new();
    static HASH_RE: OnceLock<Regex> = OnceLock::new();
    let path_re = PATH_RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:[a-z]:\\|\\\\\?\\|\\\\[^\\\s]+\\[^\\\s]+|/(?:home|users|root|tmp)/)[^"]*"#,
        )
        .expect("路径脱敏正则必须合法")
    });
    let hash_re =
        HASH_RE.get_or_init(|| Regex::new(r"\b[0-9a-fA-F]{64}\b").expect("哈希脱敏正则必须合法"));
    let without_paths = path_re.replace_all(text, "<path>");
    hash_re
        .replace_all(&without_paths, |captures: &regex::Captures| {
            format!("{}…", &captures[0][..12])
        })
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{build_record, redact_text, EVENTS};
    use regex::Regex;
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::path::Path;

    #[test]
    fn record_contains_required_schema_fields() {
        let record = build_record(
            "check_hit",
            "Checking",
            None,
            "info",
            json!({ "releaseId": "release-1" }),
            "session-1",
            "install-1",
        );
        for key in [
            "ts",
            "eventId",
            "sessionId",
            "installId",
            "event",
            "phase",
            "code",
            "severity",
            "os",
            "arch",
            "detail",
        ] {
            assert!(record.get(key).is_some(), "缺少字段 {key}");
        }
    }

    #[test]
    fn redaction_removes_full_hash_and_paths() {
        let hash = "a".repeat(64);
        let redacted_hash = redact_text(&hash);
        assert!(!redacted_hash.contains(&hash));
        assert!(redacted_hash.contains("aaaaaaaaaaaa…"));

        assert_eq!(redact_text(r"C:\Users\alice\Verthys\data.bin"), "<path>");
        assert_eq!(
            redact_text(r"C:\Users\Alice Smith\Verthys\data.bin"),
            "<path>"
        );
        assert_eq!(redact_text(r"\\server\share\data.bin"), "<path>");
    }

    #[test]
    fn exported_zip_is_readable_and_redacted() {
        let dir =
            std::env::temp_dir().join(format!("verthys-updater-log-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let line = json!({
            "event": "e2e_prepared",
            "detail": {
                "path": r"C:\Users\alice\Verthys\data.bin",
                "sha256": "a".repeat(64)
            }
        })
        .to_string();
        std::fs::write(dir.join("updater-20260101.jsonl"), format!("{line}\n")).unwrap();
        let target = dir.join("export.zip");
        super::write_archive(&dir, &target).unwrap();

        let file = std::fs::File::open(&target).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        {
            let mut entry = archive.by_name("updater-20260101.jsonl").unwrap();
            let mut text = String::new();
            std::io::Read::read_to_string(&mut entry, &mut text).unwrap();
            assert!(!text.contains("C:\\Users"));
            assert!(!text.contains(&"a".repeat(64)));
            assert!(text.contains("aaaaaaaaaaaa…"));
        }
        assert!(archive.by_name("manifest.json").is_ok());
        drop(archive);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn emitted_events_are_registered() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/updater");
        let pattern = Regex::new(r#"(?s)log::append\(\s*[^,]+,\s*"([a-z_]+)""#).unwrap();
        let mut emitted = BTreeSet::new();
        for entry in std::fs::read_dir(root).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for captures in pattern.captures_iter(&text) {
                emitted.insert(captures[1].to_string());
            }
        }
        let registered: BTreeSet<String> = EVENTS.iter().map(|value| value.to_string()).collect();
        let missing: Vec<_> = emitted.difference(&registered).cloned().collect();
        assert!(missing.is_empty(), "未登记的事件: {missing:?}");
    }
}
