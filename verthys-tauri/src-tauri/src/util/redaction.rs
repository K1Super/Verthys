/*
 * util/redaction.rs — 日志导出的路径与长哈希脱敏（纯函数，无日志权限）
 *
 * 职责：应用日志与更新日志在导出前统一执行同一套脱敏规则，避免用户把
 * 本机绝对路径或完整 SHA-256 带走。规则只替换路径与 64 位十六进制串，
 * 不改动时间戳、等级、模块名与错误码，保证导出包仍可用于排障。
 */
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// 递归脱敏 JSON 值：字符串替换路径与长哈希，结构保持不变
pub(crate) fn redact_value(value: &mut Value) {
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

/// 脱敏一行文本；合法 JSON 行按结构处理，非 JSON 行按文本规则处理
pub(crate) fn redact_json_line(line: &str) -> String {
    match serde_json::from_str::<Value>(line) {
        Ok(mut value) => {
            redact_value(&mut value);
            serde_json::to_string(&value).unwrap_or_else(|_| redact_text(line))
        }
        Err(_) => redact_text(line),
    }
}

/// 文本脱敏：Windows/Unix 用户路径 → `<path>`；64 位哈希 → 前 12 位 + 省略号
pub(crate) fn redact_text(text: &str) -> String {
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
    use super::{redact_json_line, redact_text};

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
    fn json_line_redaction_keeps_structure() {
        let line = serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "level": "INFO",
            "module": "entry",
            "message": r"unlock C:\Users\alice\vault.verthys",
            "hash": "b".repeat(64),
        })
        .to_string();
        let redacted = redact_json_line(&line);
        let value: serde_json::Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(value["level"], "INFO");
        assert_eq!(value["module"], "entry");
        assert_eq!(value["timestamp"], "2026-01-01T00:00:00Z");
        assert_eq!(value["message"], "unlock <path>");
        assert_eq!(value["hash"], "bbbbbbbbbbbb…");
    }

    #[test]
    fn non_json_line_is_redacted_as_text() {
        let line = r#"raw log C:\Users\alice\vault.verthys"#;
        assert_eq!(redact_json_line(line), "raw log <path>");
    }
}
