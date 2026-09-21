/*
 * util/log_sanitizer.rs — 日志敏感负载脱敏（纯函数，无日志权限）
 *
 * 职责：为「请求/响应 JSON 可能落日志」的场景提供安全摘要，
 * 白名单字段（如 op）保留原值用于排障，其余字段值一律替换为
 * 类型 + 规模占位，杜绝口令、密钥、密文等敏感内容进入日志文件。
 *
 * 契约：
 *   - 输入是合法 JSON → 输出结构等价的摘要 JSON（嵌套递归脱敏）。
 *   - 输入非 JSON   → 输出长度占位，绝不回显原文。
 *   - 白名单命中仅限标量（string/number/bool），
 *     结构化值（object/array）即使字段名在白名单中也只保留规模。
 */
use serde_json::Value;

/// 生成 JSON 负载的日志安全摘要。
/// keep_fields 内的顶层/嵌套标量字段保留原值，其余值只保留类型与规模。
pub(crate) fn json_log_summary(json: &str, keep_fields: &[&str]) -> String {
    match serde_json::from_str::<Value>(json) {
        Ok(v) => serde_json::to_string(&sanitize_value(&v, keep_fields))
            .unwrap_or_else(|_| "<摘要序列化失败>".to_string()),
        Err(_) => format!("<非 JSON 负载, 长度 {}B>", json.len()),
    }
}

/// 递归脱敏：对象键名保留，值按白名单规则替换。
fn sanitize_value(v: &Value, keep: &[&str]) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, val) in map {
                let kept = keep.contains(&k.as_str())
                    && matches!(
                        val,
                        Value::String(_) | Value::Number(_) | Value::Bool(_)
                    );
                let sanitized = if kept {
                    val.clone()
                } else {
                    Value::String(redact_value(val))
                };
                out.insert(k.clone(), sanitized);
            }
            Value::Object(out)
        }
        other => Value::String(redact_value(other)),
    }
}

/// 非白名单值的统一脱敏形态：仅保留类型与规模信息。
fn redact_value(v: &Value) -> String {
    match v {
        Value::String(s) => format!("<str:{}B>", s.len()),
        Value::Number(_) => "<num>".to_string(),
        Value::Bool(_) => "<bool>".to_string(),
        Value::Null => "null".to_string(),
        Value::Array(a) => format!("<arr:{}>", a.len()),
        Value::Object(o) => format!("<obj:{}>", o.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEEP: &[&str] = &["op"];

    #[test]
    fn 敏感字段被脱敏且白名单字段保留() {
        let payload = r#"{"op":"derive_global_key","password":"secret-pw","bin_password":"secret-bp"}"#;
        let out = json_log_summary(payload, KEEP);
        assert!(!out.contains("secret-pw"), "口令明文不得出现: {}", out);
        assert!(!out.contains("secret-bp"), "二进制口令明文不得出现: {}", out);
        assert!(out.contains("derive_global_key"), "白名单 op 应保留: {}", out);
    }

    #[test]
    fn 非json输入只回长度不回原文() {
        let payload = "plain-secret-payload";
        let out = json_log_summary(payload, KEEP);
        assert!(
            out.contains(&format!("<非 JSON 负载, 长度 {}B>", payload.len())),
            "应含长度占位: {}",
            out
        );
        assert!(!out.contains("plain-secret"), "原文不得出现: {}", out);
    }

    #[test]
    fn 嵌套对象与数组递归脱敏() {
        let payload = r#"{"op":"verify","nested":{"password":"inner-secret"},"list":["a","b"]}"#;
        let out = json_log_summary(payload, KEEP);
        assert!(!out.contains("inner-secret"), "嵌套敏感值不得出现: {}", out);
        assert!(out.contains("<obj:1>"), "嵌套对象应以规模占位: {}", out);
        assert!(out.contains("<arr:2>"), "数组应以规模占位: {}", out);
    }

    #[test]
    fn 白名单命中结构化值时仍只保留规模() {
        let payload = r#"{"op":{"evil":"结构化值不应整体保留"}}"#;
        let out = json_log_summary(payload, KEEP);
        assert!(!out.contains("结构化值不应整体保留"), "结构化白名单值应脱敏: {}", out);
    }

    #[test]
    fn 数组顶层负载同样安全() {
        let payload = r#"[{"password":"arr-secret"}]"#;
        let out = json_log_summary(payload, KEEP);
        assert!(!out.contains("arr-secret"), "数组内敏感值不得出现: {}", out);
    }
}
