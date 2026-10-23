/*
 * updater/verify.rs — 安装包与清单的签名复验
 *
 * 插件在下载阶段已经用配置公钥校验过安装包；本模块再次用同一信任根复验，
 * 以便区分“签名损坏”和“签名来自其他密钥”。清单签名覆盖去掉签名对象后的
 * 规范化 JSON，客户端重新规范化后验证，不依赖字段顺序与空白。
 */

use super::UpdaterError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use minisign_verify::{Error as MinisignError, PublicKey, Signature};
use serde_json::Value;
use tauri::AppHandle;

fn updater_config(app: &AppHandle) -> Result<&Value, UpdaterError> {
    app.config()
        .plugins
        .0
        .get("updater")
        .ok_or_else(|| UpdaterError::new("E_UPDATER_SIG_INVALID", "缺少更新插件配置", false))
}

fn decode_public_key(encoded: &str) -> Result<PublicKey, UpdaterError> {
    let raw = STANDARD
        .decode(encoded)
        .map_err(|_| UpdaterError::new("E_UPDATER_SIG_INVALID", "公钥不是合法 Base64", false))?;
    let text = String::from_utf8(raw)
        .map_err(|_| UpdaterError::new("E_UPDATER_SIG_INVALID", "公钥不是 UTF-8", false))?;
    PublicKey::decode(&text)
        .map_err(|_| UpdaterError::new("E_UPDATER_SIG_INVALID", "公钥格式非法", false))
}

fn decode_signature(encoded: &str) -> Result<Signature, UpdaterError> {
    let raw = STANDARD
        .decode(encoded)
        .map_err(|_| UpdaterError::new("E_UPDATER_SIG_INVALID", "签名不是合法 Base64", false))?;
    let text = String::from_utf8(raw)
        .map_err(|_| UpdaterError::new("E_UPDATER_SIG_INVALID", "签名不是 UTF-8", false))?;
    Signature::decode(&text)
        .map_err(|_| UpdaterError::new("E_UPDATER_SIG_INVALID", "签名格式非法", false))
}

fn verify_with_key(
    public_key: &PublicKey,
    bytes: &[u8],
    signature: &Signature,
) -> Result<(), UpdaterError> {
    match public_key.verify(bytes, signature, true) {
        Ok(()) => Ok(()),
        Err(MinisignError::UnexpectedKeyId) => Err(UpdaterError::new(
            "E_UPDATER_SIG_PUBKEY_MISMATCH",
            "签名 key id 与内置公钥不匹配",
            false,
        )),
        Err(_) => Err(UpdaterError::new(
            "E_UPDATER_SIG_INVALID",
            "签名校验失败",
            false,
        )),
    }
}

/// 复验安装包签名；公钥取自更新插件配置，与插件下载阶段使用同一信任根。
pub fn verify_installer(
    app: &AppHandle,
    bytes: &[u8],
    signature_base64: &str,
) -> Result<(), UpdaterError> {
    let config = updater_config(app)?;
    let encoded = config
        .get("pubkey")
        .and_then(Value::as_str)
        .ok_or_else(|| UpdaterError::new("E_UPDATER_SIG_INVALID", "缺少内置公钥", false))?;
    verify_bytes_with_pubkey(encoded, bytes, signature_base64)
}

/// 使用指定公钥复验字节签名；供安装包校验与纯函数测试复用。
pub fn verify_bytes_with_pubkey(
    encoded_pubkey: &str,
    bytes: &[u8],
    signature_base64: &str,
) -> Result<(), UpdaterError> {
    let public_key = decode_public_key(encoded_pubkey)?;
    let signature = decode_signature(signature_base64)?;
    verify_with_key(&public_key, bytes, &signature)
}

/// 复验清单签名；未配置清单公钥时回退到安装包公钥，便于本机验证。
pub fn verify_manifest_signature(app: &AppHandle, raw: &Value) -> Result<(), UpdaterError> {
    let config = updater_config(app)?;
    let encoded = config
        .get("manifestPubkey")
        .or_else(|| config.get("pubkey"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            UpdaterError::new("E_UPDATER_MANIFEST_SIG_INVALID", "未配置清单公钥", false)
        })?;
    verify_manifest_bytes_with_pubkey(raw, encoded)
}

/// 使用指定公钥复验清单签名；供命令与纯函数测试复用。
pub fn verify_manifest_bytes_with_pubkey(
    raw: &Value,
    encoded_pubkey: &str,
) -> Result<(), UpdaterError> {
    let signature_base64 = raw
        .get("manifest_signature")
        .and_then(|value| value.get("signature"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            UpdaterError::new("E_UPDATER_MANIFEST_SIG_INVALID", "清单签名结构非法", false)
        })?;
    let mut unsigned = raw.clone();
    if let Some(object) = unsigned.as_object_mut() {
        object.remove("manifest_signature");
    }
    let canonical = canonical_json(&unsigned)?;
    verify_bytes_with_pubkey(encoded_pubkey, canonical.as_bytes(), signature_base64).map_err(
        |error| {
            UpdaterError::new(
                "E_UPDATER_MANIFEST_SIG_INVALID",
                error.message.as_str(),
                false,
            )
        },
    )
}

/// 规范化 JSON：对象键排序、无空白、整数直接输出。
///
/// 清单只使用字符串、整数、布尔、数组与对象；不使用浮点数，避免不同运行时
/// 对数字文本化的差异。该约束由清单生成脚本保证。
fn canonical_json(value: &Value) -> Result<String, UpdaterError> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => {
            if value.is_f64() {
                return Err(UpdaterError::new(
                    "E_UPDATER_MANIFEST_SIG_INVALID",
                    "清单不允许浮点数",
                    false,
                ));
            }
            Ok(value.to_string())
        }
        Value::String(value) => serde_json::to_string(value).map_err(|_| {
            UpdaterError::new("E_UPDATER_MANIFEST_SIG_INVALID", "字符串序列化失败", false)
        }),
        Value::Array(items) => {
            let mut output = String::from("[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&canonical_json(item)?);
            }
            output.push(']');
            Ok(output)
        }
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let mut output = String::from("{");
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).map_err(|_| {
                    UpdaterError::new("E_UPDATER_MANIFEST_SIG_INVALID", "键名序列化失败", false)
                })?);
                output.push(':');
                output.push_str(&canonical_json(&map[key])?);
            }
            output.push('}');
            Ok(output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_json, verify_bytes_with_pubkey, verify_manifest_bytes_with_pubkey};
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn canonical_json_sorts_keys_and_omits_spaces() {
        let value = json!({ "b": 2, "a": ["x", true] });
        assert_eq!(canonical_json(&value).unwrap(), r#"{"a":["x",true],"b":2}"#);
    }

    #[test]
    fn canonical_json_rejects_float() {
        let value = json!({ "value": 1.5 });
        assert!(canonical_json(&value).is_err());
    }

    #[test]
    fn verifies_signed_local_manifest_when_artifact_exists() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let manifest_path = root.join("build/updater/latest.json");
        if !manifest_path.exists() {
            return;
        }
        let config: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("verthys-tauri/src-tauri/tauri.conf.json")).unwrap(),
        )
        .unwrap();
        let pubkey = config["plugins"]["updater"]["pubkey"].as_str().unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();
        verify_manifest_bytes_with_pubkey(&manifest, pubkey).unwrap();
    }

    #[test]
    fn verifies_real_installer_when_artifact_exists() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let manifest_path = root.join("build/updater/latest.json");
        if !manifest_path.exists() {
            return;
        }
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let platform = &manifest["platforms"]["windows-x86_64"];
        let file_name = platform["url"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        let installer = manifest_path.parent().unwrap().join(file_name);
        if !installer.exists() {
            return;
        }
        let config: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("verthys-tauri/src-tauri/tauri.conf.json")).unwrap(),
        )
        .unwrap();
        let pubkey = config["plugins"]["updater"]["pubkey"].as_str().unwrap();
        let bytes = std::fs::read(installer).unwrap();
        verify_bytes_with_pubkey(pubkey, &bytes, platform["signature"].as_str().unwrap()).unwrap();
    }
}
