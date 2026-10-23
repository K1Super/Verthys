/*
 * updater/manifest.rs — 清单扩展字段解析与准入判定
 *
 * Tauri 插件只解析 version / notes / pub_date / platforms.signature / platforms.url；
 * 其余字段由本模块读取 raw_json 后执行。任何字段的失败都必须在此处拒绝，
 * 不能把“字段存在”当成“已生效”。
 */

use super::{transport, verify, UpdaterError};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tauri::AppHandle;
use tauri_plugin_updater::Update;

// 版本常量由构建脚本在编译期解析核心头文件生成。手写常量会随核心升级静默失配，
// 使兼容门永远判定通过，因此这里不允许出现任何字面量回退。
include!(concat!(env!("OUT_DIR"), "/core_versions.rs"));

/// 单个安装包允许的最大字节数；下载层与清单层共用同一上限，避免内存被无限流耗尽。
pub(crate) const MAX_INSTALLER_BYTES: u64 = 512 * 1024 * 1024;

/// 通过准入判定的清单视图。
#[derive(Debug, Clone)]
pub struct ValidatedManifest {
    pub release_id: String,
    pub channel: String,
    pub version: String,
    pub force_update: bool,
    pub size: u64,
    pub sha256: String,
    pub file_version: String,
    pub download_url: String,
    /// 允许的重定向主机；初始主机已在其中，清单渠道决定是否放宽回环。
    pub allowed_download_hosts: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Compatibility {
    abi: Option<AbiRange>,
    container: Option<ContainerRange>,
}

#[derive(Debug, Deserialize, Default)]
struct AbiRange {
    min: Option<String>,
    max: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ContainerRange {
    min: Option<u32>,
    max: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct Rollout {
    percentage: u8,
    #[serde(default)]
    salt: String,
}

/// 校验清单并返回可安装视图；返回 `None` 表示暂停、撤回或灰度未命中。
pub fn validate(
    app: &AppHandle,
    update: &Update,
    channel: &str,
    install_id: &str,
) -> Result<Option<ValidatedManifest>, UpdaterError> {
    let raw = &update.raw_json;

    let schema_version = raw
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("清单缺少 schema_version"))?;
    if schema_version != 2 {
        return Err(invalid("清单 schema_version 不受支持"));
    }

    let manifest_signature = raw.get("manifest_signature");
    if manifest_signature.is_some() {
        verify::verify_manifest_signature(app, raw)?;
    } else if channel != "local" {
        return Err(UpdaterError::new(
            "E_UPDATER_MANIFEST_SIG_INVALID",
            "非本机渠道的清单必须带签名",
            false,
        ));
    }

    let release_id = raw
        .get("release_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid("清单缺少 release_id"))?
        .to_string();

    let manifest_channel = raw
        .get("channel")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("清单缺少 channel"))?;
    if manifest_channel != channel {
        return Err(UpdaterError::new(
            "E_UPDATER_CHANNEL_MISMATCH",
            "清单渠道与请求渠道不一致",
            false,
        ));
    }

    if raw.get("paused").and_then(Value::as_bool).unwrap_or(false) {
        return Ok(None);
    }

    let revoked = raw
        .get("revoked_release_ids")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .any(|item| item == release_id)
        })
        .unwrap_or(false);
    if revoked {
        return Err(UpdaterError::new(
            "E_UPDATER_INSTALL_REVOKED",
            "该发布已被撤回",
            false,
        ));
    }

    let version = raw
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("清单缺少 version"))?;
    if version != update.version {
        return Err(invalid("清单版本与插件解析结果不一致"));
    }

    let current = semver::Version::parse(&update.current_version)
        .map_err(|_| invalid("当前版本不是合法 SemVer"))?;
    let target = semver::Version::parse(version).map_err(|_| invalid("清单版本不是合法 SemVer"))?;
    if target <= current {
        return Err(UpdaterError::new(
            "E_UPDATER_VERSION_BLOCKED",
            "目标版本不高于当前版本",
            false,
        ));
    }

    let min_version = raw
        .get("min_version")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if let Some(minimum) = &min_version {
        let minimum =
            semver::Version::parse(minimum).map_err(|_| invalid("min_version 不是合法 SemVer"))?;
        if current < minimum {
            return Err(UpdaterError::new(
                "E_UPDATER_BRIDGE_REQUIRED",
                "需要先安装桥接版本",
                false,
            ));
        }
    }

    let force_below = raw
        .get("force_below")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let force_update = if let Some(minimum) = &force_below {
        let minimum =
            semver::Version::parse(minimum).map_err(|_| invalid("force_below 不是合法 SemVer"))?;
        current < minimum
    } else {
        false
    };

    validate_compatibility(raw)?;

    let rollout: Rollout = raw
        .get("rollout")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| invalid("rollout 结构非法"))?
        .unwrap_or(Rollout {
            percentage: 100,
            salt: String::new(),
        });
    if rollout.percentage > 100 {
        return Err(invalid("rollout.percentage 超出范围"));
    }
    if rollout.percentage < 100 {
        let bucket = rollout_bucket(install_id, &rollout.salt);
        if bucket >= u32::from(rollout.percentage) * 100 {
            return Ok(None);
        }
    }

    let platform =
        select_platform(raw, &update.target).ok_or_else(|| invalid("清单缺少当前平台的物料"))?;
    let (download_url, allowed_download_hosts) =
        validate_download_url(app, platform, channel, update)?;
    let size = platform
        .get("size")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0 && *value <= MAX_INSTALLER_BYTES)
        .ok_or_else(|| invalid("清单 size 非法或超过允许上限"))?;
    let sha256 = platform
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| invalid("清单 sha256 非法"))?
        .to_ascii_lowercase();
    let file_version = platform
        .get("file_version")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("清单缺少 file_version"))?;
    let file_version = normalize_three(file_version)?;
    if file_version != normalize_three(version)? {
        return Err(invalid("file_version 与 version 不一致"));
    }

    Ok(Some(ValidatedManifest {
        release_id,
        channel: channel.to_string(),
        version: version.to_string(),
        force_update,
        size,
        sha256,
        file_version,
        download_url,
        allowed_download_hosts,
    }))
}

/// 校验清单声明的 ABI 与容器区间是否覆盖当前核心。
///
/// 当前版本来自编译期生成常量；任一区间不含当前值即拒绝，未知或缺失视为
/// 不声明限制。该函数不依赖运行期上下文，便于用当前常量做回归断言。
fn validate_compatibility(raw: &Value) -> Result<(), UpdaterError> {
    let compatibility: Compatibility = raw
        .get("compatibility")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| invalid("compatibility 结构非法"))?
        .unwrap_or_default();
    if let Some(abi) = compatibility.abi {
        if let Some(minimum) = abi.min.as_deref() {
            let minimum = parse_hex_version(minimum)?;
            if CORE_API_VERSION < minimum {
                return Err(compat("当前 ABI 低于清单要求"));
            }
        }
        if let Some(maximum) = abi.max.as_deref() {
            let maximum = parse_hex_version(maximum)?;
            if CORE_API_VERSION > maximum {
                return Err(compat("当前 ABI 高于清单上限"));
            }
        }
    }
    if let Some(container) = compatibility.container {
        if let Some(minimum) = container.min {
            if CORE_CONTAINER_VERSION < minimum {
                return Err(compat("当前容器版本低于清单要求"));
            }
        }
        if let Some(maximum) = container.max {
            if CORE_CONTAINER_VERSION > maximum {
                return Err(compat("当前容器版本高于清单上限"));
            }
        }
    }
    Ok(())
}

/// 选择平台物料。NSIS 键优先，与插件安装器类型一致；其余键仅作兼容回退。
fn select_platform<'a>(raw: &'a Value, target: &str) -> Option<&'a Value> {
    let platforms = raw.get("platforms")?.as_object()?;
    let nsis = format!("{target}-nsis");
    platforms
        .get(&nsis)
        .or_else(|| platforms.get(target))
        .or_else(|| platforms.get("windows-x86_64-nsis"))
        .or_else(|| platforms.get("windows-x86_64"))
}

/// 校验平台下载地址：必须与插件解析结果一致，并满足渠道的协议与主机限制。
fn validate_download_url(
    app: &AppHandle,
    platform: &Value,
    channel: &str,
    update: &Update,
) -> Result<(String, Vec<String>), UpdaterError> {
    let raw = platform
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("清单缺少平台下载地址"))?;
    let endpoint = endpoint_host(app);
    let configured = configured_download_hosts(app);
    validate_download_url_value(
        raw,
        channel,
        &update.download_url,
        endpoint.as_deref(),
        &configured,
    )
}

/// 纯函数形式的下载地址校验；便于用固定输入覆盖各渠道边界。
fn validate_download_url_value(
    raw: &str,
    channel: &str,
    plugin_url: &reqwest::Url,
    endpoint_host: Option<&str>,
    configured_hosts: &[String],
) -> Result<(String, Vec<String>), UpdaterError> {
    let parsed = reqwest::Url::parse(raw).map_err(|_| invalid("清单下载地址不是合法 URL"))?;
    if &parsed != plugin_url {
        return Err(invalid("清单下载地址与插件解析结果不一致"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid("清单下载地址不得包含凭据"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid("清单下载地址缺少主机"))?
        .to_ascii_lowercase();

    if channel == "local" {
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(invalid("本机渠道下载地址协议非法"));
        }
        if !transport::is_loopback_host(&host) {
            return Err(invalid("本机渠道下载地址必须指向回环主机"));
        }
        return Ok((parsed.to_string(), vec![host]));
    }

    if parsed.scheme() != "https" {
        return Err(invalid("非本机渠道下载地址必须使用 https"));
    }
    let endpoint_ok = endpoint_host.is_some_and(|value| value.eq_ignore_ascii_case(&host));
    let listed = configured_hosts
        .iter()
        .any(|value| value.eq_ignore_ascii_case(&host));
    if !endpoint_ok && !listed {
        return Err(invalid("下载地址主机不在允许范围"));
    }

    let mut allowed = vec![host];
    for value in configured_hosts {
        let value = value.to_ascii_lowercase();
        if !allowed.contains(&value) {
            allowed.push(value);
        }
    }
    Ok((parsed.to_string(), allowed))
}

/// 读取构建时写入的更新渠道；缺失时按稳定渠道处理。
pub(crate) fn configured_channel(app: &AppHandle) -> Result<String, UpdaterError> {
    let channel = app
        .config()
        .plugins
        .0
        .get("updater")
        .and_then(|value| value.get("channel"))
        .and_then(Value::as_str)
        .unwrap_or("stable");
    if !matches!(channel, "local" | "internal" | "beta" | "stable") {
        return Err(config_invalid("更新渠道配置非法"));
    }
    Ok(channel.to_string())
}

/// Authenticode 验证策略。
///
/// 生产渠道必须开启；本机渠道默认关闭，便于回环物料在未做系统签名时仍可验证
/// 更新链路。指纹与主体为可选的额外钉扎，未配置时只要求系统信任链通过。
#[derive(Debug, Clone, Default)]
pub(crate) struct AuthenticodeConfig {
    pub require: bool,
    pub revocation: bool,
    pub subject: Option<String>,
    pub thumbprint: Option<String>,
}

/// 读取 Authenticode 策略；结构或指纹格式非法时拒绝更新。
pub(crate) fn authenticode_config(app: &AppHandle) -> Result<AuthenticodeConfig, UpdaterError> {
    let Some(value) = app
        .config()
        .plugins
        .0
        .get("updater")
        .and_then(|updater| updater.get("authenticode"))
    else {
        return Ok(AuthenticodeConfig::default());
    };
    if !value.is_object() {
        return Err(config_invalid("Authenticode 配置必须是对象"));
    }
    let require = value
        .get("require")
        .map(|item| {
            item.as_bool()
                .ok_or_else(|| config_invalid("Authenticode require 必须是布尔值"))
        })
        .transpose()?
        .unwrap_or(false);
    let revocation = value
        .get("revocation")
        .map(|item| {
            item.as_bool()
                .ok_or_else(|| config_invalid("Authenticode revocation 必须是布尔值"))
        })
        .transpose()?
        .unwrap_or(true);
    let subject = value
        .get("subject")
        .map(|item| {
            item.as_str()
                .ok_or_else(|| config_invalid("Authenticode subject 必须是字符串"))
        })
        .transpose()?
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string);
    let thumbprint = value
        .get("thumbprint")
        .map(|item| {
            item.as_str()
                .ok_or_else(|| config_invalid("Authenticode thumbprint 必须是字符串"))
        })
        .transpose()?
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(normalize_thumbprint)
        .transpose()?;
    Ok(AuthenticodeConfig {
        require,
        revocation,
        subject,
        thumbprint,
    })
}

/// 证书指纹只保留十六进制并统一大写；长度必须为 SHA-1 的 40 位。
fn normalize_thumbprint(raw: &str) -> Result<String, UpdaterError> {
    let value: String = raw
        .chars()
        .filter(|character| !character.is_whitespace() && *character != ':')
        .collect();
    if value.len() != 40 || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(config_invalid("Authenticode 指纹必须是 40 位十六进制"));
    }
    Ok(value.to_ascii_uppercase())
}

/// 审计有效配置；不合法即禁用更新，避免明文或占位端点进入运行期。
pub fn audit_config(app: &AppHandle) -> Result<(), UpdaterError> {
    let channel = configured_channel(app)?;
    let updater = app
        .config()
        .plugins
        .0
        .get("updater")
        .ok_or_else(|| config_invalid("缺少更新插件配置"))?;
    let endpoints = updater
        .get("endpoints")
        .and_then(Value::as_array)
        .ok_or_else(|| config_invalid("更新端点配置缺失"))?;
    if endpoints.is_empty() {
        return Err(config_invalid("更新端点不能为空"));
    }
    let insecure = updater
        .get("dangerousInsecureTransportProtocol")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let pubkey = updater
        .get("pubkey")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if pubkey.is_empty() {
        return Err(config_invalid("更新公钥缺失"));
    }

    for (index, endpoint) in endpoints.iter().enumerate() {
        let raw = endpoint
            .as_str()
            .ok_or_else(|| config_invalid(format!("更新端点 {index} 非法")))?;
        let url = reqwest::Url::parse(raw)
            .map_err(|_| config_invalid(format!("更新端点 {index} 不是合法 URL")))?;
        let host = url
            .host_str()
            .ok_or_else(|| config_invalid(format!("更新端点 {index} 缺少主机")))?
            .to_ascii_lowercase();
        if channel == "local" {
            if url.scheme() != "http" && url.scheme() != "https" {
                return Err(config_invalid("本机更新端点协议非法"));
            }
            if !transport::is_loopback_host(&host) {
                return Err(config_invalid("本机更新端点必须指向回环主机"));
            }
            if url.scheme() == "http" && !insecure {
                return Err(config_invalid("本机 HTTP 端点未开启明文传输许可"));
            }
        } else {
            if url.scheme() != "https" {
                return Err(config_invalid("生产更新端点必须使用 https"));
            }
            if insecure {
                return Err(config_invalid("生产环境不允许明文传输开关"));
            }
            if is_placeholder_host(&host) {
                return Err(config_invalid("生产更新端点仍是占位主机"));
            }
        }
    }
    // 生产渠道必须在系统信任层验证安装包；仅靠 minisign 无法覆盖 SmartScreen
    // 与外部分发场景。本机渠道允许关闭，避免开发物料因未做系统签名而不可测。
    let authenticode = authenticode_config(app)?;
    if channel != "local" && !authenticode.require {
        return Err(config_invalid("生产更新必须启用 Authenticode"));
    }
    if channel != "local" && !authenticode.revocation {
        return Err(config_invalid("生产更新必须检查证书吊销状态"));
    }
    Ok(())
}

fn is_placeholder_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    transport::is_loopback_host(&host)
        || host == "example.com"
        || host.ends_with(".example")
        || host.ends_with(".invalid")
        || host.ends_with(".test")
}

fn config_invalid(message: impl Into<String>) -> UpdaterError {
    UpdaterError::new("E_UPDATER_CONFIG_INVALID", message, false)
}

/// 读取首个更新端点主机；生产下载地址必须与端点或配置白名单一致。
fn endpoint_host(app: &AppHandle) -> Option<String> {
    let endpoints = app
        .config()
        .plugins
        .0
        .get("updater")?
        .get("endpoints")?
        .as_array()?;
    let raw = endpoints.first()?.as_str()?;
    reqwest::Url::parse(raw)
        .ok()?
        .host_str()
        .map(|value| value.to_ascii_lowercase())
}

/// 读取允许的下载主机白名单；未配置时仅允许端点主机与同源地址。
fn configured_download_hosts(app: &AppHandle) -> Vec<String> {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|value| value.get("allowedDownloadHosts"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|value| value.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

fn parse_hex_version(value: &str) -> Result<u32, UpdaterError> {
    let text = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u32::from_str_radix(text, 16).map_err(|_| invalid("ABI 版本不是合法十六进制"))
}

fn normalize_three(value: &str) -> Result<String, UpdaterError> {
    let version = semver::Version::parse(value).map_err(|_| invalid("版本不是合法 SemVer"))?;
    Ok(format!(
        "{}.{}.{}",
        version.major, version.minor, version.patch
    ))
}

fn rollout_bucket(install_id: &str, salt: &str) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(install_id.as_bytes());
    hasher.update(b":");
    hasher.update(salt.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    (u64::from_le_bytes(bytes) % 10_000) as u32
}

fn invalid(message: &str) -> UpdaterError {
    UpdaterError::new("E_UPDATER_MANIFEST_INVALID", message, false)
}

fn compat(message: &str) -> UpdaterError {
    UpdaterError::new("E_UPDATER_COMPAT_BLOCKED", message, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_version_keeps_three_components() {
        assert_eq!(normalize_three("4.1.3").unwrap(), "4.1.3");
    }

    #[test]
    fn parse_abi_accepts_hex_and_plain() {
        assert_eq!(parse_hex_version("0x000B").unwrap(), 0x000B);
        assert_eq!(parse_hex_version("000B").unwrap(), 0x000B);
    }

    #[test]
    fn rollout_bucket_is_stable_and_bounded() {
        let first = rollout_bucket("install-1", "salt");
        let second = rollout_bucket("install-1", "salt");
        assert_eq!(first, second);
        assert!(first < 10_000);
        assert_ne!(first, rollout_bucket("install-2", "salt"));
    }

    #[test]
    fn download_url_policy_binds_plugin_url_and_channel() {
        let local_url = reqwest::Url::parse("http://127.0.0.1:8765/installer.exe").unwrap();
        let (url, hosts) =
            validate_download_url_value(local_url.as_str(), "local", &local_url, None, &[])
                .unwrap();
        assert_eq!(url, local_url.as_str());
        assert_eq!(hosts, vec!["127.0.0.1".to_string()]);

        let lan_url = reqwest::Url::parse("http://192.168.1.10/installer.exe").unwrap();
        assert!(
            validate_download_url_value(lan_url.as_str(), "local", &lan_url, None, &[]).is_err()
        );

        let other_local = reqwest::Url::parse("http://127.0.0.1:8765/other.exe").unwrap();
        assert!(
            validate_download_url_value(other_local.as_str(), "local", &local_url, None, &[])
                .is_err()
        );

        let stable_http = reqwest::Url::parse("http://updates.example.com/installer.exe").unwrap();
        assert!(validate_download_url_value(
            stable_http.as_str(),
            "stable",
            &stable_http,
            Some("updates.example.com"),
            &[]
        )
        .is_err());

        let stable_https =
            reqwest::Url::parse("https://updates.example.com/installer.exe").unwrap();
        assert!(validate_download_url_value(
            stable_https.as_str(),
            "stable",
            &stable_https,
            Some("updates.example.com"),
            &[]
        )
        .is_ok());

        let cdn = reqwest::Url::parse("https://cdn.example.com/installer.exe").unwrap();
        assert!(validate_download_url_value(
            cdn.as_str(),
            "stable",
            &cdn,
            Some("updates.example.com"),
            &[]
        )
        .is_err());
        assert!(validate_download_url_value(
            cdn.as_str(),
            "stable",
            &cdn,
            Some("updates.example.com"),
            &["cdn.example.com".to_string()]
        )
        .is_ok());
    }

    #[test]
    fn compatibility_gate_rejects_ranges_excluding_current_core() {
        let accepted = json!({
            "compatibility": {
                "abi": {
                    "min": format!("0x{CORE_API_VERSION:04X}"),
                    "max": format!("0x{CORE_API_VERSION:04X}")
                },
                "container": {
                    "min": CORE_CONTAINER_VERSION,
                    "max": CORE_CONTAINER_VERSION
                }
            }
        });
        assert!(validate_compatibility(&accepted).is_ok());

        if let Some(previous) = CORE_API_VERSION.checked_sub(1) {
            let abi_above = json!({
                "compatibility": { "abi": { "max": format!("0x{previous:04X}") } }
            });
            assert_eq!(
                validate_compatibility(&abi_above).unwrap_err().code,
                "E_UPDATER_COMPAT_BLOCKED"
            );
        }

        if let Some(next) = CORE_API_VERSION.checked_add(1) {
            let abi_below = json!({
                "compatibility": { "abi": { "min": format!("0x{next:04X}") } }
            });
            assert_eq!(
                validate_compatibility(&abi_below).unwrap_err().code,
                "E_UPDATER_COMPAT_BLOCKED"
            );
        }

        if CORE_CONTAINER_VERSION > 0 {
            let container_above = json!({
                "compatibility": { "container": { "max": CORE_CONTAINER_VERSION - 1 } }
            });
            assert_eq!(
                validate_compatibility(&container_above).unwrap_err().code,
                "E_UPDATER_COMPAT_BLOCKED"
            );
        }
    }
}
