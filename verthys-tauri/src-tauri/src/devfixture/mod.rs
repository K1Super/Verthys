/*
 * 开发填充配置：DPAPI 配置存储、路径校验与指纹。
 *
 * 该模块只服务开发期填充工具；发布构建由命令层拒绝，且不参与生产流程。
 */

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::util::crypto::{dpapi_protect, dpapi_unprotect};

/// 填充配置目录名；位于应用配置目录下，内容整体经 DPAPI 加密。
pub const STORE_DIR: &str = "devfixture";
/// 填充配置文件名。
pub const PROFILE_FILE: &str = "profile.bin";
/// 当前填充配置 schema 版本。
pub const PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevFixtureStatus {
    pub enabled: bool,
    pub reason: String,
    pub store_dir: String,
    pub profile_exists: bool,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DevFixtureProfile {
    pub schema_version: u32,
    pub container_path: String,
    pub container_keyfile_path: String,
    pub global_password: String,
    pub bin_password: String,
    pub bin_keyfile_path: String,
    pub module_keys: BTreeMap<String, String>,
    pub recovery_code: String,
    pub updated_at: String,
}

impl DevFixtureProfile {
    fn sanitize(&mut self) {
        self.schema_version = PROFILE_SCHEMA_VERSION;
        self.container_path = self.container_path.trim().to_string();
        self.container_keyfile_path = self.container_keyfile_path.trim().to_string();
        self.global_password = self.global_password.trim().to_string();
        self.bin_password = self.bin_password.trim().to_string();
        self.bin_keyfile_path = self.bin_keyfile_path.trim().to_string();
        self.recovery_code = self.recovery_code.trim().to_string();
        for value in self.module_keys.values_mut() {
            *value = value.trim().to_string();
        }
        self.updated_at = unix_seconds_string();
    }

    fn clear_secrets(&mut self) {
        self.global_password.zeroize();
        self.bin_password.zeroize();
        self.recovery_code.zeroize();
        for value in self.module_keys.values_mut() {
            value.zeroize();
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevFixtureFingerprints {
    pub global: String,
    pub bin: String,
    pub recovery: String,
    pub modules: BTreeMap<String, String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevFixtureProfileView {
    pub profile: Option<DevFixtureProfile>,
    pub fingerprints: DevFixtureFingerprints,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevFixtureSaveOutcome {
    pub fingerprints: DevFixtureFingerprints,
    pub updated_at: String,
}

pub fn status(config_dir: &Path) -> DevFixtureStatus {
    let store_dir = store_dir(config_dir);
    DevFixtureStatus {
        enabled: true,
        reason: "填充通道已启用".to_string(),
        profile_exists: store_dir.join(PROFILE_FILE).is_file(),
        store_dir: display_path(&store_dir),
    }
}

pub fn load_profile(config_dir: &Path) -> Result<DevFixtureProfileView, String> {
    let profile_path = store_dir(config_dir).join(PROFILE_FILE);
    let profile = if profile_path.is_file() {
        let ciphertext =
            std::fs::read(&profile_path).map_err(|e| format!("读取填充配置失败: {e}"))?;
        let plaintext =
            dpapi_unprotect(&ciphertext).map_err(|e| format!("解密填充配置失败: {e}"))?;
        let plaintext = zeroize::Zeroizing::new(plaintext);
        let profile: DevFixtureProfile =
            serde_json::from_slice(&plaintext).map_err(|e| format!("解析填充配置失败: {e}"))?;
        Some(profile)
    } else {
        None
    };
    let fingerprints = profile
        .as_ref()
        .map(fingerprints_of)
        .unwrap_or_else(DevFixtureFingerprints::empty);
    Ok(DevFixtureProfileView {
        profile,
        fingerprints,
    })
}

pub fn save_profile(
    config_dir: &Path,
    mut profile: DevFixtureProfile,
) -> Result<DevFixtureSaveOutcome, String> {
    let store_dir = ensure_store_dir(config_dir)?;
    profile.sanitize();
    validate_profile_paths(&profile)?;
    let serialized = zeroize::Zeroizing::new(
        serde_json::to_vec(&profile).map_err(|e| format!("序列化填充配置失败: {e}"))?,
    );
    let ciphertext = dpapi_protect(&serialized, Some("Verthys dev fixture profile"))
        .map_err(|e| format!("加密填充配置失败: {e}"))?;
    let profile_path = store_dir.join(PROFILE_FILE);
    let temp_path = store_dir.join(format!("{PROFILE_FILE}.tmp"));
    std::fs::write(&temp_path, &ciphertext).map_err(|e| format!("写入填充配置失败: {e}"))?;
    std::fs::rename(&temp_path, &profile_path).map_err(|e| format!("替换填充配置失败: {e}"))?;
    let fingerprints = fingerprints_of(&profile);
    let updated_at = profile.updated_at.clone();
    /* 保存链路在密文落盘后立即清零明文；读取链路需把明文交给前端填充，
    无法在序列化前清零，属于 dev-only 工具的已知内存驻留窗口。 */
    profile.clear_secrets();
    Ok(DevFixtureSaveOutcome {
        fingerprints,
        updated_at,
    })
}

pub fn clear_profile(config_dir: &Path) -> Result<bool, String> {
    let profile_path = store_dir(config_dir).join(PROFILE_FILE);
    if !profile_path.is_file() {
        return Ok(false);
    }
    std::fs::remove_file(&profile_path).map_err(|e| format!("删除填充配置失败: {e}"))?;
    Ok(true)
}

fn store_dir(config_dir: &Path) -> PathBuf {
    config_dir.join(STORE_DIR)
}

fn ensure_store_dir(config_dir: &Path) -> Result<PathBuf, String> {
    let dir = store_dir(config_dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建填充配置目录失败: {e}"))?;
    Ok(dir)
}

impl DevFixtureFingerprints {
    fn empty() -> Self {
        Self {
            global: "—".to_string(),
            bin: "—".to_string(),
            recovery: "—".to_string(),
            modules: BTreeMap::new(),
        }
    }
}

fn fingerprints_of(profile: &DevFixtureProfile) -> DevFixtureFingerprints {
    let modules = profile
        .module_keys
        .iter()
        .filter(|(_, value)| !value.trim().is_empty())
        .map(|(module, value)| (module.clone(), fingerprint(value)))
        .collect();
    DevFixtureFingerprints {
        global: fingerprint(&profile.global_password),
        bin: fingerprint(&profile.bin_password),
        recovery: fingerprint(&profile.recovery_code),
        modules,
    }
}

fn fingerprint(value: &str) -> String {
    if value.trim().is_empty() {
        return "—".to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let short: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    short.to_ascii_uppercase()
}

fn validate_profile_paths(profile: &DevFixtureProfile) -> Result<(), String> {
    validate_file_path(&profile.container_path, "verthys", "容器")?;
    validate_file_path(&profile.container_keyfile_path, "vkf", "容器 keyfile")?;
    validate_file_path(&profile.bin_keyfile_path, "bin", "访问密钥文件")?;
    Ok(())
}

fn validate_file_path(raw: &str, expected_ext: &str, label: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Ok(());
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(format!("{label}必须是绝对路径"));
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|e| format!("{label}不存在或不可访问: {e}"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label}不允许符号链接"));
    }
    if !metadata.is_file() {
        return Err(format!("{label}必须是文件"));
    }
    let ext = path
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if ext != expected_ext {
        return Err(format!("{label}扩展名必须为 .{expected_ext}"));
    }
    Ok(())
}

fn display_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    raw.strip_prefix(r"\\?\").unwrap_or(&raw).to_string()
}

fn unix_seconds_string() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("{prefix}-{}-{stamp}", std::process::id()))
    }

    #[test]
    fn profile_round_trip_and_free_paths() {
        let root = unique_temp_dir("verthys-devfixture-test");
        let config_dir = root.join("config");
        std::fs::create_dir_all(&config_dir).expect("create config dir");

        let container = root.join("Fixture.verthys");
        let bin = root.join("Fixture.bin");
        let vkf = root.join("Fixture.vkf");
        std::fs::write(&container, b"fixture").expect("write container");
        std::fs::write(&bin, b"fixture").expect("write bin");
        std::fs::write(&vkf, b"fixture").expect("write vkf");

        let outside_dir = unique_temp_dir("verthys-devfixture-outside");
        std::fs::create_dir_all(&outside_dir).expect("create outside dir");
        let outside_container = outside_dir.join("Real.verthys");
        std::fs::write(&outside_container, b"real").expect("write outside container");

        let initial_status = status(&config_dir);
        assert!(initial_status.enabled);
        assert!(!initial_status.profile_exists);

        let profile = DevFixtureProfile {
            schema_version: PROFILE_SCHEMA_VERSION,
            container_path: display_path(&container),
            container_keyfile_path: display_path(&vkf),
            global_password: "fixture-global".to_string(),
            bin_password: "fixture-bin".to_string(),
            bin_keyfile_path: display_path(&bin),
            module_keys: BTreeMap::from([("accounts".to_string(), "fixture-module".to_string())]),
            recovery_code: "FIXTURE-RECOVERY".to_string(),
            updated_at: String::new(),
        };

        let saved = save_profile(&config_dir, profile).expect("save profile");
        assert_ne!(saved.fingerprints.global, "—");
        assert!(status(&config_dir).profile_exists);

        let replacement = DevFixtureProfile {
            schema_version: PROFILE_SCHEMA_VERSION,
            container_path: display_path(&container),
            container_keyfile_path: String::new(),
            global_password: "fixture-global-2".to_string(),
            bin_password: "fixture-bin-2".to_string(),
            bin_keyfile_path: display_path(&bin),
            module_keys: BTreeMap::new(),
            recovery_code: String::new(),
            updated_at: String::new(),
        };
        save_profile(&config_dir, replacement).expect("replace profile");

        let loaded = load_profile(&config_dir).expect("load profile");
        let loaded = loaded.profile.expect("profile exists");
        assert_eq!(loaded.global_password, "fixture-global-2");
        assert_eq!(loaded.bin_password, "fixture-bin-2");
        assert!(loaded.module_keys.is_empty());

        /* 任意位置的容器路径都应被接受。 */
        assert!(
            validate_file_path(&display_path(&outside_container), "verthys", "容器").is_ok()
        );
        assert!(clear_profile(&config_dir).expect("clear profile"));
        assert!(load_profile(&config_dir)
            .expect("load after clear")
            .profile
            .is_none());

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside_dir);
    }

    #[test]
    fn save_rejects_missing_keyfile_with_field_label() {
        let root = unique_temp_dir("verthys-devfixture-missing");
        let config_dir = root.join("config");
        std::fs::create_dir_all(&config_dir).expect("create config dir");

        let missing_vkf = root.join("Missing.vkf");
        let profile = DevFixtureProfile {
            schema_version: PROFILE_SCHEMA_VERSION,
            container_keyfile_path: display_path(&missing_vkf),
            ..DevFixtureProfile::default()
        };
        let error = save_profile(&config_dir, profile).expect_err("missing keyfile must be rejected");
        assert!(
            error.contains("容器 keyfile不存在或不可访问"),
            "unexpected error: {error}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
