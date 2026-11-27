use super::check::{ensure_release_unchanged, validate_downloaded, verification_event};
use super::types::{elevation_denied, plugin_error, UpdaterError};
use crate::updater::manifest::ValidatedManifest;

fn manifest_fixture(version: &str, sha256: &str) -> ValidatedManifest {
    ValidatedManifest {
        release_id: format!("20261023-120000-{version}-b5e487ad"),
        channel: "local".into(),
        version: version.into(),
        force_update: false,
        size: 1024,
        sha256: sha256.into(),
        file_version: version.into(),
        download_url: "http://127.0.0.1:8765/installer.exe".into(),
        allowed_download_hosts: vec!["127.0.0.1".into()],
    }
}

#[test]
fn release_recheck_accepts_identical_release() {
    let current = manifest_fixture("4.1.6", &"a".repeat(64));
    let refreshed = manifest_fixture("4.1.6", &"a".repeat(64));
    assert!(ensure_release_unchanged(&current, &refreshed).is_ok());
}

#[test]
fn release_recheck_rejects_changed_release_or_bytes() {
    let current = manifest_fixture("4.1.6", &"a".repeat(64));
    let changed_version = manifest_fixture("4.1.7", &"a".repeat(64));
    let changed_bytes = manifest_fixture("4.1.6", &"b".repeat(64));
    assert_eq!(
        ensure_release_unchanged(&current, &changed_version)
            .unwrap_err()
            .code,
        "E_UPDATER_INSTALL_REVOKED"
    );
    assert_eq!(
        ensure_release_unchanged(&current, &changed_bytes)
            .unwrap_err()
            .code,
        "E_UPDATER_INSTALL_REVOKED"
    );
}
use sha2::{Digest, Sha256};
use std::path::Path;

fn plugin_minisign(error: minisign_verify::Error) -> tauri_plugin_updater::Error {
    tauri_plugin_updater::Error::Minisign(error)
}

#[test]
fn elevation_cancel_is_distinguished_from_other_launch_errors() {
    let cancelled = tauri_plugin_updater::Error::Io(std::io::Error::from_raw_os_error(
        windows::Win32::Foundation::ERROR_CANCELLED.0 as i32,
    ));
    assert!(elevation_denied(&cancelled));
    let other = tauri_plugin_updater::Error::Io(std::io::Error::from_raw_os_error(5));
    assert!(!elevation_denied(&other));
}

#[test]
fn key_id_mismatch_is_distinguished() {
    let mapped = plugin_error(plugin_minisign(minisign_verify::Error::UnexpectedKeyId));
    assert_eq!(mapped.code, "E_UPDATER_SIG_PUBKEY_MISMATCH");
}

#[test]
fn invalid_signature_maps_to_signature_error() {
    let mapped = plugin_error(plugin_minisign(minisign_verify::Error::InvalidSignature));
    assert_eq!(mapped.code, "E_UPDATER_SIG_INVALID");
}

#[test]
fn error_display_contains_code() {
    let error: UpdaterError = UpdaterError::new("E_UPDATER_NETWORK", "timeout", true);
    assert!(error.to_string().contains("E_UPDATER_NETWORK"));
}

#[test]
fn verification_failures_map_to_specific_events() {
    assert_eq!(
        verification_event("E_UPDATER_SIZE_MISMATCH"),
        "size_mismatch"
    );
    assert_eq!(
        verification_event("E_UPDATER_HASH_MISMATCH"),
        "hash_mismatch"
    );
    assert_eq!(
        verification_event("E_UPDATER_PE_VERSION_MISMATCH"),
        "pe_version_mismatch"
    );
    assert_eq!(verification_event("E_UPDATER_SIG_INVALID"), "sig_invalid");
    assert_eq!(
        verification_event("E_UPDATER_SIG_PUBKEY_MISMATCH"),
        "pubkey_mismatch"
    );
    assert_eq!(verification_event("E_UPDATER_NETWORK"), "download_failed");
}

#[test]
fn webview_capabilities_expose_no_updater_commands() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities/default.json");
    let payload = std::fs::read(&path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    let permissions = value["permissions"]
        .as_array()
        .expect("capability permissions must be an array");
    assert!(
        permissions
            .iter()
            .filter_map(serde_json::Value::as_str)
            .all(|permission| !permission.starts_with("updater:")),
        "webview must not be able to invoke updater plugin commands"
    );
}

#[test]
fn validates_downloaded_bytes_and_rejects_mismatch() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest_path = root.join("build/updater/latest.json");
    if !manifest_path.exists() {
        return;
    }
    let latest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let platform = &latest["platforms"]["windows-x86_64"];
    let url = platform["url"].as_str().unwrap();
    let file_name = url.rsplit('/').next().unwrap();
    let installer = manifest_path.parent().unwrap().join(file_name);
    let signature = installer.with_file_name(format!("{file_name}.sig"));
    if !installer.exists() || !signature.exists() {
        return;
    }
    let version = latest["version"].as_str().unwrap().to_string();
    let file_version = platform["file_version"].as_str().unwrap().to_string();
    let config: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("verthys-tauri/src-tauri/tauri.conf.json")).unwrap(),
    )
    .unwrap();
    let pubkey = config["plugins"]["updater"]["pubkey"].as_str().unwrap();
    let bytes = std::fs::read(&installer).unwrap();
    let signature_text = std::fs::read_to_string(&signature).unwrap();
    let signature_text = signature_text.trim();
    let expected_size = bytes.len() as u64;
    let expected_hash = format!("{:x}", Sha256::digest(&bytes));
    let manifest = super::manifest::ValidatedManifest {
        release_id: "test-release".to_string(),
        channel: "local".to_string(),
        version,
        force_update: false,
        size: expected_size,
        sha256: expected_hash,
        file_version: file_version.clone(),
        download_url: "http://127.0.0.1:8765/installer.exe".to_string(),
        allowed_download_hosts: vec!["127.0.0.1".to_string()],
    };

    let prepared = validate_downloaded(bytes.clone(), &manifest, |data| {
        super::verify::verify_bytes_with_pubkey(pubkey, data, signature_text)
    })
    .unwrap();
    assert_eq!(prepared.file_version, file_version);

    let mut wrong_version = manifest.clone();
    wrong_version.file_version = "9.9.9".to_string();
    let error = validate_downloaded(bytes.clone(), &wrong_version, |_| Ok(())).unwrap_err();
    assert_eq!(error.code, "E_UPDATER_PE_VERSION_MISMATCH");

    let mut wrong_hash = manifest;
    wrong_hash.sha256 = "0".repeat(64);
    let error = validate_downloaded(bytes, &wrong_hash, |_| Ok(())).unwrap_err();
    assert_eq!(error.code, "E_UPDATER_HASH_MISMATCH");
}
