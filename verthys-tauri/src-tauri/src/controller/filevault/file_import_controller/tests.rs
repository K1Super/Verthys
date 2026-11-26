/*
 * file_import_controller 单元测试
 *
 * 覆盖进度百分比有界性、磁盘空间需求与 KDF 条目回填校验。
 */
use super::*;

#[test]
fn progress_percent_is_bounded_and_file_monotonic() {
    assert_eq!(progress_percent(0, 0, 10, 4), 0);
    assert_eq!(progress_percent(0, 10, 10, 4), 25);
    assert_eq!(progress_percent(1, 0, 10, 4), 25);
    assert_eq!(progress_percent(3, 10, 10, 4), 99);
    assert_eq!(progress_percent(4, 10, 10, 4), 99);
    assert_eq!(progress_percent(0, 0, 0, 0), 0);
}

#[test]
fn build_entry_requires_kdf_material_for_encrypted_files() {
    let file = FileProgress {
        file_name: "a.bin".to_string(),
        mime: "application/octet-stream".to_string(),
        total_chunks: 0,
        ..Default::default()
    };
    let finish = FileFinish {
        meta_b64: String::new(),
        record_name: "meta_a.bin".to_string(),
        file_hash: "0".repeat(64),
        entry_key: "e".repeat(64),
        size: 0,
        total_chunks: 0,
        encrypted: true,
        chunk_hashes: Vec::new(),
        salt_b64: None,
        iterations: None,
        password_check: None,
    };
    assert!(build_entry(1, &file, &finish).is_err());

    let finish = FileFinish {
        salt_b64: Some("c2FsdA==".to_string()),
        iterations: Some(150_000),
        password_check: Some("check".to_string()),
        ..finish
    };
    let entry = build_entry(1, &file, &finish).expect("参数齐全时必须可回填");
    assert_eq!(entry.kdf.as_ref().map(|k| k.version), Some(2));
    assert!(entry.encrypted);
}
