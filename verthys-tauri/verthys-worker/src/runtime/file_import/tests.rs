use std::collections::HashSet;
use std::fs::File;
use std::time::Instant;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::runtime::content_crypto::{PBKDF2_ITER, SALT_LEN};
use crate::runtime::media::staged;
use crate::runtime::path_grants;
use crate::runtime::protocol::FileImportSource;

use super::handlers::{finish_locked, next_locked};
use super::job::{
    FileCursor, Job, CHUNK_BYTES, FINGERPRINT_PLAIN, HASH_FORMAT_VER, MAX_FILE_BYTES,
    MAX_RECORD_NAME_BYTES,
};
use super::pipeline::{
    build_meta, chunk_count, chunk_key, entry_key, file_hash_suffix, meta_record_name,
};

#[test]
fn entry_key_matches_documented_formula_and_is_path_bound() {
    let a = entry_key("C:\\data\\a.bin", 10, 1000);
    assert_eq!(a.len(), 64);
    assert!(a.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    let mut expected = Sha256::new();
    expected.update(b"file|C:\\data\\a.bin|10|1000");
    assert_eq!(a, format!("{:x}", expected.finalize()));

    assert_eq!(a, entry_key("C:\\data\\a.bin", 10, 1000));
    assert_ne!(a, entry_key("C:\\data\\b.bin", 10, 1000));
    assert_ne!(a, entry_key("C:\\data\\a.bin", 11, 1000));
    assert_ne!(a, entry_key("C:\\data\\a.bin", 10, 1001));
}

/// 同内容不同路径：条目键只由来源元数据派生，不做内容级去重。
/// 两个路径即使大小与修改时间相同，也必须得到不同条目键、各自导入。
#[test]
fn same_content_different_paths_are_distinct_entries() {
    let a = entry_key("C:\\data\\a.bin", 1024, 1000);
    let b = entry_key("C:\\data\\b.bin", 1024, 1000);
    assert_ne!(a, b);
}

/// 同一会话内同路径重试：路径/长度/修改时间不变时条目键稳定命中，
/// 由会话 committed 集合幂等跳过，不产生重复条目。
#[test]
fn same_entry_key_retry_is_idempotent_within_session() {
    let first = entry_key("C:\\data\\a.bin", 1024, 1000);
    let retry = entry_key("C:\\data\\a.bin", 1024, 1000);
    assert_eq!(first, retry);
    let committed: HashSet<String> = [first].into_iter().collect();
    assert!(committed.contains(&retry));
}

#[test]
fn chunk_key_is_stable_and_sequence_bound() {
    let entry = entry_key("C:\\data\\a.bin", 10, 1000);
    let first = chunk_key(&entry, 0);
    assert_eq!(first, chunk_key(&entry, 0));
    assert_ne!(first, chunk_key(&entry, 1));
    assert_eq!(first.len(), 64);
}

/// 明文 job 的端到端（worker 内）：真实临时文件 → 逐块读取/哈希/暂存 →
/// 收尾 → meta 字段与文件哈希口径。加密路径的 FFI 封装由 C 层测试覆盖，
/// 本用例不依赖 DLL。
#[test]
fn plaintext_job_reads_chunks_and_builds_compatible_meta() {
    let job_id = format!("file-import-test-{}", std::process::id());
    let path = std::env::temp_dir().join(format!(
        "verthys-file-import-{}.bin",
        std::process::id()
    ));
    let data: Vec<u8> = (0..(CHUNK_BYTES + 1024))
        .map(|i| (i % 251) as u8)
        .collect();
    std::fs::write(&path, &data).expect("写测试文件失败");
    let path_text = path.to_string_lossy().to_string();
    path_grants::authorize_job_target(
        "file_import",
        &job_id,
        std::slice::from_ref(&path_text),
    )
    .expect("授权测试路径失败");

    let mut job = Job {
        job_id: job_id.clone(),
        files: vec![FileImportSource {
            path: path_text.clone(),
            name: "plain.bin".to_string(),
            mime: "application/octet-stream".to_string(),
        }],
        committed: HashSet::new(),
        next_index: 0,
        current: None,
        password: Zeroizing::new(String::new()),
        cancelled: false,
        last_touch: Instant::now(),
    };

    let first = next_locked(None, &mut job)
        .file
        .expect("首个块事件");
    assert_eq!(first.status, "chunk");
    assert_eq!(first.chunk_index, Some(0));
    assert_eq!(first.chunk_total, Some(2));
    assert!(!first.file_done);
    let hash0 = blake3::hash(&data[..CHUNK_BYTES]).to_hex().to_string();
    assert_eq!(first.chunk_hash.as_deref(), Some(hash0.as_str()));

    let second = next_locked(None, &mut job)
        .file
        .expect("第二个块事件");
    assert_eq!(second.chunk_index, Some(1));
    assert!(second.file_done);
    let hash1 = blake3::hash(&data[CHUNK_BYTES..]).to_hex().to_string();
    assert_eq!(second.chunk_hash.as_deref(), Some(hash1.as_str()));

    let finish_resp = finish_locked(&mut job, &[101, 102]);
    assert!(finish_resp.ok, "收尾失败: {:?}", finish_resp.error);
    let finish = finish_resp.file_finish.expect("收尾结果");
    let mut expected = blake3::Hasher::new();
    expected.update(&data);
    expected.update(&file_hash_suffix(false));
    assert_eq!(
        finish.file_hash,
        expected.finalize().to_hex().to_string(),
        "文件哈希必须等于 BLAKE3(明文 ‖ 形态尾缀)"
    );
    assert!(!finish.encrypted);
    assert_eq!(finish.total_chunks, 2);
    assert_eq!(finish.chunk_hashes, vec![hash0, hash1]);

    let meta_bytes =
        crate::runtime::protocol::base64_decode(&finish.meta_b64).expect("meta 必须是 base64");
    let meta: serde_json::Value =
        serde_json::from_slice(&meta_bytes).expect("meta 必须是 JSON");
    assert_eq!(meta["schema"], serde_json::json!(2));
    assert_eq!(meta["chunkIds"], serde_json::json!([101, 102]));
    assert_eq!(meta["totalChunks"], serde_json::json!(2));
    assert_eq!(meta["chunkSize"], serde_json::json!(CHUNK_BYTES));
    assert_eq!(meta["encrypted"], serde_json::json!(false));
    assert_eq!(meta["fileHash"], serde_json::json!(finish.file_hash));
    assert_eq!(meta["entryKey"], serde_json::json!(finish.entry_key));
    assert!(meta.get("kdf").is_none());

    staged::clear(&job_id);
    path_grants::revoke_job(&job_id);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn chunk_count_covers_product_limits() {
    assert_eq!(chunk_count(0), 0);
    assert_eq!(chunk_count(1), 1);
    assert_eq!(chunk_count(CHUNK_BYTES as u64), 1);
    assert_eq!(chunk_count(CHUNK_BYTES as u64 + 1), 2);
    assert_eq!(chunk_count(MAX_FILE_BYTES), 512);
    assert_eq!(chunk_count(MAX_FILE_BYTES + 1), 513);
}

#[test]
fn file_hash_folds_format_and_encryption_domain() {
    let mut plain = blake3::Hasher::new();
    plain.update(b"payload");
    plain.update(&file_hash_suffix(false));
    let mut expected_plain = blake3::Hasher::new();
    expected_plain.update(b"payload");
    expected_plain.update(&[HASH_FORMAT_VER, FINGERPRINT_PLAIN]);
    assert_eq!(
        plain.finalize().to_hex().to_string(),
        expected_plain.finalize().to_hex().to_string()
    );

    let mut encrypted = blake3::Hasher::new();
    encrypted.update(b"payload");
    encrypted.update(&file_hash_suffix(true));
    assert_ne!(
        encrypted.finalize().to_hex().to_string(),
        expected_plain.finalize().to_hex().to_string()
    );
}

fn cursor(encrypted: bool) -> FileCursor {
    FileCursor {
        file: File::open(std::env::current_exe().expect("测试进程可执行文件必须可打开"))
            .expect("测试进程可执行文件必须可打开"),
        path: "C:\\data\\a.bin".to_string(),
        name: "a.bin".to_string(),
        mime: "application/octet-stream".to_string(),
        size: 0,
        mtime_ms: 0,
        entry_key: "e".repeat(64),
        total_chunks: 0,
        next_chunk: 0,
        bytes_read: 0,
        encrypted,
        salt: encrypted.then_some([0x11; SALT_LEN]),
        iterations: if encrypted { PBKDF2_ITER } else { 0 },
        key: None,
        password_check_b64: encrypted.then(|| "check".to_string()),
        file_hasher: blake3::Hasher::new(),
        chunk_hashes: Vec::new(),
    }
}

#[test]
fn meta_payload_keeps_legacy_field_names() {
    let plain = cursor(false);
    let bytes = build_meta(&plain, &[], &"0".repeat(64)).expect("明文 meta 必须可序列化");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("meta 必须是 JSON");
    for key in [
        "schema",
        "name",
        "size",
        "mime",
        "chunkIds",
        "chunkHashes",
        "chunkSize",
        "totalChunks",
        "encrypted",
        "fileHash",
        "entryKey",
    ] {
        assert!(value.get(key).is_some(), "缺少既有字段: {}", key);
    }
    assert!(value.get("kdf").is_none(), "明文条目不得携带 KDF 参数");
    assert!(value.get("passwordCheck").is_none());

    let encrypted = cursor(true);
    let bytes = build_meta(&encrypted, &[7], &"0".repeat(64)).expect("加密 meta 必须可序列化");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("meta 必须是 JSON");
    assert_eq!(value["encrypted"], serde_json::json!(true));
    assert_eq!(value["kdf"]["version"], serde_json::json!(2));
    assert_eq!(value["kdf"]["iterations"], serde_json::json!(PBKDF2_ITER));
    assert!(value["kdf"]["saltB64"].is_string());
    assert!(value["passwordCheck"].is_string());
    assert_eq!(value["chunkIds"], serde_json::json!([7]));
}

#[test]
fn record_name_rejects_overlong_display_names() {
    assert!(meta_record_name("a.bin").is_ok());
    let limit = MAX_RECORD_NAME_BYTES.saturating_sub("meta_".len());
    assert!(meta_record_name(&"x".repeat(limit)).is_ok());
    assert!(meta_record_name(&"x".repeat(limit + 1)).is_err());
}
