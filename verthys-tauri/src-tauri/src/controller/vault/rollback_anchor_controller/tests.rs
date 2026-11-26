/*
 * rollback_anchor_controller 单元测试
 *
 * 覆盖容器头识别、目标合并、深度扫描跳过规则与自定义位置校验。
 */
use super::*;
use crate::repository::anchor_scan_store::{ScanStore, StoredScanEntry, StoredScanRoot};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::Instant;

fn sample_header(uuid: [u8; 16]) -> [u8; CONTAINER_HEADER_BYTES] {
    let mut header = [0u8; CONTAINER_HEADER_BYTES];
    header[0..4].copy_from_slice(&CONTAINER_MAGIC);
    header[4..6].copy_from_slice(&CONTAINER_VERSION_MAJOR.to_le_bytes());
    header[8..10].copy_from_slice(&(CONTAINER_HEADER_BYTES as u16).to_le_bytes());
    header[12..28].copy_from_slice(&uuid);
    header
}

fn write_container(path: &Path, uuid: [u8; 16]) {
    let mut file = File::create(path).expect("create container");
    file.write_all(&sample_header(uuid)).expect("write header");
}

fn budget() -> ScanBudget {
    ScanBudget {
        global_deadline: Instant::now() + Duration::from_secs(5),
        max_files: 10_000,
        files_seen: 0,
    }
}

#[test]
fn uuid_hex_validation() {
    assert!(is_uuid_hex("0123456789abcdef0123456789abcdef"));
    assert!(is_uuid_hex("0123456789ABCDEF0123456789ABCDEF"));
    assert!(!is_uuid_hex(""));
    assert!(!is_uuid_hex("0011"));
    assert!(!is_uuid_hex("zz23456789abcdef0123456789abcdef"));
}

#[test]
fn header_uuid_accepts_valid_and_rejects_bad() {
    let uuid = [0xABu8; 16];
    let header = sample_header(uuid);
    assert_eq!(header_uuid(&header), Some(uuid));

    let mut bad_magic = header;
    bad_magic[0] = b'X';
    assert_eq!(header_uuid(&bad_magic), None);

    let mut bad_version = header;
    bad_version[4] = 3;
    assert_eq!(header_uuid(&bad_version), None);

    let mut bad_len = header;
    bad_len[8..10].copy_from_slice(&10u16.to_le_bytes());
    assert_eq!(header_uuid(&bad_len), None);
}

#[test]
fn scan_dir_finds_container_and_ignores_junk() {
    let dir = tempfile::tempdir().expect("temp dir");
    let uuid = [0x5Au8; 16];
    write_container(&dir.path().join("sample.verthys"), uuid);
    fs::write(dir.path().join("junk.txt"), b"not a container").expect("write junk");

    let target = ScanTarget {
        path: dir.path().to_string_lossy().to_string(),
        kind: TargetKind::Dir,
        source: RootSource::Custom,
    };
    let mut budget = budget();
    let outcome = scan_target(
        &target,
        &mut budget,
        Instant::now() + Duration::from_secs(5),
        SCAN_MAX_DEPTH,
    );
    assert!(outcome.available);
    assert!(!outcome.counters.truncated);
    assert_eq!(outcome.counters.files_seen, 2);
    assert_eq!(outcome.counters.matched, 1);
    assert_eq!(outcome.entries.len(), 1);
    assert_eq!(outcome.entries[0].uuid, uuid_hex(&uuid));
    assert_eq!(outcome.entries[0].paths.len(), 1);
}

#[test]
fn scan_dir_dedupes_same_path_case_insensitively() {
    let dir = tempfile::tempdir().expect("temp dir");
    let uuid = [0x11u8; 16];
    let container = dir.path().join("Sample.verthys");
    write_container(&container, uuid);
    let mut collected = CollectedEntries::default();
    collected.insert(uuid, &container);
    collected.insert(uuid, Path::new(&container.to_string_lossy().to_uppercase()));
    let entries = collected.into_entries();
    assert_eq!(entries[0].paths.len(), 1);
}

#[test]
fn history_targets_add_file_and_parent_and_prefer_container_source() {
    let mut store = ScanStore::default();
    store.roots.push(StoredScanRoot::new(
        r"D:\Vaults\Vault.verthys",
        "file",
        "recent",
    ));
    let history = vec![
        (
            r"D:\Vaults\Vault.verthys".to_string(),
            RootSource::Container,
        ),
        (r"D:\Vaults\Vault.verthys".to_string(), RootSource::Recent),
    ];
    let targets = targets_from_history(&history, &store);
    assert!(targets.iter().any(|target| {
        target.kind == TargetKind::File
            && target.source == RootSource::Container
            && target.path.ends_with("Vault.verthys")
    }));
    assert!(targets
        .iter()
        .any(|target| { target.kind == TargetKind::Dir && target.path == r"D:\Vaults" }));
    assert_eq!(
        targets
            .iter()
            .filter(|target| target.kind == TargetKind::File)
            .count(),
        1
    );
}

#[test]
fn stored_file_root_adds_parent_without_history() {
    let mut store = ScanStore::default();
    store.roots.push(StoredScanRoot::new(
        r"D:\Vaults\Vault.verthys",
        "file",
        "recent",
    ));
    let targets = targets_from_history(&[], &store);
    assert!(targets.iter().any(
        |target| target.kind == TargetKind::File && target.path.ends_with("Vault.verthys")
    ));
    assert!(targets
        .iter()
        .any(|target| target.kind == TargetKind::Dir && target.path == r"D:\Vaults"));
}

#[test]
fn native_path_normalizes_forward_slashes_on_windows() {
    if cfg!(windows) {
        assert_eq!(
            native_path("D:/Vaults/Vault.verthys"),
            r"D:\Vaults\Vault.verthys"
        );
    }
}

#[test]
fn truncated_outcome_unions_existing_evidence() {
    let mut store = ScanStore::default();
    store
        .roots
        .push(StoredScanRoot::new(r"D:\Vaults", "dir", "custom"));
    store.roots[0].entries.push(StoredScanEntry {
        uuid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        paths: vec![r"D:\Vaults\old.verthys".into()],
    });
    let target = ScanTarget {
        path: r"D:\Vaults".into(),
        kind: TargetKind::Dir,
        source: RootSource::Custom,
    };
    let outcome = RootOutcome {
        available: true,
        counters: Counters {
            files_seen: 3,
            matched: 1,
            permission_errors: 1,
            other_errors: 0,
            truncated: true,
        },
        entries: vec![StoredScanEntry {
            uuid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            paths: vec![r"D:\Vaults\new.verthys".into()],
        }],
    };
    apply_root_outcome(&mut store, &target, outcome, 100);
    let paths = &store.roots[0].entries[0].paths;
    assert_eq!(paths.len(), 2);
    assert!(paths.iter().any(|path| path.ends_with("old.verthys")));
    assert!(paths.iter().any(|path| path.ends_with("new.verthys")));
    assert_eq!(store.roots[0].last_success_at, 0);
}

#[test]
fn deep_user_target_is_registered_and_preferred() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut store = ScanStore::default();
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    push_deep_user_target(
        &mut store,
        &mut targets,
        &mut seen,
        dir.path().to_path_buf(),
    );
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].source, RootSource::DeepUser);
    assert_eq!(store.roots[0].source, "deep_user");

    let mut sortable = vec![
        ScanTarget {
            path: r"C:\Users".into(),
            kind: TargetKind::Dir,
            source: RootSource::Deep,
        },
        ScanTarget {
            path: r"C:\Users\X\Desktop".into(),
            kind: TargetKind::Dir,
            source: RootSource::DeepUser,
        },
    ];
    sort_targets(&mut sortable, &store);
    assert_eq!(sortable[0].source, RootSource::DeepUser);
    assert_eq!(sortable[1].source, RootSource::Deep);
}

#[test]
fn completed_outcome_replaces_stale_evidence() {
    let mut store = ScanStore::default();
    store
        .roots
        .push(StoredScanRoot::new(r"D:\Vaults", "dir", "custom"));
    store.roots[0].entries.push(StoredScanEntry {
        uuid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        paths: vec![r"D:\Vaults\deleted.verthys".into()],
    });
    let target = ScanTarget {
        path: r"D:\Vaults".into(),
        kind: TargetKind::Dir,
        source: RootSource::Custom,
    };
    let outcome = RootOutcome {
        available: true,
        counters: Counters::default(),
        entries: Vec::new(),
    };
    apply_root_outcome(&mut store, &target, outcome, 200);
    assert!(store.roots[0].entries.is_empty());
    assert_eq!(store.roots[0].last_success_at, 200);
}

#[test]
fn build_result_merges_evidence_from_multiple_roots() {
    let uuid = "cccccccccccccccccccccccccccccccc";
    let mut store = ScanStore::default();
    store
        .roots
        .push(StoredScanRoot::new("D:\\A", "dir", "recent"));
    store.roots[0].entries.push(StoredScanEntry {
        uuid: uuid.into(),
        paths: vec![r"D:\A\Vault.verthys".into()],
    });
    store
        .roots
        .push(StoredScanRoot::new("E:\\B", "dir", "recent"));
    store.roots[1].entries.push(StoredScanEntry {
        uuid: uuid.into(),
        paths: vec![r"E:\B\Vault.verthys".into()],
    });
    let result = build_scan_result(&store, &PassOutcome::default(), false);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].paths.len(), 2);
}

#[test]
fn collected_entries_marks_overflow_after_path_cap() {
    let mut collected = CollectedEntries::default();
    let uuid = [0x77u8; 16];
    for index in 0..(SCAN_MAX_PATHS_PER_UUID + 1) {
        let path = format!("D:\\Vaults\\{}.verthys", index);
        collected.insert(uuid, Path::new(&path));
    }
    assert!(collected.overflow);
    let entries = collected.into_entries();
    assert_eq!(entries[0].paths.len(), SCAN_MAX_PATHS_PER_UUID);
}

#[test]
fn custom_root_validation_rejects_relative_path() {
    assert!(normalize_custom_roots(vec!["relative\\vault".into()]).is_err());
}
