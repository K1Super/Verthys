/*
 * rollback_anchor_controller 单元测试
 *
 * 覆盖容器头识别、瞬态探针、并行目录扫描、覆盖去重、目标排序与自定义
 * 位置校验。
 */
use super::*;
use crate::repository::anchor_scan_store;
use crate::repository::anchor_scan_store::{ScanStore, StoredScanEntry, StoredScanRoot};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

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

fn scan_dir_once(path: &Path, source: RootSource, covered: HashSet<String>) -> RootOutcome {
    let target = ScanTarget {
        path: path.to_string_lossy().to_string(),
        kind: TargetKind::Dir,
        source,
    };
    let budget = ScanBudget::new(10_000, Duration::from_secs(5));
    let mut outcomes = scan_targets(&[target], &budget, &covered, |_| {});
    outcomes.remove(0)
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

    let mut zero = header;
    zero[12..28].copy_from_slice(&[0u8; 16]);
    assert_eq!(header_uuid(&zero), None);
}

#[test]
fn scan_dir_finds_container_and_ignores_junk() {
    let dir = tempfile::tempdir().expect("temp dir");
    let uuid = [0x5Au8; 16];
    write_container(&dir.path().join("sample.verthys"), uuid);
    fs::write(dir.path().join("junk.txt"), b"not a container").expect("write junk");

    let outcome = scan_dir_once(dir.path(), RootSource::Custom, HashSet::new());
    assert!(outcome.available);
    assert!(!outcome.counters.truncated);
    assert_eq!(outcome.counters.files_seen, 2);
    assert_eq!(outcome.counters.matched, 1);
    assert_eq!(outcome.entries.len(), 1);
    assert_eq!(outcome.entries[0].uuid, uuid_hex(&uuid));
    assert_eq!(outcome.entries[0].paths.len(), 1);
}

#[test]
fn scan_ignores_zero_uuid_container() {
    let dir = tempfile::tempdir().expect("temp dir");
    write_container(&dir.path().join("zero.verthys"), [0u8; 16]);
    let outcome = scan_dir_once(dir.path(), RootSource::Custom, HashSet::new());
    assert_eq!(outcome.counters.files_seen, 1);
    assert_eq!(outcome.counters.matched, 0);
    assert!(outcome.entries.is_empty());
}

#[test]
fn covered_directory_is_not_scanned_twice() {
    let dir = tempfile::tempdir().expect("temp dir");
    let child = dir.path().join("vaults");
    fs::create_dir(&child).expect("create child");
    write_container(&child.join("sample.verthys"), [0x31u8; 16]);

    let mut covered = HashSet::new();
    covered.insert(anchor_scan_store::path_key(&child.to_string_lossy()));
    let outcome = scan_dir_once(dir.path(), RootSource::Volume, covered);
    assert_eq!(outcome.counters.matched, 0);
    assert_eq!(outcome.counters.files_seen, 0);
}

#[test]
fn volume_scan_skips_os_directories_only_at_root() {
    let dir = tempfile::tempdir().expect("temp dir");
    let system = dir.path().join("Windows");
    fs::create_dir(&system).expect("create system dir");
    write_container(&system.join("sample.verthys"), [0x41u8; 16]);
    let nested = dir.path().join("Users").join("Windows");
    fs::create_dir_all(&nested).expect("create nested");
    write_container(&nested.join("sample.verthys"), [0x42u8; 16]);

    let outcome = scan_dir_once(dir.path(), RootSource::Volume, HashSet::new());
    let entries = &outcome.entries;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].uuid, uuid_hex(&[0x42u8; 16]));
}

#[test]
fn nested_dependency_directories_are_skipped() {
    let dir = tempfile::tempdir().expect("temp dir");
    let modules = dir.path().join("node_modules").join("pkg");
    fs::create_dir_all(&modules).expect("create modules");
    write_container(&modules.join("sample.verthys"), [0x71u8; 16]);
    let outcome = scan_dir_once(dir.path(), RootSource::Volume, HashSet::new());
    assert_eq!(outcome.counters.files_seen, 0);
    assert_eq!(outcome.counters.matched, 0);
}

#[test]
fn progress_marks_each_root_done_once_after_nested_traversal() {
    let dir = tempfile::tempdir().expect("temp dir");
    let nested = dir.path().join("a").join("b");
    fs::create_dir_all(&nested).expect("create nested");
    write_container(&nested.join("sample.verthys"), [0x51u8; 16]);
    let target = ScanTarget {
        path: dir.path().to_string_lossy().to_string(),
        kind: TargetKind::Dir,
        source: RootSource::Volume,
    };
    let budget = ScanBudget::new(10_000, Duration::from_secs(5));
    let mut last_tick = None;
    let outcomes = scan_targets(&[target], &budget, &HashSet::new(), |tick| {
        last_tick = Some(tick);
    });
    assert_eq!(outcomes[0].counters.matched, 1);
    let tick = last_tick.expect("progress tick");
    assert_eq!(tick.roots_total, 1);
    assert_eq!(tick.roots_done, 1);
}

#[test]
fn volume_scan_stops_at_depth_eight_without_marking_truncated() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut level = dir.path().to_path_buf();
    for index in 1..=VOLUME_SCAN_MAX_DEPTH {
        level = level.join(format!("d{}", index));
    }
    fs::create_dir_all(&level).expect("create depth");
    write_container(&level.join("inside.verthys"), [0x81u8; 16]);
    let too_deep = level.join("d9");
    fs::create_dir_all(&too_deep).expect("create deeper");
    write_container(&too_deep.join("outside.verthys"), [0x82u8; 16]);

    let outcome = scan_dir_once(dir.path(), RootSource::Volume, HashSet::new());
    assert_eq!(outcome.counters.matched, 1);
    assert_eq!(outcome.entries[0].uuid, uuid_hex(&[0x81u8; 16]));
    assert!(!outcome.counters.truncated);
}

#[test]
fn volume_scan_skips_appdata_but_custom_scan_keeps_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let appdata = dir
        .path()
        .join("Users")
        .join("user")
        .join("AppData")
        .join("Local");
    fs::create_dir_all(&appdata).expect("create appdata");
    write_container(&appdata.join("sample.verthys"), [0x91u8; 16]);

    let volume = scan_dir_once(dir.path(), RootSource::Volume, HashSet::new());
    assert_eq!(volume.counters.matched, 0);
    assert!(!volume.counters.truncated);

    let custom = scan_dir_once(dir.path(), RootSource::Custom, HashSet::new());
    assert_eq!(custom.counters.matched, 1);
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
fn scan_file_probe_reads_exact_container() {
    let dir = tempfile::tempdir().expect("temp dir");
    let uuid = [0x61u8; 16];
    let container = dir.path().join("Vault.verthys");
    write_container(&container, uuid);
    let target = ScanTarget {
        path: container.to_string_lossy().to_string(),
        kind: TargetKind::File,
        source: RootSource::Container,
    };
    let budget = ScanBudget::new(100, Duration::from_secs(5));
    let outcomes = scan_targets(&[target], &budget, &HashSet::new(), |_| {});
    assert!(outcomes[0].available);
    assert_eq!(outcomes[0].counters.matched, 1);
    assert_eq!(outcomes[0].entries[0].uuid, uuid_hex(&uuid));
}

#[test]
fn history_targets_are_exact_file_probes_and_custom_roots_persist() {
    let mut store = ScanStore::default();
    store
        .roots
        .push(StoredScanRoot::new(r"D:\Vaults", "dir", "custom"));
    store
        .roots
        .push(StoredScanRoot::new(r"D:\Old\old.verthys", "file", "recent"));
    let history = vec![(
        r"D:\Vaults\Vault.verthys".to_string(),
        RootSource::Container,
    )];
    let targets = targets_from_history(&history, &store);
    assert!(targets.iter().any(|target| {
        target.kind == TargetKind::File
            && target.source == RootSource::Container
            && target.path.ends_with("Vault.verthys")
    }));
    assert!(targets.iter().any(|target| target.kind == TargetKind::Dir
        && target.source == RootSource::Custom
        && target.path == r"D:\Vaults"));
    assert!(!targets
        .iter()
        .any(|target| target.path.ends_with("old.verthys")));
    assert!(!targets
        .iter()
        .any(|target| target.path == r"D:\Vaults" && target.source == RootSource::Recent));
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
fn target_sort_orders_probe_custom_volume() {
    let mut targets = vec![
        ScanTarget {
            path: r"C:\".into(),
            kind: TargetKind::Dir,
            source: RootSource::Volume,
        },
        ScanTarget {
            path: r"D:\Vaults".into(),
            kind: TargetKind::Dir,
            source: RootSource::Custom,
        },
        ScanTarget {
            path: r"D:\Old\old.verthys".into(),
            kind: TargetKind::File,
            source: RootSource::Recent,
        },
        ScanTarget {
            path: r"D:\Vault.verthys".into(),
            kind: TargetKind::File,
            source: RootSource::Container,
        },
    ];
    sort_targets(&mut targets);
    assert_eq!(targets[0].source, RootSource::Container);
    assert_eq!(targets[1].source, RootSource::Recent);
    assert_eq!(targets[2].source, RootSource::Custom);
    assert_eq!(targets[3].source, RootSource::Volume);
}

#[test]
fn is_under_volume_matches_drive_root_case_insensitively() {
    let volumes: HashSet<String> = [anchor_scan_store::path_key(r"C:\")].into_iter().collect();
    assert!(is_under_volume(
        r"C:\Users\Administrator\Desktop\Vault.verthys",
        &volumes
    ));
    assert!(is_under_volume("c:/Users/Administrator/Desktop", &volumes));
    assert!(!is_under_volume(r"Z:\Vault.verthys", &volumes));
}

#[test]
fn truncated_outcome_unions_existing_evidence_and_drops_missing_paths() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root_path = dir.path().to_string_lossy().to_string();
    let old_path = dir.path().join("old.verthys");
    let new_path = dir.path().join("new.verthys");
    let gone_path = dir.path().join("gone.verthys");
    fs::write(&old_path, b"old").expect("write old");
    fs::write(&new_path, b"new").expect("write new");

    let mut store = ScanStore::default();
    store
        .roots
        .push(StoredScanRoot::new(&root_path, "dir", "custom"));
    store.roots[0].entries.push(StoredScanEntry {
        uuid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        paths: vec![
            old_path.to_string_lossy().to_string(),
            gone_path.to_string_lossy().to_string(),
        ],
        capped: false,
    });
    let target = ScanTarget {
        path: root_path,
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
            paths: vec![new_path.to_string_lossy().to_string()],
            capped: false,
        }],
    };
    apply_root_outcome(&mut store, &target, outcome, 100);
    let paths = &store.roots[0].entries[0].paths;
    assert_eq!(paths.len(), 2);
    assert!(paths.iter().any(|path| path.ends_with("old.verthys")));
    assert!(paths.iter().any(|path| path.ends_with("new.verthys")));
    assert!(!paths.iter().any(|path| path.ends_with("gone.verthys")));
    assert_eq!(store.roots[0].last_success_at, 0);
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
        capped: false,
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
        .push(StoredScanRoot::new("D:\\A", "dir", "volume"));
    store.roots[0].entries.push(StoredScanEntry {
        uuid: uuid.into(),
        paths: vec![r"D:\A\Vault.verthys".into()],
        capped: false,
    });
    store
        .roots
        .push(StoredScanRoot::new("E:\\B", "dir", "volume"));
    store.roots[1].entries.push(StoredScanEntry {
        uuid: uuid.into(),
        paths: vec![r"E:\B\Vault.verthys".into()],
        capped: false,
    });
    let result = build_scan_result(&store, &PassOutcome::default());
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].paths.len(), 2);
}

#[test]
fn build_result_marks_capped_evidence_after_merging_roots() {
    let uuid = "abcdefabcdefabcdefabcdefabcdefab";
    let each = SCAN_MAX_PATHS_PER_UUID / 2 + 4;
    let mut store = ScanStore::default();
    store
        .roots
        .push(StoredScanRoot::new("D:\\A", "dir", "volume"));
    store.roots[0].entries.push(StoredScanEntry {
        uuid: uuid.into(),
        paths: (0..each)
            .map(|index| format!(r"D:\A\{}.verthys", index))
            .collect(),
        capped: false,
    });
    store
        .roots
        .push(StoredScanRoot::new("E:\\B", "dir", "volume"));
    store.roots[1].entries.push(StoredScanEntry {
        uuid: uuid.into(),
        paths: (0..each)
            .map(|index| format!(r"E:\B\{}.verthys", index))
            .collect(),
        capped: false,
    });
    let result = build_scan_result(&store, &PassOutcome::default());
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].paths.len(), SCAN_MAX_PATHS_PER_UUID);
    assert!(result.entries[0].capped);
    assert!(!result.truncated);
}

#[test]
fn build_result_includes_transient_probe_roots() {
    let uuid = "dddddddddddddddddddddddddddddddd";
    let store = ScanStore::default();
    let mut probe = StoredScanRoot::new(r"Z:\Vault.verthys", "file", "recent");
    probe.entries.push(StoredScanEntry {
        uuid: uuid.into(),
        paths: vec![r"Z:\Vault.verthys".into()],
        capped: false,
    });
    let outcome = PassOutcome {
        ran: true,
        transient_roots: vec![probe],
        ..Default::default()
    };
    let result = build_scan_result(&store, &outcome);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.roots.len(), 1);
    assert_eq!(result.roots[0].source, "recent");
}

#[test]
fn collected_entries_marks_capped_after_path_cap() {
    let mut collected = CollectedEntries::default();
    let uuid = [0x77u8; 16];
    for index in 0..(SCAN_MAX_PATHS_PER_UUID + 1) {
        let path = format!("D:\\Vaults\\{}.verthys", index);
        collected.insert(uuid, Path::new(&path));
    }
    let entries = collected.into_entries();
    assert_eq!(entries[0].paths.len(), SCAN_MAX_PATHS_PER_UUID);
    assert!(entries[0].capped);
}

#[test]
fn scan_dir_marks_evidence_capped_without_truncating() {
    let dir = tempfile::tempdir().expect("temp dir");
    let uuid = [0x66u8; 16];
    for index in 0..=SCAN_MAX_PATHS_PER_UUID {
        write_container(&dir.path().join(format!("copy-{}.verthys", index)), uuid);
    }
    let outcome = scan_dir_once(dir.path(), RootSource::Custom, HashSet::new());
    assert!(!outcome.counters.truncated);
    assert_eq!(
        outcome.counters.matched,
        (SCAN_MAX_PATHS_PER_UUID + 1) as u64
    );
    assert_eq!(outcome.entries.len(), 1);
    assert!(outcome.entries[0].capped);
    assert_eq!(outcome.entries[0].paths.len(), SCAN_MAX_PATHS_PER_UUID);
}

#[test]
fn union_entries_marks_capped_without_returning_truncation() {
    let uuid = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();
    let each = SCAN_MAX_PATHS_PER_UUID / 2 + 4;
    let old = vec![StoredScanEntry {
        uuid: uuid.clone(),
        paths: (0..each)
            .map(|index| format!(r"D:\Old\{}.verthys", index))
            .collect(),
        capped: false,
    }];
    let new = vec![StoredScanEntry {
        uuid: uuid.clone(),
        paths: (0..each)
            .map(|index| format!(r"D:\New\{}.verthys", index))
            .collect(),
        capped: false,
    }];
    let entries = union_entries(old, new);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].paths.len(), SCAN_MAX_PATHS_PER_UUID);
    assert!(entries[0].capped);
}

#[test]
fn completed_outcome_preserves_entry_capped_flag() {
    let mut store = ScanStore::default();
    store
        .roots
        .push(StoredScanRoot::new(r"D:\Vaults", "dir", "custom"));
    let target = ScanTarget {
        path: r"D:\Vaults".into(),
        kind: TargetKind::Dir,
        source: RootSource::Custom,
    };
    let outcome = RootOutcome {
        available: true,
        counters: Counters::default(),
        entries: vec![StoredScanEntry {
            uuid: "ffffffffffffffffffffffffffffffff".into(),
            paths: vec![r"D:\Vaults\copy.verthys".into()],
            capped: true,
        }],
    };
    apply_root_outcome(&mut store, &target, outcome, 300);
    assert!(!store.roots[0].truncated);
    assert!(store.roots[0].entries[0].capped);
    assert_eq!(store.roots[0].last_success_at, 300);
}

#[test]
fn custom_root_validation_rejects_relative_path() {
    assert!(normalize_custom_roots(vec!["relative\\vault".into()]).is_err());
}
