/*
 * 扫描预算、计数与遍历实现
 *
 * 职责边界：有界预算（文件数/深度/时长）、权限错误单独计数、跳过符号
 * 链接与重解析点、只读容器固定头识别 UUID。
 */

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::Path;
use std::time::Instant;


use crate::repository::anchor_scan_store::{self, StoredScanEntry};

use super::*;
use std::io::Read;

pub(super) struct ScanBudget {
    pub(super) global_deadline: Instant,
    pub(super) max_files: u64,
    pub(super) files_seen: u64,
}

impl ScanBudget {
    pub(super) fn take_file(&mut self) -> bool {
        if self.files_seen >= self.max_files {
            false
        } else {
            self.files_seen += 1;
            true
        }
    }
}

#[derive(Default, Clone, Copy)]
pub(super) struct Counters {
    pub(super) files_seen: u64,
    pub(super) matched: u64,
    pub(super) permission_errors: u64,
    pub(super) other_errors: u64,
    pub(super) truncated: bool,
}

impl Counters {
    pub(super) fn merge(&mut self, other: &Counters) {
        self.files_seen = self.files_seen.saturating_add(other.files_seen);
        self.matched = self.matched.saturating_add(other.matched);
        self.permission_errors = self
            .permission_errors
            .saturating_add(other.permission_errors);
        self.other_errors = self.other_errors.saturating_add(other.other_errors);
        self.truncated |= other.truncated;
    }
}

pub(super) fn count_error(counters: &mut Counters, err: &std::io::Error) {
    if err.kind() == ErrorKind::PermissionDenied {
        counters.permission_errors = counters.permission_errors.saturating_add(1);
    } else {
        counters.other_errors = counters.other_errors.saturating_add(1);
    }
    // 任何读取错误都意味着覆盖不完整，后续不得据此判定“文件已不存在”。
    counters.truncated = true;
}

#[derive(Default)]
pub(super) struct CollectedEntries {
    pub(super) map: HashMap<String, CollectedPaths>,
    /// 单 UUID 路径数达到上限，证据未完整展示
    pub(super) overflow: bool,
}

#[derive(Default)]
pub(super) struct CollectedPaths {
    pub(super) keys: HashSet<String>,
    pub(super) paths: Vec<String>,
}

impl CollectedEntries {
    pub(super) fn insert(&mut self, uuid: [u8; 16], path: &Path) {
        let display = path.to_string_lossy().to_string();
        let path_key = anchor_scan_store::path_key(&display);
        let entry = self.map.entry(uuid_hex(&uuid)).or_default();
        if entry.keys.insert(path_key) {
            if entry.paths.len() < SCAN_MAX_PATHS_PER_UUID {
                entry.paths.push(display);
            } else {
                self.overflow = true;
            }
        }
    }

    pub(super) fn into_entries(self) -> Vec<StoredScanEntry> {
        let mut entries: Vec<StoredScanEntry> = self
            .map
            .into_iter()
            .map(|(uuid, mut paths)| {
                paths.paths.sort();
                StoredScanEntry {
                    uuid,
                    paths: paths.paths,
                }
            })
            .collect();
        entries.sort_by(|a, b| a.uuid.cmp(&b.uuid));
        entries
    }
}

pub(super) struct RootOutcome {
    pub(super) available: bool,
    pub(super) counters: Counters,
    pub(super) entries: Vec<StoredScanEntry>,
}

/* ------------------------------------------------------------------ *
 * 扫描实现                                                             *
 * ------------------------------------------------------------------ */

pub(super) fn inspect_container_file(path: &Path, counters: &mut Counters, collected: &mut CollectedEntries) {
    if !is_container_candidate(path) {
        return;
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            count_error(counters, &e);
            return;
        }
    };
    let mut header = [0u8; CONTAINER_HEADER_BYTES];
    let mut read = 0usize;
    while read < header.len() {
        match file.read(&mut header[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) => {
                count_error(counters, &e);
                return;
            }
        }
    }
    if read < header.len() {
        return;
    }
    if let Some(uuid) = header_uuid(&header) {
        counters.matched = counters.matched.saturating_add(1);
        collected.insert(uuid, path);
    }
}

pub(super) fn walk_read_dir(
    entries: fs::ReadDir,
    depth: usize,
    budget: &mut ScanBudget,
    root_deadline: Instant,
    max_depth: usize,
    counters: &mut Counters,
    collected: &mut CollectedEntries,
) {
    for entry in entries {
        if scan_cancelled()
            || Instant::now() >= root_deadline
            || Instant::now() >= budget.global_deadline
            || budget.files_seen >= budget.max_files
        {
            counters.truncated = true;
            return;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                count_error(counters, &e);
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                count_error(counters, &e);
                continue;
            }
        };
        /* 先用 file_type 拦住符号链接，再从 metadata 属性拦截 Windows
         * 重解析点（junction），避免递归进入同一目标形成环。 */
        if file_type.is_symlink() {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(e) => {
                count_error(counters, &e);
                continue;
            }
        };
        if is_reparse_or_symlink(&metadata) {
            continue;
        }
        if metadata.is_dir() {
            if depth + 1 > max_depth {
                counters.truncated = true;
                continue;
            }
            let entries = match fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(e) => {
                    count_error(counters, &e);
                    continue;
                }
            };
            walk_read_dir(
                entries,
                depth + 1,
                budget,
                root_deadline,
                max_depth,
                counters,
                collected,
            );
        } else if metadata.is_file() {
            if !budget.take_file() {
                counters.truncated = true;
                return;
            }
            counters.files_seen = counters.files_seen.saturating_add(1);
            inspect_container_file(&path, counters, collected);
        }
    }
}

pub(super) fn scan_file_target(
    target: &ScanTarget,
    budget: &mut ScanBudget,
    root_deadline: Instant,
) -> RootOutcome {
    let mut counters = Counters::default();
    let mut collected = CollectedEntries::default();
    let path = Path::new(&target.path);
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return RootOutcome {
                available: false,
                counters,
                entries: Vec::new(),
            };
        }
        Err(e) => {
            count_error(&mut counters, &e);
            return RootOutcome {
                available: false,
                counters,
                entries: Vec::new(),
            };
        }
    };
    if !metadata.is_file() {
        return RootOutcome {
            available: false,
            counters,
            entries: Vec::new(),
        };
    }
    if scan_cancelled()
        || Instant::now() >= root_deadline
        || Instant::now() >= budget.global_deadline
    {
        counters.truncated = true;
        return RootOutcome {
            available: true,
            counters,
            entries: Vec::new(),
        };
    }
    if !budget.take_file() {
        counters.truncated = true;
        return RootOutcome {
            available: true,
            counters,
            entries: Vec::new(),
        };
    }
    counters.files_seen = counters.files_seen.saturating_add(1);
    inspect_container_file(path, &mut counters, &mut collected);
    if collected.overflow {
        counters.truncated = true;
    }
    RootOutcome {
        available: true,
        counters,
        entries: collected.into_entries(),
    }
}

pub(super) fn scan_dir_target(
    target: &ScanTarget,
    budget: &mut ScanBudget,
    root_deadline: Instant,
    max_depth: usize,
) -> RootOutcome {
    let mut counters = Counters::default();
    let mut collected = CollectedEntries::default();
    let path = Path::new(&target.path);
    /* fs::metadata 会跟随根目录的一次重解析（例如 OneDrive 重定向目录）；
     * 递归内部仍跳过重解析点，避免环路与重复遍历。 */
    let root_metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return RootOutcome {
                available: false,
                counters,
                entries: Vec::new(),
            };
        }
        Err(e) => {
            count_error(&mut counters, &e);
            return RootOutcome {
                available: false,
                counters,
                entries: Vec::new(),
            };
        }
    };
    if !root_metadata.is_dir() {
        return RootOutcome {
            available: false,
            counters,
            entries: Vec::new(),
        };
    }
    if scan_cancelled()
        || Instant::now() >= root_deadline
        || Instant::now() >= budget.global_deadline
    {
        counters.truncated = true;
        return RootOutcome {
            available: true,
            counters,
            entries: Vec::new(),
        };
    }
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) => {
            count_error(&mut counters, &e);
            return RootOutcome {
                available: false,
                counters,
                entries: Vec::new(),
            };
        }
    };
    walk_read_dir(
        entries,
        0,
        budget,
        root_deadline,
        max_depth,
        &mut counters,
        &mut collected,
    );
    if collected.overflow {
        counters.truncated = true;
    }
    RootOutcome {
        available: true,
        counters,
        entries: collected.into_entries(),
    }
}

pub(super) fn scan_target(
    target: &ScanTarget,
    budget: &mut ScanBudget,
    root_deadline: Instant,
    max_depth: usize,
) -> RootOutcome {
    match target.kind {
        TargetKind::File => scan_file_target(target, budget, root_deadline),
        TargetKind::Dir => scan_dir_target(target, budget, root_deadline, max_depth),
    }
}
