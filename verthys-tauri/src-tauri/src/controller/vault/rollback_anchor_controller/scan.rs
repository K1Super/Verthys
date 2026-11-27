/*
 * 扫描预算、计数与并行遍历实现
 *
 * 职责边界：全局有界预算（文件数/深度/时长）、权限错误单独计数、跳过
 * 符号链接与重解析点、只读容器固定头识别 UUID、按目标归集证据。
 *
 * 完整性语义：truncated 只表示目录遍历被预算、取消或读取错误截断；
 * 单 UUID 证据列表超过展示上限时只标记该条目的 capped，不影响整体完整性。
 *
 * 并发模型：所有目录目标进入同一工作队列，由有限工作线程并行遍历；
 * 每个目标独立累计计数与证据，最终按目标合并，结果与线程调度无关。
 */

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::repository::anchor_scan_store::{self, StoredScanEntry};

use super::*;
use std::io::Read;

const PROGRESS_INTERVAL: Duration = Duration::from_millis(150);
const TIME_CHECK_MASK: u64 = 0xFF;

pub(super) struct ScanBudget {
    pub(super) deadline: Instant,
    pub(super) max_files: u64,
    pub(super) files_seen: AtomicU64,
    pub(super) exhausted: AtomicBool,
}

impl ScanBudget {
    pub(super) fn new(max_files: u64, budget: Duration) -> Self {
        Self {
            deadline: Instant::now() + budget,
            max_files,
            files_seen: AtomicU64::new(0),
            exhausted: AtomicBool::new(false),
        }
    }

    pub(super) fn take_file(&self) -> bool {
        if self.exhausted.load(Ordering::Relaxed) {
            return false;
        }
        let seen = self.files_seen.fetch_add(1, Ordering::Relaxed);
        if seen >= self.max_files {
            self.exhausted.store(true, Ordering::Relaxed);
            return false;
        }
        true
    }

    pub(super) fn exceeded(&self) -> bool {
        scan_cancelled()
            || self.exhausted.load(Ordering::Relaxed)
            || Instant::now() >= self.deadline
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
}

#[derive(Default)]
pub(super) struct CollectedPaths {
    pub(super) keys: HashSet<String>,
    pub(super) paths: Vec<String>,
    /// 该 UUID 的路径数超过展示上限，证据列表不完整。
    /// 只影响单个锚点的证据展示，不表示目录遍历被截断。
    pub(super) capped: bool,
}

impl CollectedPaths {
    fn push_path(&mut self, path_key: String, display: String) {
        if !self.keys.insert(path_key) {
            return;
        }
        if self.paths.len() < SCAN_MAX_PATHS_PER_UUID {
            self.paths.push(display);
        } else {
            self.capped = true;
        }
    }
}

impl CollectedEntries {
    pub(super) fn insert(&mut self, uuid: [u8; 16], path: &Path) {
        let display = path.to_string_lossy().to_string();
        let path_key = anchor_scan_store::path_key(&display);
        self.map
            .entry(uuid_hex(&uuid))
            .or_default()
            .push_path(path_key, display);
    }

    pub(super) fn into_entries(self) -> Vec<StoredScanEntry> {
        let mut entries: Vec<StoredScanEntry> = self
            .map
            .into_iter()
            .map(|(uuid, mut collected)| {
                collected.paths.sort();
                StoredScanEntry {
                    uuid,
                    paths: collected.paths,
                    capped: collected.capped,
                }
            })
            .collect();
        entries.sort_by(|a, b| a.uuid.cmp(&b.uuid));
        entries
    }

    fn merge_from(&mut self, other: CollectedEntries) {
        for (uuid, collected) in other.map {
            let entry = self.map.entry(uuid).or_default();
            entry.capped |= collected.capped;
            for path in collected.paths {
                entry.push_path(anchor_scan_store::path_key(&path), path);
            }
        }
    }
}

#[derive(Default)]
pub(super) struct RootOutcome {
    pub(super) available: bool,
    pub(super) counters: Counters,
    pub(super) entries: Vec<StoredScanEntry>,
}

#[derive(Default)]
struct RootStats {
    files_seen: AtomicU64,
    matched: AtomicU64,
    permission_errors: AtomicU64,
    other_errors: AtomicU64,
    truncated: AtomicBool,
    /// 该目标尚未完成的目录任务数；归零表示目标覆盖完成
    pending: AtomicUsize,
}

impl RootStats {
    fn snapshot(&self) -> Counters {
        Counters {
            files_seen: self.files_seen.load(Ordering::Relaxed),
            matched: self.matched.load(Ordering::Relaxed),
            permission_errors: self.permission_errors.load(Ordering::Relaxed),
            other_errors: self.other_errors.load(Ordering::Relaxed),
            truncated: self.truncated.load(Ordering::Relaxed),
        }
    }

    fn record_error(&self, err: &std::io::Error) {
        /* 遍历期间文件/目录被并发删除是正常现象：目标已不存在，不构成
         * 覆盖缺口，也不应让整轮扫描退化为“不完整”。 */
        if err.kind() == ErrorKind::NotFound {
            return;
        }
        if err.kind() == ErrorKind::PermissionDenied {
            self.permission_errors.fetch_add(1, Ordering::Relaxed);
        } else {
            self.other_errors.fetch_add(1, Ordering::Relaxed);
        }
        self.truncated.store(true, Ordering::Relaxed);
    }

    fn mark_truncated(&self) {
        self.truncated.store(true, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct DirTask {
    target: usize,
    path: PathBuf,
    /// 相对扫描目标根的深度；目标根自身为 0
    depth: usize,
}

#[derive(Default)]
struct WalkState {
    queue: VecDeque<DirTask>,
    pending: usize,
    done: bool,
}

struct WalkShared {
    state: Mutex<WalkState>,
    wake: Condvar,
    aborted: AtomicBool,
}

impl WalkShared {
    fn new(queue: VecDeque<DirTask>, pending: usize) -> Self {
        Self {
            state: Mutex::new(WalkState {
                queue,
                pending,
                done: pending == 0,
            }),
            wake: Condvar::new(),
            aborted: AtomicBool::new(false),
        }
    }

    fn is_done(&self) -> bool {
        self.state.lock().map(|state| state.done).unwrap_or(true)
    }
}

struct ProgressState {
    roots_done: AtomicUsize,
    current: AtomicUsize,
}

/// 一次并行遍历的只读上下文：工作线程只借用，不持有所有权。
struct ScanContext<'a> {
    targets: &'a [ScanTarget],
    stats: &'a [RootStats],
    covered: &'a HashSet<String>,
    budget: &'a ScanBudget,
    progress: &'a ProgressState,
}

pub(super) struct ScanProgressTick {
    pub(super) roots_total: usize,
    pub(super) roots_done: usize,
    pub(super) current_path: String,
    pub(super) files_seen: u64,
    pub(super) matched: u64,
    pub(super) partial: bool,
}

/* ------------------------------------------------------------------ *
 * 扫描实现                                                             *
 * ------------------------------------------------------------------ */

fn read_container_uuid(path: &Path) -> Result<Option<[u8; 16]>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut header = [0u8; CONTAINER_HEADER_BYTES];
    let mut read = 0usize;
    while read < header.len() {
        match file.read(&mut header[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) => return Err(e),
        }
    }
    if read < header.len() {
        return Ok(None);
    }
    Ok(header_uuid(&header))
}

fn scan_file_target(target: &ScanTarget, budget: &ScanBudget) -> RootOutcome {
    let mut counters = Counters::default();
    let mut collected = CollectedEntries::default();
    let path = Path::new(&target.path);
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return RootOutcome::default();
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
        return RootOutcome::default();
    }
    if budget.exceeded() {
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
    match read_container_uuid(path) {
        Ok(Some(uuid)) => {
            counters.matched = counters.matched.saturating_add(1);
            collected.insert(uuid, path);
        }
        Ok(None) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => count_error(&mut counters, &e),
    }
    RootOutcome {
        available: true,
        counters,
        entries: collected.into_entries(),
    }
}

fn max_depth_for(source: RootSource) -> usize {
    if source == RootSource::Volume {
        VOLUME_SCAN_MAX_DEPTH
    } else {
        CUSTOM_SCAN_MAX_DEPTH
    }
}

fn process_dir(
    ctx: &ScanContext<'_>,
    task: &DirTask,
    shared: &WalkShared,
    subdirs: &mut Vec<(PathBuf, usize)>,
    collected: &mut HashMap<usize, CollectedEntries>,
) {
    let target = &ctx.targets[task.target];
    let stats = &ctx.stats[task.target];
    if ctx.budget.exceeded() {
        stats.mark_truncated();
        shared.aborted.store(true, Ordering::Relaxed);
        return;
    }
    let entries = match fs::read_dir(&task.path) {
        Ok(entries) => entries,
        Err(e) => {
            stats.record_error(&e);
            return;
        }
    };
    let volume_root =
        target.source == RootSource::Volume || Path::new(&target.path).parent().is_none();
    let max_depth = max_depth_for(target.source);
    let mut tick = 0u64;
    for entry in entries {
        tick = tick.wrapping_add(1);
        if scan_cancelled() {
            stats.mark_truncated();
            shared.aborted.store(true, Ordering::Relaxed);
            return;
        }
        if tick & TIME_CHECK_MASK == 0 && Instant::now() >= ctx.budget.deadline {
            stats.mark_truncated();
            shared.aborted.store(true, Ordering::Relaxed);
            return;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                stats.record_error(&e);
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                stats.record_error(&e);
                continue;
            }
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            let name = entry.file_name();
            if task.depth == 0 && volume_root && is_volume_skip_dir(&name) {
                continue;
            }
            if volume_root && is_volume_nested_skip_dir(&name) {
                continue;
            }
            if is_nested_skip_dir(&name) {
                continue;
            }
            if !ctx.covered.is_empty() {
                let key = anchor_scan_store::path_key(&path.to_string_lossy());
                if ctx.covered.contains(&key) {
                    continue;
                }
            }
            if task.depth + 1 > max_depth {
                /* 深度上限是声明的覆盖边界，不是读取失败：不标记 truncated，
                 * 其他已覆盖位置仍可作为完整扫描结果。 */
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(e) => {
                    stats.record_error(&e);
                    continue;
                }
            };
            if is_reparse_or_symlink(&metadata) {
                continue;
            }
            subdirs.push((path, task.depth + 1));
        } else if file_type.is_file() {
            if !ctx.budget.take_file() {
                stats.mark_truncated();
                shared.aborted.store(true, Ordering::Relaxed);
                return;
            }
            stats.files_seen.fetch_add(1, Ordering::Relaxed);
            if !is_container_candidate(&path) {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(e) => {
                    stats.record_error(&e);
                    continue;
                }
            };
            /* 候选容器本身是重解析点（云占位/链接）时无法在不触发下载的
             * 前提下读取头部；这属于覆盖缺口，必须阻止“未找到”推断。 */
            if is_reparse_or_symlink(&metadata) {
                stats.mark_truncated();
                continue;
            }
            match read_container_uuid(&path) {
                Ok(Some(uuid)) => {
                    stats.matched.fetch_add(1, Ordering::Relaxed);
                    collected
                        .entry(task.target)
                        .or_default()
                        .insert(uuid, &path);
                }
                Ok(None) => {}
                Err(e) => stats.record_error(&e),
            }
        }
    }
}

fn worker_loop(
    shared: &WalkShared,
    ctx: &ScanContext<'_>,
    collected: &mut HashMap<usize, CollectedEntries>,
) {
    loop {
        let task = {
            let mut state = match shared.state.lock() {
                Ok(state) => state,
                Err(_) => return,
            };
            loop {
                if state.done {
                    return;
                }
                if shared.aborted.load(Ordering::Relaxed) {
                    mark_aborted(&mut state, ctx.stats, shared);
                    return;
                }
                if let Some(task) = state.queue.pop_front() {
                    break task;
                }
                if state.pending == 0 {
                    state.done = true;
                    shared.wake.notify_all();
                    return;
                }
                state = match shared.wake.wait(state) {
                    Ok(state) => state,
                    Err(_) => return,
                };
            }
        };
        ctx.progress.current.store(task.target, Ordering::Relaxed);
        let mut subdirs = Vec::new();
        process_dir(ctx, &task, shared, &mut subdirs, collected);
        {
            let mut state = match shared.state.lock() {
                Ok(state) => state,
                Err(_) => return,
            };
            for (path, depth) in subdirs {
                state.queue.push_back(DirTask {
                    target: task.target,
                    path,
                    depth,
                });
                state.pending += 1;
                ctx.stats[task.target]
                    .pending
                    .fetch_add(1, Ordering::Relaxed);
            }
            state.pending = state.pending.saturating_sub(1);
            if state.pending == 0 {
                state.done = true;
                shared.wake.notify_all();
            } else if !state.queue.is_empty() {
                /* 一次目录展开可能产生多个兄弟任务；只唤醒一个会让其余
                 * 工作线程继续沉睡，队列再大也无法并行。 */
                shared.wake.notify_all();
            }
        }
        if ctx.stats[task.target]
            .pending
            .fetch_sub(1, Ordering::AcqRel)
            == 1
        {
            ctx.progress.roots_done.fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn mark_aborted(state: &mut WalkState, stats: &[RootStats], shared: &WalkShared) {
    for stat in stats {
        if stat.pending.load(Ordering::Relaxed) > 0 {
            stat.mark_truncated();
        }
    }
    state.queue.clear();
    state.pending = 0;
    state.done = true;
    shared.wake.notify_all();
}

/// 并行扫描全部目标，返回与 `targets` 等长的结果。
pub(super) fn scan_targets<F: FnMut(ScanProgressTick)>(
    targets: &[ScanTarget],
    budget: &ScanBudget,
    covered: &HashSet<String>,
    mut on_tick: F,
) -> Vec<RootOutcome> {
    let stats: Vec<RootStats> = targets.iter().map(|_| RootStats::default()).collect();
    let mut outcomes: Vec<RootOutcome> = targets.iter().map(|_| RootOutcome::default()).collect();
    let progress = ProgressState {
        roots_done: AtomicUsize::new(0),
        current: AtomicUsize::new(usize::MAX),
    };
    let mut initial: VecDeque<DirTask> = VecDeque::new();

    for (index, target) in targets.iter().enumerate() {
        if target.kind == TargetKind::File {
            outcomes[index] = scan_file_target(target, budget);
            progress.roots_done.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let path = Path::new(&target.path);
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => {
                outcomes[index].available = true;
                stats[index].pending.store(1, Ordering::Relaxed);
                initial.push_back(DirTask {
                    target: index,
                    path: path.to_path_buf(),
                    depth: 0,
                });
            }
            Ok(_) => {
                progress.roots_done.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                progress.roots_done.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                stats[index].record_error(&e);
                progress.roots_done.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    let task_count = initial.len();
    let shared = WalkShared::new(initial, task_count);
    let ctx = ScanContext {
        targets,
        stats: &stats,
        covered,
        budget,
        progress: &progress,
    };
    let mut locals: Vec<HashMap<usize, CollectedEntries>> = Vec::new();
    if task_count > 0 {
        let workers = worker_count().min(task_count);
        let shared_ref = &shared;
        let ctx_ref = &ctx;
        thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for _ in 0..workers {
                handles.push(scope.spawn(move || {
                    let mut local: HashMap<usize, CollectedEntries> = HashMap::new();
                    worker_loop(shared_ref, ctx_ref, &mut local);
                    local
                }));
            }
            let mut last_tick = Instant::now();
            while !shared.is_done() {
                thread::sleep(Duration::from_millis(30));
                if last_tick.elapsed() >= PROGRESS_INTERVAL {
                    last_tick = Instant::now();
                    on_tick(tick_snapshot(&ctx));
                }
            }
            for handle in handles {
                if let Ok(local) = handle.join() {
                    locals.push(local);
                }
            }
        });
    }
    on_tick(tick_snapshot(&ctx));

    let mut merged: Vec<CollectedEntries> = targets
        .iter()
        .map(|_| CollectedEntries::default())
        .collect();
    for local in locals {
        for (index, collected) in local {
            if index < merged.len() {
                merged[index].merge_from(collected);
            }
        }
    }
    for (index, outcome) in outcomes.iter_mut().enumerate() {
        if targets[index].kind != TargetKind::Dir {
            continue;
        }
        outcome.counters = stats[index].snapshot();
        if !merged[index].map.is_empty() {
            outcome.entries = std::mem::take(&mut merged[index]).into_entries();
        }
    }
    outcomes
}

fn tick_snapshot(ctx: &ScanContext<'_>) -> ScanProgressTick {
    let files_seen = ctx
        .stats
        .iter()
        .map(|stat| stat.files_seen.load(Ordering::Relaxed))
        .sum();
    let matched = ctx
        .stats
        .iter()
        .map(|stat| stat.matched.load(Ordering::Relaxed))
        .sum();
    let truncated = ctx
        .stats
        .iter()
        .any(|stat| stat.truncated.load(Ordering::Relaxed));
    let current = ctx.progress.current.load(Ordering::Relaxed);
    let current_path = ctx
        .targets
        .get(current)
        .map(|target| target.path.clone())
        .unwrap_or_default();
    ScanProgressTick {
        roots_total: ctx.targets.len(),
        roots_done: ctx.progress.roots_done.load(Ordering::Relaxed),
        current_path,
        files_seen,
        matched,
        partial: truncated || ctx.budget.exhausted.load(Ordering::Relaxed) || scan_cancelled(),
    }
}

fn worker_count() -> usize {
    thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(2)
        .clamp(2, SCAN_MAX_WORKERS)
}
