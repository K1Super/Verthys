/*
 * file_import/job.rs — job 状态、上限常量与空闲回收
 *
 * JOBS 只驻留内存：每个 job 持有文件清单、已提交条目键与当前文件游标；
 * 空闲窗口用于回收异常退出残留的 job 槽与文件句柄。
 */

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::runtime::budget::{
    PB_MAX_FILE_CHUNK_SIZE_BYTES, PB_MAX_RECORD_NAME_BYTES, PB_USER_FILE_SIZE_LIMIT,
};
use crate::runtime::content_crypto::SALT_LEN;
use crate::runtime::media::staged;
use crate::runtime::protocol::FileImportSource;

/// 单 job 文件数上限（与宿主授权批次一致）
pub(super) const MAX_JOB_FILES: usize = 10_000;
/// 并发 job 上限
pub(super) const MAX_OPEN_JOBS: usize = 4;
/// 分块口径（跨层预算单一权威来源）
pub(super) const CHUNK_BYTES: usize = PB_MAX_FILE_CHUNK_SIZE_BYTES as usize;
/// 单文件体量上限
pub(super) const MAX_FILE_BYTES: u64 = PB_USER_FILE_SIZE_LIMIT;
/// 记录名长度上限（字节）
pub(super) const MAX_RECORD_NAME_BYTES: usize = PB_MAX_RECORD_NAME_BYTES as usize;
/// 空闲 job 回收窗口：宿主异常退出后不得永久占用 job 槽与文件句柄。
const JOB_IDLE_TTL: Duration = Duration::from_secs(600);

/// 元数据写入形态标记（读取侧按字段存在性分流，不依赖该值）
pub(super) const META_SCHEMA: u32 = 2;
/// 去重键的域分隔标识（与 `fileHashSuffix` 前端口径一致）
pub(super) const HASH_FORMAT_VER: u8 = 1;
/// 明文条目的指纹域字节
pub(super) const FINGERPRINT_PLAIN: u8 = 0x00;
/// 加密条目的指纹域字节
pub(super) const FINGERPRINT_ENCRYPTED: u8 = 0x01;

pub(super) struct FileCursor {
    pub(super) file: File,
    pub(super) path: String,
    pub(super) name: String,
    pub(super) mime: String,
    pub(super) size: u64,
    pub(super) mtime_ms: u64,
    pub(super) entry_key: String,
    pub(super) total_chunks: u32,
    pub(super) next_chunk: u32,
    pub(super) bytes_read: u64,
    pub(super) encrypted: bool,
    pub(super) salt: Option<[u8; SALT_LEN]>,
    pub(super) iterations: u32,
    pub(super) key: Option<Zeroizing<[u8; 32]>>,
    pub(super) password_check_b64: Option<String>,
    pub(super) file_hasher: blake3::Hasher,
    pub(super) chunk_hashes: Vec<String>,
}

pub(super) struct Job {
    pub(super) job_id: String,
    pub(super) files: Vec<FileImportSource>,
    pub(super) committed: HashSet<String>,
    pub(super) next_index: usize,
    pub(super) current: Option<FileCursor>,
    pub(super) password: Zeroizing<String>,
    pub(super) cancelled: bool,
    pub(super) last_touch: Instant,
}

static JOBS: std::sync::LazyLock<Mutex<HashMap<String, Job>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) fn prune_stale(jobs: &mut HashMap<String, Job>) {
    let now = Instant::now();
    jobs.retain(|_, job| now.saturating_duration_since(job.last_touch) < JOB_IDLE_TTL);
    staged::prune_all();
}

pub(super) fn lock_jobs() -> std::sync::MutexGuard<'static, HashMap<String, Job>> {
    JOBS.lock().unwrap_or_else(|poison| poison.into_inner())
}
