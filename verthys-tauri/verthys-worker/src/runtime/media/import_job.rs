/*
 * media/import_job.rs — 原生照片导入 job
 *
 * 数据面：worker 负责读文件、哈希、400px 缩略图、动图探测、分块封装；
 * 宿主按拉取节奏取走密文块并写入容器。2048px 预览不进入导入关键路径，
 * 由首次查看的读取 job 懒生成。job 状态只驻留内存，进程退出即失效；
 * 已写入的块由宿主台账/WAL 与孤儿 GC 结算。
 */

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::time::UNIX_EPOCH;

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::runtime::budget::{PB_MAX_RECORD_NAME_BYTES, PB_PHOTO_CHUNK_SIZE_BYTES, PB_PHOTO_MAX_BYTES};
use crate::runtime::module_keys;
use crate::runtime::path_grants;
use crate::runtime::protocol::{base64_encode, MediaFinishPayload, MediaNextPayload, Request, Response};
use crate::runtime::worker::Worker;

use super::animated;
use super::decoder;
use super::mime;
use super::staged;

const MAX_JOB_PATHS: usize = 10_000;
const MAX_OPEN_JOBS: usize = 4;
const HASH_BUF_BYTES: usize = 1024 * 1024;
const CHUNK_BYTES: usize = PB_PHOTO_CHUNK_SIZE_BYTES as usize;
/// 空闲 job 回收窗口：宿主异常退出后不得永久占用 job 槽与文件句柄。
const JOB_IDLE_TTL: Duration = Duration::from_secs(600);

struct FileCursor {
    file: File,
    name: String,
    mime: String,
    size: u64,
    file_hash: String,
    entry_key: String,
    total_chunks: u32,
    next_chunk: u32,
    thumb_b64: String,
    animated: Option<bool>,
    created_at: i64,
    chunk_hashes: Vec<String>,
    verify_hasher: blake3::Hasher,
}

/// 单文件预取（哈希 + 缩略图 + 动图探测）的等待上限。
///
/// 预取在宿主写当前文件期间并行执行，正常已就绪；上限只防预取线程异常
/// 挂起拖死导入循环（与宿主 next 超时同量级）。
const PREFETCH_WAIT: Duration = Duration::from_secs(300);

/// 预取槽：索引固定为启动预取时的待打开位置，结果经单向通道回传。
struct PrefetchSlot {
    index: usize,
    rx: std::sync::mpsc::Receiver<Result<FileCursor, String>>,
}

struct Job {
    job_id: String,
    paths: Vec<String>,
    /// 宿主已提交的条目键：命中即跳过，不读文件、不解码。
    committed: HashSet<String>,
    next_path: usize,
    current: Option<FileCursor>,
    /// 下一个文件的预取结果：宿主处理当前文件期间提前完成读盘/哈希/缩略图
    prefetch: Option<PrefetchSlot>,
    cancelled: bool,
    last_touch: Instant,
}

static JOBS: std::sync::LazyLock<Mutex<HashMap<String, Job>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/* ------------------------------------------------------------------ *
 * 入口                                                                *
 * ------------------------------------------------------------------ */

pub(crate) fn handle_begin(req: &Request) -> Response {
    const OP: &str = "photo_import_job_begin";
    let job_id = req.job_id.trim();
    if job_id.is_empty() {
        return error(OP, "job_id 不能为空");
    }
    if req.paths.is_empty() {
        return error(OP, "路径列表为空");
    }
    if req.paths.len() > MAX_JOB_PATHS {
        return error(OP, "路径数量超过单 job 上限");
    }
    for path in &req.paths {
        if !path_grants::job_contains_for("photo_import", job_id, path) {
            return error(OP, "存在未授权路径");
        }
    }

    let mut jobs = lock_jobs();
    prune_stale(&mut jobs);
    if jobs.len() >= MAX_OPEN_JOBS {
        return error(OP, "并发导入 job 已达上限");
    }
    if jobs.contains_key(job_id) {
        return error(OP, "job 已存在");
    }
    jobs.insert(
        job_id.to_string(),
        Job {
            job_id: job_id.to_string(),
            paths: req.paths.clone(),
            committed: req.committed_entry_keys.iter().cloned().collect(),
            next_path: 0,
            current: None,
            prefetch: None,
            cancelled: false,
            last_touch: Instant::now(),
        },
    );
    Response::ok(OP)
}

pub(crate) fn handle_next(worker: &Worker, req: &Request) -> Response {
    const OP: &str = "photo_import_job_next";
    let mut jobs = lock_jobs();
    prune_stale(&mut jobs);
    let Some(job) = jobs.get_mut(&req.job_id) else {
        return error(OP, "job 不存在或已结束");
    };
    job.last_touch = Instant::now();
    if job.cancelled {
        return photo_response(OP, next_payload(&job.job_id, "cancelled"));
    }

    if job.current.is_none() {
        /* 新文件开始：上一文件已由宿主 finish/放弃，残留暂存与幂等映射必须释放。 */
        staged::clear(&job.job_id);
        match open_next(job) {
            Ok(None) => {}
            Ok(Some(payload)) => return photo_response(OP, payload),
            Err(e) => return error(OP, &e),
        }
    }

    let Some(mut cursor) = job.current.take() else {
        return photo_response(OP, next_payload(&job.job_id, "done"));
    };
    let seq = cursor.next_chunk;
    if seq >= cursor.total_chunks {
        return error(OP, "当前文件分块状态异常");
    }
    let start = seq as u64 * CHUNK_BYTES as u64;
    let remaining = cursor.size.saturating_sub(start);
    let len = remaining.min(CHUNK_BYTES as u64) as usize;
    if len == 0 {
        return error(OP, "当前文件分块为空");
    }

    let mut plain = Zeroizing::new(vec![0u8; len]);
    if let Err(e) = cursor.file.read_exact(&mut plain[..]) {
        staged::clear(&job.job_id);
        return skipped_response(&job.job_id, job.next_path.saturating_sub(1), &cursor.name, format!("读取照片块失败: {}", e));
    }

    let sealed = match module_keys::seal_photo_chunk(
        worker,
        &cursor.file_hash,
        seq,
        cursor.total_chunks,
        &plain,
    ) {
        Ok(data) => data,
        Err(e) => {
            staged::clear(&job.job_id);
            return skipped_response(&job.job_id, job.next_path.saturating_sub(1), &cursor.name, format!("加密照片块失败: {:?}", e));
        }
    };
    cursor.verify_hasher.update(&plain[..]);
    let sealed_hash = blake3::hash(&sealed).to_hex().to_string();
    let chunk_key_value = chunk_key(&cursor.entry_key, seq);
    if let Err(e) = staged::stage(
        &job.job_id,
        &chunk_key_value,
        sealed_hash.clone(),
        Zeroizing::new(sealed),
    ) {
        staged::clear(&job.job_id);
        return error(OP, &e);
    }
    cursor.chunk_hashes.push(sealed_hash.clone());
    cursor.next_chunk += 1;

    let file_done = cursor.next_chunk >= cursor.total_chunks;
    let payload = MediaNextPayload {
        status: "chunk".to_string(),
        job_id: Some(job.job_id.clone()),
        file_index: Some(job.next_path.saturating_sub(1) as u32),
        file_name: Some(cursor.name.clone()),
        mime: Some(cursor.mime.clone()),
        size: Some(cursor.size),
        file_hash: Some(cursor.file_hash.clone()),
        entry_key: Some(cursor.entry_key.clone()),
        chunk_index: Some(seq),
        chunk_total: Some(cursor.total_chunks),
        chunk_key: Some(chunk_key_value),
        chunk_hash: Some(sealed_hash),
        chunk_staged: Some(true),
        file_done,
        thumb_b64: if file_done { Some(cursor.thumb_b64.clone()) } else { None },
        animated: if file_done { cursor.animated } else { None },
        created_at: if file_done { Some(cursor.created_at) } else { None },
        error: None,
    };
    job.current = Some(cursor);
    photo_response(OP, payload)
}

pub(crate) fn handle_finish(worker: &Worker, req: &Request) -> Response {
    const OP: &str = "photo_import_job_finish";
    let mut jobs = lock_jobs();
    let Some(job) = jobs.get_mut(&req.job_id) else {
        return error(OP, "job 不存在或已结束");
    };
    let Some(cursor) = job.current.take() else {
        return error(OP, "没有待收尾的文件");
    };
    if req.chunk_ids.len() != cursor.total_chunks as usize {
        return error(OP, "块记录数与该文件块数不一致");
    }
    if req.chunk_ids.contains(&0) {
        return error(OP, "存在未分配的块记录 ID");
    }

    let digest = cursor.verify_hasher.finalize().to_hex().to_string();
    if digest != cursor.file_hash {
        return error(OP, "源文件在导入过程中发生变化，已拒绝收尾");
    }
    /* 收尾成功：本文件的暂存与幂等映射不再需要，立即释放内存。 */
    staged::clear(&req.job_id);

    let meta = PhotoMetaOut {
        name: &cursor.name,
        mime: &cursor.mime,
        size: cursor.size,
        thumb_b64: &cursor.thumb_b64,
        chunk_ids: &req.chunk_ids,
        chunk_data_b64: Vec::new(),
        chunk_hashes: &cursor.chunk_hashes,
        file_hash: &cursor.file_hash,
        entry_key: &cursor.entry_key,
        created_at: cursor.created_at,
        animated: cursor.animated,
    };
    let meta_json = match serde_json::to_vec(&meta) {
        Ok(v) => Zeroizing::new(v),
        Err(e) => return error(OP, &format!("序列化照片索引失败: {}", e)),
    };
    let sealed = match module_keys::seal_photo_meta(worker, &meta_json) {
        Ok(v) => v,
        Err(e) => return error(OP, &format!("加密照片索引失败: {:?}", e)),
    };
    let record_name = match meta_record_name(&cursor.name) {
        Ok(name) => name,
        Err(e) => return error(OP, &e),
    };

    /* 预览不再随导入写入：首次查看由读取 job 从解密字节懒生成并回写，
     * 导入关键路径只承担索引与缩略图。 */
    let mut resp = Response::ok(OP);
    resp.photo_finish = Some(MediaFinishPayload {
        meta_b64: base64_encode(&sealed),
        record_name,
        preview_b64: None,
        preview_record_name: None,
        animated: None,
    });
    resp
}

pub(crate) fn handle_cancel(req: &Request) -> Response {
    const OP: &str = "photo_import_job_cancel";
    let mut jobs = lock_jobs();
    if let Some(job) = jobs.get_mut(&req.job_id) {
        job.cancelled = true;
        job.current = None;
        staged::clear(&req.job_id);
    }
    Response::ok(OP)
}

pub(crate) fn handle_end(req: &Request) -> Response {
    const OP: &str = "photo_import_job_end";
    {
        let mut jobs = lock_jobs();
        jobs.remove(&req.job_id);
    }
    staged::clear(&req.job_id);
    path_grants::revoke_job(&req.job_id);
    Response::ok(OP)
}

/* ------------------------------------------------------------------ *
 * 文件推进                                                            *
 * ------------------------------------------------------------------ */

/// 打开下一个文件；Ok(None) 表示 current 已就绪。
///
/// 优先消费预取结果：预取在宿主写上一张照片期间并行完成读盘/哈希/缩略图，
/// 命中时本函数只剩一次通道接收。预取索引与待打开位置不一致（取消/重排）
/// 时丢弃并回退同步打开，语义与未启用预取完全一致。
fn open_next(job: &mut Job) -> Result<Option<MediaNextPayload>, String> {
    if let Some(slot) = job.prefetch.take() {
        if slot.index == job.next_path && slot.index < job.paths.len() {
            let index = slot.index;
            job.next_path += 1;
            let path = job.paths[index].clone();
            let prepared = match slot.rx.recv_timeout(PREFETCH_WAIT) {
                Ok(result) => result,
                Err(_) => Err("照片预取超时".to_string()),
            };
            return match prepared {
                Ok(cursor) => {
                    job.current = Some(cursor);
                    start_prefetch(job);
                    Ok(None)
                }
                Err(e) => Ok(Some(skipped_payload(
                    &job.job_id,
                    index,
                    file_name(Path::new(&path)),
                    e,
                ))),
            };
        }
    }
    /* 单次推进：任一分支都向上返回一个事件（打开成功 / 去重 / 跳过 /
     * 完成），由宿主下一次 next 继续推进；循环体不存在可重复路径。 */
    if job.next_path < job.paths.len() {
        let index = job.next_path;
        job.next_path += 1;
        let path = job.paths[index].clone();
        if !path_grants::job_contains_for("photo_import", &job.job_id, &path) {
            return Ok(Some(skipped_payload(
                &job.job_id,
                index,
                file_name(Path::new(&path)),
                "路径未授权或授权已过期".to_string(),
            )));
        }
        /* 去重前置：entry_key 只依赖元数据，命中时不读文件、不哈希、不解码。
         * 元数据不可读时交给 open_file 报具体错误。 */
        if let Some(key) = stat_entry_key(Path::new(&path)) {
            if job.committed.contains(&key) {
                return Ok(Some(deduped_payload(
                    &job.job_id,
                    index,
                    file_name(Path::new(&path)),
                )));
            }
        }
        match open_file(Path::new(&path)) {
            Ok(cursor) => {
                job.current = Some(cursor);
                start_prefetch(job);
                return Ok(None);
            }
            Err(e) => {
                return Ok(Some(skipped_payload(
                    &job.job_id,
                    index,
                    file_name(Path::new(&path)),
                    e,
                )));
            }
        }
    }
    Ok(Some(next_payload(&job.job_id, "done")))
}

/// 为下一个待打开文件启动预取。
///
/// 只在当前文件已打开后调用：宿主随后写块/索引的时间窗口正好覆盖预取的
/// 读盘与解码成本。路径授权与去重判定与同步路径同一规则；线程启动失败
/// 时静默回退同步打开，不影响导入语义。
fn start_prefetch(job: &mut Job) {
    if job.prefetch.is_some() || job.next_path >= job.paths.len() {
        return;
    }
    let index = job.next_path;
    let path = job.paths[index].clone();
    if !path_grants::job_contains_for("photo_import", &job.job_id, &path) {
        return;
    }
    if let Some(key) = stat_entry_key(Path::new(&path)) {
        if job.committed.contains(&key) {
            return; /* 去重命中：无需读盘解码 */
        }
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("photo-import-prefetch".into())
        .spawn(move || {
            let _ = tx.send(open_file(Path::new(&path)));
        });
    if spawned.is_ok() {
        job.prefetch = Some(PrefetchSlot { index, rx });
    }
}

/// 仅用元数据计算条目键；文件不可 stat 或为空时返回 None。
/// 公式必须与 `open_file` 的 entry_key 一致，否则去重会漏判。
fn stat_entry_key(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let size = meta.len();
    if size == 0 {
        return None;
    }
    let mtime_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    Some(entry_key(&file_name(path), size, mtime_ms))
}

fn open_file(path: &Path) -> Result<FileCursor, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("读取文件属性失败: {}", e))?;
    let size = meta.len();
    if size == 0 {
        return Err("文件为空".to_string());
    }
    if size > PB_PHOTO_MAX_BYTES {
        return Err(format!(
            "文件超过单张照片上限（{} > {} 字节）",
            size, PB_PHOTO_MAX_BYTES
        ));
    }
    let mtime_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mime_type = mime::detect_mime(path)?;
    let file_hash = blake3_file_hash(path)?;
    /* 导入路径只生成网格缩略图；2048px 预览由首次查看懒生成，
     * 避免为每张大图在关键路径上多付一次整图编码。 */
    let thumb_b64 = decoder::generate_thumb_b64(path)?;
    let animated = animated::detect(path, mime_type)?;
    let name = file_name(path);
    let entry_key = entry_key(&name, size, mtime_ms);
    let total_chunks = chunk_count(size);

    let mut file = File::open(path).map_err(|e| format!("打开文件失败: {}", e))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("文件定位失败: {}", e))?;

    Ok(FileCursor {
        file,
        name,
        mime: mime_type.to_string(),
        size,
        file_hash,
        entry_key,
        total_chunks,
        next_chunk: 0,
        thumb_b64,
        animated,
        created_at: now_ms(),
        chunk_hashes: Vec::with_capacity(total_chunks as usize),
        verify_hasher: blake3::Hasher::new(),
    })
}

fn blake3_file_hash(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("打开文件失败: {}", e))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = Zeroizing::new(vec![0u8; HASH_BUF_BYTES]);
    loop {
        let n = file
            .read(&mut buf[..])
            .map_err(|e| format!("读取文件失败: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/* ------------------------------------------------------------------ *
 * 键与记录名                                                          *
 * ------------------------------------------------------------------ */

fn chunk_count(size: u64) -> u32 {
    size.div_ceil(CHUNK_BYTES as u64) as u32
}

fn entry_key(name: &str, size: u64, mtime_ms: u64) -> String {
    sha256_hex(format!("file|{}|{}|{}", name, size, mtime_ms).as_bytes())
}

fn chunk_key(entry_key: &str, seq: u32) -> String {
    sha256_hex(format!("chunk|{}|{}", entry_key, seq).as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn meta_record_name(name: &str) -> Result<String, String> {
    let record = format!("meta_{}", name);
    if record.len() <= PB_MAX_RECORD_NAME_BYTES as usize {
        return Ok(record);
    }
    Err("文件名过长，无法生成照片记录名".to_string())
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("photo")
        .to_string()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/* ------------------------------------------------------------------ *
 * 响应装配                                                            *
 * ------------------------------------------------------------------ */

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhotoMetaOut<'a> {
    name: &'a str,
    mime: &'a str,
    size: u64,
    thumb_b64: &'a str,
    chunk_ids: &'a [u64],
    chunk_data_b64: Vec<String>,
    chunk_hashes: &'a [String],
    file_hash: &'a str,
    entry_key: &'a str,
    created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    animated: Option<bool>,
}

fn next_payload(job_id: &str, status: &str) -> MediaNextPayload {
    MediaNextPayload {
        status: status.to_string(),
        job_id: Some(job_id.to_string()),
        file_index: None,
        file_name: None,
        mime: None,
        size: None,
        file_hash: None,
        entry_key: None,
        chunk_index: None,
        chunk_total: None,
        chunk_key: None,
        chunk_hash: None,
        chunk_staged: None,
        file_done: false,
        thumb_b64: None,
        animated: None,
        created_at: None,
        error: None,
    }
}

fn skipped_payload(job_id: &str, index: usize, name: String, reason: String) -> MediaNextPayload {
    let mut payload = next_payload(job_id, "skipped");
    payload.file_index = Some(index as u32);
    payload.file_name = Some(name);
    payload.error = Some(reason);
    payload
}

/// 去重命中：条目键已在宿主 WAL 提交，未新增记录，也不是失败。
fn deduped_payload(job_id: &str, index: usize, name: String) -> MediaNextPayload {
    let mut payload = next_payload(job_id, "deduped");
    payload.file_index = Some(index as u32);
    payload.file_name = Some(name);
    payload
}

fn skipped_response(job_id: &str, index: usize, name: &str, reason: String) -> Response {
    photo_response(
        "photo_import_job_next",
        skipped_payload(job_id, index, name.to_string(), reason),
    )
}

fn photo_response(op: &str, payload: MediaNextPayload) -> Response {
    let mut resp = Response::ok(op);
    resp.photo = Some(payload);
    resp
}

fn error(op: &str, message: &str) -> Response {
    let mut resp = Response::ok(op);
    resp.ok = false;
    resp.error = Some(message.to_string());
    resp
}

fn prune_stale(jobs: &mut HashMap<String, Job>) {
    let now = Instant::now();
    jobs.retain(|_, job| now.saturating_duration_since(job.last_touch) < JOB_IDLE_TTL);
    staged::prune_all();
}

fn lock_jobs() -> std::sync::MutexGuard<'static, HashMap<String, Job>> {
    JOBS.lock().unwrap_or_else(|poison| poison.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_count_covers_product_boundaries() {
        let mib = 1024 * 1024u64;
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK_BYTES as u64), 1);
        assert_eq!(chunk_count(CHUNK_BYTES as u64 + 1), 2);
        assert_eq!(chunk_count(18_591_252), 5);
        assert_eq!(chunk_count(25_616_712), 7);
        assert_eq!(chunk_count(50 * mib), 13);
        assert_eq!(chunk_count(PB_PHOTO_MAX_BYTES), 25);
        assert_eq!(chunk_count(PB_PHOTO_MAX_BYTES + 1), 26);
    }

    #[test]
    fn entry_and_chunk_keys_are_stable_and_metadata_bound() {
        let a = entry_key("a.jpg", 10, 1000);
        let b = entry_key("a.jpg", 10, 1000);
        let c = entry_key("a.jpg", 10, 1001);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(chunk_key(&a, 0), chunk_key(&b, 0));
        assert_ne!(chunk_key(&a, 0), chunk_key(&a, 1));
    }

    #[test]
    fn meta_record_name_is_bounded() {
        assert_eq!(meta_record_name("a.jpg").unwrap(), "meta_a.jpg");
        let long = "x".repeat(PB_MAX_RECORD_NAME_BYTES as usize);
        assert!(meta_record_name(&long).is_err());
    }

    #[test]
    fn prefetch_serves_next_file_in_order() {
        let dir = std::env::temp_dir().join(format!("vty-prefetch-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let a = dir.join("a.png");
        let b = dir.join("b.png");
        let img = image::RgbImage::from_fn(8, 8, |x, y| {
            image::Rgb([(x * 20) as u8, (y * 20) as u8, 128])
        });
        img.save(&a).unwrap();
        img.save(&b).unwrap();

        let job_id = format!("prefetch-test-{}", std::process::id());
        let paths = vec![
            a.to_string_lossy().to_string(),
            b.to_string_lossy().to_string(),
        ];
        path_grants::authorize_job_target("photo_import", &job_id, &paths).unwrap();

        let mut job = Job {
            job_id: job_id.clone(),
            paths,
            committed: HashSet::new(),
            next_path: 0,
            current: None,
            prefetch: None,
            cancelled: false,
            last_touch: Instant::now(),
        };

        assert!(open_next(&mut job).unwrap().is_none(), "首个文件应打开成功");
        assert_eq!(job.current.as_ref().unwrap().name, "a.png");
        assert!(job.prefetch.is_some(), "打开首文件后应启动下一文件预取");

        // 模拟宿主写完首文件后继续拉取：预取结果直接就绪，不重复读盘
        job.current = None;
        assert!(open_next(&mut job).unwrap().is_none(), "预取命中应直接就绪");
        assert_eq!(job.current.as_ref().unwrap().name, "b.png");
        assert!(job.prefetch.is_none(), "末文件不产生预取");

        path_grants::revoke_job(&job_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staged_next_payload_has_no_inline_ciphertext() {
        let mut payload = next_payload("job-1", "chunk");
        payload.chunk_key = Some("a".repeat(64));
        payload.chunk_hash = Some("b".repeat(64));
        payload.chunk_staged = Some(true);
        let json = serde_json::to_value(&payload).unwrap();
        assert!(json.get("chunk_b64").is_none());
        assert_eq!(
            json.get("chunk_staged").and_then(|value| value.as_bool()),
            Some(true)
        );
    }
}
