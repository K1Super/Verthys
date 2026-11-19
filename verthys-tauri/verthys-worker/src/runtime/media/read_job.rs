/*
 * media/read_job.rs — 原生照片读取 job
 *
 * 预览：按确定性名称命中预览记录则直接解密返回；缺失/损坏/头不匹配时
 * 逐块解密原图、原生生成 2048px 预览，返回 JPEG 并把待写回的密文交给
 * 宿主单写者落库。
 *
 * 原图：宿主按块拉取明文；worker 逐块解密并校验块序号/总数，全部块
 * 完成后才以整图 BLAKE3 判定完整性。明文只存在于本次响应与前端 Blob，
 * 不落盘。
 *
 * 布局边界：支持既有 `meta` + `chunk`（内联或外置）与索引瘦身布局
 * （`slim_meta`、`chunkSetId`、`slim_chunk`）；不再回退桌面 JS 读取链路。
 */

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::runtime::budget::PB_PHOTO_MAX_BYTES;
use crate::runtime::module_keys;
use crate::runtime::protocol::{
    base64_encode, MediaPreviewRecord, MediaReadPayload, Request, Response,
};
use crate::runtime::worker::Worker;

use super::decoder;
use super::preview;
use super::source::{self, load_chunk_cipher, read_meta, PhotoMetaIn};

/// 并发读取 job 上限：预览是一次性操作，原图 job 按查看器实例计数。
const MAX_READ_JOBS: usize = 4;
/// 空闲 job 回收窗口：宿主异常退出后不残留明文/密文引用。
const JOB_IDLE_TTL: Duration = Duration::from_secs(120);


struct FullJob {
    job_id: String,
    meta_id: u64,
    meta: PhotoMetaIn,
    next_seq: u32,
    total: u32,
    hasher: blake3::Hasher,
    cancelled: bool,
    /// 终态失败（末块哈希不符/块顺序错乱）：后续 next 一律返回错误，
    /// 不得因哈希器已 finalize 而返回 done 掩盖完整性失败。
    failed: bool,
    last_touch: Instant,
}

static JOBS: std::sync::LazyLock<std::sync::Mutex<HashMap<String, FullJob>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));
static JOB_SEQ: AtomicU64 = AtomicU64::new(1);

/* ------------------------------------------------------------------ *
 * 入口                                                                *
 * ------------------------------------------------------------------ */

pub(crate) fn handle_begin(worker: &Worker, req: &Request) -> Response {
    const OP: &str = "photo_read_job_begin";
    if req.meta_id == 0 {
        return error(OP, "meta_id 不能为空");
    }
    let mode = req.mode.as_str();
    if mode != "preview" && mode != "full" {
        return error(OP, "读取模式非法");
    }

    let mut meta_record = match read_meta(worker, req.meta_id) {
        Ok(meta) => meta,
        Err(e) => return error(OP, &e),
    };
    if let Err(e) = source::resolve_chunk_refs(worker, &mut meta_record) {
        return error(OP, &e);
    }
    let total = match meta_record.chunk_total() {
        Ok(total) => total,
        Err(e) => return error(OP, &e),
    };
    if meta_record.size == 0 || meta_record.size > PB_PHOTO_MAX_BYTES {
        return error(OP, "照片大小超出原生读取范围");
    }

    if mode == "preview" {
        match preview_for_meta(worker, req.meta_id, &mut meta_record) {
            Ok((jpeg_b64, cached, record)) => {
                let mut resp = Response::ok(OP);
                resp.photo_read = Some(MediaReadPayload {
                    status: "preview".to_string(),
                    job_id: Some(req.job_id.clone()),
                    meta_id: Some(req.meta_id),
                    name: Some(meta_record.name.clone()),
                    mime: Some(meta_record.mime.clone()),
                    size: Some(meta_record.size),
                    chunk_index: None,
                    chunk_total: Some(total),
                    data_b64: Some(jpeg_b64),
                    preview_cached: Some(cached),
                });
                resp.photo_record = record;
                resp
            }
            Err(e) => error(OP, &e),
        }
    } else {
        let mut jobs = lock_jobs();
        prune_stale(&mut jobs);
        if jobs.len() >= MAX_READ_JOBS {
            return error(OP, "并发读取 job 已达上限");
        }
        if jobs.contains_key(&req.job_id) {
            return error(OP, "job 已存在");
        }
        let job_id = if req.job_id.is_empty() {
            format!(
                "read-{}-{}",
                req.meta_id,
                JOB_SEQ.fetch_add(1, Ordering::Relaxed)
            )
        } else {
            req.job_id.clone()
        };
        jobs.insert(
            job_id.clone(),
            FullJob {
                job_id: job_id.clone(),
                meta_id: req.meta_id,
                meta: meta_record,
                next_seq: 0,
                total,
                hasher: blake3::Hasher::new(),
                cancelled: false,
                failed: false,
                last_touch: Instant::now(),
            },
        );
        let job = jobs.get(&job_id).expect("刚插入的 job");
        let payload = MediaReadPayload {
            status: "ready".to_string(),
            job_id: Some(job_id),
            meta_id: Some(req.meta_id),
            name: Some(job.meta.name.clone()),
            mime: Some(job.meta.mime.clone()),
            size: Some(job.meta.size),
            chunk_index: None,
            chunk_total: Some(total),
            data_b64: None,
            preview_cached: None,
        };
        let mut resp = Response::ok(OP);
        resp.photo_read = Some(payload);
        resp
    }
}

pub(crate) fn handle_next(worker: &Worker, req: &Request) -> Response {
    const OP: &str = "photo_read_job_next";
    let mut jobs = lock_jobs();
    prune_stale(&mut jobs);
    let Some(job) = jobs.get_mut(&req.job_id) else {
        return error(OP, "job 不存在或已结束");
    };
    job.last_touch = Instant::now();
    if job.cancelled {
        return read_response(OP, finished_payload(&job.job_id, job.meta_id, "cancelled"));
    }
    if job.failed {
        return error(OP, "照片完整性校验失败");
    }
    if job.next_seq >= job.total {
        return read_response(OP, finished_payload(&job.job_id, job.meta_id, "done"));
    }

    let seq = job.next_seq;
    let cipher = match load_chunk_cipher(worker, &mut job.meta, seq) {
        Ok(c) => c,
        Err(e) => return error(OP, &e),
    };
    let (plain, chunk_seq, chunk_total) = match module_keys::open_photo_chunk_any(worker, &cipher) {
        Ok(v) => v,
        Err(e) => return error(OP, &format!("解密照片块失败: {:?}", e)),
    };
    drop(cipher);
    if chunk_seq != seq || chunk_total != job.total {
        job.failed = true;
        return error(OP, "照片块序号与索引声明不一致");
    }
    job.hasher.update(&plain);
    job.next_seq += 1;
    let done = job.next_seq >= job.total;
    let hash_ok = if done {
        job.hasher.finalize().to_hex().to_string() == job.meta.file_hash
    } else {
        true
    };
    if !hash_ok {
        job.failed = true;
        return error(OP, "照片完整性校验失败");
    }

    let mut resp = Response::ok(OP);
    resp.photo_read = Some(MediaReadPayload {
        status: if done { "done" } else { "chunk" }.to_string(),
        job_id: Some(job.job_id.clone()),
        meta_id: Some(job.meta_id),
        name: Some(job.meta.name.clone()),
        mime: Some(job.meta.mime.clone()),
        size: Some(job.meta.size),
        chunk_index: Some(seq),
        chunk_total: Some(job.total),
        data_b64: Some(base64_encode(&plain)),
        preview_cached: None,
    });
    resp
}

/// 删除级联：按 meta ID 返回关联预览记录 ID（找不到则跳过）。
///
/// 预览记录不进入块台账，删除侧必须单独定位；名称规则与读取侧一致
/// （entry_key 优先，历史照片退回 metaId）。单个 meta 读取/解密失败
/// 不阻断整批删除。
pub(crate) fn handle_preview_ids(worker: &Worker, req: &Request) -> Response {
    const OP: &str = "photo_preview_ids";
    let mut out: Vec<u64> = Vec::new();
    for meta_id in &req.ids {
        if *meta_id == 0 {
            continue;
        }
        let Ok(meta) = read_meta(worker, *meta_id) else {
            continue;
        };
        let Ok(name) = preview::record_name(
            if meta.entry_key.is_empty() {
                None
            } else {
                Some(meta.entry_key.as_str())
            },
            *meta_id,
        ) else {
            continue;
        };
        if let Ok((true, lid)) = worker.call_find_lid_by_name(&name) {
            out.push(lid);
        }
    }
    out.sort_unstable();
    out.dedup();
    let mut resp = Response::ok(OP);
    resp.ids = out;
    resp
}

pub(crate) fn handle_cancel(req: &Request) -> Response {
    const OP: &str = "photo_read_job_cancel";
    let mut jobs = lock_jobs();
    if let Some(job) = jobs.get_mut(&req.job_id) {
        job.cancelled = true;
    }
    Response::ok(OP)
}

pub(crate) fn handle_end(req: &Request) -> Response {
    const OP: &str = "photo_read_job_end";
    lock_jobs().remove(&req.job_id);
    Response::ok(OP)
}

/* ------------------------------------------------------------------ *
 * 预览                                                                *
 * ------------------------------------------------------------------ */

fn preview_for_meta(
    worker: &Worker,
    meta_id: u64,
    meta: &mut PhotoMetaIn,
) -> Result<(String, bool, Option<MediaPreviewRecord>), String> {
    let name = preview::record_name(
        if meta.entry_key.is_empty() {
            None
        } else {
            Some(meta.entry_key.as_str())
        },
        meta_id,
    )?;

    if let Some(jpeg) = read_preview_record(worker, &name, &meta.file_hash)? {
        return Ok((base64_encode(&jpeg), true, None));
    }

    let jpeg = generate_preview(worker, meta)?;
    let payload = preview::build_payload(&meta.file_hash, &jpeg)?;
    let sealed = module_keys::seal_photo_preview(worker, &payload)
        .map_err(|e| format!("封装照片预览失败: {:?}", e))?;
    Ok((
        base64_encode(&jpeg),
        false,
        Some(MediaPreviewRecord {
            name,
            data_b64: base64_encode(&sealed),
        }),
    ))
}

fn read_preview_record(
    worker: &Worker,
    name: &str,
    file_hash: &str,
) -> Result<Option<Vec<u8>>, String> {
    let (found, id) = worker
        .call_find_lid_by_name(name)
        .map_err(|rc| format!("查找预览记录失败（0x{:08X}）", rc))?;
    if !found {
        return Ok(None);
    }
    let (rtype, _record_name, data) = match worker.call_get_record(id) {
        Ok(v) => v,
        // 预览记录可能在查找后被并发删除：按缺失处理
        Err(_) => return Ok(None),
    };
    if rtype != 0x0b {
        return Ok(None);
    }
    let plain = match module_keys::open_photo_record(worker, "preview", &data) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    match preview::split_payload(&plain, file_hash) {
        Ok(jpeg) => Ok(Some(jpeg.to_vec())),
        Err(_) => Ok(None),
    }
}

fn generate_preview(worker: &Worker, meta: &mut PhotoMetaIn) -> Result<Vec<u8>, String> {
    source::resolve_chunk_refs(worker, meta)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(meta.size as usize));
    let total = meta.chunk_total()?;
    for seq in 0..total {
        let cipher = load_chunk_cipher(worker, meta, seq)?;
        let (chunk, chunk_seq, chunk_total) = module_keys::open_photo_chunk_any(worker, &cipher)
            .map_err(|e| format!("解密照片块失败: {:?}", e))?;
        if chunk_seq != seq || chunk_total != total {
            return Err("照片块序号与索引声明不一致".to_string());
        }
        plain.extend_from_slice(&chunk);
        if plain.len() as u64 > PB_PHOTO_MAX_BYTES {
            return Err("照片明文字节超出上限".to_string());
        }
    }
    if plain.len() as u64 != meta.size {
        return Err("照片明文字节与索引声明不一致".to_string());
    }
    decoder::generate_preview_from_bytes(&plain, &meta.mime)
}

/* ------------------------------------------------------------------ *
 * 响应与 job 清理                                                     *
 * ------------------------------------------------------------------ */

fn finished_payload(job_id: &str, meta_id: u64, status: &str) -> MediaReadPayload {
    MediaReadPayload {
        status: status.to_string(),
        job_id: Some(job_id.to_string()),
        meta_id: Some(meta_id),
        name: None,
        mime: None,
        size: None,
        chunk_index: None,
        chunk_total: None,
        data_b64: None,
        preview_cached: None,
    }
}

fn read_response(op: &str, payload: MediaReadPayload) -> Response {
    let mut resp = Response::ok(op);
    resp.photo_read = Some(payload);
    resp
}

fn error(op: &str, message: &str) -> Response {
    let mut resp = Response::ok(op);
    resp.ok = false;
    resp.error = Some(message.to_string());
    resp
}

fn prune_stale(jobs: &mut HashMap<String, FullJob>) {
    let now = Instant::now();
    jobs.retain(|_, job| now.saturating_duration_since(job.last_touch) < JOB_IDLE_TTL);
}

fn lock_jobs() -> std::sync::MutexGuard<'static, HashMap<String, FullJob>> {
    JOBS.lock().unwrap_or_else(|poison| poison.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(file_hash: &str, chunk_count: usize) -> PhotoMetaIn {
        PhotoMetaIn {
            name: "a.jpg".to_string(),
            mime: "image/jpeg".to_string(),
            size: 10,
            file_hash: file_hash.to_string(),
            entry_key: "e".repeat(64),
            thumb_b64: String::new(),
            created_at: 1,
            animated: None,
            chunk_ids: vec![1; chunk_count],
            chunk_data_b64: Vec::new(),
            wrapped_file_key: None,
            fmt: None,
            thumb_id: 0,
            chunk_set_id: 0,
            chunk_count: None,
        }
    }

    #[test]
    fn slim_layout_is_detected() {
        let mut m = meta(&"a".repeat(64), 1);
        assert!(!m.slim_layout());
        m.wrapped_file_key = Some("wrapped".into());
        assert!(m.slim_layout());

        let mut m = meta(&"a".repeat(64), 1);
        m.fmt = Some(2);
        assert!(m.slim_layout());
    }

    #[test]
    fn chunk_total_prefers_inline_and_rejects_empty() {
        let mut m = meta(&"a".repeat(64), 0);
        assert!(m.chunk_total().is_err());
        m.chunk_data_b64 = vec!["x".into(), "y".into()];
        assert_eq!(m.chunk_total().unwrap(), 2);
    }

    #[test]
    fn stale_jobs_are_pruned() {
        let mut jobs = HashMap::new();
        jobs.insert(
            "old".to_string(),
            FullJob {
                job_id: "old".into(),
                meta_id: 1,
                meta: meta(&"a".repeat(64), 1),
                next_seq: 0,
                total: 1,
                hasher: blake3::Hasher::new(),
                cancelled: false,
                failed: false,
                last_touch: Instant::now() - JOB_IDLE_TTL - Duration::from_secs(1),
            },
        );
        prune_stale(&mut jobs);
        assert!(jobs.is_empty());
    }
}
