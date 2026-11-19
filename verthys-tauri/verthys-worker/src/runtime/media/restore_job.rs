/*
 * media/restore_job.rs — 原生 VENC 备份还原 job
 *
 * 流式解析 .venc：逐帧认证、逐张校验块数/字节数/整图 BLAKE3，并用当前
 * 模块 MDEK 逐块重封装。宿主负责把块经单写者落库，再调用
 * `photo_restore_photo_finish` 取回已封装的 meta。
 *
 * 容器在预览后被替换必须失败：开始时携带预览扫描得到的 fileHash 列表，
 * 每张清单与列表逐项比对。
 */

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::runtime::budget::PB_PHOTO_CHUNK_SIZE_BYTES;
use crate::runtime::module_keys;
use crate::runtime::path_grants;
use crate::runtime::protocol::{
    base64_encode, MediaFinishPayload, MediaNextPayload, MediaVencPreview, Request, Response,
};
use crate::runtime::worker::Worker;

use super::animated;
use super::mime;
use super::venc::{LightMeta, VencError, VencFrame, VencReader};

const MAX_RESTORE_JOBS: usize = 2;
/// 空闲 job 回收窗口：单次 next 可能解密并重封装大块，阈值与长任务超时对齐。
const JOB_IDLE_TTL: Duration = Duration::from_secs(600);
const CHUNK_BYTES: usize = PB_PHOTO_CHUNK_SIZE_BYTES as usize;
const MIN_TOKEN_LENGTH: usize = 8;

const OP_BEGIN: &str = "photo_restore_job_begin";
const OP_NEXT: &str = "photo_restore_job_next";
const OP_FINISH: &str = "photo_restore_photo_finish";

struct RestorePhoto {
    meta: LightMeta,
    entry_key: String,
    next_chunk: u32,
    chunk_hashes: Vec<String>,
    hasher: blake3::Hasher,
    size: u64,
    /// 候选动图格式保留明文，用于收尾时按字节探测
    blob: Option<Zeroizing<Vec<u8>>>,
}

struct Job {
    reader: VencReader<BufReader<File>>,
    expected_hashes: Vec<String>,
    photo_index: u32,
    current: Option<RestorePhoto>,
    awaiting_finish: bool,
    cancelled: bool,
    finished: bool,
    last_touch: Instant,
}

static JOBS: std::sync::LazyLock<Mutex<HashMap<String, Job>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/* ------------------------------------------------------------------ *
 * 入口                                                                *
 * ------------------------------------------------------------------ */

pub(crate) fn handle_begin(req: &Request) -> Response {
    let job_id = req.job_id.trim();
    if job_id.is_empty() {
        return error(OP_BEGIN, "job_id 不能为空");
    }
    if req.path.is_empty() {
        return error(OP_BEGIN, "备份路径为空");
    }
    if !path_grants::job_contains_for("photo_restore", job_id, &req.path) {
        return error(OP_BEGIN, "路径未授权或授权已过期");
    }
    let token = req.token.trim();
    if token.len() < MIN_TOKEN_LENGTH {
        return error(OP_BEGIN, "令牌格式不正确");
    }
    for hash in &req.expected_hashes {
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return error(OP_BEGIN, "预览清单哈希非法");
        }
    }
    let file = match File::open(&req.path) {
        Ok(f) => f,
        Err(_) => return error(OP_BEGIN, "无法打开备份文件"),
    };
    let total_bytes = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return error(OP_BEGIN, "无法读取备份文件属性"),
    };
    let reader = match VencReader::open(BufReader::new(file), total_bytes, token) {
        Ok(r) => r,
        Err(e) => return error(OP_BEGIN, &venc_message(e)),
    };

    let mut jobs = lock_jobs();
    prune_stale(&mut jobs);
    if jobs.len() >= MAX_RESTORE_JOBS {
        return error(OP_BEGIN, "并发还原 job 已达上限");
    }
    if jobs.contains_key(job_id) {
        return error(OP_BEGIN, "job 已存在");
    }
    jobs.insert(
        job_id.to_string(),
        Job {
            reader,
            expected_hashes: req.expected_hashes.clone(),
            photo_index: 0,
            current: None,
            awaiting_finish: false,
            cancelled: false,
            finished: false,
            last_touch: Instant::now(),
        },
    );
    Response::ok(OP_BEGIN)
}

/// 预览扫描：只读清单帧，不产生导入状态。
///
/// 桌面端解析 .venc 不再把整包读入 JS；本入口流式认证每一帧，返回清单
/// 字段供用户确认。块帧只解密不保留，尾部计数照常交叉校验。
pub(crate) fn handle_inspect(req: &Request) -> Response {
    const OP: &str = "photo_venc_inspect";
    const MAX_PREVIEWS: usize = 10_000;
    /// 缩略图预算：超过后仅返回清单字段（缩略图为空），避免撑爆响应行。
    const MAX_THUMB_BYTES: usize = 16 * 1024 * 1024;

    if req.job_id.trim().is_empty() || req.path.is_empty() {
        return error(OP, "预览任务参数不完整");
    }
    if !path_grants::job_contains_for("photo_parse", req.job_id.trim(), &req.path) {
        return error(OP, "路径未授权或授权已过期");
    }
    let token = req.token.trim();
    if token.len() < MIN_TOKEN_LENGTH {
        return error(OP, "令牌格式不正确");
    }
    let file = match File::open(&req.path) {
        Ok(f) => f,
        Err(_) => return error(OP, "无法打开备份文件"),
    };
    let total_bytes = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return error(OP, "无法读取备份文件属性"),
    };
    let mut reader = match VencReader::open(BufReader::new(file), total_bytes, token) {
        Ok(r) => r,
        Err(e) => return error(OP, &venc_message(e)),
    };

    let mut previews: Vec<MediaVencPreview> = Vec::new();
    let mut thumb_bytes = 0usize;
    loop {
        let frame = match reader.next_frame() {
            Ok(frame) => frame,
            Err(e) => return error(OP, &venc_message(e)),
        };
        match frame {
            Some(VencFrame::Manifest(meta)) => {
                if previews.len() >= MAX_PREVIEWS {
                    return error(OP, "备份预览数量超出上限");
                }
                let next_thumb = thumb_bytes.saturating_add(meta.thumb_b64.len());
                let thumb_b64 = if next_thumb > MAX_THUMB_BYTES {
                    String::new()
                } else {
                    thumb_bytes = next_thumb;
                    meta.thumb_b64
                };
                previews.push(MediaVencPreview {
                    name: meta.name,
                    mime: meta.mime,
                    size: meta.size,
                    file_hash: meta.file_hash,
                    thumb_b64,
                    chunk_count: meta.chunk_count,
                    created_at: meta.created_at,
                });
            }
            Some(VencFrame::Chunk(_)) => {}
            Some(VencFrame::Trailer {
                frame_count,
                body_bytes,
            }) => {
                if reader.verify_trailer(frame_count, body_bytes).is_err() {
                    return error(OP, &venc_message(VencError::Corrupt));
                }
                // 尾部帧必须是最后一帧：任何尾随字节都视为结构损坏
                match reader.next_frame() {
                    Ok(None) => {}
                    Ok(Some(_)) => return error(OP, &venc_message(VencError::Corrupt)),
                    Err(e) => return error(OP, &venc_message(e)),
                }
                if previews.is_empty() {
                    return error(OP, "容器内无照片");
                }
                let mut resp = Response::ok(OP);
                resp.photo_previews = Some(previews);
                return resp;
            }
            None => return error(OP, "缺少尾部校验帧"),
        }
    }
}

pub(crate) fn handle_next(worker: &Worker, req: &Request) -> Response {
    let mut jobs = lock_jobs();
    prune_stale(&mut jobs);
    let Some(job) = jobs.get_mut(&req.job_id) else {
        return error(OP_NEXT, "job 不存在或已结束");
    };
    job.last_touch = Instant::now();

    if job.cancelled {
        return photo_response(OP_NEXT, next_payload("cancelled"));
    }
    if job.finished {
        return photo_response(OP_NEXT, next_payload("done"));
    }
    if job.awaiting_finish {
        return error(OP_NEXT, "上一张照片尚未收尾");
    }

    if job.current.is_some() {
        return read_chunk(worker, job);
    }

    let frame = match job.reader.next_frame() {
        Ok(frame) => frame,
        Err(e) => return error(OP_NEXT, &venc_message(e)),
    };
    match frame {
        Some(VencFrame::Manifest(meta)) => {
            if let Some(expected) = job.expected_hashes.get(job.photo_index as usize) {
                if meta.file_hash != *expected {
                    return error(OP_NEXT, "备份文件在预览后已变更，请重新选择文件");
                }
            } else if !job.expected_hashes.is_empty() {
                return error(OP_NEXT, "容器照片数量与预览结果不一致");
            }
            let entry_key = parsed_entry_key(&meta.file_hash);
            let blob = if mime::is_animated_candidate(&meta.mime) {
                Some(Zeroizing::new(Vec::new()))
            } else {
                None
            };
            let photo = RestorePhoto {
                entry_key,
                next_chunk: 0,
                chunk_hashes: Vec::with_capacity(meta.chunk_count as usize),
                hasher: blake3::Hasher::new(),
                size: 0,
                blob,
                meta,
            };
            let mut payload = next_payload("photo");
            payload.file_index = Some(job.photo_index);
            payload.file_name = Some(photo.meta.name.clone());
            payload.mime = Some(photo.meta.mime.clone());
            payload.size = Some(photo.meta.size);
            payload.file_hash = Some(photo.meta.file_hash.clone());
            payload.entry_key = Some(photo.entry_key.clone());
            payload.chunk_total = Some(photo.meta.chunk_count);
            payload.thumb_b64 = Some(photo.meta.thumb_b64.clone());
            payload.created_at = Some(photo.meta.created_at);
            job.current = Some(photo);
            job.photo_index += 1;
            photo_response(OP_NEXT, payload)
        }
        Some(VencFrame::Chunk(_)) => error(OP_NEXT, "块帧先于清单帧出现"),
        Some(VencFrame::Trailer {
            frame_count,
            body_bytes,
        }) => {
            if job.reader.verify_trailer(frame_count, body_bytes).is_err() {
                return error(OP_NEXT, &venc_message(VencError::Corrupt));
            }
            // 尾部帧后不得再有字节（与解析器/前端容器契约一致）
            match job.reader.next_frame() {
                Ok(None) => {}
                Ok(Some(_)) => return error(OP_NEXT, &venc_message(VencError::Corrupt)),
                Err(e) => return error(OP_NEXT, &venc_message(e)),
            }
            if !job.expected_hashes.is_empty()
                && job.photo_index as usize != job.expected_hashes.len()
            {
                return error(OP_NEXT, "容器照片数量与预览结果不一致");
            }
            if job.photo_index == 0 {
                return error(OP_NEXT, "容器内无照片");
            }
            job.finished = true;
            photo_response(OP_NEXT, next_payload("done"))
        }
        None => error(OP_NEXT, "缺少尾部校验帧"),
    }
}

fn read_chunk(worker: &Worker, job: &mut Job) -> Response {
    let mut photo = job.current.take().expect("current 已确认存在");
    let frame = match job.reader.next_frame() {
        Ok(frame) => frame,
        Err(e) => return error(OP_NEXT, &venc_message(e)),
    };
    let Some(VencFrame::Chunk(plain)) = frame else {
        return error(OP_NEXT, "照片块数少于清单声明");
    };
    if plain.is_empty() || plain.len() > CHUNK_BYTES {
        return error(OP_NEXT, "照片块长度非法");
    }
    let seq = photo.next_chunk;
    if seq >= photo.meta.chunk_count {
        return error(OP_NEXT, "照片块数超过清单声明");
    }
    let sealed = match module_keys::seal_photo_chunk(
        worker,
        &photo.meta.file_hash,
        seq,
        photo.meta.chunk_count,
        &plain,
    ) {
        Ok(v) => v,
        Err(e) => return error(OP_NEXT, &format!("加密照片块失败: {:?}", e)),
    };
    let chunk_hash = blake3::hash(&sealed).to_hex().to_string();
    photo.hasher.update(&plain);
    photo.size = photo.size.saturating_add(plain.len() as u64);
    if photo.size > photo.meta.size {
        return error(OP_NEXT, "照片明文字节超过清单声明");
    }
    if let Some(blob) = photo.blob.as_mut() {
        blob.extend_from_slice(&plain);
    }
    photo.chunk_hashes.push(chunk_hash.clone());
    photo.next_chunk += 1;

    let mut payload = next_payload("chunk");
    payload.file_index = Some(job.photo_index.saturating_sub(1));
    payload.file_name = Some(photo.meta.name.clone());
    payload.chunk_index = Some(seq);
    payload.chunk_total = Some(photo.meta.chunk_count);
    payload.chunk_key = Some(chunk_key(&photo.entry_key, seq));
    payload.chunk_b64 = Some(base64_encode(&sealed));
    payload.chunk_hash = Some(chunk_hash);

    if photo.next_chunk >= photo.meta.chunk_count {
        job.awaiting_finish = true;
    }
    job.current = Some(photo);
    photo_response(OP_NEXT, payload)
}

/* ------------------------------------------------------------------ *
 * 单张收尾                                                            *
 * ------------------------------------------------------------------ */

pub(crate) fn handle_finish(worker: &Worker, req: &Request) -> Response {
    let mut jobs = lock_jobs();
    let Some(job) = jobs.get_mut(&req.job_id) else {
        return error(OP_FINISH, "job 不存在或已结束");
    };
    if !job.awaiting_finish {
        return error(OP_FINISH, "当前没有待收尾的照片");
    }
    let Some(photo) = job.current.take() else {
        return error(OP_FINISH, "当前没有待收尾的照片");
    };
    if photo.next_chunk != photo.meta.chunk_count {
        return error(OP_FINISH, "照片块数不完整");
    }
    if photo.size != photo.meta.size {
        return error(OP_FINISH, "照片字节数与清单声明不一致");
    }
    let digest = photo.hasher.finalize().to_hex().to_string();
    if digest != photo.meta.file_hash {
        return error(OP_FINISH, "照片完整性校验失败");
    }

    if req.skip_photo {
        job.awaiting_finish = false;
        return finish_response(MediaFinishPayload {
            meta_b64: String::new(),
            record_name: String::new(),
            preview_b64: None,
            preview_record_name: None,
            animated: None,
        });
    }

    if req.chunk_ids.len() != photo.meta.chunk_count as usize {
        return error(OP_FINISH, "块记录数与该照片块数不一致");
    }
    if req.chunk_ids.iter().any(|id| *id == 0) {
        return error(OP_FINISH, "存在未分配的块记录 ID");
    }

    let animated = photo
        .blob
        .as_deref()
        .and_then(|bytes| animated::detect_bytes(bytes, &photo.meta.mime).ok().flatten());

    let meta = RestoreMetaOut {
        name: &photo.meta.name,
        mime: &photo.meta.mime,
        size: photo.meta.size,
        thumb_b64: &photo.meta.thumb_b64,
        chunk_ids: &req.chunk_ids,
        chunk_data_b64: Vec::new(),
        chunk_hashes: &photo.chunk_hashes,
        file_hash: &photo.meta.file_hash,
        entry_key: &photo.entry_key,
        created_at: photo.meta.created_at,
        animated,
    };
    let meta_json = match serde_json::to_vec(&meta) {
        Ok(v) => Zeroizing::new(v),
        Err(e) => return error(OP_FINISH, &format!("序列化照片索引失败: {}", e)),
    };
    let sealed = match module_keys::seal_photo_meta(worker, &meta_json) {
        Ok(v) => v,
        Err(e) => return error(OP_FINISH, &format!("加密照片索引失败: {:?}", e)),
    };

    job.awaiting_finish = false;
    finish_response(MediaFinishPayload {
        meta_b64: base64_encode(&sealed),
        record_name: String::new(),
        preview_b64: None,
        preview_record_name: None,
        animated,
    })
}

pub(crate) fn handle_cancel(req: &Request) -> Response {
    let mut jobs = lock_jobs();
    if let Some(job) = jobs.get_mut(&req.job_id) {
        job.cancelled = true;
        job.current = None;
    }
    Response::ok("photo_restore_job_cancel")
}

pub(crate) fn handle_end(req: &Request) -> Response {
    lock_jobs().remove(&req.job_id);
    path_grants::revoke_job(&req.job_id);
    Response::ok("photo_restore_job_end")
}

/* ------------------------------------------------------------------ *
 * 键与响应                                                            *
 * ------------------------------------------------------------------ */

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RestoreMetaOut<'a> {
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

fn parsed_entry_key(file_hash: &str) -> String {
    sha256_hex(format!("parsed|{}", file_hash).as_bytes())
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

fn next_payload(status: &str) -> MediaNextPayload {
    MediaNextPayload {
        status: status.to_string(),
        job_id: None,
        file_index: None,
        file_name: None,
        mime: None,
        size: None,
        file_hash: None,
        entry_key: None,
        chunk_index: None,
        chunk_total: None,
        chunk_key: None,
        chunk_b64: None,
        chunk_hash: None,
        file_done: false,
        thumb_b64: None,
        animated: None,
        created_at: None,
        error: None,
    }
}

fn photo_response(op: &str, payload: MediaNextPayload) -> Response {
    let mut resp = Response::ok(op);
    resp.photo = Some(payload);
    resp
}

fn finish_response(payload: MediaFinishPayload) -> Response {
    let mut resp = Response::ok(OP_FINISH);
    resp.photo_finish = Some(payload);
    resp
}

fn error(op: &str, message: &str) -> Response {
    let mut resp = Response::ok(op);
    resp.ok = false;
    resp.error = Some(message.to_string());
    resp
}

fn venc_message(err: VencError) -> String {
    match err {
        VencError::Auth => "TAG_VERIFICATION_FAILED: 令牌错误或文件被篡改".to_string(),
        VencError::Unsupported => {
            "UNSUPPORTED_VERSION: 备份格式版本或加密参数不受支持".to_string()
        }
        VencError::TooLarge => "容器超过解析上限".to_string(),
        VencError::Corrupt => "备份文件结构损坏".to_string(),
        VencError::Invalid | VencError::Internal => "备份解析失败".to_string(),
    }
}

fn prune_stale(jobs: &mut HashMap<String, Job>) {
    let now = Instant::now();
    jobs.retain(|_, job| now.saturating_duration_since(job.last_touch) < JOB_IDLE_TTL);
}

fn lock_jobs() -> std::sync::MutexGuard<'static, HashMap<String, Job>> {
    JOBS.lock().unwrap_or_else(|poison| poison.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_and_chunk_keys_match_frontend_derivation() {
        let hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        let entry = parsed_entry_key(hash);
        let expected = sha256_hex(format!("parsed|{}", hash).as_bytes());
        assert_eq!(entry, expected);
        assert_eq!(entry.len(), 64);
        assert_eq!(chunk_key(&entry, 3), sha256_hex(format!("chunk|{}|3", entry).as_bytes()));
    }

    #[test]
    fn venc_messages_keep_frontend_classification_tokens() {
        assert!(venc_message(VencError::Auth).starts_with("TAG_VERIFICATION_FAILED"));
        assert!(venc_message(VencError::Unsupported).starts_with("UNSUPPORTED_VERSION"));
        assert!(!venc_message(VencError::Corrupt).contains("TAG_VERIFICATION_FAILED"));
    }
}
