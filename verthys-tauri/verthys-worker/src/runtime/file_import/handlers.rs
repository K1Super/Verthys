/*
 * file_import/handlers.rs — 五个 job 命令与 job 推进/收尾
 *
 * 命令只做参数校验与 job 状态推进；文件读取、加密与 meta 装配委托给
 * pipeline，状态存取经 job 的 JOBS 锁。
 */

use std::io::Read;
use std::time::Instant;

use zeroize::Zeroizing;

use crate::runtime::media::staged;
use crate::runtime::module_keys;
use crate::runtime::path_grants;
use crate::runtime::protocol::{
    base64_encode, FileFinishPayload, FileNextPayload, Request, Response,
};
use crate::runtime::worker::Worker;

use super::job::{lock_jobs, prune_stale, Job, CHUNK_BYTES, MAX_JOB_FILES, MAX_OPEN_JOBS};
use super::pipeline::{
    build_meta, chunk_key, error, error_with_code, file_hash_suffix, file_response,
    identity_matches, meta_record_name, next_payload, open_next, skipped_response,
};

pub(crate) fn handle_begin(req: &Request) -> Response {
    const OP: &str = "file_import_job_begin";
    let job_id = req.job_id.trim();
    if job_id.is_empty() {
        return error(OP, "job_id 不能为空");
    }
    if req.files.is_empty() {
        return error(OP, "文件列表为空");
    }
    if req.files.len() > MAX_JOB_FILES {
        return error(OP, "文件数量超过单 job 上限");
    }
    for source in &req.files {
        if source.path.is_empty() || source.path.contains('\0') {
            return error(OP, "文件路径非法");
        }
        if source.name.is_empty() || source.name.contains('\0') {
            return error(OP, "文件名非法");
        }
        /* MIME 只用于展示与 meta 字段，限制长度避免畸形输入撑大 meta 载荷。 */
        if source.mime.len() > 256 || source.mime.contains('\0') {
            return error(OP, "MIME 类型非法");
        }
        if !path_grants::job_contains_for("file_import", job_id, &source.path) {
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
            files: req.files.clone(),
            committed: req.committed_entry_keys.iter().cloned().collect(),
            next_index: 0,
            current: None,
            password: req.password.clone(),
            cancelled: false,
            last_touch: Instant::now(),
        },
    );
    Response::ok(OP)
}

const NEXT_OP: &str = "file_import_job_next";

pub(crate) fn handle_next(worker: &Worker, req: &Request) -> Response {
    let mut jobs = lock_jobs();
    prune_stale(&mut jobs);
    let Some(job) = jobs.get_mut(&req.job_id) else {
        return error(NEXT_OP, "job 不存在或已结束");
    };
    next_locked(Some(worker), job)
}

/// 推进一个已定位的 job；加密路径必须携带 worker，明文路径不依赖 FFI。
pub(super) fn next_locked(worker: Option<&Worker>, job: &mut Job) -> Response {
    job.last_touch = Instant::now();
    if job.cancelled {
        return file_response(NEXT_OP, next_payload(&job.job_id, "cancelled"));
    }

    if job.current.is_none() {
        /* 新文件开始：上一文件已收尾/放弃，残留暂存与幂等映射必须释放。 */
        staged::clear(&job.job_id);
        match open_next(worker, job) {
            Ok(None) => {}
            Ok(Some(payload)) => return file_response(NEXT_OP, payload),
            Err(e) => return error(NEXT_OP, &e),
        }
    }

    let Some(mut cursor) = job.current.take() else {
        return file_response(NEXT_OP, next_payload(&job.job_id, "done"));
    };
    let seq = cursor.next_chunk;
    if seq >= cursor.total_chunks {
        return error(NEXT_OP, "当前文件分块状态异常");
    }
    let start = seq as u64 * CHUNK_BYTES as u64;
    let remaining = cursor.size.saturating_sub(start);
    let len = remaining.min(CHUNK_BYTES as u64) as usize;
    if len == 0 {
        return error(NEXT_OP, "当前文件分块为空");
    }

    let mut plain = Zeroizing::new(vec![0u8; len]);
    if let Err(e) = cursor.file.read_exact(&mut plain[..]) {
        return skipped_response(
            &job.job_id,
            job.next_index.saturating_sub(1),
            &cursor.name,
            "E_READ_FAILED",
            &format!("读取文件块失败: {}", e),
        );
    }
    cursor.bytes_read = cursor.bytes_read.saturating_add(len as u64);
    cursor.file_hasher.update(&plain[..]);

    let stored: Zeroizing<Vec<u8>> = if cursor.encrypted {
        let (Some(key), Some(salt)) = (cursor.key.as_ref(), cursor.salt.as_ref()) else {
            return error(NEXT_OP, "文件密钥状态异常");
        };
        let Some(worker) = worker else {
            return error(NEXT_OP, "加密引擎不可用");
        };
        match module_keys::seal_file_v2_chunk(worker, &key[..], salt, &plain[..]) {
            Ok(sealed) => Zeroizing::new(sealed),
            Err(e) => {
                return skipped_response(
                    &job.job_id,
                    job.next_index.saturating_sub(1),
                    &cursor.name,
                    "E_ENCRYPT_FAILED",
                    &format!("加密文件块失败: {:?}", e),
                )
            }
        }
    } else {
        plain
    };

    let chunk_hash = blake3::hash(&stored[..]).to_hex().to_string();
    let chunk_key = chunk_key(&cursor.entry_key, seq);
    if let Err(e) = staged::stage(
        &job.job_id,
        &chunk_key,
        chunk_hash.clone(),
        stored,
    ) {
        staged::clear(&job.job_id);
        return error(NEXT_OP, &e);
    }
    cursor.chunk_hashes.push(chunk_hash.clone());
    cursor.next_chunk += 1;

    let file_done = cursor.next_chunk >= cursor.total_chunks;
    let payload = FileNextPayload {
        status: "chunk".to_string(),
        job_id: Some(job.job_id.clone()),
        file_index: Some(job.next_index.saturating_sub(1) as u32),
        file_name: Some(cursor.name.clone()),
        mime: Some(cursor.mime.clone()),
        size: Some(cursor.size),
        chunk_index: Some(seq),
        chunk_total: Some(cursor.total_chunks),
        chunk_key: Some(chunk_key),
        chunk_hash: Some(chunk_hash),
        chunk_staged: Some(true),
        file_done,
        reason: None,
        error: None,
    };
    job.current = Some(cursor);
    file_response(NEXT_OP, payload)
}

pub(crate) fn handle_finish(req: &Request) -> Response {
    const OP: &str = "file_import_job_finish";
    let mut jobs = lock_jobs();
    let Some(job) = jobs.get_mut(&req.job_id) else {
        return error(OP, "job 不存在或已结束");
    };
    job.last_touch = Instant::now();
    finish_locked(job, &req.chunk_ids)
}

/// 收尾一个已定位的 job；块 ID 由宿主按块序回填。
pub(super) fn finish_locked(job: &mut Job, chunk_ids: &[u64]) -> Response {
    const OP: &str = "file_import_job_finish";
    let Some(mut cursor) = job.current.take() else {
        return error(OP, "没有待收尾的文件");
    };
    if chunk_ids.len() != cursor.total_chunks as usize {
        return error_with_code(OP, "块记录数与该文件块数不一致", "E_META_FAILED");
    }
    if chunk_ids.contains(&0) {
        return error_with_code(OP, "存在未分配的块记录 ID", "E_CHUNK_FAILED");
    }
    if cursor.bytes_read != cursor.size {
        return error_with_code(OP, "已读字节数与文件长度不符，已拒绝收尾", "E_FILE_CHANGED");
    }
    if !identity_matches(&cursor) {
        return error_with_code(
            OP,
            "源文件在导入过程中发生变化，已拒绝收尾",
            "E_FILE_CHANGED",
        );
    }

    let mut hasher = std::mem::replace(&mut cursor.file_hasher, blake3::Hasher::new());
    hasher.update(&file_hash_suffix(cursor.encrypted));
    let file_hash = hasher.finalize().to_hex().to_string();

    /* 收尾成功：本文件的暂存与幂等映射不再需要，立即释放内存。 */
    staged::clear(&job.job_id);

    let meta_json = match build_meta(&cursor, chunk_ids, &file_hash) {
        Ok(v) => Zeroizing::new(v),
        Err(e) => return error_with_code(OP, &e, "E_META_FAILED"),
    };
    let record_name = match meta_record_name(&cursor.name) {
        Ok(name) => name,
        Err(e) => return error_with_code(OP, &e, "E_META_FAILED"),
    };

    let mut resp = Response::ok(OP);
    resp.file_finish = Some(FileFinishPayload {
        meta_b64: base64_encode(&meta_json),
        record_name,
        file_hash,
        entry_key: cursor.entry_key.clone(),
        size: cursor.size,
        total_chunks: cursor.total_chunks,
        encrypted: cursor.encrypted,
        chunk_hashes: cursor.chunk_hashes.clone(),
        salt_b64: cursor.salt.as_ref().map(|s| base64_encode(s)),
        iterations: cursor.salt.as_ref().map(|_| cursor.iterations),
        password_check: cursor.password_check_b64.clone(),
    });
    resp
}

pub(crate) fn handle_cancel(req: &Request) -> Response {
    const OP: &str = "file_import_job_cancel";
    let mut jobs = lock_jobs();
    if let Some(job) = jobs.get_mut(&req.job_id) {
        job.cancelled = true;
        job.current = None;
        staged::clear(&req.job_id);
    }
    Response::ok(OP)
}

pub(crate) fn handle_end(req: &Request) -> Response {
    const OP: &str = "file_import_job_end";
    {
        let mut jobs = lock_jobs();
        jobs.remove(&req.job_id);
    }
    staged::clear(&req.job_id);
    path_grants::revoke_job(&req.job_id);
    Response::ok(OP)
}
