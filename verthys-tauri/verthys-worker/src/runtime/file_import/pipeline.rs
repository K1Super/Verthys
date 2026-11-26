/*
 * file_import/pipeline.rs — 文件推进、键/哈希、meta 与响应装配
 *
 * 单文件生命周期：stat 校验 → 身份快照 → （可选）口令 KDF → 分块推进；
 * 键、哈希与 meta 字段与既有落盘口径逐字节一致，读取侧无需迁移。
 */

use std::fs::File;
use std::path::Path;
use std::time::UNIX_EPOCH;

use sha2::{Digest, Sha256};

use crate::runtime::content_crypto::{PBKDF2_ITER, SALT_LEN};
use crate::runtime::module_keys;
use crate::runtime::path_grants;
use crate::runtime::protocol::{base64_encode, FileNextPayload, Response};
use crate::runtime::worker::Worker;

use super::job::{
    FileCursor, Job, CHUNK_BYTES, FINGERPRINT_ENCRYPTED, FINGERPRINT_PLAIN, HASH_FORMAT_VER,
    MAX_FILE_BYTES, MAX_RECORD_NAME_BYTES, META_SCHEMA,
};

/// 打开下一个文件；Ok(None) 表示 current 已就绪。
pub(super) fn open_next(
    worker: Option<&Worker>,
    job: &mut Job,
) -> Result<Option<FileNextPayload>, String> {
    /* 单次推进：每个分支都返回一个事件，由宿主下一次 next 继续推进；
     * 不存在可重复路径，因此不使用循环。 */
    if job.next_index < job.files.len() {
        let index = job.next_index;
        job.next_index += 1;
        let source = job.files[index].clone();

        if !path_grants::job_contains_for("file_import", &job.job_id, &source.path) {
            return Ok(Some(skipped_payload(
                &job.job_id,
                index,
                &source.name,
                "E_READ_FAILED",
                "路径未授权或授权已过期",
            )));
        }

        let meta = match std::fs::metadata(&source.path) {
            Ok(meta) => meta,
            Err(e) => {
                return Ok(Some(skipped_payload(
                    &job.job_id,
                    index,
                    &source.name,
                    "E_STAT_FAILED",
                    &format!("读取文件属性失败: {}", e),
                )))
            }
        };
        if !meta.is_file() {
            return Ok(Some(skipped_payload(
                &job.job_id,
                index,
                &source.name,
                "E_READ_FAILED",
                "来源不是普通文件",
            )));
        }
        let size = meta.len();
        if size > MAX_FILE_BYTES {
            return Ok(Some(skipped_payload(
                &job.job_id,
                index,
                &source.name,
                "E_FILE_TOO_LARGE",
                "文件超过单文件大小上限",
            )));
        }
        let Some(mtime_ms) = mtime_ms(&meta) else {
            return Ok(Some(skipped_payload(
                &job.job_id,
                index,
                &source.name,
                "E_STAT_FAILED",
                "无法获取文件修改时间",
            )));
        };
        let entry_key = entry_key(&source.path, size, mtime_ms);
        if job.committed.contains(&entry_key) {
            return Ok(Some(deduped_payload(&job.job_id, index, &source.name)));
        }
        if meta_record_name(&source.name).is_err() {
            return Ok(Some(skipped_payload(
                &job.job_id,
                index,
                &source.name,
                "E_META_FAILED",
                "文件名过长，无法生成元数据记录名",
            )));
        }

        let file = match File::open(&source.path) {
            Ok(file) => file,
            Err(e) => {
                return Ok(Some(skipped_payload(
                    &job.job_id,
                    index,
                    &source.name,
                    "E_READ_FAILED",
                    &format!("打开文件失败: {}", e),
                )))
            }
        };

        let encrypted = !job.password.is_empty();
        let mut salt = None;
        let mut key = None;
        let mut password_check_b64 = None;
        if encrypted {
            let new_salt: [u8; SALT_LEN] = match crate::runtime::content_crypto::random_bytes() {
                Ok(v) => v,
                Err(_) => {
                    return Ok(Some(skipped_payload(
                        &job.job_id,
                        index,
                        &source.name,
                        "E_ENCRYPT_FAILED",
                        "随机源不可用",
                    )))
                }
            };
            let derived = match module_keys::derive_file_password_key(
                &job.password,
                &new_salt,
                PBKDF2_ITER,
            ) {
                Ok(key) => key,
                Err(e) => {
                    return Ok(Some(skipped_payload(
                        &job.job_id,
                        index,
                        &source.name,
                        "E_ENCRYPT_FAILED",
                        &format!("文件密钥派生失败: {:?}", e),
                    )))
                }
            };
            let Some(worker) = worker else {
                return Ok(Some(skipped_payload(
                    &job.job_id,
                    index,
                    &source.name,
                    "E_ENCRYPT_FAILED",
                    "加密引擎不可用",
                )));
            };
            let check = match module_keys::seal_file_v2_check(worker, &derived[..], &new_salt) {
                Ok(sealed) => base64_encode(&sealed),
                Err(e) => {
                    return Ok(Some(skipped_payload(
                        &job.job_id,
                        index,
                        &source.name,
                        "E_ENCRYPT_FAILED",
                        &format!("口令校验块生成失败: {:?}", e),
                    )))
                }
            };
            salt = Some(new_salt);
            key = Some(derived);
            password_check_b64 = Some(check);
        }

        let total_chunks = chunk_count(size);
        let cursor = FileCursor {
            file,
            path: source.path,
            name: source.name,
            mime: source.mime,
            size,
            mtime_ms,
            entry_key,
            total_chunks,
            next_chunk: 0,
            bytes_read: 0,
            encrypted,
            salt,
            iterations: if encrypted { PBKDF2_ITER } else { 0 },
            key,
            password_check_b64,
            file_hasher: blake3::Hasher::new(),
            chunk_hashes: Vec::with_capacity(total_chunks as usize),
        };

        if total_chunks == 0 {
            let mut payload = next_payload(&job.job_id, "empty");
            payload.file_index = Some(index as u32);
            payload.file_name = Some(cursor.name.clone());
            payload.mime = Some(cursor.mime.clone());
            payload.size = Some(cursor.size);
            job.current = Some(cursor);
            return Ok(Some(payload));
        }

        job.current = Some(cursor);
        return Ok(None);
    }
    Ok(Some(next_payload(&job.job_id, "done")))
}

/// 来源身份复查：打开句柄与路径两侧都必须与初始快照一致。
pub(super) fn identity_matches(cursor: &FileCursor) -> bool {
    let handle_ok = cursor
        .file
        .metadata()
        .map(|m| m.len() == cursor.size && mtime_ms(&m) == Some(cursor.mtime_ms))
        .unwrap_or(false);
    if !handle_ok {
        return false;
    }
    std::fs::metadata(Path::new(&cursor.path))
        .map(|m| m.len() == cursor.size && mtime_ms(&m) == Some(cursor.mtime_ms))
        .unwrap_or(false)
}

/* ------------------------------------------------------------------ *
 * 键、哈希与元数据                                                     *
 * ------------------------------------------------------------------ */

/// 非内容条目键：路径/长度/修改时间的 SHA-256（与旧前端口径逐字节一致）。
pub(super) fn entry_key(path: &str, size: u64, mtime_ms: u64) -> String {
    sha256_hex(format!("file|{}|{}|{}", path, size, mtime_ms).as_bytes())
}

/// 由条目键与块序号派生非内容块键。
pub(super) fn chunk_key(entry_key: &str, seq: u32) -> String {
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

/// 文件哈希尾缀：格式版本 + 加密形态（与旧前端口径一致）。
pub(super) fn file_hash_suffix(encrypted: bool) -> [u8; 2] {
    [
        HASH_FORMAT_VER,
        if encrypted {
            FINGERPRINT_ENCRYPTED
        } else {
            FINGERPRINT_PLAIN
        },
    ]
}

pub(super) fn chunk_count(size: u64) -> u32 {
    size.div_ceil(CHUNK_BYTES as u64) as u32
}

fn mtime_ms(meta: &std::fs::Metadata) -> Option<u64> {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
}

pub(super) fn meta_record_name(name: &str) -> Result<String, String> {
    let record = format!("meta_{}", name);
    if record.len() <= MAX_RECORD_NAME_BYTES {
        return Ok(record);
    }
    Err("文件名过长，无法生成元数据记录名".to_string())
}

/// meta 载荷：字段名与旧写入形态逐字段兼容，读取侧无需分支迁移。
pub(super) fn build_meta(
    cursor: &FileCursor,
    chunk_ids: &[u64],
    file_hash: &str,
) -> Result<Vec<u8>, String> {
    let mut map = serde_json::Map::new();
    map.insert("schema".into(), serde_json::json!(META_SCHEMA));
    map.insert("name".into(), serde_json::json!(cursor.name.as_str()));
    map.insert("size".into(), serde_json::json!(cursor.size));
    map.insert("mime".into(), serde_json::json!(cursor.mime.as_str()));
    map.insert("chunkIds".into(), serde_json::json!(chunk_ids));
    map.insert("chunkHashes".into(), serde_json::json!(&cursor.chunk_hashes));
    map.insert("chunkSize".into(), serde_json::json!(CHUNK_BYTES));
    map.insert("totalChunks".into(), serde_json::json!(cursor.total_chunks));
    map.insert("encrypted".into(), serde_json::json!(cursor.encrypted));
    map.insert("fileHash".into(), serde_json::json!(file_hash));
    map.insert("entryKey".into(), serde_json::json!(cursor.entry_key.as_str()));
    if cursor.encrypted {
        let (Some(salt), Some(check)) = (cursor.salt.as_ref(), cursor.password_check_b64.as_ref())
        else {
            return Err("加密条目的密钥参数缺失".to_string());
        };
        map.insert(
            "kdf".into(),
            serde_json::json!({
                "version": 2,
                "saltB64": base64_encode(salt),
                "iterations": cursor.iterations,
            }),
        );
        map.insert("passwordCheck".into(), serde_json::json!(check));
    }
    serde_json::to_vec(&serde_json::Value::Object(map))
        .map_err(|e| format!("序列化元数据失败: {}", e))
}

/* ------------------------------------------------------------------ *
 * 响应装配                                                            *
 * ------------------------------------------------------------------ */

pub(super) fn next_payload(job_id: &str, status: &str) -> FileNextPayload {
    FileNextPayload {
        status: status.to_string(),
        job_id: Some(job_id.to_string()),
        file_index: None,
        file_name: None,
        mime: None,
        size: None,
        chunk_index: None,
        chunk_total: None,
        chunk_key: None,
        chunk_hash: None,
        chunk_staged: None,
        file_done: false,
        reason: None,
        error: None,
    }
}

fn skipped_payload(
    job_id: &str,
    index: usize,
    name: &str,
    reason: &str,
    detail: &str,
) -> FileNextPayload {
    let mut payload = next_payload(job_id, "skipped");
    payload.file_index = Some(index as u32);
    payload.file_name = Some(name.to_string());
    payload.reason = Some(reason.to_string());
    payload.error = Some(detail.to_string());
    payload
}

pub(super) fn skipped_response(
    job_id: &str,
    index: usize,
    name: &str,
    reason: &str,
    detail: &str,
) -> Response {
    file_response(
        "file_import_job_next",
        skipped_payload(job_id, index, name, reason, detail),
    )
}

fn deduped_payload(job_id: &str, index: usize, name: &str) -> FileNextPayload {
    let mut payload = next_payload(job_id, "deduped");
    payload.file_index = Some(index as u32);
    payload.file_name = Some(name.to_string());
    payload
}

pub(super) fn file_response(op: &str, payload: FileNextPayload) -> Response {
    let mut resp = Response::ok(op);
    resp.file = Some(payload);
    resp
}

pub(super) fn error(op: &str, message: &str) -> Response {
    let mut resp = Response::ok(op);
    resp.ok = false;
    resp.error = Some(message.to_string());
    resp
}

/// 带结构化原因码的失败：宿主按码归类，不解析错误文本。
pub(super) fn error_with_code(op: &str, message: &str, code: &str) -> Response {
    let mut resp = error(op, message);
    resp.error_code = Some(code.to_string());
    resp
}
