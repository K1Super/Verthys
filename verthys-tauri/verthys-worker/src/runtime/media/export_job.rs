/*
 * media/export_job.rs — 原生照片导出 job
 *
 * worker 只产出字节，不打开用户目标文件：宿主按事件流把 segment 追加到
 * 暂存文件，失败即 abort，保证目标文件任何时刻都是完整的旧版或新版。
 *
 * 数据来源：meta + 块引用（source.rs）。每张照片先完成整图 BLAKE3 与
 * 字节数校验，再产出任何帧；校验失败按张跳过（venc-single 不含该张），
 * 不会把损坏内容写进容器。
 */

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::runtime::budget::{PB_PHOTO_CHUNK_SIZE_BYTES, PB_PHOTO_MAX_BYTES};
use crate::runtime::protocol::{base64_encode, MediaExportPayload, Request, Response};
use crate::runtime::worker::Worker;

use super::animated;
use super::decoder;
use super::source::{self, load_plain_chunks, read_meta, verify_plain, PhotoMetaIn};
use super::venc::{LightMeta, VencError, VencWriter};

/// 并发导出 job 上限：导出与导入共享宿主槽位，worker 侧留少量余量。
const MAX_EXPORT_JOBS: usize = 2;
/// 空闲 job 回收窗口：单次 next 可能解码 100MiB PNG，阈值与长任务超时对齐。
const JOB_IDLE_TTL: Duration = Duration::from_secs(600);
/// 单条响应承载的原始字节上限（base64 后约 5.59MB）。
const SEGMENT_BYTES: usize = PB_PHOTO_CHUNK_SIZE_BYTES as usize;
/// 单次导出最多照片数。
const MAX_EXPORT_IDS: usize = 10_000;
/// 令牌最小长度（与前端 MIN_TOKEN_LENGTH 一致）。
const MIN_TOKEN_LENGTH: usize = 8;

const OP_BEGIN: &str = "photo_export_job_begin";
const OP_NEXT: &str = "photo_export_job_next";

/* ------------------------------------------------------------------ *
 * 格式                                                                *
 * ------------------------------------------------------------------ */

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Original,
    VencSingle,
    VencMultiple,
    Png,
}

impl Format {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "original" => Some(Self::Original),
            "venc-single" => Some(Self::VencSingle),
            "venc-multiple" => Some(Self::VencMultiple),
            "png" => Some(Self::Png),
            _ => None,
        }
    }

    fn needs_token(self) -> bool {
        matches!(self, Self::VencSingle | Self::VencMultiple)
    }
}

/* ------------------------------------------------------------------ *
 * job 状态                                                            *
 * ------------------------------------------------------------------ */

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    /// venc-single：容器前缀（头 + 包裹密钥）
    SinglePrefix,
    /// venc-single：当前照片的帧段（文件已在容器开始处打开）
    SinglePhotoFrames,
    /// venc-single：尾部帧；段写完后结束文件
    SingleTrailer,
    /// 每张照片一个独立文件（original / venc-multiple / png）
    StandaloneFile,
}

struct Pending {
    kind: PendingKind,
    file_index: u32,
    name: String,
    mime: String,
    size: u64,
    segments: Vec<Zeroizing<Vec<u8>>>,
    next: usize,
}

struct PhotoOutcome {
    index: u32,
    name: String,
    status: &'static str,
    reason: Option<&'static str>,
}

struct Job {
    ids: Vec<u64>,
    format: Format,
    token: Zeroizing<String>,
    index: usize,
    preflight_done: bool,
    /// 预检失败的照片（下标 → 展示名与原因）
    pre_failures: HashMap<usize, (String, &'static str)>,
    container: Option<VencWriter>,
    single_started: bool,
    single_any_ok: bool,
    pending: Option<Pending>,
    ready_photo: Option<PhotoOutcome>,
    finished: bool,
    cancelled: bool,
    /// venc-single 打包中途失败：容器已写入部分帧，后续不得继续追加，
    /// 否则尾帧计数与实际帧不一致。失败后整个 job 终止。
    fatal: Option<String>,
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
    let Some(format) = Format::parse(req.format.as_str()) else {
        return error(OP_BEGIN, "导出格式非法");
    };
    if req.ids.is_empty() {
        return error(OP_BEGIN, "照片列表为空");
    }
    if req.ids.len() > MAX_EXPORT_IDS {
        return error(OP_BEGIN, "照片数量超过单次导出上限");
    }
    if req.ids.iter().any(|id| *id == 0) {
        return error(OP_BEGIN, "照片 ID 非法");
    }
    let token = Zeroizing::new(req.token.trim().to_string());
    if format.needs_token() {
        if token.len() < MIN_TOKEN_LENGTH {
            return error(OP_BEGIN, "加密令牌过短");
        }
    }

    let mut jobs = lock_jobs();
    if jobs.len() >= MAX_EXPORT_JOBS {
        return error(OP_BEGIN, "并发导出 job 已达上限");
    }
    if jobs.contains_key(job_id) {
        return error(OP_BEGIN, "job 已存在");
    }
    jobs.insert(
        job_id.to_string(),
        Job {
            ids: req.ids.clone(),
            format,
            token,
            index: 0,
            preflight_done: false,
            pre_failures: HashMap::new(),
            container: None,
            single_started: false,
            single_any_ok: false,
            pending: None,
            ready_photo: None,
            finished: false,
            cancelled: false,
            fatal: None,
            last_touch: Instant::now(),
        },
    );
    Response::ok(OP_BEGIN)
}

pub(crate) fn handle_next(worker: &Worker, req: &Request) -> Response {
    let mut jobs = lock_jobs();
    prune_stale(&mut jobs);
    let Some(job) = jobs.get_mut(&req.job_id) else {
        return error(OP_NEXT, "job 不存在或已结束");
    };
    job.last_touch = Instant::now();

    loop {
        if job.cancelled {
            return event(OP_NEXT, simple("cancelled"));
        }
        if let Some(message) = job.fatal.as_deref() {
            return error(OP_NEXT, message);
        }
        if job.finished {
            return event(OP_NEXT, simple("done"));
        }
        if let Some(outcome) = job.ready_photo.take() {
            return event(OP_NEXT, photo_event(&outcome));
        }

        // ===== 预检：任何输出之前确认全部照片的块引用可解析 =====
        if !job.preflight_done {
            preflight(worker, job);
            job.preflight_done = true;
            continue;
        }

        // ===== 当前段输出 =====
        if let Some(pending) = job.pending.as_ref() {
            if pending.next < pending.segments.len() {
                let index = pending.next;
                let file_index = pending.file_index;
                let data = pending.segments[index].clone();
                if let Some(p) = job.pending.as_mut() {
                    p.next += 1;
                }
                let mut payload = simple("segment");
                payload.file_index = Some(file_index);
                payload.data_b64 = Some(base64_encode(&data));
                return event(OP_NEXT, payload);
            }
            let pending = job.pending.take().expect("pending 刚被确认存在");
            match pending.kind {
                PendingKind::SinglePrefix => {
                    continue;
                }
                PendingKind::StandaloneFile => {
                    let mut payload = simple("file_end");
                    payload.file_index = Some(pending.file_index);
                    payload.file_ok = Some(true);
                    job.ready_photo = Some(PhotoOutcome {
                        index: pending.file_index,
                        name: pending.name,
                        status: "ok",
                        reason: None,
                    });
                    return event(OP_NEXT, payload);
                }
                PendingKind::SinglePhotoFrames => {
                    job.single_any_ok = true;
                    return event(
                        OP_NEXT,
                        photo_event(&PhotoOutcome {
                            index: pending.file_index,
                            name: pending.name,
                            status: "ok",
                            reason: None,
                        }),
                    );
                }
                PendingKind::SingleTrailer => {
                    let mut payload = simple("file_end");
                    payload.file_index = Some(0);
                    payload.file_ok = Some(true);
                    job.finished = true;
                    return event(OP_NEXT, payload);
                }
            }
        }

        // ===== venc-single：容器开始 =====
        if job.format == Format::VencSingle && !job.single_started {
            match VencWriter::new(&job.token) {
                Ok((writer, prefix)) => {
                    job.container = Some(writer);
                    job.single_started = true;
                    let mut payload = simple("file_begin");
                    payload.file_index = Some(0);
                    payload.file_name = Some("verthys.venc".to_string());
                    payload.mime = Some("application/octet-stream".to_string());
                    payload.size = Some(0);
                    // 前缀作为首批段输出（下一轮 next 先于照片帧返回）
                    job.pending = Some(Pending {
                        kind: PendingKind::SinglePrefix,
                        file_index: 0,
                        name: String::new(),
                        mime: String::new(),
                        size: 0,
                        segments: into_segments(&prefix),
                        next: 0,
                    });
                    return event(OP_NEXT, payload);
                }
                Err(e) => return venc_error(OP_NEXT, e),
            }
        }

        // ===== 下一张照片 =====
        if job.index < job.ids.len() {
            let index = job.index;
            job.index += 1;
            if let Some((name, reason)) = job.pre_failures.remove(&index) {
                return event(
                    OP_NEXT,
                    photo_event(&PhotoOutcome {
                        index: index as u32,
                        name,
                        status: "failed",
                        reason: Some(reason),
                    }),
                );
            }
            match prepare_photo(worker, job, index) {
                Ok(pending) => {
                    let file_index = pending.file_index;
                    let name = pending.name.clone();
                    let mime = pending.mime.clone();
                    let size = pending.size;
                    job.pending = Some(pending);
                    if job.format == Format::VencSingle {
                        continue;
                    }
                    let mut payload = simple("file_begin");
                    payload.file_index = Some(file_index);
                    payload.file_name = Some(name);
                    payload.mime = Some(mime);
                    payload.size = Some(size);
                    return event(OP_NEXT, payload);
                }
                Err(PrepareError::TooLarge) => {
                    return error_code(OP_NEXT, "E_EXPORT_TOO_LARGE", "容器体积超过单文件上限");
                }
                Err(PrepareError::Photo(name, reason)) => {
                    return event(
                        OP_NEXT,
                        photo_event(&PhotoOutcome {
                            index: index as u32,
                            name,
                            status: "failed",
                            reason: Some(reason),
                        }),
                    );
                }
            }
        }

        // ===== 全部照片处理完成 =====
        if job.format == Format::VencSingle {
            if !job.single_any_ok {
                return error(OP_NEXT, "没有可导出的照片");
            }
            let trailer = match job.container.as_mut().expect("容器已创建").finish() {
                Ok(bytes) => bytes,
                Err(e) => return venc_error(OP_NEXT, e),
            };
            job.pending = Some(Pending {
                kind: PendingKind::SingleTrailer,
                file_index: 0,
                name: String::new(),
                mime: String::new(),
                size: 0,
                segments: into_segments(&trailer),
                next: 0,
            });
            continue;
        }

        job.finished = true;
        return event(OP_NEXT, simple("done"));
    }
}

pub(crate) fn handle_cancel(req: &Request) -> Response {
    let mut jobs = lock_jobs();
    if let Some(job) = jobs.get_mut(&req.job_id) {
        job.cancelled = true;
        job.pending = None;
        job.container = None;
    }
    Response::ok("photo_export_job_cancel")
}

pub(crate) fn handle_end(req: &Request) -> Response {
    lock_jobs().remove(&req.job_id);
    Response::ok("photo_export_job_end")
}

/* ------------------------------------------------------------------ *
 * 预检与单张准备                                                      *
 * ------------------------------------------------------------------ */

fn preflight(worker: &Worker, job: &mut Job) {
    for (index, id) in job.ids.iter().enumerate() {
        match read_meta(worker, *id) {
            Ok(mut meta) => {
                let usable = meta.size > 0
                    && meta.size <= PB_PHOTO_MAX_BYTES
                    && source::resolve_chunk_refs(worker, &mut meta).is_ok()
                    && meta.chunk_total().is_ok();
                if !usable {
                    job.pre_failures
                        .insert(index, (display_name(&meta), "data-missing"));
                }
            }
            Err(_) => {
                job.pre_failures
                    .insert(index, ("照片".to_string(), "data-missing"));
            }
        }
    }
}

enum PrepareError {
    TooLarge,
    Photo(String, &'static str),
}

fn prepare_photo(worker: &Worker, job: &mut Job, index: usize) -> Result<Pending, PrepareError> {
    let id = job.ids[index];
    let mut meta = read_meta(worker, id)
        .map_err(|_| PrepareError::Photo(format!("照片 #{}", id), "data-missing"))?;
    if source::resolve_chunk_refs(worker, &mut meta).is_err() {
        return Err(PrepareError::Photo(display_name(&meta), "data-missing"));
    }
    if meta.size == 0 || meta.size > PB_PHOTO_MAX_BYTES {
        return Err(PrepareError::Photo(display_name(&meta), "data-missing"));
    }
    let total = meta
        .chunk_total()
        .map_err(|_| PrepareError::Photo(display_name(&meta), "data-missing"))?;
    let chunks = load_plain_chunks(worker, &mut meta).map_err(|e| {
        let reason = if e.contains("读取照片块失败") || e.contains("块引用缺失") {
            "data-missing"
        } else {
            "decrypt-failed"
        };
        PrepareError::Photo(display_name(&meta), reason)
    })?;
    if chunks.len() != total as usize {
        return Err(PrepareError::Photo(display_name(&meta), "decrypt-failed"));
    }
    verify_plain(&meta, &chunks)
        .map_err(|_| PrepareError::Photo(display_name(&meta), "decrypt-failed"))?;

    /* 瘦身布局的缩略图在独立记录中；容器清单必须携带明文缩略图，
     * 缺失时按 thumb_id 读取并在清单校验前补齐。 */
    let thumb_b64 = if meta.thumb_b64.is_empty() {
        source::load_thumb_b64(worker, &meta)
            .ok()
            .flatten()
            .unwrap_or_default()
    } else {
        meta.thumb_b64.clone()
    };
    let light = LightMeta {
        name: meta.name.clone(),
        mime: meta.mime.clone(),
        size: meta.size,
        thumb_b64,
        file_hash: meta.file_hash.clone(),
        created_at: meta.created_at,
        chunk_count: total,
    };
    if light.validate().is_err() {
        return Err(PrepareError::Photo(display_name(&meta), "pack-failed"));
    }

    match job.format {
        Format::Original => Ok(Pending {
            kind: PendingKind::StandaloneFile,
            file_index: index as u32,
            name: display_name(&meta),
            mime: meta.mime.clone(),
            size: meta.size,
            segments: chunks_to_segments(&chunks),
            next: 0,
        }),
        Format::Png => {
            let bytes = concat_chunks(&chunks);
            let animated = match meta.animated {
                Some(value) => value,
                None => animated::detect_bytes(&bytes, &meta.mime)
                    .unwrap_or(None)
                    .unwrap_or(false),
            };
            if animated {
                return Err(PrepareError::Photo(
                    display_name(&meta),
                    "animated-unsupported",
                ));
            }
            let png = decoder::encode_png_bytes(&bytes, &meta.mime)
                .map_err(|_| PrepareError::Photo(display_name(&meta), "convert-failed"))?;
            Ok(Pending {
                kind: PendingKind::StandaloneFile,
                file_index: index as u32,
                name: display_name(&meta),
                mime: "image/png".to_string(),
                size: png.len() as u64,
                segments: into_segments(&png),
                next: 0,
            })
        }
        Format::VencMultiple => {
            let (mut writer, prefix) = VencWriter::new(&job.token)
                .map_err(|e| pack_error(e, &meta))?;
            let mut bytes = prefix;
            bytes.extend_from_slice(
                &writer
                    .write_manifest(&light)
                    .map_err(|e| pack_error(e, &meta))?,
            );
            for chunk in &chunks {
                bytes.extend_from_slice(
                    &writer
                        .write_chunk(chunk)
                        .map_err(|e| pack_error(e, &meta))?,
                );
            }
            bytes.extend_from_slice(&writer.finish().map_err(|e| pack_error(e, &meta))?);
            Ok(Pending {
                kind: PendingKind::StandaloneFile,
                file_index: index as u32,
                name: display_name(&meta),
                mime: "application/octet-stream".to_string(),
                size: bytes.len() as u64,
                segments: into_segments(&bytes),
                next: 0,
            })
        }
        Format::VencSingle => {
            let packed = (|| -> Result<Vec<u8>, VencError> {
                let writer = job
                    .container
                    .as_mut()
                    .ok_or(VencError::Internal)?;
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&writer.write_manifest(&light)?);
                for chunk in &chunks {
                    bytes.extend_from_slice(&writer.write_chunk(chunk)?);
                }
                Ok(bytes)
            })();
            let bytes = match packed {
                Ok(bytes) => bytes,
                Err(e) => {
                    // 容器可能已写入部分帧：毒化 job，禁止继续追加/收尾
                    job.fatal = Some("单文件容器打包失败".to_string());
                    return Err(pack_error(e, &meta));
                }
            };
            Ok(Pending {
                kind: PendingKind::SinglePhotoFrames,
                file_index: index as u32,
                name: display_name(&meta),
                mime: "application/octet-stream".to_string(),
                size: bytes.len() as u64,
                segments: into_segments(&bytes),
                next: 0,
            })
        }
    }
}

fn pack_error(err: VencError, meta: &PhotoMetaIn) -> PrepareError {
    match err {
        VencError::TooLarge => PrepareError::TooLarge,
        _ => PrepareError::Photo(display_name(meta), "pack-failed"),
    }
}

/* ------------------------------------------------------------------ *
 * 字节工具                                                            *
 * ------------------------------------------------------------------ */

fn display_name(meta: &PhotoMetaIn) -> String {
    if meta.name.is_empty() {
        "照片".to_string()
    } else {
        meta.name.clone()
    }
}

fn concat_chunks(chunks: &[Zeroizing<Vec<u8>>]) -> Zeroizing<Vec<u8>> {
    let total: usize = chunks.iter().map(|c| c.len()).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    for chunk in chunks {
        out.extend_from_slice(chunk);
    }
    out
}

fn chunks_to_segments(chunks: &[Zeroizing<Vec<u8>>]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out = Vec::new();
    for chunk in chunks {
        out.extend(into_segments(chunk));
    }
    out
}

fn into_segments(bytes: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    bytes
        .chunks(SEGMENT_BYTES)
        .map(|part| Zeroizing::new(part.to_vec()))
        .collect()
}

/* ------------------------------------------------------------------ *
 * 响应装配                                                            *
 * ------------------------------------------------------------------ */

fn simple(status: &str) -> MediaExportPayload {
    MediaExportPayload {
        status: status.to_string(),
        file_index: None,
        file_name: None,
        mime: None,
        size: None,
        data_b64: None,
        file_ok: None,
        name: None,
        reason: None,
        photo_status: None,
        error: None,
        error_code: None,
    }
}

fn photo_event(outcome: &PhotoOutcome) -> MediaExportPayload {
    let mut payload = simple("photo");
    payload.file_index = Some(outcome.index);
    payload.name = Some(outcome.name.clone());
    payload.photo_status = Some(outcome.status.to_string());
    payload.reason = outcome.reason.map(|r| r.to_string());
    payload
}

fn event(op: &str, payload: MediaExportPayload) -> Response {
    let mut resp = Response::ok(op);
    resp.photo_export = Some(payload);
    resp
}

fn error(op: &str, message: &str) -> Response {
    let mut resp = Response::ok(op);
    resp.ok = false;
    resp.error = Some(message.to_string());
    resp
}

fn error_code(op: &str, code: &str, message: &str) -> Response {
    let mut resp = error(op, message);
    resp.error_code = Some(code.to_string());
    resp
}

fn venc_error(op: &str, err: VencError) -> Response {
    match err {
        VencError::TooLarge => error_code(op, "E_EXPORT_TOO_LARGE", "容器体积超过单文件上限"),
        other => error(op, &format!("容器打包失败: {:?}", other)),
    }
}

fn prune_stale(jobs: &mut HashMap<String, Job>) {
    let now = Instant::now();
    jobs.retain(|_, job| now.saturating_duration_since(job.last_touch) < JOB_IDLE_TTL);
}

fn lock_jobs() -> std::sync::MutexGuard<'static, HashMap<String, Job>> {
    JOBS.lock().unwrap_or_else(|poison| poison.into_inner())
}
