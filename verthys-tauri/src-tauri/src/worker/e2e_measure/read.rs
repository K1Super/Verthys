//! 原生读取协议端到端：预览命中、删除后懒生成与写回、名称索引、
//! 原图逐块解密比对、取消与布局边界。

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::worker::WorkerSession;

use super::common::{
    json_ok, native_add_record, native_add_staged, native_chunk_total, native_mb_label,
    native_send, native_send_ok, E2eStateGuard, NATIVE_MIB, TYPE_PHOTO_CHUNK, TYPE_PHOTO_META,
};

const TYPE_PHOTO_PREVIEW: u32 = 11;
/// JPEG 起始/结束标记：预览必须是一张完整可解码的 JPEG。
const READ_E2E_JPEG_SOI: [u8; 2] = [0xFF, 0xD8];
const READ_E2E_JPEG_EOI: [u8; 2] = [0xFF, 0xD9];

pub(super) struct ReadE2ePhoto {
    pub(super) meta_id: u64,
    pub(super) chunk_total: usize,
    pub(super) preview_name: String,
    pub(super) preview_id: u64,
    /// 源文件 BLAKE3（导入事件返回；导出/还原用例作为预览哈希输入）
    pub(super) file_hash: String,
}

fn read_e2e_sizes_bytes() -> Vec<u64>
{
    let mut sizes: Vec<u64> = Vec::new();
    if let Ok(raw) = std::env::var("VERTHYS_NATIVE_READ_E2E_SIZES_MB") {
        for token in raw.split(',') {
            if let Ok(mb) = token.trim().parse::<f64>() {
                if mb.is_finite() && mb > 0.0 {
                    sizes.push((mb * NATIVE_MIB as f64).round() as u64);
                }
            }
        }
    }
    if sizes.is_empty() {
        /* 10MiB 覆盖常规路径，100MiB 覆盖产品上限附近的块数与内存边界。 */
        sizes.push(10 * NATIVE_MIB);
        sizes.push(100 * NATIVE_MIB);
    }
    sizes.dedup();
    sizes
}

/// 导入单张照片并按生产顺序写入 meta 与预览记录；返回读取所需的索引。
pub(super) fn read_e2e_import(
    session: &WorkerSession,
    job_id: &str,
    path: &std::path::Path,
    expected_size: u64,
) -> Result<ReadE2ePhoto, String>
{
    let path_text = path.to_string_lossy().to_string();
    native_send_ok(
        session,
        serde_json::json!({
            "op": "authorize_path_batch",
            "job_id": job_id,
            "paths": [path_text],
        }),
    )?;
    native_send_ok(
        session,
        serde_json::json!({
            "op": "photo_import_job_begin",
            "job_id": job_id,
            "paths": [path_text],
        }),
    )?;

    let mut chunk_ids: Vec<u64> = Vec::new();
    let mut file_hash = String::new();

    loop {
        let value = native_send_ok(
            session,
            serde_json::json!({"op": "photo_import_job_next", "job_id": job_id}),
        )?;
        let photo = value
            .get("photo")
            .ok_or_else(|| format!("{job_id}: next 响应缺少 photo"))?;
        match photo.get("status").and_then(|v| v.as_str()).unwrap_or("") {
            "chunk" => {
                let seq = photo
                    .get("chunk_index")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| format!("{job_id}: chunk 缺少 chunk_index"))?
                    as usize;
                let total = photo
                    .get("chunk_total")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| format!("{job_id}: chunk 缺少 chunk_total"))?
                    as usize;
                let chunk_key = photo
                    .get("chunk_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("{job_id}: chunk 缺少 chunk_key"))?;
                let chunk_hash = photo
                    .get("chunk_hash")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("{job_id}: chunk 缺少 chunk_hash"))?;
                if photo.get("chunk_staged").and_then(|v| v.as_bool()) != Some(true) {
                    return Err(format!("{job_id}: 未启用块暂存 (seq={seq})"));
                }
                if photo.get("chunk_b64").is_some() {
                    return Err(format!("{job_id}: 暂存块仍携带 chunk_b64 (seq={seq})"));
                }
                if let Some(hash) = photo.get("file_hash").and_then(|v| v.as_str()) {
                    if !hash.is_empty() {
                        file_hash = hash.to_string();
                    }
                }
                let file_done = photo
                    .get("file_done")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let size = photo
                    .get("size")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| format!("{job_id}: chunk 缺少 size"))?;
                if seq != chunk_ids.len() {
                    return Err(format!(
                        "{job_id}: 块序号不连续 seq={seq} 期望={}",
                        chunk_ids.len()
                    ));
                }
                if total != native_chunk_total(expected_size) {
                    return Err(format!(
                        "{job_id}: chunk_total={total} 与 ceil(size/4MiB) 不一致"
                    ));
                }
                if size != expected_size {
                    return Err(format!(
                        "{job_id}: 导入字节 {size} 与样本 {expected_size} 不一致"
                    ));
                }
                let id = native_add_staged(
                    session,
                    job_id,
                    TYPE_PHOTO_CHUNK,
                    &format!("chunk_{chunk_key}"),
                    chunk_key,
                    chunk_hash,
                )?;
                chunk_ids.push(id);
                if file_done {
                    if chunk_ids.len() != total {
                        return Err(format!(
                            "{job_id}: file_done 时块数 {} 与 chunk_total {} 不一致",
                            chunk_ids.len(),
                            total
                        ));
                    }
                    let finish = native_send_ok(
                        session,
                        serde_json::json!({
                            "op": "photo_import_job_finish",
                            "job_id": job_id,
                            "chunk_ids": chunk_ids,
                        }),
                    )?;
                    let tail = native_send_ok(
                        session,
                        serde_json::json!({"op": "photo_import_job_next", "job_id": job_id}),
                    )?;
                    if tail
                        .get("photo")
                        .and_then(|p| p.get("status"))
                        .and_then(|v| v.as_str())
                        != Some("done")
                    {
                        return Err(format!("{job_id}: 收尾后期望 done"));
                    }
                    native_send_ok(
                        session,
                        serde_json::json!({"op": "photo_import_job_end", "job_id": job_id}),
                    )?;
                    return read_e2e_store_import(session, job_id, finish, total, file_hash);
                }
            }
            "skipped" => {
                let error = photo
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return Err(format!("{job_id}: 非预期 skipped: {error}"));
            }
            other => return Err(format!("{job_id}: 非预期 photo 状态 {other}")),
        }
    }
}

/// 把 finish 返回的 meta 与预览写入同一批次，并返回读取索引。
fn read_e2e_store_import(
    session: &WorkerSession,
    job_id: &str,
    finish_response: serde_json::Value,
    chunk_total: usize,
    file_hash: String,
) -> Result<ReadE2ePhoto, String>
{
    let finish = finish_response
        .get("photo_finish")
        .cloned()
        .ok_or_else(|| format!("{job_id}: finish 响应缺少 photo_finish"))?;
    let meta_b64 = finish
        .get("meta_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{job_id}: finish 缺少 meta_b64"))?;
    let record_name = finish
        .get("record_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{job_id}: finish 缺少 record_name"))?;
    let preview_b64 = finish
        .get("preview_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{job_id}: finish 缺少预览密文（导入未生成预览）"))?;
    let preview_name = finish
        .get("preview_record_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{job_id}: finish 缺少预览记录名"))?;
    if !preview_name.starts_with("preview_") || preview_name == "preview_" {
        return Err(format!("{job_id}: 预览记录名非法 {preview_name}"));
    }

    /* meta 与预览同一批次写入，与宿主生产路径一致。 */
    let added = native_send_ok(
        session,
        serde_json::json!({
            "op": "add_records",
            "records": [
                {"rtype": TYPE_PHOTO_META, "name": record_name, "data": meta_b64},
                {"rtype": TYPE_PHOTO_PREVIEW, "name": preview_name, "data": preview_b64},
            ],
        }),
    )?;
    let ids = added
        .get("ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("{job_id}: add_records 缺少 ids"))?;
    if ids.len() != 2 {
        return Err(format!("{job_id}: add_records 返回 {} 个 id（期望 2）", ids.len()));
    }
    let meta_id = ids[0]
        .as_u64()
        .ok_or_else(|| format!("{job_id}: meta id 非法"))?;
    let preview_id = ids[1]
        .as_u64()
        .ok_or_else(|| format!("{job_id}: preview id 非法"))?;

    let opened = native_send_ok(
        session,
        serde_json::json!({
            "op": "module_open",
            "module": "photo",
            "kind": "meta",
            "data": meta_b64,
        }),
    )?;
    let plain_b64 = opened
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{job_id}: module_open 缺少 data"))?;
    let plain = STANDARD
        .decode(plain_b64)
        .map_err(|e| format!("{job_id}: meta base64 解码失败: {e}"))?;
    serde_json::from_slice::<serde_json::Value>(&plain)
        .map_err(|e| format!("{job_id}: meta JSON 解析失败: {e}"))?;

    Ok(ReadE2ePhoto {
        meta_id,
        chunk_total,
        preview_name: preview_name.to_string(),
        preview_id,
        file_hash,
    })
}

/// 读取预览并校验响应形状；返回解码后的 JPEG 字节。
fn read_e2e_preview_bytes(
    session: &WorkerSession,
    job_id: &str,
    meta_id: u64,
    expect_cached: bool,
) -> Result<(Vec<u8>, Option<serde_json::Value>), String>
{
    let value = native_send(
        session,
        serde_json::json!({
            "op": "photo_read_job_begin",
            "job_id": job_id,
            "mode": "preview",
            "meta_id": meta_id,
        }),
    )?;
    if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(format!(
            "预览读取失败: {}",
            value.get("error").and_then(|v| v.as_str()).unwrap_or("?")
        ));
    }
    let read = value
        .get("photo_read")
        .ok_or_else(|| "预览响应缺少 photo_read".to_string())?;
    if read.get("status").and_then(|v| v.as_str()) != Some("preview") {
        return Err(format!(
            "预览状态异常: {:?}",
            read.get("status").and_then(|v| v.as_str())
        ));
    }
    if read.get("preview_cached").and_then(|v| v.as_bool()) != Some(expect_cached) {
        return Err(format!(
            "preview_cached={:?}（期望 {expect_cached}）",
            read.get("preview_cached").and_then(|v| v.as_bool())
        ));
    }
    let data_b64 = read
        .get("data_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "预览响应缺少 data_b64".to_string())?;
    let jpeg = STANDARD
        .decode(data_b64)
        .map_err(|e| format!("预览 base64 解码失败: {e}"))?;
    native_send_ok(
        session,
        serde_json::json!({"op": "photo_read_job_end", "job_id": job_id}),
    )?;
    Ok((jpeg, value.get("photo_record").cloned()))
}

/// 原图逐块读取并与源文件逐字节比对；返回块数。
pub(super) fn read_e2e_full(
    session: &WorkerSession,
    job_id: &str,
    meta_id: u64,
    expected: &[u8],
) -> Result<usize, String>
{
    let begin = native_send(
        session,
        serde_json::json!({
            "op": "photo_read_job_begin",
            "job_id": job_id,
            "mode": "full",
            "meta_id": meta_id,
        }),
    )?;
    if begin.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(format!(
            "原图读取开始失败: {}",
            begin.get("error").and_then(|v| v.as_str()).unwrap_or("?")
        ));
    }
    let ready = begin
        .get("photo_read")
        .ok_or_else(|| "原图 begin 响应缺少 photo_read".to_string())?;
    if ready.get("status").and_then(|v| v.as_str()) != Some("ready") {
        return Err("原图 begin 状态不是 ready".to_string());
    }
    let total = ready
        .get("chunk_total")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "原图 begin 缺少 chunk_total".to_string())? as usize;

    let mut offset = 0usize;
    let mut seq = 0usize;
    loop {
        let value = native_send_ok(
            session,
            serde_json::json!({"op": "photo_read_job_next", "job_id": job_id}),
        )?;
        let read = value
            .get("photo_read")
            .ok_or_else(|| format!("{job_id}: next 缺少 photo_read"))?;
        let status = read
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if status == "cancelled" {
            return Err(format!("{job_id}: 未取消的 job 返回 cancelled"));
        }
        if read.get("chunk_index").and_then(|v| v.as_u64()) != Some(seq as u64) {
            return Err(format!("{job_id}: 块序号乱序 seq={seq}"));
        }
        let data_b64 = read
            .get("data_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{job_id}: 第 {seq} 块缺少 data_b64"))?;
        let plain = STANDARD
            .decode(data_b64)
            .map_err(|e| format!("{job_id}: 第 {seq} 块 base64 解码失败: {e}"))?;
        let end = offset + plain.len();
        if end > expected.len() {
            return Err(format!("{job_id}: 第 {seq} 块超出原图字节范围"));
        }
        if plain != expected[offset..end] {
            return Err(format!("{job_id}: 第 {seq} 块明文与源文件不一致"));
        }
        offset = end;
        seq += 1;
        if status == "done" {
            break;
        }
        if status != "chunk" {
            return Err(format!("{job_id}: 非预期状态 {status}"));
        }
    }
    if seq != total {
        return Err(format!("{job_id}: 实读块数 {seq} 与声明 {total} 不一致"));
    }
    if offset != expected.len() {
        return Err(format!(
            "{job_id}: 原图字节 {offset} 与源文件 {} 不一致",
            expected.len()
        ));
    }
    native_send_ok(
        session,
        serde_json::json!({"op": "photo_read_job_end", "job_id": job_id}),
    )?;
    Ok(seq)
}

#[test]
fn worker_native_read_e2e() -> Result<(), String>
{
    if std::env::var("VERTHYS_NATIVE_READ_E2E").ok().as_deref() != Some("1") {
        eprintln!("native read e2e 跳过：未设置 VERTHYS_NATIVE_READ_E2E=1");
        return Ok(());
    }

    let _state_guard = E2eStateGuard::new();

    let worker = std::env::var("VERTHYS_WORKER_E2E_WORKER")
        .expect("缺少 VERTHYS_WORKER_E2E_WORKER");
    let dll = std::env::var("VERTHYS_WORKER_E2E_DLL")
        .expect("缺少 VERTHYS_WORKER_E2E_DLL");
    let fixture_dir = std::path::PathBuf::from(
        std::env::var("VERTHYS_NATIVE_E2E_DIR").expect("缺少 VERTHYS_NATIVE_E2E_DIR"),
    );
    assert!(std::path::Path::new(&worker).is_file(), "worker 不存在: {worker}");
    assert!(std::path::Path::new(&dll).is_file(), "DLL 不存在: {dll}");
    assert!(fixture_dir.is_dir(), "样本目录不存在: {}", fixture_dir.display());

    let sizes = read_e2e_sizes_bytes();
    let mut fixtures: Vec<(std::path::PathBuf, u64)> = Vec::new();
    for size in &sizes {
        let mb = *size as f64 / NATIVE_MIB as f64;
        let path = fixture_dir.join(format!("jpeg_{}.jpg", native_mb_label(mb)));
        let actual = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        assert!(
            actual == *size,
            "样本 {} 字节为 {}（期望 {}）",
            path.display(),
            actual,
            size
        );
        fixtures.push((path, *size));
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("创建 tokio runtime 失败");
    let _guard = runtime.enter();

    let dir = tempfile::tempdir().expect("创建读取用例临时目录失败");
    let vault = dir.path().join("native_read_e2e.verthys").to_string_lossy().to_string();
    let password = "native-e2e-read-pass";

    let session = WorkerSession::spawn(&worker, &dll).expect("启动 worker 失败");
    session.wait_for_ready_signal().expect("worker 就绪失败");
    session
        .authorize_path("v4_create", "write", &vault)
        .expect("v4_create 路径授权失败");
    let created = session
        .send_json(
            &serde_json::json!({"op": "v4_create", "path": vault, "password": password})
                .to_string(),
        )
        .expect("v4_create 请求失败");
    assert!(json_ok(&created), "v4_create 失败: {created}");
    session
        .authorize_path("unlock", "read", &vault)
        .expect("unlock 路径授权失败");
    let unlocked = session
        .send_json(
            &serde_json::json!({"op": "unlock", "path": vault, "password": password})
                .to_string(),
        )
        .expect("unlock 请求失败");
    assert!(json_ok(&unlocked), "unlock 失败: {unlocked}");

    for (index, (path, size)) in fixtures.iter().enumerate() {
        let job_id = format!("read-e2e-import-{index}");
        let photo = read_e2e_import(&session, &job_id, path, *size)
            .unwrap_or_else(|e| panic!("导入 {} 失败: {e}", path.display()));

        /* 名称索引必须能在批量写入后定位预览记录。 */
        let found = native_send_ok(
            &session,
            serde_json::json!({
                "op": "find_lid_by_name",
                "name": photo.preview_name,
            }),
        )?;
        if found.get("found").and_then(|v| v.as_bool()) != Some(true) {
            panic!("find_lid_by_name 未命中 {}", photo.preview_name);
        }
        if found.get("id").and_then(|v| v.as_u64()) != Some(photo.preview_id) {
            panic!(
                "find_lid_by_name 返回 id={:?}（期望 {}）",
                found.get("id"),
                photo.preview_id
            );
        }

        let (jpeg, record) = read_e2e_preview_bytes(
            &session,
            &format!("read-e2e-preview-{index}"),
            photo.meta_id,
            true,
        )
        .unwrap_or_else(|e| panic!("{}: 预览命中失败: {e}", path.display()));
        if record.is_some() {
            panic!("{}: 命中预览却返回了待写回记录", path.display());
        }
        if !jpeg.starts_with(&READ_E2E_JPEG_SOI) || !jpeg.ends_with(&READ_E2E_JPEG_EOI) {
            panic!(
                "{}: 预览不是完整 JPEG（len={} head={:02X?} tail={:02X?}）",
                path.display(),
                jpeg.len(),
                &jpeg[..2.min(jpeg.len())],
                &jpeg[jpeg.len().saturating_sub(2)..]
            );
        }
        println!(
            "[native-read-e2e] photo={}MB preview_bytes={} cached=true",
            native_mb_label(*size as f64 / NATIVE_MIB as f64),
            jpeg.len()
        );

        /* 删除级联：按 meta 解析出预览记录 ID。 */
        let cascade = native_send_ok(
            &session,
            serde_json::json!({"op": "photo_preview_ids", "ids": [photo.meta_id]}),
        )?;
        let ids = cascade
            .get("ids")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "photo_preview_ids 缺少 ids".to_string())
            .unwrap_or_else(|e| panic!("{e}"));
        if !ids.iter().any(|v| v.as_u64() == Some(photo.preview_id)) {
            panic!("photo_preview_ids 未包含预览记录 {}", photo.preview_id);
        }

        /* 原图逐块读取：每个块的明文必须与源文件对应区间完全一致。 */
        let original = std::fs::read(path).expect("读取样本文件失败");
        let chunks = read_e2e_full(
            &session,
            &format!("read-e2e-full-{index}"),
            photo.meta_id,
            &original,
        )
        .unwrap_or_else(|e| panic!("{}: 原图读取失败: {e}", path.display()));
        if chunks != photo.chunk_total {
            panic!(
                "{}: 块数 {chunks} 与导入声明 {} 不一致",
                path.display(),
                photo.chunk_total
            );
        }
        println!(
            "[native-read-e2e] photo={}MB full_chunks={} bytes={}",
            native_mb_label(*size as f64 / NATIVE_MIB as f64),
            chunks,
            original.len()
        );

        /* 懒生成、取消与布局边界只在最小样本上执行一次，避免重复大图解码。 */
        if index != 0 {
            continue;
        }

        native_send_ok(
            &session,
            serde_json::json!({"op": "delete_record", "id": photo.preview_id}),
        )?;
        let (lazy_jpeg, lazy_record) = read_e2e_preview_bytes(
            &session,
            "read-e2e-preview-lazy",
            photo.meta_id,
            false,
        )
        .expect("懒生成预览失败");
        let lazy_record = lazy_record.expect("懒生成未返回待写回记录");
        if lazy_record.get("name").and_then(|v| v.as_str()) != Some(photo.preview_name.as_str()) {
            panic!(
                "懒生成记录名 {:?} 与导入记录名 {} 不一致",
                lazy_record.get("name"),
                photo.preview_name
            );
        }
        let lazy_b64 = lazy_record
            .get("data_b64")
            .and_then(|v| v.as_str())
            .expect("懒生成记录缺少 data_b64");
        let new_id = native_add_record(
            &session,
            TYPE_PHOTO_PREVIEW,
            &photo.preview_name,
            lazy_b64,
        )
        .expect("写回懒生成预览失败");
        if new_id == photo.preview_id {
            panic!("写回预览复用了已删除的记录 ID");
        }
        let (hit_jpeg, hit_record) = read_e2e_preview_bytes(
            &session,
            "read-e2e-preview-relay",
            photo.meta_id,
            true,
        )
        .expect("写回后预览未命中");
        if hit_record.is_some() {
            panic!("写回后预览仍返回待写回记录");
        }
        if !hit_jpeg.starts_with(&READ_E2E_JPEG_SOI) || hit_jpeg.len() < 1024 {
            panic!("写回后预览不是有效 JPEG（len={}）", hit_jpeg.len());
        }
        if lazy_jpeg.len() < 1024 {
            panic!("懒生成预览过小（len={}）", lazy_jpeg.len());
        }
        println!(
            "[native-read-e2e] lazy_preview_bytes={} relay_hit_bytes={}",
            lazy_jpeg.len(),
            hit_jpeg.len()
        );

        /* 取消：读到首块后取消，后续 next 必须返回 cancelled。 */
        let begin = native_send_ok(
            &session,
            serde_json::json!({
                "op": "photo_read_job_begin",
                "job_id": "read-e2e-cancel",
                "mode": "full",
                "meta_id": photo.meta_id,
            }),
        )
        .expect("取消用例 begin 失败");
        if begin
            .get("photo_read")
            .and_then(|r| r.get("status"))
            .and_then(|v| v.as_str())
            != Some("ready")
        {
            panic!("取消用例 begin 状态异常");
        }
        native_send_ok(
            &session,
            serde_json::json!({"op": "photo_read_job_next", "job_id": "read-e2e-cancel"}),
        )
        .expect("取消用例首块读取失败");
        native_send_ok(
            &session,
            serde_json::json!({"op": "photo_read_job_cancel", "job_id": "read-e2e-cancel"}),
        )
        .expect("取消请求失败");
        let cancelled = native_send_ok(
            &session,
            serde_json::json!({"op": "photo_read_job_next", "job_id": "read-e2e-cancel"}),
        )
        .expect("取消后 next 失败");
        if cancelled
            .get("photo_read")
            .and_then(|r| r.get("status"))
            .and_then(|v| v.as_str())
            != Some("cancelled")
        {
            panic!("取消后状态不是 cancelled");
        }
        native_send_ok(
            &session,
            serde_json::json!({"op": "photo_read_job_end", "job_id": "read-e2e-cancel"}),
        )
        .expect("取消用例 end 失败");
        println!("[native-read-e2e] cancel status=cancelled");

        /* 瘦身布局原生读取：slim_meta 双标签与 photo_meta_get 必须可用；
         * 预览可因块内容无效失败，但不得再返回布局不支持。 */
        let slim_meta = serde_json::json!({
            "name": "slim.jpg",
            "mime": "image/jpeg",
            "size": 4096,
            "fileHash": "00".repeat(32),
            "entryKey": "e".repeat(64),
            "chunkIds": [1],
            "wrappedFileKey": "AAAA",
            "fmt": 2,
        });
        let sealed = native_send_ok(
            &session,
            serde_json::json!({
                "op": "module_seal",
                "module": "photo",
                "kind": "slim_meta",
                "data": STANDARD.encode(serde_json::to_vec(&slim_meta).unwrap()),
            }),
        )
        .expect("封装瘦身 meta 失败");
        let sealed_b64 = sealed
            .get("data")
            .and_then(|v| v.as_str())
            .expect("module_seal 缺少 data");
        let slim_id = native_add_record(
            &session,
            TYPE_PHOTO_META,
            "meta_slim_e2e.jpg",
            sealed_b64,
        )
        .expect("写入瘦身 meta 失败");
        let meta_reply = native_send(
            &session,
            serde_json::json!({"op": "photo_meta_get", "ids": [slim_id]}),
        )
        .expect("瘦身布局 photo_meta_get 请求失败");
        if meta_reply.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            panic!("瘦身布局 photo_meta_get 失败: {:?}", meta_reply.get("error"));
        }
        let slim_item = meta_reply
            .get("photo_meta")
            .and_then(|v| v.as_array())
            .and_then(|v| v.first())
            .expect("photo_meta_get 缺少条目");
        if slim_item.get("slim").and_then(|v| v.as_bool()) != Some(true) {
            panic!("photo_meta_get 未标记瘦身布局");
        }
        let slim = native_send(
            &session,
            serde_json::json!({
                "op": "photo_read_job_begin",
                "job_id": "read-e2e-slim",
                "mode": "preview",
                "meta_id": slim_id,
            }),
        )
        .expect("瘦身布局 begin 请求失败");
        if slim.get("error_code").and_then(|v| v.as_str())
            == Some("E_PHOTO_LAYOUT_UNSUPPORTED")
        {
            panic!("瘦身布局仍返回 E_PHOTO_LAYOUT_UNSUPPORTED");
        }
        println!("[native-read-e2e] slim layout meta_get ok");
    }

    println!("[native-read-e2e] SUMMARY sizes={}", fixtures.len());
    Ok(())
}
