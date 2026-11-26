//! 原生照片导入协议端到端：逐块暂存、收尾校验、超限/移动跳过与取消。

use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::worker::WorkerSession;

use super::common::{
    json_ok, native_add_record, native_add_staged, native_chunk_total, native_mb_label,
    native_send_ok, E2eStateGuard, NativeTotals, NATIVE_MIB, TYPE_PHOTO_CHUNK, TYPE_PHOTO_META,
};

struct PendingFile {
    index: u32,
    name: String,
    mime: String,
    size: u64,
    total: usize,
    ids: Vec<u64>,
    started: Instant,
}

/// 收尾当前文件：finish → 解 meta → 校验索引 → 写 meta 记录。
fn native_finish_and_verify(
    session: &WorkerSession,
    job_id: &str,
    file: &PendingFile,
) -> Result<String, String>
{
    let value = native_send_ok(
        session,
        serde_json::json!({
            "op": "photo_import_job_finish",
            "job_id": job_id,
            "chunk_ids": file.ids,
        }),
    )?;
    let finish = value
        .get("photo_finish")
        .ok_or_else(|| format!("{}: finish 响应缺少 photo_finish", file.name))?;
    let record_name = finish
        .get("record_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{}: finish 响应缺少 record_name", file.name))?;
    let expected_name = format!("meta_{}", file.name);
    if record_name != expected_name {
        return Err(format!(
            "{}: record_name={} 与期望 {} 不一致",
            file.name, record_name, expected_name
        ));
    }
    let meta_b64 = finish
        .get("meta_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{}: finish 响应缺少 meta_b64", file.name))?;

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
        .ok_or_else(|| format!("{}: module_open 响应缺少 data", file.name))?;
    let plain = STANDARD
        .decode(plain_b64)
        .map_err(|e| format!("{}: meta 明文 base64 解码失败: {e}", file.name))?;
    let meta: serde_json::Value = serde_json::from_slice(&plain)
        .map_err(|e| format!("{}: meta JSON 解析失败: {e}", file.name))?;

    let chunk_ids = meta
        .get("chunkIds")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("{}: meta 缺少 chunkIds", file.name))?;
    if chunk_ids.len() != file.ids.len() {
        return Err(format!(
            "{}: meta chunkIds 长度 {} 与块记录数 {} 不一致",
            file.name,
            chunk_ids.len(),
            file.ids.len()
        ));
    }
    for (position, value) in chunk_ids.iter().enumerate() {
        let id = value
            .as_u64()
            .ok_or_else(|| format!("{}: meta chunkIds[{}] 非整数", file.name, position))?;
        if id != file.ids[position] {
            return Err(format!(
                "{}: meta chunkIds[{}]={} 与块记录 {} 顺序不一致",
                file.name, position, id, file.ids[position]
            ));
        }
    }

    if meta.get("size").and_then(|v| v.as_u64()) != Some(file.size) {
        return Err(format!(
            "{}: meta size={:?} 与文件字节 {} 不一致",
            file.name,
            meta.get("size"),
            file.size
        ));
    }
    if meta.get("name").and_then(|v| v.as_str()) != Some(file.name.as_str()) {
        return Err(format!(
            "{}: meta name={:?} 与文件名不一致",
            file.name,
            meta.get("name")
        ));
    }
    let file_hash = meta
        .get("fileHash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if file_hash.len() != 64 || !file_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{}: fileHash 非 64 位 hex", file.name));
    }
    let thumb = meta
        .get("thumbB64")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if thumb.is_empty() {
        return Err(format!("{}: meta thumbB64 为空", file.name));
    }
    let hash_count = meta
        .get("chunkHashes")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    if hash_count != chunk_ids.len() {
        return Err(format!(
            "{}: meta chunkHashes 长度 {} 与 chunkIds 长度 {} 不一致",
            file.name,
            hash_count,
            chunk_ids.len()
        ));
    }

    native_add_record(session, TYPE_PHOTO_META, record_name, meta_b64)?;
    Ok(record_name.to_string())
}

/// 跑一个 job 直到 done；每个文件在 file_done 后立即 finish 并写 meta。
pub(super) fn native_import_job(
    session: &WorkerSession,
    job_id: &str,
    paths: &[String],
    totals: &mut NativeTotals,
    reports: &mut Vec<serde_json::Value>,
    _violations: &mut Vec<String>,
) -> Result<(), String>
{
    native_send_ok(
        session,
        serde_json::json!({
            "op": "authorize_path_batch",
            "job_id": job_id,
            "paths": paths,
        }),
    )?;
    native_send_ok(
        session,
        serde_json::json!({
            "op": "photo_import_job_begin",
            "job_id": job_id,
            "paths": paths,
        }),
    )?;

    let outcome = (|| -> Result<(), String> {
        let mut pending: Option<PendingFile> = None;
        loop {
            let value = native_send_ok(
                session,
                serde_json::json!({"op": "photo_import_job_next", "job_id": job_id}),
            )?;
            let photo = value
                .get("photo")
                .ok_or_else(|| format!("{job_id}: next 响应缺少 photo"))?;
            let status = photo
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match status {
                "chunk" => {
                    let index = photo
                        .get("file_index")
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| format!("{job_id}: chunk 缺少 file_index"))?
                        as u32;
                    let name = photo
                        .get("file_name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("{job_id}: chunk 缺少 file_name"))?
                        .to_string();
                    let mime = photo
                        .get("mime")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let size = photo
                        .get("size")
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| format!("{name}: chunk 缺少 size"))?;
                    let total = photo
                        .get("chunk_total")
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| format!("{name}: chunk 缺少 chunk_total"))?
                        as usize;
                    let seq = photo
                        .get("chunk_index")
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| format!("{name}: chunk 缺少 chunk_index"))?
                        as usize;
                    let chunk_key = photo
                        .get("chunk_key")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("{name}: chunk 缺少 chunk_key"))?;
                    let chunk_hash = photo
                        .get("chunk_hash")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("{name}: chunk 缺少 chunk_hash"))?;
                    let staged = photo
                        .get("chunk_staged")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let file_done = photo
                        .get("file_done")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    if !staged {
                        return Err(format!("{name}: 未启用块暂存 (seq={seq})"));
                    }
                    if photo.get("chunk_b64").is_some() {
                        return Err(format!("{name}: 暂存块仍携带 chunk_b64 (seq={seq})"));
                    }
                    let expected_total = native_chunk_total(size);
                    if total != expected_total {
                        return Err(format!(
                            "{name}: chunk_total={total} 与 ceil(size/4MiB)={expected_total} 不一致"
                        ));
                    }

                    let mut file = match pending.take() {
                        Some(file) => {
                            if file.index != index || file.name != name {
                                return Err(format!(
                                    "{name}: 块序号归属跳变 index={index} 上一个文件={}",
                                    file.name
                                ));
                            }
                            if seq != file.ids.len() {
                                return Err(format!(
                                    "{name}: 块序号不连续 seq={seq} 期望={}",
                                    file.ids.len()
                                ));
                            }
                            file
                        }
                        None => {
                            if seq != 0 {
                                return Err(format!("{name}: 首块序号为 {seq}"));
                            }
                            PendingFile {
                                index,
                                name: name.clone(),
                                mime: mime.clone(),
                                size,
                                total,
                                ids: Vec::new(),
                                started: Instant::now(),
                            }
                        }
                    };

                    let record = format!("chunk_{chunk_key}");
                    let id = native_add_staged(
                        session,
                        job_id,
                        TYPE_PHOTO_CHUNK,
                        &record,
                        chunk_key,
                        chunk_hash,
                    )?;
                    file.ids.push(id);

                    if file_done {
                        if file.ids.len() != file.total {
                            return Err(format!(
                                "{}: file_done 时块数 {} 与 chunk_total {} 不一致",
                                file.name,
                                file.ids.len(),
                                file.total
                            ));
                        }
                        let record_name =
                            native_finish_and_verify(session, job_id, &file)?;
                        let ms = file.started.elapsed().as_millis();
                        println!(
                            "[native-e2e] name={} bytes={} chunks={} ms={}",
                            file.name,
                            file.size,
                            file.ids.len(),
                            ms
                        );
                        reports.push(serde_json::json!({
                            "name": file.name,
                            "status": "imported",
                            "mime": file.mime,
                            "bytes": file.size,
                            "chunks": file.ids.len(),
                            "chunk_staged": true,
                            "ms": ms,
                            "record_name": record_name,
                        }));
                        totals.files += 1;
                        totals.chunks += file.ids.len();
                        totals.bytes += file.size;
                    } else {
                        pending = Some(file);
                    }
                }
                "skipped" => {
                    /* 常规导入不允许任何文件被跳过：超限/移动类用例走独立路径。 */
                    let name = photo
                        .get("file_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let error = photo
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    return Err(format!("{job_id}: 非预期 skipped name={name} error={error}"));
                }
                "done" => {
                    if pending.is_some() {
                        return Err(format!("{job_id}: done 时仍有未收尾文件"));
                    }
                    break;
                }
                other => {
                    return Err(format!("{job_id}: 非预期 photo 状态 {other}"));
                }
            }
        }
        Ok(())
    })();

    let end = native_send_ok(
        session,
        serde_json::json!({"op": "photo_import_job_end", "job_id": job_id}),
    );
    match (outcome, end) {
        (Ok(()), Ok(_)) => Ok(()),
        (Ok(()), Err(e)) => Err(format!("{job_id}: job_end 失败: {e}")),
        (Err(e), _) => Err(e),
    }
}

/// 超限 / 源文件移动：首个 next 必须 skipped 且原因匹配，随后 done。
fn native_run_skipped_job(
    session: &WorkerSession,
    job_id: &str,
    path: &str,
    expect_reason: &str,
    before_next: Option<(&std::path::Path, &std::path::Path)>,
) -> Result<String, String>
{
    native_send_ok(
        session,
        serde_json::json!({
            "op": "authorize_path_batch",
            "job_id": job_id,
            "paths": [path],
        }),
    )?;
    native_send_ok(
        session,
        serde_json::json!({
            "op": "photo_import_job_begin",
            "job_id": job_id,
            "paths": [path],
        }),
    )?;

    let outcome = (|| -> Result<String, String> {
        if let Some((from, to)) = before_next {
            std::fs::rename(from, to)
                .map_err(|e| format!("{job_id}: 重命名源文件失败: {e}"))?;
        }
        let value = native_send_ok(
            session,
            serde_json::json!({"op": "photo_import_job_next", "job_id": job_id}),
        )?;
        let photo = value
            .get("photo")
            .ok_or_else(|| format!("{job_id}: next 响应缺少 photo"))?;
        if photo.get("status").and_then(|v| v.as_str()) != Some("skipped") {
            return Err(format!(
                "{job_id}: 期望 skipped，实际 status={:?}",
                photo.get("status")
            ));
        }
        let error = photo
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !error.contains(expect_reason) {
            return Err(format!(
                "{job_id}: skipped 原因不含“{expect_reason}”: {error}"
            ));
        }
        let value = native_send_ok(
            session,
            serde_json::json!({"op": "photo_import_job_next", "job_id": job_id}),
        )?;
        let photo = value
            .get("photo")
            .ok_or_else(|| format!("{job_id}: next 响应缺少 photo"))?;
        if photo.get("status").and_then(|v| v.as_str()) != Some("done") {
            return Err(format!(
                "{job_id}: skipped 后期望 done，实际 status={:?}",
                photo.get("status")
            ));
        }
        Ok(error)
    })();

    let end = native_send_ok(
        session,
        serde_json::json!({"op": "photo_import_job_end", "job_id": job_id}),
    );
    match (outcome, end) {
        (Ok(error), Ok(_)) => Ok(error),
        (Ok(_), Err(e)) => Err(format!("{job_id}: job_end 失败: {e}")),
        (Err(e), _) => Err(e),
    }
}

/// 取消：读到首块后 cancel，下一次 next 必须返回 cancelled。
fn native_run_cancel_job(
    session: &WorkerSession,
    job_id: &str,
    path: &str,
) -> Result<u64, String>
{
    native_send_ok(
        session,
        serde_json::json!({
            "op": "authorize_path_batch",
            "job_id": job_id,
            "paths": [path],
        }),
    )?;
    native_send_ok(
        session,
        serde_json::json!({
            "op": "photo_import_job_begin",
            "job_id": job_id,
            "paths": [path],
        }),
    )?;

    let outcome = (|| -> Result<u64, String> {
        let value = native_send_ok(
            session,
            serde_json::json!({"op": "photo_import_job_next", "job_id": job_id}),
        )?;
        let photo = value
            .get("photo")
            .ok_or_else(|| format!("{job_id}: next 响应缺少 photo"))?;
        if photo.get("status").and_then(|v| v.as_str()) != Some("chunk") {
            return Err(format!(
                "{job_id}: 期望 chunk，实际 status={:?}",
                photo.get("status")
            ));
        }
        if photo.get("chunk_index").and_then(|v| v.as_u64()) != Some(0) {
            return Err(format!("{job_id}: 首块 chunk_index 非 0"));
        }
        let size = photo
            .get("size")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("{job_id}: chunk 缺少 size"))?;

        native_send_ok(
            session,
            serde_json::json!({"op": "photo_import_job_cancel", "job_id": job_id}),
        )?;

        let value = native_send_ok(
            session,
            serde_json::json!({"op": "photo_import_job_next", "job_id": job_id}),
        )?;
        let photo = value
            .get("photo")
            .ok_or_else(|| format!("{job_id}: next 响应缺少 photo"))?;
        if photo.get("status").and_then(|v| v.as_str()) != Some("cancelled") {
            return Err(format!(
                "{job_id}: 取消后期望 cancelled，实际 status={:?}",
                photo.get("status")
            ));
        }
        Ok(size)
    })();

    let end = native_send_ok(
        session,
        serde_json::json!({"op": "photo_import_job_end", "job_id": job_id}),
    );
    match (outcome, end) {
        (Ok(size), Ok(_)) => Ok(size),
        (Ok(_), Err(e)) => Err(format!("{job_id}: job_end 失败: {e}")),
        (Err(e), _) => Err(e),
    }
}

#[test]
fn worker_native_import_e2e()
{
    if std::env::var("VERTHYS_NATIVE_E2E").ok().as_deref() != Some("1") {
        eprintln!("native e2e 跳过：未设置 VERTHYS_NATIVE_E2E=1");
        return;
    }

    /* 隔离生产安全状态：E2E 每次 v4_create 都会消耗一个 rollback.state
     * 条目，长期运行会把真实环境的 64 条槽位占满并导致新建容器失败。 */
    let _state_guard = E2eStateGuard::new();

    let worker = std::env::var("VERTHYS_WORKER_E2E_WORKER")
        .expect("缺少 VERTHYS_WORKER_E2E_WORKER");
    let dll = std::env::var("VERTHYS_WORKER_E2E_DLL")
        .expect("缺少 VERTHYS_WORKER_E2E_DLL");
    let fixture_dir = std::path::PathBuf::from(
        std::env::var("VERTHYS_NATIVE_E2E_DIR").expect("缺少 VERTHYS_NATIVE_E2E_DIR"),
    );
    let json_out = std::env::var("VERTHYS_NATIVE_E2E_JSON").ok();

    assert!(std::path::Path::new(&worker).is_file(), "worker 不存在: {worker}");
    assert!(std::path::Path::new(&dll).is_file(), "DLL 不存在: {dll}");
    assert!(
        fixture_dir.is_dir(),
        "测试图片目录不存在: {}",
        fixture_dir.display()
    );

    /* 固定矩阵：文件名与精确字节数必须同时命中，避免“同名但尺寸错位”的假通过。 */
    let mut matrix: Vec<(String, u64)> = Vec::new();
    for mb in [10.0_f64, 17.73, 24.43, 30.0, 50.0, 100.0] {
        matrix.push((
            format!("jpeg_{}.jpg", native_mb_label(mb)),
            (mb * NATIVE_MIB as f64).round() as u64,
        ));
    }
    for name in ["png_100.png", "webp_100.webp", "gif_100.gif", "apng_100.png"] {
        matrix.push((name.to_string(), 100 * NATIVE_MIB));
    }
    let move_source = "move_me.jpg".to_string();

    let mut required: Vec<String> = matrix.iter().map(|(name, _)| name.clone()).collect();
    required.push("over_100.jpg".to_string());
    required.push(move_source.clone());

    let missing: Vec<String> = required
        .iter()
        .map(|name| fixture_dir.join(name))
        .filter(|path| !path.is_file())
        .map(|path| path.display().to_string())
        .collect();
    assert!(
        missing.is_empty(),
        "缺少测试图片（{} 个）:\n{}",
        missing.len(),
        missing.join("\n")
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("创建 tokio runtime 失败");
    let _guard = runtime.enter();

    let dir = tempfile::tempdir().expect("创建测量临时目录失败");
    let vault = dir.path().join("native_e2e.verthys").to_string_lossy().to_string();
    let password = "native-e2e-import-pass";

    let session = WorkerSession::spawn(&worker, &dll).expect("启动 worker 失败");
    session.wait_for_ready_signal().expect("worker 就绪失败");

    session
        .authorize_path("v4_create", "write", &vault)
        .expect("v4_create 路径授权失败");
    let response = session
        .send_json(
            &serde_json::json!({
                "op": "v4_create",
                "path": vault,
                "password": password,
            })
            .to_string(),
        )
        .expect("v4_create 请求失败");
    assert!(json_ok(&response), "v4_create 失败: {response}");

    session
        .authorize_path("unlock", "read", &vault)
        .expect("unlock 路径授权失败");
    let response = session
        .send_json(
            &serde_json::json!({
                "op": "unlock",
                "path": vault,
                "password": password,
            })
            .to_string(),
        )
        .expect("unlock 请求失败");
    assert!(json_ok(&response), "unlock 失败: {response}");

    let mut reports: Vec<serde_json::Value> = Vec::new();
    let mut totals = NativeTotals::default();
    let mut failures: Vec<String> = Vec::new();
    let mut violations: Vec<String> = Vec::new();
    let mut job_seq = 0usize;
    let started = Instant::now();

    for (name, expected) in &matrix {
        let path = fixture_dir.join(name);
        let actual = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if actual != *expected {
            failures.push(format!(
                "{name}: 文件字节 {actual} 与矩阵期望 {expected} 不一致"
            ));
            continue;
        }
        job_seq += 1;
        let job_id = format!("native-e2e-{job_seq}");
        if let Err(e) = native_import_job(
            &session,
            &job_id,
            &[path.to_string_lossy().to_string()],
            &mut totals,
            &mut reports,
            &mut violations,
        ) {
            failures.push(e);
        }
    }

    /* 混合批量：一个 job 内 3 个文件，逐个 finish/写 meta。 */
    job_seq += 1;
    let mixed_paths: Vec<String> = ["jpeg_10.jpg", "png_100.png", "gif_100.gif"]
        .iter()
        .map(|name| fixture_dir.join(name).to_string_lossy().to_string())
        .collect();
    let before_mixed = reports.len();
    match native_import_job(
        &session,
        &format!("native-e2e-{job_seq}"),
        &mixed_paths,
        &mut totals,
        &mut reports,
        &mut violations,
    ) {
        Ok(()) => {
            let imported = reports[before_mixed..]
                .iter()
                .filter(|r| r.get("status").and_then(|v| v.as_str()) == Some("imported"))
                .count();
            if imported != 3 {
                failures.push(format!(
                    "混合批量导入文件数 {imported}（期望 3）"
                ));
            }
            println!("[native-e2e] mixed batch files=3 imported={imported}");
        }
        Err(e) => failures.push(e),
    }

    /* 超限：100MiB+1 必须在打开阶段被判 skipped，且 worker 不崩溃。 */
    job_seq += 1;
    let over_path = fixture_dir.join("over_100.jpg");
    match native_run_skipped_job(
        &session,
        &format!("native-e2e-{job_seq}"),
        &over_path.to_string_lossy(),
        "超过单张照片上限",
        None,
    ) {
        Ok(error) => {
            println!("[native-e2e] over-limit skipped: {error}");
            reports.push(serde_json::json!({
                "name": "over_100.jpg",
                "status": "skipped",
                "error": error,
            }));
            totals.files += 1;
        }
        Err(e) => failures.push(e),
    }
    if !session.is_alive() {
        failures.push("超限用例后 worker 进程已退出".to_string());
    }

    /* 源文件移动：授权/begin 后改名，首次打开必须失败并继续 done。 */
    job_seq += 1;
    let move_scratch = tempfile::tempdir().expect("创建移动用例临时目录失败");
    let move_copy = move_scratch.path().join("move_me.jpg");
    std::fs::copy(fixture_dir.join(&move_source), &move_copy)
        .expect("复制 move_me.jpg 失败");
    let move_away = move_scratch.path().join("move_me.jpg.moved");
    match native_run_skipped_job(
        &session,
        &format!("native-e2e-{job_seq}"),
        &move_copy.to_string_lossy(),
        "",
        Some((move_copy.as_path(), move_away.as_path())),
    ) {
        Ok(error) => {
            println!("[native-e2e] moved-source skipped: {error}");
            reports.push(serde_json::json!({
                "name": "move_me.jpg",
                "status": "skipped",
                "error": error,
            }));
            totals.files += 1;
        }
        Err(e) => failures.push(e),
    }

    /* 取消：读到首块后 cancel，下一次 next 必须 cancelled。 */
    job_seq += 1;
    let cancel_path = fixture_dir.join("jpeg_50.jpg");
    match native_run_cancel_job(
        &session,
        &format!("native-e2e-{job_seq}"),
        &cancel_path.to_string_lossy(),
    ) {
        Ok(size) => {
            println!("[native-e2e] cancel bytes={size} status=cancelled");
            reports.push(serde_json::json!({
                "name": "jpeg_50.jpg",
                "status": "cancelled",
                "bytes": size,
            }));
        }
        Err(e) => failures.push(e),
    }

    let elapsed_ms = started.elapsed().as_millis();
    println!(
        "[native-e2e] SUMMARY files={} chunks={} total_bytes={} elapsed_ms={}",
        totals.files, totals.chunks, totals.bytes, elapsed_ms
    );

    if let Some(path) = &json_out {
        let report = serde_json::json!({
            "worker": worker,
            "dll": dll,
            "fixture_dir": fixture_dir.to_string_lossy(),
            "summary": {
                "files": totals.files,
                "chunks": totals.chunks,
                "total_bytes": totals.bytes,
                "elapsed_ms": elapsed_ms,
            },
            "files": reports,
            "failures": failures,
            "violations": violations,
        });
        std::fs::write(
            path,
            serde_json::to_string_pretty(&report).expect("序列化结果失败"),
        )
        .unwrap_or_else(|e| panic!("写结果失败 {path}: {e}"));
    }

    if !failures.is_empty() {
        panic!("native e2e 失败 {} 项:\n{}", failures.len(), failures.join("\n"));
    }
    if !violations.is_empty() {
        panic!(
            "native e2e 预算断言失败 {} 项:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }
}
