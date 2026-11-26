//! 导入数据面测量：单轮导入耗时与去重前置端到端。

use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::worker::WorkerSession;

use super::common::{
    env_photo_sizes_bytes, env_usize, json_ok, mib_text, ADD_RECORDS_PAYLOAD_BUDGET,
    PHOTO_CHUNK_BYTES, TYPE_PHOTO_CHUNK, TYPE_PHOTO_META,
};

/// 运行一轮导入：块记录 + meta + flush；返回 add_records / flush 耗时（毫秒）。
///
/// `batch=true` 时把块与 meta 合并为一次 add_records（仅当载荷在预算内），
/// 用于验证“提交次数”对端到端耗时的影响。
fn import_one(
    session: &WorkerSession,
    scenario: usize,
    round: usize,
    photo_bytes: usize,
    batch: bool,
    flush: bool,
) -> Result<(u128, u128), String>
{
    let mut remaining = photo_bytes;
    let mut chunk_index = 0usize;
    // (rtype, name, base64)
    let mut records: Vec<(u32, String, String)> = Vec::new();

    while remaining > 0 {
        let size = remaining.min(PHOTO_CHUNK_BYTES);
        // 密文内容对存储层是 opaque；用确定性填充避免额外随机依赖。
        let data = vec![((round as u64 * 131 + chunk_index as u64) & 0xFF) as u8; size];
        let encoded = STANDARD.encode(&data);
        /* 名称带场景号：同一测量进程会跑多个尺寸，round 会重新计数，
         * 不带场景号会生成重复记录名，破坏索引与去重语义。 */
        let name = format!(
            "chunk_{:016x}{:032x}{:032x}",
            scenario as u64, round as u64, chunk_index as u64
        );
        records.push((TYPE_PHOTO_CHUNK, name, encoded));
        remaining -= size;
        chunk_index += 1;
    }
    records.push((
        TYPE_PHOTO_META,
        format!("meta_{:016x}{:032x}", scenario as u64, round as u64),
        STANDARD.encode(vec![0xA5u8; 1024]),
    ));

    let total_chars: usize = records.iter().map(|(_, n, d)| n.len() + d.len()).sum();
    let mut add_ms = 0u128;
    if batch && total_chars <= ADD_RECORDS_PAYLOAD_BUDGET {
        let started = Instant::now();
        let payload: Vec<serde_json::Value> = records
            .iter()
            .map(|(rtype, name, data)| {
                serde_json::json!({"rtype": rtype, "name": name, "data": data})
            })
            .collect();
        let request = serde_json::json!({"op": "add_records", "records": payload});
        let response = session.send_json(&request.to_string())?;
        if !json_ok(&response) {
            return Err(format!("批量 add_records 失败: round={} resp={}", round, response));
        }
        add_ms += started.elapsed().as_millis();
    } else {
        for (rtype, name, data) in &records {
            let request = serde_json::json!({
                "op": "add_records",
                "records": [{
                    "rtype": rtype,
                    "name": name,
                    "data": data,
                }],
            });
            let started = Instant::now();
            let response = session.send_json(&request.to_string())?;
            if !json_ok(&response) {
                return Err(format!(
                    "add_records 失败: round={} name={} resp={}",
                    round, name, response
                ));
            }
            add_ms += started.elapsed().as_millis();
        }
    }

    let started = Instant::now();
    let flush_ms = if flush {
        let response = session.send_json(r#"{"op":"flush"}"#)?;
        if !json_ok(&response) {
            return Err(format!("flush 失败: round={} resp={}", round, response));
        }
        started.elapsed().as_millis()
    } else {
        /* add_records 自身已提交容器；跳过 flush 用于测量“每轮一次提交”路径。 */
        0
    };

    Ok((add_ms, flush_ms))
}

#[test]
fn worker_import_e2e_measure()
{
    if std::env::var("VERTHYS_WORKER_E2E").ok().as_deref() != Some("1") {
        eprintln!("worker e2e 测量跳过：未设置 VERTHYS_WORKER_E2E=1");
        return;
    }

    let worker = std::env::var("VERTHYS_WORKER_E2E_WORKER")
        .expect("缺少 VERTHYS_WORKER_E2E_WORKER");
    let dll = std::env::var("VERTHYS_WORKER_E2E_DLL")
        .expect("缺少 VERTHYS_WORKER_E2E_DLL");
    let label = std::env::var("VERTHYS_WORKER_E2E_LABEL").unwrap_or_else(|_| "unknown".into());
    let photo_sizes = env_photo_sizes_bytes();
    let rounds = env_usize("VERTHYS_WORKER_E2E_ROUNDS", 3);
    let batch = std::env::var("VERTHYS_WORKER_E2E_BATCH").ok().as_deref() == Some("1");
    let flush = std::env::var("VERTHYS_WORKER_E2E_FLUSH").ok().as_deref() != Some("0");
    let defer = std::env::var("VERTHYS_WORKER_E2E_DEFER").ok().as_deref() == Some("1");
    let json_out = std::env::var("VERTHYS_WORKER_E2E_JSON").ok();

    assert!(std::path::Path::new(&worker).is_file(), "worker 不存在: {worker}");
    assert!(std::path::Path::new(&dll).is_file(), "DLL 不存在: {dll}");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("创建 tokio runtime 失败");
    let _guard = runtime.enter();

    let dir = tempfile::tempdir().expect("创建测量临时目录失败");
    let vault_path = dir.path().join("worker_e2e.verthys");
    let vault = vault_path.to_string_lossy().to_string();
    let password = "worker-e2e-measure-pass";

    let started = Instant::now();
    let session = WorkerSession::spawn(&worker, &dll).expect("启动 worker 失败");
    session.wait_for_ready_signal().expect("worker 就绪失败");
    let ready_ms = started.elapsed().as_millis();

    session
        .authorize_path("v4_create", "write", &vault)
        .expect("v4_create 路径授权失败");
    let started = Instant::now();
    let response = session
        .send_json(&serde_json::json!({
            "op": "v4_create",
            "path": vault,
            "password": password,
        }).to_string())
        .expect("v4_create 请求失败");
    assert!(json_ok(&response), "v4_create 失败: {response}");
    let create_ms = started.elapsed().as_millis();

    session
        .authorize_path("unlock", "read", &vault)
        .expect("unlock 路径授权失败");
    let started = Instant::now();
    let response = session
        .send_json(&serde_json::json!({
            "op": "unlock",
            "path": vault,
            "password": password,
        }).to_string())
        .expect("unlock 请求失败");
    assert!(json_ok(&response), "unlock 失败: {response}");
    let unlock_ms = started.elapsed().as_millis();

    /* G0-A2：每个尺寸视为一次独立导入批次（Begin → 各轮 → Commit）。
     * 旧 DLL 缺符号时打印一次不支持，后续尺寸继续按逐次锚点提交测量；
     * 符号已确认存在后再次失败属于真实错误，直接中止而不是静默回退。 */
    let mut defer_supported = false;
    let mut defer_probed = false;
    let mut size_reports: Vec<serde_json::Value> = Vec::with_capacity(photo_sizes.len());

    for (scenario, &photo_bytes) in photo_sizes.iter().enumerate() {
        let mut defer_active = false;
        if defer && (!defer_probed || defer_supported) {
            let response = session
                .send_json(r#"{"op":"bulk_import_begin"}"#)
                .expect("bulk_import_begin 请求失败");
            if json_ok(&response) {
                defer_active = true;
                defer_supported = true;
                println!(
                    "[worker-e2e] label={} photo={}MB bulk_import_begin=supported",
                    label,
                    mib_text(photo_bytes)
                );
            } else if defer_probed {
                panic!("bulk_import_begin 失败: photo={}MB resp={}", mib_text(photo_bytes), response);
            } else {
                println!(
                    "[worker-e2e] label={} bulk_import_begin=unsupported resp={}",
                    label, response
                );
            }
            defer_probed = true;
        }

        let mut rows: Vec<(u128, u128, u128)> = Vec::with_capacity(rounds);
        for round in 0..rounds {
            let started = Instant::now();
            let (add_ms, flush_ms) =
                import_one(&session, scenario, round, photo_bytes, batch, flush)
                    .expect("导入轮次失败");
            let total_ms = started.elapsed().as_millis();
            rows.push((add_ms, flush_ms, total_ms));
            println!(
                "[worker-e2e] label={} photo={}MB({}B) round={} add={}ms flush={}ms total={}ms",
                label,
                mib_text(photo_bytes),
                photo_bytes,
                round,
                add_ms,
                flush_ms,
                total_ms
            );
        }

        if defer_active {
            let response = session
                .send_json(r#"{"op":"bulk_import_commit"}"#)
                .expect("bulk_import_commit 请求失败");
            assert!(json_ok(&response), "bulk_import_commit 失败: {response}");
        }

        let import_total: u128 = rows.iter().map(|r| r.2).sum();
        let import_avg = import_total / rows.len().max(1) as u128;
        println!(
            "[worker-e2e] label={} photo={}MB bytes={} batch={} flush={} rounds={} ready={}ms create={}ms unlock={}ms import_avg={}ms import_total={}ms",
            label,
            mib_text(photo_bytes),
            photo_bytes,
            batch as u8,
            flush as u8,
            rounds,
            ready_ms,
            create_ms,
            unlock_ms,
            import_avg,
            import_total
        );

        let detail: Vec<serde_json::Value> = rows
            .iter()
            .map(|(add, flush, total)| {
                serde_json::json!({
                    "add_ms": add,
                    "flush_ms": flush,
                    "total_ms": total,
                })
            })
            .collect();
        size_reports.push(serde_json::json!({
            "photo_bytes": photo_bytes,
            "photo_mb": mib_text(photo_bytes),
            "defer_active": defer_active,
            "import_avg_ms": import_avg,
            "import_total_ms": import_total,
            "rounds_detail": detail,
        }));
    }

    let lock_resp = session.send_json(r#"{"op":"lock"}"#).unwrap_or_default();
    let _ = lock_resp;

    if let Some(path) = json_out {
        let report = serde_json::json!({
            "label": label,
            "worker": worker,
            "dll": dll,
            "batch": batch,
            "flush": flush,
            "defer": defer,
            "defer_probed": defer_probed,
            "defer_supported": defer_supported,
            "rounds": rounds,
            "ready_ms": ready_ms,
            "create_ms": create_ms,
            "unlock_ms": unlock_ms,
            "sizes": size_reports,
        });
        if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()) {
            panic!("写测量结果失败 {}: {e}", path);
        }
    }
}

/* ================================================================== *
 * 去重前置端到端：命中已提交条目键时必须在打开文件前跳过               *
 *                                                                    *
 * 用无效 JPEG 作为探针：若去重未前置，worker 必然因解码失败返回         *
 * skipped；返回 deduped 即证明命中发生在 open_file 之前。              *
 * ================================================================== */

fn dedupe_entry_key(name: &str, size: u64, mtime_ms: u64) -> String
{
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(format!("file|{}|{}|{}", name, size, mtime_ms).as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[test]
fn worker_dedupe_skips_before_open()
{
    if std::env::var("VERTHYS_WORKER_E2E").ok().as_deref() != Some("1") {
        eprintln!("worker dedupe e2e 跳过：未设置 VERTHYS_WORKER_E2E=1");
        return;
    }

    let worker = std::env::var("VERTHYS_WORKER_E2E_WORKER")
        .expect("缺少 VERTHYS_WORKER_E2E_WORKER");
    let dll = std::env::var("VERTHYS_WORKER_E2E_DLL")
        .expect("缺少 VERTHYS_WORKER_E2E_DLL");
    assert!(std::path::Path::new(&worker).is_file(), "worker 不存在: {worker}");
    assert!(std::path::Path::new(&dll).is_file(), "DLL 不存在: {dll}");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("创建 tokio runtime 失败");
    let _guard = runtime.enter();

    let dir = tempfile::tempdir().expect("创建去重测量临时目录失败");
    /* 故意写入非 JPEG 内容：只有去重前置才能让本次导入返回 deduped。 */
    let probe = dir.path().join("dedupe_probe.jpg");
    std::fs::write(&probe, vec![0x5Au8; 64 * 1024]).expect("写去重探针失败");
    let meta = std::fs::metadata(&probe).expect("读取探针元数据失败");
    let size = meta.len();
    let mtime_ms = meta
        .modified()
        .expect("读取探针 mtime 失败")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("探针 mtime 早于 Unix 纪元")
        .as_millis() as u64;
    let key = dedupe_entry_key("dedupe_probe.jpg", size, mtime_ms);

    let vault = dir.path().join("dedupe.verthys").to_string_lossy().to_string();
    let password = "worker-dedupe-e2e-pass";

    let session = WorkerSession::spawn(&worker, &dll).expect("启动 worker 失败");
    session.wait_for_ready_signal().expect("worker 就绪失败");
    session
        .authorize_path("v4_create", "write", &vault)
        .expect("v4_create 路径授权失败");
    let response = session
        .send_json(&serde_json::json!({
            "op": "v4_create",
            "path": vault,
            "password": password,
        }).to_string())
        .expect("v4_create 请求失败");
    assert!(json_ok(&response), "v4_create 失败: {response}");
    session
        .authorize_path("unlock", "read", &vault)
        .expect("unlock 路径授权失败");
    let response = session
        .send_json(&serde_json::json!({
            "op": "unlock",
            "path": vault,
            "password": password,
        }).to_string())
        .expect("unlock 请求失败");
    assert!(json_ok(&response), "unlock 失败: {response}");

    let path_text = probe.to_string_lossy().to_string();
    let run_job = |job_id: &str, committed: &[String]| -> serde_json::Value {
        session
            .send_json(&serde_json::json!({
                "op": "authorize_path_batch",
                "job_id": job_id,
                "paths": [path_text],
            }).to_string())
            .expect("authorize_path_batch 请求失败");
        let begin = session
            .send_json(&serde_json::json!({
                "op": "photo_import_job_begin",
                "job_id": job_id,
                "paths": [path_text],
                "committed_entry_keys": committed,
            }).to_string())
            .expect("photo_import_job_begin 请求失败");
        assert!(json_ok(&begin), "job_begin 失败: {begin}");
        let next = session
            .send_json(&serde_json::json!({
                "op": "photo_import_job_next",
                "job_id": job_id,
            }).to_string())
            .expect("photo_import_job_next 请求失败");
        let end = session
            .send_json(&serde_json::json!({
                "op": "photo_import_job_end",
                "job_id": job_id,
            }).to_string())
            .expect("photo_import_job_end 请求失败");
        assert!(json_ok(&end), "job_end 失败: {end}");
        serde_json::from_str(&next).expect("next 响应解析失败")
    };

    let started = Instant::now();
    let hit = run_job("dedupe-hit", std::slice::from_ref(&key));
    let hit_job_ms = started.elapsed().as_millis();
    assert!(
        hit_job_ms <= 2000,
        "单文件去重命中耗时 {}ms 超过 2s",
        hit_job_ms
    );
    let status = hit
        .get("photo")
        .and_then(|p| p.get("status"))
        .and_then(|s| s.as_str())
        .unwrap_or("?");
    assert_eq!(status, "deduped", "命中已提交键时必须前置跳过: {hit}");

    let miss = run_job("dedupe-miss", &[]);
    let status = miss
        .get("photo")
        .and_then(|p| p.get("status"))
        .and_then(|s| s.as_str())
        .unwrap_or("?");
    assert_ne!(status, "deduped", "无已提交键时不得被去重: {miss}");
    assert_eq!(status, "skipped", "无效 JPEG 未命中时应由打开/解码失败跳过: {miss}");

    println!("[worker-dedupe] hit=deduped hit_job_ms={hit_job_ms} miss={status} key={key}");
}
