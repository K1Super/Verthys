//! worker/e2e_measure.rs — 导入数据面端到端测量（仅测试构建）
//!
//! 目的：用真实 `verthys-worker.exe` + 真实 `verthys.dll`，走与生产导入
//! 相同的 IPC 协议（签名信封、JSON、base64）测量：
//!   - worker 启动与就绪
//!   - 建库 / 解锁
//!   - 每张照片的块记录 add_records、meta add_records 与 flush
//!
//! 不包含：前端加密、缩略图生成、宿主 WAL 与命令层调度。
//! 由 `VERTHYS_WORKER_E2E=1` 启用；未设置时直接通过，避免影响常规测试。
//!
//! 环境变量：
//!   VERTHYS_WORKER_E2E_WORKER  worker 可执行文件（必填）
//!   VERTHYS_WORKER_E2E_DLL     verthys.dll（必填，须与 worker 构建期基线一致）
//!   VERTHYS_WORKER_E2E_LABEL   结果标签（默认 unknown）
//!   VERTHYS_WORKER_E2E_PHOTO_BYTES      单张照片精确字节数
//!   VERTHYS_WORKER_E2E_PHOTO_SIZES_MB   逗号分隔的小数 MiB 列表（如 10,17.73,24.43）
//!   VERTHYS_WORKER_E2E_PHOTO_MB         单张照片 MiB（未设置且无列表时跑 10/17.73/24.43 矩阵）
//!   VERTHYS_WORKER_E2E_ROUNDS  轮次（默认 3）
//!   VERTHYS_WORKER_E2E_BATCH=1 合并记录
//!   VERTHYS_WORKER_E2E_FLUSH=0 跳过 flush
//!   VERTHYS_WORKER_E2E_DEFER=1 批量导入锚点推迟（G0-A2 原型 DLL）
//!   VERTHYS_WORKER_E2E_JSON    可选：结果写入 JSON 文件
//!
//! 原生导入/读取/导出还原 E2E 分别由 VERTHYS_NATIVE_E2E、
//! VERTHYS_NATIVE_READ_E2E、VERTHYS_NATIVE_EXPORT_E2E 启用；
//! 可选 VERTHYS_NATIVE_EXPORT_E2E_OUT 落盘容器供前端兼容性复核，
//! VERTHYS_JS_VENC_E2E_DIR 指向前端 packVenc 产物供 worker 还原复核。

use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::worker::WorkerSession;
use super::budget::{PB_PHOTO_CHUNK_SIZE_BYTES};

/// 照片分块大小：取跨层预算单一权威值，不再保留本地副本。
const PHOTO_CHUNK_BYTES: usize = PB_PHOTO_CHUNK_SIZE_BYTES as usize;
/// 照片数据块记录类型。
const TYPE_PHOTO_CHUNK: u32 = 5;
/// 照片 meta 记录类型。
const TYPE_PHOTO_META: u32 = 1;

fn env_usize(name: &str, default: usize) -> usize
{
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

/// 解析待测照片尺寸（字节）。
///
/// 优先级：精确字节 > 小数 MB 列表 > 单值 MB > 缺省矩阵 10/17.73/24.43。
/// 支持 17.73、24.43 这类真实文件大小；10MB 只是最小样本，不是上限。
fn env_photo_sizes_bytes() -> Vec<usize>
{
    let mut sizes: Vec<usize> = Vec::new();

    if let Ok(raw) = std::env::var("VERTHYS_WORKER_E2E_PHOTO_BYTES") {
        if let Ok(v) = raw.trim().parse::<usize>() {
            if v > 0 {
                sizes.push(v);
            }
        }
    }
    if sizes.is_empty() {
        if let Ok(raw) = std::env::var("VERTHYS_WORKER_E2E_PHOTO_SIZES_MB") {
            for token in raw.split(',') {
                if let Ok(mb) = token.trim().parse::<f64>() {
                    if mb.is_finite() && mb > 0.0 {
                        sizes.push((mb * 1024.0 * 1024.0).round() as usize);
                    }
                }
            }
        }
    }
    if sizes.is_empty() {
        if let Ok(raw) = std::env::var("VERTHYS_WORKER_E2E_PHOTO_MB") {
            if let Ok(mb) = raw.trim().parse::<f64>() {
                if mb.is_finite() && mb > 0.0 {
                    sizes.push((mb * 1024.0 * 1024.0).round() as usize);
                }
            }
        }
    }
    if sizes.is_empty() {
        /* 缺省跑小矩阵：10MiB 只是最小样本，缺省也覆盖实拍大图尺寸。 */
        for mb in [10.0_f64, 17.73, 24.43] {
            sizes.push((mb * 1024.0 * 1024.0).round() as usize);
        }
    }
    sizes.dedup();
    sizes
}

/// 以 MiB（1024²）展示尺寸；与 Windows 资源管理器显示的“MB”口径一致。
fn mib_text(bytes: usize) -> String
{
    format!("{:.2}", bytes as f64 / (1024.0 * 1024.0))
}

fn json_ok(resp: &str) -> bool
{
    serde_json::from_str::<serde_json::Value>(resp)
        .ok()
        .and_then(|v| v.get("ok").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

/// 单次 add_records 的 base64 载荷上限（与 worker/IPC 预算一致，留出余量）。
const ADD_RECORDS_PAYLOAD_BUDGET: usize = 12 * 1024 * 1024;

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

/* ================================================================== *
 * 原生照片导入协议端到端（真实 worker + 真实 DLL）                    *
 *                                                                    *
 * 由 VERTHYS_NATIVE_E2E=1 启用；走 worker 的 photo_import_job_* 原生  *
 * 协议，逐块写记录、收尾解 meta，覆盖超限、混合批量、源文件移动与取消。*
 * ================================================================== */

const NATIVE_MIB: u64 = 1024 * 1024;
const NATIVE_CHUNK_BYTES: usize = PB_PHOTO_CHUNK_SIZE_BYTES as usize;
/// 单个协议请求的超时：一次 next/add_records 可能承载整块 4MiB 密文。
const NATIVE_OP_TIMEOUT: Duration = Duration::from_secs(120);

fn native_chunk_total(size: u64) -> usize
{
    size.div_ceil(NATIVE_CHUNK_BYTES as u64) as usize
}

fn native_mb_label(mb: f64) -> String
{
    if mb.fract() == 0.0 {
        format!("{}", mb as u64)
    } else {
        format!("{}", mb)
    }
}

fn native_send(
    session: &WorkerSession,
    request: serde_json::Value,
) -> Result<serde_json::Value, String>
{
    let op = request
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let raw = session
        .send_json_with_timeout(&request.to_string(), NATIVE_OP_TIMEOUT)
        .map_err(|e| format!("{op} 请求失败: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("{op} 响应解析失败: {e}"))
}

fn native_send_ok(
    session: &WorkerSession,
    request: serde_json::Value,
) -> Result<serde_json::Value, String>
{
    let op = request
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let value = native_send(session, request)?;
    if value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        return Ok(value);
    }
    let detail = value
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("无错误信息");
    Err(format!("{op} 失败: {detail}"))
}

/// 写入单条记录并返回 C 层分配的 ID；ID=0 视为失败（finish 明确拒绝 0）。
fn native_add_record(
    session: &WorkerSession,
    rtype: u32,
    name: &str,
    data_b64: &str,
) -> Result<u64, String>
{
    let value = native_send_ok(
        session,
        serde_json::json!({
            "op": "add_records",
            "records": [{"rtype": rtype, "name": name, "data": data_b64}],
        }),
    )?;
    let ids = value
        .get("ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("add_records 响应缺少 ids: name={name}"))?;
    if ids.len() != 1 {
        return Err(format!(
            "add_records 返回 {} 个 id（期望 1）: name={name}",
            ids.len()
        ));
    }
    let id = ids[0]
        .as_u64()
        .ok_or_else(|| format!("add_records id 非法: name={name}"))?;
    if id == 0 {
        return Err(format!("add_records 返回 id=0: name={name}"));
    }
    Ok(id)
}

/// 提交一块 worker 暂存密文（引用提交，不携带密文）。
fn native_add_staged(
    session: &WorkerSession,
    job_id: &str,
    rtype: u32,
    name: &str,
    chunk_key: &str,
    chunk_hash: &str,
) -> Result<u64, String>
{
    let value = native_send_ok(
        session,
        serde_json::json!({
            "op": "add_records_staged",
            "staged_records": [{
                "rtype": rtype,
                "name": name,
                "job_id": job_id,
                "chunk_key": chunk_key,
                "chunk_hash": chunk_hash,
            }],
        }),
    )?;
    let ids = value
        .get("ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("add_records_staged 响应缺少 ids: name={name}"))?;
    if ids.len() != 1 {
        return Err(format!(
            "add_records_staged 返回 {} 个 id（期望 1）: name={name}",
            ids.len()
        ));
    }
    let id = ids[0]
        .as_u64()
        .ok_or_else(|| format!("add_records_staged id 非法: name={name}"))?;
    if id == 0 {
        return Err(format!("add_records_staged 返回 id=0: name={name}"));
    }
    Ok(id)
}

#[derive(Default)]
struct NativeTotals {
    files: usize,
    chunks: usize,
    bytes: u64,
}

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
fn native_import_job(
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

/// E2E 安全状态隔离：把 rollback/lockout 状态写入临时目录，避免消耗
/// 真实环境有限的 rollback.state 槽位。仅测试构建的 DLL 识别该变量。
static E2E_STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct E2eStateGuard {
    dir: tempfile::TempDir,
    previous: Option<std::ffi::OsString>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl E2eStateGuard {
    fn new() -> Self {
        let lock = E2E_STATE_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let dir = tempfile::tempdir().expect("创建 E2E 状态目录失败");
        let previous = std::env::var_os("VERTHYS_TEST_STATE_DIR");
        std::env::set_var("VERTHYS_TEST_STATE_DIR", dir.path());
        Self {
            dir,
            previous,
            _lock: lock,
        }
    }

    /// 隔离目录中的回退状态文件路径；用于断言测试构建确实使用了该目录。
    fn rollback_state_path(&self) -> std::path::PathBuf {
        self.dir.path().join("rollback.state")
    }
}

impl Drop for E2eStateGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var("VERTHYS_TEST_STATE_DIR", value),
            None => std::env::remove_var("VERTHYS_TEST_STATE_DIR"),
        }
    }
}

#[test]
fn e2e_state_guard_sets_and_restores_isolated_dir() {
    let previous = std::env::var_os("VERTHYS_TEST_STATE_DIR");
    let isolated;
    {
        let guard = E2eStateGuard::new();
        isolated = guard.dir.path().to_path_buf();
        assert_eq!(
            std::env::var_os("VERTHYS_TEST_STATE_DIR"),
            Some(isolated.clone().into_os_string())
        );
        assert!(!guard.rollback_state_path().exists());
    }
    assert_eq!(std::env::var_os("VERTHYS_TEST_STATE_DIR"), previous);
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

/* ================================================================== *
 * 原生读取协议端到端（真实 worker + 真实 DLL）                        *
 *                                                                    *
 * 覆盖：预览命中、删除后的懒生成与写回、名称索引定位、删除级联预览    *
 * ID、原图逐块解密后与源文件逐字节比对、取消、布局不支持的结构化错误  *
 * 码。由 VERTHYS_NATIVE_READ_E2E=1 启用；未设置时直接通过。           *
 * ================================================================== */

const TYPE_PHOTO_PREVIEW: u32 = 11;
/// JPEG 起始/结束标记：预览必须是一张完整可解码的 JPEG。
const READ_E2E_JPEG_SOI: [u8; 2] = [0xFF, 0xD8];
const READ_E2E_JPEG_EOI: [u8; 2] = [0xFF, 0xD9];

struct ReadE2ePhoto {
    meta_id: u64,
    chunk_total: usize,
    preview_name: String,
    preview_id: u64,
    /// 源文件 BLAKE3（导入事件返回；导出/还原用例作为预览哈希输入）
    file_hash: String,
}

/// 小样本暂存链路冒烟：真实 worker + DLL，验证「密文不出 worker、
/// 引用提交、跨块分组」全链路。由 VERTHYS_NATIVE_STAGED_E2E=1 启用。
#[test]
fn worker_native_staged_smoke_e2e()
{
    if std::env::var("VERTHYS_NATIVE_STAGED_E2E").ok().as_deref() != Some("1") {
        eprintln!("native staged smoke 跳过：未设置 VERTHYS_NATIVE_STAGED_E2E=1");
        return;
    }
    let _state_guard = E2eStateGuard::new();
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

    let dir = tempfile::tempdir().expect("创建暂存冒烟临时目录失败");
    let fixture = dir.path().join("staged_smoke.jpg");
    /* 1x1 有效 JPEG + 尾部填充：跨过 4MiB 分块边界，覆盖 2 块暂存。
     * 尾部字节只参与整文件哈希，不影响 JPEG 解码。 */
    const ONE_PX_JPEG_B64: &str = "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPDs0NDP/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AVN//2Q==";
    let mut bytes = STANDARD
        .decode(ONE_PX_JPEG_B64)
        .expect("内置 JPEG 解码失败");
    let target = NATIVE_CHUNK_BYTES + 12345;
    bytes.resize(target, 0);
    std::fs::write(&fixture, &bytes).expect("写入暂存冒烟样本失败");

    let vault = dir
        .path()
        .join("staged_smoke.verthys")
        .to_string_lossy()
        .to_string();
    let password = "staged-smoke-pass";
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
    /* 隔离目录必须真实生效：v4_create 收尾提交会在该目录写入 rollback.state。
     * 若缺失，说明 DLL 未识别测试钩子或回落到了生产状态目录。 */
    assert!(
        _state_guard.rollback_state_path().is_file(),
        "E2E 隔离目录未生成 rollback.state: {}",
        _state_guard.rollback_state_path().display()
    );
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

    let mut totals = NativeTotals::default();
    let mut reports = Vec::new();
    let mut violations = Vec::new();
    native_import_job(
        &session,
        "staged-smoke-1",
        &[fixture.to_string_lossy().to_string()],
        &mut totals,
        &mut reports,
        &mut violations,
    )
    .expect("暂存导入失败");

    assert_eq!(totals.files, 1, "reports={reports:?}");
    assert!(totals.chunks >= 2, "样本应跨块: chunks={}", totals.chunks);
    assert_eq!(totals.bytes, target as u64);
    assert!(violations.is_empty(), "violations={violations:?}");
    println!(
        "[native-staged-smoke] bytes={} chunks={} reports={reports:?}",
        totals.bytes, totals.chunks
    );
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
fn read_e2e_import(
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
fn read_e2e_full(
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

/* ================================================================== *
 * 原生导出与备份还原端到端（真实 worker + 真实 DLL）                  *
 *                                                                    *
 * 覆盖：original 明文逐字节、PNG 签名、venc-single/multiple 容器头、   *
 * 还原后逐块读取与源文件一致、预览 hash 不匹配拒绝、错误令牌拒绝。      *
 * 由 VERTHYS_NATIVE_EXPORT_E2E=1 启用；未设置时直接通过。             *
 * ================================================================== */

const EXPORT_E2E_PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

struct ExportE2eResult {
    files: Vec<Vec<u8>>,
    photos: Vec<(u32, String, String)>,
}

/// 跑完一个导出 job；按 file_end 顺序返回每个文件的完整字节。
fn export_e2e_run(
    session: &WorkerSession,
    job_id: &str,
    ids: &[u64],
    format: &str,
    token: Option<&str>,
) -> Result<ExportE2eResult, String>
{
    let mut begin = serde_json::json!({
        "op": "photo_export_job_begin",
        "job_id": job_id,
        "ids": ids,
        "format": format,
    });
    if let Some(token) = token {
        begin["token"] = serde_json::json!(token);
    }
    native_send_ok(session, begin)?;

    let mut files: Vec<Vec<u8>> = Vec::new();
    let mut current: Option<Vec<u8>> = None;
    let mut photos: Vec<(u32, String, String)> = Vec::new();

    let outcome = (|| -> Result<(), String> {
        loop {
            let value = native_send_ok(
                session,
                serde_json::json!({"op": "photo_export_job_next", "job_id": job_id}),
            )?;
            let event = value
                .get("photo_export")
                .ok_or_else(|| format!("{job_id}: next 缺少 photo_export"))?;
            match event.get("status").and_then(|v| v.as_str()).unwrap_or("") {
                "file_begin" => {
                    if current.is_some() {
                        return Err(format!("{job_id}: 重复 file_begin"));
                    }
                    current = Some(Vec::new());
                }
                "segment" => {
                    let data_b64 = event
                        .get("data_b64")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("{job_id}: segment 缺少 data_b64"))?;
                    let bytes = STANDARD
                        .decode(data_b64)
                        .map_err(|e| format!("{job_id}: segment 解码失败: {e}"))?;
                    if bytes.len() > PB_PHOTO_CHUNK_SIZE_BYTES as usize {
                        return Err(format!("{job_id}: segment 超过 4MiB: {}", bytes.len()));
                    }
                    current
                        .as_mut()
                        .ok_or_else(|| format!("{job_id}: segment 先于 file_begin"))?
                        .extend_from_slice(&bytes);
                }
                "file_end" => {
                    let file = current
                        .take()
                        .ok_or_else(|| format!("{job_id}: file_end 缺少当前文件"))?;
                    if event.get("file_ok").and_then(|v| v.as_bool()) != Some(true) {
                        return Err(format!("{job_id}: file_ok=false"));
                    }
                    files.push(file);
                }
                "photo" => {
                    let index = event
                        .get("file_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let name = event
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let status = event
                        .get("photo_status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let reason = event
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if status != "ok" {
                        return Err(format!("{job_id}: 照片 {name} 导出失败: {reason}"));
                    }
                    photos.push((index, name, status));
                }
                "done" => break,
                "cancelled" => return Err(format!("{job_id}: 导出被取消")),
                other => return Err(format!("{job_id}: 未知导出状态 {other}")),
            }
        }
        Ok(())
    })();

    let end = native_send_ok(
        session,
        serde_json::json!({"op": "photo_export_job_end", "job_id": job_id}),
    );
    outcome?;
    end?;
    if let Some(file) = current {
        return Err(format!("{job_id}: 导出结束时仍有未关闭文件（{} 字节）", file.len()));
    }
    Ok(ExportE2eResult { files, photos })
}

/// 还原一个容器：写入块与 meta，随后按块读取与源文件逐字节比对。
fn restore_e2e_run(
    session: &WorkerSession,
    job_id: &str,
    path: &std::path::Path,
    token: &str,
    expected_hashes: &[String],
    sources: &[Vec<u8>],
) -> Result<usize, String>
{
    let path_text = path.to_string_lossy().to_string();
    native_send_ok(
        session,
        serde_json::json!({
            "op": "authorize_path_batch",
            "job_id": job_id,
            "paths": [path_text],
            "target_op": "photo_restore",
        }),
    )?;
    native_send_ok(
        session,
        serde_json::json!({
            "op": "photo_restore_job_begin",
            "job_id": job_id,
            "path": path_text,
            "token": token,
            "expected_hashes": expected_hashes,
        }),
    )?;

    let mut chunk_ids: Vec<u64> = Vec::new();
    let mut photo_index = 0u32;
    let mut restored = 0usize;

    let outcome = (|| -> Result<(), String> {
        loop {
            let value = native_send_ok(
                session,
                serde_json::json!({"op": "photo_restore_job_next", "job_id": job_id}),
            )?;
            let photo = value
                .get("photo")
                .ok_or_else(|| format!("{job_id}: next 缺少 photo"))?;
            match photo.get("status").and_then(|v| v.as_str()).unwrap_or("") {
                "photo" => {
                    photo_index = photo
                        .get("file_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    chunk_ids.clear();
                }
                "chunk" => {
                    let seq = photo
                        .get("chunk_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize;
                    if seq != chunk_ids.len() {
                        return Err(format!(
                            "{job_id}: 还原块序号乱序 seq={seq} 期望={}",
                            chunk_ids.len()
                        ));
                    }
                    let chunk_key = photo
                        .get("chunk_key")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("{job_id}: chunk 缺少 chunk_key"))?;
                    let chunk_hash = photo
                        .get("chunk_hash")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("{job_id}: chunk 缺少 chunk_hash"))?;
                    if photo.get("chunk_staged").and_then(|v| v.as_bool()) != Some(true) {
                        return Err(format!("{job_id}: 还原块未启用暂存 (seq={seq})"));
                    }
                    if photo.get("chunk_b64").is_some() {
                        return Err(format!("{job_id}: 还原暂存块仍携带 chunk_b64 (seq={seq})"));
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

                    let total = photo
                        .get("chunk_total")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize;
                    if chunk_ids.len() != total {
                        continue;
                    }
                    let finish = native_send_ok(
                        session,
                        serde_json::json!({
                            "op": "photo_restore_photo_finish",
                            "job_id": job_id,
                            "chunk_ids": chunk_ids,
                        }),
                    )?;
                    let meta_b64 = finish
                        .get("photo_finish")
                        .and_then(|p| p.get("meta_b64"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("{job_id}: 收尾缺少 meta_b64"))?;
                    let record_name = format!("parsed_e2e_{}_{}", job_id, photo_index);
                    let meta_id = native_add_record(
                        session,
                        TYPE_PHOTO_META,
                        &record_name,
                        meta_b64,
                    )?;
                    let found = native_send_ok(
                        session,
                        serde_json::json!({"op": "find_lid_by_name", "name": record_name}),
                    )?;
                    if found.get("id").and_then(|v| v.as_u64()) != Some(meta_id) {
                        return Err(format!("{job_id}: 名称索引未指向还原 meta {meta_id}"));
                    }
                    let source = sources
                        .get(photo_index as usize)
                        .ok_or_else(|| format!("{job_id}: 缺少源文件 {photo_index}"))?;
                    read_e2e_full(
                        session,
                        &format!("{job_id}-read-{photo_index}"),
                        meta_id,
                        source,
                    )?;
                    restored += 1;
                    chunk_ids.clear();
                }
                "done" => break,
                "cancelled" => return Err(format!("{job_id}: 还原被取消")),
                other => return Err(format!("{job_id}: 未知还原状态 {other}")),
            }
        }
        Ok(())
    })();

    let end = native_send_ok(
        session,
        serde_json::json!({"op": "photo_restore_job_end", "job_id": job_id}),
    );
    outcome?;
    end?;
    Ok(restored)
}

#[test]
fn worker_native_export_restore_e2e() -> Result<(), String>
{
    if std::env::var("VERTHYS_NATIVE_EXPORT_E2E").ok().as_deref() != Some("1") {
        eprintln!("native export e2e 跳过：未设置 VERTHYS_NATIVE_EXPORT_E2E=1");
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

    let fixtures: Vec<(std::path::PathBuf, u64)> = [10.0_f64, 17.73]
        .iter()
        .map(|mb| {
            (
                fixture_dir.join(format!("jpeg_{}.jpg", native_mb_label(*mb))),
                (*mb * NATIVE_MIB as f64).round() as u64,
            )
        })
        .collect();
    for (path, size) in &fixtures {
        let actual = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        assert!(
            actual == *size,
            "样本 {} 字节为 {}（期望 {}）",
            path.display(),
            actual,
            size
        );
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("创建 tokio runtime 失败");
    let _guard = runtime.enter();

    let dir = tempfile::tempdir().expect("创建导出用例临时目录失败");
    let vault = dir.path().join("native_export_e2e.verthys").to_string_lossy().to_string();
    let password = "native-e2e-export-pass";
    let token = "native-e2e-export-token";

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

    let mut imported: Vec<ReadE2ePhoto> = Vec::new();
    let mut sources: Vec<Vec<u8>> = Vec::new();
    for (index, (path, size)) in fixtures.iter().enumerate() {
        let photo = read_e2e_import(
            &session,
            &format!("export-e2e-import-{index}"),
            path,
            *size,
        )
        .unwrap_or_else(|e| panic!("导入 {} 失败: {e}", path.display()));
        sources.push(std::fs::read(path).expect("读取源文件失败"));
        imported.push(photo);
    }
    let ids: Vec<u64> = imported.iter().map(|p| p.meta_id).collect();
    let hashes: Vec<String> = imported.iter().map(|p| p.file_hash.clone()).collect();

    /* ===== original：逐字节等于源文件 ===== */
    let original = export_e2e_run(
        &session,
        "export-e2e-original",
        &[ids[0]],
        "original",
        None,
    )?;
    assert_eq!(original.files.len(), 1, "original 应产出 1 个文件");
    assert_eq!(original.photos.len(), 1, "original 应记录 1 张照片结果");
    assert_eq!(original.files[0], sources[0], "original 字节必须与源文件一致");
    println!(
        "[native-export-e2e] original bytes={}",
        original.files[0].len()
    );

    /* ===== PNG：签名与体积 ===== */
    let png = export_e2e_run(&session, "export-e2e-png", &[ids[0]], "png", None)?;
    assert_eq!(png.files.len(), 1, "png 应产出 1 个文件");
    assert_eq!(png.photos.len(), 1, "png 应记录 1 张照片结果");
    assert!(
        png.files[0].starts_with(&EXPORT_E2E_PNG_SIG),
        "PNG 签名不符"
    );
    assert!(png.files[0].len() > 1024, "PNG 体积异常");
    println!("[native-export-e2e] png bytes={}", png.files[0].len());

    /* ===== venc-single + 还原 ===== */
    let single = export_e2e_run(
        &session,
        "export-e2e-single",
        &ids,
        "venc-single",
        Some(token),
    )?;
    assert_eq!(single.files.len(), 1, "venc-single 应产出 1 个容器");
    assert_eq!(single.photos.len(), 2, "venc-single 应记录 2 张照片结果");
    assert_eq!(&single.files[0][..4], b"VENC", "容器魔数不符");
    assert_eq!(
        u16::from_be_bytes([single.files[0][4], single.files[0][5]]),
        3,
        "容器版本必须为 3"
    );
    let single_path = dir.path().join("single.venc");
    std::fs::write(&single_path, &single.files[0]).expect("写 single.venc 失败");
    let restored = restore_e2e_run(
        &session,
        "export-e2e-restore-single",
        &single_path,
        token,
        &hashes,
        &sources,
    )?;
    assert_eq!(restored, 2, "venc-single 应还原 2 张");
    println!(
        "[native-export-e2e] single container bytes={} restored={restored}",
        single.files[0].len()
    );

    /* ===== venc-multiple + 每张独立还原 ===== */
    let multiple = export_e2e_run(
        &session,
        "export-e2e-multiple",
        &ids,
        "venc-multiple",
        Some(token),
    )?;
    assert_eq!(multiple.files.len(), 2, "venc-multiple 应产出 2 个容器");
    assert_eq!(multiple.photos.len(), 2, "venc-multiple 应记录 2 张照片结果");
    for (index, file) in multiple.files.iter().enumerate() {
        let path = dir.path().join(format!("multi_{index}.venc"));
        std::fs::write(&path, file).expect("写 multi.venc 失败");
        let restored = restore_e2e_run(
            &session,
            &format!("export-e2e-restore-multi-{index}"),
            &path,
            token,
            &[hashes[index].clone()],
            &[sources[index].clone()],
        )?;
        assert_eq!(restored, 1, "venc-multiple 第 {index} 个容器应还原 1 张");
    }
    println!("[native-export-e2e] multiple containers={}", multiple.files.len());

    /* ===== 取消：导出与还原在 job 边界立即收敛 ===== */
    native_send_ok(
        &session,
        serde_json::json!({
            "op": "photo_export_job_begin",
            "job_id": "export-e2e-cancel",
            "ids": [ids[0]],
            "format": "venc-single",
            "token": token,
        }),
    )?;
    native_send_ok(
        &session,
        serde_json::json!({"op": "photo_export_job_next", "job_id": "export-e2e-cancel"}),
    )?;
    native_send_ok(
        &session,
        serde_json::json!({"op": "photo_export_job_cancel", "job_id": "export-e2e-cancel"}),
    )?;
    let export_cancelled = native_send_ok(
        &session,
        serde_json::json!({"op": "photo_export_job_next", "job_id": "export-e2e-cancel"}),
    )?;
    assert_eq!(
        export_cancelled
            .get("photo_export")
            .and_then(|e| e.get("status"))
            .and_then(|v| v.as_str()),
        Some("cancelled"),
        "导出取消后状态必须为 cancelled"
    );
    native_send_ok(
        &session,
        serde_json::json!({"op": "photo_export_job_end", "job_id": "export-e2e-cancel"}),
    )?;

    native_send_ok(
        &session,
        serde_json::json!({
            "op": "authorize_path_batch",
            "job_id": "export-e2e-restore-cancel",
            "paths": [single_path.to_string_lossy().to_string()],
            "target_op": "photo_restore",
        }),
    )?;
    native_send_ok(
        &session,
        serde_json::json!({
            "op": "photo_restore_job_begin",
            "job_id": "export-e2e-restore-cancel",
            "path": single_path.to_string_lossy().to_string(),
            "token": token,
            "expected_hashes": hashes,
        }),
    )?;
    native_send_ok(
        &session,
        serde_json::json!({"op": "photo_restore_job_cancel", "job_id": "export-e2e-restore-cancel"}),
    )?;
    let restore_cancelled = native_send_ok(
        &session,
        serde_json::json!({"op": "photo_restore_job_next", "job_id": "export-e2e-restore-cancel"}),
    )?;
    assert_eq!(
        restore_cancelled
            .get("photo")
            .and_then(|p| p.get("status"))
            .and_then(|v| v.as_str()),
        Some("cancelled"),
        "还原取消后状态必须为 cancelled"
    );
    native_send_ok(
        &session,
        serde_json::json!({"op": "photo_restore_job_end", "job_id": "export-e2e-restore-cancel"}),
    )?;
    println!("[native-export-e2e] cancel statuses verified");

    /* 可选：把容器落盘供 JS 兼容性复核（前端 packVenc/unpackVenc 双向） */
    if let Ok(out_dir) = std::env::var("VERTHYS_NATIVE_EXPORT_E2E_OUT") {
        let out = std::path::PathBuf::from(out_dir);
        std::fs::create_dir_all(&out)
            .map_err(|e| format!("创建 JS 复核目录失败: {e}"))?;
        std::fs::write(out.join("single.venc"), &single.files[0])
            .map_err(|e| format!("写 single.venc 失败: {e}"))?;
        for (index, file) in multiple.files.iter().enumerate() {
            std::fs::write(out.join(format!("multi_{index}.venc")), file)
                .map_err(|e| format!("写 multi_{index}.venc 失败: {e}"))?;
        }
        let meta = serde_json::json!({
            "token": token,
            "hashes": hashes,
            "photos": imported
                .iter()
                .map(|p| serde_json::json!({
                    "metaId": p.meta_id,
                    "chunkTotal": p.chunk_total,
                    "fileHash": p.file_hash,
                }))
                .collect::<Vec<_>>(),
        });
        std::fs::write(
            out.join("export_meta.json"),
            serde_json::to_vec_pretty(&meta).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("写 export_meta.json 失败: {e}"))?;
        println!("[native-export-e2e] dumped containers to {}", out.display());
    }

    /* ===== 预览 hash 不匹配：必须拒绝 ===== */
    let mut reversed = hashes.clone();
    reversed.reverse();
    native_send_ok(
        &session,
        serde_json::json!({
            "op": "authorize_path_batch",
            "job_id": "export-e2e-replaced",
            "paths": [single_path.to_string_lossy().to_string()],
            "target_op": "photo_restore",
        }),
    )?;
    native_send_ok(
        &session,
        serde_json::json!({
            "op": "photo_restore_job_begin",
            "job_id": "export-e2e-replaced",
            "path": single_path.to_string_lossy().to_string(),
            "token": token,
            "expected_hashes": reversed,
        }),
    )?;
    let replaced = native_send(
        &session,
        serde_json::json!({"op": "photo_restore_job_next", "job_id": "export-e2e-replaced"}),
    )?;
    native_send_ok(
        &session,
        serde_json::json!({"op": "photo_restore_job_end", "job_id": "export-e2e-replaced"}),
    )?;
    assert_eq!(
        replaced.get("ok").and_then(|v| v.as_bool()),
        Some(false),
        "预览哈希不匹配必须失败"
    );
    assert!(
        replaced
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("已变更"),
        "预览哈希不匹配错误文案不符: {:?}",
        replaced.get("error")
    );
    println!("[native-export-e2e] replaced container rejected");

    /* ===== 错误令牌：必须认证失败 ===== */
    native_send_ok(
        &session,
        serde_json::json!({
            "op": "authorize_path_batch",
            "job_id": "export-e2e-wrong-token",
            "paths": [single_path.to_string_lossy().to_string()],
            "target_op": "photo_restore",
        }),
    )?;
    let wrong = native_send(
        &session,
        serde_json::json!({
            "op": "photo_restore_job_begin",
            "job_id": "export-e2e-wrong-token",
            "path": single_path.to_string_lossy().to_string(),
            "token": "wrong-token-0000",
            "expected_hashes": hashes,
        }),
    )?;
    assert_eq!(wrong.get("ok").and_then(|v| v.as_bool()), Some(false));
    assert!(
        wrong
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("TAG_VERIFICATION_FAILED"),
        "错误令牌未归因为认证失败: {:?}",
        wrong.get("error")
    );
    println!("[native-export-e2e] wrong token rejected");

    println!("[native-export-e2e] SUMMARY photos={}", sources.len());
    Ok(())
}

/// JS `packVenc` 产物还原：验证 worker 能解析旧/前端生成的容器。
///
/// 目录契约（由前端临时脚本生成）：
///   js_fixture.venc  容器字节
///   js_fixture.json  { token, fileHash, chunksHex: [..] }
#[test]
fn worker_native_js_fixture_e2e() -> Result<(), String>
{
    if std::env::var("VERTHYS_JS_VENC_E2E").ok().as_deref() != Some("1") {
        eprintln!("js fixture e2e 跳过：未设置 VERTHYS_JS_VENC_E2E=1");
        return Ok(());
    }
    let worker = std::env::var("VERTHYS_WORKER_E2E_WORKER")
        .expect("缺少 VERTHYS_WORKER_E2E_WORKER");
    let dll = std::env::var("VERTHYS_WORKER_E2E_DLL")
        .expect("缺少 VERTHYS_WORKER_E2E_DLL");
    let fixture_dir = std::path::PathBuf::from(
        std::env::var("VERTHYS_JS_VENC_E2E_DIR").expect("缺少 VERTHYS_JS_VENC_E2E_DIR"),
    );
    let venc_path = fixture_dir.join("js_fixture.venc");
    let meta_path = fixture_dir.join("js_fixture.json");
    let venc_bytes = std::fs::read(&venc_path)
        .map_err(|e| format!("读取 {} 失败: {e}", venc_path.display()))?;
    let meta_raw = std::fs::read(&meta_path)
        .map_err(|e| format!("读取 {} 失败: {e}", meta_path.display()))?;
    let meta: serde_json::Value =
        serde_json::from_slice(&meta_raw).map_err(|e| format!("fixture JSON 解析失败: {e}"))?;
    let token = meta
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "fixture 缺少 token".to_string())?;
    let file_hash = meta
        .get("fileHash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "fixture 缺少 fileHash".to_string())?
        .to_string();
    let mut source: Vec<u8> = Vec::new();
    for chunk in meta
        .get("chunksHex")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "fixture 缺少 chunksHex".to_string())?
    {
        let hex = chunk
            .as_str()
            .ok_or_else(|| "chunksHex 项不是字符串".to_string())?;
        if !hex.len().is_multiple_of(2) {
            return Err("chunksHex 长度非法".to_string());
        }
        for i in 0..hex.len() / 2 {
            let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("chunksHex 解析失败: {e}"))?;
            source.push(byte);
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("创建 tokio runtime 失败");
    let _guard = runtime.enter();

    let dir = tempfile::tempdir().expect("创建 JS fixture 临时目录失败");
    let vault = dir.path().join("js_fixture.verthys").to_string_lossy().to_string();
    let password = "js-fixture-e2e-pass";
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

    let restored = restore_e2e_run(
        &session,
        "js-fixture-restore",
        &venc_path,
        token,
        &[file_hash],
        &[source.clone()],
    )?;
    assert_eq!(restored, 1, "JS 容器应还原 1 张");
    println!(
        "[js-venc-e2e] container bytes={} restored={restored}",
        venc_bytes.len()
    );
    Ok(())
}


