//! 原生导出与备份还原端到端：original 明文、PNG、venc 容器、还原校验、
//! 预览 hash 不匹配拒绝与错误令牌拒绝。

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::worker::budget::PB_PHOTO_CHUNK_SIZE_BYTES;
use crate::worker::WorkerSession;

use super::common::{
    json_ok, native_add_record, native_add_staged, native_mb_label, native_send, native_send_ok,
    E2eStateGuard, NATIVE_MIB, TYPE_PHOTO_CHUNK, TYPE_PHOTO_META,
};
use super::read::{read_e2e_full, read_e2e_import, ReadE2ePhoto};

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
pub(super) fn restore_e2e_run(
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
