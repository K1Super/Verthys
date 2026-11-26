//! JS `packVenc` 产物还原：验证 worker 能解析旧/前端生成的容器。
//!
//! 目录契约（由前端临时脚本生成）：
//!   js_fixture.venc  容器字节
//!   js_fixture.json  { token, fileHash, chunksHex: [..] }

use crate::worker::WorkerSession;

use super::common::json_ok;
use super::export_restore::restore_e2e_run;

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
