//! 小样本暂存链路冒烟：真实 worker + DLL，验证「密文不出 worker、
//! 引用提交、跨块分组」全链路。

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::worker::WorkerSession;

use super::common::{json_ok, E2eStateGuard, NativeTotals, NATIVE_CHUNK_BYTES};
use super::native_import::native_import_job;

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
