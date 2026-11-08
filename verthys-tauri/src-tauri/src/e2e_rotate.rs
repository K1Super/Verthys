/*
 * e2e_rotate.rs — Tauri 宿主层全库 DEK 轮换集成用例（测试专用）
 *
 * 仅在启用 `e2e_rotate` 特性且设置 VERTHYS_E2E_ROTATE=1 时由入口派发。
 * 目的：用真实 AppHandle / AppState / worker 子进程 / DLL 验证以下链路，
 * 而不是只测 worker IPC 或 C 公共 API：
 *   worker_init → 创建容器（返回恢复码）→ 写记录 → 启用模块 →
 *   锁库 → 恢复码解锁 → 轮换 Begin/UnlockModule/Run/Abort →
 *   轮换 Begin/UnlockModule/Run/Commit → 读回记录 → 清理
 *
 * 安全边界：
 *   - 容器口令由本机保管模块生成，不经过前端与本模块；
 *   - 恢复码、模块口令只在本进程内存中存在，不写日志；
 *   - 结果文件只包含步骤名与错误码，不含任何密钥/明文。
 */

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tauri::Manager;
use zeroize::Zeroizing;

use crate::controller::types::VerthysResponse;
use crate::controller::module_controller::verthys_module_enable;
use crate::controller::vault_rotate_controller::{
    verthys_rotate_abort, verthys_rotate_attach_keyfile, verthys_rotate_begin,
    verthys_rotate_cancel, verthys_rotate_commit, verthys_rotate_run,
    verthys_rotate_unlock_module,
};
use crate::controller::verthys_controller::{
    verthys_add_record, verthys_create, verthys_get_record, verthys_lock, verthys_lock_persist,
    verthys_unlock_recovery,
};
use crate::controller::worker_controller::{worker_destroy, worker_init};
use crate::service::vault_rotate::RotateProgress;
use crate::state::AppState;

/// 模块口令（与容器口令无关；仅测试进程内存）
const MODULE_PASSWORD: &str = "rotate-e2e-module-pw";
/// 记录载荷（用于提交后读回校验）
const RECORD_PAYLOAD: &[u8] = b"rotate-payload";
/// 记录类型 accounts（不受模块 0 保护，提交后可直接读回）
const RECORD_TYPE_ACCOUNTS: u32 = 2;

fn expect_ok(
    label: &str,
    result: Result<VerthysResponse, String>,
) -> Result<VerthysResponse, String> {
    match result {
        Ok(resp) if resp.ok => Ok(resp),
        Ok(resp) => Err(format!(
            "{}: {}",
            label,
            resp.error.unwrap_or_else(|| "unknown".into())
        )),
        Err(e) => Err(format!("{}: {}", label, e)),
    }
}

/// 断言失败且错误码精确匹配（轮换边界用例）。
fn expect_err_code(
    label: &str,
    result: Result<VerthysResponse, String>,
    code: &str,
) -> Result<(), String> {
    match result {
        Ok(resp) if !resp.ok && resp.error.as_deref() == Some(code) => Ok(()),
        Ok(resp) => Err(format!(
            "{}: 期望 {}，实际 ok={} error={:?}",
            label, code, resp.ok, resp.error
        )),
        Err(e) => Err(format!("{}: 期望 {}，实际通信错误 {}", label, code, e)),
    }
}

fn sandbox_dir() -> Result<PathBuf, String> {
    let raw = std::env::var("VERTHYS_E2E_ROTATE_DIR")
        .map_err(|_| "缺少 VERTHYS_E2E_ROTATE_DIR".to_string())?;
    let dir = PathBuf::from(&raw);
    if !dir.is_absolute() {
        return Err("VERTHYS_E2E_ROTATE_DIR 必须是绝对路径".into());
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建沙箱目录失败: {}", e))?;
    Ok(dir)
}

fn state(app: &tauri::AppHandle) -> tauri::State<'_, AppState> {
    app.state::<AppState>()
}

/// 执行一次完整轮换往返；返回每个通过步骤的名称。
async fn run_e2e(app: &tauri::AppHandle) -> Result<Vec<String>, String> {
    let dir = sandbox_dir()?;
    let vault = dir.join("host-rotate.vty");
    let new_a = dir.join("host-rotate.vty.rot-a");
    let new_b = dir.join("host-rotate.vty.rot-b");
    for path in [&vault, &new_a, &new_b] {
        if path.exists() {
            std::fs::remove_file(path)
                .map_err(|e| format!("清理沙箱残留失败: {}", e))?;
        }
    }
    let vault_str = vault.to_string_lossy().to_string();
    let new_a_str = new_a.to_string_lossy().to_string();
    let new_b_str = new_b.to_string_lossy().to_string();

    let mut passed = Vec::new();

    expect_ok(
        "worker_init",
        worker_init(app.clone(), state(app), String::new()).await,
    )?;
    passed.push("worker_init".to_string());

    let created = expect_ok(
        "create",
        verthys_create(app.clone(), state(app), vault_str.clone(), None, None).await,
    )?;
    let recovery_code = Zeroizing::new(
        created
            .recovery_code
            .clone()
            .filter(|code| !code.is_empty())
            .ok_or_else(|| "创建容器未返回恢复码".to_string())?,
    );
    passed.push("create".to_string());

    let payload_b64 = crate::util::base64::base64_encode(RECORD_PAYLOAD);
    let record = expect_ok(
        "add_record",
        verthys_add_record(
            app.clone(),
            state(app),
            RECORD_TYPE_ACCOUNTS,
            "host-rotate-record".to_string(),
            payload_b64.clone(),
        )
        .await,
    )?;
    let record_id = record
        .id
        .ok_or_else(|| "add_record 未返回记录 ID".to_string())?;
    passed.push("add_record".to_string());

    /* 边界 1：普通（非恢复码）会话发起轮换必须被策略拒绝，且不产生作业。 */
    expect_err_code(
        "rotate_begin(normal session)",
        verthys_rotate_begin(app.clone(), new_a_str.clone(), Some(0x01)).await,
        "ERR_00000017",
    )?;
    passed.push("rotate_reject_non_recovery".to_string());

    expect_ok(
        "module_enable",
        verthys_module_enable(
            app.clone(),
            state(app),
            0,
            MODULE_PASSWORD.to_string(),
            None,
        )
        .await,
    )?;
    passed.push("module_enable".to_string());

    expect_ok("lock_persist", verthys_lock_persist(state(app)).await)?;
    expect_ok("lock", verthys_lock(app.clone(), state(app)).await)?;
    /* 与前端 lockAll 同序：lock 只清会话守卫，worker_destroy 才终止子进程
     * 并把生命周期回到 Uninitialized；下一次 unlock 前必须重新 worker_init。 */
    expect_ok("worker_destroy", worker_destroy(state(app)).await)?;
    expect_ok(
        "worker_init(2)",
        worker_init(app.clone(), state(app), String::new()).await,
    )?;
    passed.push("lock".to_string());

    expect_ok(
        "unlock_recovery",
        verthys_unlock_recovery(
            app.clone(),
            state(app),
            vault_str.clone(),
            recovery_code.to_string(),
        )
        .await,
    )?;
    passed.push("unlock_recovery".to_string());

    /* 边界 2：目标路径已存在 → EXISTS，且不产生作业。 */
    let existing = dir.join("host-rotate-existing.vty");
    std::fs::write(&existing, b"occupied").map_err(|e| format!("写入占位文件失败: {}", e))?;
    let existing_str = existing.to_string_lossy().to_string();
    expect_err_code(
        "rotate_begin(existing target)",
        verthys_rotate_begin(app.clone(), existing_str.clone(), Some(0x01)).await,
        "ERR_00000004",
    )?;
    std::fs::remove_file(&existing).map_err(|e| format!("清理占位文件失败: {}", e))?;

    /* 边界 3：已启用模块未登记口令就 Run → MODULE_LOCKED，作业只能 Abort。 */
    expect_ok(
        "rotate_begin(missing module)",
        verthys_rotate_begin(app.clone(), new_a_str.clone(), Some(0x01)).await,
    )?;
    let channel_missing = tauri::ipc::Channel::<RotateProgress>::new(|_body| Ok(()));
    expect_err_code(
        "rotate_run(missing module)",
        verthys_rotate_run(app.clone(), channel_missing).await,
        "ERR_0000001D",
    )?;
    expect_ok(
        "rotate_abort(missing module)",
        verthys_rotate_abort(app.clone()).await,
    )?;
    if Path::new(&new_a_str).exists() {
        return Err("rotate_abort(missing module): 临时库仍然存在".into());
    }
    passed.push("rotate_module_locked_guard".to_string());

    /* 边界 5：Begin 后先置位取消信号，Run 必须按取消收敛（POLICY）并 Abort。 */
    expect_ok(
        "rotate_begin(cancel)",
        verthys_rotate_begin(app.clone(), new_a_str.clone(), Some(0x01)).await,
    )?;
    expect_ok(
        "rotate_cancel",
        verthys_rotate_cancel(app.clone()).await,
    )?;
    expect_ok(
        "rotate_unlock_module(cancel)",
        verthys_rotate_unlock_module(
            app.clone(),
            0,
            MODULE_PASSWORD.to_string(),
            None,
        )
        .await,
    )?;
    let channel_cancel = tauri::ipc::Channel::<RotateProgress>::new(|_body| Ok(()));
    expect_err_code(
        "rotate_run(cancel)",
        verthys_rotate_run(app.clone(), channel_cancel).await,
        "ERR_00000017",
    )?;
    expect_ok(
        "rotate_abort(cancel)",
        verthys_rotate_abort(app.clone()).await,
    )?;
    if Path::new(&new_a_str).exists() {
        return Err("rotate_abort(cancel): 临时库仍然存在".into());
    }
    passed.push("rotate_cancel".to_string());

    /* 边界 4：作业期间写操作 → ROTATE_PENDING；Abort 后源库记录仍可读。 */
    let begin_pending = expect_ok(
        "rotate_begin(pending)",
        verthys_rotate_begin(app.clone(), new_a_str.clone(), Some(0x01)).await,
    )?;
    if begin_pending.rotate_stage != Some(1) {
        return Err(format!(
            "rotate_begin(pending): 阶段非法 {:?}",
            begin_pending.rotate_stage
        ));
    }
    expect_ok(
        "rotate_unlock_module(pending)",
        verthys_rotate_unlock_module(
            app.clone(),
            0,
            MODULE_PASSWORD.to_string(),
            None,
        )
        .await,
    )?;
    expect_err_code(
        "add_record(rotate pending)",
        verthys_add_record(
            app.clone(),
            state(app),
            RECORD_TYPE_ACCOUNTS,
            "blocked-by-rotate".to_string(),
            payload_b64.clone(),
        )
        .await,
        "ERR_0000001C",
    )?;

    let progress_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&progress_count);
    let channel = tauri::ipc::Channel::<RotateProgress>::new(move |_body| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    expect_ok(
        "rotate_run(pending)",
        verthys_rotate_run(app.clone(), channel).await,
    )?;
    if progress_count.load(Ordering::SeqCst) == 0 {
        return Err("rotate_run(pending): 未收到任何进度事件".into());
    }
    expect_ok(
        "rotate_abort(pending)",
        verthys_rotate_abort(app.clone()).await,
    )?;
    if Path::new(&new_a_str).exists() {
        return Err("rotate_abort(pending): 临时库仍然存在".into());
    }
    let source_after_abort = expect_ok(
        "get_record(after abort)",
        verthys_get_record(app.clone(), state(app), record_id).await,
    )?;
    if source_after_abort.data.as_deref() != Some(payload_b64.as_str()) {
        return Err("get_record(after abort): 源库记录内容不一致".into());
    }
    passed.push("rotate_run_abort".to_string());

    /* 轮换 B：Run 后 Commit，记录必须随新库保留且可读回。 */
    expect_ok(
        "rotate_begin(B)",
        verthys_rotate_begin(app.clone(), new_b_str.clone(), Some(0x01)).await,
    )?;
    expect_ok(
        "rotate_unlock_module(B)",
        verthys_rotate_unlock_module(
            app.clone(),
            0,
            MODULE_PASSWORD.to_string(),
            None,
        )
        .await,
    )?;
    let progress_count_b = Arc::new(AtomicUsize::new(0));
    let counter_b = Arc::clone(&progress_count_b);
    let channel_b = tauri::ipc::Channel::<RotateProgress>::new(move |_body| {
        counter_b.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    expect_ok(
        "rotate_run(B)",
        verthys_rotate_run(app.clone(), channel_b).await,
    )?;
    if progress_count_b.load(Ordering::SeqCst) == 0 {
        return Err("rotate_run(B): 未收到任何进度事件".into());
    }
    expect_ok(
        "rotate_commit(B)",
        verthys_rotate_commit(app.clone(), Some(false)).await,
    )?;
    if Path::new(&new_b_str).exists() {
        return Err("rotate_commit(B): 临时库未被原子替换".into());
    }

    let got = expect_ok(
        "get_record",
        verthys_get_record(app.clone(), state(app), record_id).await,
    )?;
    if got.data.as_deref() != Some(payload_b64.as_str()) {
        return Err("get_record: 轮换提交后记录内容不一致".into());
    }
    passed.push("rotate_run_commit".to_string());

    expect_ok("lock_persist(final)", verthys_lock_persist(state(app)).await)?;
    expect_ok("lock(final)", verthys_lock(app.clone(), state(app)).await)?;
    let _ = worker_destroy(state(app)).await;
    passed.push("cleanup".to_string());

    /* 场景 2：keyfile 容器的恢复会话补录。
     * 恢复解锁不携带 keyfile → Begin 必须 POLICY；补录正确 keyfile 后
     * Begin 才能继续。 */
    let vault_kf = dir.join("host-rotate-keyfile.vty");
    let keyfile = dir.join("host-rotate.vkf");
    let new_kf = dir.join("host-rotate-keyfile.vty.rot");
    let missing_kf = dir.join("host-rotate-missing.vkf");
    for path in [&vault_kf, &keyfile, &new_kf, &missing_kf] {
        if path.exists() {
            std::fs::remove_file(path)
                .map_err(|e| format!("清理 keyfile 沙箱失败: {}", e))?;
        }
    }
    let vault_kf_str = vault_kf.to_string_lossy().to_string();
    let keyfile_str = keyfile.to_string_lossy().to_string();
    let new_kf_str = new_kf.to_string_lossy().to_string();
    let missing_kf_str = missing_kf.to_string_lossy().to_string();

    expect_ok(
        "worker_init(kf)",
        worker_init(app.clone(), state(app), String::new()).await,
    )?;
    let created_kf = expect_ok(
        "create_keyfile",
        verthys_create(
            app.clone(),
            state(app),
            vault_kf_str.clone(),
            None,
            Some(keyfile_str.clone()),
        )
        .await,
    )?;
    let recovery_kf = Zeroizing::new(
        created_kf
            .recovery_code
            .clone()
            .filter(|code| !code.is_empty())
            .ok_or_else(|| "keyfile 容器创建未返回恢复码".to_string())?,
    );
    expect_ok("lock_persist(kf)", verthys_lock_persist(state(app)).await)?;
    expect_ok("lock(kf)", verthys_lock(app.clone(), state(app)).await)?;
    expect_ok("worker_destroy(kf)", worker_destroy(state(app)).await)?;
    expect_ok(
        "worker_init(kf-2)",
        worker_init(app.clone(), state(app), String::new()).await,
    )?;
    expect_ok(
        "unlock_recovery(kf)",
        verthys_unlock_recovery(
            app.clone(),
            state(app),
            vault_kf_str.clone(),
            recovery_kf.to_string(),
        )
        .await,
    )?;

    expect_err_code(
        "rotate_begin(kf without digest)",
        verthys_rotate_begin(app.clone(), new_kf_str.clone(), Some(0x01)).await,
        "ERR_00000017",
    )?;
    expect_err_code(
        "rotate_attach_keyfile(missing)",
        verthys_rotate_attach_keyfile(app.clone(), missing_kf_str).await,
        "ERR_0000001B",
    )?;
    expect_ok(
        "rotate_attach_keyfile",
        verthys_rotate_attach_keyfile(app.clone(), keyfile_str.clone()).await,
    )?;
    expect_ok(
        "rotate_begin(after attach)",
        verthys_rotate_begin(app.clone(), new_kf_str.clone(), Some(0x01)).await,
    )?;
    expect_ok(
        "rotate_abort(after attach)",
        verthys_rotate_abort(app.clone()).await,
    )?;
    if Path::new(&new_kf_str).exists() {
        return Err("rotate_abort(after attach): 临时库仍然存在".into());
    }
    passed.push("rotate_keyfile_attach".to_string());

    expect_ok("lock_persist(kf-final)", verthys_lock_persist(state(app)).await)?;
    expect_ok("lock(kf-final)", verthys_lock(app.clone(), state(app)).await)?;
    let _ = worker_destroy(state(app)).await;

    Ok(passed)
}

/// 入口：执行用例、写结果文件并退出应用。
///
/// 结果文件仅含 PASS/FAIL 与步骤名/错误信息；退出码 0=通过 1=失败。
pub(crate) async fn run_and_report(app: tauri::AppHandle) {
    let result_path = std::env::var("VERTHYS_E2E_ROTATE_RESULT").unwrap_or_default();
    let outcome = run_e2e(&app).await;
    let text = match outcome {
        Ok(steps) => format!("PASS\n{}", steps.join("\n")),
        Err(error) => format!("FAIL\n{}", error),
    };
    if !result_path.is_empty() {
        if let Err(e) = std::fs::write(&result_path, &text) {
            log::error!("[e2e_rotate] 写结果文件失败: {}", e);
        }
    }
    log::info!("[e2e_rotate] {}", text.replace('\n', " | "));
    app.exit(if text.starts_with("PASS") { 0 } else { 1 });
}
