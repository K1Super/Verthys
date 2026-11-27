/*
 * 回退锚点 Tauri 命令
 *
 * 职责边界：列表/回收/释放只做参数边界、转发与审计；扫描与自定义位置
 * 管理为宿主侧只读操作。释放必须由前端二次确认传入 confirm=true。
 */

use std::sync::atomic::Ordering;

use serde_json::json;
use tauri::ipc::Channel;
use tauri::{AppHandle, State};

use crate::controller::types::{AnchorScanProgress, VerthysResponse};
use crate::repository::anchor_scan_store::{self};
use crate::repository::verthys_state::get_state_dir;
use crate::state::AppState;
use crate::util::audit_log::{AuditEventType, AuditResult};

use super::*;

/// 列出本机回退锚点（不要求容器已解锁）。
#[tauri::command]
pub async fn verthys_rollback_anchor_list(
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    forward(&state, &json!({ "op": "rollback_anchor_list" }))
}

/// 回收所有“见证确定不存在”的锚点。ACTIVE/TAMPERED/UNKNOWN 保留。
#[tauri::command]
pub async fn verthys_rollback_anchor_reclaim(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    confirm: bool,
) -> Result<VerthysResponse, String> {
    if !confirm {
        let mut resp = VerthysResponse::err("rollback_anchor_reclaim", "缺少显式确认");
        resp.error_code = Some("ERR_00000001".into());
        return Ok(resp);
    }
    let resp = forward(
        &state,
        &json!({ "op": "rollback_anchor_reclaim", "anchor_confirm": true }),
    )?;
    let result = if resp.ok {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    audit_anchor(
        &app,
        AuditEventType::RollbackAnchorReclaim,
        result,
        None,
        Some(format!(
            "removed={} cleanup_failed={}",
            resp.anchor_removed.unwrap_or(0),
            resp.anchor_cleanup_failed.unwrap_or(0)
        )),
    );
    Ok(resp)
}

/// 显式释放指定 UUID 的锚点并删除两槽见证。
///
/// 该操作会使仍存在的容器在下次打开时 fail-closed，只能使用恢复码
/// 重设锚点；前端必须完成二次确认后才可传入 confirm=true。
#[tauri::command]
pub async fn verthys_rollback_anchor_release(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    uuid: String,
    confirm: bool,
) -> Result<VerthysResponse, String> {
    if !confirm {
        let mut resp = VerthysResponse::err("rollback_anchor_release", "缺少显式确认");
        resp.error_code = Some("ERR_00000001".into());
        return Ok(resp);
    }
    if !is_uuid_hex(&uuid) {
        let mut resp = VerthysResponse::err("rollback_anchor_release", "UUID 格式非法");
        resp.error_code = Some("ERR_00000001".into());
        return Ok(resp);
    }
    let resp = forward(
        &state,
        &json!({
            "op": "rollback_anchor_release",
            "uuid": uuid,
            "anchor_confirm": true,
        }),
    )?;
    let result = if resp.ok {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };
    audit_anchor(
        &app,
        AuditEventType::RollbackAnchorRelease,
        result,
        Some(&uuid),
        Some(format!(
            "released={} cleanup_failed={}",
            resp.anchor_released.unwrap_or(0),
            resp.anchor_cleanup_failed.unwrap_or(0)
        )),
    );
    Ok(resp)
}

/// 扫描全部本地容器位置，返回 UUID → 路径证据。
///
/// - peek=true：只读取上次持久化证据，不遍历磁盘（打开管理弹窗时使用）；
/// - roots 非空：校验并持久化为自定义位置后参与扫描；
/// - force=false：最近一次完整扫描在缓存窗口内直接返回持久化证据；
/// - 其余情况执行一次全量扫描（本地磁盘根 + 自定义位置 + 当前/最近探针）。
#[tauri::command]
pub async fn verthys_rollback_anchor_scan(
    app: AppHandle,
    roots: Option<Vec<String>>,
    force: Option<bool>,
    peek: Option<bool>,
    on_progress: Channel<AnchorScanProgress>,
) -> Result<VerthysResponse, String> {
    let config_dir = get_state_dir(&app)?;
    if peek.unwrap_or(false) {
        let _guard = SCAN_LOCK.lock().await;
        let store = load_store(&config_dir);
        let result = build_scan_result(&store, &PassOutcome::default());
        return Ok(scan_response(result));
    }
    let additions = match normalize_custom_roots(roots.unwrap_or_default()) {
        Ok(additions) => additions,
        Err(message) => return Ok(scan_invalid(message)),
    };
    let force = force.unwrap_or(false);

    let _guard = SCAN_LOCK.lock().await;
    SCAN_CANCEL.store(false, Ordering::SeqCst);
    let mut store = load_store(&config_dir);
    if !additions.is_empty() {
        if let Err(message) = add_custom_roots(&mut store, &additions) {
            return Ok(scan_invalid(message));
        }
        anchor_scan_store::save(&config_dir, &store)?;
    }

    if !force
        && additions.is_empty()
        && is_cache_fresh(&store)
        && cache_matches_current_container(&app, &store)
    {
        // 缓存命中只返回既有证据，不重复写扫描审计。
        let result = build_scan_result(&store, &PassOutcome::default());
        return Ok(scan_response(result));
    }

    let app_for_task = app.clone();
    let config_for_task = config_dir.clone();
    let (store, outcome) = tokio::task::spawn_blocking(move || {
        run_scan_pass(app_for_task, config_for_task, store, on_progress)
    })
    .await
    .map_err(|e| format!("scan task join: {}", e))??;
    let result = build_scan_result(&store, &outcome);
    audit_scan(&app, &result);
    Ok(scan_response(result))
}

/// 请求停止正在进行的扫描；扫描线程在下一个目录项边界退出并保留已完成证据。
#[tauri::command]
pub async fn verthys_rollback_anchor_scan_cancel() -> Result<VerthysResponse, String> {
    SCAN_CANCEL.store(true, Ordering::SeqCst);
    Ok(VerthysResponse::ok("rollback_anchor_scan_cancel"))
}

/// 移除一个自定义扫描位置，返回移除后的持久化证据。
#[tauri::command]
pub async fn verthys_rollback_anchor_scan_forget_root(
    app: AppHandle,
    path: String,
) -> Result<VerthysResponse, String> {
    let config_dir = get_state_dir(&app)?;
    let _guard = SCAN_LOCK.lock().await;
    let mut store = load_store(&config_dir);
    if anchor_scan_store::remove_custom(&mut store, &path) {
        anchor_scan_store::save(&config_dir, &store)?;
    }
    let result = build_scan_result(&store, &PassOutcome::default());
    Ok(scan_response(result))
}
