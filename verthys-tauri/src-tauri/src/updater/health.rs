/*
 * updater/health.rs — 新版本启动健康自检
 *
 * 自检结论必须由 Rust 判定：前端只负责触发与展示。判定依据是安装后真实
 * 存在的 DLL、worker 状态与版本握手，不触发容器解锁，也不修改用户数据。
 */

use super::lkg;
use super::log;
use super::marker::{self, PendingMarker};
use super::repair;
use super::UpdaterError;
use crate::controller::worker_controller;
use crate::infrastructure::path_resolver;
use crate::state::{AppState, WorkerLifecycleState};
use serde::Serialize;
use serde_json::json;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};

const DLL_CHECK_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthItem {
    pub name: String,
    pub status: String,
    pub duration_ms: u64,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthReport {
    pub has_pending: bool,
    pub verdict: String,
    pub current_version: String,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub release_id: Option<String>,
    pub items: Vec<HealthItem>,
    pub repair_available: bool,
    pub repair_version: Option<String>,
    pub detail: Option<String>,
}

/// 执行一次健康自检；标记不存在或不属于本进程时返回 `no_pending`。
pub async fn run(app: &AppHandle) -> Result<HealthReport, UpdaterError> {
    let current = app.package_info().version.to_string();
    let marker = match marker::read_pending(app) {
        Ok(Some(value)) => value,
        Ok(None) => return Ok(empty_report(current, "no_pending")),
        Err(error) => {
            let quarantined = marker::quarantine_pending(app);
            log::append(
                app,
                "marker_invalid",
                "HealthCheck",
                Some(&error.code),
                "error",
                json!({ "quarantined": quarantined.is_ok() }),
            );
            let repair = repair::view(app);
            return Ok(HealthReport {
                has_pending: false,
                verdict: "marker_invalid".to_string(),
                current_version: current,
                from_version: None,
                to_version: None,
                release_id: None,
                items: Vec::new(),
                repair_available: repair.available,
                repair_version: repair.version,
                detail: Some(error.message),
            });
        }
    };

    if marker.owner_pid == std::process::id() {
        return Ok(empty_report(current, "no_pending"));
    }
    if marker.to_version != current {
        let detail = "安装后版本未变更";
        let archived = marker::finish_pending(app, "install_failed", Some(detail))?;
        let _ = repair::write_from_marker(app, &archived);
        log::append(
            app,
            "install_failed",
            "HealthCheck",
            Some("E_UPDATER_INSTALL_FAILED"),
            "error",
            json!({ "releaseId": archived.release_id }),
        );
        return Ok(report_from_marker(
            &archived,
            current,
            "install_failed",
            Vec::new(),
            Some(detail.to_string()),
        ));
    }

    let dll_item = check_dll(app).await;
    let (worker_item, worker_started_by_health) = check_worker(app).await;
    let abi_item = check_abi(&marker, app).await;
    let items = vec![
        dll_item,
        worker_item,
        abi_item,
        HealthItem {
            name: "read_only_probe".to_string(),
            status: "skipped".to_string(),
            duration_ms: 0,
            detail: Some("只读探测需要业务会话，健康自检不触发解锁".to_string()),
        },
    ];
    // 自检启动的 worker 不在前端预加载缓存内；销毁后让后续解锁重新启动，
    // 避免状态机停在 Ready 而前端仍认为未初始化。
    if worker_started_by_health {
        let _ = worker_controller::worker_destroy(app.state::<AppState>()).await;
    }
    let failed = items.iter().any(|item| item.status == "failed");
    let detail = summarize(&items);

    if failed {
        let archived = marker::finish_pending(app, "rolled_back", Some(&detail))?;
        repair::write_from_marker(app, &archived)?;
        log::append(
            app,
            "health_fail",
            "HealthCheck",
            Some("E_UPDATER_HEALTH_FAIL"),
            "error",
            json!({ "items": items }),
        );
        log::append(
            app,
            "rolled_back",
            "HealthCheck",
            Some("E_UPDATER_HEALTH_FAIL"),
            "error",
            json!({ "releaseId": archived.release_id }),
        );
        return Ok(report_from_marker(
            &archived,
            current,
            "rolled_back",
            items,
            Some(detail),
        ));
    }

    let archived = marker::finish_pending(app, "health_confirmed", Some(&detail))?;
    if let Some(candidate) = archived.candidate.as_ref() {
        if let Err(error) = lkg::promote(app, candidate) {
            log::append(
                app,
                "repair_failed",
                "HealthCheck",
                Some(&error.code),
                "warn",
                json!({ "stage": "promote_lkg" }),
            );
        }
    }
    let _ = repair::clear(app);
    log::append(
        app,
        "health_ok",
        "HealthCheck",
        None,
        "info",
        json!({ "items": items }),
    );
    Ok(report_from_marker(
        &archived,
        current,
        "health_confirmed",
        items,
        Some(detail),
    ))
}

async fn check_dll(app: &AppHandle) -> HealthItem {
    let started = Instant::now();
    let path = match path_resolver::resolve_dll_path(app) {
        Ok(value) => value,
        Err(error) => {
            return item_failed("dll_integrity", started, error);
        }
    };
    let has_baseline = !path_resolver::get_dll_hash_prefix().is_empty();
    let result = tokio::time::timeout(
        DLL_CHECK_TIMEOUT,
        tokio::task::spawn_blocking(move || path_resolver::verify_dll_integrity(&path)),
    )
    .await;
    match result {
        Ok(Ok(Ok(()))) if has_baseline => {
            item_ok("dll_integrity", started, "加密核心哈希与编译基线一致")
        }
        Ok(Ok(Ok(()))) => item_skipped(
            "dll_integrity",
            started,
            "开发构建未嵌入 DLL 哈希基线，跳过比对",
        ),
        Ok(Ok(Err(error))) => item_failed("dll_integrity", started, error),
        Ok(Err(error)) => item_failed("dll_integrity", started, error.to_string()),
        Err(_) => item_failed("dll_integrity", started, "DLL 完整性校验超时"),
    }
}

/// 检查 worker；返回值第二项表示是否由本次自检启动了 worker。
async fn check_worker(app: &AppHandle) -> (HealthItem, bool) {
    let started = Instant::now();
    let state = app.state::<AppState>();
    let lifecycle = state.worker_lifecycle.current_state().await;
    if lifecycle.is_ready() {
        return (item_ok("worker_ready", started, "worker 已就绪"), false);
    }
    if lifecycle.is_initializing() {
        let waited = tokio::time::timeout(
            WORKER_READY_TIMEOUT,
            state.worker_lifecycle.wait_for_ready_or_failed(),
        )
        .await;
        let item = match waited {
            Ok(Ok(WorkerLifecycleState::Ready)) => {
                item_ok("worker_ready", started, "worker 初始化完成")
            }
            Ok(Ok(failed)) => item_failed(
                "worker_ready",
                started,
                format!("worker 初始化失败: {failed:?}"),
            ),
            Ok(Err(_)) => item_failed("worker_ready", started, "等待 worker 就绪超时"),
            Err(_) => item_failed("worker_ready", started, "worker 初始化超时"),
        };
        return (item, false);
    }

    let init = tokio::time::timeout(
        WORKER_READY_TIMEOUT,
        worker_controller::worker_init(app.clone(), app.state::<AppState>(), String::new()),
    )
    .await;
    let item = match init {
        Ok(Ok(response)) if response.ok => {
            let state = app.state::<AppState>();
            if state.has_session() && state.is_worker_alive() {
                item_ok("worker_ready", started, "worker 启动并通过就绪握手")
            } else {
                item_failed("worker_ready", started, "worker 返回就绪但进程不可用")
            }
        }
        Ok(Ok(response)) => item_failed(
            "worker_ready",
            started,
            response
                .error
                .unwrap_or_else(|| "worker 初始化失败".to_string()),
        ),
        Ok(Err(error)) => item_failed("worker_ready", started, error),
        Err(_) => item_failed("worker_ready", started, "worker 启动超时"),
    };
    (item, true)
}

async fn check_abi(_marker: &PendingMarker, app: &AppHandle) -> HealthItem {
    let started = Instant::now();
    let state = app.state::<AppState>();
    if state.has_session() && state.is_worker_alive() {
        item_ok(
            "abi_negotiation",
            started,
            "worker 预检已校验 DLL 接口与容器格式版本",
        )
    } else {
        item_failed(
            "abi_negotiation",
            started,
            "worker 未就绪，无法确认接口与容器格式版本",
        )
    }
}

fn item_ok(name: &str, started: Instant, detail: &str) -> HealthItem {
    HealthItem {
        name: name.to_string(),
        status: "ok".to_string(),
        duration_ms: started.elapsed().as_millis() as u64,
        detail: Some(detail.to_string()),
    }
}

fn item_skipped(name: &str, started: Instant, detail: &str) -> HealthItem {
    HealthItem {
        name: name.to_string(),
        status: "skipped".to_string(),
        duration_ms: started.elapsed().as_millis() as u64,
        detail: Some(detail.to_string()),
    }
}

fn item_failed(name: &str, started: Instant, detail: impl Into<String>) -> HealthItem {
    HealthItem {
        name: name.to_string(),
        status: "failed".to_string(),
        duration_ms: started.elapsed().as_millis() as u64,
        detail: Some(detail.into()),
    }
}

fn summarize(items: &[HealthItem]) -> String {
    items
        .iter()
        .map(|item| format!("{}={}", item.name, item.status))
        .collect::<Vec<_>>()
        .join(", ")
}

fn empty_report(current: String, verdict: &str) -> HealthReport {
    HealthReport {
        has_pending: false,
        verdict: verdict.to_string(),
        current_version: current,
        from_version: None,
        to_version: None,
        release_id: None,
        items: Vec::new(),
        repair_available: false,
        repair_version: None,
        detail: None,
    }
}

fn report_from_marker(
    marker: &PendingMarker,
    current: String,
    verdict: &str,
    items: Vec<HealthItem>,
    detail: Option<String>,
) -> HealthReport {
    let repair = repair::view_from_marker(marker);
    HealthReport {
        has_pending: false,
        verdict: verdict.to_string(),
        current_version: current,
        from_version: Some(marker.from_version.clone()),
        to_version: Some(marker.to_version.clone()),
        release_id: Some(marker.release_id.clone()),
        items,
        repair_available: repair.available,
        repair_version: repair.version,
        detail,
    }
}
