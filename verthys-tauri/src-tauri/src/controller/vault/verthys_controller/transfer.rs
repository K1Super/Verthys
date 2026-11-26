/*
 * 容器导出与导入
 *
 * 职责边界：整库加密导出与按口令导入。口令以 Zeroizing 持有，序列化完成
 * 即擦除原件；导出/导入路径必须先取得 worker exact-path 授权。
 */

use super::*;
use crate::controller::types::VerthysResponse;
use crate::state::AppState;
use tauri::State;
use zeroize::Zeroizing;
/// export / import 请求体（共用 path + password 两字段结构）
#[derive(serde::Serialize)]
struct PathPasswordReq<'a> {
    op: &'static str,
    path: &'a str,
    password: &'a str,
}

// ===== 导入导出 =====

/// 导出整个容器为加密文件（用新密码加密）。
/// 密码发送后立即擦除。
#[tauri::command]
pub async fn verthys_export(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    export_path: String,
    password: String,
) -> Result<VerthysResponse, String> {
    let _io = state.io_guard();
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, "export") {
        return Ok(VerthysResponse::err("export", &msg));
    }

    let password = Zeroizing::new(password);

    state
        .authorize_worker_path("export", "write", &export_path)
        .map_err(|e| format!("导出路径未授权: {}", e))?;

    let req_str = Zeroizing::new(
        serde_json::to_string(&PathPasswordReq {
            op: "export",
            path: &export_path,
            password: &password,
        })
        .map_err(|e| format!("serialize request: {}", e))?,
    );

    // 序列化完成即销毁口令原件，仅保留 Zeroizing 序列化副本直至发送
    drop(password);

    let resp_json = state.send(req_str.as_str())?;
    drop(req_str);
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 从加密文件导入容器（用给定密码解密）。
/// 密码发送后立即擦除。
#[tauri::command]
pub async fn verthys_import(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    import_path: String,
    password: String,
) -> Result<VerthysResponse, String> {
    let _io = state.io_guard();
    if let Err(msg) = require_unlocked(&app, &state, "import") {
        return Ok(VerthysResponse::err("import", &msg));
    }

    let password = Zeroizing::new(password);

    state
        .authorize_worker_path("import", "read", &import_path)
        .map_err(|e| format!("导入路径未授权: {}", e))?;

    let req_str = Zeroizing::new(
        serde_json::to_string(&PathPasswordReq {
            op: "import",
            path: &import_path,
            password: &password,
        })
        .map_err(|e| format!("serialize request: {}", e))?,
    );

    // 序列化完成即销毁口令原件，仅保留 Zeroizing 序列化副本直至发送
    drop(password);

    let resp_json = state.send(req_str.as_str())?;
    drop(req_str);
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}
