/*
 * 记录 CRUD 与分页枚举
 *
 * 职责边界：单条增删读、批量删除（含外置块级联展开）、流式分页枚举与
 * 摘要计数。所有入口先经数据域会话闸门；写入侧按 worker 行协议上限
 * 前置拒绝超限载荷，避免超限请求打断 worker 连接。
 */

use super::*;
use crate::constants::import_writer as wconst;
use crate::controller::types::{EnumerateBatch, VerthysResponse};
use crate::repository::verthys_chunks;
use crate::state::AppState;
use std::collections::HashSet;
use tauri::State;
use zeroize::Zeroizing;
/// add_record 请求体（name 与 data 为用户记录明文，一并借用序列化）
#[derive(serde::Serialize)]
struct AddRecordReq<'a> {
    op: &'static str,
    rtype: u32,
    name: &'a str,
    data: &'a str,
}

// ===== 记录 CRUD =====

/// 添加单条记录。
#[tauri::command]
pub async fn verthys_add_record(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    rtype: u32,
    name: String,
    data_b64: String,
) -> Result<VerthysResponse, String> {
    let _io = state.io_guard();
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, "add_record") {
        return Ok(VerthysResponse::err("add_record", &msg));
    }

    // 记录名与数据 base64 均为用户明文，包装进 Zeroizing 统一擦除
    let name = Zeroizing::new(name);
    let data_b64 = Zeroizing::new(data_b64);

    // 写入侧协议护栏：与批量写入路径同一上限（记录载荷 base64 长度）。
    // worker 行协议单行硬上限 16MiB，超限请求会被 worker 侧判定协议异常并
    // 断开连接（worker 失联，后续全部操作级联失败）。此处前置拒绝，把
    // 「超限即断链」的系统级故障收敛为可读的按条错误。
    if name.is_empty() || name.len() > wconst::MAX_RECORD_NAME_LEN {
        log::warn!("[verthys_add_record] 拒绝非法记录名（长度 {}）", name.len());
        return Ok(VerthysResponse::err(
            "add_record",
            "记录名长度非法（空或超上限）",
        ));
    }
    if data_b64.is_empty() || data_b64.len() > wconst::MAX_IPC_PAYLOAD_BYTES {
        log::warn!(
            "[verthys_add_record] 拒绝越限记录载荷: {} 字节（上限 {}）",
            data_b64.len(),
            wconst::MAX_IPC_PAYLOAD_BYTES
        );
        return Ok(VerthysResponse::err(
            "add_record",
            &format!(
                "记录载荷超过单条上限 {} 字节",
                wconst::MAX_IPC_PAYLOAD_BYTES
            ),
        ));
    }

    let req_str = Zeroizing::new(
        serde_json::to_string(&AddRecordReq {
            op: "add_record",
            rtype,
            name: &name,
            data: &data_b64,
        })
        .map_err(|e| format!("serialize request: {}", e))?,
    );

    let resp_json = state.send(req_str.as_str())?;

    // 发送完成：序列化副本与记录明文原件统一销毁
    drop(req_str);
    drop(data_b64);
    drop(name);

    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 按 ID 读取记录。
#[tauri::command]
pub async fn verthys_get_record(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    id: u64,
) -> Result<VerthysResponse, String> {
    let _io = state.io_guard();
    if let Err(msg) = require_unlocked(&app, &state, "get_record") {
        return Ok(VerthysResponse::err("get_record", &msg));
    }

    let req = serde_json::json!({
        "op": "get_record",
        "id": id,
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 一次性枚举全部记录（自 start_id 开始），适用于记录数较少时。
/// 超时 60 秒，若记录数巨大建议使用流式版本。
///
/// 实现：worker 侧 enumerate_records 受响应行字节预算约束（防单行超限
/// 断开协议），单次调用可能只返回预算内的前缀批次，故此处按游标循环
/// 聚合全部批次后一次性返回，对调用方保持「一次调用拿到全量记录」契约。
#[tauri::command]
pub async fn verthys_enumerate_records(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    start_id: u64,
) -> Result<VerthysResponse, String> {
    let _io = state.io_guard();
    if let Err(msg) = require_unlocked(&app, &state, "enumerate_records") {
        return Ok(VerthysResponse::err("enumerate_records", &msg));
    }

    /// 聚合安全阀：与流式枚举同量级（200 万条），防异常游标导致无限循环
    const ENUM_LOOP_SAFETY_LIMIT: usize = 2_000_000;

    let mut current_id: u64 = if start_id > 0 { start_id } else { 1 };
    let mut all_records: Vec<crate::controller::types::VerthysRecordEntry> = Vec::new();
    let mut exhausted = false;

    while !exhausted {
        let req = serde_json::json!({
            "op": "enumerate_records",
            "id": current_id,
        });
        let resp_json =
            state.send_with_timeout(&req.to_string(), std::time::Duration::from_secs(60))?;
        let resp: VerthysResponse =
            serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;

        if !resp.ok {
            log::warn!(
                "[verthys_enumerate_records] worker 返回失败: {:?}",
                resp.error
            );
            return Ok(resp);
        }

        let batch = resp.records.unwrap_or_default();
        let count = batch.len();
        let last_id = resp.id.unwrap_or(0);
        exhausted = resp.exhausted.unwrap_or(false);
        all_records.extend(batch);

        if count == 0 && !exhausted {
            // 空批次且未标注遍历结束：防御性收敛，避免死循环
            log::warn!("[verthys_enumerate_records] 空批次且未 exhausted，强制终止");
            exhausted = true;
        }
        if last_id > 0 {
            current_id = last_id + 1;
        } else if !exhausted {
            log::warn!("[verthys_enumerate_records] 游标无进展且未 exhausted，强制终止");
            exhausted = true;
        }
        if all_records.len() > ENUM_LOOP_SAFETY_LIMIT {
            log::error!(
                "[verthys_enumerate_records] 超过安全阀 {} 条，强制终止",
                ENUM_LOOP_SAFETY_LIMIT
            );
            break;
        }
    }

    log::info!(
        "[verthys_enumerate_records] 枚举完成: total={}",
        all_records.len()
    );

    Ok(VerthysResponse {
        records: Some(all_records),
        exhausted: Some(true),
        ..VerthysResponse::ok("enumerate_records")
    })
}

/// 流式枚举记录，通过 Tauri Channel 分批次推送，避免一次性序列化大 JSON。
///
/// 适用于数千条以上记录的场景。后端循环调用 worker enumerate_records，
/// 每批最多 batch_size 条，通过 Channel 推送给前端，前端收到即渲染。
/// 返回累计推送总数。
#[tauri::command]
pub async fn verthys_enumerate_records_stream(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    start_id: u64,
    batch_size: u64,
    on_batch: tauri::ipc::Channel<EnumerateBatch>,
) -> Result<VerthysResponse, String> {
    let _io = state.io_guard();
    if let Err(msg) = require_unlocked(&app, &state, "enumerate_records_stream") {
        return Ok(VerthysResponse::err("enumerate_records_stream", &msg));
    }

    let batch = if batch_size == 0 {
        200u64
    } else {
        batch_size.min(500)
    };
    let mut current_id: u64 = if start_id > 0 { start_id } else { 1 };
    let mut total_pushed: u64 = 0;
    let mut exhausted = false;

    log::info!(
        "[verthys_enumerate_records_stream] 开始流式枚举: start_id={}, batch_size={}",
        start_id,
        batch
    );

    while !exhausted {
        let req = serde_json::json!({
            "op": "enumerate_records",
            "id": current_id,
            "max_count": batch,
        });
        let resp_json =
            state.send_with_timeout(&req.to_string(), std::time::Duration::from_secs(60))?;
        let resp: VerthysResponse =
            serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;

        if !resp.ok {
            log::warn!(
                "[verthys_enumerate_records_stream] worker 返回失败: {:?}",
                resp.error
            );
            return Ok(resp);
        }

        let records = resp.records.unwrap_or_default();
        let count = records.len() as u64;
        let last_id = resp.id.unwrap_or(0);
        exhausted = resp.exhausted.unwrap_or(false);

        if count == 0 && !exhausted {
            log::warn!("[verthys_enumerate_records_stream] 空批次且未 exhausted，强制终止");
            exhausted = true;
        }

        total_pushed += count;

        let batch_payload = EnumerateBatch {
            records,
            last_id,
            count,
            exhausted,
            total_pushed,
            error: None,
        };
        if let Err(e) = on_batch.send(batch_payload) {
            log::warn!(
                "[verthys_enumerate_records_stream] Channel 推送失败（前端可能已关闭）: {}",
                e
            );
            return Ok(VerthysResponse {
                record_count: Some(total_pushed),
                exhausted: Some(true),
                ..VerthysResponse::ok("enumerate_records_stream")
            });
        }

        if last_id > 0 {
            current_id = last_id + 1;
        }

        if exhausted {
            break;
        }

        if total_pushed > 2_000_000 {
            log::error!("[verthys_enumerate_records_stream] 超过安全阀 200 万条，强制终止");
            break;
        }
    }

    log::info!(
        "[verthys_enumerate_records_stream] 流式枚举完成: total_pushed={}",
        total_pushed
    );

    Ok(VerthysResponse {
        record_count: Some(total_pushed),
        exhausted: Some(true),
        ..VerthysResponse::ok("enumerate_records_stream")
    })
}

/// 批量删除的单次 IPC 超时：基础 15s + 每千条 2s，上限 300s。
///
/// 删除是单事务提交，耗时随记录数增长但远低于线性；上限用于防止
/// worker 挂死时永久阻塞。前端不设超时，等待本命令的真实结果。
const DELETE_BATCH_BASE_TIMEOUT_SECS: u64 = 15;
const DELETE_BATCH_TIMEOUT_PER_1K: u64 = 2;
const DELETE_BATCH_MAX_TIMEOUT_SECS: u64 = 300;

pub(crate) fn delete_batch_timeout(count: usize) -> std::time::Duration {
    let scaled = DELETE_BATCH_BASE_TIMEOUT_SECS
        .saturating_add((count as u64 / 1000).saturating_mul(DELETE_BATCH_TIMEOUT_PER_1K));
    std::time::Duration::from_secs(scaled.min(DELETE_BATCH_MAX_TIMEOUT_SECS))
}

/// 删除单条记录。
#[tauri::command]
pub async fn verthys_delete_record(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    id: u64,
) -> Result<VerthysResponse, String> {
    let _io = state.io_guard();
    if let Err(msg) = require_unlocked(&app, &state, "delete_record") {
        return Ok(VerthysResponse::err("delete_record", &msg));
    }

    let req = serde_json::json!({
        "op": "delete_record",
        "id": id,
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 批量删除记录，一次性传递 ID 列表，worker 在单次事务内完成删除。
///
/// 级联展开：输入通常是索引记录 ID（照片/文件 meta）。其外置块记录
/// （含瘦身布局的缩略图/块集）由外置块台账按 owner 反查补齐，前端无需
/// 为删除逐条解密 meta。台账不可用时拒绝本次删除：只删输入 ID 会让
/// 外置块变成无主活记录，物理字节与逻辑记录都无法再回收。
#[tauri::command]
pub async fn verthys_delete_records(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    ids: Vec<u64>,
) -> Result<VerthysResponse, String> {
    let _io = state.io_guard();
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, "delete_records") {
        return Ok(VerthysResponse::err("delete_records", &msg));
    }

    let mut all_ids: Vec<u64> = ids.into_iter().filter(|id| *id != 0).collect();
    all_ids.sort_unstable();
    all_ids.dedup();
    if all_ids.is_empty() {
        return Ok(VerthysResponse::ok("delete_records"));
    }

    /* 级联展开：索引记录 → 其外置块。活跃导入会话的台账在写者内存中，
     * 优先读取会话视图；否则加载磁盘台账（spawn_blocking 隔离同步 IO）。 */
    let mut ledger_for_cleanup: Option<verthys_chunks::ChunkLedger> = None;
    if let Some(vpath) = state.verthys_session_path() {
        let owners: HashSet<u64> = all_ids.iter().copied().collect();
        if state.has_import_session() {
            let guard = state.lock_import_session();
            if let Some(session) = guard.as_ref() {
                all_ids.extend(session.chunk_ledger.chunk_ids_for_owners(&owners));
            }
        } else {
            let load_path = vpath.clone();
            match tauri::async_runtime::spawn_blocking(move || {
                verthys_chunks::load_chunk_ledger(&load_path)
            })
            .await
            {
                Ok(Ok(ledger)) => {
                    all_ids.extend(ledger.chunk_ids_for_owners(&owners));
                    ledger_for_cleanup = Some(ledger);
                }
                Ok(Err(e)) => {
                    log::warn!(
                        "[verthys_delete_records] 块台账不可用，已取消删除以避免无主外置块: {}",
                        e
                    );
                    return Ok(VerthysResponse::err(
                        "delete_records",
                        "块台账不可用，已取消删除以避免残留外置块；请重试",
                    ));
                }
                Err(e) => {
                    log::warn!(
                        "[verthys_delete_records] 块台账加载任务异常，已取消删除: {}",
                        e
                    );
                    return Ok(VerthysResponse::err(
                        "delete_records",
                        "块台账加载异常，已取消删除以避免残留外置块；请重试",
                    ));
                }
            }
        }
        all_ids.sort_unstable();
        all_ids.dedup();
    }

    /* 预览记录不进块台账：按 meta 名称索引定位后并入同一次删除事务。
     * 查找失败只影响派生缓存，不阻断照片删除。 */
    if !all_ids.is_empty() {
        let req = serde_json::json!({"op": "photo_preview_ids", "ids": all_ids});
        match state.send(&req.to_string()) {
            Ok(raw) => match serde_json::from_str::<VerthysResponse>(&raw) {
                Ok(resp) if resp.ok => all_ids.extend(resp.ids.unwrap_or_default()),
                Ok(resp) => log::warn!(
                    "[verthys_delete_records] 预览记录定位失败（继续删除）: {:?}",
                    resp.error
                ),
                Err(e) => log::warn!(
                    "[verthys_delete_records] 预览定位响应解析失败（继续删除）: {}",
                    e
                ),
            },
            Err(e) => log::warn!(
                "[verthys_delete_records] 预览定位 worker 通信失败（继续删除）: {}",
                e
            ),
        }
        all_ids.sort_unstable();
        all_ids.dedup();
    }

    let timeout = delete_batch_timeout(all_ids.len());
    log::info!(
        "[verthys_delete_records] 批量删除 {} 条记录（超时 {}s）",
        all_ids.len(),
        timeout.as_secs()
    );
    let req = serde_json::json!({
        "op": "delete_records",
        "ids": all_ids,
    });
    let resp_json = state.send_with_timeout(&req.to_string(), timeout)?;
    let mut resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    if resp.ok {
        resp.processed_count = Some(all_ids.len() as u64);
        /* 删除成功后收敛台账：移除已删除块条目，避免台账随删除无限增长。
         * 落盘失败不改变删除结论（残留条目只影响后续 GC 判定面）。 */
        if let Some(mut ledger) = ledger_for_cleanup {
            if let Some(vpath) = state.verthys_session_path() {
                let removed = ledger.remove_many(&all_ids);
                if removed > 0 {
                    match tauri::async_runtime::spawn_blocking(move || {
                        verthys_chunks::save_chunk_ledger(&vpath, &ledger)
                    })
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => log::warn!(
                            "[verthys_delete_records] 块台账收敛落盘失败（删除已生效）: {}",
                            e
                        ),
                        Err(e) => log::warn!(
                            "[verthys_delete_records] 块台账收敛任务异常（删除已生效）: {}",
                            e
                        ),
                    }
                }
            }
        }
    }
    /* 删除已提交：空间回收由 C 存储引擎在事务提交时完成，本层不再
     * 触发任何后台压缩，删除响应也不等待空间整理。 */
    Ok(resp)
}

/// 获取当前已加载的轻量摘要记录数（用于 UI 展示）。
#[tauri::command]
pub async fn verthys_get_summary_count(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    let _io = state.io_guard();
    if let Err(msg) = require_unlocked(&app, &state, "get_summary_count") {
        return Ok(VerthysResponse::err("get_summary_count", &msg));
    }

    let req = serde_json::json!({
        "op": "get_summary_count",
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}

/// 轻量级检查是否存在指定类型的记录（只扫描摘要索引，不读数据块）。
#[tauri::command]
pub async fn verthys_has_record_by_type(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    rtype: u32,
) -> Result<VerthysResponse, String> {
    let _io = state.io_guard();
    if let Err(msg) = require_unlocked(&app, &state, "has_record_by_type") {
        return Ok(VerthysResponse::err("has_record_by_type", &msg));
    }

    let req = serde_json::json!({
        "op": "has_record_by_type",
        "rtype": rtype,
    });
    let resp_json = state.send(&req.to_string())?;
    let resp: VerthysResponse =
        serde_json::from_str(&resp_json).map_err(|e| format!("parse response: {}", e))?;
    Ok(resp)
}
