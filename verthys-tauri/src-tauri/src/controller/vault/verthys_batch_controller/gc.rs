/*
 * 孤儿块回收
 *
 * 职责边界：结算台账后回收未被任何 meta 引用的块记录。结算失败即拒绝
 * 回收，宁可暂缓也不得删除可能仍被引用的块。
 */

use crate::controller::types::VerthysResponse;
use crate::controller::vault::verthys_controller::{delete_batch_timeout, require_unlocked};
use crate::constants::command_names::cmd;
use crate::state::AppState;
use tauri::{Manager, State};

use super::*;
/* ------------------------------------------------------------------ *
 * 命令：verthys_gc_orphan_chunks                                       *
 * ------------------------------------------------------------------ */

/// 孤儿外置块 GC：删除台账中 owner=0（未被任何 meta 引用）的块记录。
///
/// 大文件照片先以外置块（独立记录）上传，上传成功即记账 owner=0；随后
/// meta 记录入库时把引用块的 owner 改写为 meta id。若上传后、meta 入库
/// 前发生崩溃或导入中断，这些块记录残留且无引用，即为孤儿。
///
/// 流程：
///   1. 数据域解锁态闸门 + 活跃导入会话检查（会话期间台账驻留内存，
///      文件视图滞后，禁止 GC）；
///   2. spawn_blocking 内：结算块归属（依据 WAL 归属声明改写台账、冻结
///      无法证明归属的历史条目）→ 加载台账 → 取 garbage_ids()；
///   3. 空列表直接返回 ok（processed_count=0）；
///   4. 非空：经 worker delete_records 逐个删除，!ok 即 err（不删台账）；
///   5. 删除成功后从台账移除各垃圾 id 并落盘（落盘失败也 err，但记录已删，
///      下次 GC 重试收敛，语义无害）。
///
/// 结算失败即拒绝本次回收：台账若可能把已被引用的块判为孤儿，宁可暂缓
/// 回收也不得删除。
///
/// 返回 processed_count = 实际回收的块记录数。
#[tauri::command]
pub async fn verthys_gc_orphan_chunks(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, cmd::GC_ORPHAN_CHUNKS) {
        return Ok(VerthysResponse::err(cmd::GC_ORPHAN_CHUNKS, &msg));
    }

    /* 与 begin 共用生命周期锁：避免“检查无会话”后新会话开始上传块，
     * 本 GC 随后把 owner=0 的活跃块判为孤儿删除。 */
    let _lifecycle = IMPORT_LIFECYCLE_LOCK.lock().await;

    // 活跃会话期间台账驻留会话内存，磁盘台账文件视图滞后，禁止 GC
    if state.has_import_session() {
        log::warn!("[verthys_gc_orphan_chunks] 存在活跃导入会话，拒绝 GC");
        return Ok(VerthysResponse::err(
            cmd::GC_ORPHAN_CHUNKS,
            "存在活跃导入会话，请先结束导入",
        ));
    }

    let vpath = match state.verthys_session_path() {
        Some(p) => p,
        None => {
            return Ok(VerthysResponse::err(
                cmd::GC_ORPHAN_CHUNKS,
                "无法确定加密库路径，请先解锁",
            ));
        }
    };

    let gc_vpath = vpath.clone();
    let gc_app = app.clone();
    // 单次 GC 的整体超时上界：覆盖删除命令的最大超时 + 台账结算/落盘余量
    let gc_timeout =
        delete_batch_timeout(usize::MAX).saturating_add(std::time::Duration::from_secs(30));

    let outcome = tokio::time::timeout(
        gc_timeout,
        tauri::async_runtime::spawn_blocking(move || -> Result<u64, String> {
            // 结算必须先于台账读取：崩溃窗口内记录已提交而台账尚未改写归属，
            // 直接按台账回收会删掉仍被引用的块。结算失败即放弃本次回收。
            let settlement = crate::repository::verthys_wal::settle_chunk_owners(&gc_vpath)
                .map_err(|e| format!("块归属结算失败，放弃回收: {}", e))?;
            if settlement.changed() {
                log::info!(
                    "[verthys_gc_orphan_chunks] 回收前结算: 归属改写={} 冻结={}",
                    settlement.settled,
                    settlement.frozen
                );
            }

            let mut ledger = crate::repository::verthys_chunks::load_chunk_ledger(&gc_vpath)?;
            let garbage = ledger.garbage_ids();
            if garbage.is_empty() {
                return Ok(0);
            }

            let removed = garbage.len() as u64;
            let req = serde_json::json!({"op": "delete_records", "ids": garbage.clone()});
            let state = gc_app.state::<AppState>();
            let resp_json = state
                .send_with_timeout(&req.to_string(), delete_batch_timeout(garbage.len()))
                .map_err(|e| format!("worker 通信失败: {}", e))?;
            let resp: VerthysResponse = serde_json::from_str(&resp_json)
                .map_err(|e| format!("delete_records 响应解析失败: {}", e))?;
            if !resp.ok {
                return Err(format!("delete_records 失败: {:?}", resp.error));
            }

            // 删除成功后从台账移除垃圾条目；落盘失败也回 err，但块已删除，
            // 台账下次 GC 会重试收敛，无害。
            for id in &garbage {
                ledger.remove(id);
            }
            if let Err(e) = crate::repository::verthys_chunks::save_chunk_ledger(&gc_vpath, &ledger)
            {
                return Err(format!(
                    "块已删除但台账未收敛（下次 GC 会重试，无害）: {}",
                    e
                ));
            }
            Ok(removed)
        }),
    )
    .await;

    match outcome {
        Err(_) => {
            log::error!("[verthys_gc_orphan_chunks] GC 超时");
            Ok(VerthysResponse::err(
                cmd::GC_ORPHAN_CHUNKS,
                "孤儿块回收超时，请重试",
            ))
        }
        Ok(Err(e)) => {
            log::error!("[verthys_gc_orphan_chunks] GC 任务异常: {}", e);
            Ok(VerthysResponse::err(
                cmd::GC_ORPHAN_CHUNKS,
                "孤儿块回收失败",
            ))
        }
        Ok(Ok(Err(e))) => {
            log::error!("[verthys_gc_orphan_chunks] GC 失败: {}", e);
            Ok(VerthysResponse::err(cmd::GC_ORPHAN_CHUNKS, &e))
        }
        Ok(Ok(Ok(removed))) => {
            log::info!("[verthys_gc_orphan_chunks] 已回收 {} 个孤儿块", removed);
            let mut resp = VerthysResponse::ok(cmd::GC_ORPHAN_CHUNKS);
            resp.processed_count = Some(removed);
            Ok(resp)
        }
    }
}
