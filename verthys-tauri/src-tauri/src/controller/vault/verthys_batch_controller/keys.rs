/*
 * 导入去重键维护
 *
 * 职责边界：释放失效导入去重键，避免已删记录的条目键永久占用。
 */

use crate::constants::import_writer::WRITER_SEND_TIMEOUT;
use crate::controller::types::VerthysResponse;
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::repository::verthys_wal::{self};
use crate::constants::command_names::cmd;
use crate::state::import_writer::{
    self, WriterCommand,
};
use crate::state::AppState;
use tauri::State;

use super::*;
/* ------------------------------------------------------------------ *
 * 命令：verthys_forget_import_keys                                        *
 * ------------------------------------------------------------------ */

/// 删除照片后释放续传幂等锁（WAL 追加删除墓碑）。
///
/// 前端批量删除照片成功后调用：后端向 WAL 追加删除墓碑（含 fsync），
/// 恢复重放时从 committed 集合移除非内容条目键，实现「删除后可重新导入」。
/// 若存在活跃导入会话，同步更新会话内存集合与计数（本会话立即生效）。
/// WAL 与快照均不存在时为无操作（去重集合本为空）。
///
/// 条目键来源：`entry_keys` 由前端以来源元数据派生（非内容哈希）；meta
/// 不可解密或历史条目缺键时，前端传入 `record_ids`，后端据 WAL committed
/// 映射（entry_key → verthys_id）反查条目键。删除后记录 ID 不复用，
/// 按 ID 释放不会误伤仍存活的导入项。
#[tauri::command]
pub async fn verthys_forget_import_keys(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    entry_keys: Vec<String>,
    record_ids: Option<Vec<u64>>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, cmd::FORGET_IMPORT_KEYS) {
        return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, &msg));
    }
    let mut ids: Vec<u64> = record_ids.unwrap_or_default();
    ids.retain(|id| *id > 0);
    ids.sort_unstable();
    ids.dedup();
    if entry_keys.is_empty() && ids.is_empty() {
        return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, "条目键列表不能为空"));
    }
    if entry_keys
        .iter()
        .any(|h| h.is_empty() || h.len() > crate::constants::import_writer::MAX_RECORD_HASH_LEN)
    {
        return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, "条目键格式非法"));
    }

    // 活跃会话：墓碑必须经单写者 FIFO 落盘（与会话批量写入共用同一
    // WAL 文件句柄），命令层直接以第二句柄追加会与写者线程并发写
    // 同一文件，存在 JSON 行交错损坏风险
    if state.has_import_session() {
        let writer = match import_writer::ensure(&app) {
            Ok(w) => w,
            Err(e) => {
                log::error!("[verthys_forget_import_keys] 写者不可用: {}", e);
                return Ok(VerthysResponse::err(
                    cmd::FORGET_IMPORT_KEYS,
                    &format!("写入通道不可用: {}", e),
                ));
            }
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let cmd = WriterCommand::AppendRemoved {
            keys: entry_keys.clone(),
            record_ids: ids.clone(),
            reply: reply_tx,
        };
        if let Err(e) = submit_writer_cmd(&writer, cmd, reply_rx).await {
            log::error!("[verthys_forget_import_keys] 墓碑写入失败: {}", e);
            return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, &e));
        }

        log::info!(
            "[verthys_forget_import_keys] 墓碑已落盘: {} 条目键 + {} 记录 ID（经写者通道，会话内即时移除）",
            entry_keys.len(),
            ids.len()
        );

        let mut resp = VerthysResponse::ok(cmd::FORGET_IMPORT_KEYS);
        resp.processed_count = Some(entry_keys.len() as u64);
        return Ok(resp);
    }

    // 无活跃会话：不存在并发写者，直接以单句柄追加墓碑
    let vpath = match state.verthys_session_path() {
        Some(p) => p,
        None => {
            return Ok(VerthysResponse::err(
                cmd::FORGET_IMPORT_KEYS,
                "无法确定加密库路径，请先解锁",
            ));
        }
    };

    let vpath_clone = vpath.clone();
    let entry_keys_clone = entry_keys.clone();
    let ids_clone = ids.clone();
    let write_result = tokio::time::timeout(
        WRITER_SEND_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            // 记录 ID → 条目键：meta 不可解密时仍可释放续传幂等锁
            let resolved = verthys_wal::keys_for_ids(&vpath_clone, &ids_clone)?;
            let mut all_keys = entry_keys_clone;
            all_keys.extend(resolved);
            all_keys.sort_unstable();
            all_keys.dedup();
            verthys_wal::append_removed(&vpath_clone, &all_keys)?;
            Ok::<usize, String>(all_keys.len())
        }),
    )
    .await;

    let released = match write_result {
        Err(_) => {
            log::error!("[verthys_forget_import_keys] 墓碑写入超时");
            return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, "去重锁释放超时"));
        }
        Ok(Err(e)) => {
            log::error!("[verthys_forget_import_keys] 墓碑写入任务异常: {}", e);
            return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, "去重锁释放失败"));
        }
        Ok(Ok(Err(e))) => {
            log::error!("[verthys_forget_import_keys] 墓碑写入失败: {}", e);
            return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, &e));
        }
        Ok(Ok(Ok(n))) => n,
    };

    log::info!(
        "[verthys_forget_import_keys] 墓碑已落盘: {} 条目键（无活跃会话，恢复期生效）",
        released
    );

    let mut resp = VerthysResponse::ok(cmd::FORGET_IMPORT_KEYS);
    resp.processed_count = Some(released as u64);
    Ok(resp)
}
