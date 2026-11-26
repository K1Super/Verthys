use tauri::ipc::Channel;

use crate::constants::command_names::cmd;
use crate::repository::verthys_chunks::save_chunk_ledger;
use crate::repository::verthys_wal::ImportSession;
use crate::state::AppState;
use crate::util::contracts::ImportBatchProgress;

use super::writer_actor::{now_ms, EndOutcome};

/// 推送单条记录处理后的进度（Channel 断开/不可用时忽略，进度不阻塞存储路径）
pub(super) fn emit_progress(
    progress: Option<&Channel<ImportBatchProgress>>,
    session: &ImportSession,
    batch_id: u64,
    processed: u64,
    total: u64,
    batch_start_ms: u64,
) {
    if let Some(channel) = progress {
        let _ = channel.send(ImportBatchProgress {
            batch_id,
            processed_in_batch: processed,
            total_in_batch: total,
            total_committed: session.total_committed,
            total_skipped: session.total_skipped,
            elapsed_ms: now_ms().saturating_sub(batch_start_ms),
        });
    }
}

/// 关闭导入会话（写者线程内）：取出会话 → WAL finish（end 条目 +
/// success 时 compact），会话随 guard 复位为空
pub(super) fn process_end(state: &AppState, success: bool) -> Result<EndOutcome, String> {
    let mut guard = state.lock_import_session();

    // 成功结束必须先让台账落盘：台账是块归属的权威副本，若落盘失败仍压缩
    // WAL，归属声明会随压缩消失，之后只能按过期台账回收。失败时保留会话与
    // WAL，调用方可排除磁盘障碍后重试结束，不丢失任何已提交数据。
    if success {
        let session = guard
            .as_mut()
            .ok_or_else(|| format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN))?;
        if let Err(e) = save_chunk_ledger(&session.verthys_path, &session.chunk_ledger) {
            log::error!("[import_writer] 会话结束前块台账落盘失败，拒绝结束: {}", e);
            return Err(format!(
                "块台账落盘失败，导入结束被拒绝（保留续传状态）: {}",
                e
            ));
        }
        session.ledger_dirty = false;
    }

    let session = guard
        .take()
        .ok_or_else(|| format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN))?;

    let import_id = session.import_id.clone();
    let total_committed = session.total_committed;
    session.writer.finish(&import_id, success)?;

    log::info!(
        "[import_writer] 会话已关闭: import_id={} success={} 累计 committed={}",
        import_id,
        success,
        total_committed
    );
    Ok(EndOutcome {
        import_id,
        total_committed,
    })
}
