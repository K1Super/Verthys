/*
 * 批量写入命令
 *
 * 职责边界：记录批与内容块的单写者提交；超时语义由 submit_writer_cmd 的
 * 三层超时保证，超时表示未入队，可按幂等键安全重试。
 */

use crate::controller::types::{BatchRecordInput, ChunkBlob, ImportBatchProgress, VerthysResponse};
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::constants::command_names::cmd;
use crate::state::import_writer::{
    self, BatchAppendOutcome, ChunkAppendOutcome, WriterCommand,
};
use crate::state::AppState;
use tauri::State;

use super::*;
/// 批量写入 N 条已加密记录（经单写者通道串行执行 WAL pending → worker
/// 批量 add_records → WAL committed → 检查点）。
///
/// 落实「N 次加密，1 次 IPC 传输」：前端 Worker 池并行加密 N 条记录后，
/// 单次 IPC 调用本命令写入。实际存储变更由唯一写者线程执行（worker
/// 批量事务提交 + 子批一次 WAL fsync），本命令仅做闸门、投递与应答
/// 组装，阻塞的存储 IO 由写者线程承担，不占用异步运行时线程。
///
/// 每条记录的语义（写者线程内）：
///   1. 条目键幂等：若 entry_key ∈ committed_keys → 跳过，ids[i]=0
///   2. WAL pending（子批级合并刷盘）
///   3. worker add_records：单次事务提交子批，返回分配的 verthys ID
///   4. WAL committed（按子批一次 fsync）
///   5. mark_committed：更新内存去重集合 + 累计计数
///   6. 失败处理：worker 失败 → failed_indices.push(i)，ids[i]=0；
///      子批失败时回退逐条写入以隔离单条错误
///   7. 进度推送：每条记录处理后通过 Channel 推送 ImportBatchProgress
/// 批次结束：WAL checkpoint（fsync）
///
/// 返回字段：
///   - ids：本批次每条记录分配的 verthys ID（0 表示幂等跳过或失败）
///   - batch_id：本批次 ID（从 1 递增）
///   - failed_indices：本批次失败记录的下标列表
///   - processed_count：本批次实际处理（含幂等跳过）的记录数
///   - total_count：导入会话累计已 committed 记录数（检查点）
///   - skipped_count：本批次因条目键幂等跳过的记录数
#[tauri::command]
pub async fn verthys_add_records_batch(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    records: Vec<BatchRecordInput>,
    on_progress: tauri::ipc::Channel<ImportBatchProgress>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, cmd::ADD_RECORDS_BATCH) {
        return Ok(VerthysResponse::err(cmd::ADD_RECORDS_BATCH, &msg));
    }

    let total_in_batch = records.len() as u64;
    log::info!(
        "[verthys_add_records_batch] 收到批量写入请求: {} 条记录",
        total_in_batch
    );

    // 快速失败：无活跃会话（权威判定在写者线程内持会话锁复核）
    if !state.has_import_session() {
        log::warn!("[verthys_add_records_batch] 无活跃导入会话，拒绝写入");
        return Ok(VerthysResponse::err(
            cmd::ADD_RECORDS_BATCH,
            &format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN),
        ));
    }

    // 取用写者（缺失/心跳失效时原地重建）——全部存储变更经唯一写者串行
    let writer = match import_writer::ensure(&app) {
        Ok(w) => w,
        Err(e) => {
            log::error!("[verthys_add_records_batch] 写者不可用: {}", e);
            return Ok(VerthysResponse::err(
                cmd::ADD_RECORDS_BATCH,
                &format!("写入通道不可用: {}", e),
            ));
        }
    };

    let (reply_tx, reply_rx) =
        tokio::sync::oneshot::channel::<Result<BatchAppendOutcome, String>>();
    let cmd = WriterCommand::AppendPending {
        records,
        progress: Some(on_progress),
        reply: reply_tx,
    };

    let outcome = match submit_writer_cmd(&writer, cmd, reply_rx).await {
        Ok(o) => o,
        Err(e) => return Ok(VerthysResponse::err(cmd::ADD_RECORDS_BATCH, &e)),
    };

    let mut resp = VerthysResponse::ok(cmd::ADD_RECORDS_BATCH);
    resp.ids = Some(outcome.ids);
    resp.batch_id = Some(outcome.batch_id);
    resp.failed_indices = Some(outcome.failed_indices);
    resp.processed_count = Some(outcome.processed_in_batch);
    resp.total_count = Some(outcome.total_committed);
    resp.skipped_count = Some(outcome.skipped_in_batch);
    Ok(resp)
}

/* ------------------------------------------------------------------ *
 * 命令：verthys_add_chunk_batch                                         *
 * ------------------------------------------------------------------ */

/// 上传外置加密块（大文件分块记录，经单写者通道串行落库）。
///
/// 大文件（块密文总量超过内联阈值）的照片先将块上传为独立记录，
/// 随后 meta 记录携带 chunk_ids 引用；块上传与 meta 写入同走唯一
/// 写者 FIFO，写者侧校验引用完整性（块必须在本会话已成功上传），
/// 未上传的引用按条拒绝，杜绝悬空引用入库。
///
/// 返回字段：
///   - ids：每块的记录 ID（0 = 失败；同块键重复上传复用既有 ID）
///   - failed_indices：失败块的下标列表
///
/// 块记录不进入 WAL committed 集合：块是纯密文负载，meta committed 才是
/// 恢复单元；同块键重传经会话映射幂等复用，不产生重复块记录。
#[tauri::command]
pub async fn verthys_add_chunk_batch(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    chunks: Vec<ChunkBlob>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, cmd::ADD_CHUNK_BATCH) {
        return Ok(VerthysResponse::err(cmd::ADD_CHUNK_BATCH, &msg));
    }

    log::info!(
        "[verthys_add_chunk_batch] 收到块上传请求: {} 条",
        chunks.len()
    );

    // 快速失败：无活跃会话（权威判定在写者线程内持会话锁复核）
    if !state.has_import_session() {
        log::warn!("[verthys_add_chunk_batch] 无活跃导入会话，拒绝块上传");
        return Ok(VerthysResponse::err(
            cmd::ADD_CHUNK_BATCH,
            &format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN),
        ));
    }

    // 取用写者（缺失/心跳失效时原地重建）——块上传与 meta 写入同一 FIFO
    let writer = match import_writer::ensure(&app) {
        Ok(w) => w,
        Err(e) => {
            log::error!("[verthys_add_chunk_batch] 写者不可用: {}", e);
            return Ok(VerthysResponse::err(
                cmd::ADD_CHUNK_BATCH,
                &format!("写入通道不可用: {}", e),
            ));
        }
    };

    let (reply_tx, reply_rx) =
        tokio::sync::oneshot::channel::<Result<ChunkAppendOutcome, String>>();
    let cmd = WriterCommand::AppendChunks {
        chunks,
        reply: reply_tx,
    };

    let outcome = match submit_writer_cmd(&writer, cmd, reply_rx).await {
        Ok(o) => o,
        Err(e) => return Ok(VerthysResponse::err(cmd::ADD_CHUNK_BATCH, &e)),
    };

    let mut resp = VerthysResponse::ok(cmd::ADD_CHUNK_BATCH);
    resp.ids = Some(outcome.ids);
    resp.failed_indices = Some(outcome.failed_indices);
    Ok(resp)
}
