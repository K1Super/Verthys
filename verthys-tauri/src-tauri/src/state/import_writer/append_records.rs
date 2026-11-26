use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::ipc::Channel;

use crate::constants::command_names::cmd;
use crate::constants::import_writer as wconst;
use crate::constants::record_types::TYPE_PHOTO_PREVIEW;
use crate::repository::verthys_wal::{ImportSession, WalEntry};
use crate::state::AppState;
use crate::util::contracts::{BatchRecordInput, ImportBatchProgress};

use super::end_progress::emit_progress;
use super::worker_batch::{
    worker_add_records, PreparedRecord, WorkerAddError, WorkerWriteReply, WORKER_ADD_RECORDS_BATCH,
    WORKER_ADD_RECORDS_BYTES,
};
use super::writer_actor::{append_ledger_changes, now_ms};

/// 批量写入（写者线程内）：本地校验/幂等 → WAL pending（deferred）→
/// worker 批量 add_records（失败回退逐条）→ WAL committed 批量 fsync →
/// 检查点。窗口内持会话锁。
///
/// 性能契约：数据落盘按子批提交（每子批一次 C 层事务 + 一次 WAL fsync），
/// 不做逐条 fsync；单条失败仍按条计入 failed_indices，不中止批次。
pub(super) fn process_append_pending(
    state: &AppState,
    records: Vec<BatchRecordInput>,
    progress: Option<&Channel<ImportBatchProgress>>,
    heartbeat: &AtomicU64,
) -> Result<super::BatchAppendOutcome, String> {
    if records.is_empty() {
        log::warn!("[import_writer] 拒绝空批量写入");
        return Err("批量记录不能为空".to_string());
    }
    if records.len() > wconst::MAX_BATCH_RECORDS {
        log::warn!(
            "[import_writer] 拒绝越限批量写入: {} > {}",
            records.len(),
            wconst::MAX_BATCH_RECORDS
        );
        return Err(format!("批量记录数超过上限 {}", wconst::MAX_BATCH_RECORDS));
    }

    let batch_start = now_ms();
    let total_in_batch = records.len() as u64;
    log::info!("[import_writer] 开始批次: 记录数={}", total_in_batch);

    let mut session_guard = state.lock_import_session();
    let session: &mut ImportSession = session_guard
        .as_mut()
        .ok_or_else(|| format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN))?;

    let batch_id = session.allocate_batch_id();
    let import_id = session.import_id.clone();

    let mut ids: Vec<u64> = vec![0u64; records.len()];
    let mut failed_indices: Vec<u64> = Vec::new();
    let mut processed_in_batch: u64 = 0;
    let mut skipped_in_batch: u64 = 0;
    let mut committed_in_batch: u64 = 0;
    let mut ledger_changes: Vec<(u64, u64)> = Vec::new();
    let mut prepared: Vec<PreparedRecord> = Vec::with_capacity(records.len());

    // ===== 阶段 1：本地校验 + 幂等 + WAL pending，收集待批量写入记录 =====
    for (i, rec) in records.into_iter().enumerate() {
        let idx = i as u64;
        heartbeat.store(now_ms(), Ordering::SeqCst);

        // 条目键由前端生成（文件来源元数据键或解析来源键），不是内容哈希；
        // 缺失时用会话内稳定键兜底，保证同一批次重试不会因空键重复写入。
        let entry_key = if rec.entry_key.is_empty() {
            format!("auto-{}-{}", import_id, idx)
        } else {
            rec.entry_key.clone()
        };

        // 0. 输入校验：条目键/名称/载荷非空且不超上限。畸形或越限输入按条
        //    拒绝而不中止整批（与块上传路径同一纪律）；载荷上限取单条 IPC
        //    上限，防失控载荷进入 WAL 与 worker 写入。
        if entry_key.len() > wconst::MAX_RECORD_HASH_LEN
            || rec.name.is_empty()
            || rec.name.len() > wconst::MAX_RECORD_NAME_LEN
            || rec.data_b64.is_empty()
            || rec.data_b64.len() > wconst::MAX_IPC_PAYLOAD_BYTES
        {
            log::warn!(
                "[import_writer] 批次 {} 记录 {} 输入校验失败（条目键/名称/载荷非法或超限）",
                batch_id,
                idx
            );
            failed_indices.push(idx);
            processed_in_batch += 1;
            emit_progress(
                progress,
                session,
                batch_id,
                processed_in_batch,
                total_in_batch,
                batch_start,
            );
            continue;
        }

        // 1. 条目键幂等：entry_key ∈ committed_keys → 跳过（同一导入项重试）
        if session.is_committed(&entry_key) {
            skipped_in_batch += 1;
            session.mark_skipped();
            processed_in_batch += 1;
            emit_progress(
                progress,
                session,
                batch_id,
                processed_in_batch,
                total_in_batch,
                batch_start,
            );
            continue;
        }

        // 1.5 外置块引用校验：任一引用未在本会话成功上传即拒绝该条
        // （块上传与 meta 写入同走本写者 FIFO，未记账必然是越序或伪造）
        if let Some(chunk_ids) = rec.chunk_ids.as_deref() {
            if !session.chunk_refs_known(chunk_ids) {
                log::warn!(
                    "[import_writer] 批次 {} 记录 {} 外置块引用未上传，拒绝写入",
                    batch_id,
                    idx
                );
                failed_indices.push(idx);
                processed_in_batch += 1;
                emit_progress(
                    progress,
                    session,
                    batch_id,
                    processed_in_batch,
                    total_in_batch,
                    batch_start,
                );
                continue;
            }
        }

        // 2. WAL pending（deferred：不单独 fsync，随子批 committed / 末尾
        //    checkpoint 一并落盘——pending 恢复时本就被忽略，逐条落盘是纯浪费）
        if let Err(e) = session.writer.append_deferred(&WalEntry::Pending {
            import_id: import_id.clone(),
            batch_id,
            entry_key: entry_key.clone(),
            name: rec.name.clone(),
            idx,
        }) {
            log::error!(
                "[import_writer] 批次 {} 记录 {} WAL pending 写入失败: {}",
                batch_id,
                idx,
                e
            );
            failed_indices.push(idx);
            processed_in_batch += 1;
            emit_progress(
                progress,
                session,
                batch_id,
                processed_in_batch,
                total_in_batch,
                batch_start,
            );
            continue;
        }

        prepared.push(PreparedRecord {
            idx,
            record: rec,
            entry_key,
        });
    }

    // ===== 阶段 2：按条数 + 载荷预算切子批，批量写入并回填结果 =====
    let mut start = 0usize;
    while start < prepared.len() {
        let mut end = start;
        let mut bytes = 0usize;
        while end < prepared.len() && end - start < WORKER_ADD_RECORDS_BATCH {
            let item_bytes = prepared[end].record.name.len()
                + prepared[end].record.data_b64.len();
            if end > start && bytes.saturating_add(item_bytes) > WORKER_ADD_RECORDS_BYTES {
                break;
            }
            bytes = bytes.saturating_add(item_bytes);
            end += 1;
        }

        let slice: Vec<&PreparedRecord> = prepared[start..end].iter().collect();
        let batch_items: Vec<(u32, &str, &str)> = slice
            .iter()
            .map(|item| {
                (
                    item.record.rtype,
                    item.record.name.as_str(),
                    item.record.data_b64.as_str(),
                )
            })
            .collect();
        heartbeat.store(now_ms(), Ordering::SeqCst);

        // 批量接口在 C 层是全有或全无：成功即全成功；失败回退逐条写入，
        // 把单条坏记录的影响限制在该条，其余记录继续落库。
        let results: Vec<Option<u64>> = match worker_add_records(state, &batch_items) {
            Ok(batch_ids) => batch_ids.into_iter().map(Some).collect(),
            Err(WorkerAddError::Transport(e)) => {
                /* worker 不可达：逐条回退会把一次超时放大成 N 次超时，
                 * 整批上抛由调用方按幂等条目键重试。 */
                log::error!(
                    "[import_writer] 批次 {} 子批 [{}, {}) worker 不可用，整批上抛重试: {}",
                    batch_id,
                    start,
                    end,
                    e
                );
                return Err(format!("worker 批量写入不可用: {}", e));
            }
            Err(WorkerAddError::Rejected(batch_err)) => {
                log::warn!(
                    "[import_writer] 批次 {} 子批 [{}, {}) 批量写入被拒绝，回退逐条: {}",
                    batch_id,
                    start,
                    end,
                    batch_err
                );
                let mut per_record: Vec<Option<u64>> = Vec::with_capacity(slice.len());
                for item in &slice {
                    heartbeat.store(now_ms(), Ordering::SeqCst);
                    match worker_add_record(
                        state,
                        item.record.rtype,
                        &item.record.name,
                        &item.record.data_b64,
                    ) {
                        Ok(verthys_id) => per_record.push(Some(verthys_id)),
                        Err(e) => {
                            log::warn!(
                                "[import_writer] 批次 {} 记录 {} add_record 失败: {}",
                                batch_id,
                                item.idx,
                                e
                            );
                            failed_indices.push(item.idx);
                            per_record.push(None);
                        }
                    }
                }
                per_record
            }
        };

        // 4. WAL committed 子批一次 fsync；携带外置块集合供崩溃后归属结算。
        //    落盘失败时数据已入库，本会话内存集合仍记账（best-effort 去重），
        //    极端场景下的跨会话重复由下次续传幂等破坏承担。
        //    同一批次共用条目键的多条记录（meta 与预览）只落首条 committed 行：
        //    WAL 的 ID 映射是删除释放去重锁的权威来源，重复行会让后写记录
        //    覆盖索引记录 ID。
        let mut wal_keys: HashSet<&str> = HashSet::new();
        let committed_entries: Vec<WalEntry> = slice
            .iter()
            .zip(results.iter())
            .filter_map(|(item, result)| {
                result.and_then(|verthys_id| {
                    if !wal_keys.insert(item.entry_key.as_str()) {
                        return None;
                    }
                    Some(WalEntry::Committed {
                        import_id: import_id.clone(),
                        batch_id,
                        entry_key: item.entry_key.clone(),
                        verthys_id,
                        name: item.record.name.clone(),
                        chunk_ids: item.record.chunk_ids.clone(),
                    })
                })
            })
            .collect();
        if !committed_entries.is_empty() {
            if let Err(e) = session.writer.append_batch(&committed_entries) {
                log::error!(
                    "[import_writer] 批次 {} 子批 [{}, {}) WAL committed 写入失败: {}",
                    batch_id,
                    start,
                    end,
                    e
                );
            }
        }

        // 结果回填：ID / 幂等集合 / 外置块 owner / 进度
        for (offset, item) in slice.iter().enumerate() {
            if let Some(verthys_id) = results[offset] {
                session.mark_committed(&item.entry_key, verthys_id);
                ids[item.idx as usize] = verthys_id;
                committed_in_batch += 1;
                if let Some(chunk_ids) = item.record.chunk_ids.as_deref() {
                    for cid in chunk_ids {
                        session.chunk_ledger.set_owner(*cid, verthys_id);
                        ledger_changes.push((*cid, verthys_id));
                    }
                }
            }
            processed_in_batch += 1;
            emit_progress(
                progress,
                session,
                batch_id,
                processed_in_batch,
                total_in_batch,
                batch_start,
            );
        }
        start = end;
    }

    // 6. WAL checkpoint（批次末尾兜底 fsync，pending 至此必已持久）
    if let Err(e) = session.writer.append(&WalEntry::Checkpoint {
        import_id: import_id.clone(),
        batch_id,
        committed_count: session.total_committed,
    }) {
        log::error!(
            "[import_writer] 批次 {} WAL checkpoint 写入失败: {}",
            batch_id,
            e
        );
    }

    // 外置块归属变更以追加日志落盘（同一持锁窗口内，session_guard 尚未 drop）：
    // 仅写本批变更 + 一次 fsync，避免大会话反复重写整份台账导致 O(n²) 写放大。
    // 失败不中断批次，只置脏标记并在会话结束前做全量压缩。日志若停留在旧版本，
    // 已被 meta 引用的块仍显示为孤儿候选；回收前的 WAL 结算会兜底，且结束
    // 失败时拒绝压缩 WAL，确保归属声明不丢。
    append_ledger_changes(session, &ledger_changes);

    let total_committed = session.total_committed;
    // 释放会话锁（guard drop）
    drop(session_guard);

    // 稳定输出：失败下标按输入序升序，调用方回填/展示不依赖内部处理顺序
    failed_indices.sort_unstable();

    let elapsed = now_ms().saturating_sub(batch_start);
    log::info!(
        "[import_writer] 批次 {} 完成: committed={} skipped={} failed={} 耗时={}ms 累计 committed={}",
        batch_id,
        committed_in_batch,
        skipped_in_batch,
        failed_indices.len(),
        elapsed,
        total_committed
    );

    Ok(super::BatchAppendOutcome {
        batch_id,
        ids,
        failed_indices,
        processed_in_batch,
        skipped_in_batch,
        committed_in_batch,
        total_committed,
        elapsed_ms: elapsed,
    })
}

/// 向 worker 发起单条 add_record 并解析结果（错误分类统一脱敏）
///
/// 返回分配的记录 ID（>0）；worker 失败 / 响应解析失败 / 通信失败
/// 均分类为可读错误字符串，由调用方按条计入失败。
pub(super) fn worker_add_record(
    state: &AppState,
    rtype: u32,
    name: &str,
    data_b64: &str,
) -> Result<u64, String> {
    let req = serde_json::json!({
        "op": "add_record",
        "rtype": rtype,
        "name": name,
        "data": data_b64,
    });
    match state.send(&req.to_string()) {
        Ok(resp_json) => {
            match serde_json::from_str::<WorkerWriteReply>(&resp_json) {
                Ok(resp) if resp.ok => match resp.id {
                    Some(id) if id > 0 => Ok(id),
                    _ => {
                        log::warn!("[import_writer] worker add_record 返回 ID 无效");
                        Err("worker add_record 返回 ID 无效".to_string())
                    }
                },
                Ok(resp) => {
                    log::warn!(
                        "[import_writer] worker add_record 返回失败: {:?}",
                        resp.error
                    );
                    Err(format!("worker add_record 失败: {:?}", resp.error))
                }
                Err(e) => {
                    log::warn!("[import_writer] add_record 响应解析失败: {}", e);
                    Err(format!("响应解析失败: {}", e))
                }
            }
        }
        Err(e) => {
            log::warn!("[import_writer] add_record worker 通信失败: {}", e);
            Err(format!("worker 通信失败: {}", e))
        }
    }
}

/// worker 名称查找响应投影。
#[derive(serde::Deserialize)]
struct WorkerFindReply {
    ok: bool,
    #[serde(default)]
    found: Option<bool>,
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

/// 按名称查记录 ID（名称盲索引）；未命中返回 None。
fn worker_find_lid_by_name(state: &AppState, name: &str) -> Result<Option<u64>, String> {
    let req = serde_json::json!({ "op": "find_lid_by_name", "name": name });
    match state.send(&req.to_string()) {
        Ok(raw) => match serde_json::from_str::<WorkerFindReply>(&raw) {
            Ok(r) if r.ok => Ok(if r.found.unwrap_or(false) { r.id } else { None }),
            Ok(r) => Err(format!("worker find_lid_by_name 失败: {:?}", r.error)),
            Err(e) => Err(format!("find_lid_by_name 响应解析失败: {}", e)),
        },
        Err(e) => Err(format!("worker 通信失败: {}", e)),
    }
}

/// 派生缓存写入：不依赖导入会话；同名记录已存在时直接复用。
///
/// 名称幂等与写入在同一写者线程内完成，避免并发懒生成产生重复预览。
pub(super) fn process_append_derived(state: &AppState, record: BatchRecordInput) -> Result<u64, String> {
    if record.rtype != TYPE_PHOTO_PREVIEW {
        return Err("派生记录类型不被支持".to_string());
    }
    if record.name.is_empty()
        || record.name.len() > wconst::MAX_RECORD_NAME_LEN
        || record.data_b64.is_empty()
        || record.data_b64.len() > wconst::MAX_IPC_PAYLOAD_BYTES
    {
        return Err("派生记录名称或载荷非法".to_string());
    }
    if let Some(existing) = worker_find_lid_by_name(state, &record.name)? {
        return Ok(existing);
    }
    worker_add_record(state, record.rtype, &record.name, &record.data_b64)
}

/// 追加删除墓碑（写者线程内）：经会话写者句柄落盘 + 会话内存集合即时释放。
///
/// 与会话批量写入共用同一 WAL 文件句柄（FIFO 串行），杜绝命令层直开
/// 第二句柄并发追加导致的 JSON 行交错损坏。无活跃会话时调用方走
/// 直接追加路径（此时不存在并发写者）。
pub(super) fn process_append_removed(
    state: &AppState,
    keys: &[String],
    record_ids: &[u64],
) -> Result<(), String> {
    let mut session_guard = state.lock_import_session();
    let session = session_guard
        .as_mut()
        .ok_or_else(|| format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN))?;

    /* 记录 ID 解析条目键：删除时 meta 不可解密（或历史条目缺键）仍能
     * 凭 WAL committed 映射释放续传幂等锁。 */
    let mut resolved: Vec<String> = keys.to_vec();
    for id in record_ids {
        if let Some(key) = session.key_for_id(*id) {
            resolved.push(key.to_string());
        }
    }
    resolved.sort_unstable();
    resolved.dedup();
    if resolved.is_empty() {
        return Ok(());
    }

    session.writer.append(&WalEntry::Removed {
        keys: resolved.clone(),
        at: now_ms(),
    })?;

    let mut removed = 0u64;
    for key in &resolved {
        if session.forget_committed(key) {
            removed += 1;
        }
    }
    log::info!(
        "[import_writer] 墓碑已落盘: {} 条目键（会话内即时移除 {}）",
        resolved.len(),
        removed
    );
    Ok(())
}
