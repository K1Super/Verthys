use std::sync::atomic::{AtomicU64, Ordering};

use crate::constants::command_names::cmd;
use crate::constants::import_writer as wconst;
use crate::constants::record_types::{
    TYPE_FILEVERTHYS_CHUNK, TYPE_PHOTO_CHUNK, TYPE_PHOTO_CHUNK_SET, TYPE_PHOTO_THUMB,
};
use crate::repository::verthys_wal::ImportSession;
use crate::state::AppState;
use crate::util::contracts::ChunkBlob;

use super::append_records::worker_add_record;
use super::worker_batch::{worker_add_records, worker_add_records_staged, WorkerAddError};
use super::writer_actor::{append_ledger_changes, now_ms, ChunkAppendOutcome};

/// 外置块角色是否受支持：未知角色值一律拒收，防越界类型写入容器索引。
///
/// 受支持角色覆盖照片链路（数据块 / 缩略图 / 块集）与清藏链路（文件块），
/// 各角色共用同一上传通道、会话幂等映射与孤儿台账。
pub(super) fn is_supported_chunk_rtype(rtype: u32) -> bool {
    matches!(
        rtype,
        TYPE_PHOTO_CHUNK | TYPE_PHOTO_THUMB | TYPE_PHOTO_CHUNK_SET | TYPE_FILEVERTHYS_CHUNK
    )
}

/// 块键格式校验：块键直接嵌入记录名，仅允许 16–64 个小写十六进制字符。
///
/// 块键是调用方生成的非内容键；限定字符集与长度可避免任意字符进入记录名，
/// 同时保证同一导入项重试的键稳定可复用。
pub(super) fn is_valid_chunk_key(key: &str) -> bool {
    (16..=64).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 暂存块内容哈希：固定 64 位小写十六进制 BLAKE3。
fn is_valid_chunk_hash(hash: &str) -> bool {
    hash.len() == 64 && is_valid_chunk_key(hash)
}

/// 由角色与调用方块键派生块记录名。
///
/// `chunk_key` 是随机/来源元数据派生的非内容键，不是内容哈希：记录名
/// 不承载原始文件名与分块序号，也不得让“同内容是否已存在”可被枚举。
pub(super) fn chunk_record_name(rtype: u32, chunk_key: &str) -> String {
    match rtype {
        TYPE_PHOTO_THUMB => format!("thumb_{}", chunk_key),
        TYPE_PHOTO_CHUNK_SET => format!("cset_{}", chunk_key),
        _ => format!("chunk_{}", chunk_key),
    }
}

/// 块载荷来源：inline=宿主持有 base64 密文；staged=密文驻留 worker 暂存区。
enum ChunkPayload {
    Inline(String),
    Staged {
        job_id: String,
        chunk_key: String,
        chunk_hash: String,
    },
}

/// 已通过本地校验、待批量上传的外置块
struct PreparedChunk {
    /// 输入下标
    idx: u64,
    /// 非内容块键（会话幂等映射的键）
    chunk_key: String,
    /// 记录类型（块 / 缩略图 / 块集 / 文件块）
    rtype: u32,
    /// 派生记录名（进入容器索引，不含原始文件名）
    record_name: String,
    payload: ChunkPayload,
}

/// 外置块上传（写者线程内）：校验 → 会话内幂等去重 → worker 批量 add_records。
///
/// 块记录不入 WAL：块是纯密文负载，meta committed 才是恢复单元；
/// 崩溃窗口产生的孤儿块记录为有界残留（≤ 一个未完成批次），
/// 同块键重传经会话映射幂等复用既有 ID，不产生重复记录。
///
/// 批量写入：一次 IPC 覆盖本批全部新块（C 层单事务提交），失败回退逐条
/// 以隔离单块错误；块上传是照片导入的热路径，逐块 IPC + 逐块提交会让
/// 大照片（数十块）的写放大与 IPC 往返随分块数线性增长。
pub(super) fn process_append_chunks(
    state: &AppState,
    chunks: Vec<ChunkBlob>,
    heartbeat: &AtomicU64,
) -> Result<ChunkAppendOutcome, String> {
    if chunks.is_empty() {
        log::warn!("[import_writer] 拒绝空块上传");
        return Err("块列表不能为空".to_string());
    }
    if chunks.len() > wconst::MAX_CHUNKS_PER_IPC {
        log::warn!(
            "[import_writer] 拒绝越限块上传: {} > {}",
            chunks.len(),
            wconst::MAX_CHUNKS_PER_IPC
        );
        return Err(format!(
            "单次块上传不超过 {} 条",
            wconst::MAX_CHUNKS_PER_IPC
        ));
    }
    let payload_bytes: usize = chunks
        .iter()
        .map(|c| {
            c.chunk_key.len()
                + c.data_b64.len()
                + c.job_id.len()
                + c.chunk_hash.len()
        })
        .sum();
    if payload_bytes > wconst::MAX_IPC_PAYLOAD_BYTES {
        log::warn!(
            "[import_writer] 拒绝越限块载荷: {} bytes > {}",
            payload_bytes,
            wconst::MAX_IPC_PAYLOAD_BYTES
        );
        return Err(format!(
            "块载荷超过上限 {} 字节",
            wconst::MAX_IPC_PAYLOAD_BYTES
        ));
    }
    /* 同一批次只允许一种载荷来源：inline 块带密文，staged 块只带引用。
     * 混合会让批量提交无法选择单一 worker 协议，显式拒绝。 */
    let staged_mode = chunks[0].staged;
    if chunks.iter().any(|chunk| chunk.staged != staged_mode) {
        log::warn!("[import_writer] 拒绝混合块批次（inline/staged）");
        return Err("块批次不得混合 inline 与暂存模式".to_string());
    }

    let mut session_guard = state.lock_import_session();
    let session: &mut ImportSession = session_guard
        .as_mut()
        .ok_or_else(|| format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN))?;

    let total = chunks.len();
    let mut ids: Vec<u64> = vec![0u64; total];
    let mut failed_indices: Vec<u64> = Vec::new();
    let mut ledger_changes: Vec<(u64, u64)> = Vec::new();
    let mut prepared: Vec<PreparedChunk> = Vec::with_capacity(total);

    // ===== 阶段 1：本地校验 + 会话幂等 =====
    for (i, chunk) in chunks.into_iter().enumerate() {
        heartbeat.store(now_ms(), Ordering::SeqCst);
        let idx = i as u64;

        // 输入校验：块键须为 16–64 位小写十六进制（进入记录名）；
        // inline 块要求非空 base64 密文，staged 块要求 job_id/chunk_hash
        // 完整且不得携带密文；角色类型须为已知外置载荷类型。畸形输入按条
        // 失败而不中止整批。
        let staged = chunk.staged;
        let payload_ok = if staged {
            chunk.data_b64.is_empty()
                && !chunk.job_id.is_empty()
                && chunk.job_id.len() <= 128
                && is_valid_chunk_hash(&chunk.chunk_hash)
        } else {
            !chunk.data_b64.is_empty()
        };
        if !is_valid_chunk_key(&chunk.chunk_key) || !payload_ok {
            log::warn!(
                "[import_writer] 块 {} 输入校验失败（块键/载荷/暂存引用非法）",
                idx
            );
            failed_indices.push(idx);
            continue;
        }
        let rtype = chunk.rtype.unwrap_or(TYPE_PHOTO_CHUNK);
        if !is_supported_chunk_rtype(rtype) {
            log::warn!(
                "[import_writer] 块 {} 记录类型越界被拒绝: rtype={}",
                idx,
                rtype
            );
            failed_indices.push(idx);
            continue;
        }

        // 会话内幂等：同块键复用既有 ID（批次重试安全；不同内容键不共享）
        if let Some(existing) = session.lookup_chunk(&chunk.chunk_key) {
            ids[i] = existing;
            continue;
        }

        let chunk_key = chunk.chunk_key;
        let record_name = chunk_record_name(rtype, &chunk_key);
        let payload = if staged {
            ChunkPayload::Staged {
                job_id: chunk.job_id,
                chunk_key: chunk_key.clone(),
                chunk_hash: chunk.chunk_hash,
            }
        } else {
            ChunkPayload::Inline(chunk.data_b64)
        };
        prepared.push(PreparedChunk {
            idx,
            chunk_key,
            rtype,
            record_name,
            payload,
        });
    }

    // ===== 阶段 2：批量写入（失败回退逐条） =====
    if !prepared.is_empty() {
        heartbeat.store(now_ms(), Ordering::SeqCst);
        let results: Vec<Option<u64>> = if staged_mode {
            let batch_items: Vec<(u32, &str, &str, &str, &str)> = prepared
                .iter()
                .map(|item| match &item.payload {
                    ChunkPayload::Staged {
                        job_id,
                        chunk_key,
                        chunk_hash,
                    } => (
                        item.rtype,
                        item.record_name.as_str(),
                        job_id.as_str(),
                        chunk_key.as_str(),
                        chunk_hash.as_str(),
                    ),
                    ChunkPayload::Inline(_) => {
                        unreachable!("staged 批次内不得出现 inline 块")
                    }
                })
                .collect();
            match worker_add_records_staged(state, &batch_items) {
                Ok(batch_ids) => batch_ids.into_iter().map(Some).collect(),
                Err(WorkerAddError::Transport(e)) => {
                    log::error!(
                        "[import_writer] 暂存块批量提交 worker 不可用，整批上抛重试: {}",
                        e
                    );
                    return Err(format!("worker 暂存块写入不可用: {}", e));
                }
                Err(WorkerAddError::Rejected(batch_err)) => {
                    log::warn!(
                        "[import_writer] 暂存块批量提交被拒绝，回退逐条: {}",
                        batch_err
                    );
                    let mut per_record: Vec<Option<u64>> = Vec::with_capacity(prepared.len());
                    for item in &prepared {
                        heartbeat.store(now_ms(), Ordering::SeqCst);
                        let ChunkPayload::Staged {
                            job_id,
                            chunk_key,
                            chunk_hash,
                        } = &item.payload
                        else {
                            unreachable!("staged 批次内不得出现 inline 块");
                        };
                        let single = [(
                            item.rtype,
                            item.record_name.as_str(),
                            job_id.as_str(),
                            chunk_key.as_str(),
                            chunk_hash.as_str(),
                        )];
                        match worker_add_records_staged(state, &single) {
                            Ok(ids) if ids.len() == 1 => per_record.push(Some(ids[0])),
                            Ok(_) => {
                                log::warn!(
                                    "[import_writer] 暂存块 {} 返回 ID 数量非法",
                                    item.idx
                                );
                                failed_indices.push(item.idx);
                                per_record.push(None);
                            }
                            Err(e) => {
                                log::warn!("[import_writer] 暂存块 {} 上传失败: {:?}", item.idx, e);
                                failed_indices.push(item.idx);
                                per_record.push(None);
                            }
                        }
                    }
                    per_record
                }
            }
        } else {
            let batch_items: Vec<(u32, &str, &str)> = prepared
                .iter()
                .map(|item| match &item.payload {
                    ChunkPayload::Inline(data_b64) => (
                        item.rtype,
                        item.record_name.as_str(),
                        data_b64.as_str(),
                    ),
                    ChunkPayload::Staged { .. } => {
                        unreachable!("inline 批次内不得出现暂存块")
                    }
                })
                .collect();
            match worker_add_records(state, &batch_items) {
                Ok(batch_ids) => batch_ids.into_iter().map(Some).collect(),
                Err(WorkerAddError::Transport(e)) => {
                    log::error!(
                        "[import_writer] 块批量上传 worker 不可用，整批上抛重试: {}",
                        e
                    );
                    return Err(format!("worker 块写入不可用: {}", e));
                }
                Err(WorkerAddError::Rejected(batch_err)) => {
                    log::warn!(
                        "[import_writer] 块批量上传被拒绝，回退逐条: {}",
                        batch_err
                    );
                    let mut per_record: Vec<Option<u64>> = Vec::with_capacity(prepared.len());
                    for item in &prepared {
                        heartbeat.store(now_ms(), Ordering::SeqCst);
                        let ChunkPayload::Inline(data_b64) = &item.payload else {
                            unreachable!("inline 批次内不得出现暂存块");
                        };
                        match worker_add_record(
                            state,
                            item.rtype,
                            &item.record_name,
                            data_b64,
                        ) {
                            Ok(id) => per_record.push(Some(id)),
                            Err(e) => {
                                log::warn!("[import_writer] 块 {} 上传失败: {}", item.idx, e);
                                failed_indices.push(item.idx);
                                per_record.push(None);
                            }
                        }
                    }
                    per_record
                }
            }
        };

        for (offset, item) in prepared.iter().enumerate() {
            heartbeat.store(now_ms(), Ordering::SeqCst);
            match results[offset] {
                Some(id) => {
                    session.remember_chunk(&item.chunk_key, id);
                    // 台账记账：刚上传的块 owner=0（未被 meta 引用，孤儿候选）
                    session.chunk_ledger.set_owner(id, 0);
                    ledger_changes.push((id, 0));
                    ids[item.idx as usize] = id;
                }
                None => {
                    // 失败已在逐条回退时入账；批量成功路径不会出现 None
                    if !failed_indices.contains(&item.idx) {
                        failed_indices.push(item.idx);
                    }
                }
            }
        }
    }

    log::info!(
        "[import_writer] 块上传完成: 提交={} 成功={} 失败={}",
        total,
        ids.iter().filter(|&&i| i > 0).count(),
        failed_indices.len()
    );

    // 台账落盘：刚上传块的 owner=0（孤儿候选）须持久化，否则崩溃后无法
    // 识别可回收块。采用追加日志而非全量快照，单批成本 O(变更数 + fsync)；
    // 追加失败只置脏标记，不把已写入容器的块退化为「整批失败」。
    heartbeat.store(now_ms(), Ordering::SeqCst);
    append_ledger_changes(session, &ledger_changes);
    heartbeat.store(now_ms(), Ordering::SeqCst);

    // 稳定输出：失败下标按输入序升序
    failed_indices.sort_unstable();

    Ok(ChunkAppendOutcome {
        ids,
        failed_indices,
    })
}
