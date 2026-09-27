/*
 * state/import_writer.rs — 照片导入单写者通道
 *
 * 职责：把「批量写入 + 会话关闭」两类存储变更收敛到唯一写者线程，
 * 消除原先「命令线程内持会话锁 + 串行 worker IPC」模式的两个问题：
 *   - 阻塞的 worker IPC 占用 Tauri 异步运行时线程；
 *   - 并发变更仅靠会话互斥锁兜底，缺乏端到端超时与饥饿观察。
 *
 * 通道模型：
 *   - crossbeam bounded(1) 队列天然背压，每命令携带独立 oneshot 应答；
 *   - 三层超时：命令层发送 / 应答层等待 / 写者心跳看门狗
 *     （阈值与巡检周期由 constants::import_writer 单源定义）；
 *   - 写者线程逐条命令执行时同步调用 worker 与 WAL，阻塞仅发生在本
 *     专用线程；心跳在每个命令与每条记录处理处刷新，防长批次误判。
 *
 * 重建语义（心跳超时）：
 *   取用方/看门狗将旧写者置死（alive=false）并孵化新写者。置死后旧
 *   写者不再执行任何已排队命令，一律回「写者已被重建」错误引导调用方
 *   重试到新写者；仍在执行中的单条命令完成后，其产物由 WAL 哈希去重
 *   兜底（同哈希在新批次被跳过，不产生重复记录）。
 *
 * 依赖方向：state → worker / repository::verthys_wal / controller::types /
 *            constants（本模块与 import_session 同层，属会话级流程编排）
 */

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::ipc::Channel;
use tauri::Manager;

use crate::constants::import_writer as wconst;
use crate::constants::record_types::{TYPE_PHOTO_CHUNK, TYPE_PHOTO_CHUNK_SET, TYPE_PHOTO_THUMB};
use crate::controller::types::{BatchRecordInput, ChunkBlob, ImportBatchProgress};
use crate::repository::verthys_chunks::save_chunk_ledger;
use crate::repository::verthys_wal::{ImportSession, WalEntry};
use crate::security::command_names::cmd;
use crate::state::AppState;

/// 单批追加结果（命令应答负载）
#[derive(Debug)]
pub struct BatchAppendOutcome {
    /// 本批次 ID（写者线程内分配，保证 WAL 批次序单调）
    pub batch_id: u64,
    /// 本批次每条记录分配的 verthys ID（0 = 去重跳过或失败）
    pub ids: Vec<u64>,
    /// 本批次失败记录的下标列表
    pub failed_indices: Vec<u64>,
    /// 本批次实际处理（含去重跳过）的记录数
    pub processed_in_batch: u64,
    /// 本批次因哈希去重跳过的记录数
    pub skipped_in_batch: u64,
    /// 本批次新增 committed 的记录数
    pub committed_in_batch: u64,
    /// 导入会话累计已 committed 记录数（检查点）
    pub total_committed: u64,
    /// 本批次耗时（毫秒）
    pub elapsed_ms: u64,
}

/// 会话关闭结果（命令应答负载）
#[derive(Debug)]
pub struct EndOutcome {
    /// 已关闭的导入会话 ID
    pub import_id: String,
    /// 最终累计 committed 记录数
    pub total_committed: u64,
}

/// 外置块上传结果（命令应答负载）
#[derive(Debug)]
pub struct ChunkAppendOutcome {
    /// 每块对应的记录 ID（0 = 失败；同哈希重复上传复用既有 ID）
    pub ids: Vec<u64>,
    /// 失败块的下标列表
    pub failed_indices: Vec<u64>,
}

/// 写者命令（每命令独立 oneshot 应答，跨线程传递）
pub enum WriterCommand {
    /// 批量写入（WAL pending → worker add_record → WAL committed → 检查点）
    AppendPending {
        records: Vec<BatchRecordInput>,
        /// 前端进度 Channel（可选，测试路径不携带）
        progress: Option<Channel<ImportBatchProgress>>,
        reply: tokio::sync::oneshot::Sender<Result<BatchAppendOutcome, String>>,
    },
    /// 关闭导入会话（WAL end + 按需 compact）
    End {
        success: bool,
        reply: tokio::sync::oneshot::Sender<Result<EndOutcome, String>>,
    },
    /// 上传外置加密块（块记录不入 WAL，本会话幂等去重）
    AppendChunks {
        chunks: Vec<ChunkBlob>,
        reply: tokio::sync::oneshot::Sender<Result<ChunkAppendOutcome, String>>,
    },
    /// 追加删除墓碑（释放去重锁）：经会话写者句柄落盘，与会话批量写入
    /// 共用同一文件句柄，避免命令层直接以第二句柄并发追加 WAL
    AppendRemoved {
        hashes: Vec<String>,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

/// 写者句柄（存于 AppState，命令层取用后 Clone 发送；克隆为浅拷贝）
#[derive(Clone)]
pub struct ImportWriterHandle {
    tx: crossbeam_channel::Sender<WriterCommand>,
    last_heartbeat: Arc<AtomicU64>,
    alive: Arc<AtomicBool>,
}

impl ImportWriterHandle {
    /// 句柄是否可用（未被置死且心跳新鲜）
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
            && now_ms().saturating_sub(self.last_heartbeat.load(Ordering::SeqCst))
                < wconst::WRITER_HEARTBEAT_TIMEOUT_MS
    }

    /// 置死句柄（重建前隔离旧写者，防其继续变更存储）
    pub(crate) fn kill(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    /// 提交命令（阻塞发送；调用方须在 spawn_blocking + 超时内调用）
    pub fn submit(&self, cmd: WriterCommand) -> Result<(), String> {
        self.tx
            .send(cmd)
            .map_err(|_| "写者通道已关闭，导入写入不可用".to_string())
    }
}

/// 当前 Unix 毫秒时间戳
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// 孵化写者线程
///
/// 线程生命周期 = 应用生命周期（通道断开或进程退出时自然结束）。
/// 心跳超时触发的重建由 ensure 负责（旧句柄置死并替换），不在此处。
fn spawn_writer(app: tauri::AppHandle) -> Result<ImportWriterHandle, String> {
    let (tx, rx) = crossbeam_channel::bounded::<WriterCommand>(1);
    let last_heartbeat = Arc::new(AtomicU64::new(now_ms()));
    let alive = Arc::new(AtomicBool::new(true));

    let hb = Arc::clone(&last_heartbeat);
    let alive_clone = Arc::clone(&alive);
    std::thread::Builder::new()
        .name("import-writer".into())
        .spawn(move || writer_loop(rx, app, hb, alive_clone))
        .map_err(|e| format!("写者线程创建失败: {}", e))?;

    Ok(ImportWriterHandle {
        tx,
        last_heartbeat,
        alive,
    })
}

/// 取用写者句柄：缺失或已失效 → 原地重建；返回可用句柄（可 Clone）
pub fn ensure(app: &tauri::AppHandle) -> Result<ImportWriterHandle, String> {
    let state = app.state::<AppState>();
    let mut guard = state.lock_writer();
    if let Some(handle) = guard.as_ref() {
        if handle.is_alive() {
            return Ok(handle.clone());
        }
        handle.kill();
        log::warn!("[import_writer] 检测到写者失效，触发重建");
    }
    let handle = spawn_writer(app.clone())?;
    *guard = Some(handle.clone());
    log::info!("[import_writer] 写者已就绪");
    Ok(handle)
}

/// 启动写者心跳看门狗（应用 setup 时调用一次）
///
/// 巡检周期内对比写者最后心跳与超时阈值，超时即重建。重建通过置死
/// 隔离旧写者（其后续命令一律回错不执行），调用方经 ensure 获得与
/// 看门狗一致的重建能力，不存在第二套状态。
pub fn spawn_watchdog(app: tauri::AppHandle, shutdown: tokio_util::sync::CancellationToken) {
    tauri::async_runtime::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_millis(wconst::WRITER_HEARTBEAT_SWEEP_MS));
        interval.tick().await; // 跳过首次立即触发（启动时写者未必已创建）
        log::info!(
            "[import_writer] 心跳看门狗启动（巡检 {}ms / 阈值 {}ms）",
            wconst::WRITER_HEARTBEAT_SWEEP_MS,
            wconst::WRITER_HEARTBEAT_TIMEOUT_MS
        );
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    log::info!("[import_writer] 看门狗收到关闭信号，退出");
                    break;
                }
                _ = interval.tick() => {
                    let state = app.state::<AppState>();
                    if state.writer_is_stale() {
                        log::error!("[import_writer] 写者心跳超时，触发重建");
                        if let Err(e) = ensure(&app) {
                            log::error!("[import_writer] 写者重建失败: {}", e);
                        }
                    }
                }
            }
        }
    });
}

/// 写者线程主循环：串行消费命令，逐命令/逐记录刷新心跳
///
/// 空闲等待以巡检周期为粒度轮询并刷新心跳（空闲保活）：心跳仅在
/// 命令处理时刷新会使空闲超时（阈值 15s）的写者被看门狗误判死亡，
/// 触发"重建→就绪→通道关闭退出"的无意义循环；超时粒度取巡检周期
/// 保证任一巡检时刻心跳新鲜度恒小于阈值。
fn writer_loop(
    rx: crossbeam_channel::Receiver<WriterCommand>,
    app: tauri::AppHandle,
    heartbeat: Arc<AtomicU64>,
    alive: Arc<AtomicBool>,
) {
    loop {
        heartbeat.store(now_ms(), Ordering::SeqCst);
        let cmd = match rx.recv_timeout(Duration::from_millis(wconst::WRITER_HEARTBEAT_SWEEP_MS)) {
            Ok(c) => c,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,   /* 空闲保活 */
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                log::info!("[import_writer] 写者通道关闭，线程退出");
                break;
            }
        };

        // 心跳超时被重建：旧写者不再执行任何后续变更，仅回错引导重试
        if !alive.load(Ordering::SeqCst) {
            match cmd {
                WriterCommand::AppendPending { reply, .. } => {
                    let _ = reply.send(Err("写者已被重建，请重试本批次".to_string()));
                }
                WriterCommand::End { reply, .. } => {
                    let _ = reply.send(Err("写者已被重建，请重试结束操作".to_string()));
                }
                WriterCommand::AppendChunks { reply, .. } => {
                    let _ = reply.send(Err("写者已被重建，请重试块上传".to_string()));
                }
                WriterCommand::AppendRemoved { reply, .. } => {
                    let _ = reply.send(Err("写者已被重建，请重试释放去重锁".to_string()));
                }
            }
            continue;
        }

        let state = app.state::<AppState>();
        match cmd {
            WriterCommand::AppendPending {
                records,
                progress,
                reply,
            } => {
                let result = process_append_pending(&state, records, progress.as_ref(), &heartbeat);
                let _ = reply.send(result);
            }
            WriterCommand::End { success, reply } => {
                let _ = reply.send(process_end(&state, success));
            }
            WriterCommand::AppendChunks { chunks, reply } => {
                let _ = reply.send(process_append_chunks(&state, &chunks, &heartbeat));
            }
            WriterCommand::AppendRemoved { hashes, reply } => {
                let _ = reply.send(process_append_removed(&state, &hashes));
            }
        }
        heartbeat.store(now_ms(), Ordering::SeqCst);
    }
}

/// 批量写入（写者线程内）：去重 → WAL pending（deferred）→ worker
/// add_record → WAL committed（逐条 fsync）→ 检查点。窗口内持会话锁。
///
/// 与旧控制器内实现逐条语义等价；错误均按条计入 failed_indices，
/// 不因单条失败中止批次。
fn process_append_pending(
    state: &AppState,
    records: Vec<BatchRecordInput>,
    progress: Option<&Channel<ImportBatchProgress>>,
    heartbeat: &AtomicU64,
) -> Result<BatchAppendOutcome, String> {
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

    for (i, rec) in records.iter().enumerate() {
        let idx = i as u64;
        processed_in_batch += 1;
        heartbeat.store(now_ms(), Ordering::SeqCst);

        // 0. 输入校验：哈希/名称/载荷非空且不超上限。畸形或越限输入按条
        //    拒绝而不中止整批（与块上传路径同一纪律）；载荷上限取单条 IPC
        //    上限，防失控载荷进入 WAL 与 worker 写入。
        if rec.hash.is_empty()
            || rec.hash.len() > wconst::MAX_RECORD_HASH_LEN
            || rec.name.is_empty()
            || rec.name.len() > wconst::MAX_RECORD_NAME_LEN
            || rec.data_b64.is_empty()
            || rec.data_b64.len() > wconst::MAX_IPC_PAYLOAD_BYTES
        {
            log::warn!(
                "[import_writer] 批次 {} 记录 {} 输入校验失败（哈希/名称/载荷非法或超限）",
                batch_id,
                idx
            );
            failed_indices.push(idx);
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

        // 1. 哈希去重：hash ∈ committed_hashes → 跳过（幂等保证）
        if session.is_committed(&rec.hash) {
            skipped_in_batch += 1;
            session.mark_skipped();
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

        // 2. WAL pending（deferred：不单独 fsync，随批次内后续条目的
        //    fsync 落盘——pending 恢复时本就被忽略，逐条落盘是纯浪费）
        if let Err(e) = session.writer.append_deferred(&WalEntry::Pending {
            import_id: import_id.clone(),
            batch_id,
            hash: rec.hash.clone(),
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

        // 3. worker add_record（错误分类统一在 worker_add_record 内完成）
        match worker_add_record(state, rec.rtype, &rec.name, &rec.data_b64) {
            Ok(verthys_id) => {
                // 4. WAL committed（逐条 fsync；数据已即时落盘）
                match session.writer.append(&WalEntry::Committed {
                    import_id: import_id.clone(),
                    batch_id,
                    hash: rec.hash.clone(),
                    verthys_id,
                    name: rec.name.clone(),
                }) {
                    Ok(()) => {
                        session.mark_committed(&rec.hash);
                        ids[i] = verthys_id;
                        committed_in_batch += 1;
                    }
                    Err(e) => {
                        // committed 落盘失败：数据已入库，本会话内存集合
                        // 仍记账（best-effort 去重），极端场景下的跨会话
                        // 重复由下次续传幂等破坏承担
                        log::error!(
                            "[import_writer] 批次 {} 记录 {} WAL committed 写入失败: {}",
                            batch_id,
                            idx,
                            e
                        );
                        session.mark_committed(&rec.hash);
                        ids[i] = verthys_id;
                        committed_in_batch += 1;
                    }
                }
                // 外置块 owner 记账：meta 入库成功后，把其引用的块记录
                // owner 由 0 改写为 verthys_id（孤儿候选转正，不再被 GC 回收）
                if let Some(chunk_ids) = rec.chunk_ids.as_deref() {
                    if !chunk_ids.is_empty() {
                        for cid in chunk_ids {
                            session.chunk_ledger.set_owner(*cid, verthys_id);
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "[import_writer] 批次 {} 记录 {} add_record 失败: {}",
                    batch_id,
                    idx,
                    e
                );
                failed_indices.push(idx);
            }
        }

        // 5. 进度推送（每条记录处理后）
        emit_progress(
            progress,
            session,
            batch_id,
            processed_in_batch,
            total_in_batch,
            batch_start,
        );
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

    // 外置块台账落盘（同一持锁窗口内，session_guard 尚未 drop）：失败仅
    // 记 error 不中断批次。台账丢失不破坏已入库数据，GC 退化为保守不删。
    if let Err(e) = save_chunk_ledger(&session.verthys_path, &session.chunk_ledger) {
        log::error!(
            "[import_writer] 批次 {} 块台账落盘失败（GC 退化为保守不删）: {}",
            batch_id,
            e
        );
    }

    let total_committed = session.total_committed;
    // 释放会话锁（guard drop）
    drop(session_guard);

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

    Ok(BatchAppendOutcome {
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
fn worker_add_record(
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
            match serde_json::from_str::<crate::controller::types::VerthysResponse>(&resp_json) {
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

/// 外置块上传（写者线程内）：校验 → 会话内幂等去重 → worker add_record。
///
/// 块记录不入 WAL：块是纯密文负载，meta committed 才是恢复单元；
/// 崩溃窗口产生的孤儿块记录为有界残留（≤ 一个未完成批次），
/// 同哈希重传经会话映射幂等复用既有 ID，不产生重复记录。
fn process_append_chunks(
    state: &AppState,
    chunks: &[ChunkBlob],
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
    let payload_bytes: usize = chunks.iter().map(|c| c.hash.len() + c.data_b64.len()).sum();
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

    let mut session_guard = state.lock_import_session();
    let session: &mut ImportSession = session_guard
        .as_mut()
        .ok_or_else(|| format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN))?;

    let mut ids: Vec<u64> = Vec::with_capacity(chunks.len());
    let mut failed_indices: Vec<u64> = Vec::new();

    for (i, chunk) in chunks.iter().enumerate() {
        heartbeat.store(now_ms(), Ordering::SeqCst);
        let idx = i as u64;

        // 输入校验：哈希非空且不超上限（64 位 hex 块哈希的标准长度），
        // 载荷非空；角色类型须为已知的外置载荷类型（未知类型拒绝该条，
        // 避免越界类型值写入容器索引）。畸形输入按条失败而不中止整批
        if chunk.hash.is_empty()
            || chunk.hash.len() > wconst::MAX_RECORD_HASH_LEN
            || chunk.data_b64.is_empty()
        {
            log::warn!("[import_writer] 块 {} 输入校验失败（哈希/载荷非法）", idx);
            failed_indices.push(idx);
            ids.push(0);
            continue;
        }
        let rtype = chunk.rtype.unwrap_or(TYPE_PHOTO_CHUNK);
        if rtype != TYPE_PHOTO_CHUNK && rtype != TYPE_PHOTO_THUMB && rtype != TYPE_PHOTO_CHUNK_SET {
            log::warn!(
                "[import_writer] 块 {} 记录类型越界被拒绝: rtype={}",
                idx,
                rtype
            );
            failed_indices.push(idx);
            ids.push(0);
            continue;
        }
        let record_name = match rtype {
            TYPE_PHOTO_THUMB => format!("thumb_{}", chunk.hash),
            TYPE_PHOTO_CHUNK_SET => format!("cset_{}", chunk.hash),
            _ => format!("chunk_{}", chunk.hash),
        };

        // 会话内幂等去重：同哈希复用既有 ID（批次重试安全）
        if let Some(existing) = session.lookup_chunk(&chunk.hash) {
            ids.push(existing);
            continue;
        }

        // worker add_record（记录名与类型由角色决定；名称由哈希派生保证可追溯）
        match worker_add_record(state, rtype, &record_name, &chunk.data_b64) {
            Ok(id) => {
                session.remember_chunk(&chunk.hash, id);
                // 台账记账：刚上传的块 owner=0（未被 meta 引用，孤儿候选）
                session.chunk_ledger.set_owner(id, 0);
                ids.push(id);
            }
            Err(e) => {
                log::warn!("[import_writer] 块 {} 上传失败: {}", idx, e);
                failed_indices.push(idx);
                ids.push(0);
            }
        }
    }

    log::info!(
        "[import_writer] 块上传完成: 提交={} 成功={} 失败={}",
        chunks.len(),
        ids.iter().filter(|&&i| i > 0).count(),
        failed_indices.len()
    );

    // 台账落盘：刚上传块的 owner=0（孤儿候选）须持久化，否则崩溃后无法
    // 识别可回收块。落盘失败向上传播为 Err。
    if let Err(e) = save_chunk_ledger(&session.verthys_path, &session.chunk_ledger) {
        log::error!("[import_writer] 块台账落盘失败: {}", e);
        return Err(format!("块台账落盘失败: {}", e));
    }

    Ok(ChunkAppendOutcome {
        ids,
        failed_indices,
    })
}

/// 追加删除墓碑（写者线程内）：经会话写者句柄落盘 + 会话内存集合即时释放。
///
/// 与会话批量写入共用同一 WAL 文件句柄（FIFO 串行），杜绝命令层直开
/// 第二句柄并发追加导致的 JSON 行交错损坏。无活跃会话时调用方走
/// 直接追加路径（此时不存在并发写者）。
fn process_append_removed(state: &AppState, hashes: &[String]) -> Result<(), String> {
    let mut session_guard = state.lock_import_session();
    let session = session_guard
        .as_mut()
        .ok_or_else(|| format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN))?;

    session.writer.append(&WalEntry::Removed {
        hashes: hashes.to_vec(),
        at: now_ms(),
    })?;

    let mut removed = 0u64;
    for hash in hashes {
        if session.forget_committed(hash) {
            removed += 1;
        }
    }
    log::info!(
        "[import_writer] 墓碑已落盘: {} 哈希（会话内即时移除 {}）",
        hashes.len(),
        removed
    );
    Ok(())
}

/// 推送单条记录处理后的进度（Channel 断开/不可用时忽略，进度不阻塞存储路径）
fn emit_progress(
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
fn process_end(state: &AppState, success: bool) -> Result<EndOutcome, String> {
    let session = {
        let mut guard = state.lock_import_session();
        guard.take()
    };
    let session =
        session.ok_or_else(|| format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN))?;

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

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::verthys_wal;
    use tempfile::tempdir;

    /// 构造带活跃会话的 AppState（WAL 落于临时目录），返回时保留目录存活性
    fn state_with_session() -> (AppState, String, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let verthys_path = dir
            .path()
            .join("test.verthys")
            .to_string_lossy()
            .to_string();
        let state = AppState::new();
        let session = ImportSession::new(&verthys_path, "imp-test").unwrap();
        *state.lock_import_session() = Some(session);
        (state, verthys_path, dir)
    }

    fn hb() -> Arc<AtomicU64> {
        Arc::new(AtomicU64::new(0))
    }

    fn rec(name: &str, hash: &str) -> BatchRecordInput {
        BatchRecordInput {
            rtype: 1,
            name: name.to_string(),
            hash: hash.to_string(),
            data_b64: "encoded".to_string(),
            chunk_ids: None,
            chunk_hashes: None,
        }
    }

    #[test]
    fn test_process_end_success_compacts_and_clears_session() {
        let (state, verthys_path, _dir) = state_with_session();
        {
            let mut guard = state.lock_import_session();
            let session = guard.as_mut().unwrap();
            session.mark_committed("h1");
            session
                .writer
                .append(&WalEntry::Committed {
                    import_id: "imp-test".into(),
                    batch_id: 1,
                    hash: "h1".into(),
                    verthys_id: 42,
                    name: "a.jpg".into(),
                })
                .unwrap();
        }

        let outcome = process_end(&state, true).unwrap();
        assert_eq!(outcome.total_committed, 1);
        assert_eq!(outcome.import_id, "imp-test");
        assert!(state.lock_import_session().is_none());

        let snap = verthys_wal::load(&verthys_path).unwrap();
        assert!(snap.committed_hashes.contains("h1"));
        assert!(snap.active_import_id.is_none(), "end 后应无活跃会话");
    }

    #[test]
    fn test_process_end_missing_session_errors() {
        let state = AppState::new();
        assert!(process_end(&state, true).is_err());
        assert!(process_end(&state, false).is_err());
    }

    #[test]
    fn test_process_append_pending_worker_down_all_failed_gracefully() {
        let (state, verthys_path, _dir) = state_with_session();
        let records = vec![rec("a.jpg", "h1"), rec("b.jpg", "h2")];

        let outcome = process_append_pending(&state, records, None, &hb()).unwrap();
        assert_eq!(outcome.batch_id, 1);
        assert_eq!(outcome.failed_indices, vec![0, 1]);
        assert_eq!(outcome.ids, vec![0, 0]);
        assert_eq!(outcome.processed_in_batch, 2);
        assert_eq!(outcome.committed_in_batch, 0);
        assert_eq!(outcome.total_committed, 0);

        // 批次末尾检查点已落盘（pending 不进入 committed，检查点生效）
        let snap = verthys_wal::load(&verthys_path).unwrap();
        assert_eq!(snap.last_batch_id, 1);
        assert_eq!(snap.last_committed_count, 0);
        assert!(snap.committed_hashes.is_empty());
    }

    #[test]
    fn test_process_append_pending_dedup_skips_committed() {
        let (state, _verthys_path, _dir) = state_with_session();
        {
            let mut guard = state.lock_import_session();
            guard.as_mut().unwrap().mark_committed("h1");
        }

        let outcome =
            process_append_pending(&state, vec![rec("a.jpg", "h1")], None, &hb()).unwrap();
        assert_eq!(outcome.skipped_in_batch, 1);
        assert_eq!(outcome.committed_in_batch, 0);
        assert!(outcome.failed_indices.is_empty());
        assert_eq!(outcome.ids, vec![0]);
    }

    #[test]
    fn test_process_append_pending_rejects_empty_and_oversize() {
        let (state, _verthys_path, _dir) = state_with_session();
        assert!(process_append_pending(&state, vec![], None, &hb()).is_err());

        let many: Vec<BatchRecordInput> = (0..wconst::MAX_BATCH_RECORDS + 1)
            .map(|i| rec(&format!("f{}", i), &format!("h{}", i)))
            .collect();
        assert!(process_append_pending(&state, many, None, &hb()).is_err());
    }

    #[test]
    fn test_process_append_pending_rejects_malformed_per_item() {
        let (state, _verthys_path, _dir) = state_with_session();

        // 畸形条目：空哈希 / 空名称 / 超长载荷；逐条拒绝而不中止整批
        let empty_hash = rec("a.jpg", "");
        let empty_name = rec("", "h2");
        let mut oversize = rec("c.jpg", "h3");
        oversize.data_b64 = "A".repeat(wconst::MAX_IPC_PAYLOAD_BYTES + 1);

        let outcome =
            process_append_pending(&state, vec![empty_hash, empty_name, oversize], None, &hb())
                .unwrap();

        assert_eq!(outcome.failed_indices, vec![0, 1, 2]);
        assert_eq!(outcome.ids, vec![0, 0, 0]);
        assert_eq!(outcome.committed_in_batch, 0);
        assert_eq!(outcome.skipped_in_batch, 0);
        assert_eq!(outcome.processed_in_batch, 3);
    }

    #[test]
    fn test_process_append_pending_rejects_oversize_name() {
        let (state, _verthys_path, _dir) = state_with_session();
        let long_name = "n".repeat(wconst::MAX_RECORD_NAME_LEN + 1);

        let outcome =
            process_append_pending(&state, vec![rec(&long_name, "h1")], None, &hb()).unwrap();

        assert_eq!(outcome.failed_indices, vec![0]);
        assert_eq!(outcome.ids, vec![0]);
    }

    #[test]
    fn test_process_append_pending_missing_session_errors() {
        let state = AppState::new();
        let err =
            process_append_pending(&state, vec![rec("a.jpg", "h1")], None, &hb()).unwrap_err();
        assert!(err.contains("无活跃导入会话"));
    }

    #[test]
    fn test_process_append_chunks_worker_down_all_failed() {
        let (state, _verthys_path, _dir) = state_with_session();
        let chunks = vec![
            ChunkBlob {
                hash: "a".repeat(64),
                data_b64: "x".into(),
                rtype: None,
            },
            ChunkBlob {
                hash: "b".repeat(64),
                data_b64: "y".into(),
                rtype: None,
            },
        ];
        let outcome = process_append_chunks(&state, &chunks, &hb()).unwrap();
        assert_eq!(outcome.failed_indices, vec![0, 1]);
        assert_eq!(outcome.ids, vec![0, 0]);
    }

    #[test]
    fn test_process_append_chunks_rejects_empty_oversize_malformed() {
        let (state, _verthys_path, _dir) = state_with_session();
        assert!(process_append_chunks(&state, &[], &hb()).is_err());

        let many: Vec<ChunkBlob> = (0..wconst::MAX_CHUNKS_PER_IPC + 1)
            .map(|i| ChunkBlob {
                hash: format!("{i:064x}"),
                data_b64: "x".into(),
                rtype: None,
            })
            .collect();
        assert!(process_append_chunks(&state, &many, &hb()).is_err());

        // 畸形输入按条失败，不中止整批（worker 未初始化时其余块也按失败入账）
        let mixed = vec![
            ChunkBlob {
                hash: "a".repeat(64),
                data_b64: "x".into(),
                rtype: None,
            },
            ChunkBlob {
                hash: String::new(),
                data_b64: "y".into(),
                rtype: None,
            },
        ];
        let outcome = process_append_chunks(&state, &mixed, &hb()).unwrap();
        assert!(outcome.failed_indices.contains(&1), "畸形块必须入失败集");
        assert_eq!(outcome.ids[1], 0);
    }

    #[test]
    fn test_process_append_chunks_rejects_unknown_role_type() {
        let (state, _verthys_path, _dir) = state_with_session();
        // 未知角色类型（既非块也非缩略图）：按条拒绝，不写入越界类型
        let chunks = vec![ChunkBlob {
            hash: "c".repeat(64),
            data_b64: "z".into(),
            rtype: Some(0x30),
        }];
        let outcome = process_append_chunks(&state, &chunks, &hb()).unwrap();
        assert_eq!(outcome.failed_indices, vec![0]);
        assert_eq!(outcome.ids, vec![0]);
    }

    #[test]
    fn test_process_append_pending_dangling_chunk_ref_rejected() {
        let (state, _verthys_path, _dir) = state_with_session();
        // 引用未上传的块 ID：按条拒绝，不进入 WAL pending
        let mut record = rec("a.jpg", "h1");
        record.chunk_ids = Some(vec![999]);
        let outcome = process_append_pending(&state, vec![record], None, &hb()).unwrap();
        assert_eq!(outcome.failed_indices, vec![0]);
        assert_eq!(outcome.ids, vec![0]);
        assert_eq!(outcome.committed_in_batch, 0);
    }

    #[test]
    fn test_import_session_chunk_bookkeeping() {
        let (state, _verthys_path, _dir) = state_with_session();
        {
            let mut guard = state.lock_import_session();
            let session = guard.as_mut().unwrap();
            assert!(!session.chunk_refs_known(&[1]));
            session.remember_chunk("aa", 1);
            session.remember_chunk("bb", 2);
            assert_eq!(session.lookup_chunk("aa"), Some(1));
            assert!(session.chunk_refs_known(&[1, 2]));
            assert!(!session.chunk_refs_known(&[1, 3]));
        }
    }

    #[test]
    fn test_writer_handle_alive_semantics() {
        let (tx, _rx) = crossbeam_channel::bounded::<WriterCommand>(1);
        let handle = ImportWriterHandle {
            tx,
            last_heartbeat: Arc::new(AtomicU64::new(now_ms())),
            alive: Arc::new(AtomicBool::new(true)),
        };
        assert!(handle.is_alive());
        handle.kill();
        assert!(!handle.is_alive());

        // 心跳陈旧亦判定失效（即使未被置死）
        let (tx2, _rx2) = crossbeam_channel::bounded::<WriterCommand>(1);
        let stale = ImportWriterHandle {
            tx: tx2,
            last_heartbeat: Arc::new(AtomicU64::new(
                now_ms().saturating_sub(wconst::WRITER_HEARTBEAT_TIMEOUT_MS + 1000),
            )),
            alive: Arc::new(AtomicBool::new(true)),
        };
        assert!(!stale.is_alive());
    }
}
