/*
 * state/import_writer.rs — 照片导入单写者通道
 *
 * 职责：把「批量写入 + 会话关闭」两类存储变更收敛到唯一写者线程，
 * 避免命令线程内持会话锁 + 串行 worker IPC 的两个问题：
 *   - 阻塞的 worker IPC 占用 Tauri 异步运行时线程；
 *   - 并发变更仅靠会话互斥锁兜底，缺乏端到端超时与饥饿观察。
 *
 * 通道模型：
 *   - crossbeam bounded(WRITER_CHANNEL_CAPACITY) 队列背压，每命令携带独立 oneshot 应答；
 *   - 三层超时：命令层发送 / 应答层等待 / 写者心跳看门狗
 *     （阈值与巡检周期由 constants::import_writer 单源定义）；
 *   - 写者线程逐条命令执行时同步调用 worker 与 WAL，阻塞仅发生在本
 *     专用线程；心跳在每个命令与每条记录处理处刷新，防长批次误判。
 *
 * 重建语义（心跳超时）：
 *   只有确认旧写者线程已退出才允许重建。心跳陈旧但线程未退出时，旧线程
 *   可能仍持有导入会话锁；此时孵化新写者会永久阻塞在会话锁上（旧线程
 *   是唯一释放者），形成双写者死锁。该情形一律返回可重试的繁忙错误。
 *   确认退出后置死旧句柄并孵化新写者；旧线程已无任何未完成变更。
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
use crate::constants::record_types::{
    TYPE_FILEVERTHYS_CHUNK, TYPE_PHOTO_CHUNK, TYPE_PHOTO_CHUNK_SET, TYPE_PHOTO_THUMB,
};
use crate::controller::types::{BatchRecordInput, ChunkBlob, ImportBatchProgress};
use crate::repository::verthys_chunks::{append_chunk_ledger_entries, save_chunk_ledger};
use crate::repository::verthys_wal::{ImportSession, WalEntry};
use crate::security::command_names::cmd;
use crate::state::AppState;

/// 单批追加结果（命令应答负载）
#[derive(Debug)]
pub struct BatchAppendOutcome {
    /// 本批次 ID（写者线程内分配，保证 WAL 批次序单调）
    pub batch_id: u64,
    /// 本批次每条记录分配的 verthys ID（0 = 幂等跳过或失败）
    pub ids: Vec<u64>,
    /// 本批次失败记录的下标列表
    pub failed_indices: Vec<u64>,
    /// 本批次实际处理（含幂等跳过）的记录数
    pub processed_in_batch: u64,
    /// 本批次因条目键幂等跳过的记录数
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
    /// 每块对应的记录 ID（0 = 失败；同块键重复上传复用既有 ID）
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
    /// 共用同一文件句柄，避免命令层直接以第二句柄并发追加 WAL。
    /// `record_ids` 供 meta 不可解密时按记录 ID 解析条目键。
    AppendRemoved {
        keys: Vec<String>,
        record_ids: Vec<u64>,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

/// 写者句柄（存于 AppState，命令层取用后 Clone 发送；克隆为浅拷贝）
#[derive(Clone)]
pub struct ImportWriterHandle {
    tx: crossbeam_channel::Sender<WriterCommand>,
    last_heartbeat: Arc<AtomicU64>,
    alive: Arc<AtomicBool>,
    /// 写者线程是否已真正退出（区分“心跳陈旧但仍在执行长事务”）
    thread_exited: Arc<AtomicBool>,
}

impl ImportWriterHandle {
    /// 句柄是否可用（未被置死且心跳新鲜）
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
            && now_ms().saturating_sub(self.last_heartbeat.load(Ordering::SeqCst))
                < wconst::WRITER_HEARTBEAT_TIMEOUT_MS
    }

    /// 写者线程是否已退出（只有确认退出才允许重建，避免双写者竞争会话锁）
    pub fn is_thread_exited(&self) -> bool {
        self.thread_exited.load(Ordering::SeqCst)
    }

    /// 置死句柄（重建前隔离旧写者，防其继续变更存储）
    pub(crate) fn kill(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    /// 提交命令（带超时的有界发送）。
    ///
    /// 超时返回表示命令**未进入通道**，调用方可安全重试（幂等键保证）；
    /// 不会像外层 timeout 包裹 spawn_blocking 那样把命令遗弃在阻塞线程中。
    pub fn submit_timeout(&self, cmd: WriterCommand, timeout: Duration) -> Result<(), String> {
        match self.tx.send_timeout(cmd, timeout) {
            Ok(()) => Ok(()),
            Err(crossbeam_channel::SendTimeoutError::Timeout(_)) => {
                Err("写者通道繁忙（背压已满），请稍后重试".to_string())
            }
            Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                Err("写者通道已关闭，导入写入不可用".to_string())
            }
        }
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
    let (tx, rx) = crossbeam_channel::bounded::<WriterCommand>(wconst::WRITER_CHANNEL_CAPACITY);
    let last_heartbeat = Arc::new(AtomicU64::new(now_ms()));
    let alive = Arc::new(AtomicBool::new(true));
    let thread_exited = Arc::new(AtomicBool::new(false));

    let hb = Arc::clone(&last_heartbeat);
    let alive_clone = Arc::clone(&alive);
    let exited_clone = Arc::clone(&thread_exited);
    std::thread::Builder::new()
        .name("import-writer".into())
        .spawn(move || {
            /* panic 也必须落下退出标记：否则看门狗会看到一个“心跳陈旧但
             * 线程未退出”的写者，永远拒绝重建，导入永久不可用。 */
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                writer_loop(rx, app, hb, alive_clone);
            }));
            exited_clone.store(true, Ordering::SeqCst);
        })
        .map_err(|e| format!("写者线程创建失败: {}", e))?;

    Ok(ImportWriterHandle {
        tx,
        last_heartbeat,
        alive,
        thread_exited,
    })
}

/// 取用写者句柄：缺失或线程已退出 → 原地重建；返回可用句柄（可 Clone）
///
/// 心跳陈旧但线程**未退出**时拒绝重建：旧线程可能仍在执行一次长事务并
/// 持有导入会话锁，此时孵化新写者会让新线程永久阻塞在会话锁上（旧线程
/// 是唯一能释放锁的线程），形成“双写者死锁 + 全链路超时”的永久挂起。
/// 该情形返回繁忙错误，由调用方幂等重试；旧事务完成后心跳自然恢复。
pub fn ensure(app: &tauri::AppHandle) -> Result<ImportWriterHandle, String> {
    let state = app.state::<AppState>();
    let mut guard = state.lock_writer();
    if let Some(handle) = guard.as_ref() {
        if handle.is_alive() {
            return Ok(handle.clone());
        }
        if !handle.is_thread_exited() {
            log::error!(
                "[import_writer] 写者心跳陈旧但线程仍在执行长事务，拒绝重建以避免会话锁死锁"
            );
            return Err("写者正在执行长事务，请稍后重试".to_string());
        }
        handle.kill();
        log::warn!("[import_writer] 检测到写者线程已退出，触发重建");
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
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue, /* 空闲保活 */
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
                let _ = reply.send(process_append_chunks(&state, chunks, &heartbeat));
            }
            WriterCommand::AppendRemoved {
                keys,
                record_ids,
                reply,
            } => {
                let _ = reply.send(process_append_removed(&state, &keys, &record_ids));
            }
        }
        heartbeat.store(now_ms(), Ordering::SeqCst);
    }
}

/// 把一批台账归属变更追加到日志（写者线程内持有会话锁时调用）。
///
/// 失败只置脏标记并记录日志，不向上传播：台账是孤儿回收的判定依据，
/// 不是数据权威。追加失败时已入库记录不受影响，会话成功结束时仍会全量
/// 压缩写入全部内存条目；崩溃窗口内未落账的块只会保守地不被回收，
/// 不会扩大删除面。
fn append_ledger_changes(session: &mut ImportSession, changes: &[(u64, u64)]) {
    if changes.is_empty() {
        return;
    }
    if let Err(e) = append_chunk_ledger_entries(&session.verthys_path, changes) {
        session.ledger_dirty = true;
        log::error!(
            "[import_writer] 块台账日志追加失败（{} 条变更，会话结束前全量压缩重试）: {}",
            changes.len(),
            e
        );
    }
}

/// 批量写入的单次 worker 子批条数上限。
///
/// C 层 `VERTHYS_ADD_RECORDS_MAX` 为 512；此处取 128，使单条坏记录导致
/// 子批整体失败时，回退到逐条写入的代价有界，同时把 IPC 轮次压到
/// 「每 128 条 1 次」。
const WORKER_ADD_RECORDS_BATCH: usize = 128;

/// 单次 worker 子批的载荷预算（name + base64 数据字符数）。
///
/// 取单次 IPC 预算的 80%，余量覆盖 JSON 包装与协议字段；超过预算即切
/// 子批，避免大批量写入撞上协议行上限。
const WORKER_ADD_RECORDS_BYTES: usize = wconst::MAX_IPC_PAYLOAD_BYTES * 4 / 5;

/// 已通过本地校验、待批量写入的记录（下标保留用于结果回填）
struct PreparedRecord {
    /// 输入下标（failed_indices / ids 的语义位置）
    idx: u64,
    /// 原记录（数据已由调用方加密）
    record: BatchRecordInput,
    /// 归一化条目键（WAL 幂等键）
    entry_key: String,
}

/// 批量写入失败分类。
///
/// 区分传输级与记录级失败是性能与正确性的关键：
///   - Transport：worker 不可达/响应协议异常。逐条回退只会把一次 15s 超时
///     放大成 N×15s（128 条即半小时级挂起），必须整体上抛交调用方重试；
///   - Rejected：worker 正常响应但 C 层拒绝。逐条回退可隔离单条坏记录，
///     其余记录继续落库。
enum WorkerAddError {
    Transport(String),
    Rejected(String),
}

/// add_records 单条请求（借用原始载荷，避免中间 Value 复制整批 base64）
#[derive(serde::Serialize)]
struct AddRecordsItem<'a> {
    rtype: u32,
    name: &'a str,
    data: &'a str,
}

/// add_records 请求体（直接序列化，不经过 serde_json::Value 中转）
#[derive(serde::Serialize)]
struct AddRecordsRequest<'a> {
    op: &'static str,
    records: Vec<AddRecordsItem<'a>>,
}

/// 向 worker 发起一次批量 add_records 并解析结果。
///
/// 条目以 `(rtype, name, data_b64)` 元组传入：pending 记录与块上传共用同一
/// 批量协议，避免两份 JSON 构造与响应校验实现漂移。
/// 契约：成功时返回与输入等长且全为正 ID 的列表。
fn worker_add_records(
    state: &AppState,
    items: &[(u32, &str, &str)],
) -> Result<Vec<u64>, WorkerAddError> {
    let req = AddRecordsRequest {
        op: "add_records",
        records: items
            .iter()
            .map(|(rtype, name, data)| AddRecordsItem {
                rtype: *rtype,
                name,
                data,
            })
            .collect(),
    };
    let json = serde_json::to_string(&req)
        .map_err(|e| WorkerAddError::Transport(format!("请求序列化失败: {}", e)))?;
    match state.send(&json) {
        Ok(resp_json) => {
            match serde_json::from_str::<crate::controller::types::VerthysResponse>(&resp_json) {
                Ok(resp) if resp.ok => {
                    let ids = resp.ids.unwrap_or_default();
                    if ids.len() != items.len() || ids.iter().any(|id| *id == 0) {
                        log::warn!(
                            "[import_writer] worker add_records 返回 ID 列表非法: got={} expected={}",
                            ids.len(),
                            items.len()
                        );
                        return Err(WorkerAddError::Transport(
                            "worker add_records 返回 ID 列表非法".to_string(),
                        ));
                    }
                    Ok(ids)
                }
                Ok(resp) => {
                    log::warn!(
                        "[import_writer] worker add_records 返回失败: {:?}",
                        resp.error
                    );
                    Err(WorkerAddError::Rejected(format!(
                        "worker add_records 失败: {:?}",
                        resp.error
                    )))
                }
                Err(e) => {
                    log::warn!("[import_writer] add_records 响应解析失败: {}", e);
                    Err(WorkerAddError::Transport(format!("响应解析失败: {}", e)))
                }
            }
        }
        Err(e) => {
            log::warn!("[import_writer] add_records worker 通信失败: {}", e);
            Err(WorkerAddError::Transport(format!("worker 通信失败: {}", e)))
        }
    }
}

/// 批量写入（写者线程内）：本地校验/幂等 → WAL pending（deferred）→
/// worker 批量 add_records（失败回退逐条）→ WAL committed 批量 fsync →
/// 检查点。窗口内持会话锁。
///
/// 性能契约：数据落盘按子批提交（每子批一次 C 层事务 + 一次 WAL fsync），
/// 不做逐条 fsync；单条失败仍按条计入 failed_indices，不中止批次。
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
        let committed_entries: Vec<WalEntry> = slice
            .iter()
            .zip(results.iter())
            .filter_map(|(item, result)| {
                result.map(|verthys_id| WalEntry::Committed {
                    import_id: import_id.clone(),
                    batch_id,
                    entry_key: item.entry_key.clone(),
                    verthys_id,
                    name: item.record.name.clone(),
                    chunk_ids: item.record.chunk_ids.clone(),
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

/// 外置块角色是否受支持：未知角色值一律拒收，防越界类型写入容器索引。
///
/// 受支持角色覆盖照片链路（数据块 / 缩略图 / 块集）与清藏链路（文件块），
/// 各角色共用同一上传通道、会话幂等映射与孤儿台账。
fn is_supported_chunk_rtype(rtype: u32) -> bool {
    matches!(
        rtype,
        TYPE_PHOTO_CHUNK | TYPE_PHOTO_THUMB | TYPE_PHOTO_CHUNK_SET | TYPE_FILEVERTHYS_CHUNK
    )
}

/// 块键格式校验：块键直接嵌入记录名，仅允许 16–64 个小写十六进制字符。
///
/// 块键是调用方生成的非内容键；限定字符集与长度可避免任意字符进入记录名，
/// 同时保证同一导入项重试的键稳定可复用。
fn is_valid_chunk_key(key: &str) -> bool {
    (16..=64).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 由角色与调用方块键派生块记录名。
///
/// `chunk_key` 是随机/来源元数据派生的非内容键，不是内容哈希：记录名
/// 不承载原始文件名与分块序号，也不得让“同内容是否已存在”可被枚举。
fn chunk_record_name(rtype: u32, chunk_key: &str) -> String {
    match rtype {
        TYPE_PHOTO_THUMB => format!("thumb_{}", chunk_key),
        TYPE_PHOTO_CHUNK_SET => format!("cset_{}", chunk_key),
        _ => format!("chunk_{}", chunk_key),
    }
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
    /// 加密载荷 base64
    data_b64: String,
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
fn process_append_chunks(
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
        .map(|c| c.chunk_key.len() + c.data_b64.len())
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

        // 输入校验：块键须为 16–64 位小写十六进制（进入记录名），载荷非空；
        // 角色类型须为已知的外置载荷类型（未知类型拒绝该条，避免越界类型值
        // 写入容器索引）。畸形输入按条失败而不中止整批。
        if !is_valid_chunk_key(&chunk.chunk_key) || chunk.data_b64.is_empty() {
            log::warn!("[import_writer] 块 {} 输入校验失败（块键/载荷非法）", idx);
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

        let record_name = chunk_record_name(rtype, &chunk.chunk_key);
        prepared.push(PreparedChunk {
            idx,
            chunk_key: chunk.chunk_key,
            rtype,
            record_name,
            data_b64: chunk.data_b64,
        });
    }

    // ===== 阶段 2：批量写入（失败回退逐条） =====
    if !prepared.is_empty() {
        heartbeat.store(now_ms(), Ordering::SeqCst);
        let batch_items: Vec<(u32, &str, &str)> = prepared
            .iter()
            .map(|item| (item.rtype, item.record_name.as_str(), item.data_b64.as_str()))
            .collect();
        let results: Vec<Option<u64>> = match worker_add_records(state, &batch_items) {
            Ok(batch_ids) => batch_ids.into_iter().map(Some).collect(),
            Err(WorkerAddError::Transport(e)) => {
                log::error!("[import_writer] 块批量上传 worker 不可用，整批上抛重试: {}", e);
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
                    match worker_add_record(state, item.rtype, &item.record_name, &item.data_b64) {
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

/// 追加删除墓碑（写者线程内）：经会话写者句柄落盘 + 会话内存集合即时释放。
///
/// 与会话批量写入共用同一 WAL 文件句柄（FIFO 串行），杜绝命令层直开
/// 第二句柄并发追加导致的 JSON 行交错损坏。无活跃会话时调用方走
/// 直接追加路径（此时不存在并发写者）。
fn process_append_removed(
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

    fn rec(name: &str, entry_key: &str) -> BatchRecordInput {
        BatchRecordInput {
            rtype: 1,
            name: name.to_string(),
            entry_key: entry_key.to_string(),
            data_b64: "encoded".to_string(),
            chunk_ids: None,
            chunk_hashes: None,
        }
    }

    /// 台账落盘临时文件路径；把该路径占为目录即可令落盘确定性失败
    fn ledger_tmp_path(verthys_path: &str) -> std::path::PathBuf {
        let mut p = crate::repository::container_layout::chunk_ledger_file_for(verthys_path);
        let mut name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
        name.push(".tmp");
        p.set_file_name(name);
        p
    }

    #[test]
    fn test_process_end_success_compacts_and_clears_session() {
        let (state, verthys_path, _dir) = state_with_session();
        {
            let mut guard = state.lock_import_session();
            let session = guard.as_mut().unwrap();
            session.mark_committed("h1", 42);
            session
                .writer
                .append(&WalEntry::Committed {
                    import_id: "imp-test".into(),
                    batch_id: 1,
                    entry_key: "h1".into(),
                    verthys_id: 42,
                    name: "a.jpg".into(),
                    chunk_ids: Some(Vec::new()),
                })
                .unwrap();
        }

        let outcome = process_end(&state, true).unwrap();
        assert_eq!(outcome.total_committed, 1);
        assert_eq!(outcome.import_id, "imp-test");
        assert!(state.lock_import_session().is_none());

        let snap = verthys_wal::load(&verthys_path).unwrap();
        assert!(snap.committed_keys.contains("h1"));
        assert!(snap.active_import_id.is_none(), "end 后应无活跃会话");
    }

    #[test]
    fn test_process_end_missing_session_errors() {
        let state = AppState::new();
        assert!(process_end(&state, true).is_err());
        assert!(process_end(&state, false).is_err());
    }

    #[test]
    fn test_process_end_rejects_when_ledger_persist_fails() {
        // 成功结束以减少 WAL 为前提：台账落盘失败必须拒绝结束并保留会话，
        // 否则归属声明随压缩消失，之后只能按过期台账回收
        let (state, verthys_path, _dir) = state_with_session();
        let tmp_dir = ledger_tmp_path(&verthys_path);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let err = process_end(&state, true).unwrap_err();
        assert!(
            err.contains("台账落盘失败"),
            "错误应说明台账落盘失败: {}",
            err
        );
        assert!(
            state.lock_import_session().is_some(),
            "落盘失败必须保留会话以支持重试"
        );

        std::fs::remove_dir_all(&tmp_dir).unwrap();
        let outcome = process_end(&state, true).unwrap();
        assert_eq!(outcome.import_id, "imp-test");
        assert!(state.lock_import_session().is_none());
    }

    #[test]
    fn test_ledger_journal_append_failure_marks_dirty_and_end_compacts() {
        let (state, verthys_path, _dir) = state_with_session();
        let journal =
            crate::repository::container_layout::chunk_ledger_journal_file_for(&verthys_path);
        // 台账日志路径被同名目录占用 → 追加打开确定性失败
        std::fs::create_dir_all(&journal).unwrap();

        {
            let mut guard = state.lock_import_session();
            let session = guard.as_mut().unwrap();
            session.chunk_ledger.set_owner(7, 0);
            append_ledger_changes(session, &[(7, 0)]);
        }
        {
            let guard = state.lock_import_session();
            assert!(
                guard.as_ref().unwrap().ledger_dirty,
                "日志追加失败应置脏标记"
            );
        }

        // 排除障碍后，结束路径全量压缩写入内存台账并清理日志
        std::fs::remove_dir_all(&journal).unwrap();
        process_end(&state, true).unwrap();

        let loaded = crate::repository::verthys_chunks::load_chunk_ledger(&verthys_path).unwrap();
        assert_eq!(loaded.owner_of(7), Some(0));
        assert!(!journal.exists(), "全量压缩后日志必须被清理");
    }

    #[test]
    fn test_process_append_pending_worker_down_fails_batch_for_retry() {
        let (state, _verthys_path, _dir) = state_with_session();
        let records = vec![rec("a.jpg", "h1"), rec("b.jpg", "h2")];

        /* worker 不可达属传输级失败：整批上抛供调用方按幂等条目键重试，
         * 避免把一次超时放大成逐条 N 次超时。 */
        let err = process_append_pending(&state, records, None, &hb()).unwrap_err();
        assert!(err.contains("worker"), "错误应标注 worker 不可用: {err}");
    }

    #[test]
    fn test_process_append_pending_dedup_skips_committed() {
        let (state, _verthys_path, _dir) = state_with_session();
        {
            let mut guard = state.lock_import_session();
            guard.as_mut().unwrap().mark_committed("h1", 1);
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

        // 畸形条目：空名称 / 超长载荷 / 超长名称；逐条拒绝而不中止整批
        //（空条目键由会话内稳定键兜底，属合法输入，不作为畸形样例）
        let empty_name = rec("", "h1");
        let mut oversize = rec("b.jpg", "h2");
        oversize.data_b64 = "A".repeat(wconst::MAX_IPC_PAYLOAD_BYTES + 1);
        let long_name = rec(&"n".repeat(wconst::MAX_RECORD_NAME_LEN + 1), "h3");

        let outcome =
            process_append_pending(&state, vec![empty_name, oversize, long_name], None, &hb())
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
    fn test_process_append_chunks_worker_down_fails_batch_for_retry() {
        let (state, _verthys_path, _dir) = state_with_session();
        let chunks = vec![
            ChunkBlob {
                chunk_key: "a".repeat(64),
                data_b64: "x".into(),
                rtype: None,
            },
            ChunkBlob {
                chunk_key: "b".repeat(64),
                data_b64: "y".into(),
                rtype: None,
            },
        ];
        /* 传输级失败整批上抛，由协调器重试（块键幂等，不会产生重复语义） */
        let err = process_append_chunks(&state, chunks, &hb()).unwrap_err();
        assert!(err.contains("worker"), "错误应标注 worker 不可用: {err}");
    }

    #[test]
    fn test_process_append_chunks_rejects_empty_oversize_malformed() {
        let (state, _verthys_path, _dir) = state_with_session();
        assert!(process_append_chunks(&state, vec![], &hb()).is_err());

        let many: Vec<ChunkBlob> = (0..wconst::MAX_CHUNKS_PER_IPC + 1)
            .map(|i| ChunkBlob {
                chunk_key: format!("{i:064x}"),
                data_b64: "x".into(),
                rtype: None,
            })
            .collect();
        assert!(process_append_chunks(&state, many, &hb()).is_err());

        // 畸形输入按条失败，不中止整批（全部条目均在本地被拒绝时批次正常返回）
        let mixed = vec![
            ChunkBlob {
                chunk_key: "a".repeat(64),
                data_b64: "x".into(),
                rtype: Some(0x30), // 未知角色类型
            },
            ChunkBlob {
                chunk_key: String::new(), // 空块键
                data_b64: "y".into(),
                rtype: None,
            },
        ];
        let outcome = process_append_chunks(&state, mixed, &hb()).unwrap();
        assert_eq!(outcome.failed_indices, vec![0, 1], "畸形块必须入失败集");
        assert_eq!(outcome.ids, vec![0, 0]);
    }

    #[test]
    fn test_process_append_chunks_rejects_unknown_role_type() {
        let (state, _verthys_path, _dir) = state_with_session();
        // 未知角色类型（既非块也非缩略图）：按条拒绝，不写入越界类型
        let chunks = vec![ChunkBlob {
            chunk_key: "c".repeat(64),
            data_b64: "z".into(),
            rtype: Some(0x30),
        }];
        let outcome = process_append_chunks(&state, chunks, &hb()).unwrap();
        assert_eq!(outcome.failed_indices, vec![0]);
        assert_eq!(outcome.ids, vec![0]);
    }

    #[test]
    fn test_chunk_rtype_whitelist_covers_fileverthys_and_rejects_others() {
        // 受支持角色：照片数据块 / 缩略图 / 块集 + 清藏文件块
        assert!(is_supported_chunk_rtype(TYPE_FILEVERTHYS_CHUNK));
        assert!(is_supported_chunk_rtype(TYPE_PHOTO_CHUNK));
        assert!(is_supported_chunk_rtype(TYPE_PHOTO_THUMB));
        assert!(is_supported_chunk_rtype(TYPE_PHOTO_CHUNK_SET));

        // 非外置载荷角色（元数据类型 / 加密根记录 / 越界值）一律拒收
        assert!(!is_supported_chunk_rtype(0));
        assert!(!is_supported_chunk_rtype(0x08));
        assert!(!is_supported_chunk_rtype(0x10));
        assert!(!is_supported_chunk_rtype(0x30));
    }

    #[test]
    fn test_chunk_record_name_derivation_by_role() {
        let key = "d".repeat(64);
        let other = "f".repeat(64);

        // 清藏文件块与照片数据块共用默认前缀；缩略图与块集各有专属前缀
        assert_eq!(
            chunk_record_name(TYPE_FILEVERTHYS_CHUNK, &key),
            format!("chunk_{key}")
        );
        assert_eq!(
            chunk_record_name(TYPE_PHOTO_CHUNK, &key),
            format!("chunk_{key}")
        );
        assert_eq!(
            chunk_record_name(TYPE_PHOTO_THUMB, &key),
            format!("thumb_{key}")
        );
        assert_eq!(
            chunk_record_name(TYPE_PHOTO_CHUNK_SET, &key),
            format!("cset_{key}")
        );

        // 不同块键必须产生不同记录名（不是内容哈希，不跨文件复用）
        assert_ne!(
            chunk_record_name(TYPE_PHOTO_CHUNK, &key),
            chunk_record_name(TYPE_PHOTO_CHUNK, &other)
        );
        assert!(!chunk_record_name(TYPE_FILEVERTHYS_CHUNK, "e").contains("bin"));
    }

    #[test]
    fn test_chunk_key_format_validation() {
        // 合法：16–64 位小写十六进制
        assert!(is_valid_chunk_key(&"a".repeat(16)));
        assert!(is_valid_chunk_key(&"0f".repeat(32)));
        assert!(is_valid_chunk_key(&"a".repeat(64)));
        // 非法：过短 / 过长 / 大写 / 非十六进制字符
        assert!(!is_valid_chunk_key(&"a".repeat(15)));
        assert!(!is_valid_chunk_key(&"a".repeat(65)));
        assert!(!is_valid_chunk_key(&"A".repeat(64)));
        assert!(!is_valid_chunk_key(&"z".repeat(64)));
        assert!(!is_valid_chunk_key("chunk-0000-0000"));
        assert!(!is_valid_chunk_key(""));
    }

    #[test]
    fn test_process_append_chunks_rejects_malformed_key_format() {
        let (state, _verthys_path, _dir) = state_with_session();
        let chunks = vec![
            ChunkBlob {
                chunk_key: "A".repeat(64),
                data_b64: "x".into(),
                rtype: None,
            },
            ChunkBlob {
                chunk_key: "c".repeat(15),
                data_b64: "y".into(),
                rtype: None,
            },
        ];
        let outcome = process_append_chunks(&state, chunks, &hb()).unwrap();
        assert_eq!(outcome.failed_indices, vec![0, 1]);
        assert_eq!(outcome.ids, vec![0, 0]);
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
            thread_exited: Arc::new(AtomicBool::new(false)),
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
            thread_exited: Arc::new(AtomicBool::new(false)),
        };
        assert!(!stale.is_alive());
        assert!(!stale.is_thread_exited());
    }
}
