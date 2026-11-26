use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::ipc::Channel;
use tauri::Manager;

use crate::constants::import_writer as wconst;
use crate::repository::verthys_chunks::append_chunk_ledger_entries;
use crate::repository::verthys_wal::ImportSession;
use crate::state::AppState;
use crate::util::contracts::{BatchRecordInput, ChunkBlob, ImportBatchProgress};

use super::append_chunks::process_append_chunks;
use super::append_records::{
    process_append_derived, process_append_pending, process_append_removed,
};
use super::end_progress::process_end;

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
    /// 写入派生缓存记录（当前仅照片预览）：不依赖导入会话，按记录名
    /// 幂等（已存在则复用），不进入 WAL/去重集合。
    AppendDerived {
        record: BatchRecordInput,
        /// 返回记录 ID（已存在时为既有 ID）
        reply: tokio::sync::oneshot::Sender<Result<u64, String>>,
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
pub(super) fn now_ms() -> u64 {
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
                WriterCommand::AppendDerived { reply, .. } => {
                    let _ = reply.send(Err("写者已被重建，请重试写入预览".to_string()));
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
            WriterCommand::AppendDerived { record, reply } => {
                let _ = reply.send(process_append_derived(&state, record));
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
pub(super) fn append_ledger_changes(session: &mut ImportSession, changes: &[(u64, u64)]) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
