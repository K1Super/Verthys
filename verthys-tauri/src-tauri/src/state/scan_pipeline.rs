/*
 * state/scan_pipeline.rs — 泛型扫描流水线状态机
 *
 *
 * 架构定位：状态层（state）扫描流水线模块
 *   - 依赖 controller::types（记录类型）+ infrastructure::shared_memory（SHM 读取）
 *   - 依赖 state::locked_buffer（LockedBuffer RAII）+ state::AppState（worker IPC）
 *   - 提供泛型 ScanPipelineState<T>，消除全量/摘要扫描的代码重复
 *
 * 第 11.3 项 — 泛型 ScanPipelineState<T: ScanRecord>：
 *   原 state.rs 中 ScanState（全量）与 ScanSummaryState（摘要）字段完全相同，
 *   仅 Vec<VerthysRecordEntry> vs Vec<VerthysSummaryEntry> 类型不同，导致 ~200 行
 *   逐字复制代码。泛型化后，全量与摘要实例化同一套状态机+双缓冲调度器。
 *
 *   trait ScanRecord: Zeroize + VirtualLockable + Clone + Send + 'static
 *     - Zeroize: 支持 LockedBuffer<T> Drop 时擦除
 *     - VirtualLockable: 支持 LockedBuffer<T> 构造时锁定
 *     - Clone: 支持 records().to_vec() 克隆用于响应
 *     - Send + 'static: 支持跨线程传递（Mutex 内存储 + tokio::spawn）
 *
 *   删除重复自由函数：
 *     - secure_zero_records / secure_zero_summary_records（由 LockedBuffer Drop 替代）
 *     - virtual_lock_summary_records / virtual_unlock_summary_records（由 LockedBuffer 替代）
 *
 * 第 11.4 项 — 预取改长期 tokio::task + mpsc 控制 + CancellationToken：
 *   原 spawn_prefetch 每批创建新 spawn_blocking 任务，取消用 handle.abort()。
 *   abort 不会等待任务安全退出，可能在 I/O 中途被强制终止，导致共享内存状态不一致。
 *
 *   新设计：
 *     - scan_open 时创建一个长期 prefetch_task（tokio::spawn）
 *     - 任务通过 mpsc::Receiver<PrefetchCommand> 接收命令
 *     - 每条 Fetch 命令携带 oneshot::Sender 回复通道
 *     - 取消用 CancellationToken，任务在安全点（命令间隙）自行退出
 *     - cleanup_scan_on_failure 发送 cancel + 短超时等待 join
 *     - 删除 handle.abort() + handle.await
 *
 * 第 2.4 项 — ScanSession 状态机：
 *   ScanPipelineState 本身即状态机，current_buffer: Option<LockedBuffer<T>>
 *   表示 Active（Some）/ Closed（None）状态。prefetch_task 的存在表示预取活跃。
 *
 * CI 红线：
 *   - 不输出 log::* 含记录内容/shm_name 值（仅输出类型名与长度）
 *   - 擦除顺序由 LockedBuffer Drop 保证（先 zeroize 后 VirtualUnlock）
 */

use crate::controller::types::{VerthysRecordEntry, VerthysResponse, VerthysSummaryEntry};
use crate::infrastructure::shared_memory::{read_shm_records, read_shm_summary_records};
use crate::state::locked_buffer::{LockedBuffer, VirtualLockable};
use crate::state::AppState;
use std::sync::Mutex;
use std::time::Duration;
use tauri::Manager;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

/* ------------------------------------------------------------------ *
 * 第 11.3 项：ScanRecord trait                                         *
 *                                                                    *
 * 泛型约束，使 ScanPipelineState<T> 可统一处理全量/摘要记录。          *
 * ------------------------------------------------------------------ */

/// 扫描记录抽象（第 11.3 项）
///
/// 约束说明：
///   - `Zeroize`: LockedBuffer<T> Drop 时调用 `T::zeroize()` 擦除敏感字段
///   - `VirtualLockable`: LockedBuffer<T> 构造时调用 `T::lockable_regions()` 锁定
///   - `Clone`: `locked.records().to_vec()` 克隆记录用于 API 响应
///   - `Send + 'static`: 跨线程传递（Mutex 内存储 + tokio::spawn 任务）
///
/// 关联常量：
///   - `FETCH_OP`: worker fetch 操作名（"scan_fetch" / "scan_summary_fetch"）
///   - `CLOSE_OP`: worker close 操作名（"scan_close" / "scan_summary_close"）
///   - `ABORT_OP`: worker abort 操作名（"scan_abort" / "scan_summary_abort"，第 2.1 项）
pub trait ScanRecord: Zeroize + VirtualLockable + Clone + Send + 'static {
    /// worker 端 fetch 操作名
    const FETCH_OP: &'static str;
    /// worker 端 close 操作名
    const CLOSE_OP: &'static str;
    /// 第 2.1 项：worker 端 abort 操作名（取消并回滚游标）
    const ABORT_OP: &'static str;

    /// 从共享内存读取一批记录
    ///
    /// 第 2.7 项：返回 `(记录列表, 共享内存是否已耗尽, worker 报告的 record_count)`。
    /// 调用方校验 `records.len() == record_count`，不一致则判定数据损坏熔断。
    /// 共享内存已耗尽表示本批是最后一批，但游标可能未遍历结束（需下一轮 fetch 确认）。
    fn read_from_shm(shm_name: &str) -> Result<(Vec<Self>, bool, usize), String>;
}

impl ScanRecord for VerthysRecordEntry {
    const FETCH_OP: &'static str = "scan_fetch";
    const CLOSE_OP: &'static str = "scan_close";
    const ABORT_OP: &'static str = "scan_abort";

    fn read_from_shm(shm_name: &str) -> Result<(Vec<Self>, bool, usize), String> {
        read_shm_records(shm_name)
    }
}

impl ScanRecord for VerthysSummaryEntry {
    const FETCH_OP: &'static str = "scan_summary_fetch";
    const CLOSE_OP: &'static str = "scan_summary_close";
    const ABORT_OP: &'static str = "scan_summary_abort";

    fn read_from_shm(shm_name: &str) -> Result<(Vec<Self>, bool, usize), String> {
        read_shm_summary_records(shm_name)
    }
}

/* ------------------------------------------------------------------ *
 * 第 11.4 项：预取命令 + 长期任务控制                                   *
 * ------------------------------------------------------------------ */

/// 预取结果（第 11.4 项）：记录批次 + 是否遍历结束 + worker 报告的 record_count（第 2.7 项）
pub type PrefetchReply<T> = Result<(Vec<T>, bool, usize), String>;

/// 预取任务命令（第 11.4 项）
///
/// 通过 mpsc 通道发送给长期预取任务。每条 Fetch 命令携带 oneshot 回复通道，
/// 任务处理完成后通过 reply 发送结果。
#[derive(Debug)]
pub enum PrefetchCommand<T: ScanRecord> {
    /// 拉取下一批记录
    ///
    /// 第 2.7 项：回复结果包含 worker 报告的 record_count，供控制器校验。
    Fetch {
        /// 批量大小（传递给 worker scan_fetch/scan_summary_fetch 的 id 参数）
        batch_size: u64,
        /// 回复通道（oneshot，任务处理完成后发送结果）
        reply: oneshot::Sender<PrefetchReply<T>>,
    },
}

/// 长期预取任务句柄（第 11.4 项）
///
/// 封装 mpsc::Sender（发送命令）+ CancellationToken（取消）+ JoinHandle（等待退出）。
///
/// 生命周期：
///   - scan_open 时通过 `PrefetchTaskHandle::spawn` 创建
///   - scan_next 时通过 `send_fetch` 发送命令，通过返回的 oneshot::Receiver 等待结果
///   - scan_close / cleanup 时通过 `shutdown(timeout)` 取消并等待退出
///
/// Drop 安全：Drop 时 cancel + 关闭通道，任务自行退出（JoinHandle 分离）。
/// 正常流程应显式调用 `shutdown` 以确保任务完全退出后再释放资源。
pub struct PrefetchTaskHandle<T: ScanRecord> {
    /// 命令通道发送端（drop 时关闭通道，任务 rx.recv() 返回 None 退出）
    /// Option 包裹以支持 shutdown 时 take（Self 实现 Drop，不能直接 move 字段）
    tx: Option<mpsc::Sender<PrefetchCommand<T>>>,
    /// 取消令牌（cancel 时任务在安全点退出）
    cancel: CancellationToken,
    /// 任务 JoinHandle（shutdown 时等待退出，Drop 时分离）
    join: Option<JoinHandle<()>>,
}

impl<T: ScanRecord> PrefetchTaskHandle<T> {
    /// 创建长期预取任务（第 11.4 项）
    ///
    /// 启动一个 tokio::spawn 任务，循环等待 mpsc 命令或取消信号。
    /// 任务在安全点（命令处理间隙）检查取消，不会在 I/O 中途被强制终止。
    ///
    /// # 参数
    /// - `app`: Tauri AppHandle（用于访问 AppState 发送 worker 请求）
    /// - `shm_name`: 共享内存名称（fetch 复用 scan_open 创建的段）
    ///
    /// # 返回
    /// PrefetchTaskHandle，可通过 `send_fetch` 发送命令、`shutdown` 取消
    pub fn spawn(app: tauri::AppHandle, shm_name: String) -> Self {
        let (tx, rx) = mpsc::channel::<PrefetchCommand<T>>(8);
        let cancel = CancellationToken::new();
        let join = tokio::spawn(prefetch_task::<T>(
            app,
            shm_name,
            rx,
            cancel.clone(),
        ));
        Self { tx: Some(tx), cancel, join: Some(join) }
    }

    /// 发送 Fetch 命令并返回回复接收器（第 11.4 项）
    ///
    /// 非阻塞：发送命令后立即返回 oneshot::Receiver。
    /// 调用方在合适的时机 `reply.await` 等待结果（双缓冲：当前批返回时下一批已在预取）。
    ///
    /// 第 2.7 项：回复结果包含 worker 报告的 record_count，供控制器校验。
    ///
    /// # 错误
    /// 返回 Err 表示任务已关闭（通道断开），调用方应触发熔断清理。
    pub async fn send_fetch(
        &self,
        batch_size: u64,
    ) -> Result<oneshot::Receiver<Result<(Vec<T>, bool, usize), String>>, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let tx = self
            .tx
            .as_ref()
            .ok_or("prefetch task already shut down")?;
        tx.send(PrefetchCommand::Fetch {
            batch_size,
            reply: reply_tx,
        })
        .await
        .map_err(|_| "prefetch task channel closed".to_string())?;
        Ok(reply_rx)
    }

    /// 取消任务并等待退出（第 11.4 项）
    ///
    /// 流程：
    ///   1. cancel.cancel() —— 触发取消信号
    ///   2. take self.tx 并 drop —— 关闭命令通道
    ///   3. take self.join —— tokio::time::timeout 等待任务退出
    ///
    /// 超时后任务仍未退出则分离（JoinHandle drop 不 abort），任务最终会因
    /// 通道关闭 + 取消信号自行退出。
    ///
    /// # 参数
    /// - `timeout`: 等待退出的最长时间（建议 2s）
    pub async fn shutdown(mut self, timeout: Duration) {
        self.cancel.cancel();
        // take + drop tx 关闭通道（显式 drop 表明意图）
        drop(self.tx.take());
        // take join 并等待退出（带超时）
        let join = match self.join.take() {
            Some(j) => j,
            None => return,
        };
        match tokio::time::timeout(timeout, join).await {
            Ok(Ok(())) => {
                log::debug!(
                    "[prefetch] 任务正常退出 (type={})",
                    std::any::type_name::<T>()
                );
            }
            Ok(Err(e)) => {
                log::warn!(
                    "[prefetch] 任务退出时 panic (type={}): {}",
                    std::any::type_name::<T>(),
                    e
                );
            }
            Err(_) => {
                log::warn!(
                    "[prefetch] 任务 {}ms 内未退出，分离 (type={})",
                    timeout.as_millis(),
                    std::any::type_name::<T>()
                );
            }
        }
    }

    /// 检查任务是否已取消
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

impl<T: ScanRecord> Drop for PrefetchTaskHandle<T> {
    fn drop(&mut self) {
        // 安全网：如果未显式调用 shutdown，Drop 时取消 + 关闭通道
        // JoinHandle 分离（Option::take 后 None，drop None 为 no-op）
        self.cancel.cancel();
        // take tx 并 drop（关闭命令通道，任务 rx.recv() 返回 None 退出）
        drop(self.tx.take());
        // join 保持 Some，drop 时分离任务（不 abort）
        // shutdown 已调用过的场景：tx/join 均为 None，drop 为 no-op
    }
}

/* ------------------------------------------------------------------ *
 * 第 11.4 项：长期预取任务实现                                          *
 * ------------------------------------------------------------------ */

/// 长期预取任务主循环（第 11.4 项）
///
/// 循环等待 mpsc 命令或 CancellationToken 取消。
/// 每条 Fetch 命令在 spawn_blocking 中执行同步 I/O（send_with_timeout + read_shm），
/// 不阻塞 tokio 异步运行时。
///
/// 安全点（检查取消）：
///   1. select! 分支优先检查 cancel.cancelled()
///   2. 每条 Fetch 命令处理前检查取消
///   3. 每条 Fetch 命令处理后检查取消
///
/// 退出条件：
///   - cancel.cancelled() 触发
///   - rx.recv() 返回 None（通道关闭，所有 Sender 已 drop）
async fn prefetch_task<T: ScanRecord>(
    app: tauri::AppHandle,
    shm_name: String,
    mut rx: mpsc::Receiver<PrefetchCommand<T>>,
    cancel: CancellationToken,
) {
    let type_name = std::any::type_name::<T>();
    log::debug!("[prefetch_task] 启动 (type={})", type_name);

    loop {
        // 安全点 1：select! 优先检查取消
        let cmd = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                log::debug!("[prefetch_task] 收到取消信号，退出 (type={})", type_name);
                break;
            }
            cmd = rx.recv() => match cmd {
                Some(c) => c,
                None => {
                    log::debug!("[prefetch_task] 通道关闭，退出 (type={})", type_name);
                    break;
                }
            }
        };

        match cmd {
            PrefetchCommand::Fetch { batch_size, reply } => {
                // 安全点 2：处理前检查取消
                if cancel.is_cancelled() {
                    let _ = reply.send(Err("prefetch cancelled".to_string()));
                    break;
                }

                // 在 spawn_blocking 中执行同步 I/O
                let app_clone = app.clone();
                let shm_clone = shm_name.clone();
                let result = tokio::task::spawn_blocking(move || {
                    do_prefetch_blocking::<T>(&app_clone, &shm_clone, batch_size)
                })
                .await;

                let result = match result {
                    Ok(r) => r,
                    Err(join_err) => Err(format!(
                        "prefetch spawn_blocking join error: {}",
                        join_err
                    )),
                };

                // 发送回复（如果接收端已 drop 则忽略）
                let _ = reply.send(result);

                // 安全点 3：处理后检查取消
                if cancel.is_cancelled() {
                    log::debug!(
                        "[prefetch_task] 处理完成后发现取消信号，退出 (type={})",
                        type_name
                    );
                    break;
                }
            }
        }
    }

    log::debug!("[prefetch_task] 退出 (type={})", type_name);
}

/// 同步执行预取 I/O（第 11.4 项）
///
/// 在 spawn_blocking 中调用：
///   1. 通过 AppState::send_with_timeout 发送 fetch 请求到 worker
///   2. 通过 T::read_from_shm 从共享内存读取记录
///
/// 第 2.7 项：返回 worker 报告的 record_count（来自 SHM 头部），
/// 供控制器校验 records.len() == record_count。
///
/// # 错误
/// - send_with_timeout 失败（worker 超时/断开）
/// - 响应解析失败
/// - worker 返回 !ok（可能是熔断）
/// - 共享内存读取失败
fn do_prefetch_blocking<T: ScanRecord>(
    app: &tauri::AppHandle,
    shm_name: &str,
    batch_size: u64,
) -> Result<(Vec<T>, bool, usize), String> {
    let state = app.state::<AppState>();
    let req = serde_json::json!({
        "op": T::FETCH_OP,
        "id": batch_size,
    });
    // 第 2.6 项：预取内部二级超时（使用 TimeoutConfig.scan_prefetch）
    let prefetch_timeout = crate::constants::timeout::DEFAULT.scan_prefetch;
    let resp_json = state.send_with_timeout(&req.to_string(), prefetch_timeout)?;
    let resp: VerthysResponse = serde_json::from_str(&resp_json)
        .map_err(|e| format!("parse response: {}", e))?;
    if !resp.ok {
        return Err(format!("{} failed: {:?}", T::FETCH_OP, resp.error));
    }
    // fetch 复用 scan_open 创建的共享内存段，使用原有 shm_name 读取
    T::read_from_shm(shm_name)
}

/* ------------------------------------------------------------------ *
 * 第 11.3 项：ScanPipelineState<T> 泛型状态                             *
 * 第 2.4 项：ScanSessionState 状态机                                    *
 * ------------------------------------------------------------------ */

/// 扫描会话状态机（第 2.4 项）
///
/// 所有扫描操作（open/next/close/abort）经此状态机原子状态转移。
/// 预取失败转 Failed 禁后续 next；close/abort 安全回收转 Closed。
///
/// 状态转移图：
///   (无) --open--> Active --next--> Active (循环)
///                  Active --close--> Closed
///                  Active --abort--> Closed
///                  Active --prefetch 失败--> Failed --close--> Closed
///                  Failed --next--> 拒绝（返回错误）
///                  Closed --any--> 拒绝（返回错误）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanSessionState {
    /// 活跃：游标已打开，可执行 next
    Active,
    /// 失败：预取/读取异常，禁后续 next，需 close 回收
    Failed,
    /// 已关闭：所有资源已释放，不可再操作
    Closed,
}

impl ScanSessionState {
    /// 是否允许执行 scan_next
    pub fn allow_next(&self) -> bool {
        matches!(self, ScanSessionState::Active)
    }
}

/// 泛型扫描流水线状态（第 11.3 项）
///
/// 全量扫描（VerthysRecordEntry）与摘要扫描（VerthysSummaryEntry）共用此结构。
/// 消除原 ScanState + ScanSummaryState 约 200 行重复代码。
///
/// 字段说明：
///   - `shm_name`: scan_open 返回的共享内存名称，fetch 复用此段
///   - `current_buffer`: 当前缓冲区（A 区/B 区），LockedBuffer RAII 保证锁定+擦除
///   - `exhausted`: 游标是否已遍历结束（true = 无更多数据）
///   - `prefetch_task`: 长期预取任务句柄（None = 无预取，如已遍历结束）
///   - `pending_reply`: 待接收的预取结果（scan_next 时 await 此 receiver）
///   - `session_state`: 第 2.4 项 ScanSession 状态机（Active/Failed/Closed）
///
/// 双缓冲流水线：
///   scan_open  → 首批 → current_buffer，同时发 Fetch → pending_reply
///   scan_next  → await pending_reply → 新 current_buffer，同时发 Fetch → 新 pending_reply
///   scan_close → shutdown prefetch_task + drop current_buffer + 通知 worker
pub struct ScanPipelineState<T: ScanRecord> {
    /// 共享内存名称（scan_open 返回，fetch 复用）
    pub shm_name: String,
    /// 当前缓冲区（LockedBuffer RAII：构造时锁定，Drop 时擦除+解锁）
    pub current_buffer: Option<LockedBuffer<T>>,
    /// 游标是否已遍历结束
    pub exhausted: bool,
    /// 长期预取任务句柄（第 11.4 项）
    pub prefetch_task: Option<PrefetchTaskHandle<T>>,
    /// 待接收的预取结果（第 11.4 项：scan_next 时 await 此 receiver）
    pub pending_reply: Option<oneshot::Receiver<PrefetchReply<T>>>,
    /// 第 2.4 项：ScanSession 状态机
    pub session_state: ScanSessionState,
}

/* ------------------------------------------------------------------ *
 * 第 11.4 项：熔断清理（泛型）                                          *
 * ------------------------------------------------------------------ */

/// 泛型熔断清理：停止预取 + 擦除缓冲 + 通知 worker 取消游标（第 11.4 项 + 第 2.1 项）
///
/// 第 2.1 项变更：熔断时向 worker 发 `ABORT_OP`（scan_abort / scan_summary_abort）
/// 回滚游标，而非 `CLOSE_OP`。语义为"取消并回滚"，便于 worker 端审计与事务回滚。
///
/// 流程：
///   1. 取出 ScanPipelineState（MutexGuard 在 await 前释放）
///   2. shutdown 预取任务（cancel + 短超时等待退出）
///   3. drop pending_reply（取消待处理的预取）
///   4. drop current_buffer（LockedBuffer Drop：先擦除后解锁）
///   5. 通知 worker 取消游标（best-effort，worker 可能已在熔断中）
///
/// # 参数
/// - `mutex`: 持有 ScanPipelineState 的 Mutex
/// - `state`: AppState（用于发送 worker 请求）
/// - `shutdown_timeout`: 预取任务退出等待超时（建议 2s）
pub async fn cleanup_pipeline_on_failure<T: ScanRecord>(
    mutex: &Mutex<Option<ScanPipelineState<T>>>,
    state: &AppState,
    shutdown_timeout: Duration,
) {
    // 1. 取出 ScanPipelineState（块作用域确保 MutexGuard 在 await 前释放）
    let scan_opt = {
        let mut guard = mutex.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };

    if let Some(mut scan) = scan_opt {
        // 2. shutdown 预取任务（cancel + 等待退出）
        if let Some(handle) = scan.prefetch_task.take() {
            handle.shutdown(shutdown_timeout).await;
        }

        // 3. drop pending_reply（取消待处理预取）
        // 显式 drop 表明意图：丢弃尚未收到的预取结果
        scan.pending_reply.take();

        // 4. drop current_buffer（LockedBuffer Drop：先 zeroize 后 VirtualUnlock）
        // 显式 take + drop 表明意图：立即擦除+解锁当前缓冲区
        scan.current_buffer.take();
    }

    // 5. 第 2.1 项：通知 worker 取消游标（发 ABORT_OP 而非 CLOSE_OP）
    //    best-effort：worker 可能已在熔断中，发送失败不影响本地资源回收
    let req = serde_json::json!({"op": <T as ScanRecord>::ABORT_OP});
    let _ = state.send_with_timeout(&req.to_string(), Duration::from_secs(5));
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::secured_string::SecuredString;

    fn make_record(id: u64) -> VerthysRecordEntry {
        VerthysRecordEntry {
            id,
            rtype: 0,
            name: SecuredString::from_str(&format!("name_{}", id)),
            data: SecuredString::from_str(&format!("ZGF0YV8x={}", id)),
            original_size: Some(6),
        }
    }

    fn make_summary(id: u64) -> VerthysSummaryEntry {
        VerthysSummaryEntry {
            id,
            rtype: 0,
            name: SecuredString::from_str(&format!("summary_{}", id)),
            data_size: 100,
            physical_offset: 2048,
            merkle_leaf: SecuredString::from_str("bWVya2xlX2xlYWY="),
            created_time: 1234567890,
        }
    }

    #[test]
    fn test_scan_pipeline_state_construction() {
        let records = vec![make_record(1), make_record(2)];
        let locked = LockedBuffer::new(records).unwrap();

        let state = ScanPipelineState::<VerthysRecordEntry> {
            shm_name: "test_shm".to_string(),
            current_buffer: Some(locked),
            exhausted: false,
            prefetch_task: None,
            pending_reply: None,
            session_state: ScanSessionState::Active,
        };

        assert_eq!(state.shm_name, "test_shm");
        assert!(!state.exhausted);
        assert!(state.current_buffer.is_some());
        assert_eq!(state.current_buffer.as_ref().unwrap().len(), 2);
        assert!(state.prefetch_task.is_none());
        assert!(state.pending_reply.is_none());
        assert_eq!(state.session_state, ScanSessionState::Active);
    }

    #[test]
    fn test_scan_pipeline_state_drop_erases_buffer() {
        // 验证 ScanPipelineState drop 时 LockedBuffer 也 drop（擦除+解锁）
        let records = vec![make_record(1)];
        let locked = LockedBuffer::new(records).unwrap();

        {
            let _state = ScanPipelineState::<VerthysRecordEntry> {
                shm_name: "test".to_string(),
                current_buffer: Some(locked),
                exhausted: false,
                prefetch_task: None,
                pending_reply: None,
                session_state: ScanSessionState::Active,
            };
            // _state drop 时 LockedBuffer drop → zeroize + VirtualUnlock
        }
        // 到达此处说明 drop 正常完成
    }

    #[test]
    fn test_scan_record_consts() {
        assert_eq!(VerthysRecordEntry::FETCH_OP, "scan_fetch");
        assert_eq!(VerthysRecordEntry::CLOSE_OP, "scan_close");
        assert_eq!(VerthysRecordEntry::ABORT_OP, "scan_abort");
        assert_eq!(VerthysSummaryEntry::FETCH_OP, "scan_summary_fetch");
        assert_eq!(VerthysSummaryEntry::CLOSE_OP, "scan_summary_close");
        assert_eq!(VerthysSummaryEntry::ABORT_OP, "scan_summary_abort");
    }

    #[test]
    fn test_scan_pipeline_state_summary() {
        let records = vec![make_summary(1), make_summary(2), make_summary(3)];
        let locked = LockedBuffer::new(records).unwrap();

        let state = ScanPipelineState::<VerthysSummaryEntry> {
            shm_name: "summary_shm".to_string(),
            current_buffer: Some(locked),
            exhausted: true,
            prefetch_task: None,
            pending_reply: None,
            session_state: ScanSessionState::Active,
        };

        assert!(state.exhausted);
        assert_eq!(state.current_buffer.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn test_scan_pipeline_state_no_buffer() {
        // 无缓冲区的状态（scan_close 后或异常状态）
        let state = ScanPipelineState::<VerthysRecordEntry> {
            shm_name: String::new(),
            current_buffer: None,
            exhausted: true,
            prefetch_task: None,
            pending_reply: None,
            session_state: ScanSessionState::Closed,
        };

        assert!(state.current_buffer.is_none());
        assert!(state.exhausted);
        assert_eq!(state.session_state, ScanSessionState::Closed);
    }

    #[test]
    fn test_scan_session_state_transitions() {
        // 第 2.4 项：ScanSessionState 状态机转移
        let active = ScanSessionState::Active;
        let failed = ScanSessionState::Failed;
        let closed = ScanSessionState::Closed;

        assert!(active.allow_next());
        assert!(!failed.allow_next());
        assert!(!closed.allow_next());
    }
}
