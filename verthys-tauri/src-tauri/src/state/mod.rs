/*
 * state/mod.rs — 进程私有状态管理
 *
 * 包含：
 *   - AppState: 主进程会话状态（worker IPC session + scan_state + init_lock）
 *   - ScanPipelineState<T>: 泛型双缓冲游标扫描状态
 *   - LockedBuffer<T>: VirtualLock RAII 守卫
 *   - PrefetchTaskHandle<T>: 长期预取任务控制
 *   - InitLockGuard: 初始化锁 RAII 守卫
 *   - cleanup_scan_on_failure / cleanup_summary_scan_on_failure: 熔断清理
 *   - spawn_lock_monitor: 锁持有时间监控
 *
 * 锁中毒处理：
 *   Mutex/RwLock 中毒时 into_inner() 取出后废弃（重置为 None/Default），
 *   记录严重告警，通知 worker 关闭游标。统一通过 lock_scan_state/
 *   lock_scan_summary_state/lock_verthys_file/read_session/write_session 访问。
 *
 * IO 屏障：
 *   tokio::sync::Notify 驱动：end_io 调 notify_one，
 *   wait_io_complete 调 notified().await 并带超时。
 *
 * 锁持有时间监控：
 *   AtomicU64 记录 scan_state/scan_summary_state 锁获取时间戳。
 *   后台任务每 5s 检查，持有超 30s 告警 + try_lock 强制重置。
 *
 * 分层依赖方向：state → worker / infrastructure / repository / util
 */

pub mod file_streams;
pub mod import_writer;
pub mod key_lifecycle;
pub mod locked_buffer;
pub mod scan_pipeline;
pub mod verthys_session;
pub mod worker_lifecycle;

mod app_state;
mod cleanup;
mod guards;
#[cfg(test)]
mod tests;
mod types;

// 重导出常用类型，供控制器直接 use crate::state::{...}
// VirtualLockable / PrefetchCommand 未通过 mod.rs 重导出（无外部消费者），
// 需要时可直接从 locked_buffer / scan_pipeline 模块导入。
#[allow(unused_imports)]
pub use cleanup::{cleanup_scan_on_failure, cleanup_summary_scan_on_failure};
#[allow(unused_imports)]
pub use guards::{InitLockGuard, KeyOpGuard};
#[allow(unused_imports)]
pub use key_lifecycle::{KeyLifecycle, KeyLifecycleState, VerifyAttemptResult, VerifyCheckResult};
#[allow(unused_imports)]
pub use locked_buffer::LockedBuffer;
#[allow(unused_imports)]
pub use scan_pipeline::{
    cleanup_pipeline_on_failure, PrefetchTaskHandle, ScanPipelineState, ScanRecord,
    ScanSessionState,
};
#[allow(unused_imports)]
pub use types::{DataPlaneJob, IoGuard, TimedMutexGuard, SESSION_SUPERSEDED};
#[allow(unused_imports)]
pub use verthys_session::VerthysSessionGuard;
#[allow(unused_imports)]
pub use worker_lifecycle::{
    spawn_health_checker, SetupCache, WorkerLifecycle, WorkerLifecycleHandle, WorkerLifecycleState,
};

use crate::infrastructure::file_lock::VerthysFileLock;
use crate::util::contracts::{VerthysRecordEntry, VerthysSummaryEntry};
// 注意：VerthysSessionGuard 已通过上方 pub use 重导出，
// 此处不再重复 use，避免 E0252 重复定义错误。
use crate::worker::WorkerSession;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Mutex, RwLock};
use tokio::sync::Notify;
use zeroize::Zeroizing;

pub struct AppState {
    /// Worker 会话（RwLock 允许多读并发 send，写独占 set_session）
    ///
    /// 通过 read_session()/write_session() 访问，中毒时重置为 None。
    session: RwLock<Option<WorkerSession>>,
    /// 会话代际（单调递增）
    ///
    /// 每次会话变更（建立/替换/销毁）在写锁内递增。锁定与销毁命令在等待
    /// 轮换收敛前记录代际，等待结束后据此校验：代际已变说明目标会话已被
    /// 替换（例如用户重新解锁），必须放弃销毁，绝不能命中新会话。
    session_epoch: AtomicU64,
    /// 并发锁防重：初始化流程进行中拒绝并发请求
    pub init_lock: AtomicBool,
    /// 密钥操作互斥：GMK 验证/派生/改钥串行化
    ///
    /// 前端编排已收口为单命令，但 IPC 仍可能被并发调用；改钥包含两次
    /// PBKDF2 与多步记录写入，必须与验证/首次派生互斥，避免 GMK 槽
    /// 被后写覆盖或记录出现两条权威记录。
    pub key_op_lock: AtomicBool,
    /// 全量扫描状态（泛型 ScanPipelineState<VerthysRecordEntry>）
    ///
    /// 通过 lock_scan_state() 访问，中毒时重置为 None + 通知 worker。
    /// lock_scan_state() 记录时间戳到 scan_lock_acquired_ms。
    scan_state: Mutex<Option<ScanPipelineState<VerthysRecordEntry>>>,
    /// 摘要扫描状态（与 scan_state 对称）
    scan_summary_state: Mutex<Option<ScanPipelineState<VerthysSummaryEntry>>>,
    /// .verthys 文件跨进程独占锁
    ///
    /// 通过 lock_verthys_file() 访问，中毒时重置为 None。
    verthys_file_lock: Mutex<Option<VerthysFileLock>>,
    /// Worker IO 操作计数器（verthys_flush 屏障）
    pending_io_count: AtomicU64,
    /// IO 完成通知（通知驱动，无轮询延迟）
    ///
    /// end_io 调 notify_one，wait_io_complete 调 notified().await。
    io_notify: Notify,
    /// scan_state 锁获取时间戳（Unix 毫秒，0 = 未持有）
    scan_lock_acquired_ms: AtomicU64,
    /// scan_summary_state 锁获取时间戳
    scan_summary_lock_acquired_ms: AtomicU64,
    /// Worker 生命周期状态机（tokio::sync::Mutex + watch channel）
    ///
    /// worker_controller 的 init/destroy 通过此句柄检查状态转移，
    /// 消除并发竞态。健康检查器每 10s 检查 Ready 状态的子进程存活。
    pub worker_lifecycle: WorkerLifecycleHandle,
    /// Verthys 会话 RAII 守卫
    ///
    /// verthys_unlock 成功后创建（Some），verthys_lock 时销毁（None）。
    /// Drop 自动释放文件锁，确保异常路径不遗漏。
    verthys_session: Mutex<Option<VerthysSessionGuard>>,
    /// 密钥生命周期状态机 + 指数冷却失败计数器
    ///
    /// 维护 GMK 状态（NoKey/Locked/Unlocked）与 verify_global_key 失败计数。
    /// derive_global_key 仅 NoKey，verify_global_key 仅 Locked，clear_global_key Unlocked→Locked。
    /// verify 连续失败 5 次触发指数冷却（2s/4s/8s/16s/32s 上限 60s）。
    /// 将与 BruteForceGate 联动（DPAPI 持久化 + 界面锁定 + 索引清空）。
    pub key_lifecycle: KeyLifecycle,
    /// 照片导入会话状态（WAL + 去重哈希集 + 批次计数器）
    ///
    /// verthys_import_begin 创建，verthys_add_records_batch 期间追加 WAL + 串行 worker 插入，
    /// verthys_import_end 关闭。单 verthys 同一时刻仅一个活跃会话（Mutex 串行化保证）。
    /// 中毒处理：into_inner() 取出废弃 → 重置为 None → 告警。
    import_session: Mutex<Option<crate::repository::verthys_wal::ImportSession>>,
    /// 批量导入锚点推迟会话是否已由底层 DLL 确认生效（G0-A2 原型）。
    ///
    /// 旧 DLL 缺 Verthys_BulkImportBegin/Commit 时保持 false，导入按现状
    /// 逐次提交锚点；只有 Begin 明确成功才置位，Commit 后清零。
    bulk_defer_on: AtomicBool,
    /// 流式文件写入会话表（导出流式落盘）
    ///
    /// 通过 lock_file_streams() 访问；finalize/abort 一次性消费会话。
    /// 中毒处理：清理各会话暂存残留 → 重置为空表 → 告警。
    file_streams: file_streams::FileStreamTable,
    /// 导入写者句柄（单写者通道）
    ///
    /// 通过 lock_writer() 访问；缺失或心跳超时由 import_writer::ensure
    /// 原地重建。中毒处理：置死旧写者（防其继续变更存储）→ 重置为
    /// None → 告警。
    writer: Mutex<Option<import_writer::ImportWriterHandle>>,
    /// 数据面独占任务槽位（单 job 串行）
    ///
    /// 通过 try_begin_data_plane_job / data_plane_job_cancel_flag /
    /// finish_data_plane_job 访问；中毒处理：重置为 None → 告警。
    data_plane_job: Mutex<Option<DataPlaneJob>>,
    /// 照片原图读取的 SHM 认证密钥（job_id → 32 字节，随 job 结束清零移除）
    ///
    /// 密钥经主进程生成并随 begin 请求下发 worker，仅用于校验原图块的
    /// 共享内存载荷；不落盘、不进日志、不返回前端。
    photo_read_keys: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}
