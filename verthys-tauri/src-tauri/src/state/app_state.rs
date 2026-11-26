use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use tokio::sync::Notify;
use zeroize::Zeroizing;

use crate::infrastructure::file_lock::VerthysFileLock;
use crate::util::contracts::{VerthysRecordEntry, VerthysSummaryEntry};
use crate::worker::WorkerSession;

use super::types::now_ms;
use super::{
    AppState, DataPlaneJob, IoGuard, KeyLifecycle, ScanPipelineState, TimedMutexGuard,
    VerthysSessionGuard, WorkerLifecycleHandle,
};

impl AppState {
    pub fn new() -> Self {
        AppState {
            session: RwLock::new(None),
            session_epoch: AtomicU64::new(0),
            init_lock: AtomicBool::new(false),
            key_op_lock: AtomicBool::new(false),
            scan_state: Mutex::new(None),
            scan_summary_state: Mutex::new(None),
            verthys_file_lock: Mutex::new(None),
            pending_io_count: AtomicU64::new(0),
            io_notify: Notify::new(),
            scan_lock_acquired_ms: AtomicU64::new(0),
            scan_summary_lock_acquired_ms: AtomicU64::new(0),
            worker_lifecycle: WorkerLifecycleHandle::new(),
            verthys_session: Mutex::new(None),
            key_lifecycle: KeyLifecycle::new(),
            import_session: Mutex::new(None),
            bulk_defer_on: AtomicBool::new(false),
            file_streams: Mutex::new(std::collections::HashMap::new()),
            writer: Mutex::new(None),
            data_plane_job: Mutex::new(None),
            photo_read_keys: Mutex::new(HashMap::new()),
        }
    }

    /* ----------------------------------------------------------------
     * 锁中毒恢复方法                                      *
     *                                                                *
     * 所有 Mutex/RwLock 的 lock/read/write 统一通过这些方法访问。      *
     * 中毒时：into_inner() 取出 → 废弃（重置 None）→ 告警 → 通知 worker*
     * ---------------------------------------------------------------- */

    /// 锁定 scan_state
    ///
    /// 中毒处理：into_inner() 取出废弃数据 → 重置为 None → 严重告警 →
    /// 通知 worker 关闭游标（best-effort）。
    ///
    /// 时间戳：构造时记录当前时间到 scan_lock_acquired_ms，
    /// TimedMutexGuard Drop 时清零。后台任务据此检测死锁。
    pub fn lock_scan_state(
        &self,
    ) -> TimedMutexGuard<'_, Option<ScanPipelineState<VerthysRecordEntry>>> {
        let guard = match self.scan_state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("[POISON][scan_state] Mutex 中毒，废弃旧状态并重置为 None");
                let mut g = poisoned.into_inner();
                // 废弃旧状态（LockedBuffer Drop 会擦除+解锁记录）
                *g = None;
                // 通知 worker 关闭游标（best-effort）
                let req = serde_json::json!({"op": "scan_close"});
                let _ = self.send(&req.to_string());
                g
            }
        };
        // 记录锁获取时间戳
        self.scan_lock_acquired_ms.store(now_ms(), Ordering::SeqCst);
        TimedMutexGuard {
            guard,
            timestamp: &self.scan_lock_acquired_ms,
        }
    }

    /// 锁定 scan_summary_state
    ///
    /// 与 lock_scan_state 对称，操作 scan_summary_state。
    pub fn lock_scan_summary_state(
        &self,
    ) -> TimedMutexGuard<'_, Option<ScanPipelineState<VerthysSummaryEntry>>> {
        let guard = match self.scan_summary_state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("[POISON][scan_summary_state] Mutex 中毒，废弃旧状态并重置为 None");
                let mut g = poisoned.into_inner();
                *g = None;
                let req = serde_json::json!({"op": "scan_summary_close"});
                let _ = self.send(&req.to_string());
                g
            }
        };
        self.scan_summary_lock_acquired_ms
            .store(now_ms(), Ordering::SeqCst);
        TimedMutexGuard {
            guard,
            timestamp: &self.scan_summary_lock_acquired_ms,
        }
    }

    /// 锁定 verthys_file_lock
    ///
    /// 中毒处理：into_inner() 取出废弃 → 重置为 None → 告警。
    /// 无时间戳监控（文件锁持有时间短，不涉及死锁风险）。
    pub fn lock_verthys_file(&self) -> std::sync::MutexGuard<'_, Option<VerthysFileLock>> {
        match self.verthys_file_lock.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("[POISON][verthys_file_lock] Mutex 中毒，废弃旧锁并重置为 None");
                let mut g = poisoned.into_inner();
                // 废弃旧文件锁（VerthysFileLock Drop 会释放 LockFileEx）
                *g = None;
                g
            }
        }
    }

    /// 读取 session（RwLock read 中毒恢复）
    ///
    /// 中毒时：RwLockReadGuard 不支持 DerefMut，无法在此重置数据。
    /// 仅记录告警并返回只读守卫。数据重置将在下次 write_session() 中毒处理时执行。
    fn read_session(&self) -> std::sync::RwLockReadGuard<'_, Option<WorkerSession>> {
        match self.session.read() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!(
                    "[POISON][session] RwLock read 中毒，返回只读守卫（数据可能不一致，待 write 时重置）"
                );
                // RwLockReadGuard 仅实现 Deref（非 DerefMut），无法在此重置数据。
                // 重置操作推迟到下次 write_session() 中毒分支执行。
                poisoned.into_inner()
            }
        }
    }

    /// 写入 session（RwLock write 中毒恢复）
    fn write_session(&self) -> std::sync::RwLockWriteGuard<'_, Option<WorkerSession>> {
        match self.session.write() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("[POISON][session] RwLock write 中毒，废弃旧会话并重置为 None");
                let mut g = poisoned.into_inner();
                *g = None;
                g
            }
        }
    }

    /* ----------------------------------------------------------------
     * 初始化锁                                                        *
     * ---------------------------------------------------------------- */

    /// 尝试获取初始化锁（非阻塞，成功返回 true）
    pub fn try_acquire_init_lock(&self) -> bool {
        self.init_lock
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// 释放初始化锁
    pub fn release_init_lock(&self) {
        self.init_lock.store(false, Ordering::SeqCst);
    }

    /* ----------------------------------------------------------------
     * 密钥操作互斥锁                                                  *
     * ---------------------------------------------------------------- */

    /// 尝试获取密钥操作锁（非阻塞，成功返回 true）
    pub fn try_acquire_key_op_lock(&self) -> bool {
        self.key_op_lock
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// 释放密钥操作锁
    pub fn release_key_op_lock(&self) {
        self.key_op_lock.store(false, Ordering::SeqCst);
    }

    /* ----------------------------------------------------------------
     * Worker IO 屏障（通知驱动，无轮询）                    *
     *                                                                *
     * begin_io / end_io 配对调用，包裹 verthys_flush 等 IO 操作。         *
     * wait_io_complete 在 verthys_lock 销毁 worker 前调用。               *
     * end_io 调 io_notify.notify_one()，                                *
     * wait_io_complete 调 io_notify.notified().await。                  *
     * ---------------------------------------------------------------- */

    /// 标记 IO 操作开始（verthys_flush 入口调用）
    pub fn begin_io(&self) {
        self.pending_io_count.fetch_add(1, Ordering::SeqCst);
    }

    /// 标记 IO 操作结束（verthys_flush 出口调用，无论成功失败）
    ///
    /// fetch_sub 后调 notify_one() 唤醒 wait_io_complete。
    pub fn end_io(&self) {
        self.pending_io_count.fetch_sub(1, Ordering::SeqCst);
        // 唤醒等待 IO 完成的调用方
        self.io_notify.notify_one();
    }

    /// 获取 RAII IO 计数守卫。
    ///
    /// 长耗时 worker 操作（记录 CRUD、批量删除、导入导出）必须在入口获取
    /// 守卫：早退与 `?` 路径由 Drop 统一 end_io，锁定流程的
    /// wait_io_complete 才能看到真实在途数量。
    pub fn io_guard(&self) -> IoGuard<'_> {
        self.begin_io();
        IoGuard { state: self }
    }

    /// 获取当前 pending IO 操作数
    pub fn get_pending_io_count(&self) -> u64 {
        self.pending_io_count.load(Ordering::SeqCst)
    }

    /// 等待所有 IO 操作完成（通知驱动，无轮询延迟）
    ///
    /// verthys_lock 销毁 worker 前调用，防止持久化中途销毁 worker。
    ///
    /// 以 io_notify.notified().await + timeout 等待，事件驱动。
    ///
    /// 返回 true 表示所有 IO 已完成，false 表示超时（仍有 IO 在执行）。
    pub async fn wait_io_complete(&self, timeout: Duration) -> bool {
        // 快速路径：无待处理 IO
        if self.get_pending_io_count() == 0 {
            return true;
        }
        log::warn!(
            "[wait_io_complete] 等待 {} 个 IO 操作完成（超时 {}ms）",
            self.get_pending_io_count(),
            timeout.as_millis()
        );

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // 检查计数
            if self.get_pending_io_count() == 0 {
                log::info!("[wait_io_complete] 所有 IO 操作已完成");
                return true;
            }

            // 检查截止时间
            let now = tokio::time::Instant::now();
            if now >= deadline {
                log::error!(
                    "[wait_io_complete] 超时，仍有 {} 个 IO 操作未完成，强制销毁 worker",
                    self.get_pending_io_count()
                );
                return false;
            }

            // 等待通知或超时
            let remaining = deadline - now;
            let _ = tokio::time::timeout(remaining, self.io_notify.notified()).await;
            // 收到通知或超时后循环回检查计数
        }
    }

    /* ----------------------------------------------------------------
     * Worker 通信方法                                                 *
     *                                                                *
     * 所有 read()/write() 统一通过 read_session()/write_session() 访问 *
     * ---------------------------------------------------------------- */

    /// 发送 JSON 请求到 worker，返回响应 JSON（默认 15s 超时）
    pub fn send(&self, json: &str) -> Result<String, String> {
        let session = {
            let guard = self.read_session();
            guard.as_ref().ok_or("worker not initialized")?.clone()
        };
        session.send_json(json)
    }

    /// 为路径型 worker 操作签发一次性授权。
    ///
    /// 授权与操作、模式、规范化路径绑定，worker 在操作入口消费。
    pub fn authorize_worker_path(
        &self,
        target_op: &str,
        mode: &str,
        path: &str,
    ) -> Result<(), String> {
        let session = {
            let guard = self.read_session();
            guard.as_ref().ok_or("worker not initialized")?.clone()
        };
        session.authorize_path(target_op, mode, path)
    }

    /// 发送 JSON 请求到 worker，自定义超时
    pub fn send_with_timeout(&self, json: &str, timeout: Duration) -> Result<String, String> {
        let session = {
            let guard = self.read_session();
            guard.as_ref().ok_or("worker not initialized")?.clone()
        };
        session.send_json_with_timeout(json, timeout)
    }

    /// 发送全库轮换请求并流式接收进度（v4_rotate_run 专用）
    pub fn send_with_rotate_progress(
        &self,
        json: &str,
        progress_cb: &dyn Fn(&crate::worker::RotateProgress),
    ) -> Result<String, String> {
        let session = {
            let guard = self.read_session();
            guard.as_ref().ok_or("worker not initialized")?.clone()
        };
        session.send_json_with_rotate_progress(json, progress_cb)
    }

    /// 发送空间压缩请求并流式接收进度。
    pub fn send_with_storage_progress(
        &self,
        json: &str,
        progress_cb: &dyn Fn(&crate::worker::StorageCompactProgress),
    ) -> Result<String, String> {
        let session = {
            let guard = self.read_session();
            guard.as_ref().ok_or("worker not initialized")?.clone()
        };
        session.send_json_with_storage_progress(json, progress_cb)
    }

    /// 设置 worker 会话（写操作，使用 write_session 独占锁）
    ///
    /// 传 None 销毁现有会话（Drop 自动 kill 子进程）。
    /// 传 Some(session) 替换现有会话（旧会话 Drop 自动 kill）。
    pub fn set_session(&self, session: Option<WorkerSession>) {
        let mut guard = self.write_session();
        if let Some(existing) = guard.as_ref() {
            existing.request_stop();
        }
        *guard = session;
        // 代际在写锁内递增：代际值与会话内容始终一致，等待方不会读到
        // “新会话 + 旧代际”的撕裂组合。
        self.session_epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// 读取当前会话代际（用于延迟命令等待结束后的过期校验）
    pub fn session_epoch(&self) -> u64 {
        self.session_epoch.load(Ordering::SeqCst)
    }

    /// 仅当代际仍为 `expected` 时销毁当前会话（检查与销毁原子化）
    ///
    /// 返回 `false` 表示等待期间会话已被替换（或已由其它路径销毁后又建立），
    /// 调用方必须放弃后续破坏性动作。检查与清空都在写锁内完成，避免
    /// “校验通过 → 新会话建立 → 仍然清空”的 TOCTOU。
    pub fn clear_session_if_epoch(&self, expected: u64) -> bool {
        let mut guard = self.write_session();
        if self.session_epoch.load(Ordering::SeqCst) != expected {
            return false;
        }
        if guard.is_some() {
            *guard = None;
            self.session_epoch.fetch_add(1, Ordering::SeqCst);
        }
        true
    }

    /// 检查 worker 是否已初始化（读操作，使用 read_session 共享锁）
    pub fn has_session(&self) -> bool {
        let guard = self.read_session();
        guard.is_some()
    }

    /// 检查 worker 子进程是否存活
    ///
    /// 健康检查器每 10s 调用，Ready 状态下检查子进程存活。
    /// session 不存在或 is_alive() 返回 false 均视为不存活。
    pub fn is_worker_alive(&self) -> bool {
        let guard = self.read_session();
        guard.as_ref().map(|s| s.is_alive()).unwrap_or(false)
    }

    /* ----------------------------------------------------------------
     * VerthysSessionGuard 访问方法                           *
     * ---------------------------------------------------------------- */

    /// 锁定 verthys_session（RAII 会话守卫访问）
    ///
    /// 中毒处理：into_inner() 取出废弃 → 重置为 None → 告警。
    pub fn lock_verthys_session(&self) -> std::sync::MutexGuard<'_, Option<VerthysSessionGuard>> {
        match self.verthys_session.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("[POISON][verthys_session] Mutex 中毒，废弃旧会话守卫并重置为 None");
                let mut g = poisoned.into_inner();
                // 废弃旧会话守卫（VerthysSessionGuard Drop 会释放文件锁）
                *g = None;
                g
            }
        }
    }

    /// 检查 verthys 会话是否活跃
    pub fn has_verthys_session(&self) -> bool {
        let guard = self.lock_verthys_session();
        guard.is_some()
    }

    /// 获取当前会话绑定的 verthys 路径
    ///
    /// 返回 None 表示未解锁或会话已关闭。
    pub fn verthys_session_path(&self) -> Option<String> {
        let guard = self.lock_verthys_session();
        guard.as_ref().map(|s| s.verthys_path().to_string())
    }

    /* ----------------------------------------------------------------
     * 照片导入会话（WAL）访问方法       *
     *                                                                *
     * verthys_import_begin 创建 ImportSession 存入 import_session，    *
     * verthys_add_records_batch 期间追加 WAL + 串行 worker 插入，      *
     * verthys_import_end 关闭。单 verthys 同一时刻仅一个活跃会话。       *
     * 中毒处理：into_inner() 取出废弃 → 重置为 None → 告警。         *
     * ---------------------------------------------------------------- */

    /// 锁定 import_session（WAL 导入会话访问）
    ///
    /// 中毒处理：into_inner() 取出废弃会话（WalWriter Drop 关闭文件句柄，
    /// 已 committed 的哈希在磁盘 WAL 中持久化，下次 begin 可恢复）→
    /// 重置为 None → 严重告警。
    ///
    /// 返回的 MutexGuard 可直接 Option::take() / as_mut() / as_ref() 操作。
    pub fn lock_import_session(
        &self,
    ) -> std::sync::MutexGuard<'_, Option<crate::repository::verthys_wal::ImportSession>> {
        match self.import_session.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("[POISON][import_session] Mutex 中毒，废弃旧导入会话并重置为 None");
                let mut g = poisoned.into_inner();
                // 废弃旧会话（WalWriter Drop 关闭文件句柄；committed_keys 已落盘可恢复）
                *g = None;
                g
            }
        }
    }

    /// 检查是否存在活跃的导入会话（防重入：单 verthys 同一时刻仅一个活跃会话）
    pub fn has_import_session(&self) -> bool {
        let guard = self.lock_import_session();
        guard.is_some()
    }

    /// 记录底层 DLL 是否已确认进入锚点推迟会话（仅导入生命周期使用）。
    pub fn set_bulk_defer(&self, on: bool) {
        self.bulk_defer_on.store(on, Ordering::SeqCst);
    }

    /// 查询锚点推迟会话是否生效。
    pub fn bulk_defer_active(&self) -> bool {
        self.bulk_defer_on.load(Ordering::SeqCst)
    }

    /* ----------------------------------------------------------------
     * 流式文件写入会话表访问方法                         *
     *                                                                *
     * write_user_file_stream 创建会话，append 查指针，finalize/abort  *
     * 一次性消费（从表移除取得独占所有权）。表锁仅覆盖指针增删查，    *
     * 磁盘 IO 均在各会话自身锁与外层 spawn_blocking 中执行。          *
     * ---------------------------------------------------------------- */

    /// 锁定文件流会话表
    ///
    /// 中毒处理：取出的旧表逐会话尽力清理暂存残留（句柄已不可能再被
    /// finalize 消费，残留为纯磁盘垃圾）→ 重置为空表 → 告警。
    pub fn lock_file_streams(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        std::collections::HashMap<
            String,
            std::sync::Arc<std::sync::Mutex<super::file_streams::FileStreamState>>,
        >,
    > {
        match self.file_streams.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("[POISON][file_streams] Mutex 中毒，清理各会话暂存残留并重置为空表");
                let mut guard = poisoned.into_inner();
                let stale = std::mem::take(&mut *guard);
                for (_, entry) in stale {
                    super::file_streams::cleanup_stream_residue(entry);
                }
                guard
            }
        }
    }

    /* ----------------------------------------------------------------
     * 导入写者句柄访问方法（单写者通道）                  *
     *                                                                *
     * 写者由 import_writer::ensure 惰性创建并注册；看门狗通过          *
     * writer_is_stale 判定心跳超时并触发重建。                        *
     * ---------------------------------------------------------------- */

    /// 锁定导入写者句柄
    ///
    /// 中毒处理：置死旧写者（阻断其继续执行变更命令）→ 重置为
    /// None → 告警。下次 import_writer::ensure 将原地重建。
    pub fn lock_writer(
        &self,
    ) -> std::sync::MutexGuard<'_, Option<super::import_writer::ImportWriterHandle>> {
        match self.writer.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("[POISON][writer] Mutex 中毒，置死旧写者并重置");
                let mut guard = poisoned.into_inner();
                if let Some(handle) = guard.as_ref() {
                    handle.kill();
                }
                *guard = None;
                guard
            }
        }
    }

    /// 写者心跳是否超时（看门狗判定用）
    ///
    /// 无写者（尚未首次取用）视为健康——按需创建即可，不触发重建。
    pub fn writer_is_stale(&self) -> bool {
        let guard = self.lock_writer();
        match guard.as_ref() {
            Some(handle) => !handle.is_alive(),
            None => false,
        }
    }

    /* ----------------------------------------------------------------
     * 照片重型任务槽位访问方法（导入/导出/还原单 job 串行）          *
     *                                                                *
     * 槽位用于拒绝并发任务与投递取消标志；worker 侧 job 状态不在宿主 *
     * 镜像。中毒处理：重置为 None 后告警。                            *
     * ---------------------------------------------------------------- */

    /// 锁定照片任务槽位
    ///
    /// 中毒处理：into_inner() 取出废弃 → 重置为 None → 告警。
    fn lock_data_plane_job(&self) -> std::sync::MutexGuard<'_, Option<DataPlaneJob>> {
        match self.data_plane_job.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("[POISON][data_plane_job] Mutex 中毒，废弃旧任务槽位并重置为 None");
                let mut g = poisoned.into_inner();
                *g = None;
                g
            }
        }
    }

    /// 尝试占用照片任务槽位。
    ///
    /// 已有任务时拒绝（并发任务会争夺同一数据面/导入会话）；成功返回取消
    /// 标志，调用方在收尾时必须调用 `finish_data_plane_job` 释放槽位。
    pub fn try_begin_data_plane_job(
        &self,
        job_id: &str,
    ) -> Result<std::sync::Arc<AtomicBool>, String> {
        if job_id.trim().is_empty() {
            return Err("job_id 不能为空".to_string());
        }
        let mut guard = self.lock_data_plane_job();
        if guard.is_some() {
            return Err("已有数据面任务进行中".to_string());
        }
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        *guard = Some(DataPlaneJob {
            job_id: job_id.to_string(),
            cancel: cancel.clone(),
        });
        Ok(cancel)
    }

    /// 取指定任务的取消标志（job_id 不匹配返回 None）
    ///
    /// 仅匹配当前槽位，避免旧任务的延迟取消请求命中新任务。
    pub fn data_plane_job_cancel_flag(&self, job_id: &str) -> Option<std::sync::Arc<AtomicBool>> {
        let guard = self.lock_data_plane_job();
        guard
            .as_ref()
            .filter(|job| job.job_id == job_id)
            .map(|job| job.cancel.clone())
    }

    /// 释放数据面槽位（仅当 job_id 匹配）
    ///
    /// 按 job_id 比对，防止旧任务的收尾路径清掉后来者新建的任务。
    pub fn finish_data_plane_job(&self, job_id: &str) {
        let mut guard = self.lock_data_plane_job();
        if guard
            .as_ref()
            .map(|job| job.job_id == job_id)
            .unwrap_or(false)
        {
            *guard = None;
        }
    }

    /// 当前数据面任务 ID（无任务返回 None）
    pub fn data_plane_job_id(&self) -> Option<String> {
        self.lock_data_plane_job()
            .as_ref()
            .map(|job| job.job_id.clone())
    }

    /* ----------------------------------------------------------------
     * 原图读取 SHM 密钥表                                           *
     *                                                                *
     * 密钥只在宿主与 worker 之间流转：begin 时登记、逐块读取时取用、   *
     * end/cancel 时移除；Zeroizing 保证离开容器即清零。               *
     * ---------------------------------------------------------------- */

    fn lock_photo_read_keys(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, Zeroizing<Vec<u8>>>> {
        match self.photo_read_keys.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::error!("[POISON][photo_read_keys] Mutex 中毒，废弃全部读取密钥");
                let mut g = poisoned.into_inner();
                g.clear(); /* Drop 逐项清零 */
                g
            }
        }
    }

    /// 登记原图读取密钥（同一 job_id 重复登记时旧密钥随覆盖清零）
    pub fn set_photo_read_key(&self, job_id: &str, key: Zeroizing<Vec<u8>>) {
        if job_id.is_empty() {
            return;
        }
        let mut guard = self.lock_photo_read_keys();
        guard.insert(job_id.to_string(), key);
    }

    /// 取指定读取任务的密钥副本（不存在返回 None）
    pub fn photo_read_key(&self, job_id: &str) -> Option<Zeroizing<Vec<u8>>> {
        self.lock_photo_read_keys().get(job_id).cloned()
    }

    /// 移除读取密钥（job 结束/取消/失败时调用，密钥随之清零）
    pub fn remove_photo_read_key(&self, job_id: &str) {
        self.lock_photo_read_keys().remove(job_id);
    }
}
