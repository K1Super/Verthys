//! Windows 心跳事件与挂起看门狗：worker 每 500ms SetEvent，
//! 心跳连续缺失且全部线程挂起时触发外部处置。

use std::sync::Arc;

#[cfg(target_os = "windows")]
use std::sync::atomic::Ordering;
#[cfg(target_os = "windows")]
use std::time::Duration;

use super::WorkerSession;

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE,
};

/// 父进程心跳事件句柄包装（HANDLE 不满足 Send/Sync，经 Arc 共享给看门狗线程）
#[cfg(target_os = "windows")]
pub(super) struct HeartbeatEvent(HANDLE);
#[cfg(target_os = "windows")]
unsafe impl Send for HeartbeatEvent {}
#[cfg(target_os = "windows")]
unsafe impl Sync for HeartbeatEvent {}
#[cfg(target_os = "windows")]
impl Drop for HeartbeatEvent {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// 创建匿名心跳事件并 DuplicateHandle 注入 worker 进程。
///
/// 返回 (父进程事件句柄, worker 进程内句柄值)。句柄值仅在 worker 内有效，
/// 父进程不得 CloseHandle 它；worker 退出时由其句柄表统一回收。
/// `worker_process` 必须是 REGISTER 之前取得的句柄：驱动确认后会剥离
/// 宿主新句柄的 `PROCESS_DUP_HANDLE`，已取得的句柄不受追溯影响。
#[cfg(target_os = "windows")]
pub(super) fn create_heartbeat_event(
    worker_process: HANDLE,
) -> Option<(HeartbeatEvent, u64)> {
    use windows::Win32::System::Threading::GetCurrentProcess;

    let event = crate::infrastructure::handle_factory::create_non_inheritable_event(false, false)
        .ok()?;
    let mut worker_handle = HANDLE::default();
    let dup = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            event,
            worker_process,
            &mut worker_handle,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if dup.is_err() {
        let _ = unsafe { CloseHandle(event) };
        return None;
    }
    Some((HeartbeatEvent(event), worker_handle.0 as u64))
}

/// 判断 worker 进程的全部线程是否都处于挂起态。
///
/// 使用 SuspendThread 的返回值读取"挂起前计数"：prev=0 说明线程此前可运行，
/// 立即 ResumeThread 恢复并以"存在运行线程"返回；prev>0 说明线程已挂起，
/// 同样 ResumeThread 一次恢复到原计数。短暂挂起仅在心跳已缺失 3s 后发生，
/// 对健康进程无影响。任一 OpenThread/枚举失败按"无法确认"返回 false（保守放行）。
#[cfg(target_os = "windows")]
fn worker_all_threads_suspended(pid: u32) -> bool {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
        TH32CS_SNAPTHREAD,
    };
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME,
    };

    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) } {
        Ok(h) => h,
        Err(_) => return false,
    };
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    if unsafe { Thread32First(snapshot, &mut entry) }.is_err() {
        let _ = unsafe { CloseHandle(snapshot) };
        return false;
    }

    let mut found = false;
    let mut any_running = false;
    loop {
        if entry.th32OwnerProcessID == pid {
            found = true;
            match unsafe {
                OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
            } {
                Ok(thread) => {
                    let previous = unsafe { SuspendThread(thread) };
                    if previous == u32::MAX {
                        // 查询失败：无法确认，按可运行处理（不终止）
                        any_running = true;
                    } else {
                        if previous == 0 {
                            any_running = true;
                        }
                        // 恢复到调用前计数（prev>0 时恢复后仍保持原挂起计数）
                        let _ = unsafe { ResumeThread(thread) };
                    }
                    let _ = unsafe { CloseHandle(thread) };
                }
                Err(_) => {
                    any_running = true;
                }
            }
        }
        if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
            break;
        }
    }
    let _ = unsafe { CloseHandle(snapshot) };
    found && !any_running
}

impl WorkerSession {
    /// 启用 worker 心跳（在就绪握手通过后调用）。
    ///
    /// 句柄值经签名 IPC 下发；worker 独立线程每 500ms SetEvent。
    pub fn arm_heartbeat(&self) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            let handle = self.inner.heartbeat_worker_handle;
            if handle == 0 {
                return Err("心跳事件不可用（创建或注入失败）".into());
            }
            let request = format!(
                r#"{{"op":"arm_heartbeat","hb_handle":{}}}"#,
                handle
            );
            let response = self.send_json_with_timeout(&request, Duration::from_secs(3))?;
            let value: serde_json::Value = serde_json::from_str(&response)
                .map_err(|e| format!("arm_heartbeat 响应解析失败: {}", e))?;
            if value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                return Ok(());
            }
            Err(value
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("worker 拒绝启用心跳")
                .to_string())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err("非 Windows 平台不支持心跳看门狗".into())
        }
    }

    /// 启动挂起看门狗（在心跳启用后调用）。
    ///
    /// 每 1s 等待心跳；连续 3 次缺失（3s）后枚举 worker 线程，仅当全部
    /// 线程处于挂起态才调用 handler（避免把极端卡顿误判为挂起）。
    /// 线程异常/无法查询时保守放行，不终止。
    pub fn start_suspend_watchdog(
        &self,
        handler: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            let event = self
                .inner
                .heartbeat_event
                .clone()
                .ok_or_else(|| "心跳事件不可用".to_string())?;
            let stop = self.inner.suspend_stop.clone();
            let pid = self.inner.pid;
            let mut slot = self
                .inner
                .suspend_thread
                .lock()
                .map_err(|e| format!("挂起看门狗锁中毒: {}", e))?;
            if slot.is_some() {
                return Ok(());
            }
            let thread = std::thread::Builder::new()
                .name("verthys-suspend-watchdog".into())
                .spawn(move || {
                    use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
                    use windows::Win32::System::Threading::WaitForSingleObject;
                    let mut misses = 0u32;
                    while !stop.load(Ordering::SeqCst) {
                        let rc = unsafe { WaitForSingleObject(event.0, 1000) };
                        if rc == WAIT_TIMEOUT {
                            misses += 1;
                            if misses >= 3 {
                                if stop.load(Ordering::SeqCst) {
                                    break;
                                }
                                if worker_all_threads_suspended(pid) {
                                    log::error!(
                                        "[watchdog] worker PID={} 全部线程挂起且心跳缺失 3s，触发外部锁定",
                                        pid
                                    );
                                    handler();
                                    break;
                                }
                                misses = 0;
                            }
                        } else if rc == WAIT_OBJECT_0 {
                            misses = 0;
                        } else {
                            log::warn!("[watchdog] 心跳等待返回异常状态，看门狗退出");
                            break;
                        }
                    }
                })
                .map_err(|e| format!("启动挂起看门狗线程失败: {}", e))?;
            *slot = Some(thread);
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = handler;
            Err("非 Windows 平台不支持挂起看门狗".into())
        }
    }
}
