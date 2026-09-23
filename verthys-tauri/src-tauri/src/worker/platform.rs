//! worker/platform.rs — 平台特定代码（Windows Job Object 与孤儿进程清理）
//!
//! 修复：Windows Job Object — 绑定子进程生命周期到父进程
//!
//! 根因：应用退出（含异常退出/强杀）后 worker 子进程仍存活，累积为孤儿进程。
//!   孤儿 worker 持有 verthys 文件锁/共享内存/状态文件锁 → 状态文件损坏 → 后续启动异常。
//!
//! 修复：创建 Job Object 并设置 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 标志，
//!   将 worker 子进程分配到 Job Object。父进程退出时内核自动关闭 Job Object 句柄，
//!   触发 KILL_ON_JOB_CLOSE → 内核级强杀所有 Job 内进程。
//!   这是 Windows 上"父进程死亡则子进程必死"的标准做法，覆盖所有退出路径
//!   （正常退出、异常退出、TerminateProcess、任务管理器强杀）。
//!
//! 本模块对外提供：
//!   - JobHandle：Job Object 句柄的 newtype（实现 Send + Sync），仅 Windows
//!   - assign_child_to_job_object：将子进程分配到 Job Object，仅 Windows
//!   - kill_orphan_workers：清理孤儿 verthys-worker 进程（跨平台，非 Windows 为 no-op）

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(target_os = "windows")]
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

/// Job Object 句柄的 newtype wrapper（实现 Send + Sync）
///
/// Windows `HANDLE` 是 `*mut c_void`，不满足 `Send`/`Sync`。
/// `SessionInner` 包含 `StdMutex<Option<JobHandle>>` 并被 `Arc` 共享，
/// 必须满足 `Send + Sync`。此 wrapper 通过 `unsafe impl Send/Sync` 解决。
///
/// 安全性：Job Object 句柄通过 `CloseHandle` 显式关闭（Drop 中），
/// 不跨线程并发访问（`StdMutex` 保护），`Send + Sync` 是安全的。
#[cfg(target_os = "windows")]
pub(crate) struct JobHandle(pub(crate) HANDLE);

#[cfg(target_os = "windows")]
unsafe impl Send for JobHandle {}
#[cfg(target_os = "windows")]
unsafe impl Sync for JobHandle {}

/// 创建 Job Object（KILL_ON_JOB_CLOSE）并将子进程分配到其中。
///
/// 返回 `Some(JobHandle)` 表示成功（调用方需在 Drop 时 CloseHandle），
/// `None` 表示失败（回退到 kill_on_drop 兜底）。
#[cfg(target_os = "windows")]
pub(crate) fn assign_child_to_job_object(pid: u32) -> Option<JobHandle> {
    use windows::core::PCWSTR;

    // 1. 创建 Job Object
    //    windows 0.58: CreateJobObjectW 返回 Result<HANDLE, Error>
    let job = match unsafe { CreateJobObjectW(None, PCWSTR::null()) } {
        Ok(h) => h,
        Err(e) => {
            log::warn!("[watchdog] Job Object 创建失败（pid={}）：{}，回退到 kill_on_drop", pid, e);
            return None;
        }
    };

    // 2. 设置 KILL_ON_JOB_CLOSE：父进程退出时内核自动终止 Job 内所有进程
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let info_ptr = &mut info as *mut _ as *const _;
    let info_len = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
    let rc = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            info_ptr,
            info_len,
        )
    };
    if rc.is_err() {
        log::warn!("[watchdog] SetInformationJobObject 失败（pid={}）：{:?}，回退到 kill_on_drop", pid, rc);
        unsafe { let _ = CloseHandle(job); }
        return None;
    }

    // 3. 打开子进程句柄（PROCESS_SET_QUOTA 用于 AssignProcess，PROCESS_TERMINATE 兜底）
    let proc_handle = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, pid) };
    let ph = match proc_handle {
        Ok(h) => h,
        Err(e) => {
            log::warn!("[watchdog] OpenProcess 失败（pid={}）：{}，回退到 kill_on_drop", pid, e);
            unsafe { let _ = CloseHandle(job); }
            return None;
        }
    };

    // 4. 分配子进程到 Job Object
    //    Windows 7+ 支持 nested job assignment（进程可同时属于多个 Job Object），
    //    即使 worker 自身有 NoChildProcessCreation 策略，Job Object 仍生效。
    let assign_rc = unsafe { AssignProcessToJobObject(job, ph) };
    // 关闭进程句柄（Job Object 已保留引用）
    unsafe { let _ = CloseHandle(ph); }

    if assign_rc.is_err() {
        log::warn!("[watchdog] AssignProcessToJobObject 失败（pid={}）：{:?}，回退到 kill_on_drop", pid, assign_rc);
        unsafe { let _ = CloseHandle(job); }
        return None;
    }

    log::info!("[watchdog] worker PID={} 已绑定 Job Object（KILL_ON_JOB_CLOSE：父进程退出时内核自动终止子进程）", pid);
    Some(JobHandle(job))
}

/// 根治：杀死所有残留的孤儿 verthys-worker 进程。
///
/// 在 worker_init 启动新 worker 之前调用，清理上次异常退出遗留的孤儿进程。
/// 使用 Toolhelp32 枚举进程，按名称匹配 "verthys-worker.exe" 并 TerminateProcess。
/// 跳过当前进程的子进程（通过 PID 比较，新 worker 尚未启动故全部杀死）。
#[cfg(target_os = "windows")]
pub fn kill_orphan_workers() {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{TerminateProcess, OpenProcess as OpenProc2, PROCESS_TERMINATE as PT2};

    // windows 0.58: CreateToolhelp32Snapshot 返回 Result<HANDLE, Error>
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) => h,
        Err(_) => {
            log::warn!("[orphan_cleanup] CreateToolhelp32Snapshot 失败，跳过孤儿清理");
            return;
        }
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut killed = 0u32;

    let ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    if ok.is_err() {
        log::warn!("[orphan_cleanup] Process32FirstW 失败，跳过孤儿清理");
        unsafe { let _ = CloseHandle(snapshot); }
        return;
    }

    let target: Vec<u16> = "verthys-worker.exe\0".encode_utf16().collect();
    let target_slice = &target[..target.len().saturating_sub(1)]; // 去掉 null

    loop {
        // 比较 szExeFile（宽字符数组，null 结尾）
        let exe_name: Vec<u16> = entry.szExeFile.iter()
            .take_while(|&&c| c != 0)
            .copied()
            .collect();
        if exe_name == target_slice {
            let pid = entry.th32ProcessID;
            // 打开并终止
            let ph = unsafe { OpenProc2(PT2, false, pid) };
            if let Ok(h) = ph {
                let rc = unsafe { TerminateProcess(h, 1) };
                let _ = rc;
                unsafe { let _ = CloseHandle(h); }
                log::warn!("[orphan_cleanup] 杀死孤儿 verthys-worker PID={}", pid);
                killed += 1;
            }
        }

        let next = unsafe { Process32NextW(snapshot, &mut entry) };
        if next.is_err() {
            break;
        }
    }

    unsafe { let _ = CloseHandle(snapshot); }

    if killed > 0 {
        log::warn!("[orphan_cleanup] 共杀死 {} 个孤儿 verthys-worker 进程", killed);
        // 等待内核回收
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

#[cfg(not(target_os = "windows"))]
pub fn kill_orphan_workers() {
    // 非 Windows 平台无操作
}

#[cfg(target_os = "windows")]
use windows::Win32::System::JobObjects::SetInformationJobObject;
