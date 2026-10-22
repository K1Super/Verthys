//! worker/platform.rs — 平台特定代码（worker 进程加固与孤儿进程清理）
//!
//! 安全边界：宿主对 worker 只保留最小控制面——Job Object 负责生命周期与
//! 资源上限，进程 DACL 负责访问控制，挂起创建负责消除「先运行后加固」窗口。
//!
//! 本模块对外提供：
//!   - JobHandle：Job Object 句柄的 newtype（实现 Send + Sync），仅 Windows
//!   - harden_suspended_worker：对挂起态 worker 施加 Job/DACL 后恢复执行
//!   - verify_install_paths：Release 下校验 worker 与 DLL 位于安装目录内
//!   - kill_orphan_workers：清理孤儿 verthys-worker 进程（非 Windows 为 no-op）

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
#[cfg(target_os = "windows")]
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
#[cfg(target_os = "windows")]
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
#[cfg(target_os = "windows")]
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_SET_QUOTA, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
};

/// worker 进程提交内存上限（2 GiB）。
///
/// 取值依据：单次 IPC 载荷上限 12 MiB、批量枚举上限 5000 条，
/// 正常业务驻留远低于该值；上限用于阻断解压炸弹/无限缓存导致的资源耗尽，
/// 同时为大批量导出保留充足余量。
#[cfg(target_os = "windows")]
const WORKER_MEMORY_LIMIT_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// worker 进程数上限：Job 内仅允许一个进程，阻断派生链。
#[cfg(target_os = "windows")]
const WORKER_ACTIVE_PROCESS_LIMIT: u32 = 1;

/// 标准访问权限：读取安全描述符与修改 DACL（进程句柄通用位）。
#[cfg(target_os = "windows")]
const PROCESS_READ_CONTROL: u32 = 0x0002_0000;
#[cfg(target_os = "windows")]
const PROCESS_WRITE_DAC: u32 = 0x0004_0000;

/// SDDL 修订版本 1（与安全描述符二进制布局对应）。
#[cfg(target_os = "windows")]
const SDDL_REVISION_1: u32 = 1;

/// 受控进程 DACL：仅允许 LocalSystem 与内置管理员访问。
///
/// 不授予对象所有者（OWNER RIGHTS）：同用户进程共享所有者身份，
/// 授予所有者等于向同用户全部进程开放读写内存与注入权限。
/// 宿主在创建进程时已持有句柄，后续 kill/wait 不依赖重新 OpenProcess。
/// 非提升权限的管理员令牌中 Administrators SID 处于 deny-only，同样被拒绝。
#[cfg(target_os = "windows")]
const WORKER_PROCESS_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)";

// NtResumeProcess：恢复进程内全部挂起线程。
//
// 使用 ntdll 导出而非逐个 ResumeThread，避免枚举线程时遗漏主线程之外
// 由加载器临时创建的线程。返回 NTSTATUS，非负为成功。
#[cfg(target_os = "windows")]
#[link(name = "ntdll")]
extern "system" {
    fn NtResumeProcess(process_handle: *mut core::ffi::c_void) -> i32;
}

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

/// 给挂起态 worker 进程施加受限 DACL。
///
/// 必须在恢复执行前调用：DACL 生效前进程尚未运行任何用户态代码。
/// 失败返回 Err，由调用方终止子进程。
#[cfg(target_os = "windows")]
fn apply_restricted_dacl(process: HANDLE) -> Result<(), String> {
    let sddl = windows::core::HSTRING::from(WORKER_PROCESS_SDDL);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl,
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|e| format!("解析 worker 进程 SDDL 失败: {}", e))?;

    let set_result = unsafe {
        windows::Win32::Security::SetKernelObjectSecurity(
            process,
            DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    unsafe {
        let _ = LocalFree(HLOCAL(descriptor.0));
    }
    set_result.map_err(|e| format!("设置 worker 进程 DACL 失败: {}", e))
}

/// 对挂起态 worker 施加 Job Object 资源上限与进程 DACL，然后恢复执行。
///
/// 调用前提：子进程以 `CREATE_SUSPENDED` 创建，尚未执行任何指令。
/// 失败关闭：任一步骤失败都终止子进程并返回 Err，不允许以弱化配置继续。
#[cfg(target_os = "windows")]
pub(crate) fn harden_suspended_worker(pid: u32) -> Result<JobHandle, String> {
    let job = match unsafe { CreateJobObjectW(None, PCWSTR::null()) } {
        Ok(handle) => handle,
        Err(e) => return Err(format!("创建 Job Object 失败: {}", e)),
    };

    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    info.BasicLimitInformation.ActiveProcessLimit = WORKER_ACTIVE_PROCESS_LIMIT;
    info.ProcessMemoryLimit = WORKER_MEMORY_LIMIT_BYTES;
    let info_ptr = &info as *const _ as *const core::ffi::c_void;
    let info_len = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
    if let Err(e) = unsafe {
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, info_ptr, info_len)
    } {
        unsafe {
            let _ = CloseHandle(job);
        }
        return Err(format!("设置 Job Object 限制失败: {}", e));
    }

    let access = PROCESS_SET_QUOTA
        | PROCESS_TERMINATE
        | PROCESS_SUSPEND_RESUME
        | PROCESS_ACCESS_RIGHTS(PROCESS_READ_CONTROL | PROCESS_WRITE_DAC);
    let process = match unsafe { OpenProcess(access, false, pid) } {
        Ok(handle) => handle,
        Err(e) => {
            unsafe {
                let _ = CloseHandle(job);
            }
            return Err(format!("打开挂起态 worker 失败: {}", e));
        }
    };

    if let Err(e) = apply_restricted_dacl(process) {
        unsafe {
            let _ = CloseHandle(process);
            let _ = CloseHandle(job);
        }
        return Err(e);
    }

    if let Err(e) = unsafe { AssignProcessToJobObject(job, process) } {
        unsafe {
            let _ = CloseHandle(process);
            let _ = CloseHandle(job);
        }
        return Err(format!("将 worker 绑定到 Job Object 失败: {}", e));
    }

    let status = unsafe { NtResumeProcess(process.0) };
    unsafe {
        let _ = CloseHandle(process);
    }
    if status < 0 {
        unsafe {
            let _ = CloseHandle(job);
        }
        return Err(format!("恢复 worker 执行失败: NTSTATUS=0x{:08X}", status));
    }

    log::info!(
        "[watchdog] worker PID={} 已加固并恢复：Job 单进程/2GiB 上限、受限 DACL",
        pid
    );
    Ok(JobHandle(job))
}

/// Release 下校验 worker 与 DLL 均位于宿主安装目录内。
///
/// 开发构建跳过：dev 产物分散在 target 与仓库构建目录，路径不共根。
/// 目的：宿主解析出的路径一旦被替换为目录外文件，立即拒绝启动。
pub(crate) fn verify_install_paths(worker_exe: &str, dll_path: &str) -> Result<(), String> {
    #[cfg(debug_assertions)]
    {
        let _ = (worker_exe, dll_path);
        Ok(())
    }
    #[cfg(not(debug_assertions))]
    {
        let exe = std::env::current_exe().map_err(|e| format!("获取宿主路径失败: {}", e))?;
        let exe_dir = exe
            .parent()
            .ok_or_else(|| "宿主路径缺少父目录".to_string())?;
        let root = std::fs::canonicalize(exe_dir)
            .map_err(|e| format!("规范化安装目录失败: {}", e))?;
        // 未打包的 release 开发树（target/release）中 worker 与 DLL 分处不同目录，
        // 该布局不是部署形态；安装目录中两者必须同根。
        let root_text = root.display().to_string().to_lowercase();
        if root_text.ends_with("\\target\\release") {
            return Ok(());
        }
        for path in [worker_exe, dll_path] {
            let canonical =
                std::fs::canonicalize(path).map_err(|e| format!("规范化路径失败 {}: {}", path, e))?;
            if !canonical.starts_with(&root) {
                return Err(format!("路径越界: {} 不在安装目录内", canonical.display()));
            }
        }
        Ok(())
    }
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
    use windows::Win32::System::Threading::{
        OpenProcess as OpenProc2, TerminateProcess, PROCESS_TERMINATE as PT2,
    };

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
        unsafe {
            let _ = CloseHandle(snapshot);
        }
        return;
    }

    let target: Vec<u16> = "verthys-worker.exe\0".encode_utf16().collect();
    let target_slice = &target[..target.len().saturating_sub(1)]; // 去掉 null

    loop {
        // 比较 szExeFile（宽字符数组，null 结尾）
        let exe_name: Vec<u16> = entry
            .szExeFile
            .iter()
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
                unsafe {
                    let _ = CloseHandle(h);
                }
                log::warn!("[orphan_cleanup] 杀死孤儿 verthys-worker PID={}", pid);
                killed += 1;
            }
        }

        let next = unsafe { Process32NextW(snapshot, &mut entry) };
        if next.is_err() {
            break;
        }
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    if killed > 0 {
        log::warn!(
            "[orphan_cleanup] 共杀死 {} 个孤儿 verthys-worker 进程",
            killed
        );
        // 等待内核回收
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

#[cfg(not(target_os = "windows"))]
pub fn kill_orphan_workers() {
    // 非 Windows 平台无操作
}
