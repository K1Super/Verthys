/*
 * @file infrastructure/process_guard.rs
 * @brief 多进程资源隔离封装 - 强制进程私有资源属地化管理与自动清理
 *
 * 本模块提供进程级资源守卫（ProcessGuard），用于统一管理进程生命周期内
 * 持有的所有私有资源（包括 Rust 对象和 C 语言分配的堆内存/句柄），
 * 确保进程退出时所有资源被自动释放，防止资源泄漏。
 *
 * =============================================================================
 * 设计原则
 * =============================================================================
 * 1. 属地化管理：每个进程的私有资源必须由该进程独有的上下文对象持有所有权，
 *    跨进程传递仅允许通过管道传递纯字节流数据，禁止传递内核对象句柄。
 * 2. 自动清理：进程正常或异常退出时，ProcessGuard 的 Drop 实现会按
 *    注册逆序（LIFO）释放所有已注册资源，无需手动干预。
 * 3. 双重资源支持：同时支持 Rust 资源（实现 DropResource trait）和
 *    C 资源（通过函数指针调用释放函数），兼容混合语言项目。
 *
 * =============================================================================
 * 安全约束
 * =============================================================================
 * - 所有 C 资源指针必须保证有效性，释放函数必须与分配方式匹配
 *   （如 malloc/free、LocalAlloc/LocalFree、CloseHandle 等）。
 * - 注册到 ProcessGuard 的资源不得在其他地方手动释放，防止 double-free。
 * - 子进程创建时强制 bInheritHandles=FALSE，阻断句柄继承通道。
 *
 * =============================================================================
 * 使用场景
 * =============================================================================
 * - 进程入口层创建 ProcessGuard 实例，在初始化阶段注册各类资源。
 * - 进程退出时（包括 panic 导致的栈展开），ProcessGuard 的 Drop 自动触发清理。
 * - 子进程启动封装（spawn_isolated_child）确保新进程不继承父进程句柄，
 *   并在子进程启动后自动执行继承句柄自检（需配合 handle_factory 模块）。
 */

/// 进程资源守卫
///
/// 持有进程所有私有资源的所有权，当守卫被 Drop 时按注册逆序自动释放资源。
/// 该守卫应作为进程上下文的成员，保证在整个进程生命周期内有效。
///
/// # 资源注册
/// - Rust 资源：通过 `register_rust` 注册，需实现 `DropResource` trait。
/// - C 资源：通过 `register_c_resource` 注册，传入释放函数指针。
///
/// # 释放顺序
/// 所有资源按注册顺序的逆序（后注册先释放）清理，避免资源间依赖问题。
pub struct ProcessGuard {
    rust_resources: Vec<Box<dyn DropResource>>,
    c_resources: Vec<CResourceEntry>,
}

/// Rust 资源析构接口
///
/// 需要注册到 ProcessGuard 的 Rust 类型必须实现此 trait。
/// `cleanup` 方法在守卫 Drop 时被调用，应包含资源释放逻辑。
/// 实现者需保证 `cleanup` 可安全重入且幂等（避免因 panic 导致重复清理）。
pub trait DropResource: Send {
    /// 返回资源名称，用于调试日志。
    fn name(&self) -> &str;
    /// 执行资源清理（如关闭文件、释放内存、注销回调等）。
    fn cleanup(&mut self);
}

/// C 资源条目
///
/// 封装 C 语言分配的堆内存或句柄，以及对应的释放函数。
/// 守卫 Drop 时调用 `deleter(ptr)` 执行释放。
struct CResourceEntry {
    name: String,
    ptr: *mut std::ffi::c_void,
    deleter: unsafe extern "C" fn(*mut std::ffi::c_void),
}

// CResourceEntry 包含裸指针，需显式标记 Send 以允许跨线程传递（仅在单线程进程中使用）。
unsafe impl Send for CResourceEntry {}

impl ProcessGuard {
    /// 创建新的空资源守卫。
    ///
    /// # 调用时机
    /// 应在进程入口（如 main 或 tauri::Builder）中尽早创建，
    /// 确保在后续初始化过程中可注册资源。
    pub fn new() -> Self {
        ProcessGuard {
            rust_resources: Vec::new(),
            c_resources: Vec::new(),
        }
    }

    /// 注册一个 Rust 资源。
    ///
    /// 资源在守卫 Drop 时按注册逆序释放（后注册先释放）。
    /// 所有注册的资源必须实现 `DropResource` trait。
    pub fn register_rust(&mut self, resource: Box<dyn DropResource>) {
        self.rust_resources.push(resource);
    }

    /// 注册一个 C 资源。
    ///
    /// # 参数
    /// - `name`：资源名称（用于调试）
    /// - `ptr`：C 分配的内存/句柄指针
    /// - `deleter`：C 释放函数，签名为 `unsafe extern "C" fn(*mut c_void)`
    ///
    /// # 安全要求
    /// - `ptr` 必须指向有效资源，且未被其他方释放。
    /// - `deleter` 必须与资源分配方式匹配（如 free、CloseHandle 等）。
    /// - 守卫 Drop 时会调用 `deleter(ptr)`，调用者需确保此操作安全。
    pub fn register_c_resource(
        &mut self,
        name: impl Into<String>,
        ptr: *mut std::ffi::c_void,
        deleter: unsafe extern "C" fn(*mut std::ffi::c_void),
    ) {
        self.c_resources.push(CResourceEntry {
            name: name.into(),
            ptr,
            deleter,
        });
    }

    /// 返回已注册的资源总数（Rust + C）。
    pub fn resource_count(&self) -> usize {
        self.rust_resources.len() + self.c_resources.len()
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        // 按注册逆序释放 C 资源（后注册先释放）
        while let Some(entry) = self.c_resources.pop() {
            unsafe {
                (entry.deleter)(entry.ptr);
            }
        }

        // 按注册逆序释放 Rust 资源
        while let Some(mut resource) = self.rust_resources.pop() {
            resource.cleanup();
        }
    }
}

impl Default for ProcessGuard {
    fn default() -> Self {
        Self::new()
    }
}

/* ------------------------------------------------------------------ *
 * 子进程启动封装                                                      *
 * ------------------------------------------------------------------ */

/// 子进程启动配置
///
/// 包含可执行文件路径、命令行参数和工作目录。
pub struct ChildProcessConfig {
    pub executable: String,
    pub args: Vec<String>,
    pub working_dir: Option<String>,
}

/// 启动子进程并强制禁用句柄继承（Windows 专用，非 Windows 回退至标准 spawn）
///
/// # 安全保证
/// - Windows：通过 `CreateProcessW` 的 `bInheritHandles=FALSE` 阻断句柄继承，
///   配合 handle_factory 中创建的不可继承管道句柄，确保子进程不继承任何父进程内核对象。
/// - 非 Windows：使用标准 Command，由操作系统默认行为保证隔离（通常不继承）。
///
/// # 调用后
/// 子进程启动后应自行调用 `validate_no_inherited_handles()` 进行自检，
/// 以发现潜在的继承漏洞（防御性编程）。
#[cfg(windows)]
pub fn spawn_isolated_child(config: &ChildProcessConfig) -> Result<u32, String> {
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;
    use windows::Win32::System::Threading::{
        CreateProcessW, STARTUPINFOW,
        STARTF_USESTDHANDLES, CREATE_NO_WINDOW,
    };
    use windows::core::{PCWSTR, PWSTR};

    let mut cmdline = config.executable.clone();
    for arg in &config.args {
        cmdline.push(' ');
        cmdline.push_str(arg);
    }
    let mut wide: Vec<u16> = OsStr::new(&cmdline)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let cwd_wide: Option<Vec<u16>> = config.working_dir.as_ref().map(|d| {
        OsStr::new(d).encode_wide().chain(std::iter::once(0)).collect()
    });

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;

    let mut pi: windows::Win32::System::Threading::PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // bInheritHandles = FALSE 确保子进程不继承父进程句柄
    let result = unsafe {
        CreateProcessW(
            PCWSTR::null(),
            PWSTR(wide.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            cwd_wide.as_ref().map_or(PCWSTR::null(), |p| PCWSTR(p.as_ptr())),
            &si,
            &mut pi,
        )
    };

    match result {
        Ok(_) => {
            let pid = pi.dwProcessId;
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(pi.hThread);
                let _ = windows::Win32::Foundation::CloseHandle(pi.hProcess);
            }
            Ok(pid)
        }
        Err(e) => Err(format!("CreateProcessW 失败: {}", e)),
    }
}

#[cfg(not(windows))]
pub fn spawn_isolated_child(config: &ChildProcessConfig) -> Result<u32, String> {
    use std::process::Command;
    let child = Command::new(&config.executable)
        .args(&config.args)
        .spawn()
        .map_err(|e| format!("启动子进程失败: {}", e))?;
    Ok(child.id())
}