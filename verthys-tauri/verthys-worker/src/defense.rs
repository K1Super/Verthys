/*
 * defense.rs — Worker 进程级防御策略应用
 *
 * 职责边界：只负责进程级 mitigation、DLL 搜索策略与调试线程隐藏；
 * 不接触密钥、不处理业务数据。
 *
 * 关键约束：
 *   - 必须在 Worker 进程入口最早期调用 SetDefaultDllDirectories 与 System32
 *     only 预加载，随后再应用不可撤销的进程策略；
 *   - 关键策略应用失败必须失败关闭，禁止以“旧版 Windows 兼容”为由降级放行；
 *   - 所有预加载 DLL 必须校验最终路径位于 %SystemRoot%\System32。
 *
 * 线程与安全：全部调用发生在主线程启动阶段；策略状态使用原子变量发布。
 */

#![allow(non_snake_case, non_camel_case_types, dead_code, clippy::upper_case_acronyms, clippy::enum_variant_names)]

use std::ffi::{CStr, OsStr};
use std::os::raw::{c_char, c_int, c_void};
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicU32, Ordering};

type BOOL = c_int;
type DWORD = u32;
type HMODULE = *mut c_void;
type HANDLE = *mut c_void;
type SIZE_T = usize;

const FALSE: BOOL = 0;
const LOAD_LIBRARY_SEARCH_SYSTEM32: DWORD = 0x00000800;
const MAX_PATH_W: usize = 260;

/* ---------- ProcessMitigationPolicy 枚举 ---------- */

/* 策略编号必须与系统枚举一致；编号错位会把结构体传给另一策略，
 * 轻则无效，重则以 ERROR_INVALID_PARAMETER 失败。 */
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
enum ProcessMitigationPolicy {
    ProcessDynamicCodePolicy = 2,
    ProcessStrictHandleCheckPolicy = 3,
    ProcessExtensionPointDisablePolicy = 6,
    ProcessImageLoadPolicy = 10,
    ProcessChildProcessPolicy = 13,
}

/* ---------- Mitigation Policy 结构体 ---------- */

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PROCESS_MITIGATION_CHILD_PROCESS_POLICY {
    Flags: DWORD,
}

impl PROCESS_MITIGATION_CHILD_PROCESS_POLICY {
    fn new_no_child_process() -> Self {
        Self { Flags: 0x1 }
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PROCESS_MITIGATION_IMAGE_LOAD_POLICY {
    Flags: DWORD,
}

const IMAGE_LOAD_NO_REMOTE: DWORD = 0x1;
const IMAGE_LOAD_NO_LOW_LABEL: DWORD = 0x2;

impl PROCESS_MITIGATION_IMAGE_LOAD_POLICY {
    fn required_flags() -> DWORD {
        IMAGE_LOAD_NO_REMOTE | IMAGE_LOAD_NO_LOW_LABEL
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PROCESS_MITIGATION_DYNAMIC_CODE_POLICY {
    Flags: DWORD,
}

impl PROCESS_MITIGATION_DYNAMIC_CODE_POLICY {
    fn new_prohibit_dynamic_code() -> Self {
        /* ProhibitDynamicCode = bit0；不提供线程级 opt-out 与远程降级，
         * 避免攻击者借 opt-out 恢复可写可执行内存。 */
        Self { Flags: 0x1 }
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY {
    Flags: DWORD,
}

impl PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY {
    fn new_raise_on_invalid_handle() -> Self {
        /* RaiseExceptionOnInvalidHandleReference = bit0；
         * HandleExceptionsPermanentlyEnabled = bit1。 */
        Self { Flags: 0x3 }
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY {
    Flags: DWORD,
}

impl PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY {
    fn new_disable() -> Self {
        Self { Flags: 0x1 }
    }
}

/* ---------- 模块状态 ---------- */

const SANDBOX_ATTR_PROCESS_CREATE_DISABLE: u32 = 0x02;
const SANDBOX_ATTR_IMAGE_PREFER_SYS32: u32 = 0x04;
const SANDBOX_ATTR_IMAGE_NO_REMOTE: u32 = 0x08;
const SANDBOX_ATTR_IMAGE_NO_LOW_LABEL: u32 = 0x10;

static ACTIVE_ATTRS: AtomicU32 = AtomicU32::new(0);

/* ---------- FFI ---------- */

extern "system" {
    fn GetModuleHandleA(lpModuleName: *const c_char) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const c_char)
        -> Option<unsafe extern "system" fn() -> isize>;
    fn LoadLibraryExW(lpLibFileName: *const u16, hFile: HANDLE, dwFlags: DWORD) -> HMODULE;
    fn GetModuleFileNameW(hModule: HMODULE, lpFilename: *mut u16, nSize: DWORD) -> DWORD;
    fn GetWindowsDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32;
    fn GetCurrentThread() -> HANDLE;
    fn GetCurrentProcess() -> HANDLE;
    fn GetLastError() -> DWORD;
    fn GetProcessMitigationPolicy(
        hProcess: HANDLE,
        policy: ProcessMitigationPolicy,
        lpBuffer: *mut c_void,
        dwLength: SIZE_T,
    ) -> BOOL;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtSetInformationThread(
        thread_handle: HANDLE,
        thread_information_class: u32,
        thread_information: *mut c_void,
        thread_information_length: u32,
    ) -> i32;
}

type SetProcessMitigationPolicyFn = unsafe extern "system" fn(
    policy: ProcessMitigationPolicy,
    buffer: *const c_void,
    length: SIZE_T,
) -> BOOL;

type SetDefaultDllDirectoriesFn = unsafe extern "system" fn(directory_flags: DWORD) -> BOOL;

/* ---------- 辅助 ---------- */

unsafe fn resolve_kernel32_proc(name: &CStr) -> Option<unsafe extern "system" fn() -> isize> {
    let kernel32 = c"kernel32.dll";
    let h = GetModuleHandleA(kernel32.as_ptr());
    if !h.is_null() {
        return GetProcAddress(h, name.as_ptr());
    }
    None
}

unsafe fn read_mitigation<T: Default>(policy: ProcessMitigationPolicy) -> Option<T> {
    let mut data = T::default();
    let ok = GetProcessMitigationPolicy(
        GetCurrentProcess(),
        policy,
        &mut data as *mut T as *mut c_void,
        std::mem::size_of::<T>(),
    );
    if ok != FALSE {
        Some(data)
    } else {
        None
    }
}

unsafe fn apply_mitigation<T>(policy: ProcessMitigationPolicy, data: &T) -> bool {
    let raw = match resolve_kernel32_proc(c"SetProcessMitigationPolicy") {
        Some(p) => p,
        None => return false,
    };
    let func: SetProcessMitigationPolicyFn = std::mem::transmute(raw);
    let r = func(
        policy,
        data as *const T as *const c_void,
        std::mem::size_of::<T>(),
    );
    r != FALSE
}

unsafe fn set_default_dll_directories() -> bool {
    let raw = match resolve_kernel32_proc(c"SetDefaultDllDirectories") {
        Some(p) => p,
        None => return false,
    };
    let func: SetDefaultDllDirectoriesFn = std::mem::transmute(raw);
    func(LOAD_LIBRARY_SEARCH_SYSTEM32) != FALSE
}

fn wide(path: &str) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(Some(0)).collect()
}

unsafe fn module_path(module: HMODULE) -> Option<String> {
    let mut buffer = [0u16; MAX_PATH_W];
    let len = GetModuleFileNameW(module, buffer.as_mut_ptr(), MAX_PATH_W as DWORD);
    if len == 0 || len as usize >= MAX_PATH_W {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..len as usize]))
}

unsafe fn windows_system32_prefix() -> Option<String> {
    let mut buffer = [0u16; MAX_PATH_W];
    let len = GetWindowsDirectoryW(buffer.as_mut_ptr(), MAX_PATH_W as u32);
    if len == 0 || len as usize >= MAX_PATH_W {
        return None;
    }
    let root = String::from_utf16_lossy(&buffer[..len as usize]);
    Some(format!("{}\\System32\\", root).to_ascii_lowercase())
}

/* 预加载列表：只包含不依赖 Win32k 的导入，确保可以在禁用 Win32k 系统调用
 * 之前完成 DllMain 初始化。shell32/user32 依赖 win32u，加载后再禁用会失败；
 * verthys.dll 的静态导入由加载器在 mitigation 之后解析。
 * 全部使用 System32-only 搜索，禁止应用目录/当前目录同名 DLL 抢占。 */
const PRELOAD_DLLS: [&str; 4] = [
    "shlwapi.dll",
    "wintrust.dll",
    "crypt32.dll",
    "advapi32.dll",
];

unsafe fn preload_system32_only() -> Result<(), String> {
    let system32 = windows_system32_prefix()
        .ok_or_else(|| "无法解析 Windows System32 路径".to_string())?;
    for name in PRELOAD_DLLS {
        let name_w = wide(name);
        let module = LoadLibraryExW(name_w.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if module.is_null() {
            return Err(format!("预加载 {} 失败", name));
        }
        let path = module_path(module)
            .ok_or_else(|| format!("无法读取 {} 的最终路径", name))?;
        if !path.to_ascii_lowercase().starts_with(&system32) {
            return Err(format!("{} 最终路径不在 System32: {}", name, path));
        }
    }
    Ok(())
}

/* ---------- 公共接口 ---------- */

/// 启动最早期 DLL 搜索策略。
///
/// 必须在任何日志、panic hook、业务 DLL 或第三方库加载之前调用。
/// 先固定 System32-only 搜索，再预加载不依赖 Win32k 的导入；任一失败即失败关闭。
pub fn apply_early_dll_policy() -> Result<(), String> {
    unsafe {
        if !set_default_dll_directories() {
            return Err("SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) 失败".to_string());
        }
        preload_system32_only()?;
    }
    Ok(())
}

/// 应用 Worker 进程级 mitigation。
///
/// 必须在加载 verthys.dll 之前调用；关键策略任一失败即失败关闭。
/// 返回与 process_sandbox.h 对齐的属性位掩码。
pub fn apply_process_sandbox() -> Result<u32, String> {
    unsafe {
        let mut attrs: u32 = 0;

        /* Win32k 系统调用禁用与 C 核心的 shell32 静态导入不兼容：
         * shell32 依赖 win32u，加载它之后策略无法应用；若先应用策略，
         * shell32 的 DllMain 会在 Win32k 调用被拦截后失败（ERROR_DLL_INIT_FAILED）。
         * 因此本策略不作为强制项，worker 改为依赖 ACG、ImageLoad、Job Object
         * 与受限 DACL 收敛注入面。 */
        if apply_mitigation(
            ProcessMitigationPolicy::ProcessChildProcessPolicy,
            &PROCESS_MITIGATION_CHILD_PROCESS_POLICY::new_no_child_process(),
        ) {
            attrs |= SANDBOX_ATTR_PROCESS_CREATE_DISABLE;
        } else {
            return Err("子进程创建禁用失败".to_string());
        }

        /* System32-only 搜索已在 apply_early_dll_policy 固定；
         * 此处再次设置用于确认策略仍生效。 */
        if set_default_dll_directories() {
            attrs |= SANDBOX_ATTR_IMAGE_PREFER_SYS32;
        } else {
            return Err("System32 DLL 搜索策略确认失败".to_string());
        }

        /* 父进程可能已对自身启用图像加载策略并被当前进程继承。
         * 直接写入仅含必需位的值会清除继承的 PreferSystem32Images，
         * 属于放宽既有策略，系统以 ERROR_ACCESS_DENIED 拒绝。
         * 因此先读取当前值，再按并集只增不减地写入。 */
        let inherited = read_mitigation::<PROCESS_MITIGATION_IMAGE_LOAD_POLICY>(
            ProcessMitigationPolicy::ProcessImageLoadPolicy,
        )
        .map(|p| p.Flags)
        .unwrap_or(0);
        let required = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::required_flags();
        if inherited & required != required {
            let desired = PROCESS_MITIGATION_IMAGE_LOAD_POLICY {
                Flags: inherited | required,
            };
            if !apply_mitigation(ProcessMitigationPolicy::ProcessImageLoadPolicy, &desired) {
                let code = GetLastError();
                return Err(format!(
                    "远程/低完整性镜像加载禁用失败 (Win32={})",
                    code
                ));
            }
        }
        attrs |= SANDBOX_ATTR_IMAGE_NO_REMOTE;
        attrs |= SANDBOX_ATTR_IMAGE_NO_LOW_LABEL;

        /* ACG：禁止动态代码与非镜像可执行内存，提高远程线程载荷执行门槛。 */
        if !apply_mitigation(
            ProcessMitigationPolicy::ProcessDynamicCodePolicy,
            &PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::new_prohibit_dynamic_code(),
        ) {
            return Err("ACG 动态代码禁用失败".to_string());
        }

        /* 严格句柄校验：非法句柄引用立即异常，阻断句柄复用/猜测攻击。 */
        if !apply_mitigation(
            ProcessMitigationPolicy::ProcessStrictHandleCheckPolicy,
            &PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY::new_raise_on_invalid_handle(),
        ) {
            return Err("严格句柄校验启用失败".to_string());
        }

        /* 禁用旧式扩展点，降低第三方 DLL 注入面。 */
        if !apply_mitigation(
            ProcessMitigationPolicy::ProcessExtensionPointDisablePolicy,
            &PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::new_disable(),
        ) {
            return Err("扩展点禁用失败".to_string());
        }

        ACTIVE_ATTRS.store(attrs, Ordering::SeqCst);
        Ok(attrs)
    }
}

/// 将当前线程从调试器可见列表中隐藏。
///
/// 该调用只提高调试附加门槛，不替代进程访问控制；失败时不阻断启动。
pub fn hide_current_thread_from_debugger() {
    unsafe {
        /* ThreadHideFromDebugger = 0x11，信息长度为 0。 */
        let _ = NtSetInformationThread(GetCurrentThread(), 0x11, std::ptr::null_mut(), 0);
    }
}

/// 查询已应用的沙盒属性位掩码。
pub fn get_active_attrs() -> u32 {
    ACTIVE_ATTRS.load(Ordering::SeqCst)
}

/// 查询指定沙盒属性是否已应用。
pub fn has_attr(attr: u32) -> bool {
    (get_active_attrs() & attr) != 0
}
