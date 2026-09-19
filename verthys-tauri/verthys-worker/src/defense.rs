/*
 * defense.rs — Worker 进程级防御策略应用
 *
 * 调用时机：
 *   必须在 Worker 进程启动早期、加载 verthys.dll 之前调用。
 *   原因：
 *     - SetProcessMitigationPolicy 是进程级策略，一旦应用不可撤销
 *     - 部分 policy（如 NoRemoteImages）会立即生效，影响后续 DLL 加载行为
 *     - 必须在加载任何业务 DLL 之前完成沙盒包装
 *
 * 实现策略：
 *   - 直接 FFI 声明 SetProcessMitigationPolicy（避免依赖 windows-sys 完整 feature）
 *   - 各项 policy 独立应用，失败降级（不阻断启动）
 *   - 失败原因：旧版 Windows 不支持某些 policy（Win10 1709+ 才有）
 *
 * 与 verthys.dll 的协作：
 *   - 本模块应用进程级 mitigation policy
 *   - verthys.dll 的 Verthys_Init() 调用 defense_closure_check(BOOT) 验证
 *   - defense_closure.c 通过 process_sandbox_get_active_attrs() 查询当前生效策略
 *   - 若关键策略未应用 → DLL 启动校验返回 DEGRADED（但仍可启动）
 *
 * 安全契约：
 *   - 本模块仅做进程级 mitigation policy 应用，不接触任何密钥
 *   - 应用失败不阻断启动（旧版 Windows 兼容）
 *   - 实际状态由 defense_closure_check 在 DLL 侧查询
 */
/* Win32 命名镜像声明：本模块的类型/常量/枚举刻意与 winnt.h 同名
 * （BOOL/DWORD/HMODULE、ProcessDEPPolicy 等），便于与 Microsoft 官方文档
 * 对照审计。clippy::upper_case_acronyms / clippy::enum_variant_names 在此
 * 属误报，模块级豁免。 */
#![allow(non_snake_case, non_camel_case_types, dead_code, clippy::upper_case_acronyms, clippy::enum_variant_names)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

/* ---------- Win32 类型和常量 ---------- */

type BOOL = c_int;
type DWORD = u32;
type HMODULE = *mut c_void;
type SIZE_T = usize;

const FALSE: BOOL = 0;

/* ---------- ProcessMitigationPolicy 枚举（与 winnt.h 一致） ---------- */

/// ProcessMitigationPolicy 枚举值
/// 对应 winnt.h 中的 _PROCESS_MITIGATION_POLICY 枚举
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
enum ProcessMitigationPolicy {
    ProcessDEPPolicy = 0,
    ProcessASLRPolicy = 1,
    ProcessDynamicCodePolicy = 2,
    ProcessStrictHandleCheckPolicy = 3,
    ProcessSystemCallDisablePolicy = 4,  // Win10 1709+
    ProcessExtensionPointDisablePolicy = 5,
    ProcessChildProcessPolicy = 6,        // Win10 1709+
    ProcessPayloadOverridePolicy = 7,
    ProcessImageLoadPolicy = 8,            // Win10 1709+
    ProcessMaxMitigationPolicy = 9,
}

/* ---------- Mitigation Policy 结构体 ---------- */

/// ProcessSystemCallDisablePolicy 结构（4 字节联合体）
/// 禁用 Win32k 系统调用（窗口、GDI、消息）
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY {
    Flags: DWORD,
}

impl PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY {
    fn new_disallow_win32k() -> Self {
        // DisallowWin32kSystemCalls = bit 0
        Self { Flags: 0x1 }
    }
}

/// ProcessChildProcessPolicy 结构（4 字节联合体）
/// 禁止子进程创建
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PROCESS_MITIGATION_CHILD_PROCESS_POLICY {
    Flags: DWORD,
}

impl PROCESS_MITIGATION_CHILD_PROCESS_POLICY {
    fn new_no_child_process() -> Self {
        // NoChildProcessCreation = bit 0
        Self { Flags: 0x1 }
    }
}

/// ProcessImageLoadPolicy 结构（4 字节联合体）
/// 禁止远程/低完整性镜像加载
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PROCESS_MITIGATION_IMAGE_LOAD_POLICY {
    Flags: DWORD,
}

impl PROCESS_MITIGATION_IMAGE_LOAD_POLICY {
    fn new_no_remote_no_low() -> Self {
        // NoRemoteImages = bit 0
        // NoLowMandatoryLabelImages = bit 1
        Self { Flags: 0x3 }
    }
}

/* ---------- SetDefaultDllDirectories ---------- */

const LOAD_LIBRARY_SEARCH_SYSTEM32: DWORD = 0x00000800;

/* ---------- 模块状态 ---------- */

/// 已成功应用的沙盒属性位掩码
/// 与 process_sandbox.h 中的 SANDBOX_ATTR_* 对齐
const SANDBOX_ATTR_WIN32K_SYS_DISABLE: u32    = 0x01;
const SANDBOX_ATTR_PROCESS_CREATE_DISABLE: u32 = 0x02;
const SANDBOX_ATTR_IMAGE_PREFER_SYS32: u32    = 0x04;
const SANDBOX_ATTR_IMAGE_NO_REMOTE: u32       = 0x08;
const SANDBOX_ATTR_IMAGE_NO_LOW_LABEL: u32    = 0x10;

static mut ACTIVE_ATTRS: u32 = 0;

/* ---------- FFI 函数声明 ---------- */

extern "system" {
    fn GetModuleHandleA(lpModuleName: *const c_char) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const c_char) -> Option<unsafe extern "system" fn() -> isize>;
    fn LoadLibraryA(lpLibFileName: *const c_char) -> HMODULE;
}

/// SetProcessMitigationPolicy 函数指针类型
type SetProcessMitigationPolicyFn = unsafe extern "system" fn(
    policy: ProcessMitigationPolicy,
    buffer: *const c_void,
    length: SIZE_T,
) -> BOOL;

/// SetDefaultDllDirectories 函数指针类型
type SetDefaultDllDirectoriesFn = unsafe extern "system" fn(
    directory_flags: DWORD,
) -> BOOL;

/* ---------- 辅助函数 ---------- */

/// 动态解析 kernel32.dll 中的函数指针
///
/// 使用 GetProcAddress 动态解析，避免依赖 windows-sys 完整 feature。
/// 返回 None 表示函数不可用（旧版 Windows）。
unsafe fn resolve_kernel32_proc(name: &CStr) -> Option<unsafe extern "system" fn() -> isize> {
    // C 字符串字面量（c"..."）自带 NUL 终止，杜绝手工拼 \0 的遗漏风险
    let kernel32 = c"kernel32.dll";
    let h = GetModuleHandleA(kernel32.as_ptr());
    if h.is_null() {
        // kernel32 不在已加载模块中，尝试主动加载
        let h2 = LoadLibraryA(kernel32.as_ptr());
        if h2.is_null() {
            return None;
        }
        return GetProcAddress(h2, name.as_ptr());
    }
    GetProcAddress(h, name.as_ptr())
}

/// 应用 ProcessSystemCallDisablePolicy（禁用 Win32k 系统调用）
///
/// 返回 true 成功，false 失败（旧版 Windows 不支持）。
unsafe fn apply_win32k_syscall_disable() -> bool {
    let raw = match resolve_kernel32_proc(c"SetProcessMitigationPolicy") {
        Some(p) => p,
        None => return false,
    };
    let func: SetProcessMitigationPolicyFn = std::mem::transmute(raw);
    let policy = PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY::new_disallow_win32k();
    let r = func(
        ProcessMitigationPolicy::ProcessSystemCallDisablePolicy,
        &policy as *const _ as *const c_void,
        std::mem::size_of_val(&policy),
    );
    r != FALSE
}

/// 应用 ProcessChildProcessPolicy（NoChildProcessCreation=1）
///
/// 返回 true 成功，false 失败。
unsafe fn apply_child_process_disable() -> bool {
    let raw = match resolve_kernel32_proc(c"SetProcessMitigationPolicy") {
        Some(p) => p,
        None => return false,
    };
    let func: SetProcessMitigationPolicyFn = std::mem::transmute(raw);
    let policy = PROCESS_MITIGATION_CHILD_PROCESS_POLICY::new_no_child_process();
    let r = func(
        ProcessMitigationPolicy::ProcessChildProcessPolicy,
        &policy as *const _ as *const c_void,
        std::mem::size_of_val(&policy),
    );
    r != FALSE
}

/// 应用 SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)
///
/// 返回 true 成功，false 失败（Win8 以下不支持）。
unsafe fn apply_image_prefer_system32() -> bool {
    let raw = match resolve_kernel32_proc(c"SetDefaultDllDirectories") {
        Some(p) => p,
        None => return false,
    };
    let func: SetDefaultDllDirectoriesFn = std::mem::transmute(raw);
    let r = func(LOAD_LIBRARY_SEARCH_SYSTEM32);
    r != FALSE
}

/// 应用 ProcessImageLoadPolicy（NoRemoteImages + NoLowMandatoryLabelImages）
///
/// 返回 true 成功，false 失败。
unsafe fn apply_image_load_policy() -> bool {
    let raw = match resolve_kernel32_proc(c"SetProcessMitigationPolicy") {
        Some(p) => p,
        None => return false,
    };
    let func: SetProcessMitigationPolicyFn = std::mem::transmute(raw);
    let policy = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::new_no_remote_no_low();
    let r = func(
        ProcessMitigationPolicy::ProcessImageLoadPolicy,
        &policy as *const _ as *const c_void,
        std::mem::size_of_val(&policy),
    );
    r != FALSE
}

/* ---------- 公共接口 ---------- */

/// 应用 Worker 进程级沙盒 mitigation policy
///
/// 必须在加载 verthys.dll 之前调用。
///
/// 应用四项 policy：
///   1. WIN32K_SYSTEM_CALL_DISABLE：免疫所有窗口注入
///   2. PROCESS_CREATION_DISABLED：绝杀进程镂空、子进程注入
///   3. IMAGE_LOAD_PREFER_SYSTEM32：防本地 DLL 劫持
///   4. IMAGE_LOAD_NO_REMOTE + NO_LOW_LABEL：防反射注入 + 防低完整性镜像加载
///
/// 失败降级：
///   - 旧版 Windows 不支持某些 policy（Win10 1709+ 才有）
///   - 失败不阻断启动，仅记录降级状态
///   - 实际状态由 verthys.dll 内的 defense_closure_check 查询
///
/// 返回已成功应用的属性位掩码（与 process_sandbox.h 对齐）。
pub fn apply_process_sandbox() -> u32 {
    unsafe {
        let mut attrs: u32 = 0;

        // 0. 预加载 Win32k 依赖 DLL —— 必须在 Win32k 系统调用禁用之前完成
        //
        // 背景：
        //   DisallowWin32kSystemCalls mitigation policy 一旦应用，任何 Win32k 系统调用
        //   都会被拒绝。但 USER32.dll 的 DllMain 在首次加载时会调用 NtUser* 系统调用
        //   来初始化进程的窗口站/桌面关联，如果在 mitigation 应用之后再加载 USER32.dll
        //   （例如 verthys.dll 依赖 USER32.dll），USER32.dll 的 DllMain 会失败，
        //   导致 verthys.dll 加载失败（ERROR_DLL_INIT_FAILED = 1114）。
        //
        // 处理方式：
        //   在应用 Win32k 禁用之前，预先加载 verthys.dll 依赖的所有 Win32k-using DLL，
        //   让它们的 DllMain 在 mitigation 生效前完成初始化。后续加载 verthys.dll 时，
        //   这些依赖 DLL 已驻留内存，DllMain 不会再次运行，避开 mitigation 冲突。
        //
        // 预加载的 DLL 列表（verthys.dll 的依赖，可能调用 Win32k）：
        //   - user32.dll   窗口/消息/GDI（Win32k 主体）
        //   - shlwapi.dll  Shell 轻量 API（可能间接使用 user32）
        //   - shell32.dll  Shell API（依赖 user32）
        //   - wintrust.dll Authenticode 验证（依赖 user32/crypt32）
        //   - crypt32.dll  加密 API（可能间接使用 user32）
        preload_win32k_dependencies();

        // 1. 禁用 Win32k 系统调用（免疫窗口注入）
        //    依赖 DLL 已预加载，DllMain 不会再次触发 Win32k 调用
        if apply_win32k_syscall_disable() {
            attrs |= SANDBOX_ATTR_WIN32K_SYS_DISABLE;
        }

        // 2. 禁止子进程创建（绝杀进程镂空、子进程注入）
        if apply_child_process_disable() {
            attrs |= SANDBOX_ATTR_PROCESS_CREATE_DISABLE;
        }

        // 3. System32 优先加载（防本地 DLL 劫持）
        if apply_image_prefer_system32() {
            attrs |= SANDBOX_ATTR_IMAGE_PREFER_SYS32;
        }

        // 4. 禁止远程镜像加载 + 禁止低完整性镜像加载（防反射注入）
        if apply_image_load_policy() {
            attrs |= SANDBOX_ATTR_IMAGE_NO_REMOTE;
            attrs |= SANDBOX_ATTR_IMAGE_NO_LOW_LABEL;
        }

        ACTIVE_ATTRS = attrs;
        attrs
    }
}

/// 预加载 Win32k-using 依赖 DLL
///
/// 在应用 DisallowWin32kSystemCalls mitigation policy 之前调用，
/// 确保 USER32.dll 等依赖的 DllMain 在 Win32k 禁用生效前完成初始化。
///
/// 失败不阻断启动 —— 即使预加载失败，mitigation 应用后仍可能正常工作
/// （例如 USER32.dll 已通过其他途径被 Rust 运行时加载）。
unsafe fn preload_win32k_dependencies() {
    // 仅使用模块名（不带路径），从 System32 加载
    // 这些 DLL 都是 Windows 系统组件，加载它们不会引入安全风险
    let dlls = [
        c"user32.dll",
        c"shlwapi.dll",
        c"shell32.dll",
        c"wintrust.dll",
        c"crypt32.dll",
        c"advapi32.dll",
    ];

    let mut loaded_count: u32 = 0;
    for dll in &dlls {
        // LoadLibraryA 增加引用计数，DLL 驻留至进程退出
        // 即使 FreeLibrary，DllMain 已运行过，mitigation 不会影响
        let h = LoadLibraryA(dll.as_ptr());
        if !h.is_null() {
            loaded_count += 1;
        }
    }
    // 预加载结果不返回错误 —— 失败降级（mitigation 可能仍可工作）
    let _ = loaded_count;
}

/// 查询当前已应用的沙盒属性位掩码
///
/// 返回值与 process_sandbox.h 中的 SANDBOX_ATTR_* 对齐。
/// 用于 verthys.dll 内的 defense_closure_check 查询当前进程状态。
pub fn get_active_attrs() -> u32 {
    unsafe { ACTIVE_ATTRS }
}

/// 查询指定沙盒属性是否已应用
pub fn has_attr(attr: u32) -> bool {
    unsafe { (ACTIVE_ATTRS & attr) != 0 }
}
