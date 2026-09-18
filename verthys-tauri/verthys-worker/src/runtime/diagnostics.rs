/* diagnostics.rs — 诊断辅助：GetLastError FFI 与 Windows 错误码格式化
 *
 * 职责：
 *   - ffi_get_last_error（windows: FFI GetLastError / 非 windows: 返回 0）
 *   - format_os_error（错误码 → 人类可读描述）
 *
 * 用于 DLL 加载失败时获取底层 Windows 错误码。libloading 的 Error
 * Display 不输出错误码，仅 Debug 输出，但 Debug 也可能因其他调用
 * 清空 GetLastError 而丢失原始错误。本模块直接 FFI 调用 GetLastError
 * 在 DLL 加载失败的第一时间捕获错误码。
 *
 * 被 mod.rs 重导出为 crate::runtime::{ffi_get_last_error, format_os_error}。
 */

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}

/// 通过 FFI 调用 GetLastError，返回当前线程的最近错误码
#[cfg(windows)]
pub unsafe fn ffi_get_last_error() -> u32 {
    GetLastError()
}

#[cfg(not(windows))]
pub unsafe fn ffi_get_last_error() -> u32 {
    0
}

/// 格式化 Windows 错误码为人类可读描述
/// 重点关注 DLL 加载相关错误码（ERROR_MOD_NOT_FOUND、ERROR_DLL_NOT_FOUND 等）
pub fn format_os_error(code: u32) -> &'static str {
    match code {
        0 => "无错误 (ERROR_SUCCESS)",
        2 => "系统找不到指定的文件 (ERROR_FILE_NOT_FOUND)",
        3 => "系统找不到指定的路径 (ERROR_PATH_NOT_FOUND)",
        5 => "拒绝访问 (ERROR_ACCESS_DENIED) — 权限不足",
        14 => "存储空间不足，无法完成此操作 (ERROR_NOT_ENOUGH_MEMORY)",
        19 => "介质受写入保护 (ERROR_WRITE_PROTECT)",
        31 => "连接到系统上的设备没有发挥作用 (ERROR_GEN_FAILURE)",
        87 => "参数错误 (ERROR_INVALID_PARAMETER)",
        126 => "找不到指定的模块 (ERROR_MOD_NOT_FOUND) — DLL 或其依赖项缺失",
        127 => "找不到指定的程序 (ERROR_PROC_NOT_FOUND) — DLL 中找不到导出函数",
        193 => "%1 不是有效的 Win32 应用程序 (ERROR_BAD_EXE_FORMAT) — 32/64 位不匹配",
        216 => "该版本的 Windows 不支持此应用程序的映像 (ERROR_INVALID_EXE_SIGNATURE)",
        580 => "系统找不到指定的远程计算机 (ERROR_FILE_CHECKED_OUT)",
        1114 => "DLL 初始化例程失败 (ERROR_DLL_INIT_FAILED) — DllMain 返回 FALSE",
        14001 => "由于并行配置不正确，应用程序无法启动 (Side-by-side 配置错误)",
        _ => "未知错误码（请查询 System Error Codes）",
    }
}
