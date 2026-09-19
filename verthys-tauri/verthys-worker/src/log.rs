/*
 * log.rs — Worker 进程日志基础设施
 *
 * 架构定位：基础设施层（infrastructure）
 *   - 诊断日志宏：stderr 输出（父进程通过 stderr 管道采集）
 *   - panic hook：崩溃时输出结构化诊断信息
 *   - Windows 异常过滤：捕获 C 层 segfault
 *
 */

/// 诊断日志宏：仅在 debug 构建时输出到 stderr，release 构建中为空操作。
/// 生产环境零日志输出，防止内部信息泄露（路径、错误码、操作细节等）。
#[cfg(debug_assertions)]
macro_rules! diag {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}
#[cfg(not(debug_assertions))]
macro_rules! diag {
    ($($arg:tt)*) => {};
}
pub(crate) use diag;

/// 初始化诊断宏：在所有构建（含 release）中输出到 stderr。
/// 仅用于 Worker::new 初始化阶段（DLL 加载、Verthys_Init、就绪信号），
/// 不含敏感信息（路径/密码等在主循环中，仍用 diag! 保持 release 零输出）。
/// 当 worker 在初始化阶段卡住或崩溃时，父进程可通过 stderr 定位卡点。
macro_rules! init_diag {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}
pub(crate) use init_diag;

/* ------------------------------------------------------------------ *
 * 崩溃诊断：panic hook + Windows 异常处理                              *
 * ------------------------------------------------------------------ */

/// 安装 panic hook：将 panic 信息完整输出到 stderr
/// 默认 Rust panic hook 也会输出到 stderr，但显式 hook 可确保格式完整
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info.location();
        let loc_str = location
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let payload = info.payload();
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_string()
        };
        init_diag!(
            "PANIC at {}\n  message: {}\n  backtrace:\n{}",
            loc_str,
            msg,
            std::backtrace::Backtrace::force_capture()
        );
    }));
}

/// Windows: 安装 unhandled exception filter 捕获 C 函数 segfault
/// 当 DLL 中的 C 函数触发访问违规等异常时，将异常代码和地址输出到 stderr
#[cfg(target_os = "windows")]
pub fn install_exception_filter() {
    use std::os::raw::{c_long, c_void};

    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct EXCEPTION_POINTERS {
        exception_record: *mut c_void,
        context_record: *mut c_void,
    }

    unsafe extern "system" fn filter(ep: *mut EXCEPTION_POINTERS) -> c_long {
        if ep.is_null() {
            init_diag!("EXCEPTION: null exception pointers");
            return 0; // EXCEPTION_CONTINUE_SEARCH
        }
        // 读取 ExceptionCode（EXCEPTION_RECORD 第一个字段）
        let record = (*ep).exception_record;
        if record.is_null() {
            init_diag!("EXCEPTION: null exception record");
            return 0;
        }
        let code = *(record as *const u32);
        let addr = *((record as *const u8).add(8) as *const *const u8);

        let kind = match code {
            0xC0000005 => "ACCESS_VIOLATION (segfault)",
            0xC000001D => "ILLEGAL_INSTRUCTION",
            0xC0000025 => "NONCONTINUABLE_EXCEPTION",
            0xC0000094 => "INT_DIVIDE_BY_ZERO",
            0xC0000096 => "PRIVILEGED_INSTRUCTION",
            0xC00000FD => "STACK_OVERFLOW",
            0xC0000409 => "STACK_BUFFER_OVERRUN (__fastfail)",
            0xC0000374 => "HEAP_CORRUPTION",
            _ => "OTHER",
        };
        init_diag!(
            "EXCEPTION: code=0x{:08X} ({}) at address=0x{:p}",
            code, kind, addr
        );
        0 // EXCEPTION_CONTINUE_SEARCH（让默认 handler 处理，进程会终止）
    }

    extern "system" {
        fn SetUnhandledExceptionFilter(
            filter: unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> c_long,
        ) -> *mut c_void;
    }

    unsafe {
        SetUnhandledExceptionFilter(filter);
    }
}

#[cfg(not(target_os = "windows"))]
pub fn install_exception_filter() {
    // Unix 平台无操作（依赖 SIGSEGV/SIGABRT 信号处理，已由 exit code 体现）
}
