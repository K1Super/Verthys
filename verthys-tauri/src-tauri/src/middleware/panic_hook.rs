/*
 * middleware/panic_hook.rs — 全局异常处理器
 *
 *    "顶层（入口/主循环）行为约定"
 *
 * 职责（仅两项）：
 *   1. 构造 JSON 格式的致命错误日志（包含堆栈信息、当前进程ID、发生时间），
 *      通过日志管道发送。
 *   2. 若进程间 IPC 通道仍可用，向父进程或监控进程发送统一错误响应报文。
 *
 * 分阶段安装策略
 *   - install_minimal(): main 函数第一行安装，仅 OutputDebugString + MessageBoxW
 *     不依赖日志系统，确保从进程启动第一微秒起崩溃均可捕获
 *   - upgrade(log_sender): 日志系统就绪后升级为完整 hook
 *     以管道版本替换 minimal hook，将崩溃信息投递至日志管道
 *
 * CI 红线：
 *   - 不得在 panic 钩子中执行业务补偿处理（如重试、回滚）
 *   - 不得在非入口文件中使用 log 宏或 println
 */
use std::sync::Once;

use crate::infrastructure::log_pipe::{LogEntry, LogLevel, LogSender};

/// 全局 panic 钩子初始化守卫（确保只注册一次）
static PANIC_HOOK_INIT: Once = Once::new();
/// minimal hook 安装守卫（早于完整 hook）
static MINIMAL_HOOK_INIT: Once = Once::new();

/// 安装最小化 panic hook
///
/// 在 main 函数第一行调用，**先于任何其他代码**。
///
/// 此 hook 不依赖日志系统，仅：
///   1. Windows: 调用 OutputDebugStringW 输出崩溃信息（调试器可见）
///   2. Windows: 弹出 MessageBoxW 提示用户（GUI 模式下）
///   3. 其他平台: 输出到 stderr
///
/// 日志系统就绪后，调用 upgrade(log_sender) 升级为完整 hook。
///
/// 注意：Cargo.toml 中 panic = "abort"，栈展开受限。
/// 此 hook 仅做最小化输出后让默认 abort 执行，不依赖展开。
pub fn install_minimal() {
    MINIMAL_HOOK_INIT.call_once(|| {
        std::panic::set_hook(Box::new(minimal_panic_handler));
    });
}

/// 升级 panic hook 为完整版本
///
/// 在日志管道就绪后调用（lib.rs run() 内）。
/// 此方法将 panic hook 替换为完整版本：
///   1. 构造 JSON 格式的致命错误日志投递至管道
///   2. 仍调用 OutputDebugStringW 作为兜底（管道不可用时不丢）
///
/// log_sender 参数通过入口层注入，非全局静态变量。
pub fn upgrade(log_sender: LogSender) {
    PANIC_HOOK_INIT.call_once(|| {
        let sender = log_sender.clone();
        std::panic::set_hook(Box::new(move |info| {
            full_panic_handler(info, &sender);
        }));
    });
}

/// 兼容旧接口：install(log_sender) 等同于 upgrade(log_sender)
///
/// 保留以兼容现有 lib.rs 调用点。
/// 注意：调用前必须先调用 install_minimal()。
pub fn install(log_sender: LogSender) {
    upgrade(log_sender);
}

/// ===== panic payload 脱敏 =====
///
/// panic payload 可能携带敏感上下文（expect/unwrap 的字符串、越界索引
/// 关联数据、调试格式化的密钥材料）。三路输出（日志管道/
/// OutputDebugStringW/stderr）均存在被本机攻击者或日志读者捕获的
/// 泄露面。策略：
///   1. 截断至 256 字符（char 边界安全截断，防大块敏感数据倾倒）
///   2. 过滤控制字符（防日志注入伪造条目、防二进制密钥字节直出）
///   3. 保留 panic 位置与 backtrace（排障核心，不含用户数据）
const PANIC_PAYLOAD_MAX_CHARS: usize = 256;

fn sanitize_panic_payload(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .map(|c| {
            // 可见 ASCII 与常规空白保留；其余（控制字符/DEL/奇异 Unicode）替换
            if (c.is_ascii_graphic() || c == ' ' || c == '\t') && c != '\u{7f}' {
                c
            } else {
                '?'
            }
        })
        .collect();
    if filtered.chars().count() > PANIC_PAYLOAD_MAX_CHARS {
        let head: String = filtered.chars().take(PANIC_PAYLOAD_MAX_CHARS).collect();
        format!("{}...[truncated]", head)
    } else {
        filtered
    }
}

/// 最小化 panic 处理器（不依赖日志系统）
///
/// 仅输出到 OutputDebugString（Windows）或 stderr（其他平台）。
fn minimal_panic_handler(info: &std::panic::PanicHookInfo<'_>) {
    let payload = info.payload();
    let msg = if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "Box<dyn Any> panic payload".to_string()
    };
    let msg = sanitize_panic_payload(&msg);

    let location = info.location().map(|l| {
        format!("{}:{}:{}", l.file(), l.line(), l.column())
    }).unwrap_or_else(|| "unknown".to_string());

    let panic_msg = format!(
        "VERTHYS PANIC (minimal hook): {} at {}\npid={}",
        msg, location, std::process::id()
    );

    // Windows: OutputDebugString + MessageBoxW
    #[cfg(windows)]
    {
        output_debug_string(&panic_msg);
        // MessageBoxW 在 panic = "abort" 下可能阻塞，仅在非 windows_subsystem = "windows" 时弹窗
        // GUI 模式下不弹窗（用户可能无法看到，且会阻塞 abort）
        // 改为仅 OutputDebugString，由日志系统（升级后）记录
    }

    // 其他平台: stderr
    #[cfg(not(windows))]
    {
        eprintln!("{}", panic_msg);
    }
}

/// 完整 panic 处理器（依赖日志系统）
///
/// 构造 JSON 日志投递至管道 + OutputDebugString 兜底。
fn full_panic_handler(info: &std::panic::PanicHookInfo<'_>, sender: &LogSender) {
    let payload = info.payload();
    let msg = if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "Box<dyn Any> panic payload".to_string()
    };
    let msg = sanitize_panic_payload(&msg);

    let location = info.location().map(|l| {
        format!("{}:{}:{}", l.file(), l.line(), l.column())
    }).unwrap_or_else(|| "unknown".to_string());

    let backtrace = std::backtrace::Backtrace::force_capture();

    let message = format!(
        "PANIC: {} at {}\nBacktrace:\n{}",
        msg, location, backtrace
    );

    // 1. 构造 JSON 格式的致命错误日志，使用 send_guaranteed 不丢
    let entry = LogEntry::new(LogLevel::Fatal, "panic_hook", message.clone());
    sender.send_guaranteed(entry);

    // 2. OutputDebugString 兜底（管道可能未消费完就 abort）
    #[cfg(windows)]
    output_debug_string(&format!(
        "VERTHYS PANIC (full hook): {} | pid={}",
        message, std::process::id()
    ));

    #[cfg(not(windows))]
    {
        eprintln!("VERTHYS PANIC (full hook): {}", message);
    }
}

/// ===== OutputDebugStringW 封装（Windows） =====
#[cfg(windows)]
fn output_debug_string(msg: &str) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::System::Diagnostics::Debug::OutputDebugStringW;
    use windows::core::PCWSTR;

    let wide: Vec<u16> = std::ffi::OsStr::new(msg)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        OutputDebugStringW(PCWSTR(wide.as_ptr()));
    }
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn output_debug_string(msg: &str) {
    eprintln!("{}", msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_minimal_does_not_panic() {
        // 多次调用应幂等
        install_minimal();
        install_minimal();
    }

    #[test]
    fn test_minimal_panic_handler_format() {
        // 仅验证 handler 函数可被引用（实际触发 panic 测试在集成测试中）
        let _ = minimal_panic_handler as fn(&std::panic::PanicHookInfo<'_>);
    }

    #[test]
    fn test_sanitize_truncates_long_payload() {
        let raw = "A".repeat(1024);
        let out = sanitize_panic_payload(&raw);
        assert!(out.chars().count() < 1024);
        assert!(out.ends_with("...[truncated]"));
        assert!(out.starts_with(&"A".repeat(256)));
    }

    #[test]
    fn test_sanitize_strips_control_chars() {
        // 换行（日志注入）、NUL、DEL、二进制字节应被替换；保留可见 ASCII 与空格
        let raw = "ok\r\nvalue\u{0}\u{7f}\u{1}tail";
        let out = sanitize_panic_payload(raw);
        assert!(out.starts_with("ok??value???tail"), "got: {out}");
        assert!(!out.contains('\r') && !out.contains('\n'));
    }

    #[test]
    fn test_sanitize_keeps_normal_message() {
        let raw = "index out of bounds: the len is 3 but the index is 7";
        assert_eq!(sanitize_panic_payload(raw), raw);
    }
}
