/*
 * @file infrastructure/console_handler.rs
 * @brief 跨平台系统退出信号捕获与进程优雅停止驱动模块
 *
 * 模块业务规则与硬性约束：
 * 1. Windows依赖系统API注册控制台回调，捕获指定五类系统关闭事件，通过取消令牌异步下发停止指令。
 * 2. 进程收到停止信号后固定收尾链路：任务停止通知、日志缓冲区强制刷盘关闭、进程正常退出。
 * 3. Windows GUI编译模式存在能力边界：注销、关机会话事件无法通过控制台回调捕获，需由Tauri窗口消息循环补充实现。
 * 4. Windows中断回调上下文存在强安全限制：禁止同步锁阻塞、禁止堆内存分配、禁止文件IO操作，仅允许触发令牌取消。
 * 5. 采用全局一次性锁容器持有令牌强引用，生命周期与进程绑定，业务代码通过异步选择器监听停止信号。
 */
use std::sync::OnceLock;

use tokio_util::sync::CancellationToken;

/// 进程全局停止令牌容器
/// 设计意图：OnceLock保障多线程安全一次性初始化；强引用使令牌生命周期等同于进程，保证信号回调可稳定访问实例
static GLOBAL_CANCEL_TOKEN: OnceLock<CancellationToken> = OnceLock::new();

/// 绑定停止令牌并完成全平台系统退出信号监听注册
/// 业务特性：方法具备幂等性，重复调用仅完成首次全局令牌赋值
/// 返回值：注册过程系统调用或线程创建异常时返回格式化错误信息
pub fn register_shutdown_token(token: CancellationToken) -> Result<(), String> {
    let _ = GLOBAL_CANCEL_TOKEN.set(token.clone());

    #[cfg(windows)]
    {
        use windows::Win32::System::Console::SetConsoleCtrlHandler;

        /// Windows系统控制台中断底层回调函数
        /// 约束：严格遵循系统调用约定，上下文内仅执行令牌取消操作，规避系统中断环境下各类未定义行为
        unsafe extern "system" fn handler_proc(ctrl_type: u32) -> windows::Win32::Foundation::BOOL {
            use windows::Win32::System::Console::{
                CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT,
                CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
            };

            let should_cancel = matches!(
                ctrl_type,
                CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT
                    | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT
            );

            if should_cancel {
                if let Some(token) = GLOBAL_CANCEL_TOKEN.get() {
                    token.cancel();
                    // 业务意图：向系统声明事件已接管，阻止进程强制终止，留给业务执行优雅退出流程的时间窗口
                    return windows::Win32::Foundation::BOOL(1);
                }
            }

            windows::Win32::Foundation::BOOL(0)
        }

        let result = unsafe {
            SetConsoleCtrlHandler(Some(handler_proc), true)
        };

        result.map_err(|e| format!("SetConsoleCtrlHandler 注册失败: {}", e))?;
    }

    #[cfg(not(windows))]
    {
        let token_clone = token.clone();
        // 设计意图：独立线程+专属运行时隔离信号监听逻辑，避免侵入业务主线程运行环境
        std::thread::Builder::new()
            .name("signal-handler".to_string())
            .spawn(move || {
                use tokio::runtime::Runtime;
                let rt = Runtime::new().expect("创建 signal runtime 失败");
                rt.block_on(async {
                    use tokio::signal;
                    tokio::select! {
                        _ = signal::ctrl_c() => token_clone.cancel(),
                        _ = signal::unix::signal(signal::unix::SignalKind::terminate())
                            .ok()
                            .map(|mut s| async move { s.recv().await; })
                            .unwrap_or_else(|| std::future::pending()) => token_clone.cancel(),
                    }
                });
            })
            .map_err(|e| format!("signal-handler 线程启动失败: {}", e))?;
    }

    Ok(())
}

/// 外部主动下发停机指令
/// 适用场景：Tauri窗口关闭事件、上层管理指令触发进程退出，无已注册令牌时静默执行不引发panic
pub fn trigger_shutdown() {
    if let Some(token) = GLOBAL_CANCEL_TOKEN.get() {
        token.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证令牌注册流程与手动触发停止的逻辑有效性
    #[test]
    fn test_register_and_trigger() {
        let token = CancellationToken::new();
        register_shutdown_token(token.clone()).expect("注册应成功");

        trigger_shutdown();

        assert!(token.is_cancelled());
    }

    /// 验证未预先注册令牌时调用停机接口的程序鲁棒性
    #[test]
    fn test_trigger_without_register() {
        trigger_shutdown();
    }
}