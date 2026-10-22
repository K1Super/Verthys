/*
 * main.rs — verthys-worker 入口文件
 *
 * 架构定位：入口层（entry）
 *   - 仅负责：panic hook 安装、参数解析、控制器派发
 *   - 业务逻辑（DLL 加载、IPC 主循环）下沉至 runtime.rs
 *   - 日志基础设施（diag!/init_diag!）下沉至 log.rs
 *
 */

mod log;
mod runtime;
mod defense;

// 从日志基础设施层导入诊断宏（入口文件不做常规输出；
// 仅启动期致命错误在日志未初始化前直接写 stderr）
use crate::log::init_diag;

fn main() {
    /* 会话密钥必须先于任何 DLL 加载与日志初始化：缺失即失败关闭，
     * 禁止 worker 以无认证 IPC 形态运行。 */
    if let Err(e) = runtime::ipc_auth::init_from_env() {
        eprintln!("[worker] IPC 认证初始化失败: {}", e);
        std::process::exit(4);
    }

    /* 启动链最前置：先固定 System32-only DLL 搜索并预加载不依赖 Win32k 的导入，
     * 再隐藏主线程调试可见性。此步失败必须失败关闭，否则后续任何
     * mitigation 都可能建立在已被劫持的 DLL 搜索路径上。 */
    if defense::apply_early_dll_policy().is_err() {
        std::process::exit(3);
    }
    defense::hide_current_thread_from_debugger();

    // Step 1: 环境初始化 — 安装崩溃诊断（panic hook + Windows 异常过滤）
    // 实现由 log.rs（日志基础设施层）提供，入口仅调用安装函数
    log::install_panic_hook();
    log::install_exception_filter();
    // panic 清零器注册：hook 触发时对当前线程 GMK 驻留执行前置清零
    log::register_panic_wiper(runtime::wipe_thread_gmk);

    // Step 2: 参数解析 — 提取 dll_path
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        init_diag!("usage: verthys-worker <dll_path>");
        std::process::exit(1);
    }
    let dll_path = &args[1];

    // Step 3: 控制器派发 — 业务逻辑由 runtime::run 承载
    // 入口仅传递已解析的参数，不涉及 DLL 加载、stdin/stdout 循环等业务逻辑
    let exit_code = runtime::run(dll_path);
    std::process::exit(exit_code);
}
