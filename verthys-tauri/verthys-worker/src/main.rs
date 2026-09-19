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

// 从日志基础设施层导入诊断宏（入口文件零直接 eprintln!/println!）
use crate::log::init_diag;

fn main() {
    // Step 1: 环境初始化 — 安装崩溃诊断（panic hook + Windows 异常过滤）
    // 实现由 log.rs（日志基础设施层）提供，入口仅调用安装函数
    log::install_panic_hook();
    log::install_exception_filter();

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
