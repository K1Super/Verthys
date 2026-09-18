// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/*
 * main.rs — Tauri 主进程入口文件
 *
 *    "入口文件单一职责约束（不可突破）"
 *
 * 入口文件仅允许的 6 项职责：
 *   1. 全局执行环境初始化（设置时区、字符集、堆分配器）
 *   2. 解析并校验命令行参数与配置文件
 *   3. 创建进程级别的上下文容器
 *   4. 创建本进程私有的核心资源句柄
 *   5. 调用对应的控制器入口方法
 *   6. 注册全局异常兜底钩子
 *
 * 严格禁止：在入口函数内编写加解密、文件I/O、网络通信、数据解析转换等具体算法实现
 *
 * 第 15 章 — 方案落地：
 *   - 15.1: 删除 LOCALAPPDATA/APPDATA set_var，改用 Tauri app_data_dir + 受信 --data-dir
 *   - 15.2: current_exe().parent() 取代 current_dir()
 *   - 15.3: portable_mode Cargo feature + 删除 VERTHYS_SANDBOX_REDIRECT 读取
 *   - 15.4: --mode worker|ui|inspector 派发
 *   - 15.5: 第一行安装 install_minimal panic hook
 *   - 15.6: run() 前打开 stderr 早期日志
 *   - 15.7: 除预定义 IPC 管道名外不读用户可控环境变量
 */

fn main() {
    // ===== 第 15.5 项：main 第一行安装最小化 panic hook =====
    // 在任何其他代码执行前注册，确保从进程启动第一微秒起崩溃均可捕获。
    // 此 hook 仅调用 OutputDebugString + stderr，不依赖日志系统。
    verthys_tauri_lib::middleware::panic_hook::install_minimal();

    // ===== 第 15.6 项：早期 stderr 日志（run() 前打开） =====
    // 记录 PID/命令行/工作目录/模式，为排错提供早期可见性。
    // 此通道随后由库内日志系统接管（upgrade 后）。
    let args: Vec<String> = std::env::args().collect();
    let pid = std::process::id();
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());

    // 早期日志：仅写 stderr（debug 模式下可见，release GUI 模式下不可见但不影响）
    // 注意：第 15.7 项禁止读取用户可控环境变量，此处仅记录已获取的信息
    eprintln!(
        "[VERTHYS] early-entry pid={} exe={} cwd={} args={:?}",
        pid, exe, cwd, args
    );

    // ===== 第 15.4 项：解析 --mode 参数，派发到对应入口 =====
    // 严格遵循单一职责模板：入口层根据模式调用不同的库入口函数。
    // Worker 模式跳过 WebView 初始化，仅分配必要的 IPC 资源，缩小受攻击面。
    let mode = parse_mode_from_args(&args);

    // ===== 第 15.1-15.3 项：已删除 LOCALAPPDATA/APPDATA set_var =====
    // 数据目录解析由 lib.rs 内的 AppPaths::resolve() 完成：
    //   1. --data-dir 命令行参数（受信，已校验绝对路径）
    //   2. portable_mode Cargo feature → <exe_dir>/data
    //   3. SHGetKnownFolderPath(FOLDERID_LocalAppData) → <LocalAppData>/com.verthys.app
    //   4. <exe_dir>/data 兜底

    // ===== 第 5 项：根据运行模式调用对应的控制器入口方法，移交控制权 =====
    match mode {
        verthys_tauri_lib::middleware::context::ProcessMode::MainUi => {
            verthys_tauri_lib::run_ui();
        }
        verthys_tauri_lib::middleware::context::ProcessMode::SecureWorker => {
            verthys_tauri_lib::run_worker();
        }
        verthys_tauri_lib::middleware::context::ProcessMode::Inspector => {
            verthys_tauri_lib::run_inspector();
        }
    }
}

/// 从命令行参数解析进程模式（第 15.4 项）
///
/// 简化解析：仅查找 --mode 参数。
/// 完整配置解析（含 --data-dir 等）在 lib.rs run_ui/run_worker 内通过 parse_config 完成。
///
/// 注意：此处不调用 parse_config 以避免在 main.rs 内执行复杂逻辑
///       （入口文件单一职责约束）。
fn parse_mode_from_args(args: &[String]) -> verthys_tauri_lib::middleware::context::ProcessMode {
    use verthys_tauri_lib::middleware::context::ProcessMode;

    let mut i = 1; // 跳过程序名
    while i < args.len() {
        if args[i] == "--mode" {
            if i + 1 < args.len() {
                return ProcessMode::from_str(&args[i + 1]);
            }
        }
        i += 1;
    }
    ProcessMode::MainUi // 默认 UI 模式
}
