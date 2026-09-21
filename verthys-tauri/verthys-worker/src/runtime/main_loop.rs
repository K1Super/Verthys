/* main_loop.rs — Worker 主运行时入口（主循环）
 *
 * 职责：
 *   1. 加载 verthys.dll（Worker::new）
 *   2. 发送就绪信号（stdout JSON）
 *   3. 主循环：stdin 读取 → handle_request → stdout 输出
 *
 * 架构定位：controller 层派发入口
 *   - 由 main.rs（入口）调用，dll_path 由入口解析后传入
 *   - Worker::new 加载 DLL（service 层）
 *   - handle_request 派发到具体操作处理器（controller 层）
 *   - 返回退出码给入口，由入口决定 std::process::exit
 *
 * 依赖：std::io、crate::log、worker::Worker、dispatch::handle_request、
 *       protocol::{Request, Response}、serde_json。
 */

use std::io::{self, BufRead, Write};

use zeroize::Zeroizing;

use crate::log::{diag, init_diag};
use crate::runtime::worker::Worker;
use crate::runtime::dispatch::handle_request;
use crate::runtime::protocol::{Request, Response};

/// Worker 主运行时入口
///
/// 职责：
///   1. 加载 verthys.dll（libloading 动态加载）
///   2. 发送就绪信号（stdout JSON）
///   3. 主循环：stdin 读取 → handle_request → stdout 输出
///
/// 返回退出码：0 = 正常退出（stdin 关闭），1 = 初始化失败
pub fn run(dll_path: &str) -> i32 {
    let mut worker = match Worker::new(dll_path) {
        Ok(w) => w,
        Err(e) => {
            init_diag!("worker init failed: {}", e);
            return 1;
        }
    };

    let stdin = io::stdin();

    // ★ 企业级修复（D-STDOUT-DEADLOCK）：不再跨 handle_request 持有 stdout 锁
    //
    // 原实现：`let mut stdout_handle = stdout.lock();` 在整个主循环期间持有 stdout 锁。
    // 当 handle_request 调用 call_unlock → Verthys_Unlock（阻塞 FFI）时，主线程被阻塞
    // 但仍持有 stdout 锁。C 层进度消费线程（verthys_progress_consumer_thread）调用
    // unlock_progress_cb → io::stdout().lock() 尝试获取同一锁 → 永久阻塞。
    // 结果：进度回调全部死锁，父进程 60 秒空闲超时后报错退出。
    //
    // 修复：每次写入 stdout 时临时获取锁，写入+flush 后立即释放。
    // handle_request（可能阻塞在 FFI）执行期间不持有 stdout 锁，
    // 进度消费线程可正常获取锁写入进度行。
    //
    // 线程安全：io::stdout() 内部 ReentrantMutex 保证多次 lock() 调用串行化，
    // 主线程与消费线程的 stdout 写入不会交错。

    // 主动发送就绪信号：告诉父进程 DLL 已加载、Verthys_Init 成功、主循环即将开始
    // 父进程的 wait_for_ready_signal 会读取此信号（而非发送 ping），避免协议失步
    {
        let ready = r#"{"ok":true,"op":"ready"}"#;
        init_diag!("[worker] 发送就绪信号: {}", ready);
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        if let Err(e) = writeln!(lock, "{}", ready) {
            init_diag!("[worker] 写就绪信号失败: {}", e);
            return 1;
        }
        if let Err(e) = lock.flush() {
            init_diag!("[worker] flush 就绪信号失败: {}", e);
            return 1;
        }
        drop(lock);
        init_diag!("[worker] 就绪信号已发送，进入主循环");
    }

    for line in stdin.lock().lines() {
        // ★ 口令链零化：line 携带完整请求 JSON（含明文口令），
        //   包装进 Zeroizing 保证每轮迭代结束时 volatile 清零堆缓冲，
        //   口令明文不在主循环缓冲中跨请求驻留。
        let line = match line {
            Ok(l) => Zeroizing::new(l),
            Err(e) => {
                diag!("[worker] stdin 读取错误: {}", e);
                let _ = &e; /* release 下 diag! 为空操作，显式消费 e */
                break;
            }
        };
        if line.is_empty() {
            continue;
        }

        // 跳过 UTF-8 BOM (EF BB BF)，某些父进程可能在首次写入时附加 BOM
        // 剥离产生的副本同样进入 Zeroizing，原缓冲随即清零
        let line = match line.strip_prefix('\u{FEFF}') {
            Some(stripped) => Zeroizing::new(stripped.to_string()),
            None => line,
        };

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response {
                    ok: false,
                    op: "parse".into(),
                    error: Some(format!("json parse: {}", e)),
                    ..Response::ok("parse")
                };
                let json = serde_json::to_string(&resp).unwrap();
                let stdout = io::stdout();
                let mut lock = stdout.lock();
                if let Err(e) = writeln!(lock, "{}", json) {
                    diag!("[worker] 写响应失败(parse): {}", e);
                    let _ = &e; /* release 下 diag! 为空操作，显式消费 e */
                }
                let _ = lock.flush();
                continue;
            }
        };

        // get_record 返回 NOTFOUND 时，枚举探测应停止
        let resp = handle_request(&mut worker, &req);
        let json = serde_json::to_string(&resp).unwrap();
        diag!("[worker] 发送响应: op={} ok={} bytes={}", resp.op, resp.ok, json.len());

        // ★ 企业级修复（D-PROGRESS-DRAIN）：进度排空保障
        //
        // unlock 操作使用 C 层进度环形缓冲区 + 独立消费线程异步推送进度。
        // FFI 调用返回后，消费线程可能仍有残留进度条目未写入 stdout。
        // 若主线程立即写入最终响应，残留进度行可能在最终响应之后到达，
        // 污染下一个请求的 IPC 协议（被误读为下一请求的响应）。
        //
        // 修复：对使用进度回调的操作（unlock），FFI 返回后短暂等待（10ms），
        // 让消费线程排空环形缓冲区（32 槽，消费线程 1ms 间隔轮询，10ms 足以排空）。
        // 然后获取 stdout 锁写入最终响应，确保进度行全部在最终响应之前。
        let needs_drain = req.op.as_str() == "unlock";
        if needs_drain {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let stdout = io::stdout();
        let mut lock = stdout.lock();
        if let Err(e) = writeln!(lock, "{}", json) {
            diag!("[worker] 写响应失败: {}", e);
            let _ = &e; /* release 下 diag! 为空操作，显式消费 e */
            break;
        }
        if let Err(e) = lock.flush() {
            diag!("[worker] flush 失败: {}", e);
            let _ = &e; /* release 下 diag! 为空操作，显式消费 e */
            break;
        }
        drop(lock);
    }

    // stdin 关闭 → 主进程已退出或主动 kill → Drop 自动清理
    0
}
