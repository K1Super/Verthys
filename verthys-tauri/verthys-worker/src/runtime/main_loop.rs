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

/// stdin 单行字节上限（16MB）
///
/// 单个请求 JSON（含口令与记录数据 base64）远小于此值；
/// 超限即协议异常（对端被攻破或数据损坏），按 fail-safe 断开。
/// 读取路径全程经 read_line_bounded，行缓冲不会无界增长。
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// 带限行读取结果
enum BoundedLine {
    /// 完整读入一行（已去掉行尾换行符）
    Line,
    /// EOF 且本轮无新字节
    Eof,
    /// 单行超过字节上限：该行剩余内容已被丢弃至行尾
    TooLong { limit: usize },
}

/// 带限行读取：单行字节数超过 max 时进入丢弃模式，
/// 吞掉该行剩余字节后返回 TooLong，行缓冲增长被约束在 max 以内。
fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    buf: &mut String,
    max: usize,
) -> io::Result<BoundedLine> {
    buf.clear();
    let mut buffered = 0usize; /* 本行已拷贝字节数 */
    let mut overflowed = false;
    loop {
        let available = match reader.fill_buf() {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(if buffered == 0 && !overflowed {
                BoundedLine::Eof
            } else {
                BoundedLine::Line
            });
        }
        let newline = available.iter().position(|&b| b == b'\n');
        // 本次消费字节数：到换行（含）或无换行时整块
        let take = match newline {
            Some(pos) => pos + 1,
            None => available.len(),
        };
        if !overflowed {
            let room = max.saturating_sub(buffered);
            let copy = take.min(room);
            if copy > 0 {
                buf.push_str(&String::from_utf8_lossy(&available[..copy]));
                buffered += copy;
            }
            if take > room {
                overflowed = true;
            }
        }
        reader.consume(take);
        if newline.is_some() {
            if overflowed {
                return Ok(BoundedLine::TooLong { limit: max });
            }
            // 去掉行尾换行（\n 或 \r\n）
            if buf.ends_with('\n') {
                buf.pop();
                if buf.ends_with('\r') {
                    buf.pop();
                }
            }
            return Ok(BoundedLine::Line);
        }
        // 无换行且已超限：继续丢弃本行剩余字节
    }
}

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

    // 修复（D-STDOUT-DEADLOCK）：不再跨 handle_request 持有 stdout 锁
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

    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    let mut raw = String::new();

    loop {
        // ★ panic 兜底第三层：任何线程/回调捕获到 panic 都会置位进程级标记，
        //   主循环每轮检查，置位后立即走安全退出（Drop 自动 Lock → Deinit →
        //   清零 GMK），绝不带着已损坏的内部状态继续处理敏感数据。
        if crate::log::panic_flag_is_set() {
            init_diag!("[worker] 检测到 panic 标记已置位，主循环安全退出");
            break;
        }
        raw.clear();
        // 带限行读取（替代 lines()）：超长无换行流会令行缓冲无界增长，
        //   上限 MAX_LINE_BYTES；超限时剩余字节被丢弃至行尾，返回 TooLong。
        let outcome = match read_line_bounded(&mut stdin_lock, &mut raw, MAX_LINE_BYTES) {
            Ok(o) => o,
            Err(e) => {
                diag!("[worker] stdin 读取错误: {}", e);
                let _ = &e; /* release 下 diag! 为空操作，显式消费 e */
                break;
            }
        };
        match outcome {
            BoundedLine::Eof => break,
            BoundedLine::TooLong { limit } => {
                // 协议错误：返回结构化错误后断开（对端行为异常，fail-safe）
                // release 构建 diag! 为空操作，limit 仅用于开发诊断
                let _ = limit;
                diag!("[worker] stdin 单行超过上限（{} 字节），协议断开", limit);
                let resp = Response {
                    ok: false,
                    op: "parse".into(),
                    error: Some("line too long".into()),
                    ..Response::ok("parse")
                };
                let json = serde_json::to_string(&resp).unwrap();
                let stdout = io::stdout();
                let mut lock = stdout.lock();
                let _ = writeln!(lock, "{}", json);
                let _ = lock.flush();
                drop(lock);
                break;
            }
            BoundedLine::Line => {}
        }

        // 口令链零化：line 携带完整请求 JSON（含明文口令），
        //   包装进 Zeroizing 保证每轮迭代结束时 volatile 清零堆缓冲，
        //   口令明文不在主循环缓冲中跨请求驻留。
        //   行内容自 raw 移出，raw 于下轮迭代开头 clear。
        let line = Zeroizing::new(std::mem::take(&mut raw));
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

        // 修复（D-PROGRESS-DRAIN）：进度排空保障
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

/* ------------------------------------------------------------------ *
 * 带限行读取测试                                                      *
 *                                                                    *
 * 用小上限（16）验证三类行为：正常行、恰好边界、超限丢弃至行尾。      *
 * 残行丢弃是关键契约：TooLong 之后的下一次读取必须从下一行开始，      *
 * 否则超长行残余会污染后续请求解析。                                  *
 * ------------------------------------------------------------------ */
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_short_lines_and_crlf() {
        let mut reader = Cursor::new(b"ping\nunlock\r\n\n\xEF\xBB\xBFx\n".to_vec());
        let mut buf = String::new();
        match read_line_bounded(&mut reader, &mut buf, 64).unwrap() {
            BoundedLine::Line => assert_eq!(buf, "ping"),
            _ => panic!("应为 Line"),
        }
        match read_line_bounded(&mut reader, &mut buf, 64).unwrap() {
            BoundedLine::Line => assert_eq!(buf, "unlock"),
            _ => panic!("应为 Line（CRLF 已剥离）"),
        }
        match read_line_bounded(&mut reader, &mut buf, 64).unwrap() {
            BoundedLine::Line => assert_eq!(buf, ""),
            _ => panic!("空行应为 Line 且内容为空"),
        }
        match read_line_bounded(&mut reader, &mut buf, 64).unwrap() {
            BoundedLine::Line => assert_eq!(buf.as_bytes(), b"\xEF\xBB\xBFx"),
            _ => panic!("应为 Line"),
        }
    }

    #[test]
    fn bounded_too_long_discards_to_end_of_line() {
        // 超长行（40 字节无换行）+ 换行 + 后续正常行
        let mut data: Vec<u8> = vec![b'A'; 40];
        data.extend_from_slice(b"\nnext\n");
        let mut reader = Cursor::new(data);
        let mut buf = String::new();
        match read_line_bounded(&mut reader, &mut buf, 16).unwrap() {
            BoundedLine::TooLong { limit } => assert_eq!(limit, 16),
            _ => panic!("应为 TooLong，实为其它结果"),
        }
        // 超长行被完整丢弃：下一行必须读到 next
        match read_line_bounded(&mut reader, &mut buf, 16).unwrap() {
            BoundedLine::Line => assert_eq!(buf, "next"),
            _ => panic!("残行未被丢弃: 后续读取错误"),
        }
    }

    #[test]
    fn bounded_exact_limit_is_line_but_one_over_is_too_long() {
        // max=16：15 字节内容 + \n = 16 字节 → 恰好为 Line
        let mut reader = Cursor::new(b"0123456789abcde\n".to_vec());
        let mut buf = String::new();
        match read_line_bounded(&mut reader, &mut buf, 16).unwrap() {
            BoundedLine::Line => assert_eq!(buf, "0123456789abcde"),
            _ => panic!("恰好边界应为 Line"),
        }
        // 16 字节内容 + \n = 17 字节 → TooLong
        let mut reader2 = Cursor::new(b"0123456789abcdef\n".to_vec());
        let mut buf2 = String::new();
        match read_line_bounded(&mut reader2, &mut buf2, 16).unwrap() {
            BoundedLine::TooLong { .. } => {}
            _ => panic!("超限一字节应为 TooLong"),
        }
    }

    #[test]
    fn bounded_eof_without_newline_returns_line() {
        // 无换行的尾部数据按 read_line 语义作为最后一行返回
        let mut reader = Cursor::new(b"tail".to_vec());
        let mut buf = String::new();
        match read_line_bounded(&mut reader, &mut buf, 16).unwrap() {
            BoundedLine::Line => assert_eq!(buf, "tail"),
            _ => panic!("EOF 前无换行残余应为 Line"),
        }
        match read_line_bounded(&mut reader, &mut buf, 16).unwrap() {
            BoundedLine::Eof => {}
            _ => panic!("数据耗尽应为 Eof"),
        }
    }
}
