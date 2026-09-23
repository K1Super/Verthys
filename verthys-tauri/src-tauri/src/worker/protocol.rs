//! worker/protocol.rs — Actor 协议数据结构、常量与进度类型
//!
//! 本模块集中定义：
//!   - 各类超时常量（IPC、就绪检测、优雅退出、stderr 排空等）
//!   - 解锁进度结构体（与 worker runtime.rs 中 C 回调写入的 JSON 行对齐）
//!   - Actor 请求枚举（ActorRequest）与解锁进度流常量
//!
//! 这些类型被 worker/ 下其他模块共享引用，作为 Actor 协议的「公共词汇表」。

use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::sync::{mpsc, oneshot};

/// 默认 IPC 超时（15 秒）。超时后返回错误，避免前端 30s 挂起。
pub const DEFAULT_IPC_TIMEOUT: Duration = Duration::from_secs(15);

/// 就绪检测超时（5 秒）。worker_init 后等待 worker 主动推送的 ready 信号。
pub const READY_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Actor 优雅退出超时：发送 shutdown 后等待子进程自行退出的时间。
/// 超时后强制 child.kill() + child.wait()。
pub const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Drop 时等待 Actor 任务结束的总超时（5 秒）。
/// 防止进程退出时被 Actor 任务卡死。
pub const DROP_ACTOR_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// stderr 任务在 Actor 退出后的额外等待超时（500ms）。
/// 确保最后的 stderr 输出被消费。
pub const STDERR_DRAIN_FINAL_TIMEOUT: Duration = Duration::from_millis(500);

/// stderr 环形缓冲区大小（保留最近 N 行用于诊断错误信息）。
pub const STDERR_RING_SIZE: usize = 32;

/// stderr 诊断片段最大长度（截断过长内容，注意 UTF-8 字符边界）。
pub const STDERR_DIAG_MAX_LEN: usize = 2048;

/// IPC 管道单行字节上限（16MB）
///
/// worker 响应（含记录 base64）与进度行远小于此值。
/// 超限即协议异常（对端被攻破或协议失步），读取方必须断开并报错。
/// 读取全程经 bounded_read_line，行缓冲增长被约束在上限之内。
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// 带限行读取错误
#[derive(Debug)]
pub enum BoundedLineError {
    /// 底层 I/O 错误
    Io(std::io::Error),
    /// 单行超过字节上限：该行剩余内容已被丢弃至行尾
    TooLong { limit: usize },
}

impl std::fmt::Display for BoundedLineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundedLineError::Io(e) => write!(f, "read pipe: {}", e),
            BoundedLineError::TooLong { limit } => {
                write!(f, "pipe line exceeds {} bytes", limit)
            }
        }
    }
}

impl std::error::Error for BoundedLineError {}

/// 带限行读取：单行字节数超过 max 时进入丢弃模式，
/// 吞掉该行剩余字节后返回 Err(TooLong)，行缓冲增长被约束在 max 以内。
///
/// 返回 Ok(Some(n)) 表示读入一行（已去掉行尾 \n/\r\n），n 为行字节数；
/// Ok(None) 表示 EOF 且本轮无新字节。
pub(crate) async fn bounded_read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut String,
    max: usize,
) -> Result<Option<usize>, BoundedLineError> {
    buf.clear();
    let mut buffered = 0usize; /* 本行已拷贝字节数 */
    let mut overflowed = false;
    loop {
        let available = reader.fill_buf().await.map_err(BoundedLineError::Io)?;
        if available.is_empty() {
            return Ok(if buffered == 0 && !overflowed {
                None
            } else {
                Some(buffered)
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
                return Err(BoundedLineError::TooLong { limit: max });
            }
            // 去掉行尾换行（\n 或 \r\n）
            if buf.ends_with('\n') {
                buf.pop();
                if buf.ends_with('\r') {
                    buf.pop();
                }
            }
            // 返回剥离换行后的行字节数（buf 已含精确内容）
            return Ok(Some(buf.len()));
        }
        // 无换行且已超限：继续丢弃本行剩余字节
    }
}

/* ------------------------------------------------------------------ *
 * 解锁进度数据结构（与 worker runtime.rs 中 unlock_progress_cb
 *   写入的 JSON 行对齐，与 verthys.h 中 VerthysUnlockProgress 公共结构对齐）
 *
 * 用于 send_json_with_unlock_progress 解析进度行并转发给前端。
 * ------------------------------------------------------------------ */

/// 解锁进度信息（从 worker 的 unlock_progress JSON 行反序列化）
///
/// 字段严格对齐 verthys.h 中 VerthysUnlockProgress 公共结构：
///   - stage：VerthysUnlockStage 枚举值（1=读超级块 2=Argon2开始 3=Argon2完成
///     4=缓存检查 5=索引解密 6=B+树完成 7=摘要完成 8=Merkle完成）
///   - percent：0~100 累计进度百分比
///   - elapsed_ms：自解锁开始累计耗时（毫秒）
///   - message：UTF-8 阶段描述（供前端直接展示）
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct UnlockProgress {
    pub stage: u32,
    pub percent: u32,
    pub elapsed_ms: u64,
    pub message: String,
}

/* ------------------------------------------------------------------ *
 * Actor 请求/响应协议                                                  *
 *                                                                    *
 * 主线程通过 mpsc::Sender<ActorRequest> 向 Actor 发送请求，           *
 * Actor 处理完毕后通过 oneshot::Sender 返回结果。                     *
 * 所有管道操作在 Actor 单任务内串行，无锁。                            *
 * ------------------------------------------------------------------ */

/// Actor 请求枚举
///
/// 每个变体对应一种 WorkerSession 公共方法。
/// 携带 oneshot::Sender 用于异步返回结果。
pub(crate) enum ActorRequest {
    /// 普通 IPC 请求（send_json / send_json_with_timeout）
    Send {
        json: String,
        timeout: Duration,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// 解锁流式请求（send_json_with_unlock_progress）
    SendStreamingUnlock {
        json: String,
        reply: oneshot::Sender<Result<String, String>>,
        progress_tx: mpsc::Sender<UnlockProgress>,
    },
    /// 就绪检测（wait_for_ready_signal）
    WaitReady {
        timeout: Duration,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// 显式关闭请求（保留用于未来协议扩展，当前通过 drop Sender 触发关闭）
    #[allow(dead_code)]
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

/// 解锁进度流的 JSON 行 op 字段值（worker C 回调写入的进度行标识）
pub(crate) const UNLOCK_PROGRESS_OP: &str = "unlock_progress";

/// 解锁进度感知空闲超时（每收到一条进度行重置）
///
/// Argon2id SECURE 预设（64MiB/3/1）单次派生 6~15s，期间无进度事件，
/// 60 秒裕量覆盖极端情况（低端 CPU + 杀毒扫描），避免误判超时。
pub(crate) const UNLOCK_PROGRESS_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// 验证解锁进度流常量
    #[test]
    fn test_unlock_progress_constants() {
        assert_eq!(UNLOCK_PROGRESS_OP, "unlock_progress");
        assert_eq!(
            UNLOCK_PROGRESS_IDLE_TIMEOUT,
            Duration::from_secs(60)
        );
    }

    /// 验证 UnlockProgress 反序列化
    #[test]
    fn test_unlock_progress_deserialize() {
        let json = r#"{
            "stage": 3,
            "percent": 45,
            "elapsed_ms": 8000,
            "message": "Argon2id 派生完成"
        }"#;
        let p: UnlockProgress = serde_json::from_str(json).unwrap();
        assert_eq!(p.stage, 3);
        assert_eq!(p.percent, 45);
        assert_eq!(p.elapsed_ms, 8000);
        assert_eq!(p.message, "Argon2id 派生完成");
    }

    /// 验证 ActorRequest 枚举通道通信
    ///
    /// 此测试验证 mpsc + oneshot 模式的请求-响应机制，
    /// 不涉及真实子进程。
    #[tokio::test(flavor = "multi_thread")]
    async fn test_actor_request_channel_pattern() {
        let (request_tx, mut request_rx) = mpsc::channel::<ActorRequest>(8);
        let (reply_tx, reply_rx) = oneshot::channel();

        // 发送请求
        request_tx
            .send(ActorRequest::Send {
                json: r#"{"op":"ping"}"#.to_string(),
                timeout: Duration::from_secs(1),
                reply: reply_tx,
            })
            .await
            .unwrap();

        // Actor 端接收并回复
        let req = request_rx.recv().await.unwrap();
        match req {
            ActorRequest::Send { json, timeout, reply } => {
                assert_eq!(json, r#"{"op":"ping"}"#);
                assert_eq!(timeout, Duration::from_secs(1));
                let _ = reply.send(Ok(r#"{"ok":true,"op":"pong"}"#.to_string()));
            }
            _ => panic!("期望 ActorRequest::Send"),
        }

        // 调用端接收回复
        let result = reply_rx.await.unwrap().unwrap();
        assert_eq!(result, r#"{"ok":true,"op":"pong"}"#);
    }

    /// 验证通道关闭后 send 返回错误
    #[tokio::test(flavor = "multi_thread")]
    async fn test_channel_close_detection() {
        let (request_tx, request_rx) = mpsc::channel::<ActorRequest>(8);

        // drop 接收端，模拟 Actor 退出
        drop(request_rx);

        // 发送应失败
        let (reply_tx, _reply_rx) = oneshot::channel();
        let result = request_tx
            .send(ActorRequest::Send {
                json: "{}".to_string(),
                timeout: Duration::from_secs(1),
                reply: reply_tx,
            })
            .await;
        assert!(result.is_err(), "通道关闭后 send 应失败");
    }

    /// 验证通过 drop Sender 关闭通道的语义
    ///
    /// tokio 1.52 的 mpsc::Sender 没有 close_channel 方法，
    /// 通过 drop 所有 Sender 克隆来关闭通道。
    #[tokio::test(flavor = "multi_thread")]
    async fn test_close_channel_by_drop() {
        let (request_tx, mut request_rx) = mpsc::channel::<ActorRequest>(8);

        // drop Sender，关闭通道
        drop(request_tx);

        // 接收端应收到 None（通道关闭）
        let result = request_rx.recv().await;
        assert!(result.is_none(), "drop Sender 后 recv 应返回 None");
    }

    /// 验证 is_closed 检测
    #[tokio::test(flavor = "multi_thread")]
    async fn test_is_closed() {
        let (request_tx, request_rx) = mpsc::channel::<ActorRequest>(8);

        // 接收端存活，is_closed 应为 false
        assert!(!request_tx.is_closed());

        // drop 接收端
        drop(request_rx);

        // 接收端已 drop，is_closed 应为 true
        assert!(request_tx.is_closed());
    }

    /* ---- bounded_read_line 带限读取测试（小上限 16 验证契约） ---- */

    fn cursor_reader(data: Vec<u8>) -> tokio::io::BufReader<std::io::Cursor<Vec<u8>>> {
        tokio::io::BufReader::new(std::io::Cursor::new(data))
    }

    #[tokio::test]
    async fn bounded_read_short_lines_and_crlf() {
        let mut r = cursor_reader(b"ping\nunlock\r\nok".to_vec());
        let mut buf = String::new();
        assert_eq!(bounded_read_line(&mut r, &mut buf, 64).await.unwrap(), Some(4));
        assert_eq!(buf, "ping");
        assert_eq!(bounded_read_line(&mut r, &mut buf, 64).await.unwrap(), Some(6));
        assert_eq!(buf, "unlock"); // CRLF 剥离
        // EOF 前无换行残余按最后一行返回，随后 EOF
        assert_eq!(bounded_read_line(&mut r, &mut buf, 64).await.unwrap(), Some(2));
        assert_eq!(buf, "ok");
        assert_eq!(bounded_read_line(&mut r, &mut buf, 64).await.unwrap(), None);
    }

    #[tokio::test]
    async fn bounded_read_too_long_discards_rest_of_line() {
        let mut data = vec![b'A'; 40];
        data.extend_from_slice(b"\nnext\n");
        let mut r = cursor_reader(data);
        let mut buf = String::new();
        match bounded_read_line(&mut r, &mut buf, 16).await {
            Err(BoundedLineError::TooLong { limit }) => assert_eq!(limit, 16),
            other => panic!("应为 TooLong，实为: {:?}", other.map(|x| x.is_some())),
        }
        // 超长行已被完整丢弃：下一行必须读到 next
        assert_eq!(bounded_read_line(&mut r, &mut buf, 16).await.unwrap(), Some(4));
        assert_eq!(buf, "next");
    }

    #[tokio::test]
    async fn bounded_read_stream_window_memory_stable() {
        // 64 字节 duplex 窗口：读端 fill_buf 每次最多拿到窗口大小，
        // 超长流被分块丢弃，行缓冲增长被约束在 max 以内
        let (mut tx, mut rx) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let chunk = vec![b'B'; 8192];
            for _ in 0..4 {
                tx.write_all(&chunk).await.unwrap();
            }
            tx.write_all(b"\nend\n").await.unwrap();
        });
        let mut reader = tokio::io::BufReader::new(&mut rx);
        let mut buf = String::new();
        match bounded_read_line(&mut reader, &mut buf, 16).await {
            Err(BoundedLineError::TooLong { .. }) => {}
            _ => panic!("长流应触发 TooLong，实为其它结果"),
        }
        // 行缓冲增长被约束：丢弃模式下 buf 从未超过上限
        assert!(buf.len() <= 16);
        bounded_read_line(&mut reader, &mut buf, 16).await.unwrap();
        assert_eq!(buf, "end");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn bounded_read_exact_limit_boundary() {
        // max=16：15 字节内容 + \n = 16 字节 → 恰好为行
        let mut r = cursor_reader(b"0123456789abcde\n".to_vec());
        let mut buf = String::new();
        assert_eq!(bounded_read_line(&mut r, &mut buf, 16).await.unwrap(), Some(15));
        assert_eq!(buf, "0123456789abcde");
        // 16 字节内容 + \n = 17 字节 → TooLong
        let mut r2 = cursor_reader(b"0123456789abcdef\n".to_vec());
        let mut buf2 = String::new();
        match bounded_read_line(&mut r2, &mut buf2, 16).await {
            Err(BoundedLineError::TooLong { .. }) => {}
            _ => panic!("超限一字节应为 TooLong"),
        }
    }
}
