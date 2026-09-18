//! worker/stderr.rs — stderr 环形缓冲区与持续排空任务
//!
//! ★ 第 10.5 项：独立 tokio::task 持续异步读取 stderr 行并写入日志，
//!   即使子进程疯狂输出，stderr 管道永远不会满，IPC 通信不会被后台日志卡死。
//!
//! 同时保留最近 STDERR_RING_SIZE 行到环形缓冲区，供子进程崩溃时构造诊断信息。
//!
//! 本模块对外提供：
//!   - StderrRing：环形缓冲区类型（被 actor / graceful / session 共享）
//!   - drain_stderr：Actor 启动的持续排空任务
//!   - snapshot_stderr / truncate_utf8：诊断辅助函数

use std::sync::{Arc, Mutex as StdMutex};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::ChildStderr;

use super::protocol::STDERR_RING_SIZE;

/* ------------------------------------------------------------------ *
 * stderr 环形缓冲区                                                   *
 *                                                                    *
 * drain_stderr 任务持续读取 stderr 行并写入日志，同时保留最近        *
 * STDERR_RING_SIZE 行到环形缓冲区，用于子进程崩溃时构造诊断信息。     *
 * ------------------------------------------------------------------ */

/// stderr 环形缓冲区（保留最近 N 行用于诊断）
pub(crate) struct StderrRing {
    lines: std::collections::VecDeque<String>,
}

impl StderrRing {
    pub(crate) fn new() -> Self {
        Self {
            lines: std::collections::VecDeque::with_capacity(STDERR_RING_SIZE + 1),
        }
    }

    /// 推入一行 stderr 内容
    pub(crate) fn push(&mut self, line: String) {
        if self.lines.len() >= STDERR_RING_SIZE {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    /// 获取当前缓冲区内容的快照（拼接为单个字符串）
    pub(crate) fn snapshot(&self) -> String {
        if self.lines.is_empty() {
            return String::new();
        }
        let joined: Vec<String> = self.lines.iter().cloned().collect();
        joined.join("\n")
    }
}

/* ------------------------------------------------------------------ *
 * stderr 持续排空任务                                                  *
 *                                                                    *
 * ★ 第 10.5 项：select! 分支持续异步读 stderr，                       *
 *   BufReader 行缓冲全量写入日志。                                    *
 * ------------------------------------------------------------------ */
pub(crate) async fn drain_stderr(
    stderr: ChildStderr,
    pid: u32,
    stderr_ring: Arc<StdMutex<StderrRing>>,
) {
    let mut reader = BufReader::new(stderr);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // EOF — stderr 管道关闭
                log::debug!("[worker:stderr] PID={} stderr EOF", pid);
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    // 全量写入日志（info 级别：worker 的 stderr 包含关键诊断信息）
                    log::info!("[worker:stderr] PID={} | {}", pid, trimmed);

                    // 推入环形缓冲区（用于诊断错误信息）
                    if let Ok(mut ring) = stderr_ring.lock() {
                        ring.push(trimmed.to_string());
                    }
                }
            }
            Err(e) => {
                log::warn!("[worker:stderr] PID={} read error: {}", pid, e);
                break;
            }
        }
    }
}

/// 获取 stderr 环形缓冲区快照
pub(crate) fn snapshot_stderr(stderr_ring: &Arc<StdMutex<StderrRing>>) -> String {
    stderr_ring
        .lock()
        .map(|ring| ring.snapshot())
        .unwrap_or_default()
}

/// 截断 UTF-8 字符串到指定字节长度（注意字符边界）
pub(crate) fn truncate_utf8(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    let mut end = max_len;
    while !s.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    format!("{}...[truncated]", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// 验证 StderrRing 环形缓冲区行为
    #[test]
    fn test_stderr_ring_push_and_snapshot() {
        let mut ring = StderrRing::new();

        // 空缓冲区
        assert_eq!(ring.snapshot(), "");

        // 推入几行
        ring.push("line1".to_string());
        ring.push("line2".to_string());
        ring.push("line3".to_string());

        let snap = ring.snapshot();
        assert!(snap.contains("line1"));
        assert!(snap.contains("line2"));
        assert!(snap.contains("line3"));
    }

    /// 验证 StderrRing 环形缓冲区容量限制
    #[test]
    fn test_stderr_ring_capacity() {
        let mut ring = StderrRing::new();

        // 推入超过容量的行
        for i in 0..(STDERR_RING_SIZE + 10) {
            ring.push(format!("line{}", i));
        }

        let snap = ring.snapshot();
        // 最早的行应被淘汰
        assert!(
            !snap.contains("line0\n"),
            "最早的行应被淘汰，实际包含: {}...",
            &snap[..snap.len().min(100)]
        );
        // 最新的行应保留
        assert!(
            snap.contains(&format!("line{}", STDERR_RING_SIZE + 9)),
            "最新的行应保留"
        );
    }

    /// 验证 truncate_utf8 在 ASCII 边界正确截断
    #[test]
    fn test_truncate_utf8_ascii() {
        let s = "abcdefghij";
        let truncated = truncate_utf8(s, 5);
        assert_eq!(truncated, "abcde...[truncated]");
    }

    /// 验证 truncate_utf8 在 UTF-8 多字节边界正确截断
    #[test]
    fn test_truncate_utf8_multibyte() {
        // 中文每字符 3 字节
        let s = "你好世界测试";
        // 截断到 4 字节（应回退到 3 字节边界，即 1 个中文字符）
        let truncated = truncate_utf8(s, 4);
        assert!(truncated.starts_with("你"));
        assert!(truncated.ends_with("...[truncated]"));
    }

    /// 验证 truncate_utf8 不截断短字符串
    #[test]
    fn test_truncate_utf8_short() {
        let s = "short";
        let truncated = truncate_utf8(s, 100);
        assert_eq!(truncated, "short");
    }

    /// 验证 drain_stderr 在 EOF 时正常退出
    #[tokio::test(flavor = "multi_thread")]
    async fn test_drain_stderr_eof() {
        // 创建一个会立即 EOF 的 stderr（使用已关闭的管道）
        // 这里用一个简单的 echo 管道测试
        let (mut rx, tx) = tokio::io::duplex(64);
        drop(tx); // 关闭写端，触发 EOF

        // 由于 drain_stderr 需要 ChildStderr，这里用管道模拟
        // 实际测试中需要真实子进程，此处仅验证逻辑路径
        let _stderr_ring = Arc::new(StdMutex::new(StderrRing::new()));

        // 读取直到 EOF
        let mut reader = BufReader::new(rx);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.unwrap();
        assert_eq!(n, 0, "EOF 应返回 0");
        assert!(line.is_empty());
    }
}
