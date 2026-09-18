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

/* ------------------------------------------------------------------ *
 * 方案5：解锁进度数据结构（与 worker runtime.rs 中 unlock_progress_cb
 *   写入的 JSON 行对齐，与 verthys.h 中 VerthysUnlockProgress 公共结构对齐）
 *
 * 用于 send_json_with_unlock_progress 解析进度行并转发给前端。
 * ------------------------------------------------------------------ */

/// 解锁进度信息（从 worker 的 unlock_progress JSON 行反序列化）
///
/// 字段严格对齐 verthys.h 中 VerthysUnlockProgress 公共结构：
///   - stage：VerthysUnlockStage 枚举值（1=读超级块 2=Argon2开始 3=Argon2完成
///            4=缓存检查 5=索引解密 6=B+树完成 7=摘要完成 8=Merkle完成）
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
}
