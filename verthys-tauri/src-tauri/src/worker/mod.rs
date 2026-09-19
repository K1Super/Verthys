//! worker/ — 子进程会话管理（异步 Actor 模型）
//!
//!    "用异步 Actor 彻底消灭锁和阻塞"
//!
//! 本目录由原 `worker.rs`（1964 行）拆分为 7 个模块，零行为变更。
//!
//! 设计要点：
//!   1. 异步 Actor 消灭锁与阻塞：
//!       - WorkerSession 内部启动专用 tokio::task（Actor）
//!       - tokio::process::Command 创建子进程，获取 ChildStdout/ChildStdin/ChildStderr 异步句柄
//!       - Actor 通过 tokio::sync::mpsc<Request> 接收请求（每请求携带 oneshot 回复通道）
//!       - tokio::select! 同时等待：新请求 / stdout 可读 / 超时 / stderr 可读
//!       - 所有管道操作单任务内串行，无锁（死锁根本不可能发生）
//!
//!   2. 异步超时替代轮询循环：
//!       - tokio::time::timeout 包裹 read_line()
//!       - 进度感知超时用 select! 循环每条进度行重置超时
//!       - 删除 PeekNamedPipe + thread::sleep(50ms)
//!
//!   3. 只读诊断惰性清理：
//!       - 子进程退出/管道断裂时，Actor 仅记录退出状态 + stderr 尾部构造错误
//!       - stdin/stdout/stderr 句柄保持原样至 Actor 销毁
//!       - 析构时 child.kill() + child.wait()
//!       - 删除 diagnose_crash 清空句柄副作用
//!
//!   4. 流式响应处理：
//!       - 内部 handle_streaming_unlock_send 处理解锁进度流
//!       - 公共 API 保留 send_json_with_unlock_progress 兼容签名
//!
//!   5. 彻底杜绝 stderr 管道阻塞：
//!       - Actor 在独立 tokio::task 中持续异步读取 stderr
//!       - BufReader 行缓冲全量写入日志
//!       - 即使子进程疯狂输出，管道永远不会满
//!
//!   6. 优雅退出与强制终止结合：
//!       - stdin 发 {"op":"shutdown"} 命令
//!       - 等待 1 秒让子进程自行清理
//!       - 超时 child.kill() + await
//!       - 主线程 drop Sender，Actor 侦测通道关闭自动触发退出序列
//!
//! 模块拆分：
//!   - protocol: 协议数据结构、常量、ActorRequest 与解锁进度流常量
//!   - stderr:   stderr 环形缓冲区与持续排空任务
//!   - platform: 平台特定代码（Windows Job Object + 孤儿进程清理）
//!   - graceful: 优雅退出与诊断
//!   - actor:    Actor 主循环与请求处理
//!   - session:  WorkerSession 公共 API（保留兼容签名）
//!
//! 公共 API 兼容策略：
//!   保留 spawn/send_json/send_json_with_timeout/
//!   send_json_with_unlock_progress/wait_for_ready_signal/pid/elapsed_secs/
//!   is_alive/kill/Clone/Drop 签名，内部通过 Handle::block_on + block_in_place
//!   包装为同步返回，使 state.rs 与控制器无需立即改签名即可编译。
//!
//! 安全：
//!   - 主进程永远不加载 DLL，不持有 VerthysHandle
//!   - 子进程退出即销毁所有密钥与句柄
//!   - kill_on_drop(true) 兜底：Actor 任务异常终止时子进程不会成为孤儿

pub mod actor;
pub mod graceful;
pub mod platform;
pub mod protocol;
pub mod session;
pub mod stderr;

pub use platform::kill_orphan_workers;
pub use protocol::UnlockProgress;
pub use session::WorkerSession;
