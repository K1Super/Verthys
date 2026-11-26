//! worker/session.rs — WorkerSession 公共 API
//!
//! 对外暴露同步方法，内部由异步 Actor 单任务串行处理全部管道操作。
//!
//! 子模块职责：
//!   - heartbeat:  Windows 心跳事件、挂起检测与挂起看门狗
//!   - host_env:   开发旁路注入、测试注入与 worker 映像预注册
//!   - lifecycle:  会话结构与内部状态、启动、就绪、健康查询、终止与析构
//!   - io:         管道请求、流式进度与路径授权

mod heartbeat;
mod host_env;
mod io;
mod lifecycle;

#[cfg(test)]
mod tests;

pub use lifecycle::WorkerSession;
pub(crate) use lifecycle::{block_on_with_handle, SessionInner};
