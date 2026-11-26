/*
 * state/import_writer.rs — 照片导入单写者通道
 *
 * 职责：把「批量写入 + 会话关闭」两类存储变更收敛到唯一写者线程，
 * 避免命令线程内持会话锁 + 串行 worker IPC 的两个问题：
 *   - 阻塞的 worker IPC 占用 Tauri 异步运行时线程；
 *   - 并发变更仅靠会话互斥锁兜底，缺乏端到端超时与饥饿观察。
 *
 * 通道模型：
 *   - crossbeam bounded(WRITER_CHANNEL_CAPACITY) 队列背压，每命令携带独立 oneshot 应答；
 *   - 三层超时：命令层发送 / 应答层等待 / 写者心跳看门狗
 *     （阈值与巡检周期由 constants::import_writer 单源定义）；
 *   - 写者线程逐条命令执行时同步调用 worker 与 WAL，阻塞仅发生在本
 *     专用线程；心跳在每个命令与每条记录处理处刷新，防长批次误判。
 *
 * 重建语义（心跳超时）：
 *   只有确认旧写者线程已退出才允许重建。心跳陈旧但线程未退出时，旧线程
 *   可能仍持有导入会话锁；此时孵化新写者会永久阻塞在会话锁上（旧线程
 *   是唯一释放者），形成双写者死锁。该情形一律返回可重试的繁忙错误。
 *   确认退出后置死旧句柄并孵化新写者；旧线程已无任何未完成变更。
 *
 * 依赖方向：state → worker / repository::verthys_wal / util::contracts /
 *            constants（本模块与 import_session 同层，属会话级流程编排）
 */

mod append_chunks;
mod append_records;
mod end_progress;
mod worker_batch;
mod writer_actor;

#[cfg(test)]
mod tests;

pub use self::writer_actor::{
    ensure, spawn_watchdog, BatchAppendOutcome, ChunkAppendOutcome, EndOutcome,
    ImportWriterHandle, WriterCommand,
};
