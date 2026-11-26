//! repository/verthys_wal.rs — 照片导入 Write-Ahead Log（断点续传持久层）
//!
//! 异步批处理流水线 — 断点续传：前置 WAL + 检查点
//!
//! =============================================================================
//! 设计目标
//! =============================================================================
//! 在每条加密记录进入缓存缓冲器**之前**，先将 {entry_key, status} 写入本地 WAL，
//! 批量刷新成功后标记为 committed。崩溃/关闭后重启，扫描 WAL 即可：
//!   - 已 committed 的条目键 → 已落盘（add_record 即时 fsync），续传时直接跳过
//!   - pending 但未 committed → 未落盘，续传时重新加密入库（条目键未变，幂等）
//! 重做量不超过一个批次（检查点粒度）。
//!
//! =============================================================================
//! 持久化格式（JSON-lines，append-only）
//! =============================================================================
//! 每行一个 JSON 对象，以 `\n` 分隔。条目类型：
//!   {"kind":"begin","import_id":"<uuid>","ts":<unix_ms>}
//!   {"kind":"pending","import_id":"<uuid>","batch_id":<n>,"entry_key":"<非内容键>","name":"<file>","idx":<i>}
//!   {"kind":"committed","import_id":"<uuid>","batch_id":<n>,"entry_key":"<非内容键>","verthys_id":<lid>,"name":"<file>","chunk_ids":<[lid]|缺省>}
//!   {"kind":"checkpoint","import_id":"<uuid>","batch_id":<n>,"committed_count":<x>}
//!   {"kind":"removed","keys":["<非内容键>"],"at":<unix_ms>}
//!   {"kind":"end","import_id":"<uuid>","success":<bool>}
//!
//! `chunk_ids` 为显式声明的外置块引用集合（缺省表示历史条目、引用不可推断）；
//! 崩溃恢复据此把块归属结算进台账，防止已提交记录引用的块被当作孤儿回收。
//!
//! 每条 append 后立即 sync_all（fsync）+ 刷新到磁盘，保证崩溃不丢失已提交记录。
//!
//! =============================================================================
//! 恢复语义
//! =============================================================================
//! - load(): 全量重放 WAL，构建 committed 条目键集合 + 最后检查点。
//! - 已 committed 条目键进入 `committed_keys`，续传时生产者据此去重（幂等）。
//! - pending 未 committed：不入 committed_keys，续传时重新处理（键未变 → 重新加密入库）。
//! - compact(): 导入成功结束后，将 committed 条目键合并写入一个 begin/checkpoint/end
//!   原子替换文件，缩减 WAL 体积；失败/中断保留原 WAL 供下次续传。
//!
//! =============================================================================
//! 安全边界
//! =============================================================================
//! - 仅记录非内容条目键（调用方派生）与文件名，不含密钥、不含明文、不含密文。
//! - WAL 文件位于容器附属数据目录（受 VerthysFileLock 独占锁保护，防并发写）。
//! - 所有 IO 失败向上传播为 Err（持久层不吞异常），由控制器决定降级策略。
//!
//! =============================================================================
//! 附属目录布局
//! =============================================================================
//! - 权威写路径：附属数据目录内 import.wal（快照同目录，后缀 .snapshot）。
//!
//! 依赖方向：repository → util（单向，禁止引用 controller/service/entry）

mod import_session;
mod wal_io;
mod wal_recovery;
mod wal_types;
mod wal_writer;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_settlement;

pub use import_session::ImportSession;
pub use wal_io::{exists, remove};
pub use wal_recovery::{
    append_removed, keys_for_ids, load, prune_missing_commits, settle_chunk_owners,
    SettlementOutcome,
};
pub use wal_types::{WalEntry, WalSnapshot};
pub use wal_writer::WalWriter;
