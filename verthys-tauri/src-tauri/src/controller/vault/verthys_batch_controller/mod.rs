/*
 * controller/vault/verthys_batch_controller — 批量导入流水线
 *
 * 子模块边界：
 *   support  锚点推迟、活记录采集、去重键收敛与单写者命令投递
 *   session  导入会话生命周期（begin / end / checkpoint）
 *   write    记录批与内容块提交
 *   keys     导入去重键维护
 *   gc       孤儿块回收
 *   wal      遗留 WAL 检测
 *   tests    单元测试（仅测试构建）
 *
 * 并发约束：begin / end / GC 由 IMPORT_LIFECYCLE_LOCK 串行化，防止
 * “检查无会话”与“安装新会话”之间的竞态把活跃块判为孤儿。
 */
static IMPORT_LIFECYCLE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

mod gc;
mod keys;
mod session;
mod support;
mod wal;
mod write;

#[cfg(test)]
mod tests;

use support::*;

pub(crate) use support::{submit_writer_cmd, IMPORT_SESSION_BUSY_CODE, VERTHYS_NOT_READY_CODE};
pub use gc::verthys_gc_orphan_chunks;
pub use keys::verthys_forget_import_keys;
pub use session::{
    verthys_import_begin, verthys_import_checkpoint, verthys_import_end,
};
pub use wal::verthys_wal_recover;
pub use write::{verthys_add_chunk_batch, verthys_add_records_batch};
