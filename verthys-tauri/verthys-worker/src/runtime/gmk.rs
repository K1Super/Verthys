/* gmk — GMK 全局主密钥：内存状态、材料派生、记录 I/O 与命令编排
 *
 * 职责划分：
 *   - gmk_state    : 常量、GmkMaterial、GMK thread_local 与写入槽
 *   - gmk_material : GMK 材料派生与三要素核验
 *   - gmk_records  : 全局密钥记录 I/O 抽象、分页枚举与有效记录解析
 *   - gmk_handlers : derive / verify / change / clear 命令与 panic 清零
 *
 * 对外路径保持在本模块（runtime::gmk::*），由下方重导出提供。
 */

mod gmk_handlers;
mod gmk_material;
mod gmk_records;
mod gmk_state;

pub(crate) use gmk_handlers::{
    handle_change_global_key, handle_clear_global_key, handle_derive_and_store_global_key,
    handle_verify_global_key, wipe_thread_gmk,
};
pub(crate) use gmk_state::GMK;

#[cfg(test)]
mod tests;
