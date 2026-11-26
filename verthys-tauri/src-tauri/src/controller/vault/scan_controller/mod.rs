/*
 * controller/vault/scan_controller — 记录扫描游标
 *
 * 子模块边界：
 *   shared   游标存回、审计、shm_name/批次校验与批次密钥
 *   records  全量记录扫描 open / next / close
 *   summary  摘要扫描 open / next / close
 *   list     按类型枚举记录 ID
 *   tests    单元测试（仅测试构建）
 *
 * 安全约束：shm_name 白名单校验；每批 records.len() 必须与 worker 计数一致，
 * 不一致触发熔断与审计；游标恢复不得覆盖并发新会话。
 */
use std::time::Duration;

mod list;
mod records;
mod shared;
mod summary;

#[cfg(test)]
mod tests;


pub use list::verthys_list_ids_by_type;
pub use records::{verthys_scan_close, verthys_scan_next, verthys_scan_open};
pub use summary::{
    verthys_scan_summary_close, verthys_scan_summary_next, verthys_scan_summary_open,
};
/* ------------------------------------------------------------------ *
 * 超时配置（提取为常量，对应 TimeoutConfig::DEFAULT）         *
 * ------------------------------------------------------------------ */

/// 预取任务关闭超时（对应 TimeoutConfig.scan_prefetch_shutdown）
const PREFETCH_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// scan_open 超时（对应 TimeoutConfig.scan_open）
const SCAN_OPEN_TIMEOUT: Duration = Duration::from_secs(60);
/// scan_next 超时（对应 TimeoutConfig.scan_next）
const SCAN_NEXT_TIMEOUT: Duration = Duration::from_secs(60);
/// scan_close 超时（对应 TimeoutConfig.scan_close）
const SCAN_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);
/// 预取内部二级超时（对应 TimeoutConfig.scan_prefetch）
/// 注：生产代码在 scan_pipeline::do_prefetch_blocking 中直接使用 TimeoutConfig::DEFAULT.scan_prefetch，
/// 此常量供测试校验一致性。
#[allow(dead_code)]
const SCAN_PREFETCH_TIMEOUT: Duration = Duration::from_secs(60);
