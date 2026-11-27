/* protocol.rs — JSON 协议 + base64 编解码（模块根）
 *
 * 子模块：
 *   request  : 请求类（BatchAddRecord / StagedAddRecord / Request / FileImportSource）
 *   records  : 记录、回退锚点与状态报告（RecordEntry / AnchorEntry / SecurityStatusReport / KernelStatusReport）
 *   payloads : 媒体、文件与存储统计载荷
 *   response : Response 及其 impl、响应行长度上限与截断
 *   base64   : base64 编解码表与函数
 *   tests    : 单元测试
 *
 * 依赖：serde。被引用方：dispatch.rs / gmk.rs / main_loop.rs。
 */

mod base64;
mod payloads;
mod records;
mod request;
mod response;

#[cfg(test)]
mod tests;

pub(crate) use base64::{base64_decode, base64_encode};
pub(crate) use payloads::{
    FileFinishPayload, FileNextPayload, MediaDamageScan, MediaExportPayload,
    MediaFinishPayload, MediaMetaItem, MediaNextPayload, MediaPreviewRecord, MediaReadPayload,
    MediaVencPreview, StorageStatsEntry,
};
pub(crate) use records::{AnchorEntry, KernelStatusReport, RecordEntry, SecurityStatusReport};
// BatchAddRecord 仅经 Request.records 的字段类型消费，MAX_RESPONSE_LINE_BYTES
// 由写侧调用方与单元测试引用；模块根保留全部路径，非 test 构建无本地引用。
#[allow(unused_imports)]
pub(crate) use request::{BatchAddRecord, FileImportSource, Request, StagedAddRecord};
#[allow(unused_imports)]
pub(crate) use response::{bound_response_line, Response, MAX_RESPONSE_LINE_BYTES};
