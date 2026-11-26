/*
 * controller/types — 控制器层共享 DTO
 *
 * 领域划分：
 *   ids         记录标识 newtype
 *   status      初始化与设备绑定状态
 *   ui          剪贴板与隐私保护响应
 *   reports     动态防护与内核防护状态报告
 *   anchor      回退锚点条目与扫描结果
 *   storage     存储统计与压缩结果
 *   response    VerthysResponse 遗留兼容信封
 *   operational 预检、诊断与初始化结果
 *   batch       流式分页批次
 *
 * 对外导入路径保持 controller::types::X 不变；共享记录与批量协议类型
 * 继续从 util::contracts 重导出。
 */
mod anchor;
mod batch;
mod ids;
mod operational;
mod reports;
mod response;
mod status;
mod storage;
mod ui;

pub use anchor::*;
pub use batch::*;
pub use ids::*;
pub use operational::*;
pub use reports::*;
pub use response::*;
pub use status::*;
pub use storage::*;
pub use ui::*;

// 共享记录与批量协议类型已下沉到 util::contracts；此处重导出保持控制器导入路径稳定。
pub use crate::util::contracts::{
    BatchRecordInput, ChunkBlob, ImportBatchProgress, VerthysRecordEntry, VerthysSummaryEntry,
};
