/*
 * 流式分页批次
 *
 * 职责边界：流式枚举的 Channel 推送载荷与批次错误。
 */

use super::*;
use ts_rs::TS;
// ===== EnumerateBatch（流式分页批次）=====

/// 枚举记录流式分页批次（Tauri Channel 推送载荷）
///
/// verthys_enumerate_records_stream 命令循环调用 worker enumerate_records，
/// 每批返回通过 on_batch Channel 推送到前端。前端收到一批即渲染一批，
/// 用户感知为渐进式加载而非"瞬间冻结后爆发"，单批处理时间 < 5ms。
///
/// 批次失败时通过 error 字段返回错误信息，前端据此决定是否停止循环。
#[derive(serde::Serialize, Clone, TS)]
#[ts(export, export_to = "bindings/")]
pub struct EnumerateBatch {
    /// 本批记录列表（id/type/name/dataB64）
    pub records: Vec<VerthysRecordEntry>,
    /// 本批最后一条记录的 ID（前端据此发起下一批，0 表示无记录）
    #[ts(type = "number")]
    pub last_id: u64,
    /// 本批记录数
    #[ts(type = "number")]
    pub count: u64,
    /// 是否已遍历完毕（true 时前端停止循环）
    pub exhausted: bool,
    /// 累计已推送记录数（用于前端进度展示）
    #[ts(type = "number")]
    pub total_pushed: u64,
    /// 批次错误信息（失败时前端据此停止循环）
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<crate::controller::api_error::ApiError>,
}
