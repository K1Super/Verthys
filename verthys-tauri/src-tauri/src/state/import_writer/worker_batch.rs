use crate::constants::import_writer as wconst;
use crate::state::AppState;

/// worker 单条/批量写入响应的最小投影。
///
/// state 只需要成功标志、分配的 ID 与错误文本；直接复用控制器层的完整
/// 响应结构会把共享状态模块反向绑定到控制器层。
#[derive(serde::Deserialize)]
pub(super) struct WorkerWriteReply {
    pub(super) ok: bool,
    #[serde(default)]
    pub(super) id: Option<u64>,
    #[serde(default)]
    pub(super) ids: Option<Vec<u64>>,
    #[serde(default)]
    pub(super) error: Option<String>,
}

/// 批量写入的单次 worker 子批条数上限。
///
/// C 层 `VERTHYS_ADD_RECORDS_MAX` 为 512；此处取 128，使单条坏记录导致
/// 子批整体失败时，回退到逐条写入的代价有界，同时把 IPC 轮次压到
/// 「每 128 条 1 次」。
pub(super) const WORKER_ADD_RECORDS_BATCH: usize = 128;

/// 单次 worker 子批的载荷预算（name + base64 数据字符数）。
///
/// 取单次 IPC 预算的 80%，余量覆盖 JSON 包装与协议字段；超过预算即切
/// 子批，避免大批量写入撞上协议行上限。
pub(super) const WORKER_ADD_RECORDS_BYTES: usize = wconst::MAX_IPC_PAYLOAD_BYTES * 4 / 5;

/// 已通过本地校验、待批量写入的记录（下标保留用于结果回填）
pub(super) struct PreparedRecord {
    /// 输入下标（failed_indices / ids 的语义位置）
    pub(super) idx: u64,
    /// 原记录（数据已由调用方加密）
    pub(super) record: crate::util::contracts::BatchRecordInput,
    /// 归一化条目键（WAL 幂等键）
    pub(super) entry_key: String,
}

/// 批量写入失败分类。
///
/// 区分传输级与记录级失败是性能与正确性的关键：
///   - Transport：worker 不可达/响应协议异常。逐条回退只会把一次 15s 超时
///     放大成 N×15s（128 条即半小时级挂起），必须整体上抛交调用方重试；
///   - Rejected：worker 正常响应但 C 层拒绝。逐条回退可隔离单条坏记录，
///     其余记录继续落库。
#[derive(Debug)]
pub(super) enum WorkerAddError {
    Transport(String),
    Rejected(String),
}

/// add_records 单条请求（借用原始载荷，避免中间 Value 复制整批 base64）
#[derive(serde::Serialize)]
struct AddRecordsItem<'a> {
    rtype: u32,
    name: &'a str,
    data: &'a str,
}

/// add_records 请求体（直接序列化，不经过 serde_json::Value 中转）
#[derive(serde::Serialize)]
struct AddRecordsRequest<'a> {
    op: &'static str,
    records: Vec<AddRecordsItem<'a>>,
}

/// 向 worker 发起一次批量 add_records 并解析结果。
///
/// 条目以 `(rtype, name, data_b64)` 元组传入：pending 记录与块上传共用同一
/// 批量协议，避免两份 JSON 构造与响应校验实现漂移。
/// 契约：成功时返回与输入等长且全为正 ID 的列表。
pub(super) fn worker_add_records(
    state: &AppState,
    items: &[(u32, &str, &str)],
) -> Result<Vec<u64>, WorkerAddError> {
    let req = AddRecordsRequest {
        op: "add_records",
        records: items
            .iter()
            .map(|(rtype, name, data)| AddRecordsItem {
                rtype: *rtype,
                name,
                data,
            })
            .collect(),
    };
    let json = serde_json::to_string(&req)
        .map_err(|e| WorkerAddError::Transport(format!("请求序列化失败: {}", e)))?;
    match state.send(&json) {
        Ok(resp_json) => {
            match serde_json::from_str::<WorkerWriteReply>(&resp_json) {
                Ok(resp) if resp.ok => {
                    let ids = resp.ids.unwrap_or_default();
                    if ids.len() != items.len() || ids.contains(&0) {
                        log::warn!(
                            "[import_writer] worker add_records 返回 ID 列表非法: got={} expected={}",
                            ids.len(),
                            items.len()
                        );
                        return Err(WorkerAddError::Transport(
                            "worker add_records 返回 ID 列表非法".to_string(),
                        ));
                    }
                    Ok(ids)
                }
                Ok(resp) => {
                    log::warn!(
                        "[import_writer] worker add_records 返回失败: {:?}",
                        resp.error
                    );
                    Err(WorkerAddError::Rejected(format!(
                        "worker add_records 失败: {:?}",
                        resp.error
                    )))
                }
                Err(e) => {
                    log::warn!("[import_writer] add_records 响应解析失败: {}", e);
                    Err(WorkerAddError::Transport(format!("响应解析失败: {}", e)))
                }
            }
        }
        Err(e) => {
            log::warn!("[import_writer] add_records worker 通信失败: {}", e);
            Err(WorkerAddError::Transport(format!("worker 通信失败: {}", e)))
        }
    }
}

/// 向 worker 发起一次暂存块提交并解析结果。
///
/// 请求只携带引用（job_id/chunk_key/chunk_hash），密文由 worker 从导入
/// job 暂存区取出；宿主不再持有或传输块密文。
pub(super) fn worker_add_records_staged(
    state: &AppState,
    items: &[(u32, &str, &str, &str, &str)],
) -> Result<Vec<u64>, WorkerAddError> {
    #[derive(serde::Serialize)]
    struct StagedAddItem<'a> {
        rtype: u32,
        name: &'a str,
        job_id: &'a str,
        chunk_key: &'a str,
        chunk_hash: &'a str,
    }
    #[derive(serde::Serialize)]
    struct StagedAddRequest<'a> {
        op: &'static str,
        staged_records: Vec<StagedAddItem<'a>>,
    }

    let req = StagedAddRequest {
        op: "add_records_staged",
        staged_records: items
            .iter()
            .map(|(rtype, name, job_id, chunk_key, chunk_hash)| StagedAddItem {
                rtype: *rtype,
                name,
                job_id,
                chunk_key,
                chunk_hash,
            })
            .collect(),
    };
    let json = serde_json::to_string(&req)
        .map_err(|e| WorkerAddError::Transport(format!("请求序列化失败: {}", e)))?;
    match state.send(&json) {
        Ok(resp_json) => match serde_json::from_str::<WorkerWriteReply>(&resp_json) {
            Ok(resp) if resp.ok => {
                let ids = resp.ids.unwrap_or_default();
                if ids.len() != items.len() || ids.contains(&0) {
                    log::warn!(
                        "[import_writer] worker add_records_staged 返回 ID 列表非法: got={} expected={}",
                        ids.len(),
                        items.len()
                    );
                    return Err(WorkerAddError::Transport(
                        "worker add_records_staged 返回 ID 列表非法".to_string(),
                    ));
                }
                Ok(ids)
            }
            Ok(resp) => {
                log::warn!(
                    "[import_writer] worker add_records_staged 返回失败: {:?}",
                    resp.error
                );
                Err(WorkerAddError::Rejected(format!(
                    "worker add_records_staged 失败: {:?}",
                    resp.error
                )))
            }
            Err(e) => {
                log::warn!("[import_writer] add_records_staged 响应解析失败: {}", e);
                Err(WorkerAddError::Transport(format!("响应解析失败: {}", e)))
            }
        },
        Err(e) => {
            log::warn!("[import_writer] add_records_staged worker 通信失败: {}", e);
            Err(WorkerAddError::Transport(format!("worker 通信失败: {}", e)))
        }
    }
}
