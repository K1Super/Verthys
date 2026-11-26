/*
 * 批量导入共享辅助
 *
 * 职责边界：锚点推迟 op、活记录 ID 采集、去重键收敛、会话冲突响应、
 * 导入 ID 生成，以及单写者命令投递的三层超时封装。
 */

use crate::constants::import_writer::{WRITER_CMD_TIMEOUT, WRITER_SEND_TIMEOUT};
use crate::controller::types::VerthysResponse;
use crate::repository::verthys_wal::{self};
use crate::state::import_writer::{
    self, WriterCommand,
};
use crate::state::AppState;
use std::collections::HashSet;
use std::time::SystemTime;
use tauri::Manager;

/* ------------------------------------------------------------------ *
 * 辅助函数                                                            *
 * ------------------------------------------------------------------ */

/// 发送批量导入锚点推迟 op。
///
/// 返回：
///   Some(true)  — DLL 导出符号存在且 Begin/Commit 成功
///   Some(false) — 旧 DLL 缺符号（unsupported）或 C 层明确拒绝
///   None        — IPC/解析失败
/// 除 Some(true) 外一律回退“逐次锚点提交”，不得假设推迟已生效。
pub(super) fn send_bulk_op(state: &AppState, op: &'static str) -> Option<bool> {
    let req = serde_json::json!({ "op": op }).to_string();
    match state.send_with_timeout(&req, std::time::Duration::from_secs(30)) {
        Ok(resp) => match serde_json::from_str::<serde_json::Value>(&resp) {
            Ok(v) if v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false) => Some(true),
            Ok(v) => {
                let err = v.get("error").and_then(|e| e.as_str()).unwrap_or("");
                if err.starts_with("unsupported") {
                    log::info!("[verthys_import] DLL 不支持 {}，回退逐次锚点提交", op);
                } else {
                    log::warn!("[verthys_import] {} 失败，回退逐次锚点提交: {}", op, err);
                }
                Some(false)
            }
            Err(e) => {
                log::warn!("[verthys_import] {} 响应解析失败: {}", op, e);
                None
            }
        },
        Err(e) => {
            log::warn!("[verthys_import] {} IPC 失败: {}", op, e);
            None
        }
    }
}

/// 结构化错误码：已有活跃导入会话（前端据此唤起会话冲突确认，不做文案判定）。
/// 两个消费方（清藏导入管线与照片导入流水线）以本码为控制流契约。
pub(crate) const IMPORT_SESSION_BUSY_CODE: &str = "E_IMPORT_SESSION_BUSY";

/// 结构化错误码：加密库未就绪（未解锁/路径缺失；前端据此给出重新解锁引导）
pub(crate) const VERTHYS_NOT_READY_CODE: &str = "E_VERTHYS_NOT_READY";

/// 单次全量 ID 枚举页大小（与 C 层 VERTHYS_TYPE_ID_BATCH_MAX 同源）
const LIVE_ID_PAGE_MAX: u64 = 4096;
/// 存活 ID 枚举安全阀：超限视为异常容器，拒绝收敛（保守保留去重键）
const LIVE_ID_HARD_LIMIT: usize = 5_000_000;
/// 单页枚举超时：目录叶迭代不读记录段，正常为毫秒级
const LIVE_ID_PAGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 枚举容器内全部存活记录 ID。
///
/// 走目录叶迭代（worker `list_all_lids`）：不读记录段、不解密名称，
/// 因此与模块锁定状态无关——任一模块未解锁也不会让存活 ID 缺失，
/// 不会把仍存活的记录误判为已删除而释放其去重键。
/// 旧 DLL 缺该可选符号时返回错误，调用方跳过收敛（保留去重键）。
pub(super) fn collect_live_record_ids(app: &tauri::AppHandle) -> Result<HashSet<u64>, String> {
    let state = app.state::<AppState>();
    let mut live = HashSet::new();
    let mut after = 0u64;
    loop {
        let req = serde_json::json!({
            "op": "list_all_lids",
            "id": after,
            "max_count": LIVE_ID_PAGE_MAX,
        });
        let resp_json = state.send_with_timeout(&req.to_string(), LIVE_ID_PAGE_TIMEOUT)?;
        let resp: VerthysResponse = serde_json::from_str(&resp_json)
            .map_err(|e| format!("存活记录 ID 枚举响应解析失败: {}", e))?;
        if !resp.ok {
            return Err(resp
                .error
                .unwrap_or_else(|| "存活记录 ID 枚举失败".to_string()));
        }
        let ids = resp.ids.unwrap_or_default();
        let exhausted = resp.exhausted.unwrap_or(false);
        let Some(last) = ids.last().copied() else {
            if exhausted {
                break;
            }
            return Err("存活记录 ID 枚举未推进".to_string());
        };
        if last <= after {
            return Err("存活记录 ID 枚举游标未推进".to_string());
        }
        live.extend(ids);
        if live.len() > LIVE_ID_HARD_LIMIT {
            return Err("存活记录数量超过枚举安全阀".to_string());
        }
        after = last;
        if exhausted {
            break;
        }
    }
    Ok(live)
}

/// 收敛 WAL 去重集合：已 committed 记录 ID 已不在容器内即释放条目键。
///
/// 删除流程在 meta 不可解密时无法提供条目键，墓碑因此缺失；
/// 失效条目键会让重新导入同一来源文件被静默全部跳过。记录 ID 删除后不会
/// 复用，「ID 不存在 ⇒ 去重键失效」是安全判据。
pub(super) fn reconcile_import_keys(app: &tauri::AppHandle, vpath: &str) -> Result<u64, String> {
    let snapshot = verthys_wal::load(vpath)?;
    if snapshot.committed_ids.is_empty() {
        return Ok(0);
    }
    let live = collect_live_record_ids(app)?;
    verthys_wal::prune_missing_commits(vpath, &live)
}

/// 构造「已有导入会话」拒绝响应（导入域防重入的唯一出口）
pub(super) fn import_session_busy_response() -> VerthysResponse {
    VerthysResponse::err_code(
        "verthys_import_begin",
        IMPORT_SESSION_BUSY_CODE,
        "已有导入会话进行中，请先结束当前会话",
    )
}

/// 生成导入会话 ID（imp-<unix_ms>-<rand_hex8>）
///
/// 单调递增 + 随机后缀，保证单 verthys 内全局唯一。
/// 不引入 uuid 依赖，复用已有的 getrandom。
pub(super) fn generate_import_id() -> String {
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let mut rand_buf = [0u8; 4];
    let _ = getrandom::getrandom(&mut rand_buf);
    format!(
        "imp-{}-{:02x}{:02x}{:02x}{:02x}",
        ts, rand_buf[0], rand_buf[1], rand_buf[2], rand_buf[3]
    )
}


/* ------------------------------------------------------------------ *
 * 命令：verthys_add_records_batch                                       *
 * ------------------------------------------------------------------ */

/// 单写者命令投递：发送层超时 + 应答层超时（三层超时的前两层）。
///
/// 发送在 spawn_blocking 中执行（有界通道背压时阻塞不影响异步线程）。
/// 关键：发送超时由 `submit_timeout` 在通道内实现，超时即表示命令**未入队**，
/// 调用方可按幂等键安全重试；外层 timeout 不能包裹阻塞发送——那会把
/// 命令遗弃在仍被通道挂起的阻塞线程中，超时后仍可能被写入。
///
/// 应答经 oneshot 等待；第三层（写者心跳看门狗）由 import_writer 独立
/// 巡检，此处只把两类超时映射为可读错误供调用方组装响应。
pub(crate) async fn submit_writer_cmd<T>(
    writer: &import_writer::ImportWriterHandle,
    cmd: WriterCommand,
    reply_rx: tokio::sync::oneshot::Receiver<Result<T, String>>,
) -> Result<T, String> {
    // 第一层：命令层有界发送（通道内超时，不产生孤儿阻塞任务）
    let writer = writer.clone();
    let send_result = tauri::async_runtime::spawn_blocking(move || {
        writer.submit_timeout(cmd, WRITER_SEND_TIMEOUT)
    })
    .await;
    match send_result {
        Err(e) => {
            log::error!("[import_writer] 命令发送任务异常: {}", e);
            return Err("写者通道内部错误".to_string());
        }
        Ok(Err(e)) => {
            log::warn!("[import_writer] 写者通道不可用: {}", e);
            return Err(e);
        }
        Ok(Ok(())) => {}
    }

    // 第二层：应答层超时
    match tokio::time::timeout(WRITER_CMD_TIMEOUT, reply_rx).await {
        Err(_) => {
            log::error!(
                "[import_writer] 写者应答超时（{}s）",
                WRITER_CMD_TIMEOUT.as_secs()
            );
            Err("写入超时，请检查存储状态后重试".to_string())
        }
        Ok(Err(_)) => {
            log::error!("[import_writer] 写者应答通道关闭");
            Err("写者通道已关闭".to_string())
        }
        Ok(Ok(result)) => result,
    }
}
