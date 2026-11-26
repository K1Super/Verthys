/*
 * WAL 恢复检测
 *
 * 职责边界：扫描遗留 WAL，向用户提供断点续传判定；不直接修改会话。
 */

use crate::controller::types::VerthysResponse;
use crate::repository::verthys_wal::{self};
use crate::state::AppState;
use tauri::State;

/* ------------------------------------------------------------------ *
 * 命令：verthys_wal_recover                                             *
 * ------------------------------------------------------------------ */

/// 扫描遗留 WAL，返回 committed 哈希集（续传去重，不创建新会话）。
///
/// 应用启动时或导入前调用，检查是否存在遗留 WAL（上次崩溃/关闭未完成）：
///   - WAL 不存在 → 返回空哈希集（无需续传）
///   - WAL 存在且已 end（success） → 返回 committed 哈希集（已完成的去重集）
///   - WAL 存在且未 end → 返回 committed 哈希集（续传去重依据，pending 记录将被重新处理）
///
/// 与 verthys_import_begin 的区别：
///   - verthys_wal_recover：纯只读扫描，不创建会话，不截断 WAL
///   - verthys_import_begin：创建新会话，截断 WAL 写 begin（recover 的哈希集会被继承）
///
/// 前端典型流程：
///   1. 启动时调用 verthys_wal_recover 检查是否有遗留导入
///   2. 若有遗留：提示用户「检测到未完成的导入，是否续传？」
///   3. 用户确认后调用 verthys_import_begin（继承 committed_keys）→ 续传剩余文件
#[tauri::command]
pub async fn verthys_wal_recover(
    verthys_path: Option<String>,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    log::info!("[verthys_wal_recover] 扫描遗留 WAL");

    let vpath = match verthys_path.or_else(|| state.verthys_session_path()) {
        Some(p) => p,
        None => {
            log::warn!("[verthys_wal_recover] 无法确定 verthys 路径");
            return Ok(VerthysResponse::err(
                "verthys_wal_recover",
                "无法确定加密库路径",
            ));
        }
    };

    // 统一走 load：WAL 缺失但快照存在时（异常清理/损坏场景）快照仍
    // 承载去重集合，提前空返回会静默丢弃基线导致重启后重复入库
    let recover_vpath = vpath.clone();
    let snapshot =
        match tauri::async_runtime::spawn_blocking(move || verthys_wal::load(&recover_vpath)).await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                log::error!("[verthys_wal_recover] WAL 加载失败: {}", e);
                return Ok(VerthysResponse::err(
                    "verthys_wal_recover",
                    &format!("WAL 加载失败: {}", e),
                ));
            }
            Err(e) => {
                log::error!("[verthys_wal_recover] WAL 加载任务异常: {}", e);
                return Ok(VerthysResponse::err("verthys_wal_recover", "WAL 加载失败"));
            }
        };

    let entry_keys: Vec<String> = snapshot.committed_keys.iter().cloned().collect();
    let total_committed = snapshot.committed_keys.len() as u64;
    let has_active = snapshot.active_import_id.is_some();

    log::info!(
        "[verthys_wal_recover] WAL 扫描完成: committed={} active_import_id={:?} last_batch={}",
        total_committed,
        snapshot.active_import_id,
        snapshot.last_batch_id
    );

    let mut resp = VerthysResponse::ok("verthys_wal_recover");
    resp.entry_keys = Some(entry_keys);
    resp.total_count = Some(total_committed);
    resp.import_id = snapshot.active_import_id;
    resp.batch_id = Some(snapshot.last_batch_id);
    // has_active 通过 processed_count 字段透传（1=有活跃会话未 end，0=已 end 或无遗留）
    resp.processed_count = Some(if has_active { 1 } else { 0 });
    Ok(resp)
}
