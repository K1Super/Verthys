/*
 * 导入会话生命周期
 *
 * 职责边界：开始（含续传快照与去重键收敛）、结束（提交锚点并清会话）与
 * 检查点。begin / end 与 GC 共用生命周期互斥，检查与安装必须原子。
 */

use crate::controller::types::VerthysResponse;
use crate::controller::vault::verthys_controller::require_unlocked;
use crate::repository::verthys_wal::ImportSession;
use crate::constants::command_names::cmd;
use crate::state::import_writer::{
    self, EndOutcome, WriterCommand,
};
use crate::state::AppState;
use crate::util::path::sanitize_path;
use tauri::{Manager, State};

use super::*;
/* ------------------------------------------------------------------ *
 * 命令：verthys_import_begin                                            *
 * ------------------------------------------------------------------ */

/// 创建导入会话：初始化 WAL + 从既有快照恢复 committed_keys（续传去重）。
///
/// 流程：
///   1. 防重入：检查是否已存在活跃会话，存在则拒绝（单 verthys 同一时刻仅一个活跃会话）
///   2. 解析 verthys 路径：优先使用参数，否则从 VerthysSessionGuard 读取
///   3. 创建 ImportSession：加载遗留 WAL 快照（恢复 committed_keys）→ 截断 WAL 写 begin
///   4. 存入 AppState.import_session
///   5. 返回 import_id + committed_keys（供生产者去重）
///
/// 返回字段：
///   - import_id：导入会话 ID（贯穿整个导入生命周期）
///   - entry_keys：已 committed 的非内容条目键列表（生产者据此跳过，保证幂等）
///   - total_count：续传起始的累计 committed 计数（检查点）
#[tauri::command]
pub async fn verthys_import_begin(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    verthys_path: Option<String>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, cmd::IMPORT_BEGIN) {
        return Ok(VerthysResponse::err_code(
            cmd::IMPORT_BEGIN,
            VERTHYS_NOT_READY_CODE,
            &msg,
        ));
    }

    /* begin / end / GC 生命周期串行化：检查与安装必须在同一临界区内完成。 */
    let _lifecycle = IMPORT_LIFECYCLE_LOCK.lock().await;

    log::info!("[verthys_import_begin] 开始创建导入会话");

    // 防重入：单 verthys 同一时刻仅一个活跃会话
    if state.has_import_session() {
        log::warn!("[verthys_import_begin] 已存在活跃导入会话，拒绝重复创建");
        /* 不得清除活跃会话的推迟标记：否则 import_end 会跳过锚点提交。 */
        return Ok(import_session_busy_response());
    }

    /* 仅在新会话确实建立时清除上一轮可能残留的推迟标记。 */
    state.set_bulk_defer(false);

    // 解析 verthys 路径：优先参数，否则从会话守卫读取
    let vpath = match verthys_path.or_else(|| state.verthys_session_path()) {
        Some(p) => p,
        None => {
            log::warn!("[verthys_import_begin] 无法确定 verthys 路径（参数缺失且无活跃会话）");
            return Ok(VerthysResponse::err_code(
                "verthys_import_begin",
                VERTHYS_NOT_READY_CODE,
                "无法确定加密库路径，请先解锁",
            ));
        }
    };

    log::info!(
        "[verthys_import_begin] verthys 路径: {}",
        sanitize_path(&vpath)
    );

    // 生成导入会话 ID
    let import_id = generate_import_id();
    log::info!("[verthys_import_begin] 生成 import_id: {}", import_id);

    // 创建 ImportSession：加载遗留 WAL 快照 → 恢复 committed_keys → 截断 WAL 写 begin。
    // 会话创建含快照载入与 WAL 截断，属同步 IO，移出异步运行时线程执行
    let session_vpath = vpath.clone();
    let session_id = import_id.clone();
    let reconcile_app = app.clone();
    let session = match tauri::async_runtime::spawn_blocking(move || {
        /* 自愈：先按记录存在性收敛失效去重键。删除墓碑可能缺失，
         * 会让已删记录的条目键永久占用，重新导入被静默全部跳过。
         * 收敛失败不阻断导入：仍可凭墓碑正常续传。 */
        match reconcile_import_keys(&reconcile_app, &session_vpath) {
            Ok(0) => {}
            Ok(n) => log::info!("[verthys_import_begin] 已释放失效去重键: {} 条", n),
            Err(e) => log::warn!("[verthys_import_begin] 去重键收敛失败（继续导入）: {}", e),
        }
        ImportSession::new(&session_vpath, &session_id)
    })
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            log::error!("[verthys_import_begin] 创建导入会话失败: {}", e);
            return Ok(VerthysResponse::err(
                "verthys_import_begin",
                &format!("创建导入会话失败: {}", e),
            ));
        }
        Err(e) => {
            log::error!("[verthys_import_begin] 创建导入会话任务异常: {}", e);
            return Ok(VerthysResponse::err(
                "verthys_import_begin",
                "创建导入会话失败",
            ));
        }
    };

    // 收集恢复的 committed_keys（供前端去重）+ 累计 committed 计数
    let entry_keys: Vec<String> = session.committed_keys.iter().cloned().collect();
    let total_committed = session.total_committed;

    log::info!(
        "[verthys_import_begin] 导入会话已创建: import_id={} 续传去重哈希数={} 累计 committed={}",
        import_id,
        entry_keys.len(),
        total_committed
    );

    // 存入 AppState
    {
        let mut guard = state.lock_import_session();
        *guard = Some(session);
    }

    /* G0-A2：导入开始先提交当前锚点并进入推迟会话。失败或旧 DLL 不
     * 支持时保持逐次提交，不阻断导入。 */
    if send_bulk_op(&state, "bulk_import_begin") == Some(true) {
        state.set_bulk_defer(true);
        log::info!("[verthys_import_begin] 锚点推迟会话已生效");
        /* 看门狗：空闲超过 60s 的会话由宿主强制提交一次，避免
         * “已解锁但锚点长期滞后”跨越整个空闲期。 */
        let watchdog_app = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let st = watchdog_app.state::<AppState>();
            if st.bulk_defer_active() && st.has_import_session() {
                /* 只有 worker 确认提交成功才清标记；失败时保留推迟状态，
                 * 由 end / 下一次会话继续收口，避免把未提交的锚点当作
                 * 已提交长期悬挂。 */
                if send_bulk_op(&st, "bulk_import_commit") == Some(true) {
                    st.set_bulk_defer(false);
                    log::warn!("[verthys_import_begin] 导入超过 60s，看门狗已强制提交锚点");
                } else {
                    log::error!("[verthys_import_begin] 看门狗提交锚点失败，保留推迟状态");
                }
            }
        });
    } else {
        state.set_bulk_defer(false);
    }

    let mut resp = VerthysResponse::ok("verthys_import_begin");
    resp.import_id = Some(import_id);
    resp.entry_keys = Some(entry_keys);
    resp.total_count = Some(total_committed);
    Ok(resp)
}


/* ------------------------------------------------------------------ *
 * 命令：verthys_import_end                                              *
 * ------------------------------------------------------------------ */

/// 关闭导入会话（经单写者通道执行 WAL end + 按需 compact）。
///
/// 结束命令与批量命令同走唯一写者 FIFO：end 之前在通道内排队的批次
/// 必先执行完毕，杜绝「结束先于最后一批」的交错。写者线程内取出会话
/// 并调用 WalWriter::finish(import_id, success)：
///   - success=true：写入 end 条目并 compact WAL（原子替换，仅保留
///     committed 哈希清单）
///   - success=false：原样保留 WAL 供下次续传
/// 会话随执行结束从 AppState 清空。
///
/// 返回 total_count（最终累计 committed 计数）。
#[tauri::command]
pub async fn verthys_import_end(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    success: bool,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, cmd::IMPORT_END) {
        return Ok(VerthysResponse::err(cmd::IMPORT_END, &msg));
    }

    /* 与 begin / GC 串行化：结束会话期间不得开始新会话或并发回收。 */
    let _lifecycle = IMPORT_LIFECYCLE_LOCK.lock().await;

    log::info!("[verthys_import_end] 结束导入会话: success={}", success);

    // 快速失败：无活跃会话（权威判定在写者线程内持会话锁复核）
    if !state.has_import_session() {
        log::warn!("[verthys_import_end] 无活跃导入会话");
        /* 宿主侧会话丢失但 C 层推迟可能仍在：先收口锚点再清标记，
         * 否则会话会一直挂到 30s 硬上限。 */
        if state.bulk_defer_active()
            && send_bulk_op(&state, "bulk_import_commit") != Some(true)
        {
            log::error!("[verthys_import_end] 残留推迟会话的锚点提交未成功");
        }
        state.set_bulk_defer(false);
        return Ok(VerthysResponse::err(cmd::IMPORT_END, "无活跃导入会话"));
    }

    let writer = match import_writer::ensure(&app) {
        Ok(w) => w,
        Err(e) => {
            log::error!("[verthys_import_end] 写者不可用: {}", e);
            return Ok(VerthysResponse::err(
                cmd::IMPORT_END,
                &format!("写入通道不可用: {}", e),
            ));
        }
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<Result<EndOutcome, String>>();
    let cmd = WriterCommand::End {
        success,
        reply: reply_tx,
    };

    let outcome = match submit_writer_cmd(&writer, cmd, reply_rx).await {
        Ok(o) => o,
        Err(e) => return Ok(VerthysResponse::err(cmd::IMPORT_END, &e)),
    };

    /* 正常/取消/失败路径都收口锚点：只要 Begin 成功过，就必须 Commit。
     * 提交失败返回错误让上层提示“重新解锁补推进”，不得假装导入完全成功。 */
    if state.bulk_defer_active() {
        let committed = send_bulk_op(&state, "bulk_import_commit") == Some(true);
        /* C 层提交失败会清除会话并锁定库，宿主标记必须同步清除；
         * 失败原因向上返回，由用户重新解锁触发检查补推进。 */
        state.set_bulk_defer(false);
        if !committed {
            log::error!("[verthys_import_end] 锚点提交未成功");
            return Ok(VerthysResponse::err(
                cmd::IMPORT_END,
                "导入已结束但回退锚点提交失败，请重新解锁以补推进",
            ));
        }
    }

    let mut resp = VerthysResponse::ok(cmd::IMPORT_END);
    resp.total_count = Some(outcome.total_committed);
    resp.import_id = Some(outcome.import_id);
    Ok(resp)
}

/* ------------------------------------------------------------------ *
 * 命令：verthys_import_checkpoint                                       *
 * ------------------------------------------------------------------ */

/// 查询当前导入会话的检查点状态（累计 committed 计数 + 去重哈希集）。
///
/// 用于前端在导入过程中查询实时进度，或断点续传前确认当前状态。
/// 不修改 WAL，纯只读操作。
#[tauri::command]
pub async fn verthys_import_checkpoint(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, cmd::IMPORT_CHECKPOINT) {
        return Ok(VerthysResponse::err(cmd::IMPORT_CHECKPOINT, &msg));
    }

    let guard = state.lock_import_session();
    match guard.as_ref() {
        Some(session) => {
            let entry_keys: Vec<String> = session.committed_keys.iter().cloned().collect();
            let import_id = session.import_id.clone();
            let total_committed = session.total_committed;
            let next_batch_id = session.next_batch_id;

            log::debug!(
                "[verthys_import_checkpoint] 查询检查点: import_id={} committed={} next_batch={}",
                import_id,
                total_committed,
                next_batch_id
            );

            let mut resp = VerthysResponse::ok("verthys_import_checkpoint");
            resp.import_id = Some(import_id);
            resp.entry_keys = Some(entry_keys);
            resp.total_count = Some(total_committed);
            resp.batch_id = Some(next_batch_id.saturating_sub(1));
            Ok(resp)
        }
        None => {
            log::warn!("[verthys_import_checkpoint] 无活跃导入会话");
            Ok(VerthysResponse::err(
                "verthys_import_checkpoint",
                "无活跃导入会话",
            ))
        }
    }
}
