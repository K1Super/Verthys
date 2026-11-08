/*
 * @file controller/verthys_batch_controller.rs
 * @brief 照片导入异步批处理流水线 — 后端批量控制器
 *
 * 异步批处理流水线 — 消费者阶段（主进程）
 *
 * =============================================================================
 * 架构定位
 * =============================================================================
 * 三阶段流水线的「消费者」阶段，运行在主进程：
 *   - 生产者（渲染进程主线程）：文件扫描、条目键幂等判定、分片打包
 *   - 传输器（渲染进程 Web Worker 池）：AES-256-GCM / XChaCha20 加密 + 元数据序列化
 *   - 消费者（本文件）：批量写入存储、同步三层缓存（前端）、持久化 WAL、检查点
 *
 * 落实「N 次加密，1 次 IPC 传输」：verthys_add_records_batch 单次 IPC 写入 N 条记录，
 * 返回分配的 verthys ID 列表 + 失败索引 + 检查点信息。WAL 保证断点续传幂等。
 *
 * =============================================================================
 * 命令清单
 * =============================================================================
 *   - verthys_import_begin：创建导入会话（初始化 WAL + 恢复 committed_keys），返回 import_id + 已提交条目键集
 *   - verthys_add_records_batch：批量写入 N 条已加密记录（WAL pending → worker 批量
 *     add_records → WAL committed → 检查点），流式推送进度
 *   - verthys_import_end：关闭导入会话（success=true 触发 WAL 压缩，failure 保留 WAL 供续传）
 *   - verthys_import_checkpoint：查询当前检查点状态（累计 committed 计数）
 *   - verthys_wal_recover：扫描遗留 WAL，返回已提交条目键集（续传幂等，不创建新会话）
 *
 * =============================================================================
 * WAL 与幂等保证
 * =============================================================================
 * 每条记录进入缓存缓冲器之前先写 WAL pending；worker add_record 成功后写 WAL committed；
 * 每批次结束写 WAL checkpoint。崩溃/关闭后重启：
 *   - 已 committed 条目键 → 已落盘（add_record 即时 fsync），续传时跳过（幂等）
 *   - pending 未 committed → 未落盘，续传时重新入库（条目键未变，幂等）
 * 重做量不超过一个批次（检查点粒度）。
 *
 * =============================================================================
 * 安全边界
 * =============================================================================
 * - 本控制器不解密、不接触明文密钥：记录数据由前端 Worker 加密后以 base64 传入
 * - 仅记录非内容条目键与文件名到 WAL，不含密钥/明文/密文
 * - WAL 文件位于容器附属数据目录 <verthys_path>.d（受 VerthysFileLock 独占锁保护）
 * - 所有 IO 失败向上传播为 Err，由前端决定降级策略
 *
 * 依赖方向：controller → state / repository / controller::types / worker（单向）
 */

use crate::constants::import_writer::{WRITER_CMD_TIMEOUT, WRITER_SEND_TIMEOUT};
use crate::controller::types::{BatchRecordInput, ChunkBlob, ImportBatchProgress, VerthysResponse};
use crate::controller::verthys_controller::{delete_batch_timeout, require_unlocked};
use crate::repository::verthys_wal::{self, ImportSession};
use crate::security::command_names::cmd;
use crate::state::import_writer::{
    self, BatchAppendOutcome, ChunkAppendOutcome, EndOutcome, WriterCommand,
};
use crate::state::AppState;
use crate::util::path::sanitize_path;
use std::collections::HashSet;
use std::time::SystemTime;
use tauri::{Manager, State};

/* ------------------------------------------------------------------ *
 * 辅助函数                                                            *
 * ------------------------------------------------------------------ */

/// 结构化错误码：已有活跃导入会话（前端据此唤起会话冲突确认，不做文案判定）。
/// 两个消费方（清藏导入管线与照片导入流水线）以本码为控制流契约。
const IMPORT_SESSION_BUSY_CODE: &str = "E_IMPORT_SESSION_BUSY";

/// 结构化错误码：加密库未就绪（未解锁/路径缺失；前端据此给出重新解锁引导）
const VERTHYS_NOT_READY_CODE: &str = "E_VERTHYS_NOT_READY";

/// 去重键存在性收敛时枚举的记录类型：照片索引、文件索引。
/// 导入会话的 committed 记录只可能是索引型记录（块记录不入 WAL）；
/// 不枚举块类型，避免大批量相册在每次导入前扫描全部块 ID。
const IMPORT_INDEX_RTYPES: [u32; 2] = [0x01u32, 0x08u32];
/// 单次类型 ID 枚举上限（与 C 层同源）
const TYPE_LIST_PAGE_MAX: u64 = 4096;

/// 枚举容器内仍然存活的索引型记录 ID（走类型盲索引，不读记录密文）。
fn collect_live_record_ids(app: &tauri::AppHandle) -> Result<HashSet<u64>, String> {
    let state = app.state::<AppState>();
    let mut live = HashSet::new();
    for rtype in IMPORT_INDEX_RTYPES {
        let mut after = 0u64;
        loop {
            let req = serde_json::json!({
                "op": "list_ids_by_type",
                "rtype": rtype,
                "id": after,
                "max_count": TYPE_LIST_PAGE_MAX,
            });
            let resp_json = state.send(&req.to_string())?;
            let resp: VerthysResponse = serde_json::from_str(&resp_json)
                .map_err(|e| format!("记录 ID 枚举响应解析失败: {}", e))?;
            if !resp.ok {
                return Err(resp.error.unwrap_or_else(|| "记录 ID 枚举失败".to_string()));
            }
            let ids = resp.ids.unwrap_or_default();
            let Some(last) = ids.last().copied() else {
                break;
            };
            live.extend(ids);
            if last <= after {
                break; // 防御：游标不前进即终止
            }
            after = last;
        }
    }
    Ok(live)
}

/// 收敛 WAL 去重集合：已 committed 记录 ID 已不在容器内即释放条目键。
///
/// 删除流程在 meta 不可解密时无法提供条目键（历史缺陷），墓碑因此缺失；
/// 失效条目键会让重新导入同一来源文件被静默全部跳过。记录 ID 删除后不会
/// 复用，「ID 不存在 ⇒ 去重键失效」是安全判据。
fn reconcile_import_keys(app: &tauri::AppHandle, vpath: &str) -> Result<u64, String> {
    let snapshot = verthys_wal::load(vpath)?;
    if snapshot.committed_ids.is_empty() {
        return Ok(0);
    }
    let live = collect_live_record_ids(app)?;
    verthys_wal::prune_missing_commits(vpath, &live)
}

/// 构造「已有导入会话」拒绝响应（导入域防重入的唯一出口）
fn import_session_busy_response() -> VerthysResponse {
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
fn generate_import_id() -> String {
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

    log::info!("[verthys_import_begin] 开始创建导入会话");

    // 防重入：单 verthys 同一时刻仅一个活跃会话
    if state.has_import_session() {
        log::warn!("[verthys_import_begin] 已存在活跃导入会话，拒绝重复创建");
        return Ok(import_session_busy_response());
    }

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
        /* 自愈：先按记录存在性收敛失效去重键。删除墓碑缺失（历史缺陷）
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

    let mut resp = VerthysResponse::ok("verthys_import_begin");
    resp.import_id = Some(import_id);
    resp.entry_keys = Some(entry_keys);
    resp.total_count = Some(total_committed);
    Ok(resp)
}

/* ------------------------------------------------------------------ *
 * 命令：verthys_add_records_batch                                       *
 * ------------------------------------------------------------------ */

/// 单写者命令投递：发送层超时 + 应答层超时（三层超时的前两层）。
///
/// 发送在 spawn_blocking 中执行（有界通道背压时阻塞不影响异步线程）。
/// 关键：发送超时由 `submit_timeout` 在通道内实现，超时即表示命令**未入队**，
/// 调用方可按幂等键安全重试；不再用外层 timeout 包裹阻塞发送——那会把
/// 命令遗弃在仍被通道挂起的阻塞线程中，超时后仍可能被写入。
///
/// 应答经 oneshot 等待；第三层（写者心跳看门狗）由 import_writer 独立
/// 巡检，此处只把两类超时映射为可读错误供调用方组装响应。
async fn submit_writer_cmd<T>(
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

/// 批量写入 N 条已加密记录（经单写者通道串行执行 WAL pending → worker
/// 批量 add_records → WAL committed → 检查点）。
///
/// 落实「N 次加密，1 次 IPC 传输」：前端 Worker 池并行加密 N 条记录后，
/// 单次 IPC 调用本命令写入。实际存储变更由唯一写者线程执行（worker
/// 批量事务提交 + 子批一次 WAL fsync），本命令仅做闸门、投递与应答
/// 组装，阻塞的存储 IO 不再占用异步运行时线程。
///
/// 每条记录的语义（写者线程内）：
///   1. 条目键幂等：若 entry_key ∈ committed_keys → 跳过，ids[i]=0
///   2. WAL pending（子批级合并刷盘）
///   3. worker add_records：单次事务提交子批，返回分配的 verthys ID
///   4. WAL committed（按子批一次 fsync）
///   5. mark_committed：更新内存去重集合 + 累计计数
///   6. 失败处理：worker 失败 → failed_indices.push(i)，ids[i]=0；
///      子批失败时回退逐条写入以隔离单条错误
///   7. 进度推送：每条记录处理后通过 Channel 推送 ImportBatchProgress
/// 批次结束：WAL checkpoint（fsync）
///
/// 返回字段：
///   - ids：本批次每条记录分配的 verthys ID（0 表示幂等跳过或失败）
///   - batch_id：本批次 ID（从 1 递增）
///   - failed_indices：本批次失败记录的下标列表
///   - processed_count：本批次实际处理（含幂等跳过）的记录数
///   - total_count：导入会话累计已 committed 记录数（检查点）
///   - skipped_count：本批次因条目键幂等跳过的记录数
#[tauri::command]
pub async fn verthys_add_records_batch(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    records: Vec<BatchRecordInput>,
    on_progress: tauri::ipc::Channel<ImportBatchProgress>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, cmd::ADD_RECORDS_BATCH) {
        return Ok(VerthysResponse::err(cmd::ADD_RECORDS_BATCH, &msg));
    }

    let total_in_batch = records.len() as u64;
    log::info!(
        "[verthys_add_records_batch] 收到批量写入请求: {} 条记录",
        total_in_batch
    );

    // 快速失败：无活跃会话（权威判定在写者线程内持会话锁复核）
    if !state.has_import_session() {
        log::warn!("[verthys_add_records_batch] 无活跃导入会话，拒绝写入");
        return Ok(VerthysResponse::err(
            cmd::ADD_RECORDS_BATCH,
            &format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN),
        ));
    }

    // 取用写者（缺失/心跳失效时原地重建）——全部存储变更经唯一写者串行
    let writer = match import_writer::ensure(&app) {
        Ok(w) => w,
        Err(e) => {
            log::error!("[verthys_add_records_batch] 写者不可用: {}", e);
            return Ok(VerthysResponse::err(
                cmd::ADD_RECORDS_BATCH,
                &format!("写入通道不可用: {}", e),
            ));
        }
    };

    let (reply_tx, reply_rx) =
        tokio::sync::oneshot::channel::<Result<BatchAppendOutcome, String>>();
    let cmd = WriterCommand::AppendPending {
        records,
        progress: Some(on_progress),
        reply: reply_tx,
    };

    let outcome = match submit_writer_cmd(&writer, cmd, reply_rx).await {
        Ok(o) => o,
        Err(e) => return Ok(VerthysResponse::err(cmd::ADD_RECORDS_BATCH, &e)),
    };

    let mut resp = VerthysResponse::ok(cmd::ADD_RECORDS_BATCH);
    resp.ids = Some(outcome.ids);
    resp.batch_id = Some(outcome.batch_id);
    resp.failed_indices = Some(outcome.failed_indices);
    resp.processed_count = Some(outcome.processed_in_batch);
    resp.total_count = Some(outcome.total_committed);
    resp.skipped_count = Some(outcome.skipped_in_batch);
    Ok(resp)
}

/* ------------------------------------------------------------------ *
 * 命令：verthys_add_chunk_batch                                         *
 * ------------------------------------------------------------------ */

/// 上传外置加密块（大文件分块记录，经单写者通道串行落库）。
///
/// 大文件（块密文总量超过内联阈值）的照片先将块上传为独立记录，
/// 随后 meta 记录携带 chunk_ids 引用；块上传与 meta 写入同走唯一
/// 写者 FIFO，写者侧校验引用完整性（块必须在本会话已成功上传），
/// 未上传的引用按条拒绝，杜绝悬空引用入库。
///
/// 返回字段：
///   - ids：每块的记录 ID（0 = 失败；同块键重复上传复用既有 ID）
///   - failed_indices：失败块的下标列表
///
/// 块记录不进入 WAL committed 集合：块是纯密文负载，meta committed 才是
/// 恢复单元；同块键重传经会话映射幂等复用，不产生重复块记录。
#[tauri::command]
pub async fn verthys_add_chunk_batch(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    chunks: Vec<ChunkBlob>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, cmd::ADD_CHUNK_BATCH) {
        return Ok(VerthysResponse::err(cmd::ADD_CHUNK_BATCH, &msg));
    }

    log::info!(
        "[verthys_add_chunk_batch] 收到块上传请求: {} 条",
        chunks.len()
    );

    // 快速失败：无活跃会话（权威判定在写者线程内持会话锁复核）
    if !state.has_import_session() {
        log::warn!("[verthys_add_chunk_batch] 无活跃导入会话，拒绝块上传");
        return Ok(VerthysResponse::err(
            cmd::ADD_CHUNK_BATCH,
            &format!("无活跃导入会话，请先调用 {}", cmd::IMPORT_BEGIN),
        ));
    }

    // 取用写者（缺失/心跳失效时原地重建）——块上传与 meta 写入同一 FIFO
    let writer = match import_writer::ensure(&app) {
        Ok(w) => w,
        Err(e) => {
            log::error!("[verthys_add_chunk_batch] 写者不可用: {}", e);
            return Ok(VerthysResponse::err(
                cmd::ADD_CHUNK_BATCH,
                &format!("写入通道不可用: {}", e),
            ));
        }
    };

    let (reply_tx, reply_rx) =
        tokio::sync::oneshot::channel::<Result<ChunkAppendOutcome, String>>();
    let cmd = WriterCommand::AppendChunks {
        chunks,
        reply: reply_tx,
    };

    let outcome = match submit_writer_cmd(&writer, cmd, reply_rx).await {
        Ok(o) => o,
        Err(e) => return Ok(VerthysResponse::err(cmd::ADD_CHUNK_BATCH, &e)),
    };

    let mut resp = VerthysResponse::ok(cmd::ADD_CHUNK_BATCH);
    resp.ids = Some(outcome.ids);
    resp.failed_indices = Some(outcome.failed_indices);
    Ok(resp)
}

/* ------------------------------------------------------------------ *
 * 命令：verthys_forget_import_keys                                        *
 * ------------------------------------------------------------------ */

/// 删除照片后释放续传幂等锁（WAL 追加删除墓碑）。
///
/// 前端批量删除照片成功后调用：后端向 WAL 追加删除墓碑（含 fsync），
/// 恢复重放时从 committed 集合移除非内容条目键，实现「删除后可重新导入」。
/// 若存在活跃导入会话，同步更新会话内存集合与计数（本会话立即生效）。
/// WAL 与快照均不存在时为无操作（去重集合本为空）。
///
/// 条目键来源：`entry_keys` 由前端以来源元数据派生（非内容哈希）；meta
/// 不可解密或历史条目缺键时，前端传入 `record_ids`，后端据 WAL committed
/// 映射（entry_key → verthys_id）反查条目键。删除后记录 ID 不复用，
/// 按 ID 释放不会误伤仍存活的导入项。
#[tauri::command]
pub async fn verthys_forget_import_keys(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    entry_keys: Vec<String>,
    record_ids: Option<Vec<u64>>,
) -> Result<VerthysResponse, String> {
    if let Err(msg) = require_unlocked(&app, &state, cmd::FORGET_IMPORT_KEYS) {
        return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, &msg));
    }
    let mut ids: Vec<u64> = record_ids.unwrap_or_default();
    ids.retain(|id| *id > 0);
    ids.sort_unstable();
    ids.dedup();
    if entry_keys.is_empty() && ids.is_empty() {
        return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, "条目键列表不能为空"));
    }
    if entry_keys
        .iter()
        .any(|h| h.is_empty() || h.len() > crate::constants::import_writer::MAX_RECORD_HASH_LEN)
    {
        return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, "条目键格式非法"));
    }

    // 活跃会话：墓碑必须经单写者 FIFO 落盘（与会话批量写入共用同一
    // WAL 文件句柄），命令层直接以第二句柄追加会与写者线程并发写
    // 同一文件，存在 JSON 行交错损坏风险
    if state.has_import_session() {
        let writer = match import_writer::ensure(&app) {
            Ok(w) => w,
            Err(e) => {
                log::error!("[verthys_forget_import_keys] 写者不可用: {}", e);
                return Ok(VerthysResponse::err(
                    cmd::FORGET_IMPORT_KEYS,
                    &format!("写入通道不可用: {}", e),
                ));
            }
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let cmd = WriterCommand::AppendRemoved {
            keys: entry_keys.clone(),
            record_ids: ids.clone(),
            reply: reply_tx,
        };
        if let Err(e) = submit_writer_cmd(&writer, cmd, reply_rx).await {
            log::error!("[verthys_forget_import_keys] 墓碑写入失败: {}", e);
            return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, &e));
        }

        log::info!(
            "[verthys_forget_import_keys] 墓碑已落盘: {} 条目键 + {} 记录 ID（经写者通道，会话内即时移除）",
            entry_keys.len(),
            ids.len()
        );

        let mut resp = VerthysResponse::ok(cmd::FORGET_IMPORT_KEYS);
        resp.processed_count = Some(entry_keys.len() as u64);
        return Ok(resp);
    }

    // 无活跃会话：不存在并发写者，直接以单句柄追加墓碑（原有快速路径）
    let vpath = match state.verthys_session_path() {
        Some(p) => p,
        None => {
            return Ok(VerthysResponse::err(
                cmd::FORGET_IMPORT_KEYS,
                "无法确定加密库路径，请先解锁",
            ));
        }
    };

    let vpath_clone = vpath.clone();
    let entry_keys_clone = entry_keys.clone();
    let ids_clone = ids.clone();
    let write_result = tokio::time::timeout(
        WRITER_SEND_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            // 记录 ID → 条目键：meta 不可解密时仍可释放续传幂等锁
            let resolved = verthys_wal::keys_for_ids(&vpath_clone, &ids_clone)?;
            let mut all_keys = entry_keys_clone;
            all_keys.extend(resolved);
            all_keys.sort_unstable();
            all_keys.dedup();
            verthys_wal::append_removed(&vpath_clone, &all_keys)?;
            Ok::<usize, String>(all_keys.len())
        }),
    )
    .await;

    let released = match write_result {
        Err(_) => {
            log::error!("[verthys_forget_import_keys] 墓碑写入超时");
            return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, "去重锁释放超时"));
        }
        Ok(Err(e)) => {
            log::error!("[verthys_forget_import_keys] 墓碑写入任务异常: {}", e);
            return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, "去重锁释放失败"));
        }
        Ok(Ok(Err(e))) => {
            log::error!("[verthys_forget_import_keys] 墓碑写入失败: {}", e);
            return Ok(VerthysResponse::err(cmd::FORGET_IMPORT_KEYS, &e));
        }
        Ok(Ok(Ok(n))) => n,
    };

    log::info!(
        "[verthys_forget_import_keys] 墓碑已落盘: {} 条目键（无活跃会话，恢复期生效）",
        released
    );

    let mut resp = VerthysResponse::ok(cmd::FORGET_IMPORT_KEYS);
    resp.processed_count = Some(released as u64);
    Ok(resp)
}

/* ------------------------------------------------------------------ *
 * 命令：verthys_gc_orphan_chunks                                       *
 * ------------------------------------------------------------------ */

/// 孤儿外置块 GC：删除台账中 owner=0（未被任何 meta 引用）的块记录。
///
/// 大文件照片先以外置块（独立记录）上传，上传成功即记账 owner=0；随后
/// meta 记录入库时把引用块的 owner 改写为 meta id。若上传后、meta 入库
/// 前发生崩溃或导入中断，这些块记录残留且无引用，即为孤儿。
///
/// 流程：
///   1. 数据域解锁态闸门 + 活跃导入会话检查（会话期间台账驻留内存，
///      文件视图滞后，禁止 GC）；
///   2. spawn_blocking 内：结算块归属（依据 WAL 归属声明改写台账、冻结
///      无法证明归属的历史条目）→ 加载台账 → 取 garbage_ids()；
///   3. 空列表直接返回 ok（processed_count=0）；
///   4. 非空：经 worker delete_records 逐个删除，!ok 即 err（不删台账）；
///   5. 删除成功后从台账移除各垃圾 id 并落盘（落盘失败也 err，但记录已删，
///      下次 GC 重试收敛，语义无害）。
///
/// 结算失败即拒绝本次回收：台账若可能把已被引用的块判为孤儿，宁可暂缓
/// 回收也不得删除。
///
/// 返回 processed_count = 实际回收的块记录数。
#[tauri::command]
pub async fn verthys_gc_orphan_chunks(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    // 数据域统一解锁态闸门：未解锁直接拒绝（审计 Denied 已写入）
    if let Err(msg) = require_unlocked(&app, &state, cmd::GC_ORPHAN_CHUNKS) {
        return Ok(VerthysResponse::err(cmd::GC_ORPHAN_CHUNKS, &msg));
    }

    // 活跃会话期间台账驻留会话内存，磁盘台账文件视图滞后，禁止 GC
    if state.has_import_session() {
        log::warn!("[verthys_gc_orphan_chunks] 存在活跃导入会话，拒绝 GC");
        return Ok(VerthysResponse::err(
            cmd::GC_ORPHAN_CHUNKS,
            "存在活跃导入会话，请先结束导入",
        ));
    }

    let vpath = match state.verthys_session_path() {
        Some(p) => p,
        None => {
            return Ok(VerthysResponse::err(
                cmd::GC_ORPHAN_CHUNKS,
                "无法确定加密库路径，请先解锁",
            ));
        }
    };

    let gc_vpath = vpath.clone();
    let gc_app = app.clone();
    // 单次 GC 的整体超时上界：覆盖删除命令的最大超时 + 台账结算/落盘余量
    let gc_timeout =
        delete_batch_timeout(usize::MAX).saturating_add(std::time::Duration::from_secs(30));

    let outcome = tokio::time::timeout(
        gc_timeout,
        tauri::async_runtime::spawn_blocking(move || -> Result<u64, String> {
            // 结算必须先于台账读取：崩溃窗口内记录已提交而台账尚未改写归属，
            // 直接按台账回收会删掉仍被引用的块。结算失败即放弃本次回收。
            let settlement = crate::repository::verthys_wal::settle_chunk_owners(&gc_vpath)
                .map_err(|e| format!("块归属结算失败，放弃回收: {}", e))?;
            if settlement.changed() {
                log::info!(
                    "[verthys_gc_orphan_chunks] 回收前结算: 归属改写={} 冻结={}",
                    settlement.settled,
                    settlement.frozen
                );
            }

            let mut ledger = crate::repository::verthys_chunks::load_chunk_ledger(&gc_vpath)?;
            let garbage = ledger.garbage_ids();
            if garbage.is_empty() {
                return Ok(0);
            }

            let removed = garbage.len() as u64;
            let req = serde_json::json!({"op": "delete_records", "ids": garbage.clone()});
            let state = gc_app.state::<AppState>();
            let resp_json = state
                .send_with_timeout(&req.to_string(), delete_batch_timeout(garbage.len()))
                .map_err(|e| format!("worker 通信失败: {}", e))?;
            let resp: VerthysResponse = serde_json::from_str(&resp_json)
                .map_err(|e| format!("delete_records 响应解析失败: {}", e))?;
            if !resp.ok {
                return Err(format!("delete_records 失败: {:?}", resp.error));
            }

            // 删除成功后从台账移除垃圾条目；落盘失败也回 err，但块已删除，
            // 台账下次 GC 会重试收敛，无害。
            for id in &garbage {
                ledger.remove(id);
            }
            if let Err(e) = crate::repository::verthys_chunks::save_chunk_ledger(&gc_vpath, &ledger)
            {
                return Err(format!(
                    "块已删除但台账未收敛（下次 GC 会重试，无害）: {}",
                    e
                ));
            }
            Ok(removed)
        }),
    )
    .await;

    match outcome {
        Err(_) => {
            log::error!("[verthys_gc_orphan_chunks] GC 超时");
            Ok(VerthysResponse::err(
                cmd::GC_ORPHAN_CHUNKS,
                "孤儿块回收超时，请重试",
            ))
        }
        Ok(Err(e)) => {
            log::error!("[verthys_gc_orphan_chunks] GC 任务异常: {}", e);
            Ok(VerthysResponse::err(
                cmd::GC_ORPHAN_CHUNKS,
                "孤儿块回收失败",
            ))
        }
        Ok(Ok(Err(e))) => {
            log::error!("[verthys_gc_orphan_chunks] GC 失败: {}", e);
            Ok(VerthysResponse::err(cmd::GC_ORPHAN_CHUNKS, &e))
        }
        Ok(Ok(Ok(removed))) => {
            log::info!("[verthys_gc_orphan_chunks] 已回收 {} 个孤儿块", removed);
            let mut resp = VerthysResponse::ok(cmd::GC_ORPHAN_CHUNKS);
            resp.processed_count = Some(removed);
            Ok(resp)
        }
    }
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

    log::info!("[verthys_import_end] 结束导入会话: success={}", success);

    // 快速失败：无活跃会话（权威判定在写者线程内持会话锁复核）
    if !state.has_import_session() {
        log::warn!("[verthys_import_end] 无活跃导入会话");
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

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_session_busy_response_carries_stable_code() {
        // 会话冲突码为前端控制流契约（清藏冲突确认 / 照片引导文案）：
        // 码值与序列化形态必须稳定，文案仅作展示
        let resp = import_session_busy_response();
        assert!(!resp.ok);
        assert_eq!(resp.error_code.as_deref(), Some("E_IMPORT_SESSION_BUSY"));
        assert_eq!(
            resp.error.as_deref(),
            Some("已有导入会话进行中，请先结束当前会话")
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"error_code\":\"E_IMPORT_SESSION_BUSY\""));
    }

    #[test]
    fn test_generate_import_id_unique() {
        let id1 = generate_import_id();
        let id2 = generate_import_id();
        assert!(id1.starts_with("imp-"));
        assert!(id2.starts_with("imp-"));
        // 即使同一毫秒，随机后缀也应使两者不同
        assert_ne!(id1, id2, "import_id 应全局唯一");
    }

    #[test]
    fn test_batch_record_input_deserialize() {
        let json = r#"{"rtype":1,"name":"meta_a.jpg","entry_key":"abcd1234","data_b64":"base64data"}"#;
        let rec: BatchRecordInput = serde_json::from_str(json).unwrap();
        assert_eq!(rec.rtype, 1);
        assert_eq!(rec.name, "meta_a.jpg");
        assert_eq!(rec.entry_key, "abcd1234");
        assert_eq!(rec.data_b64, "base64data");
    }

    #[test]
    fn test_import_batch_progress_serialize() {
        let p = ImportBatchProgress {
            batch_id: 1,
            processed_in_batch: 5,
            total_in_batch: 10,
            total_committed: 100,
            total_skipped: 3,
            elapsed_ms: 1234,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"batch_id\":1"));
        assert!(json.contains("\"total_committed\":100"));
    }

    #[test]
    fn test_command_name_constants_match_registered_commands() {
        // 命令名常量必须与 Tauri 命令注册名逐字一致（授权闸门审计口径依赖）。
        assert_eq!(cmd::IMPORT_BEGIN, "verthys_import_begin");
        assert_eq!(cmd::ADD_RECORDS_BATCH, "verthys_add_records_batch");
        assert_eq!(cmd::IMPORT_CHECKPOINT, "verthys_import_checkpoint");
        assert_eq!(cmd::IMPORT_END, "verthys_import_end");
    }
}
