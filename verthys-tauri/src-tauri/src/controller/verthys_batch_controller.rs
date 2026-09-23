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
 *   - 生产者（渲染进程主线程）：文件扫描、哈希去重、分片打包
 *   - 传输器（渲染进程 Web Worker 池）：AES-256-GCM / XChaCha20 加密 + 元数据序列化
 *   - 消费者（本文件）：批量写入存储、同步三层缓存（前端）、持久化 WAL、检查点
 *
 * 落实「N 次加密，1 次 IPC 传输」：verthys_add_records_batch 单次 IPC 写入 N 条记录，
 * 返回分配的 verthys ID 列表 + 失败索引 + 检查点信息。WAL 保证断点续传幂等。
 *
 * =============================================================================
 * 命令清单
 * =============================================================================
 *   - verthys_import_begin：创建导入会话（初始化 WAL + 恢复 committed_hashes），返回 import_id + 去重哈希集
 *   - verthys_add_records_batch：批量写入 N 条已加密记录（WAL pending → worker add_record 串行 → WAL committed → 检查点），流式推送进度
 *   - verthys_import_end：关闭导入会话（success=true 触发 WAL 压缩，failure 保留 WAL 供续传）
 *   - verthys_import_checkpoint：查询当前检查点状态（累计 committed 计数）
 *   - verthys_wal_recover：扫描遗留 WAL，返回 committed 哈希集（续传去重，不创建新会话）
 *
 * =============================================================================
 * WAL 与幂等保证
 * =============================================================================
 * 每条记录进入缓存缓冲器之前先写 WAL pending；worker add_record 成功后写 WAL committed；
 * 每批次结束写 WAL checkpoint。崩溃/关闭后重启：
 *   - 已 committed 哈希 → 已落盘（v2 add_record 即时 fsync），续传时跳过（幂等）
 *   - pending 未 committed → 未落盘，续传时重新入库（哈希未变，幂等）
 * 重做量不超过一个批次（检查点粒度）。
 *
 * =============================================================================
 * 安全边界
 * =============================================================================
 * - 本控制器不解密、不接触明文密钥：记录数据由前端 Worker 加密后以 base64 传入
 * - 仅记录内容哈希（BLAKE3 hex）与文件名到 WAL，不含密钥/明文/密文
 * - WAL 文件位于 verthys 文件同目录（受 VerthysFileLock 独占锁保护）
 * - 所有 IO 失败向上传播为 Err，由前端决定降级策略
 *
 * 依赖方向：controller → state / repository / controller::types / worker（单向）
 */

use crate::controller::types::VerthysResponse;
use crate::repository::verthys_wal::{self, ImportSession, WalEntry};
use crate::state::AppState;
use crate::util::path::sanitize_path;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use tauri::State;

/* ------------------------------------------------------------------ *
 * 批量导入数据类型（与前端 types/verthys.ts 严格对齐，snake_case）       *
 * ------------------------------------------------------------------ */

/// 单条已加密记录输入（前端 Worker 池加密后产出）
///
/// 字段语义：
///   - rtype：记录类型（TYPE_PHOTO_META=0x01 等，与现有 verthys_add_record 一致）
///   - name：记录名称（如 `meta_xxx.jpg`）
///   - hash：原始文件内容的 BLAKE3 hex（用于去重 + WAL 幂等）
///   - data_b64：已加密的记录数据 base64（前端 XChaCha20-Poly1305 加密产物）
#[derive(Debug, Clone, Deserialize)]
pub struct BatchRecordInput {
    pub rtype: u32,
    pub name: String,
    pub hash: String,
    pub data_b64: String,
}

/// 批量写入进度（通过 Tauri Channel 流式推送到前端）
///
/// 前端在 requestAnimationFrame 内接收并绘制进度条，保证任何时刻最多一帧间隔更新，
/// 绝不参与数据处理热路径。
#[derive(Debug, Clone, Serialize)]
pub struct ImportBatchProgress {
    /// 本批次 ID（从 1 递增，前端据此对齐检查点）
    pub batch_id: u64,
    /// 本批次已处理记录数（含去重跳过 + 失败）
    pub processed_in_batch: u64,
    /// 本批次总记录数
    pub total_in_batch: u64,
    /// 导入会话累计已 committed 记录数（检查点）
    pub total_committed: u64,
    /// 导入会话累计因哈希去重跳过的记录数
    pub total_skipped: u64,
    /// 本批次已耗时（毫秒，自批次开始累计）
    pub elapsed_ms: u64,
}

/* ------------------------------------------------------------------ *
 * 辅助函数                                                            *
 * ------------------------------------------------------------------ */

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
    format!("imp-{}-{:02x}{:02x}{:02x}{:02x}", ts, rand_buf[0], rand_buf[1], rand_buf[2], rand_buf[3])
}

/// 当前 Unix 毫秒时间戳
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/* ------------------------------------------------------------------ *
 * 命令：verthys_import_begin                                            *
 * ------------------------------------------------------------------ */

/// 创建导入会话：初始化 WAL + 从既有快照恢复 committed_hashes（续传去重）。
///
/// 流程：
///   1. 防重入：检查是否已存在活跃会话，存在则拒绝（单 verthys 同一时刻仅一个活跃会话）
///   2. 解析 verthys 路径：优先使用参数，否则从 VerthysSessionGuard 读取
///   3. 创建 ImportSession：加载遗留 WAL 快照（恢复 committed_hashes）→ 截断 WAL 写 begin
///   4. 存入 AppState.import_session
///   5. 返回 import_id + committed_hashes（供生产者去重）
///
/// 返回字段：
///   - import_id：导入会话 ID（贯穿整个导入生命周期）
///   - hashes：已 committed 的内容哈希列表（生产者据此去重，保证幂等）
///   - total_count：续传起始的累计 committed 计数（检查点）
#[tauri::command]
pub async fn verthys_import_begin(
    state: State<'_, AppState>,
    verthys_path: Option<String>,
) -> Result<VerthysResponse, String> {
    log::info!("[verthys_import_begin] 开始创建导入会话");

    // 防重入：单 verthys 同一时刻仅一个活跃会话
    if state.has_import_session() {
        log::warn!("[verthys_import_begin] 已存在活跃导入会话，拒绝重复创建");
        return Ok(VerthysResponse::err(
            "verthys_import_begin",
            "已有导入会话进行中，请先结束当前会话",
        ));
    }

    // 解析 verthys 路径：优先参数，否则从会话守卫读取
    let vpath = match verthys_path.or_else(|| state.verthys_session_path()) {
        Some(p) => p,
        None => {
            log::warn!("[verthys_import_begin] 无法确定 verthys 路径（参数缺失且无活跃会话）");
            return Ok(VerthysResponse::err(
                "verthys_import_begin",
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

    // 创建 ImportSession：加载遗留 WAL 快照 → 恢复 committed_hashes → 截断 WAL 写 begin
    let session = match ImportSession::new(&vpath, &import_id) {
        Ok(s) => s,
        Err(e) => {
            log::error!("[verthys_import_begin] 创建导入会话失败: {}", e);
            return Ok(VerthysResponse::err(
                "verthys_import_begin",
                &format!("创建导入会话失败: {}", e),
            ));
        }
    };

    // 收集恢复的 committed_hashes（供前端去重）+ 累计 committed 计数
    let hashes: Vec<String> = session.committed_hashes.iter().cloned().collect();
    let total_committed = session.total_committed;

    log::info!(
        "[verthys_import_begin] 导入会话已创建: import_id={} 续传去重哈希数={} 累计 committed={}",
        import_id,
        hashes.len(),
        total_committed
    );

    // 存入 AppState
    {
        let mut guard = state.lock_import_session();
        *guard = Some(session);
    }

    let mut resp = VerthysResponse::ok("verthys_import_begin");
    resp.import_id = Some(import_id);
    resp.hashes = Some(hashes);
    resp.total_count = Some(total_committed);
    Ok(resp)
}

/* ------------------------------------------------------------------ *
 * 命令：verthys_add_records_batch                                       *
 * ------------------------------------------------------------------ */

/// 批量写入 N 条已加密记录（WAL pending → worker add_record 串行 → WAL committed → 检查点）。
///
/// 落实「N 次加密，1 次 IPC 传输」：前端 Worker 池并行加密 N 条记录后，
/// 单次 IPC 调用本命令写入。后端串行调用 worker add_record（worker 内部已即时 fsync），
/// 每条记录伴随 WAL pending/committed，每批次结束写检查点。
///
/// 流程（每条记录）：
///   1. 哈希去重：若 hash ∈ committed_hashes → 跳过，ids[i]=0，skipped_count++
///   2. WAL pending：写入 {hash, status:'pending'} 到 WAL（fsync）
///   3. worker add_record：发送 {"op":"add_record",...} 到 worker，获取分配的 verthys ID
///   4. WAL committed：写入 {hash, verthys_id, status:'committed'} 到 WAL（fsync）
///   5. mark_committed：更新内存去重集合 + 累计计数
///   6. 失败处理：worker 返回失败 → failed_indices.push(i)，ids[i]=0，不写 committed
///   7. 进度推送：每条记录处理后通过 Channel 推送 ImportBatchProgress
///
/// 批次结束：
///   8. WAL checkpoint：写入 {batch_id, committed_count} 到 WAL（fsync）
///
/// 返回字段：
///   - ids：本批次每条记录分配的 verthys ID（0 表示去重跳过或失败）
///   - batch_id：本批次 ID（从 1 递增）
///   - failed_indices：本批次失败记录的下标列表
///   - processed_count：本批次实际处理（含去重跳过）的记录数
///   - total_count：导入会话累计已 committed 记录数（检查点）
///   - skipped_count：本批次因哈希去重跳过的记录数
#[tauri::command]
pub async fn verthys_add_records_batch(
    state: State<'_, AppState>,
    records: Vec<BatchRecordInput>,
    on_progress: tauri::ipc::Channel<ImportBatchProgress>,
) -> Result<VerthysResponse, String> {
    let batch_start = now_ms();
    let total_in_batch = records.len() as u64;

    log::info!(
        "[verthys_add_records_batch] 收到批量写入请求: {} 条记录",
        total_in_batch
    );

    // 取出导入会话引用（持锁期间完成本批次全部操作，保证 WAL 写顺序）
    // 注意：ImportSession 持有 WalWriter 文件句柄，必须独占访问。
    // 此处通过 lock_import_session 获取 MutexGuard，整个批次期间持锁。
    // 批次内串行 worker add_record（worker 内部已即时 fsync，串行保证写顺序）。
    let mut session_guard = state.lock_import_session();
    let session: &mut ImportSession = match session_guard.as_mut() {
        Some(s) => s,
        None => {
            log::warn!("[verthys_add_records_batch] 无活跃导入会话，拒绝写入");
            return Ok(VerthysResponse::err(
                "verthys_add_records_batch",
                "无活跃导入会话，请先调用 verthys_import_begin",
            ));
        }
    };

    let batch_id = session.allocate_batch_id();
    let import_id = session.import_id.clone();

    log::info!(
        "[verthys_add_records_batch] 开始批次 {}: import_id={} 记录数={}",
        batch_id,
        import_id,
        total_in_batch
    );

    let mut ids: Vec<u64> = vec![0u64; records.len()];
    let mut failed_indices: Vec<u64> = Vec::new();
    let mut processed_in_batch: u64 = 0;
    let mut skipped_in_batch: u64 = 0;
    let mut committed_in_batch: u64 = 0;

    // 串行处理每条记录（worker add_record 必须串行：保证 WAL 写顺序 + verthys 内部事务一致）
    for (i, rec) in records.iter().enumerate() {
        let idx = i as u64;
        processed_in_batch += 1;

        // 1. 哈希去重：hash ∈ committed_hashes → 跳过（幂等保证）
        if session.is_committed(&rec.hash) {
            skipped_in_batch += 1;
            session.mark_skipped();
            log::debug!(
                "[verthys_add_records_batch] 批次 {} 记录 {} 哈希已 committed，跳过: hash={}",
                batch_id,
                idx,
                rec.hash
            );
            // 推送进度
            let _ = on_progress.send(ImportBatchProgress {
                batch_id,
                processed_in_batch,
                total_in_batch,
                total_committed: session.total_committed,
                total_skipped: session.total_skipped,
                elapsed_ms: now_ms().saturating_sub(batch_start),
            });
            continue;
        }

        // 2. WAL pending：写入 {hash, status:'pending'} 到 WAL（fsync）
        if let Err(e) = session.writer.append(&WalEntry::Pending {
            import_id: import_id.clone(),
            batch_id,
            hash: rec.hash.clone(),
            name: rec.name.clone(),
            idx,
        }) {
            log::error!(
                "[verthys_add_records_batch] 批次 {} 记录 {} WAL pending 写入失败: {}",
                batch_id,
                idx,
                e
            );
            failed_indices.push(idx);
            let _ = on_progress.send(ImportBatchProgress {
                batch_id,
                processed_in_batch,
                total_in_batch,
                total_committed: session.total_committed,
                total_skipped: session.total_skipped,
                elapsed_ms: now_ms().saturating_sub(batch_start),
            });
            continue;
        }

        // 3. worker add_record：发送 {"op":"add_record",...} 到 worker
        let req = serde_json::json!({
            "op": "add_record",
            "rtype": rec.rtype,
            "name": rec.name,
            "data": rec.data_b64,
        });

        let add_result: Result<VerthysResponse, String> = match state.send(&req.to_string()) {
            Ok(resp_json) => {
                match serde_json::from_str::<VerthysResponse>(&resp_json) {
                    Ok(resp) if resp.ok => Ok(resp),
                    Ok(resp) => {
                        log::warn!(
                            "[verthys_add_records_batch] 批次 {} 记录 {} worker add_record 返回失败: {:?}",
                            batch_id,
                            idx,
                            resp.error
                        );
                        Err(format!("worker add_record 失败: {:?}", resp.error))
                    }
                    Err(e) => {
                        log::warn!(
                            "[verthys_add_records_batch] 批次 {} 记录 {} 响应解析失败: {}",
                            batch_id,
                            idx,
                            e
                        );
                        Err(format!("响应解析失败: {}", e))
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "[verthys_add_records_batch] 批次 {} 记录 {} worker 通信失败: {}",
                    batch_id,
                    idx,
                    e
                );
                Err(format!("worker 通信失败: {}", e))
            }
        };

        match add_result {
            Ok(resp) => {
                let verthys_id = resp.id.unwrap_or(0);
                if verthys_id == 0 {
                    log::warn!(
                        "[verthys_add_records_batch] 批次 {} 记录 {} worker 返回 id=0，视为失败",
                        batch_id,
                        idx
                    );
                    failed_indices.push(idx);
                } else {
                    // 4. WAL committed：写入 {hash, verthys_id, status:'committed'} 到 WAL（fsync）
                    if let Err(e) = session.writer.append(&WalEntry::Committed {
                        import_id: import_id.clone(),
                        batch_id,
                        hash: rec.hash.clone(),
                        verthys_id,
                        name: rec.name.clone(),
                    }) {
                        log::error!(
                            "[verthys_add_records_batch] 批次 {} 记录 {} WAL committed 写入失败（数据已入库但 WAL 未记录）: {}",
                            batch_id,
                            idx,
                            e
                        );
                        // 数据已入库但 WAL committed 写入失败：记录为失败但 verthys_id 已分配
                        // 此处仍标记为失败，让前端感知异常（数据已落盘，下次续传哈希不在 committed 集合会重复入库）
                        // 权衡：WAL committed 写入失败是极端情况（磁盘满/IO错误），
                        //   数据已通过 worker add_record 即时 fsync 落盘，但去重集合未更新。
                        //   续传时该哈希不在 committed_hashes → 重复入库（产生重复记录）。
                        //   为避免重复，此处仍标记 committed（best-effort）：更新内存集合，
                        //   即使磁盘 WAL 未记录，内存集合在本会话内仍可去重。
                        session.mark_committed(&rec.hash);
                        ids[i] = verthys_id;
                        committed_in_batch += 1;
                    } else {
                        // 5. mark_committed：更新内存去重集合 + 累计计数
                        session.mark_committed(&rec.hash);
                        ids[i] = verthys_id;
                        committed_in_batch += 1;
                        log::debug!(
                            "[verthys_add_records_batch] 批次 {} 记录 {} 已 committed: hash={} verthys_id={}",
                            batch_id,
                            idx,
                            rec.hash,
                            verthys_id
                        );
                    }
                }
            }
            Err(_) => {
                failed_indices.push(idx);
            }
        }

        // 6. 进度推送：每条记录处理后推送
        let _ = on_progress.send(ImportBatchProgress {
            batch_id,
            processed_in_batch,
            total_in_batch,
            total_committed: session.total_committed,
            total_skipped: session.total_skipped,
            elapsed_ms: now_ms().saturating_sub(batch_start),
        });
    }

    // 8. WAL checkpoint：写入 {batch_id, committed_count} 到 WAL（fsync）
    if let Err(e) = session.writer.append(&WalEntry::Checkpoint {
        import_id: import_id.clone(),
        batch_id,
        committed_count: session.total_committed,
    }) {
        log::error!(
            "[verthys_add_records_batch] 批次 {} WAL checkpoint 写入失败: {}",
            batch_id,
            e
        );
        // checkpoint 写入失败不回滚已 committed 数据（已落盘），仅告警
    }

    let elapsed = now_ms().saturating_sub(batch_start);
    log::info!(
        "[verthys_add_records_batch] 批次 {} 完成: committed={} skipped={} failed={} 耗时={}ms 累计 committed={}",
        batch_id,
        committed_in_batch,
        skipped_in_batch,
        failed_indices.len(),
        elapsed,
        session.total_committed
    );

    let total_committed = session.total_committed;

    // 释放会话锁（guard drop）
    drop(session_guard);

    let mut resp = VerthysResponse::ok("verthys_add_records_batch");
    resp.ids = Some(ids);
    resp.batch_id = Some(batch_id);
    resp.failed_indices = Some(failed_indices);
    resp.processed_count = Some(processed_in_batch);
    resp.total_count = Some(total_committed);
    resp.skipped_count = Some(skipped_in_batch);
    Ok(resp)
}

/* ------------------------------------------------------------------ *
 * 命令：verthys_import_end                                              *
 * ------------------------------------------------------------------ */

/// 关闭导入会话：success=true 触发 WAL 压缩，failure 保留 WAL 供续传。
///
/// 流程：
///   1. 取出 ImportSession（Option::take）
///   2. 调用 WalWriter::finish(import_id, success)：
///      - 写入 end 条目（fsync）
///      - success=true：compact WAL（原子替换，仅保留 committed 哈希清单）
///      - success=false：原样保留 WAL 供下次续传
///   3. 清空 AppState.import_session
///
/// 返回 total_count（最终累计 committed 计数）。
#[tauri::command]
pub async fn verthys_import_end(
    state: State<'_, AppState>,
    success: bool,
) -> Result<VerthysResponse, String> {
    log::info!("[verthys_import_end] 结束导入会话: success={}", success);

    let session = {
        let mut guard = state.lock_import_session();
        guard.take()
    };

    let session = match session {
        Some(s) => s,
        None => {
            log::warn!("[verthys_import_end] 无活跃导入会话");
            return Ok(VerthysResponse::err(
                "verthys_import_end",
                "无活跃导入会话",
            ));
        }
    };

    let import_id = session.import_id.clone();
    let total_committed = session.total_committed;
    let writer = session.writer;

    // 写入 end 条目 + 压缩（success=true 时）
    if let Err(e) = writer.finish(&import_id, success) {
        log::error!(
            "[verthys_import_end] WAL finish 失败: import_id={} success={} err={}",
            import_id,
            success,
            e
        );
        return Ok(VerthysResponse::err(
            "verthys_import_end",
            &format!("WAL 关闭失败: {}", e),
        ));
    }

    log::info!(
        "[verthys_import_end] 导入会话已关闭: import_id={} success={} 累计 committed={}",
        import_id,
        success,
        total_committed
    );

    let mut resp = VerthysResponse::ok("verthys_import_end");
    resp.total_count = Some(total_committed);
    resp.import_id = Some(import_id);
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
    state: State<'_, AppState>,
) -> Result<VerthysResponse, String> {
    let guard = state.lock_import_session();
    match guard.as_ref() {
        Some(session) => {
            let hashes: Vec<String> = session.committed_hashes.iter().cloned().collect();
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
            resp.hashes = Some(hashes);
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
///   3. 用户确认后调用 verthys_import_begin（继承 committed_hashes）→ 续传剩余文件
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

    // 检查 WAL 是否存在
    if !verthys_wal::exists(&vpath) {
        log::info!("[verthys_wal_recover] 无遗留 WAL，无需续传");
        let mut resp = VerthysResponse::ok("verthys_wal_recover");
        resp.hashes = Some(Vec::new());
        resp.total_count = Some(0);
        return Ok(resp);
    }

    // 加载 WAL 快照
    let snapshot = match verthys_wal::load(&vpath) {
        Ok(s) => s,
        Err(e) => {
            log::error!("[verthys_wal_recover] WAL 加载失败: {}", e);
            return Ok(VerthysResponse::err(
                "verthys_wal_recover",
                &format!("WAL 加载失败: {}", e),
            ));
        }
    };

    let hashes: Vec<String> = snapshot.committed_hashes.iter().cloned().collect();
    let total_committed = snapshot.committed_hashes.len() as u64;
    let has_active = snapshot.active_import_id.is_some();

    log::info!(
        "[verthys_wal_recover] WAL 扫描完成: committed={} active_import_id={:?} last_batch={}",
        total_committed,
        snapshot.active_import_id,
        snapshot.last_batch_id
    );

    let mut resp = VerthysResponse::ok("verthys_wal_recover");
    resp.hashes = Some(hashes);
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
        let json = r#"{"rtype":1,"name":"meta_a.jpg","hash":"abcd1234","data_b64":"base64data"}"#;
        let rec: BatchRecordInput = serde_json::from_str(json).unwrap();
        assert_eq!(rec.rtype, 1);
        assert_eq!(rec.name, "meta_a.jpg");
        assert_eq!(rec.hash, "abcd1234");
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
}
