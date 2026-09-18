/* dispatch.rs — 请求派发
 *
 * 职责：
 *   - probe_global_key_inproc（解锁成功后进程内探测全局主密钥记录）
 *   - handle_request（大型 match 派发器）
 *
 * 依赖：crate::log::diag、worker::Worker、protocol、ffi_types::VERTHYS_OK、gmk::handle_*。
 * 被引用方：main_loop.rs（handle_request）。
 */

use crate::log::diag;
use crate::runtime::worker::Worker;
use crate::runtime::protocol::{Request, Response, RecordEntry, base64_encode, base64_decode};
use crate::runtime::ffi_types::VERTHYS_OK;
use crate::runtime::gmk::{
    handle_derive_global_key, handle_verify_global_key, handle_derive_module_subkey,
    handle_clear_global_key,
};

/* ------------------------------------------------------------------ *
 * ★ 企业级根治方案：解锁成功后进程内探测全局主密钥记录                  *
 *                                                                    *
 * 原缺陷：解锁成功后前端需发起 3~4 次 IPC 往返                        *
 *   (verthysHasRecordByType → findLidByTypeEarlyStop → verthysGetRecord) *
 * 才能判断是否存在全局主密钥记录并取回数据。该链路存在两类致命问题：   *
 *   1. v1 容器：Verthys_HasRecordByType 返回 VERTHYS_ERR_FORMAT 假阴性，  *
 *      前端 probe 抛异常 → globalKeyRecordLoadingRef 永驻 true        *
 *      → UI 卡死在 "loading" 视图，无法进入身份验证窗口               *
 *   2. IPC 竞态：多次往返任意一环超时/失败均导致 initUnlock 永不完成   *
 *                                                                    *
 * 根治策略：将探测逻辑下沉到 worker 解锁成功分支进程内一次性完成，     *
 * 结果内联到 unlock 响应的 has_global_key/global_key_id/              *
 * global_key_record 三字段，彻底消除前端 IPC 链路。                   *
 *                                                                    *
 * 健壮性契约（前端据此决策，无需再发 probe）：                        *
 *   - Some(true),  Some(lid), Some(b64) → 命中且读取成功              *
 *   - Some(true),  Some(lid), None      → 命中 lid 但读取失败         *
 *                                            （前端按 id 自取 record） *
 *   - Some(false), None,      None      → 确认无全局密钥记录          *
 *   - None,        None,      None      → 探测异常，前端回退 probe    *
 * ------------------------------------------------------------------ */
pub(crate) fn probe_global_key_inproc(
    worker: &Worker,
) -> (Option<bool>, Option<u64>, Option<String>) {
    /* TYPE_GLOBAL_KEY = 0x10，与前端 constants/key_manager_const.ts 对齐 */
    const TYPE_GLOBAL_KEY: u8 = 0x10;

    let (rc, found, lid) = worker.call_find_first_lid_by_type(TYPE_GLOBAL_KEY);
    if rc != VERTHYS_OK {
        diag!(
            "[worker] probe_global_key: find_first_lid 失败 rc={:08X}，前端回退 probe",
            rc
        );
        return (None, None, None);
    }
    if !found {
        diag!("[worker] probe_global_key: 确认无全局密钥记录（v1/v2 全遍历确认）");
        return (Some(false), None, None);
    }
    diag!("[worker] probe_global_key: 命中全局密钥记录 lid={}", lid);
    match worker.call_get_record(lid) {
        Ok((_rtype, _name, data)) => {
            let b64 = base64_encode(&data);
            diag!(
                "[worker] probe_global_key: 读取记录成功 ({} bytes → b64 {})",
                data.len(),
                b64.len()
            );
            (Some(true), Some(lid), Some(b64))
        }
        Err(e) => {
            diag!(
                "[worker] probe_global_key: 读取记录失败 rc={:08X}，前端按 id 自取",
                e
            );
            let _ = &e; /* release 下 diag! 为空操作，显式消费 e */
            (Some(true), Some(lid), None)
        }
    }
}

/* ------------------------------------------------------------------ *
 * 请求处理                                                            *
 * ------------------------------------------------------------------ */

pub(crate) fn handle_request(worker: &mut Worker, req: &Request) -> Response {
    diag!("[worker] 处理请求: op={}", req.op);
    match req.op.as_str() {
        "ping" => Response::ok("ping"),
        "unlock" => {
            /* ★ 方案九：透传 flags（预热状态位域）给 C 层 Verthys_Unlock */
            /* ★ E-8（WP-5 渐进式解锁）：VERTHYS_ERR_PARTIAL_UNLOCK 表示容器已进入
             * 最小可操作状态（超级块验证 + 密钥导入 + 分区表加载完成，索引
             * 预热后台进行中），与 verthys_api.c Unlock 成功分支语义一致——
             * 按成功处理，正常执行 GMK 探测并返回。 */
            const VERTHYS_ERR_PARTIAL_UNLOCK: u32 = 0x00000011;
            let r = worker.call_unlock(&req.path, &req.password, req.flags);
            if r == VERTHYS_OK || r == VERTHYS_ERR_PARTIAL_UNLOCK {
                /* ★ 企业级根治方案：解锁成功后进程内探测全局主密钥记录，
                 * 结果内联到响应三字段，消除前端 IPC 链路与 v1 假阴性死锁。 */
                let (has_gmk, gmk_id, gmk_record) = probe_global_key_inproc(worker);
                Response {
                    has_global_key: has_gmk,
                    global_key_id: gmk_id,
                    global_key_record: gmk_record,
                    ..Response::ok("unlock")
                }
            } else {
                /* ★ 企业级修复（D-STATE-RECOVERY）：级联 INVALID 状态恢复
                 *
                 * 场景：前一次解锁因 stdout 死锁导致父进程 60 秒超时退出，
                 * 但 worker 进程仍在运行且 Verthys_Unlock FFI 已成功完成，
                 * ctx->state 停留在 VERTHYS_STATE_UNLOCKED。后续解锁请求调用
                 * Verthys_Unlock 时命中 `if (ctx->state == VERTHYS_STATE_UNLOCKED)
                 * return VERTHYS_ERR_INVALID` 立即失败。
                 *
                 * 恢复策略：检测到 INVALID 时先调用 Verthys_Lock（将状态从
                 * UNLOCKED 切换到 LOCKED），再重试 Verthys_Unlock。仅当 verthys
                 * 确实处于 UNLOCKED 状态时 Lock 才会成功，其他 INVALID 原因
                 * （handle NULL / path NULL）Lock 也会失败，不影响安全语义。 */
                const VERTHYS_ERR_INVALID: u32 = 0x00000001;
                if r == VERTHYS_ERR_INVALID {
                    diag!("[worker] unlock 返回 INVALID，尝试状态恢复（lock → retry unlock）");
                    let lock_r = worker.call_lock();
                    diag!("[worker] 状态恢复 lock 返回: {:08X}", lock_r);
                    if lock_r == VERTHYS_OK {
                        let r2 = worker.call_unlock(&req.path, &req.password, req.flags);
                        diag!("[worker] 状态恢复 retry unlock 返回: {:08X}", r2);
                        if r2 == VERTHYS_OK || r2 == VERTHYS_ERR_PARTIAL_UNLOCK {
                            let (has_gmk, gmk_id, gmk_record) =
                                probe_global_key_inproc(worker);
                            return Response {
                                has_global_key: has_gmk,
                                global_key_id: gmk_id,
                                global_key_record: gmk_record,
                                ..Response::ok("unlock")
                            };
                        }
                        return Response::err("unlock", r2);
                    }
                }
                Response::err("unlock", r)
            }
        }
        "create_with_preset" => {
            diag!("[worker] call_create_with_preset: path={} preset={}", req.path, req.preset);
            let r = worker.call_create_with_preset(&req.path, &req.password, req.preset);
            diag!("[worker] create_with_preset 返回: {:08X}", r);
            if r == VERTHYS_OK {
                Response::ok("create_with_preset")
            } else {
                /* ★ 企业级修复（D-STATE-RECOVERY）：级联 INVALID 状态恢复
                 *
                 * 与 unlock 对称：前一次操作可能将 ctx->state 停留在 UNLOCKED，
                 * 导致 Verthys_CreateWithPreset 命中 `if (ctx->state ==
                 * VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID`。
                 * 先 Lock 再重试 create_with_preset。 */
                const VERTHYS_ERR_INVALID: u32 = 0x00000001;
                if r == VERTHYS_ERR_INVALID {
                    diag!("[worker] create_with_preset 返回 INVALID，尝试状态恢复（lock → retry）");
                    let lock_r = worker.call_lock();
                    diag!("[worker] 状态恢复 lock 返回: {:08X}", lock_r);
                    if lock_r == VERTHYS_OK {
                        let r2 = worker.call_create_with_preset(&req.path, &req.password, req.preset);
                        diag!("[worker] 状态恢复 retry create 返回: {:08X}", r2);
                        if r2 == VERTHYS_OK {
                            return Response::ok("create_with_preset");
                        }
                        return Response::err("create_with_preset", r2);
                    }
                }
                Response::err("create_with_preset", r)
            }
        }
        "lock" => {
            diag!("[worker] call_lock");
            let r = worker.call_lock();
            diag!("[worker] lock 返回: {:08X}", r);
            if r == VERTHYS_OK {
                Response::ok("lock")
            } else {
                Response::err("lock", r)
            }
        }
        // ★ 企业级根治：Verthys_Flush 显式刷盘
        //   替代旧 verthys_flush 的 lock+unlock 模式。
        //   旧模式缺陷：lock 清零密钥 + state=LOCKED，若 unlock 超时/失败，
        //   worker 永久卡在 LOCKED 状态，所有后续 get_record 返回 VERTHYS_ERR_LOCKED，
        //   前端照片全部无法读取（表现为"照片损坏/元数据丢失"）。
        //   Verthys_Flush 不改变 state、不清零密钥，安全且高效。
        "flush" => {
            diag!("[worker] call_flush");
            let r = worker.call_flush();
            diag!("[worker] flush 返回: {:08X}", r);
            if r == VERTHYS_OK {
                Response::ok("flush")
            } else {
                Response::err("flush", r)
            }
        }
        "add_record" => {
            let data = match base64_decode(&req.data) {
                Ok(d) => d,
                Err(_) => {
                    return Response {
                        ok: false,
                        op: "add_record".into(),
                        error: Some("base64 decode failed".into()),
                        ..Response::ok("add_record")
                    }
                }
            };
            match worker.call_add_record(req.rtype, &req.name, &data) {
                Ok(id) => Response {
                    ok: true,
                    op: "add_record".into(),
                    id: Some(id),
                    ..Response::ok("add_record")
                },
                Err(code) => Response::err("add_record", code),
            }
        }
        "get_record" => match worker.call_get_record(req.id) {
            Ok((rtype, name, data)) => Response {
                ok: true,
                op: "get_record".into(),
                rtype: Some(rtype),
                name: Some(name),
                data: Some(base64_encode(&data)),
                ..Response::ok("get_record")
            },
            Err(code) => Response::err("get_record", code),
        },
        "enumerate_records" => {
            // 批量枚举记录：从 start_id 开始顺序读取，连续 5 次 NOTFOUND 停止
            // 整个循环在 worker 子进程内完成，消除 N 次 IPC 往返开销
            //
            // ★ 项5：分页支持（数据流式传输，消除 JSON 解析阻塞）
            //   - req.rtype > 0 表示 max_count（本批最多返回条数）
            //   - req.rtype == 0 表示不限制（兼容旧调用，全量枚举）
            //   - 返回 exhausted=true 表示已遍历完毕（null_streak >= 5 或到达 100_000）
            //   - 返回 id 字段为本批最后一条记录的 ID（前端据此发起下一批 start_id）
            //   - 返回 record_count 字段为本批实际返回条数
            // 前端可循环调用本 op 实现流式分页加载（每批 50~200 条），
            // 每批 JSON 体积小，JSON.parse 耗时 < 5ms，主线程不阻塞。
            let start_id = if req.id > 0 { req.id } else { 1 };
            let max_count: usize = if req.rtype > 0 { req.rtype as usize } else { usize::MAX };
            let mut records: Vec<RecordEntry> = Vec::with_capacity(max_count.min(500));
            let mut null_streak: u32 = 0;
            let mut last_id: u64 = start_id.saturating_sub(1);
            let mut exhausted = false;

            for id in start_id..=100_000 {
                if records.len() >= max_count {
                    // 已达本批上限，停止枚举（未遍历完毕，exhausted=false）
                    break;
                }
                match worker.call_get_record(id) {
                    Ok((rtype, name, data)) => {
                        null_streak = 0;
                        last_id = id;
                        records.push(RecordEntry {
                            id,
                            rtype,
                            name,
                            data: base64_encode(&data),
                        });
                    }
                    Err(_) => {
                        null_streak += 1;
                        if null_streak >= 5 {
                            // 连续 5 次未找到记录，认为已遍历完毕
                            exhausted = true;
                            break;
                        }
                    }
                }
            }
            // 到达上限 100_000 也视为遍历完毕
            if last_id >= 100_000 {
                exhausted = true;
            }
            // 若未指定 max_count（全量模式）且未触发 null_streak 终止，
            // 但 records 非空且 last_id < 100_000，说明循环正常结束（理论上不会发生，
            // 因为 for 循环会一直跑到 100_000），此处兜底标记 exhausted。
            if max_count == usize::MAX && !exhausted {
                exhausted = true;
            }

            let count = records.len() as u64;
            Response {
                ok: true,
                op: "enumerate_records".into(),
                id: Some(last_id),
                records: Some(records),
                exhausted: Some(exhausted),
                record_count: Some(count),
                ..Response::ok("enumerate_records")
            }
        }
        "scan_open" => {
            // 打开扫描游标：创建共享内存 + 复用 vbtree_scan_all + 首批预加载
            let start_lid = if req.id > 0 { req.id } else { 0 };
            let batch_size = if req.rtype > 0 { req.rtype as u64 } else { 500 };
            match worker.call_scan_open(start_lid, batch_size) {
                Ok((shm_name, shm_size, count, exhausted)) => Response {
                    ok: true,
                    op: "scan_open".into(),
                    exhausted: Some(exhausted),
                    shm_name: Some(shm_name),
                    shm_size: Some(shm_size as u64),
                    record_count: Some(count as u64),
                    ..Response::ok("scan_open")
                },
                Err(code) => Response::err("scan_open", code),
            }
        }
        "scan_fetch" => {
            // 批量拉取记录：游标驱动遍历器填充共享内存缓冲区，不重复定位
            let max_count = if req.id > 0 { req.id } else { 500 };
            match worker.call_scan_fetch(max_count) {
                Ok((count, exhausted)) => Response {
                    ok: true,
                    op: "scan_fetch".into(),
                    exhausted: Some(exhausted),
                    record_count: Some(count as u64),
                    ..Response::ok("scan_fetch")
                },
                Err(code) => Response::err("scan_fetch", code),
            }
        }
        "scan_close" => {
            // 关闭扫描游标：销毁共享内存 + 释放遍历句柄/快照
            let _ = worker.call_scan_close();
            Response::ok("scan_close")
        }
        // 第 2.1 项：scan_abort — 取消扫描并回滚游标
        // 主进程在 CancellationToken 触发时发送，语义为"取消并回滚"。
        // 当前 worker 端 call_scan_close 已完成回滚（销毁 SHM + 关闭 C 游标），
        // scan_abort 与 scan_close 调用同一底层方法，但语义独立便于审计与未来扩展
        // （如 abort 时记录中断原因、回滚未提交事务等）。
        "scan_abort" => {
            // 取消扫描游标：销毁共享内存 + 回滚遍历句柄
            let _ = worker.call_scan_close();
            Response::ok("scan_abort")
        }
        // ===== 摘要扫描（Phase 2B：轻量元数据，不读数据块）=====
        "scan_summary_open" => {
            // 打开摘要扫描游标：创建 4MB 共享内存 + Verthys_ScanSummaryOpen + 首批预加载
            // 返回 shm_name 供 Tauri 主进程读取摘要记录（read_shm_summary_records）
            let start_lid = if req.id > 0 { req.id } else { 0 };
            let batch_size = if req.rtype > 0 { req.rtype as u64 } else { 1000 };
            match worker.call_scan_summary_open(start_lid, batch_size) {
                Ok((shm_name, shm_size, count, exhausted)) => Response {
                    ok: true,
                    op: "scan_summary_open".into(),
                    exhausted: Some(exhausted),
                    shm_name: Some(shm_name),
                    shm_size: Some(shm_size as u64),
                    record_count: Some(count as u64),
                    ..Response::ok("scan_summary_open")
                },
                Err(code) => Response::err("scan_summary_open", code),
            }
        }
        "scan_summary_fetch" => {
            // 批量拉取摘要记录：游标驱动遍历器填充共享内存缓冲区（72B 条目，无数据块）
            let max_count = if req.id > 0 { req.id } else { 1000 };
            match worker.call_scan_summary_fetch(max_count) {
                Ok((count, exhausted)) => Response {
                    ok: true,
                    op: "scan_summary_fetch".into(),
                    exhausted: Some(exhausted),
                    record_count: Some(count as u64),
                    ..Response::ok("scan_summary_fetch")
                },
                Err(code) => Response::err("scan_summary_fetch", code),
            }
        }
        "scan_summary_close" => {
            // 关闭摘要扫描游标：复用 call_scan_close（Verthys_ScanClose 不区分摘要/全量）
            // 销毁共享内存 + 关闭 C 游标（注销 memory_guard → 解锁 → 擦除 → 释放）
            let _ = worker.call_scan_close();
            Response::ok("scan_summary_close")
        }
        // 第 2.1 项：scan_summary_abort — 取消摘要扫描并回滚游标
        "scan_summary_abort" => {
            let _ = worker.call_scan_close();
            Response::ok("scan_summary_abort")
        }
        "delete_record" => {
            let r = worker.call_delete_record(req.id);
            if r == VERTHYS_OK {
                Response::ok("delete_record")
            } else {
                Response::err("delete_record", r)
            }
        }
        "delete_records" => {
            // 批量删除：单次事务内删除全部 ID（落实 upgrade.md 批量删除合并单次 flush）
            let r = worker.call_delete_records(&req.ids);
            if r == VERTHYS_OK {
                Response::ok("delete_records")
            } else {
                Response::err("delete_records", r)
            }
        }
        // ★ Phase 2I：获取已加载的轻量摘要记录数
        "get_summary_count" => {
            let (rc, count) = worker.call_get_summary_count();
            if rc == VERTHYS_OK {
                let mut resp = Response::ok("get_summary_count");
                resp.record_count = Some(count);
                resp
            } else {
                Response::err("get_summary_count", rc)
            }
        }
        // ★ 企业级方案：轻量级记录类型存在性检查（只扫摘要索引，不读数据块）
        // 典型耗时 < 100ms，用于启动阶段快速判断是否有全局密钥记录
        // 返回 record_count=1（存在）或 record_count=0（不存在）
        "has_record_by_type" => {
            let rtype_u8 = req.rtype as u8;
            let (rc, found) = worker.call_has_record_by_type(rtype_u8);
            if rc == VERTHYS_OK {
                let mut resp = Response::ok("has_record_by_type");
                resp.record_count = Some(if found { 1 } else { 0 });
                resp
            } else {
                Response::err("has_record_by_type", rc)
            }
        }
        "export" => {
            let r = worker.call_export(&req.path, &req.password);
            if r == VERTHYS_OK {
                Response::ok("export")
            } else {
                Response::err("export", r)
            }
        }
        "import" => {
            let r = worker.call_import(&req.path, &req.password);
            if r == VERTHYS_OK {
                Response::ok("import")
            } else {
                Response::err("import", r)
            }
        }
        "change_password" => {
            let r = worker.call_change_password(&req.old_password, &req.new_password);
            if r == VERTHYS_OK {
                Response::ok("change_password")
            } else {
                Response::err("change_password", r)
            }
        }
        // ★ WP-11（P2-3 观测出口）：防御闭环 7 路径状态实时查询
        // 防御状态为进程级事实：锁定态/未挂载态均可查询（verthys.h 行为契约），
        // 安全中心可在解锁前展示防护水位。
        "security_status" => match worker.call_security_status() {
            Ok(report) => {
                let mut resp = Response::ok("security_status");
                resp.security_status = Some(report);
                resp
            }
            Err(code) => Response::err("security_status", code),
        },
        // GMK 派生命令（#2 敏感操作下沉）
        "derive_global_key" => handle_derive_global_key(req),
        "verify_global_key" => handle_verify_global_key(req),
        "derive_module_subkey" => handle_derive_module_subkey(req),
        "clear_global_key" => handle_clear_global_key(),
        _ => Response {
            ok: false,
            op: req.op.clone(),
            error: Some("unknown op".into()),
            ..Response::ok(&req.op)
        },
    }
}
