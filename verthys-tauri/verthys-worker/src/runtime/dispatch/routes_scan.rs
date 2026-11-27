/*
 * dispatch/routes_scan.rs — 扫描游标路由
 */

use super::*;

pub(super) fn handle(worker: &mut Worker, req: &Request) -> Option<Response> {
    let resp = match req.op.as_str() {
        "scan_open" => {
            // 打开扫描游标：创建共享内存 + 复用 vbtree_scan_all + 首批预加载
            // 首批同样走 SHM 认证（与 fetch 一致，不存未认证批次窗口）
            // 条数值外部可控：双端 clamp（本端 + worker 端），防巨大分配
            let start_lid = if req.id > 0 { req.id } else { 0 };
            let batch_size = if req.max_count > 0 { clamp_enum_count(req.max_count as u64) } else { 500 };
            // 投影：缺省 FULL（历史行为）；INDEX 只对不超过阈值的记录解密取数
            let project = match parse_scan_project(&req.project) {
                Ok(p) => p,
                Err(()) => return Some(Response::err("scan_open", 0x00000001u32 /* INVALID */)),
            };
            let inline_max = parse_inline_max_bytes(req.inline_max_bytes);
            let auth_key = match parse_shm_auth_key("scan_open", &req.shm_key) {
                Ok(k) => k,
                Err(resp) => return Some(*resp),
            };
            match worker.call_scan_open(start_lid, batch_size, project, inline_max,
                                        auth_key.as_ref().map(|k| k.as_slice())) {
                Ok((shm_name, shm_size, count, exhausted, failed_ids)) => {
                    let mut resp = Response {
                        ok: true,
                        op: "scan_open".into(),
                        exhausted: Some(exhausted),
                        shm_name: Some(shm_name),
                        shm_size: Some(shm_size as u64),
                        record_count: Some(count as u64),
                        ..Response::ok("scan_open")
                    };
                    if !failed_ids.is_empty() {
                        diag!(
                            "[worker] scan_open: 本批 {} 条记录解密失败或索引不一致，随响应上报",
                            failed_ids.len()
                        );
                        resp.failed_ids = Some(failed_ids);
                    }
                    resp
                }
                Err(code) => Response::err("scan_open", code),
            }
        }
        "scan_fetch" => {
            // 批量拉取记录：游标驱动遍历器填充共享内存缓冲区，不重复定位
            // 条数值外部可控：双端 clamp（本端 + worker 端），防巨大分配
            let max_count = if req.id > 0 { clamp_enum_count(req.id) } else { 500 };
            let auth_key = match parse_shm_auth_key("scan_fetch", &req.shm_key) {
                Ok(k) => k,
                Err(resp) => return Some(*resp),
            };
            match worker.call_scan_fetch(max_count, auth_key.as_ref().map(|k| k.as_slice())) {
                Ok((count, exhausted, failed_ids)) => {
                    let mut resp = Response {
                        ok: true,
                        op: "scan_fetch".into(),
                        exhausted: Some(exhausted),
                        record_count: Some(count as u64),
                        ..Response::ok("scan_fetch")
                    };
                    if !failed_ids.is_empty() {
                        diag!(
                            "[worker] scan_fetch: 本批 {} 条记录解密失败或索引不一致，随响应上报",
                            failed_ids.len()
                        );
                        resp.failed_ids = Some(failed_ids);
                    }
                    resp
                }
                Err(code) => Response::err("scan_fetch", code),
            }
        }
        "scan_close" => {
            // 关闭扫描游标：销毁共享内存 + 释放遍历句柄/快照
            let _ = worker.call_scan_close();
            Response::ok("scan_close")
        }
        // scan_abort — 取消扫描并回滚游标
        // 主进程在 CancellationToken 触发时发送，语义为"取消并回滚"。
        // 当前 worker 端 call_scan_close 已完成回滚（销毁 SHM + 关闭 C 游标），
        // scan_abort 与 scan_close 调用同一底层方法，但语义独立便于审计与未来扩展
        // （如 abort 时记录中断原因、回滚未提交事务等）。
        "scan_abort" => {
            // 取消扫描游标：销毁共享内存 + 回滚遍历句柄
            let _ = worker.call_scan_close();
            Response::ok("scan_abort")
        }
        // ===== 摘要扫描（轻量元数据，不读数据块）=====
        "scan_summary_open" => {
            // 打开摘要扫描游标：创建 4MB 共享内存 + Verthys_ScanSummaryOpen + 首批预加载
            // 首批同样走 SHM 认证（与 fetch 一致，不存未认证批次窗口）
            // 返回 shm_name 供 Tauri 主进程读取摘要记录（read_shm_summary_records）
            let start_lid = if req.id > 0 { req.id } else { 0 };
            let batch_size = if req.max_count > 0 { clamp_enum_count(req.max_count as u64) } else { 1000 };
            let auth_key = match parse_shm_auth_key("scan_summary_open", &req.shm_key) {
                Ok(k) => k,
                Err(resp) => return Some(*resp),
            };
            match worker.call_scan_summary_open(start_lid, batch_size, auth_key.as_ref().map(|k| k.as_slice())) {
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
            // 条数值外部可控：双端 clamp（本端 + worker 端），防巨大分配
            let max_count = if req.id > 0 { clamp_enum_count(req.id) } else { 1000 };
            let auth_key = match parse_shm_auth_key("scan_summary_fetch", &req.shm_key) {
                Ok(k) => k,
                Err(resp) => return Some(*resp),
            };
            match worker.call_scan_summary_fetch(max_count, auth_key.as_ref().map(|k| k.as_slice())) {
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
        // scan_summary_abort — 取消摘要扫描并回滚游标
        "scan_summary_abort" => {
            let _ = worker.call_scan_close();
            Response::ok("scan_summary_abort")
        }
        _ => return None,
    };
    Some(resp)
}
