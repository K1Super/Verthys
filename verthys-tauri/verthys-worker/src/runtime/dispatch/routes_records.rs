/*
 * dispatch/routes_records.rs — 记录读写与存储路由
 */

use super::*;

pub(super) fn handle(worker: &mut Worker, req: &Request) -> Option<Response> {
    let resp = match req.op.as_str() {
        "find_lid_by_name" => match worker.call_find_lid_by_name(&req.name) {
            Ok((found, lid)) => {
                let mut resp = Response::ok("find_lid_by_name");
                resp.found = Some(found);
                if found {
                    resp.id = Some(lid);
                }
                resp
            }
            Err(rc) => Response::err("find_lid_by_name", rc),
        },
        "add_record" => {
            /* 解码前先按 base64 字符数拦截，避免超大载荷先分配再拒绝。
             * 12MiB 与 host 请求构造侧使用同一预算常量。 */
            if req.data.len() > crate::runtime::budget::PB_IPC_MAX_PAYLOAD_BYTES as usize {
                return Some(Response {
                    ok: false,
                    op: "add_record".into(),
                    error: Some("record payload exceeds ipc budget".into()),
                    ..Response::ok("add_record")
                });
            }
            let mut data = match base64_decode(&req.data) {
                Ok(d) => d,
                Err(_) => {
                    return Some(Response {
                        ok: false,
                        op: "add_record".into(),
                        error: Some("base64 decode failed".into()),
                        ..Response::ok("add_record")
                    })
                }
            };
            let result = match worker.call_add_record(req.rtype, &req.name, &data) {
                Ok(id) => Response {
                    ok: true,
                    op: "add_record".into(),
                    id: Some(id),
                    ..Response::ok("add_record")
                },
                Err(code) => Response::err("add_record", code),
            };
            data.zeroize();
            result
        }
        "add_records" => {
            /* 批量新增（API 0x0013）：单次 C 层事务提交。
             * 上限与 C 端 VERTHYS_ADD_RECORDS_MAX 对齐；聚合载荷按单次
             * IPC 预算约束，解码前先按 base64 字符数拦截。 */
            const MAX_ADD_RECORDS: usize = 512;
            let count = req.records.len();
            if count == 0 || count > MAX_ADD_RECORDS {
                return Some(Response {
                    ok: false,
                    op: "add_records".into(),
                    error: Some(format!(
                        "records count out of range: {} (allowed 1..={})",
                        count, MAX_ADD_RECORDS
                    )),
                    ..Response::ok("add_records")
                });
            }
            let mut total_bytes: usize = 0;
            for r in &req.records {
                if r.data.len() > crate::runtime::budget::PB_IPC_MAX_PAYLOAD_BYTES as usize {
                    return Some(Response {
                        ok: false,
                        op: "add_records".into(),
                        error: Some("record payload exceeds ipc budget".into()),
                        ..Response::ok("add_records")
                    });
                }
                total_bytes = total_bytes
                    .saturating_add(r.data.len())
                    .saturating_add(r.name.len());
            }
            if total_bytes > crate::runtime::budget::PB_IPC_MAX_PAYLOAD_BYTES as usize {
                return Some(Response {
                    ok: false,
                    op: "add_records".into(),
                    error: Some("batch payload exceeds ipc budget".into()),
                    ..Response::ok("add_records")
                });
            }

            let mut names: Vec<std::ffi::CString> = Vec::with_capacity(count);
            let mut datas: Vec<Vec<u8>> = Vec::with_capacity(count);
            for r in &req.records {
                match std::ffi::CString::new(r.name.as_str()) {
                    Ok(c) => names.push(c),
                    Err(_) => {
                        diag!("[worker] add_records: 名称含内嵌 NUL，length={}", r.name.len());
                        return Some(Response {
                            ok: false,
                            op: "add_records".into(),
                            error: Some("invalid record name".into()),
                            ..Response::ok("add_records")
                        });
                    }
                }
                match base64_decode(&r.data) {
                    Ok(d) => datas.push(d),
                    Err(_) => {
                        return Some(Response {
                            ok: false,
                            op: "add_records".into(),
                            error: Some("base64 decode failed".into()),
                            ..Response::ok("add_records")
                        });
                    }
                }
            }

            // 指针绑定：names/datas 已定型（不再 push），切片地址稳定
            let records: Vec<VerthysRecordC> = names
                .iter()
                .zip(datas.iter())
                .enumerate()
                .map(|(i, (name, data))| VerthysRecordC {
                    rtype: req.records[i].rtype,
                    name: name.as_ptr(),
                    name_len: name.as_bytes().len(),
                    data: data.as_ptr(),
                    data_len: data.len(),
                })
                .collect();

            let result = match worker.call_add_records(&records) {
                Ok(ids) => Response {
                    ok: true,
                    op: "add_records".into(),
                    ids,
                    ..Response::ok("add_records")
                },
                Err(code) => Response::err("add_records", code),
            };
            for data in datas.iter_mut() {
                data.zeroize();
            }
            result
        }
        "get_record" => match worker.call_get_record(req.id) {
            Ok((rtype, mut name, mut data)) => {
                // 协议安全护栏：单条返回同样受响应预算约束。写入侧 12MiB
                // 上限保证新数据恒可返回；历史存量超限记录改为明确错误，
                // 绝不生成超长响应行（超行即协议断开，是全链路级联故障源）
                let b64_len = data.len().div_ceil(3) * 4;
                if b64_len > ENUM_RESPONSE_DATA_BUDGET_BYTES {
                    diag!(
                        "[worker] get_record: 记录 {} 超出响应预算（b64={} 字节），拒绝内联返回",
                        req.id,
                        b64_len
                    );
                    let data_len = data.len();
                    name.zeroize();
                    data.zeroize();
                    return Some(Response {
                        ok: false,
                        op: "get_record".into(),
                        error: Some(format!(
                            "record_too_large: 记录数据 {} 字节超出单条返回上限",
                            data_len
                        )),
                        ..Response::ok("get_record")
                    });
                }
                let encoded = base64_encode(&data);
                data.zeroize();
                Response {
                    ok: true,
                    op: "get_record".into(),
                    rtype: Some(rtype),
                    name: Some(name),
                    data: Some(encoded),
                    ..Response::ok("get_record")
                }
            }
            Err(code) => Response::err("get_record", code),
        },
        "enumerate_records" => {
            // 批量枚举记录：从 start_id 开始顺序读取，连续 5 次 NOTFOUND 停止
            // 整个循环在 worker 子进程内完成，消除 N 次 IPC 往返开销
            //
            // 分页语义：
            //   - req.max_count > 0 表示 max_count（本批最多返回条数）
            //   - req.max_count == 0 表示不限制（兼容旧调用，全量枚举）
            //   - 返回 exhausted=true 表示已遍历完毕（null_streak >= 5 或到达 MAX_ENUM_RECORDS）
            //   - 返回 id 字段为本批最后一条记录的 ID（调用方据此发起下一批 start_id）
            //   - 返回 record_count 字段为本批实际返回条数
            // 调用方可循环调用本 op 实现流式分页加载（每批 50~200 条）。
            //
            // 响应字节预算（协议安全不变量）：行协议单行硬上限 16MiB（主机与
            // worker 双向一致），历史实现无预算约束——批量记录（如相册内含
            // 内联密文的 meta）在单行内可达数十 MiB，主机读取侧判定超限后按
            // 协议异常断开，worker 连接随之失联（后续所有操作级联失败）。
            // 算法见 build_enum_batch：按 base64 长度累计预算截批，被截断的
            // 批次返回 exhausted=false，调用方以 last_id+1 续批，单批响应恒
            // 不越过预算上限。
            let start_id = if req.id > 0 { req.id } else { 1 };
            let max_count: usize = if req.max_count > 0 { req.max_count as usize } else { usize::MAX };
            let (records, last_id, exhausted) =
                build_enum_batch(start_id, max_count, |id| worker.call_get_record(id));
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
        "delete_record" => {
            let r = worker.call_delete_record(req.id);
            if r == VERTHYS_OK {
                Response::ok("delete_record")
            } else {
                Response::err("delete_record", r)
            }
        }
        "delete_records" => {
            // 批量删除：单次事务内删除全部 ID（合并为单次 flush）
            let r = worker.call_delete_records(&req.ids);
            if r == VERTHYS_OK {
                Response::ok("delete_records")
            } else {
                Response::err("delete_records", r)
            }
        }
        // 获取已加载的轻量摘要记录数
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
        // ：轻量级记录类型存在性检查（只扫摘要索引，不读数据块）
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
        /* 按类型分页枚举记录 ID（API 0x0012）：走 类型盲索引，
         * 不读取记录密文；响应 ids 为升序 ID，exhausted 标记末页。
         * max_count 在分配前先按 C 层同源上限拦截，避免超大请求
         * 触发无界内存分配。 */
        "list_ids_by_type" => {
            const LIST_IDS_BATCH_MAX: u32 = 4096;
            let rtype_u8 = req.rtype as u8;
            if req.rtype > 0xFFu32 ||
                req.max_count == 0u32 ||
                req.max_count > LIST_IDS_BATCH_MAX {
                return Some(Response::err("list_ids_by_type", 0x00000001));
            }
            let max_count = req.max_count as u64;
            let mut ids = vec![0u64; max_count as usize];
            let mut out_count: u64 = 0;
            let mut out_exhausted: u8 = 1;
            let rc = worker.call_list_ids_by_type(
                rtype_u8,
                req.id,
                max_count,
                &mut ids,
                &mut out_count,
                &mut out_exhausted,
            );
            if rc == VERTHYS_OK {
                let used = out_count as usize;
                if used > ids.len() {
                    return Some(Response::err("list_ids_by_type", 0xFFFFFFFF));
                }
                ids.truncate(used);
                let mut resp = Response::ok("list_ids_by_type");
                resp.ids = ids;
                resp.exhausted = Some(out_exhausted != 0);
                resp
            } else {
                Response::err("list_ids_by_type", rc)
            }
        }
        /* 全量存活记录 ID 枚举（可选符号）：目录叶迭代，不读记录段、
         * 不解密名称，与模块锁定状态无关。用于导入前去重键收敛。 */
        "list_all_lids" => {
            const LIST_ALL_BATCH_MAX: u32 = 4096;
            if req.max_count == 0u32 || req.max_count > LIST_ALL_BATCH_MAX {
                return Some(Response::err("list_all_lids", 0x00000001));
            }
            let max_count = req.max_count as u64;
            let mut ids = vec![0u64; max_count as usize];
            let mut out_count: u64 = 0;
            let mut out_exhausted: u8 = 1;
            let rc = worker.call_list_all_lids(
                req.id,
                max_count,
                &mut ids,
                &mut out_count,
                &mut out_exhausted,
            );
            if rc == VERTHYS_OK {
                let used = out_count as usize;
                if used > ids.len() {
                    return Some(Response::err("list_all_lids", 0xFFFFFFFF));
                }
                ids.truncate(used);
                let mut resp = Response::ok("list_all_lids");
                resp.ids = ids;
                resp.exhausted = Some(out_exhausted != 0);
                resp
            } else {
                Response::err("list_all_lids", rc)
            }
        }
        "export" => {
            if let Some(denied) = require_path_grant("export", "write", &req.path) {
                return Some(denied);
            }
            let r = worker.call_export(&req.path, &req.password);
            if r == VERTHYS_OK {
                Response::ok("export")
            } else {
                Response::err("export", r)
            }
        }
        "import" => {
            if let Some(denied) = require_path_grant("import", "read", &req.path) {
                return Some(denied);
            }
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
        "storage_stats" => match worker.call_get_storage_stats() {
            Ok(s) => {
                let mut resp = Response::ok("storage_stats");
                resp.storage_stats = Some(StorageStatsEntry {
                    file_size: s.file_size,
                    data_end: s.data_end,
                    live_tree_bytes: s.live_tree_bytes,
                    live_segment_bytes: s.live_segment_bytes,
                    live_bytes: s.live_bytes,
                    reclaimable_bytes: s.reclaimable_bytes,
                    record_count: s.record_count,
                    file_count: s.file_count,
                    chunk_count: s.chunk_count,
                });
                resp
            }
            Err(rc) => Response::err("storage_stats", rc),
        },
        _ => return None,
    };
    Some(resp)
}
