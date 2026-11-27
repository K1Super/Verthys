/*
 * dispatch/routes_security.rs — 解锁、预设、锚点与全局密钥路由
 */

use super::*;

pub(super) fn handle(worker: &mut Worker, req: &Request) -> Option<Response> {
    let resp = match req.op.as_str() {
        "unlock" => {
            if let Some(denied) = require_path_grant("unlock", "read", &req.path) {
                return Some(denied);
            }
            /* 产品解锁只接受 VRTY：worker 先做 magic 白名单，再调用
             * Verthys_V4Unlock。 */
            /* VERTHYS_ERR_PARTIAL_UNLOCK 表示容器已进入
             * 最小可操作状态（超级块验证 + 密钥导入 + 分区表加载完成，索引
             * 预热后台进行中），与 verthys_api.c Unlock 成功分支语义一致——
             * 按成功处理，正常执行 GMK 探测并返回。 */
            const VERTHYS_ERR_PARTIAL_UNLOCK: u32 = 0x00000011;
            let r = worker.call_unlock(&req.path, &req.password);
            if r == VERTHYS_OK || r == VERTHYS_ERR_PARTIAL_UNLOCK {
                let (has_gmk, gmk_id, gmk_record) = probe_global_key_inproc(worker);
                Response {
                    has_global_key: has_gmk,
                    global_key_id: gmk_id,
                    global_key_record: gmk_record,
                    ..Response::ok("unlock")
                }
            } else {
                /*
                 * 场景：前一次解锁因 stdout 死锁导致父进程 60 秒超时退出，
                 * 但 worker 进程仍在运行且 Verthys_V4Unlock FFI 已成功完成，
                 * ctx->state 停留在 VERTHYS_STATE_UNLOCKED。后续解锁请求调用
                 * Verthys_V4Unlock 时命中 `if (ctx->state == VERTHYS_STATE_UNLOCKED)
                 * return VERTHYS_ERR_INVALID` 立即失败。
                 *
                 * 恢复策略：检测到 INVALID 时先调用 Verthys_Lock（将状态从
                 * UNLOCKED 切换到 LOCKED），再重试 Verthys_V4Unlock。仅当 verthys
                 * 确实处于 UNLOCKED 状态时 Lock 才会成功，其他 INVALID 原因
                 * （handle NULL / path NULL）Lock 也会失败，不影响安全语义。 */
                const VERTHYS_ERR_INVALID: u32 = 0x00000001;
                if r == VERTHYS_ERR_INVALID {
                    diag!("[worker] unlock 返回 INVALID，尝试状态恢复（lock → retry unlock）");
                    let lock_r = worker.call_lock();
                    diag!("[worker] 状态恢复 lock 返回: {:08X}", lock_r);
                    if lock_r == VERTHYS_OK {
                        let r2 = worker.call_unlock(&req.path, &req.password);
                        diag!("[worker] 状态恢复 retry unlock 返回: {:08X}", r2);
                        if r2 == VERTHYS_OK || r2 == VERTHYS_ERR_PARTIAL_UNLOCK {
                            let (has_gmk, gmk_id, gmk_record) =
                                probe_global_key_inproc(worker);
                            return Some(Response {
                                has_global_key: has_gmk,
                                global_key_id: gmk_id,
                                global_key_record: gmk_record,
                                ..Response::ok("unlock")
                            });
                        }
                        return Some(unlock_error(worker, "unlock", r2));
                    }
                }
                unlock_error(worker, "unlock", r)
            }
        }
        "lock" => {
            diag!("[worker] call_lock");
            let r = worker.call_lock();
            diag!("[worker] lock 返回: {:08X}", r);
            if r == VERTHYS_OK {
                /* 内容层密钥（MDEK）只存在于 C 层句柄内：call_lock 已清空
                 * C 侧模块缓存，worker 侧不存在需要额外清理的口令/派生缓存。 */
                Response::ok("lock")
            } else {
                Response::err("lock", r)
            }
        }
        // 运行时切换安全预设（贯通前端 → Rust → worker → C 双缓冲切档链路）
        // 幂等：切到当前档返回 OK；C 层返回 INVALID 时透传错误码。
        "switch_preset" => {
            diag!("[worker] call_switch_security_preset: preset={}", req.preset);
            let r = worker.call_switch_security_preset(req.preset);
            diag!("[worker] switch_preset 返回: {:08X}", r);
            if r == VERTHYS_OK {
                Response::ok("switch_preset")
            } else {
                Response::err("switch_preset", r)
            }
        }
        // 查询活跃安全预设档位（切档回读校验：切换是否真实生效）
        "get_active_preset" => {
            match worker.call_get_security_preset() {
                Ok(preset) => {
                    let mut resp = Response::ok("get_active_preset");
                    resp.data = Some(preset.to_string());
                    resp
                }
                Err(code) => Response::err("get_active_preset", code),
            }
        }
        // 查询指定档位的特性位投影（档位矩阵唯一权威输出，宿主据此展示与执行）
        "get_preset_features" => {
            match worker.call_get_preset_feature_bits(req.preset) {
                Ok(bits) => {
                    let mut resp = Response::ok("get_preset_features");
                    resp.data = Some(bits.to_string());
                    resp
                }
                Err(code) => Response::err("get_preset_features", code),
            }
        }
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
        /* 批量导入锚点推迟（API 0x0015 可选能力）。
         * 旧 DLL 缺符号时返回 unsupported，宿主按现状逐次提交，不得
         * 把“Begin 未生效”当成已进入推迟会话。 */
        "bulk_import_begin" => match worker.call_bulk_import_begin() {
            Ok(()) => Response::ok("bulk_import_begin"),
            Err(VERTHYS_SYMBOL_UNSUPPORTED) => Response {
                ok: false,
                op: "bulk_import_begin".into(),
                error: Some("unsupported: Verthys_BulkImportBegin".into()),
                ..Response::ok("bulk_import_begin")
            },
            Err(code) => Response::err("bulk_import_begin", code),
        },
        "bulk_import_commit" => match worker.call_bulk_import_commit() {
            Ok(()) => Response::ok("bulk_import_commit"),
            Err(VERTHYS_SYMBOL_UNSUPPORTED) => Response {
                ok: false,
                op: "bulk_import_commit".into(),
                error: Some("unsupported: Verthys_BulkImportCommit".into()),
                ..Response::ok("bulk_import_commit")
            },
            Err(code) => Response::err("bulk_import_commit", code),
        },
        /* 落盘自查：flush 成功后由本进程 C 层持锁句柄自查盘面结构。
         * 主进程外部读路径在 Windows 强制字节范围锁下恒失败（os error
         * 33），故校验必须落在持有会话句柄的子进程内。ok = (status==OK)；
         * 非 OK 时把 C 层 last_error 透传到响应 error 字段供上层分类。 */
        "verify_persist" => {
            diag!("[worker] call_verify_persist");
            match worker.call_verify_persist() {
                Ok(o) => {
                    let ok = o.status_code == VERTHYS_PERSIST_OK;
                    diag!(
                        "[worker] verify_persist 返回: status={} size={} magic=0x{:08X} ver={}",
                        o.status_code,
                        o.file_size,
                        o.header_magic,
                        o.header_version
                    );
                    Response {
                        ok,
                        op: "verify_persist".into(),
                        status_code: Some(o.status_code),
                        file_size: Some(o.file_size),
                        mtime_ms: Some(o.mtime_ms),
                        header_magic: Some(o.header_magic),
                        header_version: Some(o.header_version),
                        wal_offset: Some(o.wal_offset),
                        error: if ok { None } else { Some(o.last_error) },
                        ..Response::ok("verify_persist")
                    }
                }
                Err(code) => Response::err("verify_persist", code),
            }
        }
        // 动态防护 7 路径状态实时查询
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
        /* 轻量内核状态查询：只看驱动/服务回填的内核字段，
         * 不计算 7 路径防御状态，供宿主看门狗 2s 级轮询。 */
        "kernel_status" => match worker.call_kernel_status() {
            Some(report) => {
                let mut resp = Response::ok("kernel_status");
                resp.kernel_status = Some(report);
                resp
            }
            None => Response::err("kernel_status", 0x00000001),
        },
        // 回退锚点维护：列表只读；批量释放必须显式 confirm。
        "rollback_anchor_list" => match worker.call_anchor_list() {
            Ok((anchors, state)) => {
                let mut resp = Response::ok("rollback_anchor_list");
                resp.anchors = Some(anchors);
                resp.anchor_state = Some(state);
                resp
            }
            Err(code) => Response::err_raw("rollback_anchor_list", code),
        },
        "rollback_anchor_release_batch" => {
            const VERTHYS_ERR_INVALID: u32 = 0x00000001;
            const ANCHOR_BATCH_MAX: usize = 64;

            if !req.anchor_confirm {
                return Some(Response::err_raw(
                    "rollback_anchor_release_batch",
                    VERTHYS_ERR_INVALID,
                ));
            }
            if req.uuids.is_empty() || req.uuids.len() > ANCHOR_BATCH_MAX {
                return Some(Response::err_raw(
                    "rollback_anchor_release_batch",
                    VERTHYS_ERR_INVALID,
                ));
            }
            let mut parsed: Vec<[u8; 16]> = Vec::with_capacity(req.uuids.len());
            let mut seen = std::collections::HashSet::with_capacity(req.uuids.len());
            for text in &req.uuids {
                let uuid = match parse_uuid_hex(text) {
                    Some(v) => v,
                    None => {
                        return Some(Response::err_raw(
                            "rollback_anchor_release_batch",
                            VERTHYS_ERR_INVALID,
                        ))
                    }
                };
                if uuid.iter().all(|byte| *byte == 0) || !seen.insert(uuid) {
                    return Some(Response::err_raw(
                        "rollback_anchor_release_batch",
                        VERTHYS_ERR_INVALID,
                    ));
                }
                parsed.push(uuid);
            }
            match worker.call_anchor_release_batch(
                &parsed,
                crate::runtime::ffi_types::VERTHYS_ANCHOR_FLAG_CONFIRM,
            ) {
                Ok(results) => {
                    let mut resp = Response::ok("rollback_anchor_release_batch");
                    let mut released = 0u32;
                    let mut cleanup_failed = 0u32;
                    let mut outcomes = Vec::with_capacity(results.len());
                    for (index, (was_released, failed)) in results.iter().enumerate() {
                        if *was_released != 0 {
                            released += 1;
                        }
                        if *failed != 0 {
                            cleanup_failed += 1;
                        }
                        outcomes.push(crate::runtime::protocol::AnchorReleaseOutcome {
                            uuid: req.uuids[index].to_ascii_lowercase(),
                            released: *was_released != 0,
                            cleanup_failed: *failed != 0,
                        });
                    }
                    resp.anchor_release_results = Some(outcomes);
                    resp.anchor_released = Some(released);
                    resp.anchor_cleanup_failed = Some(cleanup_failed);
                    resp
                }
                Err(code) => Response::err_raw("rollback_anchor_release_batch", code),
            }
        }
        // 运行时守卫位下发（API 0x0014）：主进程安装/停止挂起守卫时同步
        // bit1，worker 与心跳位合并后通知 C 层；flags=0 表示停止守卫。
        "runtime_guards" => {
            let suspend_lock = (req.flags & 0x02) != 0;
            match worker.update_runtime_guards(suspend_lock) {
                Ok(()) => Response::ok("runtime_guards"),
                Err(code) => Response::err("runtime_guards", code),
            }
        }
        // 启用心跳线程：句柄值由父进程经 DuplicateHandle 注入，本次请求
        // 走签名 IPC 下发；worker 只持有句柄值并周期 SetEvent。
        "arm_heartbeat" => match worker.arm_heartbeat(req.hb_handle) {
            Ok(()) => Response::ok("arm_heartbeat"),
            Err(code) => Response::err("arm_heartbeat", code),
        },
        // GMK 派生命令（#2 敏感操作下沉）
        // 派生并持久化（首次初始化专用：存储+读回验证在 worker 进程内
        // 原子完成，无跨 IPC 中间态窗口）
        "derive_and_store_global_key" => handle_derive_and_store_global_key(req, worker),
        "verify_global_key" => handle_verify_global_key(req),
        // 改钥：核验旧钥 → 派生新钥 → 写新/删旧 → 成功后换槽（单次 IPC）
        "change_global_key" => handle_change_global_key(req, worker),
        "clear_global_key" => handle_clear_global_key(),
        // 内容层加解密（分片密钥只在 C 层持有，worker 不缓存模块口令）
        "module_seal" => module_keys::handle_seal_v4(req, worker),
        "module_open" => module_keys::handle_open_v4(req, worker),
        /* 损坏扫描专用：只验证模块密钥外层，不要求文件口令、不校验种类标签。 */
        "module_probe_outer" => module_keys::handle_probe_outer(req, worker),
        _ => return None,
    };
    Some(resp)
}
