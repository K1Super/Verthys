/*
 * dispatch/routes_v4.rs — V4 容器、PCR、keyfile 与模块路由
 */

use super::*;

pub(super) fn handle(worker: &mut Worker, req: &Request) -> Option<Response> {
    let resp = match req.op.as_str() {
        // 模块 M1 会话（口令只转发 C，MDEK 不进入 worker）
        "v4_create" => {
            if let Some(denied) = require_path_grant("v4_create", "write", &req.path) {
                return Some(denied);
            }
            diag!("[worker] call_create: path_bytes={}", req.path.len());
            match worker.call_create(&req.path, &req.password) {
                Ok(recovery_code) => Response {
                    recovery_code: Some(recovery_code),
                    ..Response::ok("v4_create")
                },
                Err(rc) => Response::err("v4_create", rc),
            }
        }
        "v4_unlock_recovery" => {
            if let Some(denied) =
                require_path_grant("v4_unlock_recovery", "read", &req.path)
            {
                return Some(denied);
            }
            let rc = worker.call_unlock_recovery(&req.path, &req.recovery_code);
            if rc == VERTHYS_OK {
                /* 恢复解锁与口令解锁共用同一记录层：废弃的是 C 层 GMK，
                 * 产品层的 global-key 记录仍由 AddRecord 写入并决定
                 * 初始化/验证视图。必须执行同一条进程内探测，返回固定
                 * false 会把有记录的库误导向初始化视图。 */
                let (has_gmk, gmk_id, gmk_record) = probe_global_key_inproc(worker);
                Response {
                    has_global_key: has_gmk,
                    global_key_id: gmk_id,
                    global_key_record: gmk_record,
                    recovery_mode: Some(true),
                    ..Response::ok("v4_unlock_recovery")
                }
            } else {
                Response::err("v4_unlock_recovery", rc)
            }
        }
        "v4_pcr_status" => pcr_session::handle_pcr_status(req, worker),
        "v4_pcr_enable" => pcr_session::handle_pcr_enable(req, worker),
        "v4_pcr_disable" => pcr_session::handle_pcr_disable(req, worker),
        "v4_pcr_reseal" => pcr_session::handle_pcr_reseal(req, worker),
        /* keyfile 因子：两条路径都要先授权（库路径 + keyfile 路径），
         * keyfile 内容只在 C 层读取/生成。 */
        "v4_create_keyfile" => {
            if req.keyfile_path.is_empty() {
                return Some(Response::err("v4_create_keyfile", 0x0000001A));
            }
            if let Some(denied) =
                require_path_grant("v4_create_keyfile", "write", &req.path)
            {
                return Some(denied);
            }
            if let Some(denied) =
                require_path_grant("v4_create_keyfile", "write", &req.keyfile_path)
            {
                return Some(denied);
            }
            match worker.call_create_keyfile(
                &req.path,
                &req.password,
                &req.keyfile_path,
            ) {
                Ok(recovery_code) => Response {
                    recovery_code: Some(recovery_code),
                    ..Response::ok("v4_create_keyfile")
                },
                Err(rc) => Response::err("v4_create_keyfile", rc),
            }
        }
        "v4_unlock_keyfile" => {
            if req.keyfile_path.is_empty() {
                return Some(Response::err("v4_unlock_keyfile", 0x0000001A));
            }
            if let Some(denied) =
                require_path_grant("v4_unlock_keyfile", "read", &req.path)
            {
                return Some(denied);
            }
            if let Some(denied) =
                require_path_grant("v4_unlock_keyfile", "read", &req.keyfile_path)
            {
                return Some(denied);
            }
            let rc = worker.call_unlock_keyfile(
                &req.path,
                &req.password,
                &req.keyfile_path,
            );
            if rc == VERTHYS_OK {
                /* 与 v4_unlock_recovery 同一契约：keyfile 只影响容器解锁因子，
                 * 不改变记录层。固定 false 会让启用 keyfile 的库在每次解锁后
                 * 都进入初始化视图，掩盖已存在的 global-key 记录。 */
                let (has_gmk, gmk_id, gmk_record) = probe_global_key_inproc(worker);
                Response {
                    has_global_key: has_gmk,
                    global_key_id: gmk_id,
                    global_key_record: gmk_record,
                    ..Response::ok("v4_unlock_keyfile")
                }
            } else {
                /* RATE 时与 unlock 一致附带本地退避剩余秒数；机器预算拒绝
                 * 时秒数为 0，宿主据此区分“退避中”与“服务拒绝/不可用”。 */
                unlock_error(worker, "v4_unlock_keyfile", rc)
            }
        }
        "v4_keyfile_status" => match worker.call_keyfile_status() {
            Ok((enabled, recovery_mode)) => Response {
                keyfile_enabled: Some(enabled),
                recovery_mode: Some(recovery_mode),
                ..Response::ok("v4_keyfile_status")
            },
            Err(rc) => Response::err("v4_keyfile_status", rc),
        },
        "v4_reseal_device" => {
            if !req.keyfile_path.is_empty() {
                if let Some(denied) =
                    require_path_grant("v4_reseal_device", "read", &req.keyfile_path)
                {
                    return Some(denied);
                }
            }
            let rc = worker.call_reseal_device(&req.password, &req.keyfile_path);
            if rc == VERTHYS_OK {
                Response {
                    recovery_mode: Some(true),
                    ..Response::ok("v4_reseal_device")
                }
            } else {
                Response::err("v4_reseal_device", rc)
            }
        }
        "v4_keyfile_enable" => {
            if req.keyfile_path.is_empty() {
                return Some(Response::err("v4_keyfile_enable", 0x0000001A));
            }
            if let Some(denied) =
                require_path_grant("v4_keyfile_enable", "write", &req.keyfile_path)
            {
                return Some(denied);
            }
            let rc = worker.call_keyfile_enable(&req.password, &req.keyfile_path);
            if rc == VERTHYS_OK {
                Response {
                    keyfile_enabled: Some(true),
                    ..Response::ok("v4_keyfile_enable")
                }
            } else {
                Response::err("v4_keyfile_enable", rc)
            }
        }
        "v4_keyfile_disable" => {
            /* 空路径仅恢复码会话可用（keyfile 丢失逃生），由 C 层
             * 按会话模式判定；非空路径才需要路径授权。 */
            if !req.keyfile_path.is_empty() {
                if let Some(denied) =
                    require_path_grant("v4_keyfile_disable", "read", &req.keyfile_path)
                {
                    return Some(denied);
                }
            }
            let rc = worker.call_keyfile_disable(&req.password, &req.keyfile_path);
            if rc == VERTHYS_OK {
                Response {
                    keyfile_enabled: Some(false),
                    ..Response::ok("v4_keyfile_disable")
                }
            } else {
                Response::err("v4_keyfile_disable", rc)
            }
        }
        "v4_module_enable" => module_session::handle_enable(req, worker),
        "v4_module_unlock" => module_session::handle_unlock(req, worker),
        "v4_module_lock" => module_session::handle_lock(req, worker),
        "v4_module_rotate_password" => module_session::handle_rotate_password(req, worker),
        "v4_module_disable" => module_session::handle_disable(req, worker),
        "v4_module_delete" => module_session::handle_delete(req, worker),
        "v4_module_bind_recovery" => module_session::handle_bind_recovery(req, worker),
        "v4_module_reseal_device" => module_session::handle_reseal_device(req, worker),
        "v4_module_status" => module_session::handle_status(req, worker),
        "v4_recovery_rotate" => module_session::handle_recovery_rotate(req, worker),
        _ => return None,
    };
    Some(resp)
}
