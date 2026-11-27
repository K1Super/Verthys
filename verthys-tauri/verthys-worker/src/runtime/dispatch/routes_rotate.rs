/*
 * dispatch/routes_rotate.rs — 全库轮换路由
 */

use super::*;

pub(super) fn handle(worker: &mut Worker, req: &Request) -> Option<Response> {
    let resp = match req.op.as_str() {
        /* 全库 DEK 轮换：作业式五段命令。
         * Begin 需要 new_path，路径授权与源库解锁授权独立签发；
         * 口令由宿主注入，Rust 侧不缓存、不写日志。 */
        "v4_rotate_begin" => {
            if req.new_path.is_empty() {
                return Some(Response::err("v4_rotate_begin", 0x00000001));
            }
            if let Some(denied) =
                require_path_grant("v4_rotate_begin", "write", &req.new_path)
            {
                return Some(denied);
            }
            match worker.call_rotate_begin(
                &req.new_path,
                &req.password,
                req.flags,
            ) {
                Ok(info) => Response {
                    rotate_stage: Some(info.stage),
                    rotate_modules_ready: Some(info.modules_ready),
                    rotate_records: Some(info.records),
                    rotate_files: Some(info.files),
                    rotate_chunks: Some(info.chunks),
                    rotate_bytes: Some(info.bytes),
                    ..Response::ok("v4_rotate_begin")
                },
                Err(rc) => Response::err("v4_rotate_begin", rc),
            }
        }
        "v4_rotate_attach_keyfile" => {
            if req.keyfile_path.is_empty() {
                return Some(Response::err("v4_rotate_attach_keyfile", 0x00000001));
            }
            if let Some(denied) = require_path_grant(
                "v4_rotate_attach_keyfile",
                "read",
                &req.keyfile_path,
            ) {
                return Some(denied);
            }
            let rc = worker.call_rotate_attach_keyfile(
                &req.keyfile_path,
                &req.password,
            );
            if rc == VERTHYS_OK {
                Response::ok("v4_rotate_attach_keyfile")
            } else {
                Response::err("v4_rotate_attach_keyfile", rc)
            }
        }
        "v4_rotate_unlock_module" => {
            const MODULE_COUNT: u32 = 3;
            if req.module_id >= MODULE_COUNT || req.password.is_empty() {
                return Some(Response::err("v4_rotate_unlock_module", 0x00000001));
            }
            let recovery_code = if req.recovery_code.is_empty() {
                None
            } else {
                Some(req.recovery_code.as_str())
            };
            let rc = worker.call_rotate_unlock_module(
                req.module_id,
                &req.password,
                recovery_code,
            );
            if rc == VERTHYS_OK {
                Response::ok("v4_rotate_unlock_module")
            } else {
                Response::err("v4_rotate_unlock_module", rc)
            }
        }
        "v4_rotate_run" => {
            let cancel_event = if req.cancel_event.is_empty() {
                None
            } else {
                Some(req.cancel_event.as_str())
            };
            let rc = worker.call_rotate_run(cancel_event);
            if rc == VERTHYS_OK {
                Response::ok("v4_rotate_run")
            } else {
                Response::err("v4_rotate_run", rc)
            }
        }
        "v4_rotate_commit" => {
            let rc = worker.call_rotate_commit(req.keep_old);
            if rc == VERTHYS_OK {
                Response::ok("v4_rotate_commit")
            } else {
                Response::err("v4_rotate_commit", rc)
            }
        }
        "v4_rotate_abort" => {
            let rc = worker.call_rotate_abort();
            if rc == VERTHYS_OK {
                Response::ok("v4_rotate_abort")
            } else {
                Response::err("v4_rotate_abort", rc)
            }
        }
        _ => return None,
    };
    Some(resp)
}
