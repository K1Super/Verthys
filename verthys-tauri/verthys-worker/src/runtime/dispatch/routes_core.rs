/*
 * dispatch/routes_core.rs — 基础与路径授权路由
 */

use super::*;

pub(super) fn handle(_worker: &mut Worker, req: &Request) -> Option<Response> {
    let resp = match req.op.as_str() {
        "ping" => Response::ok("ping"),
        "authorize_path" => match path_grants::authorize(&req.target_op, &req.mode, &req.path) {
            Ok(()) => Response::ok("authorize_path"),
            Err(e) => Response {
                ok: false,
                op: "authorize_path".into(),
                error: Some(e),
                ..Response::ok("authorize_path")
            },
        },
        "authorize_path_batch" => {
            let target_op = if req.target_op.is_empty() {
                "photo_import"
            } else {
                req.target_op.as_str()
            };
            match path_grants::authorize_job_target(target_op, &req.job_id, &req.paths) {
                Ok(()) => Response::ok("authorize_path_batch"),
                Err(e) => Response {
                    ok: false,
                    op: "authorize_path_batch".into(),
                    error: Some(e),
                    ..Response::ok("authorize_path_batch")
                },
            }
        }
        _ => return None,
    };
    Some(resp)
}
