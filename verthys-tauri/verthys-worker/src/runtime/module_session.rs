/* module_session.rs — v4 模块 M1 会话命令（worker 转发层）
 *
 * 职责：把 v4_module_* 请求映射到 C 层 Verthys_V4Module*，只回传状态位
 * 与（恢复码轮换时的）新恢复码。模块口令/恢复码不缓存、不写日志，
 * MDEK 永不进入 worker 响应。
 */

use crate::runtime::ffi_types::VERTHYS_OK;
use crate::runtime::protocol::{Request, Response};
use crate::runtime::worker::Worker;

const VERTHYS_MODULE_ALL: u32 = 0xFFFFFFFF;

fn valid_module(module_id: u32) -> bool {
    module_id <= 2
}

fn optional_code(text: &str) -> Option<&str> {
    if text.is_empty() { None } else { Some(text) }
}

/// 删除模块时的口令选择：恢复会话必须传空（C 层仅在此模式放行），
/// 普通会话必须传宿主注入的当前容器口令。
fn delete_password(recovery_mode: bool, password: &str) -> Option<&str> {
    if recovery_mode { None } else { optional_code(password) }
}

/// 成功响应附带模块状态；状态查询失败不影响主操作结果。
fn with_status(mut resp: Response, worker: &Worker, module_id: u32) -> Response {
    if let Ok(st) = worker.call_v4_module_status(module_id) {
        resp.enabled = Some(st.enabled != 0);
        resp.unlocked = Some(st.unlocked != 0);
        resp.has_recovery = Some(st.has_recovery != 0);
        resp.deleted = Some(st.deleted != 0);
    }
    resp
}

pub(crate) fn handle_enable(req: &Request, worker: &Worker) -> Response {
    if !valid_module(req.module_id) || req.password.is_empty() {
        return Response::err("v4_module_enable", 0x00000001);
    }
    let rc = worker.call_v4_module_enable(
        req.module_id,
        req.password.as_str(),
        optional_code(req.recovery_code.as_str()),
    );
    if rc != VERTHYS_OK {
        return Response::err("v4_module_enable", rc);
    }
    with_status(Response::ok("v4_module_enable"), worker, req.module_id)
}

pub(crate) fn handle_unlock(req: &Request, worker: &Worker) -> Response {
    if !valid_module(req.module_id) || req.password.is_empty() {
        return Response::err("v4_module_unlock", 0x00000001);
    }
    let rc = worker.call_v4_module_unlock(req.module_id, req.password.as_str());
    if rc != VERTHYS_OK {
        return Response::err("v4_module_unlock", rc);
    }
    with_status(Response::ok("v4_module_unlock"), worker, req.module_id)
}

pub(crate) fn handle_lock(req: &Request, worker: &Worker) -> Response {
    if req.module_id != VERTHYS_MODULE_ALL && !valid_module(req.module_id) {
        return Response::err("v4_module_lock", 0x00000001);
    }
    let rc = worker.call_v4_module_lock(req.module_id);
    if rc == VERTHYS_OK {
        Response::ok("v4_module_lock")
    } else {
        Response::err("v4_module_lock", rc)
    }
}

pub(crate) fn handle_rotate_password(req: &Request, worker: &Worker) -> Response {
    if !valid_module(req.module_id)
        || req.old_password.is_empty()
        || req.new_password.is_empty()
    {
        return Response::err("v4_module_rotate_password", 0x00000001);
    }
    let rc = worker.call_v4_module_rotate_password(
        req.module_id,
        req.old_password.as_str(),
        req.new_password.as_str(),
    );
    if rc != VERTHYS_OK {
        return Response::err("v4_module_rotate_password", rc);
    }
    with_status(
        Response::ok("v4_module_rotate_password"),
        worker,
        req.module_id,
    )
}

pub(crate) fn handle_disable(req: &Request, worker: &Worker) -> Response {
    if !valid_module(req.module_id) || req.password.is_empty() {
        return Response::err("v4_module_disable", 0x00000001);
    }
    let rc = worker.call_v4_module_disable(req.module_id, req.password.as_str());
    if rc != VERTHYS_OK {
        return Response::err("v4_module_disable", rc);
    }
    with_status(Response::ok("v4_module_disable"), worker, req.module_id)
}

pub(crate) fn handle_delete(req: &Request, worker: &Worker) -> Response {
    if !valid_module(req.module_id) || req.confirm != "DELETE" {
        return Response::err("v4_module_delete", 0x00000001);
    }
    /* 恢复会话已由恢复码根认证，C 层只允许空口令删除；普通会话仍必须
     * 用宿主注入的容器口令验证 user 槽。会话模式以 C 层状态为权威，
     * 查询失败 fail-closed，不把“是否恢复会话”降级为前端判断。 */
    let recovery_mode = match worker.call_v4_keyfile_status() {
        Ok((_enabled, recovery)) => recovery,
        Err(rc) => return Response::err("v4_module_delete", rc),
    };
    let password = delete_password(recovery_mode, req.password.as_str());
    let rc = worker.call_v4_module_delete(
        req.module_id,
        password,
        req.confirm.as_str(),
    );
    if rc != VERTHYS_OK {
        /* 诊断只记错误码与长度，不含口令/确认字面量；release 构建为 no-op。 */
        crate::log::diag!(
            "[worker] v4_module_delete rc={:08X} module={} pw_len={} confirm_len={}",
            rc,
            req.module_id,
            req.password.len(),
            req.confirm.len()
        );
        return Response::err("v4_module_delete", rc);
    }
    with_status(Response::ok("v4_module_delete"), worker, req.module_id)
}

pub(crate) fn handle_bind_recovery(req: &Request, worker: &Worker) -> Response {
    if !valid_module(req.module_id)
        || req.password.is_empty()
        || req.recovery_code.is_empty()
    {
        return Response::err("v4_module_bind_recovery", 0x00000001);
    }
    let rc = worker.call_v4_module_bind_recovery(
        req.module_id,
        req.password.as_str(),
        req.recovery_code.as_str(),
    );
    if rc != VERTHYS_OK {
        return Response::err("v4_module_bind_recovery", rc);
    }
    with_status(
        Response::ok("v4_module_bind_recovery"),
        worker,
        req.module_id,
    )
}

pub(crate) fn handle_reseal_device(req: &Request, worker: &Worker) -> Response {
    if !valid_module(req.module_id) || req.password.is_empty() {
        return Response::err("v4_module_reseal_device", 0x00000001);
    }
    let rc = worker.call_v4_module_reseal_device(req.module_id, req.password.as_str());
    if rc != VERTHYS_OK {
        return Response::err("v4_module_reseal_device", rc);
    }
    with_status(
        Response::ok("v4_module_reseal_device"),
        worker,
        req.module_id,
    )
}

pub(crate) fn handle_status(req: &Request, worker: &Worker) -> Response {
    if !valid_module(req.module_id) {
        return Response::err("v4_module_status", 0x00000001);
    }
    match worker.call_v4_module_status(req.module_id) {
        Ok(st) => {
            let mut resp = Response::ok("v4_module_status");
            resp.enabled = Some(st.enabled != 0);
            resp.unlocked = Some(st.unlocked != 0);
            resp.has_recovery = Some(st.has_recovery != 0);
            resp.deleted = Some(st.deleted != 0);
            resp
        }
        Err(rc) => Response::err("v4_module_status", rc),
    }
}

pub(crate) fn handle_recovery_rotate(req: &Request, worker: &Worker) -> Response {
    if req.password.is_empty() || req.old_recovery.is_empty() {
        return Response::err("v4_recovery_rotate", 0x00000001);
    }
    match worker.call_v4_recovery_rotate(req.password.as_str(), req.old_recovery.as_str()) {
        Ok(code) => {
            let mut resp = Response::ok("v4_recovery_rotate");
            resp.recovery_code = Some(code);
            resp
        }
        Err(rc) => Response::err("v4_recovery_rotate", rc),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_password_empty_in_recovery_session() {
        assert_eq!(delete_password(true, "host-injected-password"), None);
        assert_eq!(delete_password(true, ""), None);
    }

    #[test]
    fn delete_password_requires_host_password_in_normal_session() {
        assert_eq!(delete_password(false, "host-injected-password"),
                   Some("host-injected-password"));
        assert_eq!(delete_password(false, ""), None);
    }
}
