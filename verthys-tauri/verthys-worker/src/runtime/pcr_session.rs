/*
 * pcr_session.rs — PCR 策略命令
 *
 * 职责：把 PCR 状态/启停/重密封请求转发到 C 层；恢复码只在本次调用内
 * 使用，不缓存、不写日志。C 层负责恢复码二次认证与 PCR 槽持久化，
 * worker 仅做参数边界校验与响应投影。
 */
use super::protocol::Response;
use super::worker::Worker;

/// PCR 状态查询：返回 enabled 与位图，不返回任何密钥或 TPM 细节。
pub(crate) fn handle_pcr_status(req: &super::protocol::Request, worker: &Worker) -> Response {
    match worker.call_pcr_status() {
        Ok((enabled, select)) => Response {
            pcr_enabled: Some(enabled != 0),
            pcr_select: Some(select),
            ..Response::ok(req.op.as_str())
        },
        Err(rc) => Response::err(req.op.as_str(), rc),
    }
}

/// 启用 PCR 绑定。位图合法性由 C 层统一校验；空恢复码仅在恢复会话有效。
pub(crate) fn handle_pcr_enable(req: &super::protocol::Request, worker: &Worker) -> Response {
    let rc = worker.call_pcr_enable(req.pcr_select, req.recovery_code.as_str());
    if rc != crate::runtime::ffi_types::VERTHYS_OK {
        return Response::err(req.op.as_str(), rc);
    }
    handle_pcr_status(req, worker)
}

/// 关闭 PCR 绑定。
pub(crate) fn handle_pcr_disable(req: &super::protocol::Request, worker: &Worker) -> Response {
    let rc = worker.call_pcr_disable(req.recovery_code.as_str());
    if rc != crate::runtime::ffi_types::VERTHYS_OK {
        return Response::err(req.op.as_str(), rc);
    }
    handle_pcr_status(req, worker)
}

/// 用当前 PCR 重密封；恢复会话可传空恢复码。
pub(crate) fn handle_pcr_reseal(req: &super::protocol::Request, worker: &Worker) -> Response {
    let rc = worker.call_pcr_reseal(req.recovery_code.as_str());
    if rc != crate::runtime::ffi_types::VERTHYS_OK {
        return Response::err(req.op.as_str(), rc);
    }
    handle_pcr_status(req, worker)
}
