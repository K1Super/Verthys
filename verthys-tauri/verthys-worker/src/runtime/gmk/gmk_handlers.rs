/* GMK 命令处理：derive / verify / change / clear 与 panic 清零
 *
 * 所有密钥派生在 worker 子进程内完成，主进程/前端仅传递参数。
 * 任何响应都不得携带原始密钥字节：GMK 与派生密钥只以密文记录或
 * worker 内部状态存在。
 */

use super::gmk_material::{derive_gmk_material, verify_gmk_material};
use super::gmk_records::{resolve_valid_global_key_records, GmkRecordIo, WorkerRecordIo};
use super::gmk_state::{
    store_gmk, GmkMaterial, CODE_AUTH, CODE_CORRUPT, CODE_NOTFOUND, GLOBAL_KEY_MAX_CANDIDATES,
    GLOBAL_KEY_NAME, GLOBAL_KEY_RECORD_LEN, TYPE_GLOBAL_KEY, GMK,
};
use crate::runtime::protocol::{Request, Response, base64_encode};
use crate::runtime::worker::Worker;

/// 派生并持久化全局密钥（首次初始化专用，敏感操作下沉）
///
/// 时序：派生 GMK → 清理结构不完整的中断残留 → 既有合法记录直接拒绝 →
/// 写入新记录 → 读回逐字节验证 → 成功后才写入 GMK 槽。任一失败都不触碰槽，
/// 避免"记录未落盘但内存已换钥"的中间态。
pub(crate) fn handle_derive_and_store_global_key(req: &Request, worker: &Worker) -> Response {
    use crate::runtime::ffi_types::VERTHYS_OK;

    let GmkMaterial { gmk, record } = match derive_gmk_material(
        req.password.as_str(),
        req.bin_data.as_str(),
        req.bin_password.as_str(),
        "derive_and_store_global_key",
    ) {
        Ok(m) => m,
        Err(resp) => return *resp,
    };
    let mut gmk_slot = Some(gmk);

    // 失败统一补偿：尽力回收半成品记录（GMK 未写槽，无需清理）
    let mut written_id: Option<u64> = None;
    let cleanup = |written: &mut Option<u64>| {
        if let Some(id) = written.take() {
            let _ = worker.call_delete_record(id);
        }
    };

    // 1. 既有记录判定：derive 仅用于首次初始化。结构合法的 global-key
    //    记录必须经 verify / change 证明持有旧钥后才能替换；在这里删除
    //    会让绕过主进程状态机的调用直接覆盖既有密钥。只有结构不完整的
    //    中断残留（长度不符或不可读）才允许清理。
    let mut probed = 0usize;
    loop {
        if probed >= GLOBAL_KEY_MAX_CANDIDATES {
            cleanup(&mut written_id);
            return Response::err_raw("derive_and_store_global_key", CODE_CORRUPT);
        }
        probed += 1;
        let (rc, found, lid) = worker.call_find_first_lid_by_type(TYPE_GLOBAL_KEY);
        if rc != VERTHYS_OK {
            cleanup(&mut written_id);
            return Response::err_raw("derive_and_store_global_key", rc);
        }
        if !found {
            break;
        }
        let valid = matches!(
            worker.call_get_record(lid),
            Ok((_rtype, _name, data)) if data.len() == GLOBAL_KEY_RECORD_LEN
        );
        if valid {
            cleanup(&mut written_id);
            return Response::err_raw("derive_and_store_global_key", CODE_AUTH);
        }
        let del_rc = worker.call_delete_record(lid);
        if del_rc != VERTHYS_OK {
            cleanup(&mut written_id);
            return Response::err_raw("derive_and_store_global_key", del_rc);
        }
    }

    // 2. 写入新记录（单调用原子写入）
    let id = match worker.call_add_record(TYPE_GLOBAL_KEY as u32, GLOBAL_KEY_NAME, &record) {
        Ok(id) => id,
        Err(code) => {
            cleanup(&mut written_id);
            return Response::err_raw("derive_and_store_global_key", code);
        }
    };
    written_id = Some(id);

    // 3. 内容级读回验证：GetRecord 读回必须与写入逐字节一致
    match worker.call_get_record(id) {
        Ok((_rtype, _name, data)) if data == record => {
            // 4. 记录已确认落盘，才允许写 GMK 槽
            if let Some(gmk) = gmk_slot.take() {
                store_gmk(gmk);
            }
            Response {
                ok: true,
                op: "derive_and_store_global_key".into(),
                id: Some(id),
                data: Some(base64_encode(&record)),
                ..Response::ok("derive_and_store_global_key")
            }
        }
        Ok(_) => {
            cleanup(&mut written_id);
            Response::err_raw("derive_and_store_global_key", CODE_CORRUPT)
        }
        Err(code) => {
            cleanup(&mut written_id);
            Response::err_raw("derive_and_store_global_key", code)
        }
    }
}

/// 验证全局密钥（后续进入时 / 中枢重认证）
/// 输入：password + bin_data + bin_password + record(base64)
/// 输出：ok=true 验证成功，GMK 存入内存
pub(crate) fn handle_verify_global_key(req: &Request) -> Response {
    match verify_gmk_material(
        req.password.as_str(),
        req.bin_data.as_str(),
        req.bin_password.as_str(),
        req.data.as_str(),
        "verify_global_key",
    ) {
        Ok(gmk) => {
            store_gmk(gmk);
            Response::ok("verify_global_key")
        }
        Err(resp) => *resp,
    }
}

/// 修改全局密钥（后端单命令的 worker 侧编排）
///
/// 顺序与失败语义（见记录不变量 R5/R6）：
///   1. 解析最新有效记录（max id）
///   2. 核验旧三要素（旧 GMK 仅内存，不入槽）
///   3. 派生新三要素（新 GMK 暂存，不入槽）
///   4. 写入新记录 + 逐字节读回
///   5. 删除旧记录与历史残留 + 读回确认
///   6. 成功后才把新 GMK 写入槽
///
/// 任何早于第 6 步的失败都不触碰 GMK 槽；删旧失败不判失败：新记录
/// 已是最新权威，残留由下次解锁收敛清除（cleanup_pending=true）。
pub(crate) fn handle_change_global_key(req: &Request, worker: &Worker) -> Response {
    handle_change_global_key_with(req, &WorkerRecordIo(worker))
}

pub(super) fn handle_change_global_key_with(req: &Request, io: &dyn GmkRecordIo) -> Response {
    // 1. 解析权威记录：最新有效记录（max id）
    let records = match resolve_valid_global_key_records(io) {
        Ok(r) => r,
        Err(rc) => return Response::err_raw("change_global_key", rc),
    };
    let (old_id, old_record) = match records.last() {
        Some((id, data)) => (*id, data.clone()),
        None => return Response::err("change_global_key", CODE_NOTFOUND),
    };

    // 2. 核验旧三要素（旧 GMK 仅用于解密验证，不写槽）
    let old_record_b64 = base64_encode(&old_record);
    match verify_gmk_material(
        req.password.as_str(),
        req.bin_data.as_str(),
        req.bin_password.as_str(),
        &old_record_b64,
        "change_global_key",
    ) {
        Ok(old_gmk) => drop(old_gmk),
        Err(resp) => return *resp,
    }

    // 3. 派生新三要素（新 GMK 暂存，不写槽）
    let GmkMaterial {
        gmk: new_gmk,
        record: new_record,
    } = match derive_gmk_material(
        req.new_password.as_str(),
        req.new_bin_data.as_str(),
        req.new_bin_password.as_str(),
        "change_global_key",
    ) {
        Ok(m) => m,
        Err(resp) => return *resp,
    };

    // 4. 提交新记录：
    //    - 核心支持原子替换（API 0x0017）→ 单次事务内"写新 + 墓碑旧"，
    //      崩溃不会出现两条并存；
    //    - 旧核心未导出该符号 → 回退"写新 + 读回 + 删旧"（下方收敛处理旧记录）。
    //    原子路径读回不一致属于提交后完整性异常：旧记录已墓碑，不能再
    //    回滚，返回 CORRUPT 且不换槽（fail-closed，等待完整性巡检介入）。
    let new_id = match io.replace_record(old_id, TYPE_GLOBAL_KEY, GLOBAL_KEY_NAME, &new_record) {
        Ok(id) => {
            if id <= old_id {
                return Response::err_raw("change_global_key", CODE_CORRUPT);
            }
            match io.get_record(id) {
                Ok((rtype, name, data))
                    if rtype == TYPE_GLOBAL_KEY as u32
                        && name == GLOBAL_KEY_NAME
                        && data == new_record => {}
                _ => return Response::err_raw("change_global_key", CODE_CORRUPT),
            }
            id
        }
        Err(rc) if rc == crate::runtime::ffi_types::VERTHYS_SYMBOL_UNSUPPORTED => {
            // 兼容旧核心：写新 + 读回；失败回收新记录，旧记录与旧 GMK 保持不变
            let id = match io.add_record(TYPE_GLOBAL_KEY, GLOBAL_KEY_NAME, &new_record) {
                Ok(id) => id,
                Err(rc) => return Response::err_raw("change_global_key", rc),
            };
            if id <= old_id {
                let _ = io.delete_record(id);
                return Response::err_raw("change_global_key", CODE_CORRUPT);
            }
            match io.get_record(id) {
                Ok((rtype, name, data))
                    if rtype == TYPE_GLOBAL_KEY as u32
                        && name == GLOBAL_KEY_NAME
                        && data == new_record => {}
                Ok(_) => {
                    let _ = io.delete_record(id);
                    return Response::err_raw("change_global_key", CODE_CORRUPT);
                }
                Err(rc) => {
                    let _ = io.delete_record(id);
                    return Response::err_raw("change_global_key", rc);
                }
            }
            id
        }
        Err(rc) => return Response::err_raw("change_global_key", rc),
    };

    // 5. 删除旧记录与历史残留：新记录已落盘，清理失败不再判失败——
    //    最新记录为权威，残留由下次解锁收敛清除。
    //    原子替换已墓碑旧记录，此处的 NOTFOUND 视为"已删除"。
    let mut deleted = Vec::new();
    let mut cleanup_pending = false;
    for (id, _) in records.iter() {
        if *id == new_id {
            continue;
        }
        match io.delete_record(*id) {
            Ok(()) => match io.get_record(*id) {
                Err(CODE_NOTFOUND) => deleted.push(*id),
                _ => cleanup_pending = true,
            },
            Err(CODE_NOTFOUND) => deleted.push(*id),
            Err(_) => cleanup_pending = true,
        }
    }

    // 7. 新记录确认落盘后才换槽
    store_gmk(new_gmk);

    let mut resp = Response::ok("change_global_key");
    resp.id = Some(new_id);
    resp.data = Some(base64_encode(&new_record));
    resp.ids = deleted;
    resp.cleanup_pending = Some(cleanup_pending);
    resp
}

/// 清零 GMK 内存（lockAll 时调用）
pub(crate) fn handle_clear_global_key() -> Response {
    GMK.with(|g| *g.borrow_mut() = None);
    Response::ok("clear_global_key")
}

/// panic 清零器：清除当前线程 GMK TLS 驻留。
/// Zeroizing 的 Drop 在正常展开时同样会清零，此处为 panic hook 内
/// 的显式前置清零——hook 早于栈展开执行，清零先于任何诊断/转储输出。
pub(crate) fn wipe_thread_gmk() {
    GMK.with(|g| *g.borrow_mut() = None);
}
