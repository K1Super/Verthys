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
use crate::runtime::worker::clamp_enum_count;
use crate::runtime::protocol::{Request, Response, RecordEntry, base64_encode, base64_decode};
use crate::runtime::ffi_types::{
    VERTHYS_OK, VERTHYS_PERSIST_OK, VERTHYS_SCAN_PROJECT_FULL, VERTHYS_SCAN_PROJECT_INDEX,
};
use crate::runtime::budget::PB_ENUM_RESPONSE_DATA_BUDGET_BYTES;
use crate::runtime::gmk::{
    handle_derive_global_key, handle_derive_and_store_global_key, handle_verify_global_key,
    handle_derive_module_subkey, handle_clear_global_key,
};
use zeroize::Zeroizing;

/* 全量枚举遍历上界：与 C 层温缓存单段条目上限同值（100_000），
 * 全量模式以该值兜底终止，防无限枚举。 */
const MAX_ENUM_RECORDS: u64 = 100_000;

/// INDEX 投影内联阈值上限（字节，取跨层预算常量）
///
/// 取批预算为软水位线（越过即停），无法约束"单条"自身大小：阈值过大时
/// 单条内联记录即可撑爆 SHM 段。上限取值保证"单条最大内联记录 + 预算 +
/// 段内固定开销"仍落在段容量内（由预算常量的编译期断言把守）；
/// 调用方的缓存管控阈值远小于此上限，本夹层只用于阻断协议层的越界取值。
const SCAN_INDEX_INLINE_MAX_BYTES: u64 = crate::runtime::budget::PB_SCAN_INDEX_INLINE_MAX_BYTES;

/// 解析扫描投影请求字段 → C 层 VerthysScanProject 取值
///
/// 缺省（空串）与显式 "full" 等价（既有调用方语义不变）；未知取值显式
/// 拒绝，避免拼写错误被静默当成"全量解密"这类更重且更慢的语义。
fn parse_scan_project(name: &str) -> Result<u32, ()> {
    match name {
        "" | "full" => Ok(VERTHYS_SCAN_PROJECT_FULL),
        "index" => Ok(VERTHYS_SCAN_PROJECT_INDEX),
        _ => Err(()),
    }
}

/// 解析并夹紧 INDEX 内联阈值（请求字段 → C 层入参）
///
/// 夹层由 SCAN_INDEX_INLINE_MAX_BYTES 给出：请求值超过上限即收敛到上限，
/// 使"单条最大内联记录 + 取批预算 + 段内固定开销"恒落在 SHM 段容量内。
fn parse_inline_max_bytes(raw: u64) -> u64 {
    raw.min(SCAN_INDEX_INLINE_MAX_BYTES)
}

/* 修复----------------------------------------------------------- *
 * 根治：解锁成功后进程内探测全局主密钥记录                  *
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
        diag!("[worker] probe_global_key: 确认无全局密钥记录（进程内类型探测未命中）");
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

/// 单次响应可承载的记录数据预算（base64 长度合计）
///
/// 取值来自跨层预算常量单一权威来源（生成物 PB_ENUM_RESPONSE_DATA_BUDGET_BYTES）：
/// 与写入侧单条记录上限同值——单条最大记录经取回再编码后恒可单独返回；
/// 多记录聚合批次按预算截批并由调用方以游标续批。写侧另有响应行上限
/// （PB_IPC_MAX_RESPONSE_LINE_BYTES）把超限响应收敛为受控错误行，本预算
/// 必须小于该上限（生成器静态断言保证），因此正常批次不会触发写侧兜底。
const ENUM_RESPONSE_DATA_BUDGET_BYTES: usize = PB_ENUM_RESPONSE_DATA_BUDGET_BYTES as usize;

/// 批量枚举批次构造（预算截批 + 游标语义，纯逻辑便于单测覆盖）
///
/// 语义：
///   - 从 start_id 逐号读取；命中上限 max_count、预算、连续 5 次未命中
///     或编号上限即结束本批
///   - 返回值第三项 exhausted=true 表示已遍历完毕；预算截批时保持 false，
///     调用方以「返回 ID + 1」为下一批起点，保证不丢记录、不重复遍历
///   - 单条记录自身超预算（仅历史存量数据可能超出写入侧上限）：以空数据
///     占位参与返回，使游标推进（回避死循环），调用方经 get_record 单独
///     获取时得到明确错误而不是超长响应行
///
/// @param start_id 起始记录 ID（≥1）
/// @param max_count 本批条数上限（usize::MAX 表示不限）
/// @param fetch 单条读取函数（返回 (rtype, name, data) 或错误码）
/// @returns (本批记录, 本批最后一条记录 ID, 是否遍历完毕)
fn build_enum_batch<F>(
    start_id: u64,
    max_count: usize,
    mut fetch: F,
) -> (Vec<RecordEntry>, u64, bool)
where
    F: FnMut(u64) -> Result<(u32, String, Vec<u8>), u32>,
{
    let mut records: Vec<RecordEntry> = Vec::with_capacity(max_count.min(500));
    let mut null_streak: u32 = 0;
    let mut last_id: u64 = start_id.saturating_sub(1);
    let mut exhausted = false;
    // 本批已累计的 base64 数据字节（预算控制口径）
    let mut accumulated_b64_bytes: usize = 0;
    // 预算截批标志：越过预算而提前结束时必须保持 exhausted=false
    let mut budget_stopped = false;

    for id in start_id..=MAX_ENUM_RECORDS {
        if records.len() >= max_count {
            // 已达本批上限，停止枚举（未遍历完毕，exhausted=false）
            break;
        }
        match fetch(id) {
            Ok((rtype, name, data)) => {
                null_streak = 0;
                last_id = id;
                // base64 长度按 4*ceil(n/3) 精确推导，避免仅为预算判定
                // 先行编码（大记录编码是纯浪费）
                let b64_len = data.len().div_ceil(3) * 4;
                if !records.is_empty()
                    && accumulated_b64_bytes + b64_len > ENUM_RESPONSE_DATA_BUDGET_BYTES
                {
                    // 追加本条将越过预算：截批（本条留待下一批返回），
                    // 游标保持在上一条，保证续批不丢记录
                    last_id = id.saturating_sub(1);
                    budget_stopped = true;
                    break;
                }
                if b64_len > ENUM_RESPONSE_DATA_BUDGET_BYTES {
                    // 单条记录自身超预算：行协议无法承载，以空数据占位并
                    // 告警；调用方经 get_record 单独获取时会收到明确错误，
                    // 绝不触发「响应行超限 → 协议断开」的级联故障
                    diag!(
                        "[worker] enumerate_records: 记录 {} 超出响应预算（b64={} 字节），本批空数据占位",
                        id,
                        b64_len
                    );
                    accumulated_b64_bytes =
                        accumulated_b64_bytes.saturating_add(b64_len.min(1024));
                    records.push(RecordEntry {
                        id,
                        rtype,
                        name,
                        data: String::new(),
                    });
                    continue;
                }
                accumulated_b64_bytes = accumulated_b64_bytes.saturating_add(b64_len);
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
    if !budget_stopped && last_id >= MAX_ENUM_RECORDS {
        // 编号区间自然走到上限：视为遍历完毕
        exhausted = true;
    }
    if max_count == usize::MAX && !exhausted && !budget_stopped {
        // 全量模式（无 max_count）未触发编号上限与预算截批，说明循环因
        // 编号区间耗尽而结束：视为遍历完毕。预算截批时必须保持
        // exhausted=false，否则调用方会丢失剩余记录
        exhausted = true;
    }
    (records, last_id, exhausted)
}

/// 解析请求里的 SHM 认证密钥（一次性 32 字节随机 key 的 base64）
///
/// 空串 = 未提供（legacy 或无认证写段，返回 None）；非空则必须为
/// base64 且解码后恰为 32 字节，否则判定无效参数并向调用方返回错误响应。
/// 合法密钥用 Zeroizing 持有，Drop 后自动清零。
/// 错误变体经 Box 间接持有（Response 体积大，避免热路径返回值的
/// 栈膨胀；错误路径为冷路径，一次堆分配可忽略）。
fn parse_shm_auth_key(op: &str, shm_key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Box<Response>> {
    if shm_key.is_empty() {
        return Ok(None);
    }
    match base64_decode(shm_key) {
        Ok(bytes) if bytes.len() == 32 => Ok(Some(Zeroizing::new(bytes))),
        _ => Err(Box::new(Response::err(op, 0x01))),
    }
}

pub(crate) fn handle_request(worker: &mut Worker, req: &Request) -> Response {
    diag!("[worker] 处理请求: op={}", req.op);
    match req.op.as_str() {
        "ping" => Response::ok("ping"),
        "unlock" => {
            /* 透传 flags（预热状态位域）给 C 层 Verthys_Unlock */
            /* VERTHYS_ERR_PARTIAL_UNLOCK 表示容器已进入
             * 最小可操作状态（超级块验证 + 密钥导入 + 分区表加载完成，索引
             * 预热后台进行中），与 verthys_api.c Unlock 成功分支语义一致——
             * 按成功处理，正常执行 GMK 探测并返回。 */
            const VERTHYS_ERR_PARTIAL_UNLOCK: u32 = 0x00000011;
            let r = worker.call_unlock(&req.path, &req.password, req.flags);
            if r == VERTHYS_OK || r == VERTHYS_ERR_PARTIAL_UNLOCK {
                /* 根治：解锁成功后进程内探测全局主密钥记录，
                 * 结果内联到响应三字段，消除前端 IPC 链路与 v1 假阴性死锁。 */
                let (has_gmk, gmk_id, gmk_record) = probe_global_key_inproc(worker);
                Response {
                    has_global_key: has_gmk,
                    global_key_id: gmk_id,
                    global_key_record: gmk_record,
                    ..Response::ok("unlock")
                }
            } else {
                /* 修复（D-STATE-RECOVERY）：级联 INVALID 状态恢复
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
            // 路径为前端可控字符串：日志只记字节长度与 preset，
            // 不回显原始内容（防内嵌 NUL/控制符日志注入）
            diag!("[worker] call_create_with_preset: path_bytes={} preset={}", req.path.len(), req.preset);
            let r = worker.call_create_with_preset(&req.path, &req.password, req.preset);
            diag!("[worker] create_with_preset 返回: {:08X}", r);
            if r == VERTHYS_OK {
                Response::ok("create_with_preset")
            } else {
                /* 修复（D-STATE-RECOVERY）：级联 INVALID 状态恢复
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
        // 根治：Verthys_Flush 显式刷盘
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
            Ok((rtype, name, data)) => {
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
                    return Response {
                        ok: false,
                        op: "get_record".into(),
                        error: Some(format!(
                            "record_too_large: 记录数据 {} 字节超出单条返回上限",
                            data.len()
                        )),
                        ..Response::ok("get_record")
                    };
                }
                Response {
                    ok: true,
                    op: "get_record".into(),
                    rtype: Some(rtype),
                    name: Some(name),
                    data: Some(base64_encode(&data)),
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
        "scan_open" => {
            // 打开扫描游标：创建共享内存 + 复用 vbtree_scan_all + 首批预加载
            // 首批同样走 SHM 认证（与 fetch 一致，不存未认证批次窗口）
            // 条数值外部可控：双端 clamp（本端 + worker 端），防巨大分配
            let start_lid = if req.id > 0 { req.id } else { 0 };
            let batch_size = if req.max_count > 0 { clamp_enum_count(req.max_count as u64) } else { 500 };
            // 投影：缺省 FULL（历史行为）；INDEX 只对不超过阈值的记录解密取数
            let project = match parse_scan_project(&req.project) {
                Ok(p) => p,
                Err(()) => return Response::err("scan_open", 0x00000001u32 /* INVALID */),
            };
            let inline_max = parse_inline_max_bytes(req.inline_max_bytes);
            let auth_key = match parse_shm_auth_key("scan_open", &req.shm_key) {
                Ok(k) => k,
                Err(resp) => return *resp,
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
                Err(resp) => return *resp,
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
                Err(resp) => return *resp,
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
                Err(resp) => return *resp,
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
        // GMK 派生命令（#2 敏感操作下沉）
        "derive_global_key" => handle_derive_global_key(req),
        // 派生并持久化（首次初始化专用：存储+读回验证在 worker 进程内
        // 原子完成，无跨 IPC 中间态窗口）
        "derive_and_store_global_key" => handle_derive_and_store_global_key(req, worker),
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

/* ------------------------------------------------------------------ *
 * 单元测试：批量枚举响应预算与游标语义                                  *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// 构造记录源：仅存在给定 ID/长度的记录，其余返回未命中
    fn source_with(sizes: &[(u64, usize)]) -> impl Fn(u64) -> Result<(u32, String, Vec<u8>), u32> {
        let map: HashMap<u64, Vec<u8>> = sizes
            .iter()
            .map(|(id, len)| (*id, vec![0xA5u8; *len]))
            .collect();
        move |id: u64| match map.get(&id) {
            Some(data) => Ok((1u32, format!("rec-{}", id), data.clone())),
            None => Err(0x0000_0004u32),
        }
    }

    /// 预算内续批：全部记录恰好取回一次且顺序正确（不丢、不重）
    #[test]
    fn test_enum_batch_splits_by_budget_without_loss() {
        // 每条 3MiB 原始数据 → base64 4MiB；预算 12MiB → 每批至多 3 条
        let sizes: Vec<(u64, usize)> = (1..=8).map(|i| (i, 3 * 1024 * 1024)).collect();
        let fetch = source_with(&sizes);

        let mut collected: Vec<u64> = Vec::new();
        let mut cursor: u64 = 1;
        let mut batches = 0usize;
        loop {
            let (records, last_id, exhausted) = build_enum_batch(cursor, 200, &fetch);
            batches += 1;
            let mut accumulated = 0usize;
            for r in &records {
                accumulated += r.data.len();
                collected.push(r.id);
            }
            assert!(
                accumulated <= ENUM_RESPONSE_DATA_BUDGET_BYTES,
                "单批 base64 载荷 {} 越过预算 {}",
                accumulated,
                ENUM_RESPONSE_DATA_BUDGET_BYTES
            );
            if exhausted {
                break;
            }
            assert!(last_id >= cursor, "截批时必须推进游标");
            cursor = last_id + 1;
            assert!(batches < 20, "批次数异常");
        }
        assert_eq!(collected, (1..=8).collect::<Vec<u64>>(), "记录必须按序完整取回一次");
        assert!(batches >= 3, "8 条 4MiB 记录必须被预算拆成至少 3 批（实际 {}）", batches);
    }

    /// 单条超预算记录：空数据占位且游标推进（不得死循环、不得超长响应）
    #[test]
    fn test_enum_batch_oversize_single_record_placeholder() {
        // 13MiB 原始数据 → base64 ≈ 17.3MiB，超过预算
        let fetch = source_with(&[(1, 13 * 1024 * 1024), (2, 16)]);
        let (records, last_id, exhausted) = build_enum_batch(1, 200, &fetch);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, 1);
        assert!(records[0].data.is_empty(), "超预算记录以空数据占位");
        assert_eq!(records[1].id, 2);
        assert!(!records[1].data.is_empty(), "预算内记录正常返回");
        assert_eq!(last_id, 2);
        let _ = exhausted;
    }

    /// 遍历终止语义：连续 5 次未命中 → exhausted；max_count 截批 → 未遍历完
    #[test]
    fn test_enum_batch_exhausted_and_max_count_semantics() {
        let sizes: Vec<(u64, usize)> = (1..=3).map(|i| (i, 32)).collect();
        let fetch = source_with(&sizes);

        // max_count=2：两条后截批，未遍历完毕（游标推进到 2）
        let (records, last_id, exhausted) = build_enum_batch(1, 2, &fetch);
        assert_eq!(records.len(), 2);
        assert_eq!(last_id, 2);
        assert!(!exhausted, "max_count 截批时不得标记遍历完毕");

        // 继续一批：取回第 3 条后连续未命中 → 遍历完毕
        let (records2, last_id2, exhausted2) = build_enum_batch(last_id + 1, 200, &fetch);
        assert_eq!(records2.len(), 1);
        assert_eq!(records2[0].id, 3);
        assert_eq!(last_id2, 3);
        assert!(exhausted2, "连续未命中达到阈值后必须标记遍历完毕");
    }

    /// 空容器：起点即无记录，应在固定次数内判定遍历完毕（不死循环）
    #[test]
    fn test_enum_batch_empty_container_terminates() {
        let fetch = source_with(&[]);
        let (records, _last_id, exhausted) = build_enum_batch(1, 200, &fetch);
        assert!(records.is_empty());
        assert!(exhausted, "无记录时必须判定遍历完毕");
    }

    /// 扫描投影解析：缺省/显式 full 等价于历史行为；未知取值拒绝（不静默降级）
    #[test]
    fn test_scan_project_parsing_is_strict() {
        assert_eq!(parse_scan_project("").unwrap(), VERTHYS_SCAN_PROJECT_FULL);
        assert_eq!(parse_scan_project("full").unwrap(), VERTHYS_SCAN_PROJECT_FULL);
        assert_eq!(parse_scan_project("index").unwrap(), VERTHYS_SCAN_PROJECT_INDEX);
        assert!(parse_scan_project("INDEX").is_err(), "协议取值大小写敏感");
        assert!(parse_scan_project("idx").is_err(), "未知取值必须拒绝");
    }

    /// 内联阈值夹层：请求值超过上限时收敛到上限（防单条记录撑爆 SHM 段）
    #[test]
    fn test_scan_inline_threshold_clamped() {
        assert_eq!(parse_inline_max_bytes(0), 0, "纯索引阈值原样保留");
        assert_eq!(parse_inline_max_bytes(64 * 1024), 64 * 1024);
        assert_eq!(
            parse_inline_max_bytes(u64::MAX),
            SCAN_INDEX_INLINE_MAX_BYTES,
            "越界取值必须收敛到上限"
        );
    }

    /// 取批预算与段容量不变式：水位线 + 单条最大内联记录 + 段内固定开销
    /// 必须落在 SHM 段容量内（软水位线最多超出一条记录大小）。
    /// SHM 为 Windows 专用传输层，非 Windows 无该路径，故仅 Windows 校验。
    #[cfg(windows)]
    #[test]
    fn test_scan_batch_budget_fits_shm_segment() {
        use crate::runtime::scan_shm::{SCAN_BATCH_MAX_BYTES, SHM_DEFAULT_SIZE, SHM_ENTRY_SIZE};
        // 批内固定开销：头部 + 条目表（批上限 500 条）+ 认证块
        const OVERHEAD: u64 = 64 + 500 * (SHM_ENTRY_SIZE as u64) + 32;
        let worst_case = SCAN_BATCH_MAX_BYTES + SCAN_INDEX_INLINE_MAX_BYTES + OVERHEAD;
        assert!(
            worst_case <= SHM_DEFAULT_SIZE as u64,
            "最坏单批 {} 字节必须落在段容量 {} 字节内",
            worst_case,
            SHM_DEFAULT_SIZE
        );
    }
}
