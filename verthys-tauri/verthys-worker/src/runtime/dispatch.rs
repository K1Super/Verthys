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
use crate::runtime::protocol::{
    base64_decode, base64_encode, RecordEntry, Request, Response, StorageStatsEntry,
};
use crate::runtime::ffi_types::{
    VerthysRecordC, VERTHYS_OK, VERTHYS_PERSIST_OK, VERTHYS_SCAN_PROJECT_FULL,
    VERTHYS_SCAN_PROJECT_INDEX, VERTHYS_SYMBOL_UNSUPPORTED,
};
use crate::runtime::budget::PB_ENUM_RESPONSE_DATA_BUDGET_BYTES;
use crate::runtime::path_grants;
use crate::runtime::media;
use crate::runtime::file_import;
use crate::runtime::module_keys;
use crate::runtime::module_session;
use crate::runtime::pcr_session;
use crate::runtime::gmk::{
    handle_derive_and_store_global_key, handle_verify_global_key,
    handle_change_global_key, handle_clear_global_key,
};
use zeroize::{Zeroize, Zeroizing};

mod routes_core;
mod routes_media;
mod routes_records;
mod routes_scan;
mod routes_security;
mod routes_v4;
mod routes_rotate;

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

/// C 层库锁错误码（映射为 worker 0x0A RATE）
const VERTHYS_ERR_RATE: u32 = 0x0000000A;

/// 解析 32 位十六进制 UUID；长度或字符非法返回 None。
fn parse_uuid_hex(text: &str) -> Option<[u8; 16]> {
    let bytes = text.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        out[i] = ((hi as u8) << 4) | (lo as u8);
    }
    Some(out)
}

/// 解锁失败响应：库锁命中时附带剩余秒数，供 UI 展示“已锁定 X 秒”。
fn unlock_error(worker: &Worker, op: &str, rc: u32) -> Response {
    if rc == VERTHYS_ERR_RATE {
        let secs = worker.call_get_lib_lockout_remaining().unwrap_or(0);
        return Response::err_with_retry(op, rc, secs);
    }
    Response::err(op, rc)
}

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

/* ----------------------------------------------------------- *
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
        Ok((_rtype, mut name, mut data)) => {
            let b64 = base64_encode(&data);
            diag!(
                "[worker] probe_global_key: 读取记录成功 ({} bytes → b64 {})",
                data.len(),
                b64.len()
            );
            /* 记录名与原始明文在派生 base64 后立即清零，避免调用栈
             * 与分配器继续持有全局主密钥记录内容。 */
            name.zeroize();
            data.zeroize();
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
            Ok((rtype, mut name, mut data)) => {
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
                    name.zeroize();
                    data.zeroize();
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
                    data.zeroize();
                    continue;
                }
                accumulated_b64_bytes = accumulated_b64_bytes.saturating_add(b64_len);
                records.push(RecordEntry {
                    id,
                    rtype,
                    name,
                    data: base64_encode(&data),
                });
                data.zeroize();
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

/// 消费路径型操作所需的一次性授权；缺失时返回受控拒绝响应。
///
/// 授权由宿主在用户选择路径后签发，与操作、模式、规范化路径三元组绑定。
fn require_path_grant(op: &str, mode: &str, path: &str) -> Option<Response> {
    if path_grants::consume(op, mode, path) {
        return None;
    }
    Some(Response {
        ok: false,
        op: op.into(),
        error: Some("路径未授权或授权已过期".into()),
        ..Response::ok(op)
    })
}

pub(crate) fn handle_request(worker: &mut Worker, req: &Request) -> Response {
    diag!("[worker] 处理请求: op={}", req.op);
    if let Some(resp) = routes_core::handle(worker, req) { return resp; }
    if let Some(resp) = routes_media::handle(worker, req) { return resp; }
    if let Some(resp) = routes_records::handle(worker, req) { return resp; }
    if let Some(resp) = routes_scan::handle(worker, req) { return resp; }
    if let Some(resp) = routes_security::handle(worker, req) { return resp; }
    if let Some(resp) = routes_v4::handle(worker, req) { return resp; }
    if let Some(resp) = routes_rotate::handle(worker, req) { return resp; }
    Response {
        ok: false,
        op: req.op.clone(),
        error: Some("unknown op".into()),
        ..Response::ok(&req.op)
    }
}

/* ------------------------------------------------------------------ *
 * 单元测试：批量枚举响应预算与游标语义                                  *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parse_uuid_hex_accepts_lower_and_upper() {
        let lower = parse_uuid_hex("0123456789abcdef0123456789abcdef").unwrap();
        let upper = parse_uuid_hex("0123456789ABCDEF0123456789ABCDEF").unwrap();
        assert_eq!(lower, upper);
        assert_eq!(lower[0], 0x01);
        assert_eq!(lower[15], 0xEF);
    }

    #[test]
    fn parse_uuid_hex_rejects_bad_input() {
        assert!(parse_uuid_hex("").is_none());
        assert!(parse_uuid_hex("0011").is_none());
        assert!(parse_uuid_hex("zz23456789abcdef0123456789abcdef").is_none());
        assert!(parse_uuid_hex("0123456789abcdef0123456789abcde").is_none());
    }

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
