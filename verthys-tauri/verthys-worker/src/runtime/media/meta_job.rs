/*
 * media/meta_job.rs — 网格元数据与损坏探测的原生入口
 *
 * 列表/损坏扫描不再把照片索引密文送到前端解密：本模块在 worker 内读取
 * 记录、解密（既有 meta 与瘦身 slim_meta 双标签）、按需读取独立缩略图
 * 记录，只返回展示字段与缩略图字节。
 *
 * 损坏判定口径与前端历史实现一致：只有内容层认证失败且载荷不是历史
 * 明文 JSON 才算确定损坏；锁定/超时/读取失败一律不可判定，绝不误删。
 */

use crate::runtime::content_crypto::VencError;
use crate::runtime::module_keys;
use crate::runtime::protocol::{MediaDamageScan, MediaMetaItem, Request, Response};
use crate::runtime::worker::Worker;

use super::source::{load_thumb_b64, read_meta};

const OP_META_GET: &str = "photo_meta_get";
const OP_META_PROBE: &str = "photo_meta_probe";

/// 单次响应条数上限：宿主按 32 条分批，worker 侧留一倍余量。
const MAX_META_BATCH: usize = 64;
/// 单批缩略图 base64 预算：防止多条大缩略图撑爆单行响应。
const MAX_THUMB_BUDGET_BYTES: usize = 8 * 1024 * 1024;
/// 单条缩略图上限：超限只丢弃缩略图，不影响元数据展示。
const MAX_SINGLE_THUMB_BYTES: usize = 4 * 1024 * 1024;
/// 损坏扫描单次上限：与前端批量扫描入口一致。
const MAX_PROBE_BATCH: usize = 4096;

pub(crate) fn handle_meta_get(worker: &Worker, req: &Request) -> Response {
    if req.ids.is_empty() {
        return error(OP_META_GET, "照片 ID 列表为空");
    }
    if req.ids.len() > MAX_META_BATCH {
        return error(OP_META_GET, "单批照片数量超出上限");
    }
    let mut items = Vec::with_capacity(req.ids.len());
    let mut failed_ids = Vec::new();
    let mut thumb_budget = 0usize;
    for meta_id in &req.ids {
        if *meta_id == 0 {
            failed_ids.push(*meta_id);
            continue;
        }
        let mut meta = match read_meta(worker, *meta_id) {
            Ok(meta) => meta,
            Err(_) => {
                failed_ids.push(*meta_id);
                continue;
            }
        };
        /* 缩略图是派生展示数据：记录缺失/损坏时降级为空缩略图，
         * 不能把整条照片元数据判为失败（否则照片会从网格消失）。 */
        let mut thumb_b64 = load_thumb_b64(worker, &meta).ok().flatten();
        if let Some(thumb) = thumb_b64.as_ref() {
            let next = thumb_budget.saturating_add(thumb.len());
            if thumb.len() > MAX_SINGLE_THUMB_BYTES || next > MAX_THUMB_BUDGET_BYTES {
                // 缩略图只是展示增强：超预算时丢弃，元数据仍返回
                thumb_b64 = None;
            } else {
                thumb_budget = next;
            }
        }
        let slim = meta.slim_layout();
        items.push(MediaMetaItem {
            meta_id: *meta_id,
            name: std::mem::take(&mut meta.name),
            mime: std::mem::take(&mut meta.mime),
            size: meta.size,
            file_hash: std::mem::take(&mut meta.file_hash),
            entry_key: std::mem::take(&mut meta.entry_key),
            thumb_b64,
            animated: meta.animated,
            created_at: meta.created_at,
            slim,
        });
    }
    let mut resp = Response::ok(OP_META_GET);
    resp.photo_meta = Some(items);
    if !failed_ids.is_empty() {
        resp.failed_ids = Some(failed_ids);
    }
    resp
}

pub(crate) fn handle_meta_probe(worker: &Worker, req: &Request) -> Response {
    if req.ids.is_empty() {
        return error(OP_META_PROBE, "照片 ID 列表为空");
    }
    if req.ids.len() > MAX_PROBE_BATCH {
        return error(OP_META_PROBE, "单批照片数量超出上限");
    }
    let mut damaged = Vec::new();
    let mut inconclusive = 0u64;
    for meta_id in &req.ids {
        if *meta_id == 0 {
            inconclusive += 1;
            continue;
        }
        let (rtype, _name, data) = match worker.call_get_record(*meta_id) {
            Ok(v) => v,
            Err(_) => {
                inconclusive += 1;
                continue;
            }
        };
        if rtype != 0x01 {
            inconclusive += 1;
            continue;
        }
        match open_meta_any(worker, &data) {
            Ok(()) => {}
            Err(VencError::Auth) => {
                if is_legacy_plain_json(&data) {
                    inconclusive += 1;
                } else {
                    damaged.push(*meta_id);
                }
            }
            Err(_) => inconclusive += 1,
        }
    }
    let mut resp = Response::ok(OP_META_PROBE);
    resp.photo_damage = Some(MediaDamageScan {
        checked: req.ids.len() as u64,
        damaged,
        inconclusive,
    });
    resp
}

fn open_meta_any(worker: &Worker, sealed: &[u8]) -> Result<(), VencError> {
    match module_keys::open_photo_record(worker, "meta", sealed) {
        Ok(_) => Ok(()),
        Err(VencError::Auth) => module_keys::open_photo_record(worker, "slim_meta", sealed).map(|_| ()),
        Err(e) => Err(e),
    }
}

/// 历史明文 JSON 布局：旧版本曾直接写 JSON；内容层认证失败属预期，不得删除。
fn is_legacy_plain_json(sealed: &[u8]) -> bool {
    let mut i = 0;
    while i < sealed.len() && matches!(sealed[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    if i >= sealed.len() || sealed[i] != b'{' {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(&sealed[i..]).is_ok()
}

fn error(op: &str, message: &str) -> Response {
    let mut resp = Response::ok(op);
    resp.ok = false;
    resp.error = Some(message.to_string());
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_plain_json_is_exempt_from_damage() {
        assert!(is_legacy_plain_json(b"{\"name\":\"a.jpg\"}"));
        assert!(is_legacy_plain_json(b" \r\n\t{\"name\":\"a.jpg\"}"));
        assert!(!is_legacy_plain_json(b"\x00\x01\x02"));
        assert!(!is_legacy_plain_json(b"{not json"));
        assert!(!is_legacy_plain_json(b"[]"));
        assert!(!is_legacy_plain_json(b""));
    }

}
