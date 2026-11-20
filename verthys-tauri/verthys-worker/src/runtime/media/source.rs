/*
 * media/source.rs — 照片索引与块引用读取（导出/还原共用）
 *
 * 只负责从容器记录还原「meta + 明文块」数据面，不决定业务动作：
 * 查看（read_job）、导出（export_job）与还原（restore_job）共用同一套
 * 布局判定与块定位，避免三处实现漂移。
 *
 * 布局边界：支持内联 `chunkDataB64`、外置 `chunkIds`，以及索引瘦身布局
 * （`fmt==2`：按 `chunkSetId` 读取块集、按 `thumbId` 读取独立缩略图）。
 */

use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::runtime::budget::PB_PHOTO_MAX_BYTES;
use crate::runtime::module_keys;
use crate::runtime::protocol::{base64_decode, base64_encode};
use crate::runtime::worker::Worker;

/// 单张照片块数硬上限：与 VENC 帧数上限一致，阻断异常索引触发的海量读取。
const MAX_PHOTO_CHUNKS: usize = 100_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PhotoMetaIn {
    pub(crate) name: String,
    pub(crate) mime: String,
    pub(crate) size: u64,
    #[serde(default)]
    pub(crate) file_hash: String,
    #[serde(default)]
    pub(crate) entry_key: String,
    #[serde(default)]
    pub(crate) thumb_b64: String,
    #[serde(default)]
    pub(crate) created_at: i64,
    #[serde(default)]
    pub(crate) animated: Option<bool>,
    #[serde(default)]
    pub(crate) chunk_ids: Vec<u64>,
    #[serde(default)]
    pub(crate) chunk_data_b64: Vec<String>,
    #[serde(default)]
    pub(crate) wrapped_file_key: Option<String>,
    #[serde(default)]
    pub(crate) fmt: Option<u32>,
    /// 索引瘦身布局：缩略图独立记录 ID
    #[serde(default)]
    pub(crate) thumb_id: u64,
    /// 索引瘦身布局：块集记录 ID（记录内容为 {ids, hashes}）
    #[serde(default)]
    pub(crate) chunk_set_id: u64,
    /// 索引瘦身布局：清单声明的块数
    #[serde(default)]
    pub(crate) chunk_count: Option<u32>,
}

impl Drop for PhotoMetaIn {
    fn drop(&mut self) {
        self.name.zeroize();
        self.mime.zeroize();
        self.file_hash.zeroize();
        self.entry_key.zeroize();
        self.thumb_b64.zeroize();
        for chunk in self.chunk_data_b64.iter_mut() {
            chunk.zeroize();
        }
        if let Some(key) = self.wrapped_file_key.as_mut() {
            key.zeroize();
        }
    }
}

impl PhotoMetaIn {
    pub(crate) fn chunk_total(&self) -> Result<u32, String> {
        let total = if !self.chunk_data_b64.is_empty() {
            self.chunk_data_b64.len()
        } else {
            self.chunk_ids.len()
        };
        if total == 0 {
            return Err("照片缺少块引用".to_string());
        }
        if total > MAX_PHOTO_CHUNKS {
            return Err("照片块数超出上限".to_string());
        }
        Ok(total as u32)
    }

    /// 是否为索引瘦身布局（块集/缩略图独立记录）。
    pub(crate) fn slim_layout(&self) -> bool {
        self.fmt.unwrap_or(0) == 2
            || self
                .wrapped_file_key
                .as_deref()
                .map(|k| !k.is_empty())
                .unwrap_or(false)
    }
}

/// 读取并解密照片索引；记录类型不符或解密失败即拒绝。
///
/// 既有布局与索引瘦身布局使用不同的内容种类标签，任一解封成功即可；
/// 两种标签都失败时返回既有布局的错误，保持调用方错误分类不变。
pub(crate) fn read_meta(worker: &Worker, meta_id: u64) -> Result<PhotoMetaIn, String> {
    let (rtype, _name, data) = worker
        .call_get_record(meta_id)
        .map_err(|rc| format!("读取照片索引失败（0x{:08X}）", rc))?;
    if rtype != 0x01 {
        return Err("目标记录不是照片索引".to_string());
    }
    let plain = match module_keys::open_photo_record(worker, "meta", &data) {
        Ok(plain) => plain,
        Err(first) => module_keys::open_photo_record(worker, "slim_meta", &data)
            .map_err(|_| format!("解密照片索引失败: {:?}", first))?,
    };
    serde_json::from_slice(&plain).map_err(|e| format!("解析照片索引失败: {}", e))
}

/// 解析索引瘦身布局的块集记录，补齐逐块记录 ID。
///
/// 既有布局（内联密文或 chunkIds）直接返回；瘦身布局必须按 chunkSetId
/// 读取块集记录并校验声明块数/哈希项数，避免把错位块序号带入后续 AD 校验。
pub(crate) fn resolve_chunk_refs(
    worker: &Worker,
    meta: &mut PhotoMetaIn,
) -> Result<(), String> {
    if !meta.chunk_data_b64.is_empty() || !meta.chunk_ids.is_empty() {
        return Ok(());
    }
    if meta.chunk_set_id == 0 {
        return Err("照片缺少块引用".to_string());
    }
    let (_rtype, _name, data) = worker
        .call_get_record(meta.chunk_set_id)
        .map_err(|rc| format!("读取块集记录失败（0x{:08X}）", rc))?;
    let plain = module_keys::open_photo_record(worker, "chunkset", &data)
        .map_err(|e| format!("解密块集记录失败: {:?}", e))?;
    #[derive(Deserialize)]
    struct ChunkSet {
        ids: Vec<u64>,
        #[serde(default)]
        hashes: Vec<String>,
    }
    let set: ChunkSet = serde_json::from_slice(&plain)
        .map_err(|e| format!("解析块集记录失败: {}", e))?;
    if set.ids.is_empty() {
        return Err("块集记录为空".to_string());
    }
    if set.ids.len() > MAX_PHOTO_CHUNKS {
        return Err("块集项数超出上限".to_string());
    }
    if set.ids.contains(&0) {
        return Err("块集包含非法记录 ID".to_string());
    }
    if let Some(declared) = meta.chunk_count {
        if declared as usize != set.ids.len() {
            return Err("块集项数与索引声明不一致".to_string());
        }
    }
    if !set.hashes.is_empty() && set.hashes.len() != set.ids.len() {
        return Err("块集哈希项数与块数不一致".to_string());
    }
    meta.chunk_ids = set.ids;
    Ok(())
}

/// 读取列表展示用缩略图：既有布局内联，瘦身布局读取独立 thumb 记录。
pub(crate) fn load_thumb_b64(
    worker: &Worker,
    meta: &PhotoMetaIn,
) -> Result<Option<String>, String> {
    if !meta.thumb_b64.is_empty() {
        return Ok(Some(meta.thumb_b64.clone()));
    }
    if meta.thumb_id == 0 {
        return Ok(None);
    }
    let (_rtype, _name, data) = worker
        .call_get_record(meta.thumb_id)
        .map_err(|rc| format!("读取缩略图记录失败（0x{:08X}）", rc))?;
    let plain = module_keys::open_photo_record(worker, "thumb", &data)
        .map_err(|e| format!("解密缩略图记录失败: {:?}", e))?;
    Ok(Some(base64_encode(&plain)))
}

/// 读取指定块序号的密文（内联优先，其次外置记录）。
pub(crate) fn load_chunk_cipher(
    worker: &Worker,
    meta: &mut PhotoMetaIn,
    seq: u32,
) -> Result<Vec<u8>, String> {
    resolve_chunk_refs(worker, meta)?;
    if !meta.chunk_data_b64.is_empty() {
        let b64 = meta
            .chunk_data_b64
            .get(seq as usize)
            .ok_or_else(|| "照片块引用缺失".to_string())?;
        return base64_decode(b64).map_err(|_| "照片块密文编码非法".to_string());
    }
    let id = meta
        .chunk_ids
        .get(seq as usize)
        .copied()
        .ok_or_else(|| "照片块引用缺失".to_string())?;
    let (_rtype, _name, data) = worker
        .call_get_record(id)
        .map_err(|rc| format!("读取照片块失败（0x{:08X}）", rc))?;
    Ok(data)
}

/// 逐块解密全部明文；校验块序号/总数。
///
/// 返回的明文总字节仍由调用方核对 `meta.size` 与整图 BLAKE3。
pub(crate) fn load_plain_chunks(
    worker: &Worker,
    meta: &mut PhotoMetaIn,
) -> Result<Vec<Zeroizing<Vec<u8>>>, String> {
    resolve_chunk_refs(worker, meta)?;
    let total = meta.chunk_total()?;
    let mut chunks = Vec::with_capacity(total as usize);
    let mut total_bytes = 0u64;
    for seq in 0..total {
        let cipher = load_chunk_cipher(worker, meta, seq)?;
        let (plain, chunk_seq, chunk_total) = module_keys::open_photo_chunk_any(worker, &cipher)
            .map_err(|e| format!("解密照片块失败: {:?}", e))?;
        if chunk_seq != seq || chunk_total != total {
            return Err("照片块序号与索引声明不一致".to_string());
        }
        total_bytes = total_bytes.saturating_add(plain.len() as u64);
        if total_bytes > PB_PHOTO_MAX_BYTES {
            return Err("照片明文字节超出上限".to_string());
        }
        chunks.push(plain);
    }
    Ok(chunks)
}

/// 校验块字节数与整图 BLAKE3；两者任一不符即拒绝。
pub(crate) fn verify_plain(meta: &PhotoMetaIn, chunks: &[Zeroizing<Vec<u8>>]) -> Result<(), String> {
    let total: u64 = chunks.iter().map(|c| c.len() as u64).sum();
    if total != meta.size {
        return Err(format!(
            "照片明文字节与索引声明不一致: {} ≠ {}",
            total, meta.size
        ));
    }
    let mut hasher = blake3::Hasher::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    if hasher.finalize().to_hex().to_string() != meta.file_hash {
        return Err("照片完整性校验失败".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(chunk_ids: Vec<u64>, inline: Vec<String>) -> PhotoMetaIn {
        PhotoMetaIn {
            name: "a.jpg".to_string(),
            mime: "image/jpeg".to_string(),
            size: 10,
            file_hash: "a".repeat(64),
            entry_key: "e".repeat(64),
            thumb_b64: String::new(),
            created_at: 1,
            animated: None,
            chunk_ids,
            chunk_data_b64: inline,
            wrapped_file_key: None,
            fmt: None,
            thumb_id: 0,
            chunk_set_id: 0,
            chunk_count: None,
        }
    }

    #[test]
    fn slim_layout_detection_covers_fmt_and_wrapped_key() {
        let mut m = meta(vec![1], Vec::new());
        assert!(!m.slim_layout());

        m.wrapped_file_key = Some("wrapped".into());
        assert!(m.slim_layout());

        let mut m = meta(vec![1], Vec::new());
        m.fmt = Some(2);
        assert!(m.slim_layout());
    }

    #[test]
    fn chunk_total_prefers_inline_and_rejects_empty() {
        let mut m = meta(Vec::new(), Vec::new());
        assert!(m.chunk_total().is_err());
        m.chunk_data_b64 = vec!["x".into(), "y".into()];
        assert_eq!(m.chunk_total().unwrap(), 2);
    }
}
