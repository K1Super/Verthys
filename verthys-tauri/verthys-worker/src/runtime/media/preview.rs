/*
 * media/preview.rs — 预览记录的头格式与确定性命名
 *
 * 预览是派生缓存：记录名绑定导入条目标识，明文头绑定文件内容哈希。
 * 头只携带 fileHash（32 字节原始摘要）：metaId 在导入批次写入前尚未
 * 分配，无法进入同一批次的预览密文；记录名 + 内容哈希足以识别孤儿
 * 预览与记录 ID 复用错配。读取侧两者任一不匹配即视为缺失并重生成。
 */

use crate::runtime::budget::PB_MAX_RECORD_NAME_BYTES;

/// 预览明文头：BLAKE3 文件哈希原始 32 字节。
pub(crate) const PREVIEW_HEADER_BYTES: usize = 32;

/// 解析 64 字符十六进制 BLAKE3 哈希为原始字节。
pub(crate) fn parse_file_hash(file_hash: &str) -> Result<[u8; PREVIEW_HEADER_BYTES], String> {
    if file_hash.len() != PREVIEW_HEADER_BYTES * 2 {
        return Err("文件哈希长度非法".to_string());
    }
    let mut out = [0u8; PREVIEW_HEADER_BYTES];
    let bytes = file_hash.as_bytes();
    for i in 0..PREVIEW_HEADER_BYTES {
        let hi = hex_val(bytes[i * 2]).ok_or_else(|| "文件哈希字符非法".to_string())?;
        let lo = hex_val(bytes[i * 2 + 1]).ok_or_else(|| "文件哈希字符非法".to_string())?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// 预览记录名。
///
/// 原生导入在 meta 写入前已知 entry_key，预览与 meta 同一批次落库时用
/// `preview_<entry_key>`；历史照片懒生成时没有 entry_key，用
/// `preview_<metaId>`。两种名称都满足确定性定位，读取侧按 meta 字段
/// 选择同一规则。
pub(crate) fn record_name(entry_key: Option<&str>, meta_id: u64) -> Result<String, String> {
    let name = match entry_key {
        Some(key) if !key.is_empty() => format!("preview_{}", key),
        _ => format!("preview_{}", meta_id),
    };
    if name.len() > PB_MAX_RECORD_NAME_BYTES as usize {
        return Err("预览记录名超过上限".to_string());
    }
    Ok(name)
}

/// 组装预览明文：fileHash(32B) + JPEG。
pub(crate) fn build_payload(
    file_hash: &str,
    jpeg: &[u8],
) -> Result<Vec<u8>, String> {
    if jpeg.is_empty() {
        return Err("预览 JPEG 为空".to_string());
    }
    let hash = parse_file_hash(file_hash)?;
    let mut out = Vec::with_capacity(PREVIEW_HEADER_BYTES + jpeg.len());
    out.extend_from_slice(&hash);
    out.extend_from_slice(jpeg);
    Ok(out)
}

/// 校验并拆分预览明文；头哈希与当前 meta 不一致即拒绝。
pub(crate) fn split_payload<'a>(
    payload: &'a [u8],
    expected_file_hash: &str,
) -> Result<&'a [u8], String> {
    if payload.len() <= PREVIEW_HEADER_BYTES {
        return Err("预览记录过短".to_string());
    }
    let expected = parse_file_hash(expected_file_hash)?;
    if payload[..PREVIEW_HEADER_BYTES] != expected {
        return Err("预览记录与当前照片不匹配".to_string());
    }
    Ok(&payload[PREVIEW_HEADER_BYTES..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str =
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const HASH_B: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn payload_roundtrip_binds_file_hash() {
        let payload = build_payload(HASH_A, b"jpeg-bytes").unwrap();
        assert_eq!(payload.len(), PREVIEW_HEADER_BYTES + 10);
        assert_eq!(split_payload(&payload, HASH_A).unwrap(), b"jpeg-bytes");
        assert!(split_payload(&payload, HASH_B).is_err());
    }

    #[test]
    fn payload_rejects_empty_and_truncated() {
        assert!(build_payload(HASH_A, b"").is_err());
        assert!(split_payload(&[0u8; PREVIEW_HEADER_BYTES], HASH_A).is_err());
        assert!(parse_file_hash("zz").is_err());
    }

    #[test]
    fn record_name_prefers_entry_key_and_falls_back_to_meta_id() {
        assert_eq!(record_name(Some("ab12"), 7).unwrap(), "preview_ab12");
        assert_eq!(record_name(None, 7).unwrap(), "preview_7");
        assert_eq!(record_name(Some(""), 8).unwrap(), "preview_8");
    }
}
